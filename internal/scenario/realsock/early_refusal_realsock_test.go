package realsock

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/tcp"
	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The real-socket half of TestEarlyRefusalDrain_L05 (M4 design M4-D8,
// M4-D58, R1-5, R1-17; WP8): a dialer's first flight PREFACE ‖
// OPEN(EARLY) ‖ DATA(64 KiB) over loopback TCP (carrier/tcp, rendr-owned
// sockets on both ends) is refused, and the dialer always reads the typed
// OPEN_ACK — never a connection reset caused by early data the passive
// left unread when it closed — and then a clean EOF. The dialer is the
// carrier's own EstablishEarly (the session's EarlyReturn arrives with
// WP9a); the passive is a Runtime and its Listener, except for GOING_AWAY
// at admission, which the public API cannot place between the gate and
// the admission (the root package's TestEstablishEarlySyncConnAdmission
// covers that branch): its row drives the same answer through
// carrier.ReadHello and Conn.WriteAndClose, the closer the admission uses.
// Variants, each on dedicated carriers and on handle 1 of a fresh MUX
// trunk: (a) admission refusals — a full backlog, oversized metadata,
// GOING_AWAY; (b) an application Reject while the passive's carrier
// reader is held before the early DATA (Hooks.BeforeEarlyRead); (c)
// AcceptTimeout, the reader held the same way. Stimulus proof: a refused
// carrier that discarded bytes after the refusal reports Hooks.Drained
// exactly once (the refusal's concurrent drain, or its reader's exit after
// it read early DATA past the refusal), and each run makes one passive
// carrier; once a variant's runs ended and its passives closed (every
// carrier joined), the number of reports is the number of counted runs —
// a late report is never credited to another run — and a variant fails
// unless at least erMinCounted of its erRuns runs were counted.
//
// Footprint (A12.7): an invocation opens about 2,000 loopback connections
// (10 variants × 200 runs). Wherever the passive closes on its own — every
// row but the session refusals on a fresh trunk, whose trunk outlives the
// refused view — the dialer reads the passive's EOF before it half-closes,
// so TIME_WAIT lands on the listener's side and not on the dialer's
// ephemeral ports: about 400 dialer-side TIME_WAITs per invocation (a
// session refusal on a dedicated carrier then costs the passive's
// retirement bound, 2·srtt + 100 ms, per run: the raw dialer sends no
// CLOSE; about 2.5 s per such variant on loopback). A dial
// that fails for ephemeral-port exhaustion (EADDRINUSE, EADDRNOTAVAIL,
// WSAENOBUFS) is an invalid run: not counted, never a FAIL by itself.
// Helpers carry the er prefix: the package's other files belong to other
// work packages.

const (
	erRuns       = 200
	erMinCounted = 100
	erWorkers    = 8
)

type erKind int

const (
	erBacklog erKind = iota
	erMetadata
	erGoingAway
	erReject
	erAcceptTimeout
)

func (k erKind) String() string {
	return [...]string{"backlog full", "oversized metadata", "GOING_AWAY", "application Reject", "AcceptTimeout"}[k]
}

const (
	erAcceptTimeoutD = 100 * time.Millisecond // the AcceptTimeout floor
	erRejectCode     = 4242
	erBigMeta        = 1000
)

// erPassive is one worker's passive end: a Runtime and its Listener on a
// carrier/tcp listening socket, or, for GOING_AWAY, ReadHello and
// WriteAndClose on accepted sockets.
type erPassive struct {
	t       testing.TB
	kind    erKind
	l       net.Listener
	addr    string
	rt      *rendr.Runtime
	ln      *rendr.Listener
	drained atomic.Int64                  // bytes Hooks.Drained reported
	reports atomic.Int64                  // Hooks.Drained reports (one per refused carrier that drained)
	fin     sync.Once                     // finish
	hold    atomic.Pointer[chan struct{}] // BeforeEarlyRead waits on it while set
	held    atomic.Int64                  // BeforeEarlyRead calls that waited

	// GOING_AWAY: the carrier-level passive.
	cenv  *carrier.Env
	wg    sync.WaitGroup
	cmu   sync.Mutex
	conns []*carrier.Conn

	// The backlog's occupant: a plain OPEN left pending.
	occCancel context.CancelCauseFunc
	occDone   chan struct{}
}

func erEnv(local byte, hooks *testhooks.Hooks) *carrier.Env {
	var inst [16]byte
	for i := range inst {
		inst[i] = local
	}
	return &carrier.Env{
		Local:   inst,
		Timing:  carrier.Timing{DialTimeout: 10 * time.Second, AbandonWait: time.Second},
		IDs:     carrier.NewIDAllocator(0),
		Abandon: carrier.NewAbandonPool(64),
		Bufs:    carrier.NewBufPool(),
		Budget:  carrier.NewBudget(1 << 30),
		Hooks:   hooks,
	}
}

func newErPassive(t testing.TB, kind erKind, denv *carrier.Env) *erPassive {
	t.Helper()
	p := &erPassive{t: t, kind: kind}
	l, err := tcp.Listen("tcp", "127.0.0.1:0", tcp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	p.l, p.addr = l, l.Addr().String()
	hooks := &testhooks.Hooks{
		Drained: func(n int) {
			if n > 0 {
				p.reports.Add(1)
				p.drained.Add(int64(n))
			}
		},
		BeforeEarlyRead: func() {
			if ch := p.hold.Load(); ch != nil {
				p.held.Add(1)
				<-*ch
			}
		},
	}
	if kind == erGoingAway {
		p.cenv = erEnv(0xcd, hooks)
		p.wg.Add(1)
		go p.serveGoingAway()
		t.Cleanup(p.finish)
		return p
	}
	cfg := rendr.Config{}
	lc := rendr.ListenConfig{Sources: []rendr.Source{rendr.FromListener(l)}}
	switch kind {
	case erMetadata:
		cfg.Handshake.MaxMetadata = 64
	case erBacklog:
		lc.AcceptBacklog, lc.AcceptTimeout = 1, time.Minute
	case erAcceptTimeout:
		lc.AcceptTimeout = erAcceptTimeoutD
	}
	rt, err := testhooks.NewRuntime(cfg, &testhooks.Overrides{Hooks: hooks})
	if err != nil {
		t.Fatal(err)
	}
	p.rt = rt.(*rendr.Runtime)
	t.Cleanup(p.finish)
	if p.ln, err = p.rt.Listen(lc); err != nil {
		l.Close()
		t.Fatal(err)
	}
	if kind == erBacklog {
		p.occupy(denv)
	}
	return p
}

// finish closes the passive and joins its carriers (idempotent): their
// Drained reports are final afterwards. Runtime.Close joins every
// goroutine of the Runtime; the GOING_AWAY passive waits for its conns.
func (p *erPassive) finish() {
	p.fin.Do(func() {
		if p.kind == erGoingAway {
			p.closeGoingAway()
			return
		}
		if p.occCancel != nil {
			p.occCancel(carrier.ErrWithdrawn)
			<-p.occDone
		}
		p.rt.Close()
	})
}

// occupy fills the backlog of one with a plain OPEN that stays pending
// (withdrawn at the cleanup).
func (p *erPassive) occupy(denv *carrier.Env) {
	ctx, cancel := context.WithCancelCause(context.Background())
	p.occCancel, p.occDone = cancel, make(chan struct{})
	f := erFactory(p.addr, false, nil)
	go func() {
		defer close(p.occDone)
		est, err := carrier.Establish(ctx, denv, f, denv.IDs.Next(), wire.TypeOpen, erOpen([16]byte{0x0c, 15: 0x0c}, 0), nil)
		if err == nil {
			est.Conn.Kill(carrier.CauseLocalClose, "test end")
			<-est.Conn.Done()
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for p.rt.Status().AcceptBacklog[0] != 1 {
		if time.Now().After(deadline) {
			p.t.Fatal("the backlog's occupant is not pending")
		}
		time.Sleep(time.Millisecond)
	}
}

// serveGoingAway answers every accepted carrier's OPEN with OPEN_ACK
// (GOING_AWAY) through WriteAndClose, as the admission does while the
// Runtime closes.
func (p *erPassive) serveGoingAway() {
	defer p.wg.Done()
	var ack [wire.OpenAckFixedLen]byte
	n := wire.PutOpenAck(ack[:], &wire.OpenAck{Status: wire.StatusGoingAway})
	for {
		nc, err := p.l.Accept()
		if err != nil {
			return
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			deadline := time.Now().Add(10 * time.Second)
			h, err := carrier.ReadHello(p.cenv, nc, deadline, 4096, nil)
			if err != nil {
				return
			}
			p.cmu.Lock()
			p.conns = append(p.conns, h.Conn)
			p.cmu.Unlock()
			h.Conn.WriteAndClose(wire.TypeOpenAck, 0, wire.SessionHandle, ack[:n], deadline)
		}()
	}
}

func (p *erPassive) closeGoingAway() {
	p.l.Close()
	p.wg.Wait()
	p.cmu.Lock()
	conns := p.conns
	p.cmu.Unlock()
	for _, c := range conns {
		select {
		case <-c.Done():
		case <-time.After(10 * time.Second):
			p.t.Errorf("a refused carrier is not done")
		}
	}
	if n := p.cenv.Abandon.Len(); n != 0 {
		p.t.Errorf("passive abandoned %d", n)
	}
}

// erOpen is a stream OPEN of session sid with meta bytes of metadata.
func erOpen(sid [16]byte, meta int) []byte {
	m := make([]byte, meta)
	for i := range m {
		m[i] = 'm'
	}
	o := wire.Open{SID: sid, Kind: wire.KindStream, Mode: 1, RetainMs: 30000, Window: 8 << 20, Metadata: m}
	b := make([]byte, wire.OpenFixedLen+meta)
	return b[:wire.PutOpen(b, &o)]
}

// erFactory is a carrier/tcp factory to addr; got, if non-nil, receives
// the dialed conn (the dialer's raw socket).
func erFactory(addr string, mux bool, got *net.Conn) carrier.Factory {
	dial := tcp.Carrier("er", "tcp", addr, tcp.Options{}).Dial
	return carrier.Factory{Name: "er", Mux: mux, Dial: func(ctx context.Context) (net.Conn, error) {
		nc, err := dial(ctx)
		if err == nil && got != nil {
			*got = nc
		}
		return nc, err
	}}
}

// erAddrExhausted reports a dial that failed for ephemeral-port
// exhaustion, an environmental condition of the host (an invalid run).
func erAddrExhausted(err error) bool {
	var en syscall.Errno
	if !errors.As(err, &en) {
		return false
	}
	if runtime.GOOS == "windows" {
		return en == 10048 || en == 10049 || en == 10055 // WSAEADDRINUSE, WSAEADDRNOTAVAIL, WSAENOBUFS
	}
	return en == syscall.EADDRINUSE || en == syscall.EADDRNOTAVAIL
}

// erRun is one refused first flight; invalid reports a dial that failed
// for ephemeral-port exhaustion (the run is not counted).
func erRun(p *erPassive, env *carrier.Env, kind erKind, mux bool, i int, early []byte) (invalid bool, err error) {
	sid := [16]byte{0xe8, 1: byte(i >> 8), 2: byte(i), 15: byte(kind)}
	meta := 0
	if kind == erMetadata {
		meta = erBigMeta
	}
	want := wire.OpenAck{Status: wire.StatusCapacity, Code: wire.CodeBacklog}
	switch kind {
	case erMetadata:
		want = wire.OpenAck{Status: wire.StatusBadRequest, Code: wire.CodeMetadataSize}
	case erGoingAway:
		want = wire.OpenAck{Status: wire.StatusGoingAway}
	case erReject:
		want = wire.OpenAck{Status: wire.StatusRejected, Code: erRejectCode}
	case erAcceptTimeout:
		want = wire.OpenAck{Status: wire.StatusCapacity, Code: wire.CodeAcceptTimeout}
	}
	held0 := p.held.Load()
	release := make(chan struct{})
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	defer free()
	if kind == erReject || kind == erAcceptTimeout {
		p.hold.Store(&release)
		defer p.hold.Store(nil)
	}
	estDone := make(chan struct{})
	decided := make(chan error, 1)
	actx, acancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer acancel()
	switch kind {
	case erReject:
		go func() {
			pc, err := p.ln.Accept(actx)
			if err == nil {
				// The premise: the passive's reader is held before the
				// early DATA (its goroutine may run after Accept returned).
				err = erWaitHeld(p, held0)
			}
			if err == nil {
				err = pc.Reject(erRejectCode, "refused early")
			}
			free() // the refusal is decided: the held reader drains
			decided <- err
		}()
	case erAcceptTimeout:
		go func() {
			select {
			case <-estDone: // the refusal reached the dialer
			case <-time.After(erAcceptTimeoutD + 2*time.Second):
			}
			free()
			decided <- nil
		}()
	default:
		decided <- nil
	}
	var raw net.Conn
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	est, err := carrier.EstablishEarly(ctx, env, erFactory(p.addr, mux, &raw), env.IDs.Next(), wire.TypeOpen, erOpen(sid, meta), early, nil)
	close(estDone)
	if err != nil && erAddrExhausted(err) {
		acancel() // no OPEN reaches the passive: its Accept ends
		<-decided
		return true, nil
	}
	if derr := <-decided; derr != nil {
		return false, fmt.Errorf("the passive's verdict: %w", derr)
	}
	if err != nil {
		return false, fmt.Errorf("EstablishEarly: %w (want the typed refusal)", err)
	}
	defer func() {
		est.Conn.Kill(carrier.CauseLocalClose, "run end")
		<-est.Conn.Done()
	}()
	a, perr := wire.ParseOpenAck(est.Payload)
	if est.Resp.Type != wire.TypeOpenAck || perr != nil || a.Status != want.Status || a.Code != want.Code || est.Early != len(early) {
		return false, fmt.Errorf("answer %v %+v (%v, Early %d), want OPEN_ACK %v code %d after the whole flight", est.Resp.Type, a, perr, est.Early, want.Status, want.Code)
	}
	if kind == erAcceptTimeout {
		if err := erWaitHeld(p, held0); err != nil {
			return false, err
		}
	}
	// The dialer reads the rest until the passive closed — a clean EOF,
	// never a reset — and half-closes: after that EOF where the passive
	// closes on its own (TIME_WAIT then stays off the dialer's ephemeral
	// ports), before it on a fresh trunk refused by the session, which
	// the passive keeps until the dialer's EOF.
	cw, _ := raw.(interface{ CloseWrite() error })
	passiveCloses := !mux || (kind != erReject && kind != erAcceptTimeout)
	if !passiveCloses && cw != nil {
		_ = cw.CloseWrite()
	}
	_ = raw.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.Copy(io.Discard, raw); err != nil {
		return false, fmt.Errorf("after the refusal the dialer read %w, want EOF", err)
	}
	if passiveCloses && cw != nil {
		_ = cw.CloseWrite()
	}
	return false, nil
}

// erWaitHeld waits until the passive's BeforeEarlyRead held a reader since
// the count held0 (the premise of the held-reader variants).
func erWaitHeld(p *erPassive, held0 int64) error {
	deadline := time.Now().Add(5 * time.Second)
	for p.held.Load() == held0 {
		if time.Now().After(deadline) {
			return errors.New("BeforeEarlyRead did not hold the passive's reader (the premise)")
		}
		time.Sleep(100 * time.Microsecond)
	}
	return nil
}

func TestEarlyRefusalDrain_L05(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	early := make([]byte, wire.EarlyWindow)
	for i := range early {
		early[i] = byte(i*7 + 1)
	}
	for _, kind := range []erKind{erBacklog, erMetadata, erGoingAway, erReject, erAcceptTimeout} {
		for _, mux := range []bool{false, true} {
			name := kind.String() + ", dedicated"
			if mux {
				name = kind.String() + ", fresh trunk"
			}
			t.Run(name, func(t *testing.T) {
				var next, invalid atomic.Int64
				var failed atomic.Bool
				var wg sync.WaitGroup
				start := time.Now()
				var ps []*erPassive
				for w := 0; w < erWorkers; w++ {
					denv := erEnv(0xd0+byte(w), nil)
					p := newErPassive(t, kind, denv)
					ps = append(ps, p)
					wg.Add(1)
					go func() {
						defer wg.Done()
						for !failed.Load() {
							i := int(next.Add(1))
							if i > erRuns {
								return
							}
							inv, err := erRun(p, denv, kind, mux, i, early)
							if err != nil {
								failed.Store(true)
								t.Errorf("run %d: %v", i, err)
								return
							}
							if inv {
								invalid.Add(1)
							}
						}
					}()
					t.Cleanup(func() {
						if n := denv.Abandon.Len(); n != 0 {
							t.Errorf("dialer abandoned %d", n)
						}
					})
				}
				wg.Wait()
				if failed.Load() {
					return
				}
				// Every carrier joined: the reports are final, one per
				// refused carrier that drained, one carrier per valid run.
				var counted int64
				for _, p := range ps {
					p.finish()
					counted += p.reports.Load()
				}
				valid := erRuns - invalid.Load()
				t.Logf("%d of %d runs counted (stimulus: drained bytes after the refusal), %d invalid (ephemeral ports exhausted), in %v", counted, erRuns, invalid.Load(), time.Since(start).Round(time.Millisecond))
				if counted > valid {
					t.Fatalf("%d Drained reports for %d valid runs: a refused carrier reported more than once", counted, valid)
				}
				if counted < erMinCounted {
					t.Fatalf("%d of %d runs counted, want at least %d (%d runs invalid: ephemeral ports exhausted)", counted, erRuns, erMinCounted, invalid.Load())
				}
			})
		}
	}
}

// TestErAddrExhausted: the invalid-run rule of TestEarlyRefusalDrain_L05
// recognises a dial that failed for ephemeral-port exhaustion through
// EstablishError's chain, and nothing else.
func TestErAddrExhausted(t *testing.T) {
	exhausted := []syscall.Errno{syscall.EADDRINUSE, syscall.EADDRNOTAVAIL}
	if runtime.GOOS == "windows" {
		exhausted = []syscall.Errno{10048, 10049, 10055}
	}
	wrap := func(e error) error {
		return &carrier.EstablishError{Stage: "dial", Cause: carrier.CauseTransportError, Err: &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", e)}}
	}
	for _, en := range exhausted {
		if !erAddrExhausted(wrap(en)) {
			t.Errorf("errno %d: not recognised as port exhaustion", int(en))
		}
	}
	for _, err := range []error{wrap(syscall.ECONNREFUSED), wrap(syscall.ECONNRESET), io.EOF, context.DeadlineExceeded} {
		if erAddrExhausted(err) {
			t.Errorf("%v: taken for port exhaustion", err)
		}
	}
}
