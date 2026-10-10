package realsock

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
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
// AcceptTimeout, the reader held the same way. Stimulus proof per run:
// the passive reported drained bytes (Hooks.Drained: the refusal's
// concurrent drain, or the early DATA its reader read only after the
// refusal); a run without it is not counted, and a variant fails unless
// at least erMinCounted of its erRuns runs were counted. Helpers carry
// the er prefix: the package's other files belong to other work packages.

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
		Drained: func(n int) { p.drained.Add(int64(n)) },
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
		t.Cleanup(p.closeGoingAway)
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
	t.Cleanup(func() {
		if p.occCancel != nil {
			p.occCancel(carrier.ErrWithdrawn)
			<-p.occDone
		}
		p.rt.Close()
	})
	if p.ln, err = p.rt.Listen(lc); err != nil {
		l.Close()
		t.Fatal(err)
	}
	if kind == erBacklog {
		p.occupy(denv)
	}
	return p
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

// erRun is one refused first flight; it reports whether the run was
// counted (the passive drained bytes after the refusal).
func erRun(p *erPassive, env *carrier.Env, kind erKind, mux bool, i int, early []byte) (counted bool, err error) {
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
	drained0, held0 := p.drained.Load(), p.held.Load()
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
	switch kind {
	case erReject:
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			pc, err := p.ln.Accept(ctx)
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
	// The dialer half-closes and reads the rest until the passive closed:
	// a clean EOF, never a reset.
	if cw, ok := raw.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	_ = raw.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.Copy(io.Discard, raw); err != nil {
		return false, fmt.Errorf("after the refusal the dialer read %w, want EOF", err)
	}
	// The stimulus: the passive drained bytes for this run (its reader
	// reports them as it exits, which may follow the close).
	deadline := time.Now().Add(time.Second)
	for p.drained.Load() == drained0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	return p.drained.Load() > drained0, nil
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
				var next, counted atomic.Int64
				var failed atomic.Bool
				var wg sync.WaitGroup
				start := time.Now()
				for w := 0; w < erWorkers; w++ {
					denv := erEnv(0xd0+byte(w), nil)
					p := newErPassive(t, kind, denv)
					wg.Add(1)
					go func() {
						defer wg.Done()
						for !failed.Load() {
							i := int(next.Add(1))
							if i > erRuns {
								return
							}
							c, err := erRun(p, denv, kind, mux, i, early)
							if err != nil {
								failed.Store(true)
								t.Errorf("run %d: %v", i, err)
								return
							}
							if c {
								counted.Add(1)
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
				t.Logf("%d of %d runs counted (stimulus: drained bytes after the refusal) in %v", counted.Load(), erRuns, time.Since(start).Round(time.Millisecond))
				if counted.Load() < erMinCounted {
					t.Fatalf("%d of %d runs counted, want at least %d", counted.Load(), erRuns, erMinCounted)
				}
			})
		}
	}
}
