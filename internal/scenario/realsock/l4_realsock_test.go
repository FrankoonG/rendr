package realsock

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/tcp"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/l4"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The l4 rows of the real-socket group (M4 design §A12.4 without
// TestEarlyRefusalDrain_L05, which is WP8's, and the real-socket twins of
// §A12.3; WP12): two Runtimes joined by carrier/tcp on loopback, an
// l4.Server serving the passive's Listener, and real loopback TCP targets
// (net.Listen), outside synctest bubbles, on Linux and Windows alike,
// through the public API (testhooks only lower Linger and the idle floor).
// Every test registers rendrtest.AssertNoLeak first (its check runs after
// every other cleanup, once both Runtimes are closed), closes both Runtimes
// and never runs in parallel. Bounds are real-time bounds with the OS slack
// stated (A12.7 rule 4); waits poll a condition, never sleep for one.
// Helpers carry the l4r prefix: the package's other files belong to other
// work packages.

// l4rRace reports a race-detector build (the build setting "-race").
var l4rRace = msRace

// l4rNet is one test's fixture: the dialer Runtime d with its Peer, the
// passive Runtime p with its Listener and the l4.Server serving it.
type l4rNet struct {
	t      testing.TB
	d, p   *rendr.Runtime
	l      net.Listener // the passive's carrier listening socket
	ln     *rendr.Listener
	peer   *rendr.Peer
	srv    *l4.Server
	relay  *l4rRelay // with l4rOpts.relay
	cancel context.CancelFunc
	served chan error
	live0  int64
	once   sync.Once

	mu    sync.Mutex
	ends  []rendr.Event // the passive's EventSessionEnd events
	downs []rendr.Event // the passive's EventCarrierDown events of session carriers
}

// l4rOpts configure an l4rNet; the zero value is the default fixture.
type l4rOpts struct {
	dov, pov *testhooks.Overrides            // per Runtime; nil: none
	srv      *l4.Server                      // nil: the zero Server
	props    rendr.Props                     // the dialer factory's Props
	relay    bool                            // the dialer factory dials through an l4rRelay (l4rNet.relay)
	wrap     func(net.Listener) net.Listener // wraps the passive's carrier listener
	cfg      func(d, p *rendr.Config)        // edits the Configs
}

func l4rRuntime(t testing.TB, cfg rendr.Config, ov *testhooks.Overrides) *rendr.Runtime {
	t.Helper()
	if ov == nil {
		rt, err := rendr.NewRuntime(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return rt
	}
	o := *ov
	rt, err := testhooks.NewRuntime(cfg, &o)
	if err != nil {
		t.Fatal(err)
	}
	return rt.(*rendr.Runtime)
}

// newL4rNet builds the fixture and starts the Server. A cleanup closes
// everything as well, so that a failed test leaves nothing behind.
func newL4rNet(t testing.TB, o l4rOpts) *l4rNet {
	t.Helper()
	n := &l4rNet{t: t, srv: o.srv, served: make(chan error, 1), live0: testhooks.LiveSessions.Load()}
	if n.srv == nil {
		n.srv = &l4.Server{}
	}
	l, err := tcp.Listen("tcp", "127.0.0.1:0", tcp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	n.l = l
	var dcfg, pcfg rendr.Config
	pcfg.OnEvent = func(ev rendr.Event) {
		n.mu.Lock()
		defer n.mu.Unlock()
		switch {
		case ev.Kind == rendr.EventSessionEnd:
			n.ends = append(n.ends, ev)
		case ev.Kind == rendr.EventCarrierDown && ev.Session != (rendr.SessionID{}):
			n.downs = append(n.downs, ev)
		}
	}
	if o.cfg != nil {
		o.cfg(&dcfg, &pcfg)
	}
	n.d = l4rRuntime(t, dcfg, o.dov)
	n.p = l4rRuntime(t, pcfg, o.pov)
	t.Cleanup(n.shutdown)
	src := l
	if o.wrap != nil {
		src = o.wrap(l)
	}
	if n.ln, err = n.p.Listen(rendr.ListenConfig{Sources: []rendr.Source{rendr.FromListener(src)}}); err != nil {
		l.Close()
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if o.relay {
		n.relay = newL4rRelay(t, addr)
		addr = n.relay.addr()
	}
	c := tcp.Carrier("a", "tcp", addr, tcp.Options{})
	c.Props = o.props
	if n.peer, err = n.d.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{c}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	n.cancel = cancel
	go func() { n.served <- n.srv.Serve(ctx, n.ln) }()
	return n
}

// shutdown closes the fixture (idempotent) and joins Serve.
func (n *l4rNet) shutdown() {
	n.once.Do(func() {
		n.peer.Close()
		n.d.Close()
		n.p.Close()
		select {
		case <-n.served:
		case <-time.After(10 * time.Second):
			n.t.Errorf("l4.Server.Serve did not return within 10 s of Runtime.Close")
		}
		n.cancel()
	})
}

// close closes the fixture and requires that nothing is left: no session,
// handshake, actor, buffered byte or shared carrier on either Runtime, no
// connection the Server dials for or forwards, and the session registry
// back at its start.
func (n *l4rNet) close() {
	n.t.Helper()
	n.shutdown()
	for _, rt := range []*rendr.Runtime{n.d, n.p} {
		st := rt.Status()
		sc := st.Sessions
		if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || st.Handshakes != 0 || st.Sessionless != 0 || st.Actors != 0 ||
			st.BufferedBytes != 0 || st.Abandoned != 0 || st.Mux.Carriers != 0 || st.Mux.Views != 0 {
			n.t.Errorf("state left after Runtime.Close: %+v", st)
		}
	}
	if ss := n.srv.Status(); ss.Dialing != 0 || ss.Live != 0 || ss.Hooks != 0 || ss.Abandoned != 0 {
		n.t.Errorf("Server state left after Serve returned: %+v", ss)
	}
	msUntil(n.t, 10*time.Second, "the session registry back at its start", func() bool {
		return testhooks.LiveSessions.Load() == n.live0
	})
}

// dial opens one L4 session to addr (bounded by 10 s).
func (n *l4rNet) dial(addr string, o rendr.DialOptions) (*rendr.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return l4.Dial(ctx, n.peer, addr, o)
}

// mustDial is dial that fails the test on an error.
func (n *l4rNet) mustDial(addr string) *rendr.Conn {
	n.t.Helper()
	c, err := n.dial(addr, rendr.DialOptions{})
	if err != nil {
		n.t.Fatalf("l4.Dial %s: %v", addr, err)
	}
	return c
}

// passiveEnds returns the passive's EventSessionEnd events so far.
func (n *l4rNet) passiveEnds() []rendr.Event {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]rendr.Event(nil), n.ends...)
}

// passiveDowns counts the passive's session carrier deaths of cause.
func (n *l4rNet) passiveDowns(cause rendr.Cause) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	k := 0
	for _, ev := range n.downs {
		if ev.Cause == cause {
			k++
		}
	}
	return k
}

// l4rSessions returns a Runtime holds that have not ended.
func l4rSessions(rt *rendr.Runtime) int {
	sc := rt.Status().Sessions
	return sc.Open + sc.Pending + sc.Lingering + sc.Orphaned
}

// muxZero waits until both Runtimes hold no shared carrier: a trunk closes
// at its last view (M3-D20).
func (n *l4rNet) muxZero() {
	n.t.Helper()
	msUntil(n.t, 10*time.Second, "the MUX trunks closed at their last view", func() bool {
		dm, pm := n.d.Status().Mux, n.p.Status().Mux
		return dm.Carriers == 0 && dm.Views == 0 && pm.Carriers == 0 && pm.Views == 0
	})
}

// l4rTarget is a real loopback TCP server: every accepted connection runs
// handle on its own goroutine; close joins them.
type l4rTarget struct {
	ln       net.Listener
	accepted atomic.Int64
	handle   func(i int, c *net.TCPConn)
	wg       sync.WaitGroup
	mu       sync.Mutex
	conns    []*net.TCPConn
	once     sync.Once
}

func newL4rTarget(t testing.TB, handle func(i int, c *net.TCPConn)) *l4rTarget {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tg := &l4rTarget{ln: ln, handle: handle}
	tg.wg.Add(1)
	go func() {
		defer tg.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			tc := c.(*net.TCPConn)
			i := int(tg.accepted.Add(1)) - 1
			tg.mu.Lock()
			tg.conns = append(tg.conns, tc)
			tg.mu.Unlock()
			tg.wg.Go(func() { tg.handle(i, tc) })
		}
	}()
	t.Cleanup(tg.close)
	return tg
}

func (tg *l4rTarget) addr() string { return tg.ln.Addr().String() }

// close stops accepting, closes every accepted connection and joins the
// handlers (idempotent).
func (tg *l4rTarget) close() {
	tg.once.Do(func() {
		tg.ln.Close()
		tg.mu.Lock()
		for _, c := range tg.conns {
			c.Close()
		}
		tg.mu.Unlock()
		tg.wg.Wait()
	})
}

// l4rSend writes n bytes of PRNG(seed) to w and returns their SHA-256.
func l4rSend(w io.Writer, n int64, seed uint64) (sum [32]byte, err error) {
	h := sha256.New()
	_, err = io.CopyN(struct{ io.Writer }{w}, io.TeeReader(io.LimitReader(rendrtest.PRNG(seed), n), h), n)
	h.Sum(sum[:0])
	return sum, err
}

// l4rRecv reads r to its end, verifying n bytes of PRNG(seed), and returns
// the SHA-256 of what it read; got, when non-nil, counts the bytes read.
func l4rRecv(r io.Reader, n int64, seed uint64, got *atomic.Int64) (sum [32]byte, err error) {
	h := sha256.New()
	v := rendrtest.NewVerifier(seed, n)
	buf := make([]byte, 64<<10)
	for {
		k, rerr := r.Read(buf)
		if k > 0 {
			h.Write(buf[:k])
			if got != nil {
				got.Add(int64(k))
			}
			if _, werr := v.Write(buf[:k]); werr != nil {
				h.Sum(sum[:0])
				return sum, v.Done(werr)
			}
		}
		if rerr != nil {
			h.Sum(sum[:0])
			return sum, v.Done(rerr)
		}
	}
}

// l4rPRNGSum returns the SHA-256 of n bytes of PRNG(seed).
func l4rPRNGSum(n int64, seed uint64) (sum [32]byte) {
	h := sha256.New()
	io.CopyN(h, rendrtest.PRNG(seed), n)
	h.Sum(sum[:0])
	return sum
}

// l4rIsReset reports a TCP reset-class socket error (the peer's RST): the
// errno symbols on Unix, the WSA numbers the net package returns on
// Windows (WSAECONNRESET, WSAECONNABORTED).
func l4rIsReset(err error) bool {
	var en syscall.Errno
	if !errors.As(err, &en) {
		return false
	}
	if runtime.GOOS == "windows" {
		return en == 10054 || en == 10053
	}
	return en == syscall.ECONNRESET || en == syscall.ECONNABORTED || en == syscall.EPIPE
}

// l4rIsL4Reset reports the session error of a forwarded connection whose
// far socket was reset: the peer's *rendr.AbortError{l4.AbortReset}.
func l4rIsL4Reset(err error) bool {
	var ae *rendr.AbortError
	return errors.As(err, &ae) && ae.Code == l4.AbortReset && ae.Remote
}

// l4rFDs returns the number of this process's open file descriptors on
// Linux that are not pipes (-1 elsewhere: no portable fd count). Pipes are
// left out instead of forcing a garbage collection first: Go pools the
// pipe pairs of splice and closes them only from a finalizer, and a
// collection would also run the finalizer of a socket Forward dropped
// without closing it, hiding the leak this count is meant to see.
func l4rFDs() int {
	if runtime.GOOS != "linux" {
		return -1
	}
	es, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	n := 0
	for _, e := range es {
		l, err := os.Readlink("/proc/self/fd/" + e.Name())
		if err != nil || strings.HasPrefix(l, "pipe:") {
			continue // closed since the listing, or a pipe
		}
		n++
	}
	return n
}

// l4rDone waits (at most within) for c's end.
func l4rDone(t testing.TB, c *rendr.Conn, within time.Duration, what string) {
	t.Helper()
	select {
	case <-c.Done():
	case <-time.After(within):
		t.Fatalf("%s: session %v not done within %v (state %v)", what, c.ID(), within, c.Status().State)
	}
}

// l4rDeadOf reports whether st lists a dead carrier of cause.
func l4rDeadOf(st rendr.SessionStatus, cause rendr.Cause) bool {
	for _, c := range st.Carriers {
		if c.State == rendr.CarrierDead && c.DeathCause == cause {
			return true
		}
	}
	return false
}

// l4rRelay forwards TCP connections byte for byte from its listener to a
// target and can reset every connection it holds (SO_LINGER 0 and Close on
// both sockets: both rendr ends get a TCP RST).
type l4rRelay struct {
	ln     net.Listener
	target string
	mu     sync.Mutex
	pairs  map[*net.TCPConn]*net.TCPConn // dialer side → passive side
	wg     sync.WaitGroup
	once   sync.Once
}

func newL4rRelay(t testing.TB, target string) *l4rRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &l4rRelay{ln: ln, target: target, pairs: map[*net.TCPConn]*net.TCPConn{}}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				continue
			}
			a, bb := c.(*net.TCPConn), b.(*net.TCPConn)
			r.mu.Lock()
			r.pairs[a] = bb
			r.mu.Unlock()
			r.wg.Go(func() { r.serve(a, bb) })
		}
	}()
	t.Cleanup(r.close)
	return r
}

func (r *l4rRelay) addr() string { return r.ln.Addr().String() }

// serve copies both ways, half-closing each direction at its end, and
// closes both sockets once both directions ended.
func (r *l4rRelay) serve(a, b *net.TCPConn) {
	var wg sync.WaitGroup
	wg.Go(func() { io.Copy(b, a); b.CloseWrite() })
	wg.Go(func() { io.Copy(a, b); a.CloseWrite() })
	wg.Wait()
	r.mu.Lock()
	delete(r.pairs, a)
	r.mu.Unlock()
	a.Close()
	b.Close()
}

// reset resets every relayed connection and returns how many there were.
func (r *l4rRelay) reset() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := 0
	for a, b := range r.pairs {
		a.SetLinger(0)
		b.SetLinger(0)
		a.Close()
		b.Close()
		delete(r.pairs, a)
		k++
	}
	return k
}

func (r *l4rRelay) close() {
	r.once.Do(func() {
		r.ln.Close()
		r.reset()
		r.wg.Wait()
	})
}

// l4rFlow is one direction of a forwarded exchange: the digests of what
// was sent and read, and how each side ended.
type l4rFlow struct {
	sent, read       [32]byte
	sendErr, readErr error
	got              atomic.Int64 // bytes read so far
}

// check reports the flow's failures: an error on either side, or digests
// that differ.
func (f *l4rFlow) check(t testing.TB, name string) {
	t.Helper()
	if f.sendErr != nil {
		t.Errorf("%s: send: %v", name, f.sendErr)
	}
	if f.readErr != nil {
		t.Errorf("%s: read: %v", name, f.readErr)
	}
	if f.sent != f.read {
		t.Errorf("%s: SHA-256 sent %x, read %x", name, f.sent[:8], f.read[:8])
	}
}

// TestL4RealTCPE2E (§A12.4; plan:660): an L4 session through l4.Dial and
// l4.Server over carrier/tcp, relayed by a byte-for-byte TCP relay, to a
// real loopback target. 64 MiB each way (8 MiB under -race, the same
// criteria), each side half-closing after its last byte; once both
// directions passed a quarter, the relay resets the carrier (SO_LINGER 0
// on both of its sockets: a TCP RST at both rendr ends). Stimulus: both
// directions were mid-transfer at the reset, and both ends of the session
// list a carrier dead of transport_error. Load: every byte both ways.
// Integrity: SHA-256 and PRNG content both ways; the target accepted
// exactly one connection (the migration never reached it) and read the
// client's FIN after the last byte; the client read the target's FIN after
// the last byte; the session ends clean (io.EOF) and the Server counts one
// confirmed connection and no refusal.
func TestL4RealTCPE2E(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	size := int64(64 << 20)
	if l4rRace {
		size = 8 << 20
	}
	const upSeed, downSeed = 41, 42
	var up, down l4rFlow // up: client → target; down: target → client
	targetDone := make(chan struct{})
	tg := newL4rTarget(t, func(i int, c *net.TCPConn) {
		defer c.Close()
		if i != 0 {
			return // a second connection fails the test below
		}
		defer close(targetDone)
		var wg sync.WaitGroup
		wg.Go(func() {
			if down.sent, down.sendErr = l4rSend(c, size, downSeed); down.sendErr == nil {
				down.sendErr = c.CloseWrite()
			}
		})
		up.read, up.readErr = l4rRecv(c, size, upSeed, &up.got)
		wg.Wait()
	})
	n := newL4rNet(t, l4rOpts{relay: true})
	c := n.mustDial(tg.addr())
	start := time.Now()
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		var wg sync.WaitGroup
		wg.Go(func() {
			if up.sent, up.sendErr = l4rSend(c, size, upSeed); up.sendErr == nil {
				up.sendErr = c.CloseWrite()
			}
		})
		down.read, down.readErr = l4rRecv(c, size, downSeed, &down.got)
		wg.Wait()
	}()

	// The reset, mid-transfer in both directions.
	msUntil(t, 30*time.Second, "both directions past a quarter", func() bool {
		return up.got.Load() >= size/4 && down.got.Load() >= size/4
	})
	if k := n.relay.reset(); k != 1 {
		t.Fatalf("stimulus: the relay held %d connections at the reset, want the session's one carrier", k)
	}
	upAt, downAt := up.got.Load(), down.got.Load()
	resetAt := time.Since(start)

	for _, ch := range []chan struct{}{clientDone, targetDone} {
		select {
		case <-ch:
		case <-time.After(60 * time.Second):
			t.Fatalf("transfer not done within 60 s (up %d, down %d of %d bytes)", up.got.Load(), down.got.Load(), size)
		}
	}
	took := time.Since(start)
	up.check(t, "client → target")
	down.check(t, "target → client")
	if up.sent != l4rPRNGSum(size, upSeed) || down.sent != l4rPRNGSum(size, downSeed) {
		t.Errorf("load: the senders' digests are not those of %d bytes each way", size)
	}
	if upAt >= size || downAt >= size {
		t.Errorf("stimulus: at the reset up %d and down %d of %d bytes were read, want both mid-transfer", upAt, downAt, size)
	}
	if !l4rDeadOf(c.Status(), rendr.CauseTransportError) {
		t.Errorf("stimulus: the dialer's carriers %+v list none dead of transport_error", c.Status().Carriers)
	}
	if got := tg.accepted.Load(); got != 1 {
		t.Errorf("the target accepted %d connections, want 1", got)
	}
	l4rDone(t, c, 10*time.Second, "after both FINs")
	if err := c.Status().Err; err != io.EOF {
		t.Errorf("the dialer's session ended with %v, want io.EOF", err)
	}
	c.Close()
	// The passive's EventSessionEnd reaches OnEvent asynchronously (L53),
	// possibly after the Server's forward ended: wait for it, then judge it.
	msUntil(t, 10*time.Second, "the Server's forward ended and the passive's end reported", func() bool {
		return n.srv.Status().Live == 0 && len(n.passiveEnds()) > 0
	})
	ends := n.passiveEnds()
	if len(ends) != 1 || ends[0].Err != io.EOF {
		t.Errorf("the passive's session ends %+v, want one with io.EOF", ends)
	}
	if k := n.passiveDowns(rendr.CauseTransportError); k == 0 {
		t.Errorf("stimulus: the passive saw no session carrier die of transport_error")
	}
	if ss := n.srv.Status(); ss.Confirmed != 1 || ss.Rejected != 0 {
		t.Errorf("Server: %+v, want 1 confirmed, 0 rejected", ss)
	}
	t.Logf("%d bytes each way in %v; reset at %v (up %d, down %d)", size, took.Round(time.Millisecond), resetAt.Round(time.Millisecond), upAt, downAt)
	n.muxZero()
	n.close()
}

// TestServeRefusedRealSocket (§A12.4, §A8.1): l4.Dial to a loopback port
// nothing listens on. The Server's default dialer gets the OS's refusal
// and classifies it: the dialer's error is a *rendr.RejectError whose
// l4.CodeOf is CodeRefused, with the code's fixed text, never the raw dial
// error. Bound: Linux answers at once (1 s); Windows retries a refused
// loopback connect for about 2 s before it reports it (3 s). Stimulus: the
// port was bound and released, so the connect reached a closed port.
func TestServeRefusedRealSocket(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := closed.Addr().String()
	closed.Close()
	n := newL4rNet(t, l4rOpts{})
	bound := time.Second
	if runtime.GOOS == "windows" {
		bound = 3 * time.Second
	}
	start := time.Now()
	c, err := n.dial(addr, rendr.DialOptions{})
	took := time.Since(start)
	if err == nil {
		c.Close()
		t.Fatalf("l4.Dial to the closed port %s succeeded", addr)
	}
	code, ok := l4.CodeOf(err)
	if !ok || code != l4.CodeRefused {
		t.Fatalf("l4.Dial error %v: code %v (l4 %v), want %v", err, code, ok, l4.CodeRefused)
	}
	var re *rendr.RejectError
	if !errors.As(err, &re) || !errors.Is(err, rendr.ErrRejected) || re.Msg != l4.CodeRefused.String() {
		t.Errorf("l4.Dial error %#v: want a *rendr.RejectError with the fixed text %q", err, l4.CodeRefused.String())
	}
	if took > bound {
		t.Errorf("the refusal took %v, want ≤ %v on %s", took, bound, runtime.GOOS)
	}
	ss := n.srv.Status()
	if ss.Rejected != 1 || ss.ByCode[l4.CodeRefused] != 1 || ss.Confirmed != 0 || ss.LastErr == nil {
		t.Errorf("Server: %+v, want one CodeRefused refusal and its raw error kept", ss)
	}
	t.Logf("refused in %v; the Server kept %v", took.Round(time.Millisecond), ss.LastErr)
	n.close()
}

// TestL4RealTargetResetMapsToAbort (§A12.4, §A7.3; L02): the target sends
// 256 KiB, waits until the client read all of it, then closes with
// SO_LINGER 0 (a TCP RST mid-stream, no FIN). The client's next Read
// returns the peer's *rendr.AbortError{l4.AbortReset}, never io.EOF, and
// every byte before it matched (PRNG content). Stimulus: the target's
// close was a reset (SetLinger(0) succeeded) while the stream was open.
// The session ends on both ends, and the Server's forward ends.
func TestL4RealTargetResetMapsToAbort(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	const size, seed = 256 << 10, 51
	var got atomic.Int64
	readAll := make(chan struct{})
	linger := make(chan error, 1) // the target's SO_LINGER 0, or its send error
	tg := newL4rTarget(t, func(i int, c *net.TCPConn) {
		defer c.Close()
		if _, err := l4rSend(c, size, seed); err != nil {
			linger <- err
			return
		}
		select {
		case <-readAll:
		case <-time.After(20 * time.Second):
		}
		linger <- c.SetLinger(0)
	})
	n := newL4rNet(t, l4rOpts{})
	c := n.mustDial(tg.addr())
	v := rendrtest.NewVerifier(seed, size)
	buf := make([]byte, 64<<10)
	var rerr error
	for {
		k, err := c.Read(buf)
		if k > 0 {
			if _, werr := v.Write(buf[:k]); werr != nil {
				t.Fatalf("content: %v", werr)
			}
			if got.Add(int64(k)) == size {
				close(readAll)
			}
		}
		if err != nil {
			rerr = err
			break
		}
	}
	if got.Load() != size {
		t.Fatalf("the client read %d of %d bytes before %v", got.Load(), size, rerr)
	}
	if err := <-linger; err != nil {
		t.Fatalf("stimulus: the target's SO_LINGER 0: %v", err)
	}
	if rerr == io.EOF || !l4rIsL4Reset(rerr) {
		t.Errorf("the client's Read after the target's reset returned %v, want the peer's *rendr.AbortError{l4.AbortReset}", rerr)
	}
	l4rDone(t, c, 10*time.Second, "after the reset")
	c.Close()
	// The passive's EventSessionEnd reaches OnEvent asynchronously (L53),
	// possibly after the Server's forward ended: wait for it, then judge it.
	msUntil(t, 10*time.Second, "the Server's forward ended and the passive's end reported", func() bool {
		return n.srv.Status().Live == 0 && len(n.passiveEnds()) > 0
	})
	if ends := n.passiveEnds(); len(ends) != 1 || ends[0].Err == io.EOF {
		t.Errorf("the passive's session ends %+v, want one that is not io.EOF", ends)
	}
	t.Logf("the client's Read: %v", rerr)
	n.close()
}

// TestForwardCleanCloseNoReset_L05 (§A12.4, §A7.3, R1-1; L05): after a
// clean exchange the target reads every byte and then EOF, never
// ECONNRESET, also when the session ends while the passive's Forward still
// writes the tail to the target. The target answers 4 KiB and FINs at
// once, then reads the client's 1 MiB request to EOF; the client sends the
// request, half-closes and reads the answer to EOF. The Server's Dial hook
// hands Forward the real target socket behind a gate that holds the Write
// carrying the request's last byte until the passive's session has ended:
// the session ends clean (DONE both ways) once the passive application
// read the last byte (R1-1), so a Forward that reset the target at the
// session's end would destroy the tail and the FIN (the gate opens 50 ms
// after the end, so that such a reset lands first). Stimulus: the
// request's tail had not reached the target when the passive's session
// ended (the gated Write had not completed; whether pump B was already
// blocked in it or called it later in the window is logged: a reset at the
// end fails that Write either way). Integrity: the
// target read all 1 MiB (SHA-256, PRNG content) and then io.EOF; the
// client read the answer and io.EOF; both ends ended io.EOF; Forward closed
// the target socket without SO_LINGER 0.
func TestForwardCleanCloseNoReset_L05(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	const (
		reqSize, respSize = 1 << 20, 4 << 10
		reqSeed, respSeed = 61, 62
	)
	var req, resp l4rFlow
	targetDone := make(chan struct{})
	tg := newL4rTarget(t, func(i int, c *net.TCPConn) {
		defer c.Close()
		if i != 0 {
			return
		}
		defer close(targetDone)
		if resp.sent, resp.sendErr = l4rSend(c, respSize, respSeed); resp.sendErr == nil {
			resp.sendErr = c.CloseWrite()
		}
		req.read, req.readErr = l4rRecv(c, reqSize, reqSeed, &req.got)
	})
	gate := &l4rGate{open: make(chan struct{}), total: reqSize}
	srv := &l4.Server{Dial: func(ctx context.Context, r l4.Request) (net.Conn, error) {
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", r.Addr)
		if err != nil {
			return nil, err
		}
		gate.TCPConn = c.(*net.TCPConn)
		return gate, nil
	}}
	n := newL4rNet(t, l4rOpts{srv: srv, cfg: func(_, p *rendr.Config) {
		prev := p.OnEvent
		p.OnEvent = func(ev rendr.Event) {
			prev(ev)
			if ev.Kind == rendr.EventSessionEnd {
				gate.release()
			}
		}
	}})
	c := n.mustDial(tg.addr())
	sent, sendErr := l4rSend(c, reqSize, reqSeed)
	if sendErr == nil {
		sendErr = c.CloseWrite()
	}
	resp.read, resp.readErr = l4rRecv(c, respSize, respSeed, &resp.got)
	select {
	case <-targetDone:
	case <-time.After(30 * time.Second):
		t.Fatalf("the target did not finish within 30 s (%d of %d request bytes read)", req.got.Load(), reqSize)
	}
	req.sent, req.sendErr = sent, sendErr
	req.check(t, "request (client → target)")
	resp.check(t, "answer (target → client)")
	if l4rIsReset(req.readErr) {
		t.Errorf("the target read a reset after a clean exchange: %v", req.readErr)
	}
	l4rDone(t, c, 10*time.Second, "after the clean exchange")
	if err := c.Status().Err; err != io.EOF {
		t.Errorf("the dialer's session ended with %v, want io.EOF", err)
	}
	c.Close()
	// The passive's EventSessionEnd reaches OnEvent asynchronously (L53),
	// possibly after the Server's forward ended: wait for it, then judge it.
	msUntil(t, 10*time.Second, "the Server's forward ended and the passive's end reported", func() bool {
		return n.srv.Status().Live == 0 && len(n.passiveEnds()) > 0
	})
	if ends := n.passiveEnds(); len(ends) != 1 || ends[0].Err != io.EOF {
		t.Errorf("the passive's session ends %+v, want one with io.EOF", ends)
	}
	if !gate.tailOutAtEnd.Load() {
		t.Errorf("stimulus: the request's tail had reached the target before the passive's session ended")
	}
	t.Logf("at the passive's session end the tail Write was %s", map[bool]string{true: "blocked in the gate", false: "not yet called"}[gate.waitingAtEnd.Load()])
	if gate.lingered.Load() {
		t.Errorf("Forward set SO_LINGER 0 on the target socket after a clean exchange")
	}
	n.muxZero()
	n.close()
}

// l4rGate is a target socket whose Write carrying byte total is held until
// l4rGateWindow after release (the passive's session end). It records
// whether the tail was still outstanding at the release, whether that
// Write was already waiting then, and whether SetLinger(0) was called.
type l4rGate struct {
	*net.TCPConn
	total        int64
	written      atomic.Int64
	waiting      atomic.Bool
	tailOutAtEnd atomic.Bool
	waitingAtEnd atomic.Bool
	lingered     atomic.Bool
	open         chan struct{}
	once         sync.Once
}

// release opens the gate l4rGateWindow after the passive's session end:
// the window in which a Forward that resets its local at a clean session
// end would act (R1-1's defect); a correct Forward's verdict does not
// depend on it.
func (g *l4rGate) release() {
	g.once.Do(func() {
		g.waitingAtEnd.Store(g.waiting.Load())
		g.tailOutAtEnd.Store(g.written.Load() < g.total)
		time.AfterFunc(l4rGateWindow, func() { close(g.open) })
	})
}

// l4rGateWindow is the time l4rGate stays closed after the session end.
const l4rGateWindow = 50 * time.Millisecond

func (g *l4rGate) Write(p []byte) (int, error) {
	if g.written.Load()+int64(len(p)) >= g.total {
		g.waiting.Store(true)
		select {
		case <-g.open:
		case <-time.After(10 * time.Second):
		}
	}
	k, err := g.TCPConn.Write(p)
	g.written.Add(int64(k))
	return k, err
}

func (g *l4rGate) SetLinger(sec int) error {
	if sec == 0 {
		g.lingered.Store(true)
	}
	return g.TCPConn.SetLinger(sec)
}

// TestL4RealHalfClose_L04 (§A12.4, §A7.2; plan:660, L04): half-closes
// cross the L4 forward in both orders over real sockets. "client first":
// the client sends 64 KiB and half-closes; the target reads to EOF, then
// answers 1 MiB and FINs. "target first" (HTTP/1.0 style): the target
// answers 1 MiB and FINs at once while the client is still sending; the
// client reads the answer to EOF, sends on (its second 32 KiB) and
// half-closes later. Stimulus: the first FIN of each order crossed while
// the other direction was still open: in "client first" the target read
// its EOF before it wrote a byte (checked); in "target first" the client
// reads the answer to its EOF before it writes its second half (by
// construction), and the target then reads that half (the integrity
// check). Integrity: SHA-256 and PRNG content both
// ways, each direction ended by io.EOF after its last byte; one target
// connection; both ends of the session end io.EOF.
func TestL4RealHalfClose_L04(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	const (
		reqSize, respSize = 64 << 10, 1 << 20
		reqSeed, respSeed = 71, 72
	)
	t.Run("client first", func(t *testing.T) {
		var req, resp l4rFlow
		var reqDoneFirst atomic.Bool
		targetDone := make(chan struct{})
		tg := newL4rTarget(t, func(i int, c *net.TCPConn) {
			defer c.Close()
			if i != 0 {
				return
			}
			defer close(targetDone)
			req.read, req.readErr = l4rRecv(c, reqSize, reqSeed, &req.got)
			reqDoneFirst.Store(req.readErr == nil)
			if resp.sent, resp.sendErr = l4rSend(c, respSize, respSeed); resp.sendErr == nil {
				resp.sendErr = c.CloseWrite()
			}
		})
		n := newL4rNet(t, l4rOpts{})
		c := n.mustDial(tg.addr())
		var sent [32]byte
		var sendErr error
		if sent, sendErr = l4rSend(c, reqSize, reqSeed); sendErr == nil {
			sendErr = c.CloseWrite()
		}
		resp.read, resp.readErr = l4rRecv(c, respSize, respSeed, &resp.got)
		l4rHalfCloseEnd(t, n, c, tg, targetDone, sent, sendErr, &req, &resp)
		if !reqDoneFirst.Load() {
			t.Errorf("stimulus: the target did not read the client's FIN before it answered")
		}
	})
	t.Run("target first", func(t *testing.T) {
		var req, resp l4rFlow
		targetDone := make(chan struct{})
		tg := newL4rTarget(t, func(i int, c *net.TCPConn) {
			defer c.Close()
			if i != 0 {
				return
			}
			defer close(targetDone)
			var wg sync.WaitGroup
			wg.Go(func() {
				if resp.sent, resp.sendErr = l4rSend(c, respSize, respSeed); resp.sendErr == nil {
					resp.sendErr = c.CloseWrite()
				}
			})
			req.read, req.readErr = l4rRecv(c, reqSize, reqSeed, &req.got)
			wg.Wait()
		})
		n := newL4rNet(t, l4rOpts{})
		c := n.mustDial(tg.addr())
		h := sha256.New()
		src := io.TeeReader(io.LimitReader(rendrtest.PRNG(reqSeed), reqSize), h)
		if _, err := io.CopyN(struct{ io.Writer }{c}, src, reqSize/2); err != nil {
			t.Fatalf("the request's first half: %v", err)
		}
		resp.read, resp.readErr = l4rRecv(c, respSize, respSeed, &resp.got)
		if resp.readErr != nil {
			t.Fatalf("the answer before the request's second half: %v", resp.readErr)
		}
		_, sendErr := io.CopyN(struct{ io.Writer }{c}, src, reqSize-reqSize/2)
		if sendErr == nil {
			sendErr = c.CloseWrite()
		}
		var sent [32]byte
		h.Sum(sent[:0])
		l4rHalfCloseEnd(t, n, c, tg, targetDone, sent, sendErr, &req, &resp)
	})
}

// l4rHalfCloseEnd checks the end of a half-close exchange and closes the
// fixture: both flows intact (sent and sendErr are the client's request
// side), one target connection, both ends io.EOF.
func l4rHalfCloseEnd(t *testing.T, n *l4rNet, c *rendr.Conn, tg *l4rTarget, targetDone chan struct{}, sent [32]byte, sendErr error, req, resp *l4rFlow) {
	t.Helper()
	select {
	case <-targetDone:
	case <-time.After(30 * time.Second):
		t.Fatalf("the target did not finish within 30 s")
	}
	req.sent, req.sendErr = sent, sendErr
	req.check(t, "request (client → target)")
	resp.check(t, "answer (target → client)")
	if got := tg.accepted.Load(); got != 1 {
		t.Errorf("the target accepted %d connections, want 1", got)
	}
	l4rDone(t, c, 10*time.Second, "after both FINs")
	if err := c.Status().Err; err != io.EOF {
		t.Errorf("the dialer's session ended with %v, want io.EOF", err)
	}
	c.Close()
	// The passive's EventSessionEnd reaches OnEvent asynchronously (L53),
	// possibly after the Server's forward ended: wait for it, then judge it.
	msUntil(t, 10*time.Second, "the Server's forward ended and the passive's end reported", func() bool {
		return n.srv.Status().Live == 0 && len(n.passiveEnds()) > 0
	})
	if ends := n.passiveEnds(); len(ends) != 1 || ends[0].Err != io.EOF {
		t.Errorf("the passive's session ends %+v, want one with io.EOF", ends)
	}
	n.muxZero()
	n.close()
	tg.close()
}

// l4rTrack is a target socket the Server forwards to, recording whether
// Forward reset it (SetLinger(0)) and when it closed it.
type l4rTrack struct {
	*net.TCPConn
	lingered atomic.Bool
	closedAt atomic.Pointer[time.Time]
}

func (k *l4rTrack) SetLinger(sec int) error {
	if sec == 0 {
		k.lingered.Store(true)
	}
	return k.TCPConn.SetLinger(sec)
}

func (k *l4rTrack) Close() error {
	now := time.Now()
	k.closedAt.CompareAndSwap(nil, &now)
	return k.TCPConn.Close()
}

// l4rTracker is a Server Dial hook that dials the target and hands Forward
// an l4rTrack.
type l4rTracker struct {
	mu     sync.Mutex
	tracks []*l4rTrack
}

func (tr *l4rTracker) dial(ctx context.Context, r l4.Request) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", r.Addr)
	if err != nil {
		return nil, err
	}
	k := &l4rTrack{TCPConn: c.(*net.TCPConn)}
	tr.mu.Lock()
	tr.tracks = append(tr.tracks, k)
	tr.mu.Unlock()
	return k, nil
}

func (tr *l4rTracker) all() []*l4rTrack {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return append([]*l4rTrack(nil), tr.tracks...)
}

// l4rProbe writes one byte to c every 5 ms until a write fails (at most
// within) and returns nil once one failed: the socket's peer is gone.
func l4rProbe(c net.Conn, within time.Duration) error {
	deadline := time.Now().Add(within)
	for {
		if _, err := c.Write([]byte{0}); err != nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("writes to the target socket still succeed %v after its release", within)
		}
		time.Sleep(5 * time.Millisecond) // polling
	}
}

// TestStalledTargetReleasedAfterClose is the real-socket twin of msess's
// target test (§A12.3; plan:661, M4-D48, PA-49, R1-22; the synctest
// version is in internal/scenario/l4): five selector L4 sessions through
// l4.Dial and l4.Server over carrier/tcp to a real loopback target that
// reads the request to its FIN and then holds the connection open, never
// answering; the dialer's Linger is 2 s (testhooks). Each client writes an
// HTTP-like request and half-closes; once the five targets read their
// FINs (sanity: five passive sessions and five forwards live), each client
// Closes. Stimulus: nothing ends the stalled sessions before Linger (no
// release earlier than 2 s after the Close). Criteria: every target socket
// is reset by Forward (SO_LINGER 0, then Close) within Linger + 1 s of the
// Close; the passive sessions end with the peer's *rendr.AbortError
// {AbortLinger}, never AbortIdle; the clients' sessions end with
// net.ErrClosed; the Server forwards nothing; each target's socket then
// fails a write within 1 s (it saw the FIN and then the reset) and is
// closed; nothing leaks.
func TestStalledTargetReleasedAfterClose(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	const (
		sessions = 5
		linger   = 2 * time.Second
	)
	req := []byte("GET /stall HTTP/1.1\r\nHost: target\r\n\r\n")
	var fins atomic.Int64
	probe := make(chan struct{})
	probes := make(chan error, sessions)
	tg := newL4rTarget(t, func(i int, c *net.TCPConn) {
		defer c.Close()
		got, err := io.ReadAll(c) // to the client's FIN
		if err != nil || !bytes.Equal(got, req) {
			probes <- fmt.Errorf("target %d read %q, %v; want the request and its FIN", i, got, err)
			return
		}
		fins.Add(1)
		select { // stalled: holds the connection, never answers
		case <-probe:
		case <-time.After(30 * time.Second):
		}
		probes <- l4rProbe(c, time.Second)
	})
	tr := &l4rTracker{}
	n := newL4rNet(t, l4rOpts{dov: &testhooks.Overrides{Linger: linger}, srv: &l4.Server{Dial: tr.dial}})
	cs := make([]*rendr.Conn, sessions)
	for i := range cs {
		cs[i] = n.mustDial(tg.addr())
		if _, err := cs[i].Write(req); err != nil {
			t.Fatalf("client %d Write: %v", i, err)
		}
		if err := cs[i].CloseWrite(); err != nil {
			t.Fatalf("client %d CloseWrite: %v", i, err)
		}
	}
	msUntil(t, 10*time.Second, "five stalled targets read their FINs, five forwards live", func() bool {
		return fins.Load() == sessions && n.srv.Status().Live == sessions && l4rSessions(n.p) == sessions
	})
	if got := tg.accepted.Load(); got != sessions {
		t.Fatalf("the target accepted %d connections, want %d", got, sessions)
	}

	t0 := time.Now()
	for _, c := range cs {
		c.Close()
	}
	bound := linger + time.Second
	msUntil(t, time.Until(t0.Add(bound)), "every target socket released", func() bool {
		for _, k := range tr.all() {
			if k.closedAt.Load() == nil {
				return false
			}
		}
		return true
	})
	for i, k := range tr.all() {
		at := k.closedAt.Load().Sub(t0)
		if !k.lingered.Load() {
			t.Errorf("target socket %d was closed without SO_LINGER 0 (want a reset)", i)
		}
		if at < linger || at > bound {
			t.Errorf("target socket %d released %v after the Close, want in [%v, %v]", i, at.Round(time.Millisecond), linger, bound)
		}
	}
	msUntil(t, time.Until(t0.Add(bound))+100*time.Millisecond, "the passive sessions ended", func() bool {
		return len(n.passiveEnds()) == sessions && n.srv.Status().Live == 0 && l4rSessions(n.p) == 0
	})
	for _, ev := range n.passiveEnds() {
		var ae *rendr.AbortError
		if !errors.As(ev.Err, &ae) || ae.Code != rendr.AbortLinger || !ae.Remote {
			t.Errorf("a passive session ended with %v, want the peer's AbortLinger (never AbortIdle)", ev.Err)
		}
		if at := ev.Time.Sub(t0); at > bound {
			t.Errorf("a passive session ended %v after the Close, want ≤ %v", at.Round(time.Millisecond), bound)
		}
	}
	for i, c := range cs {
		l4rDone(t, c, time.Until(t0.Add(bound))+100*time.Millisecond, "a closed client")
		if err := c.Status().Err; !errors.Is(err, net.ErrClosed) {
			t.Errorf("client %d's session ended with %v, want net.ErrClosed (its Linger expired)", i, err)
		}
	}
	var rel []time.Duration
	for _, k := range tr.all() {
		rel = append(rel, k.closedAt.Load().Sub(t0).Round(time.Millisecond))
	}
	t.Logf("Linger %v: target sockets released %v after the Close", linger, rel)
	close(probe)
	for range sessions {
		if err := <-probes; err != nil {
			t.Error(err)
		}
	}
	n.muxZero()
	n.close()
	tg.close()
}

// TestIdleSessionExpires is the real-socket twin of msess's idle test
// (§A12.3; plan:661, M4-D41, M4-D48; the synctest version is in
// internal/scenario/l4): one L4 session over carrier/tcp to a real
// loopback target; the client writes "hello", the target reads it and
// then waits in Read; nothing else moves. Conn.SetIdleTimeout and the
// Server's IdleTimeout are 3 s, below the 10 s floor through testhooks'
// MinIdleTimeout. Criteria: both ends end within 3 s + 1 s of the last
// acknowledged byte and not before 3 s after the Write; the client's
// pending Read returns rendr.ErrIdleTimeout or the peer's
// *rendr.AbortError{AbortIdle}, never io.EOF; the passive's session ends
// the same way; Forward resets the target, whose Read returns a reset; the
// Server forwards nothing and the passive holds no session; on Linux the
// process's fd count is back at its count before the Dial within 1 s.
func TestIdleSessionExpires(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	const idle = 3 * time.Second
	hello := []byte("hello")
	type ended struct {
		err error
		at  time.Time
	}
	target := make(chan ended, 1)
	tg := newL4rTarget(t, func(i int, c *net.TCPConn) {
		defer c.Close()
		buf := make([]byte, len(hello))
		if _, err := io.ReadFull(c, buf); err != nil || !bytes.Equal(buf, hello) {
			target <- ended{fmt.Errorf("the target read %q, %v", buf, err), time.Now()}
			return
		}
		_, err := c.Read(make([]byte, 1)) // waits: nothing else moves
		target <- ended{err, time.Now()}
	})
	ov := &testhooks.Overrides{MinIdleTimeout: idle}
	n := newL4rNet(t, l4rOpts{dov: ov, pov: ov, srv: &l4.Server{IdleTimeout: idle}})
	fd0 := l4rFDs()
	c := n.mustDial(tg.addr())
	if err := c.SetIdleTimeout(idle); err != nil {
		t.Fatalf("SetIdleTimeout(%v): %v", idle, err)
	}
	tw := time.Now()
	if _, err := c.Write(hello); err != nil {
		t.Fatalf("Write: %v", err)
	}
	read := make(chan ended, 1)
	go func() {
		_, err := c.Read(make([]byte, 1))
		read <- ended{err, time.Now()}
	}()
	msUntil(t, 5*time.Second, "the hello acknowledged as delivered", func() bool { return c.Status().AckedBytes == uint64(len(hello)) })
	tAck := time.Now()
	bound := tAck.Add(idle + time.Second)
	isIdle := func(err error) bool {
		var ae *rendr.AbortError
		return errors.Is(err, rendr.ErrIdleTimeout) || errors.As(err, &ae) && ae.Code == rendr.AbortIdle
	}

	var r ended
	select {
	case r = <-read:
	case <-time.After(time.Until(bound)):
		t.Fatalf("the client's Read did not return within %v of the last acknowledged byte", idle+time.Second)
	}
	if r.err == io.EOF || !isIdle(r.err) {
		t.Errorf("the client's Read returned %v, want rendr.ErrIdleTimeout or the peer's AbortIdle (never io.EOF)", r.err)
	}
	if d := r.at.Sub(tw); d < idle {
		t.Errorf("the client's Read returned %v after the Write, before the idle timeout %v", d.Round(time.Millisecond), idle)
	}
	l4rDone(t, c, time.Until(bound)+100*time.Millisecond, "the idle client")
	msUntil(t, time.Until(bound)+100*time.Millisecond, "the passive's session ended and its forward released", func() bool {
		return len(n.passiveEnds()) == 1 && n.srv.Status().Live == 0 && l4rSessions(n.p) == 0
	})
	ev := n.passiveEnds()[0]
	if !isIdle(ev.Err) {
		t.Errorf("the passive's session ended with %v, want rendr.ErrIdleTimeout or the peer's AbortIdle", ev.Err)
	}
	if d := ev.Time.Sub(tw); d < idle || ev.Time.After(bound) {
		t.Errorf("the passive's session ended %v after the Write, want in [%v, %v + the ACK]", d.Round(time.Millisecond), idle, idle+time.Second)
	}
	select {
	case e := <-target:
		if !l4rIsReset(e.err) {
			t.Errorf("the target's Read returned %v, want a reset (Forward resets the target at the idle end)", e.err)
		}
		if e.at.After(bound.Add(100 * time.Millisecond)) {
			t.Errorf("the target was reset %v after the last acknowledged byte, want ≤ %v", e.at.Sub(tAck).Round(time.Millisecond), idle+time.Second)
		}
	case <-time.After(time.Second):
		t.Fatalf("the target's Read did not return within 1 s of the session's end")
	}
	if fd0 >= 0 {
		msUntil(t, time.Second, "the process's fd count back at its count before the Dial", func() bool { return l4rFDs() <= fd0 })
	}
	t.Logf("idle %v: the client's Read returned %v after the last acknowledged byte (%v), the passive ended after %v", idle,
		r.at.Sub(tAck).Round(time.Millisecond), r.err, ev.Time.Sub(tAck).Round(time.Millisecond))
	c.Close()
	n.muxZero()
	n.close()
	tg.close()
}

// TestL4RealReclaim (§A12.4; L52): 200 L4 sessions over carrier/tcp, eight
// at a time, each a 16 KiB echo through a real loopback target with a
// half-close at both ends; the Server's Dial hook (l4rTracker) hands
// Forward each real target socket and records its release. Load and
// integrity: every echo verified (PRNG content) and ended by io.EOF; 200
// target connections, 200 confirmed, no refusal. Reclaim: afterwards both
// Runtimes hold no session, buffered byte or shared carrier, the Server
// forwards nothing, Forward closed every target socket it was handed
// (plainly: a clean end never sets SO_LINGER 0), the goroutine count is
// back at its baseline taken after one warm-up session, and on Linux the
// non-pipe entries of /proc/self/fd are back at their baseline (l4rFDs);
// Windows has no portable fd count, so that check runs on Linux only (the
// tracked closes, the goroutine and the Status checks run everywhere).
func TestL4RealReclaim(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	const (
		sessions = 200
		workers  = 8
		size     = 16 << 10
	)
	tg := newL4rTarget(t, func(i int, c *net.TCPConn) {
		defer c.Close()
		buf := make([]byte, 32<<10)
		for {
			k, err := c.Read(buf)
			if k > 0 {
				if _, werr := c.Write(buf[:k]); werr != nil {
					return
				}
			}
			if err != nil {
				if err == io.EOF {
					c.CloseWrite() // the forwarded FIN arrived: answer with ours, then close
				}
				return
			}
		}
	})
	tr := &l4rTracker{}
	n := newL4rNet(t, l4rOpts{srv: &l4.Server{Dial: tr.dial}})
	echo := func(seed uint64) error {
		c, err := n.dial(tg.addr(), rendr.DialOptions{})
		if err != nil {
			return err
		}
		defer c.Close()
		sendErr := make(chan error, 1)
		go func() {
			_, err := l4rSend(c, size, seed)
			if err == nil {
				err = c.CloseWrite()
			}
			sendErr <- err
		}()
		if _, err := l4rRecv(c, size, seed, nil); err != nil {
			return fmt.Errorf("echo %d: %w", seed, err)
		}
		if err := <-sendErr; err != nil {
			return fmt.Errorf("echo %d send: %w", seed, err)
		}
		select {
		case <-c.Done():
		case <-time.After(10 * time.Second):
			return fmt.Errorf("echo %d: session not done 10 s after both FINs", seed)
		}
		if err := c.Status().Err; err != io.EOF {
			return fmt.Errorf("echo %d: session ended with %v, want io.EOF", seed, err)
		}
		return nil
	}
	idle := func() bool {
		ss := n.srv.Status()
		return ss.Live == 0 && ss.Dialing == 0 && l4rSessions(n.d) == 0 && l4rSessions(n.p) == 0 &&
			n.d.Status().BufferedBytes == 0 && n.p.Status().BufferedBytes == 0 &&
			n.d.Status().Mux.Carriers == 0 && n.p.Status().Mux.Carriers == 0
	}
	// Warm-up: the baselines include whatever the first session starts
	// for good.
	if err := echo(1000); err != nil {
		t.Fatal(err)
	}
	msUntil(t, 10*time.Second, "idle after the warm-up session", idle)
	g0, fd0 := runtime.NumGoroutine(), l4rFDs()

	next := atomic.Int64{}
	errs := make(chan error, sessions)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for {
				i := next.Add(1)
				if i > sessions {
					return
				}
				if err := echo(uint64(i)); err != nil {
					errs <- err
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if t.Failed() {
		t.FailNow()
	}
	msUntil(t, 10*time.Second, "both Runtimes and the Server idle after 200 sessions", idle)
	if ss := n.srv.Status(); ss.Confirmed != sessions+1 || ss.Rejected != 0 {
		t.Errorf("Server: %+v, want %d confirmed, none rejected", ss, sessions+1)
	}
	if got := tg.accepted.Load(); got != sessions+1 {
		t.Errorf("the target accepted %d connections, want %d", got, sessions+1)
	}
	// The target closes its own socket after the FINs, so its handler and
	// the goroutine count do not depend on Forward's close: the tracked
	// sockets prove it on every OS.
	tracks := tr.all()
	if len(tracks) != sessions+1 {
		t.Errorf("the Server's Dial hook dialed %d target sockets, want %d", len(tracks), sessions+1)
	}
	open, lingered := 0, 0
	for _, k := range tracks {
		if k.closedAt.Load() == nil {
			open++
		}
		if k.lingered.Load() {
			lingered++
		}
	}
	if open != 0 || lingered != 0 {
		t.Errorf("Forward left %d of %d target sockets open and set SO_LINGER 0 on %d after clean ends; want every socket closed plainly", open, len(tracks), lingered)
	}
	msUntil(t, 10*time.Second, "the goroutine count back at its baseline", func() bool { return runtime.NumGoroutine() <= g0 })
	if fd0 >= 0 {
		msUntil(t, 10*time.Second, "the non-pipe fds of /proc/self/fd back at their baseline", func() bool { return l4rFDs() <= fd0 })
	} else {
		t.Logf("no portable fd count on %s: the fd check runs on Linux only", runtime.GOOS)
	}
	n.close()
	tg.close()
}
