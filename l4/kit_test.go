package l4

import (
	"context"
	"crypto/sha256"
	"errors"
	"hash"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The test kit of Forward and Dial (M4 design §A12.1, WP4). A world is two
// Runtimes — the dialer d and the passive p with one push-only Listener —
// joined by rendrtest.Links whose Accept is the Listener's Handle, and a
// Peer over the links. A session pair is opened with Dial and confirmed on
// the passive by hand (the Server is WP5's). A chain adds both forwarders
// of an L4 connection: a client on a TargetPipe, the ingress Forward on
// the dialer Conn and the egress Forward on the passive Conn toward a
// rendrtest.Target. Everything is created inside the synctest bubble that
// uses it and closed before the bubble ends.

// kitOneWay is the links' one-way delay.
const kitOneWay = 5 * time.Millisecond

// kitTarget is the address the kit's sessions name (the targets ignore it).
const kitTarget = "target.test:80"

// worldOpts configures a world.
type worldOpts struct {
	links     int           // paths (0: 1)
	window    int           // Config.Window of both Runtimes (0: the default)
	linger    time.Duration // the Linger override (0: 10 s)
	dedicated bool          // Props.CheapSubflow: one carrier per session
	n         int           // sessions at once (sizes the handshake and backlog limits)
	rate      float64       // the links' rate per direction in bytes/s (0: unlimited)
}

// world is one test's two Runtimes, links and Peer.
type world struct {
	t     testing.TB
	d, p  *rendr.Runtime
	ln    *rendr.Listener
	links []*rendrtest.Link
	peer  *rendr.Peer
	once  sync.Once
}

// kitOverrides is the testhooks value of both Runtimes: the shortened
// timings of the scenario kits.
func kitOverrides(o worldOpts) testhooks.Overrides {
	linger := o.linger
	if linger == 0 {
		linger = 10 * time.Second
	}
	return testhooks.Overrides{
		DeadMin:          time.Second,
		DeadMax:          2 * time.Second,
		WriteStall:       time.Second,
		PingIdle:         500 * time.Millisecond,
		ProbeInterval:    200 * time.Millisecond,
		ProbeFresh:       2 * time.Second,
		SelectorDwell:    time.Second,
		SelectorCooldown: 2 * time.Second,
		NoPathGrace:      5 * time.Second,
		RetireGrace:      500 * time.Millisecond,
		Linger:           linger,
		RetainSlack:      2 * time.Second,
	}
}

// newWorld builds the Runtimes, the Listener, the links and the Peer.
func newWorld(t testing.TB, o worldOpts) *world {
	t.Helper()
	w := &world{t: t}
	n := max(o.n, 1)
	cfg := rendr.Config{Window: o.window}
	cfg.Handshake.MaxConcurrent = max(2*n, 64)
	ov := kitOverrides(o)
	w.d = kitRuntime(t, cfg, ov)
	w.p = kitRuntime(t, cfg, ov)
	t.Cleanup(w.shutdown)
	ln, err := w.p.Listen(rendr.ListenConfig{AcceptBacklog: max(2*n, 16)})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	w.ln = ln
	var cs []rendr.Carrier
	for i := range max(o.links, 1) {
		name := string(rune('a' + i))
		l := rendrtest.NewLink(rendrtest.LinkConfig{Name: name, Accept: ln.Handle})
		l.SetDelay(kitOneWay, 0)
		if o.rate > 0 {
			l.SetRate(o.rate)
		}
		w.links = append(w.links, l)
		cs = append(cs, rendr.StreamCarrier{Name: name, Dial: l.Dial, Props: rendr.Props{CheapSubflow: o.dedicated}})
	}
	if w.peer, err = w.d.NewPeer(rendr.PeerConfig{Carriers: cs}); err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	return w
}

func kitRuntime(t testing.TB, cfg rendr.Config, ov testhooks.Overrides) *rendr.Runtime {
	t.Helper()
	v, err := testhooks.NewRuntime(cfg, &ov)
	if err != nil {
		t.Fatalf("testhooks.NewRuntime: %v", err)
	}
	return v.(*rendr.Runtime)
}

// shutdown closes the Peer, both Runtimes and the links (once).
func (w *world) shutdown() {
	w.once.Do(func() {
		w.peer.Close()
		w.d.Close()
		w.p.Close()
		for _, l := range w.links {
			l.Close()
		}
	})
}

// open dials one L4 session with Dial and confirms it on the passive.
func (w *world) open(o rendr.DialOptions) (d, p *rendr.Conn) {
	w.t.Helper()
	var perr error
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		pend, err := w.ln.Accept(context.Background())
		if err != nil {
			perr = err
			return
		}
		p, perr = pend.Confirm()
	}()
	d, err := Dial(context.Background(), w.peer, kitTarget, o)
	<-accepted
	if err != nil || perr != nil {
		w.t.Fatalf("open: Dial %v, Accept/Confirm %v", err, perr)
	}
	return d, p
}

// activeLink returns the link that carries c's data (selector), or nil.
func (w *world) activeLink(c *rendr.Conn) *rendrtest.Link {
	for _, cs := range c.Status().Carriers {
		if cs.State == rendr.CarrierActive {
			for _, l := range w.links {
				if l.Name() == cs.Name {
					return l
				}
			}
		}
	}
	return nil
}

// chain is one forwarded L4 connection: client ↔ ingress Forward(d) ⇄
// egress Forward(p) ↔ target.
type chain struct {
	d, p      *rendr.Conn
	client    *rendrtest.TargetConn
	target    *rendrtest.Target
	ingress   <-chan ForwardResult
	egress    <-chan ForwardResult
	cancelIn  context.CancelFunc
	cancelOut context.CancelFunc
}

// chain opens a session and starts both forwarders: the client end of a
// TargetPipe(buf) on the dialer, a Target(b, buf) connection on the passive.
func (w *world) chain(b rendrtest.TargetBehaviour, buf int) *chain {
	w.t.Helper()
	ch := &chain{target: rendrtest.NewTarget(b, buf)}
	ch.d, ch.p = w.open(rendr.DialOptions{})
	tc, err := ch.target.Dial(context.Background(), kitTarget)
	if err != nil {
		w.t.Fatalf("target Dial: %v", err)
	}
	cli, srv := rendrtest.TargetPipe(buf)
	ch.client = cli
	var inCtx, outCtx context.Context
	inCtx, ch.cancelIn = context.WithCancel(context.Background())
	outCtx, ch.cancelOut = context.WithCancel(context.Background())
	ch.ingress = forwardAsync(inCtx, ch.d, srv)
	ch.egress = forwardAsync(outCtx, ch.p, tc)
	return ch
}

// forwardAsync runs Forward on its own goroutine; the channel yields the
// result.
func forwardAsync(ctx context.Context, c *rendr.Conn, local net.Conn) <-chan ForwardResult {
	res := make(chan ForwardResult, 1)
	go func() { res <- Forward(ctx, c, local) }()
	return res
}

// results waits for both forwarders' results.
func (ch *chain) results() (in, out ForwardResult) {
	return <-ch.ingress, <-ch.egress
}

// end cancels the forwarders' contexts, closes the Target and waits for
// both sessions' ends.
func (ch *chain) end(t testing.TB) {
	t.Helper()
	ch.cancelIn()
	ch.cancelOut()
	ch.target.Close()
	waitDone(t, ch.d, time.Minute)
	waitDone(t, ch.p, time.Minute)
}

// waitDone waits up to d (virtual) for c's end.
func waitDone(t testing.TB, c *rendr.Conn, d time.Duration) {
	t.Helper()
	select {
	case <-c.Done():
	case <-time.After(d):
		t.Fatalf("session %v not done after %v: %+v", c.ID(), d, c.Status())
	}
}

// readAll reads r to its end and returns the bytes' count and SHA-256 and
// the error that ended it (io.EOF at a FIN).
func readAll(r io.Reader) (int64, [32]byte, error) {
	h := sha256.New()
	buf := make([]byte, 32<<10)
	var n int64
	for {
		k, err := r.Read(buf)
		h.Write(buf[:k])
		n += int64(k)
		if err != nil {
			var sum [32]byte
			h.Sum(sum[:0])
			return n, sum, err
		}
	}
}

// prngSum is the SHA-256 of the first n bytes of PRNG(seed).
func prngSum(seed uint64, n int64) [32]byte {
	h := sha256.New()
	io.CopyN(h, rendrtest.PRNG(seed), n)
	var sum [32]byte
	h.Sum(sum[:0])
	return sum
}

// writePRNG writes n bytes of PRNG(seed) to w in 16 KiB Writes.
func writePRNG(w io.Writer, seed uint64, n int64) error {
	return writeFrom(w, rendrtest.PRNG(seed), n)
}

// writeFrom writes the next n bytes of src to w in 16 KiB Writes.
func writeFrom(w io.Writer, src io.Reader, n int64) error {
	buf := make([]byte, 16<<10)
	for n > 0 {
		k := int(min(n, int64(len(buf))))
		src.Read(buf[:k])
		if _, err := w.Write(buf[:k]); err != nil {
			return err
		}
		n -= int64(k)
	}
	return nil
}

// isReset reports whether err is a TargetPipe's connection reset.
func isReset(err error) bool { return errors.Is(err, rendrtest.ErrReset) }

// abortCode returns the code of an *rendr.AbortError and whether it came
// from the peer.
func abortCode(err error) (code rendr.AbortCode, remote, ok bool) {
	var ae *rendr.AbortError
	if !errors.As(err, &ae) {
		return 0, false, false
	}
	return ae.Code, ae.Remote, true
}

// spyConn wraps a net.Conn and records the calls Forward makes on it: the
// deadline calls, SetLinger, CloseWrite and Close (with their virtual
// instants). It offers CloseWrite and SetLinger only where the wrapped
// conn does and the spy allows them.
type spyConn struct {
	net.Conn
	mu        sync.Mutex
	deadlines []time.Time // the values passed to the deadline setters
	linger0   int
	closes    int
	closedAt  time.Time
	cw        int
}

func (s *spyConn) note(f func()) {
	s.mu.Lock()
	f()
	s.mu.Unlock()
}

func (s *spyConn) SetDeadline(t time.Time) error {
	s.note(func() { s.deadlines = append(s.deadlines, t) })
	return s.Conn.SetDeadline(t)
}

func (s *spyConn) SetReadDeadline(t time.Time) error {
	s.note(func() { s.deadlines = append(s.deadlines, t) })
	return s.Conn.SetReadDeadline(t)
}

func (s *spyConn) SetWriteDeadline(t time.Time) error {
	s.note(func() { s.deadlines = append(s.deadlines, t) })
	return s.Conn.SetWriteDeadline(t)
}

func (s *spyConn) Close() error {
	s.note(func() {
		s.closes++
		if s.closedAt.IsZero() {
			s.closedAt = time.Now()
		}
	})
	return s.Conn.Close()
}

// snapshot returns the recorded calls.
func (s *spyConn) snapshot() (deadlines []time.Time, linger0, closes, cw int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Time(nil), s.deadlines...), s.linger0, s.closes, s.cw
}

// fullSpy is a spyConn that also offers CloseWrite and SetLinger (a TCP
// conn's shape).
type fullSpy struct{ *spyConn }

func (s fullSpy) CloseWrite() error {
	s.note(func() { s.cw++ })
	return s.Conn.(interface{ CloseWrite() error }).CloseWrite()
}

func (s fullSpy) SetLinger(sec int) error {
	s.note(func() {
		if sec == 0 {
			s.linger0++
		}
	})
	return s.Conn.(interface{ SetLinger(int) error }).SetLinger(sec)
}

// runningSum is a SHA-256 of bytes written so far.
type runningSum struct{ h hash.Hash }

func newSum() runningSum                 { return runningSum{sha256.New()} }
func (s runningSum) Write(b []byte)      { s.h.Write(b) }
func (s runningSum) sum() (out [32]byte) { s.h.Sum(out[:0]); return out }
