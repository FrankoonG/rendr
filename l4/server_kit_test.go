package l4

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

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The test kit of the Server (M4 design §A6, §A12.1, WP5): a world as the
// Forward kit's (two Runtimes, links, a Peer) whose Listener has the
// AcceptBacklog and AcceptTimeout a row needs, a Server running Serve on
// it, and hooks that record their calls.

// srvOpts configures a Server world.
type srvOpts struct {
	worldOpts
	backlog       int           // AcceptBacklog (0: max(2n, 16))
	acceptTimeout time.Duration // AcceptTimeout (0: the default 10 s)
}

// newSrvWorld is newWorld with srvOpts' Listener.
func newSrvWorld(t testing.TB, o srvOpts) *world {
	t.Helper()
	w := &world{t: t}
	n := max(o.n, 1)
	cfg := rendr.Config{Window: o.window}
	cfg.Handshake.MaxConcurrent = max(2*n, 64)
	ov := kitOverrides(o.worldOpts)
	// The production NoPathGrace: an opening Dial waits that long for its
	// answer, so the Server's dial budget (up to the AcceptTimeout) is what
	// ends it, not the kit's shortened 5 s.
	ov.NoPathGrace = 15 * time.Second
	w.d = kitRuntime(t, cfg, ov)
	w.p = kitRuntime(t, cfg, ov)
	t.Cleanup(w.shutdown)
	backlog := o.backlog
	if backlog == 0 {
		backlog = max(2*n, 16)
	}
	ln, err := w.p.Listen(rendr.ListenConfig{AcceptBacklog: backlog, AcceptTimeout: o.acceptTimeout})
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

// served is one running Serve.
type served struct {
	s      *Server
	cancel context.CancelFunc
	done   chan error // Serve's result
	ended  atomic.Int64
}

// serve runs s.Serve on w's Listener with a cancellable ctx.
func serve(w *world, s *Server) *served { return serveOn(s, w.ln) }

// serveOn runs s.Serve on ln with a cancellable ctx.
func serveOn(s *Server, ln *rendr.Listener) *served {
	ctx, cancel := context.WithCancel(context.Background())
	sv := &served{s: s, cancel: cancel, done: make(chan error, 1)}
	go func() {
		err := s.Serve(ctx, ln)
		sv.ended.Store(time.Now().UnixNano())
		sv.done <- err
	}()
	return sv
}

// wait returns Serve's result, failing after d (virtual).
func (sv *served) wait(t testing.TB, d time.Duration) error {
	t.Helper()
	select {
	case err := <-sv.done:
		return err
	case <-time.After(d):
		t.Fatalf("Serve did not return within %v: %+v", d, sv.s.Status())
	}
	return nil
}

// stop cancels Serve's ctx and waits for its return.
func (sv *served) stop(t testing.TB) error {
	t.Helper()
	sv.cancel()
	return sv.wait(t, time.Minute)
}

// hookOf adapts a rendrtest dial function (it takes the address) to a
// Server.Dial hook.
func hookOf(dial func(ctx context.Context, addr string) (net.Conn, error)) func(context.Context, Request) (net.Conn, error) {
	return func(ctx context.Context, r Request) (net.Conn, error) { return dial(ctx, r.Addr) }
}

// hookLog wraps a hook and records its calls: the running count and its
// peak, and the instant of each call's start and return.
type hookLog struct {
	h       func(context.Context, Request) (net.Conn, error)
	mu      sync.Mutex
	running int
	peak    int
	calls   int
	starts  []time.Time
	returns []time.Time
	addrs   []string
}

func newHookLog(h func(context.Context, Request) (net.Conn, error)) *hookLog {
	return &hookLog{h: h}
}

func (l *hookLog) dial(ctx context.Context, r Request) (net.Conn, error) {
	l.mu.Lock()
	l.running++
	l.calls++
	l.peak = max(l.peak, l.running)
	l.starts = append(l.starts, time.Now())
	l.addrs = append(l.addrs, r.Addr)
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		l.running--
		l.returns = append(l.returns, time.Now())
		l.mu.Unlock()
	}()
	return l.h(ctx, r)
}

// snapshot returns the calls so far, the peak of concurrent calls and the
// return instants.
func (l *hookLog) snapshot() (calls, peak, running int, returns []time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls, l.peak, l.running, append([]time.Time(nil), l.returns...)
}

// dialRes is one Dial's outcome.
type dialRes struct {
	c   *rendr.Conn
	err error
	at  time.Time // when Dial returned
}

// dialAsync runs Dial(ctx, w.peer, addr) on its own goroutine.
func dialAsync(ctx context.Context, w *world, addr string) <-chan dialRes {
	res := make(chan dialRes, 1)
	go func() {
		c, err := Dial(ctx, w.peer, addr, rendr.DialOptions{})
		res <- dialRes{c, err, time.Now()}
	}()
	return res
}

// recv waits up to d (virtual) for a Dial's outcome.
func recv(t testing.TB, ch <-chan dialRes, d time.Duration) dialRes {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(d):
		t.Fatalf("Dial did not return within %v", d)
	}
	return dialRes{}
}

// wantReject fails unless err is an l4 refusal with code whose message is
// the code's fixed text.
func wantReject(t testing.TB, err error, code RejectCode) {
	t.Helper()
	if e := checkReject(err, code); e != nil {
		t.Fatal(e)
	}
}

// checkReject is wantReject's check: nil when err is an l4 refusal with
// code and the code's fixed text.
func checkReject(err error, code RejectCode) error {
	var re *rendr.RejectError
	if !errors.As(err, &re) {
		return fmt.Errorf("got %v, want a refusal %#x (%v)", err, uint32(code), code)
	}
	if got, ok := CodeOf(err); !ok || got != code || re.Msg != code.String() {
		return fmt.Errorf("got refusal %#x %q, want %#x %q", re.Code, re.Msg, uint32(code), code.String())
	}
	return nil
}

// waitFor polls cond every millisecond (virtual) for up to d.
func waitFor(t testing.TB, d time.Duration, what string, cond func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for !cond() {
		if !time.Now().Before(end) {
			t.Fatalf("not reached within %v: %s", d, what)
		}
		time.Sleep(time.Millisecond)
	}
}

// echoRoundTrip writes n bytes of PRNG(seed) on c, half-closes it and
// reads the echo to its end; it fails unless the echo is complete and
// intact and ends with io.EOF.
func echoRoundTrip(t testing.TB, c *rendr.Conn, n int64, seed uint64) {
	t.Helper()
	werr := make(chan error, 1)
	go func() {
		err := writePRNG(c, seed, n)
		if err == nil {
			err = c.CloseWrite()
		}
		werr <- err
	}()
	got, sum, err := readAll(c)
	if e := <-werr; e != nil {
		t.Fatalf("write: %v", e)
	}
	if err != io.EOF || got != n || sum != prngSum(seed, n) {
		t.Fatalf("echo: %d of %d bytes, intact %v, end %v", got, n, sum == prngSum(seed, n), err)
	}
}

// ping writes k bytes on c and reads them back from an echo target; it
// returns the round trip's duration.
func ping(t testing.TB, c *rendr.Conn, k int) time.Duration {
	t.Helper()
	d, err := pingErr(c, k)
	if err != nil {
		t.Fatalf("ping: %v", err)
	}
	return d
}

// pingErr is ping for goroutines other than the test's.
func pingErr(c *rendr.Conn, k int) (time.Duration, error) {
	buf := make([]byte, k)
	start := time.Now()
	if _, err := c.Write(buf); err != nil {
		return 0, err
	}
	if _, err := io.ReadFull(c, buf); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

// spyHook returns a hook that dials target and hands out the conn wrapped
// in a fullSpy, which it also records.
func spyHook(target *rendrtest.Target, spies *[]*spyConn, mu *sync.Mutex) func(context.Context, Request) (net.Conn, error) {
	return func(ctx context.Context, r Request) (net.Conn, error) {
		c, err := target.Dial(ctx, r.Addr)
		if err != nil {
			return nil, err
		}
		sp := &spyConn{Conn: c}
		mu.Lock()
		*spies = append(*spies, sp)
		mu.Unlock()
		return fullSpy{sp}, nil
	}
}
