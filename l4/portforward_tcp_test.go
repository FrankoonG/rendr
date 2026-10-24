package l4

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The test kit of PortForward.ServeTCP (M6 design §A8.7, §A16.1 WP7);
// helpers start with "pt". A ptWorld is two Runtimes joined by
// rendrtest.Links (the Server kit's shape, with the dialer's Config the
// row's), a passive running an l4 Server — or the row's own loop — on the
// passive Listener, and a PortForward whose ServeTCP serves a ptListener:
// an in-memory listener whose connections are TargetPipes, so the test
// holds each client end. Everything is created inside the synctest bubble
// that uses it and closed before the bubble ends.

// ptTarget is the address the forwarded sessions name (the kit's targets
// ignore it).
const ptTarget = "target.test:443"

// ptLoopback is the ptListener's default bind address.
var ptLoopback = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8443}

// ptAccept is one queued Accept result.
type ptAccept struct {
	c   net.Conn
	err error
}

// ptListener is an in-memory net.Listener (synctest-safe: Accept waits on
// channels). The test queues connections and errors; it records the
// instant every Accept call returned and counts Close calls.
type ptListener struct {
	addr   net.Addr
	q      chan ptAccept
	done   chan struct{}
	once   sync.Once
	closes atomic.Int32
	mu     sync.Mutex
	calls  []time.Time
	before func() // if set, runs in Accept before it returns a queued result
}

func newPTListener(addr net.Addr) *ptListener {
	return &ptListener{addr: addr, q: make(chan ptAccept, 64), done: make(chan struct{})}
}

var errPTClosed = &net.OpError{Op: "accept", Net: "tcp", Err: net.ErrClosed}

func (l *ptListener) Accept() (net.Conn, error) {
	defer func() {
		l.mu.Lock()
		l.calls = append(l.calls, time.Now())
		l.mu.Unlock()
	}()
	select {
	case <-l.done:
		return nil, errPTClosed
	default:
	}
	select {
	case a := <-l.q:
		if l.before != nil {
			l.before()
		}
		return a.c, a.err
	case <-l.done:
		return nil, errPTClosed
	}
}

func (l *ptListener) Close() error {
	l.closes.Add(1)
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *ptListener) Addr() net.Addr { return l.addr }

// dial queues a new connection and returns its client end.
func (l *ptListener) dial() *rendrtest.TargetConn {
	cli, srv := rendrtest.TargetPipe(0)
	l.q <- ptAccept{c: srv}
	return cli
}

// ptGatedConn is a server end whose Close waits until gate is closed (a
// teardown that takes time).
type ptGatedConn struct {
	*rendrtest.TargetConn
	gate chan struct{}
}

func (c *ptGatedConn) Close() error {
	<-c.gate
	return c.TargetConn.Close()
}

// dialGated queues a new connection whose server end's Close waits until
// release is called; it returns the client end.
func (l *ptListener) dialGated() (c *rendrtest.TargetConn, release func()) {
	cli, srv := rendrtest.TargetPipe(0)
	g := &ptGatedConn{TargetConn: srv, gate: make(chan struct{})}
	l.q <- ptAccept{c: g}
	return cli, func() { close(g.gate) }
}

// acceptCalls returns the instants at which the Accept calls so far
// returned.
func (l *ptListener) acceptCalls() []time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]time.Time(nil), l.calls...)
}

// ptTempErr is a temporary Accept error (EMFILE's shape: Temporary true).
type ptTempErr struct{}

func (ptTempErr) Error() string   { return "pt: too many open files" }
func (ptTempErr) Temporary() bool { return true }
func (ptTempErr) Timeout() bool   { return false }

// ptTimeoutErr is a timeout Accept error that does not call itself
// temporary (an embedder listener's deadline): Timeout true only.
type ptTimeoutErr struct{}

func (ptTimeoutErr) Error() string   { return "pt: accept deadline exceeded" }
func (ptTimeoutErr) Temporary() bool { return false }
func (ptTimeoutErr) Timeout() bool   { return true }

// errPTPermanent is a permanent Accept error (neither temporary nor a
// timeout).
var errPTPermanent = errors.New("pt: listener broken for good")

// ptOpts configures a ptWorld.
type ptOpts struct {
	dialerCfg rendr.Config                                     // the dialer Runtime's Config (Handshake.MaxConcurrent is set)
	dedicated bool                                             // Props.CheapSubflow: one carrier per session
	hook      func(context.Context, Request) (net.Conn, error) // the Server's Dial (nil: the echo target)
	ownLoop   bool                                             // no Server: the row runs its own loop on w.ln
	pfwd      func(*PortForward)                               // sets the PortForward up (its Peer is the kit's)
	broken    *atomic.Bool                                     // while set, the carrier's Dial reports net.ErrClosed (a tunnel that is down)
}

// ptWorld is one row's world.
type ptWorld struct {
	*world
	t      testing.TB
	echo   *rendrtest.Target
	srv    *Server
	sv     *served
	pl     *ptListener
	pf     *PortForward
	cancel context.CancelFunc
	served chan error // ServeTCP's result

	mu   sync.Mutex
	reqs []Request // the requests the Server's hook saw (App copied)
}

func newPTWorld(t testing.TB, o ptOpts) *ptWorld {
	t.Helper()
	w := &ptWorld{world: &world{t: t}, t: t, echo: rendrtest.NewTarget(rendrtest.TargetEcho(), 0)}
	cfg := o.dialerCfg
	cfg.Handshake.MaxConcurrent = 64
	ov := kitOverrides(worldOpts{})
	ov.NoPathGrace = 15 * time.Second // the Server kit's: the passive's budget ends an opening Dial
	w.d = kitRuntime(t, cfg, ov)
	w.p = kitRuntime(t, rendr.Config{Handshake: rendr.HandshakeLimits{MaxConcurrent: 64}}, ov)
	t.Cleanup(w.close)
	ln, err := w.p.Listen(rendr.ListenConfig{AcceptBacklog: 32})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	w.ln = ln
	l := rendrtest.NewLink(rendrtest.LinkConfig{Name: "a", Accept: ln.Handle})
	l.SetDelay(kitOneWay, 0)
	w.links = append(w.links, l)
	dial := l.Dial
	if o.broken != nil {
		dial = func(ctx context.Context) (net.Conn, error) {
			if o.broken.Load() {
				return nil, net.ErrClosed
			}
			return l.Dial(ctx)
		}
	}
	cs := []rendr.Carrier{rendr.StreamCarrier{Name: "a", Dial: dial, Props: rendr.Props{CheapSubflow: o.dedicated}}}
	if w.peer, err = w.d.NewPeer(rendr.PeerConfig{Carriers: cs}); err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	if !o.ownLoop {
		hook := o.hook
		if hook == nil {
			hook = func(ctx context.Context, r Request) (net.Conn, error) { return w.echo.Dial(ctx, r.Addr) }
		}
		// IdleTimeout -1: the passive sets no idle limit (its Config has
		// none), so the ingress's limit is the one a row observes.
		w.srv = &Server{IdleTimeout: -1, Dial: func(ctx context.Context, r Request) (net.Conn, error) {
			w.mu.Lock()
			r.App = bytes.Clone(r.App)
			w.reqs = append(w.reqs, r)
			w.mu.Unlock()
			return hook(ctx, r)
		}}
		w.sv = serve(w.world, w.srv)
	}
	w.pf = &PortForward{Peer: w.peer}
	if o.pfwd != nil {
		o.pfwd(w.pf)
	}
	w.pl = newPTListener(ptLoopback)
	return w
}

// serveTCP starts ServeTCP on the row's listener.
func (w *ptWorld) serveTCP() {
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	w.served = make(chan error, 1)
	go func() { w.served <- w.pf.ServeTCP(ctx, w.pl, ptTarget) }()
}

// result waits up to d (virtual) for ServeTCP's return.
func (w *ptWorld) result(d time.Duration) error {
	w.t.Helper()
	select {
	case err := <-w.served:
		w.served = nil
		return err
	case <-time.After(d):
		w.t.Fatalf("ServeTCP did not return within %v: %+v", d, w.pf.Status().TCP)
	}
	return nil
}

// stop cancels ServeTCP's ctx and returns its result.
func (w *ptWorld) stop() error {
	w.t.Helper()
	w.cancel()
	return w.result(time.Minute)
}

// close stops everything the world started (once): ServeTCP, the Server,
// the echo target, the Peer, the Runtimes and the links.
func (w *ptWorld) close() {
	if w.served != nil {
		w.cancel()
		<-w.served
		w.served = nil
	}
	if w.sv != nil {
		w.sv.cancel()
		<-w.sv.done
		w.sv = nil
	}
	w.echo.Close()
	w.shutdown()
}

// requests returns the requests the Server's hook saw.
func (w *ptWorld) requests() []Request {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]Request(nil), w.reqs...)
}

// ptEcho writes n bytes of PRNG(seed) on c, half-closes it and reads the
// echo to its end; it fails unless the echo is complete, intact and ends
// with io.EOF (a clean close).
func ptEcho(t testing.TB, c *rendrtest.TargetConn, n int64, seed uint64) {
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
		t.Fatalf("client write: %v", e)
	}
	if err != io.EOF || got != n || sum != prngSum(seed, n) {
		t.Fatalf("echo: %d of %d bytes, intact %v, end %v", got, n, sum == prngSum(seed, n), err)
	}
	c.Close()
}

// ptPing writes k bytes on c and reads them back (the connection stays
// open).
func ptPing(t testing.TB, c *rendrtest.TargetConn, k int) {
	t.Helper()
	b := bytes.Repeat([]byte{0x5a}, k)
	if _, err := c.Write(b); err != nil {
		t.Fatalf("ping write: %v", err)
	}
	got := make([]byte, k)
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, b) {
		t.Fatalf("ping read: %v (intact %v)", err, bytes.Equal(got, b))
	}
}

// ptEndNow reads c without waiting: the error that ended it (ErrReset for
// a reset, io.EOF for a clean close) or os.ErrDeadlineExceeded while it
// is still open.
func ptEndNow(c *rendrtest.TargetConn) error {
	c.SetReadDeadline(time.Now())
	defer c.SetReadDeadline(time.Time{})
	var b [1]byte
	_, err := c.Read(b[:])
	return err
}

// ptWaitEnd reads c until it ends or d (virtual) passed; it returns the
// error and the instant.
func ptWaitEnd(c *rendrtest.TargetConn, d time.Duration) (error, time.Time) {
	c.SetReadDeadline(time.Now().Add(d))
	defer c.SetReadDeadline(time.Time{})
	b := make([]byte, 1024)
	for {
		if _, err := c.Read(b); err != nil {
			return err, time.Now()
		}
	}
}

// ptWantReset fails unless c was reset (never a clean close).
func ptWantReset(t testing.TB, what string, c *rendrtest.TargetConn, d time.Duration) {
	t.Helper()
	if err, _ := ptWaitEnd(c, d); !isReset(err) {
		t.Fatalf("%s: the client read %v, want a reset (never a clean close)", what, err)
	}
}

// TestPortForwardTCP_L02 (M6 design §A8.7, §A16.1 WP7; L02: an ingress
// failure reaches the client as a reset, never as a clean end): ServeTCP
// forwards every accepted connection over its own session (Dial, then
// Forward: data and FIN both ways), carries Options (Metadata as
// Request.App, EarlyReturn honoured), applies IdleTimeout as l4.Dial and
// the Server do, resets a connection whose Dial fails (a refusal, also
// one an EarlyReturn session meets at its open) or that is beyond
// MaxConns, backs off temporary Accept errors (5 → 100 ms; a stop ends
// the wait), ends on ctx, a permanent Accept error or a closed Peer after
// resetting every connection it forwards — a carrier's net.ErrClosed is
// one connection's failure, never the serve's end —, and owns ln: closed
// exactly once, the return after every connection ended; its checks run
// before the first Accept.
func TestPortForwardTCP_L02(t *testing.T) {
	t.Run("forward", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			app := []byte("embedder-token")
			w := newPTWorld(t, ptOpts{pfwd: func(f *PortForward) { f.Options.Metadata = app }})
			w.serveTCP()
			const conns, size = 8, 64 << 10
			var wg sync.WaitGroup
			for i := range conns {
				c := w.pl.dial()
				wg.Go(func() { ptEcho(t, c, size, uint64(i+1)) })
			}
			wg.Wait()
			waitFor(t, 10*time.Second, "Live 0", func() bool { return w.pf.Status().TCP.Live == 0 })
			st := w.pf.Status().TCP
			if st.Accepted != conns || st.Refused != 0 || st.Failed != 0 || st.LastErr != nil {
				t.Fatalf("status %+v: want %d accepted, nothing refused or failed", st, conns)
			}
			reqs := w.requests()
			if len(reqs) != conns {
				t.Fatalf("%d requests at the passive, want one session per connection (%d)", len(reqs), conns)
			}
			for _, r := range reqs {
				if r.Cmd != CmdConnect || r.Addr != ptTarget || !bytes.Equal(r.App, app) {
					t.Fatalf("request %+v: want CmdConnect to %s with App %q", r, ptTarget, app)
				}
			}
			if sst := w.srv.Status(); sst.Confirmed != conns {
				t.Fatalf("Server confirmed %d, want %d", sst.Confirmed, conns)
			}
			tc := w.echo.Counts()
			if tc.Accepted != conns || tc.BytesIn != conns*size || tc.BytesOut != conns*size || tc.FINIn != conns {
				t.Fatalf("target %+v: want %d connections of %d bytes each way, each with its FIN", tc, conns, size)
			}
			if err := w.stop(); !errors.Is(err, context.Canceled) || w.pl.closes.Load() != 1 {
				t.Fatalf("ServeTCP = %v, %d Closes; want context.Canceled, closed once", err, w.pl.closes.Load())
			}
		})
	})

	t.Run("refusal", func(t *testing.T) {
		for _, early := range []bool{false, true} {
			synctest.Test(t, func(t *testing.T) {
				w := newPTWorld(t, ptOpts{
					hook: func(context.Context, Request) (net.Conn, error) { return nil, ErrDenied },
					pfwd: func(f *PortForward) { f.Options.EarlyReturn = early },
				})
				w.serveTCP()
				// The first client speaks first; the second waits for the
				// server, so nothing is unread at the ingress and only a
				// reset, never a plain Close, reaches it as one.
				for k := 1; k <= 2; k++ {
					c := w.pl.dial()
					if k == 1 {
						if _, err := c.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
							t.Fatalf("early %v: client write: %v", early, err)
						}
					}
					ptWantReset(t, "a refused Dial", c, time.Minute)
					// The reset reaches the client before the forward counts the
					// failure (Failed, then its code and LastErr: independent
					// atomics), so the wait covers every counter the row reads
					// (M6 I3: the Linux l4.slow sweep read Failed 2 and ByCode 1
					// in 1 of 300 runs, run 20261022-192558-cff1).
					waitFor(t, 10*time.Second, "the failure counted with its code", func() bool {
						st := w.pf.Status().TCP
						return st.Failed == uint64(k) && st.ByCode[CodeNotAllowed] == uint64(k) && st.LastErr != nil
					})
				}
				st := w.pf.Status().TCP
				if code, ok := CodeOf(st.LastErr); st.Accepted != 2 || st.Failed != 2 || st.ByCode[CodeNotAllowed] != 2 || !ok || code != CodeNotAllowed {
					t.Fatalf("early %v: status %+v: want 2 failures counted CodeNotAllowed with LastErr the refusal", early, st)
				}
				waitFor(t, 10*time.Second, "Live 0", func() bool { return w.pf.Status().TCP.Live == 0 })
				if w.echo.Counts().Accepted != 0 {
					t.Fatalf("early %v: the target was dialled", early)
				}
			})
		}
	})

	t.Run("maxconns", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			gate := make(chan struct{})
			var w *ptWorld
			w = newPTWorld(t, ptOpts{
				hook: func(ctx context.Context, r Request) (net.Conn, error) {
					select {
					case <-gate:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
					return w.echo.Dial(ctx, r.Addr)
				},
				pfwd: func(f *PortForward) { f.MaxConns = 2 },
			})
			w.serveTCP()
			c1, c2 := w.pl.dial(), w.pl.dial()
			waitFor(t, 10*time.Second, "both connections dialling at the passive", func() bool { return len(w.requests()) == 2 })
			c3 := w.pl.dial()
			synctest.Wait()
			if err := ptEndNow(c3); !isReset(err) {
				t.Fatalf("the connection beyond MaxConns: %v, want a reset at once", err)
			}
			if st := w.pf.Status().TCP; st.Accepted != 3 || st.Refused != 1 || st.Live != 2 || st.Failed != 0 {
				t.Fatalf("status %+v: want 3 accepted, 1 refused, 2 live", st)
			}
			if n := len(w.requests()); n != 2 {
				t.Fatalf("%d dials at the passive: the refused connection was dialled", n)
			}
			close(gate)
			var wg sync.WaitGroup
			wg.Go(func() { ptEcho(t, c1, 32<<10, 1) })
			wg.Go(func() { ptEcho(t, c2, 32<<10, 2) })
			wg.Wait()
			waitFor(t, 10*time.Second, "Live 0", func() bool { return w.pf.Status().TCP.Live == 0 })
			// The units came back: two more connections forward.
			c4, c5 := w.pl.dial(), w.pl.dial()
			wg.Go(func() { ptEcho(t, c4, 32<<10, 4) })
			wg.Go(func() { ptEcho(t, c5, 32<<10, 5) })
			wg.Wait()
			if st := w.pf.Status().TCP; st.Accepted != 5 || st.Refused != 1 {
				t.Fatalf("status %+v: want 5 accepted, 1 refused", st)
			}
			if (&PortForward{}).maxConns() != DefaultMaxConns || (&PortForward{MaxConns: -1}).maxConns() != DefaultMaxConns {
				t.Fatalf("MaxConns 0 or less: want DefaultMaxConns")
			}
		})
	})

	t.Run("early", func(t *testing.T) {
		// EarlyReturn honoured: the client's first bytes ride the OPEN
		// (the passive's EarlyBytes), and only with it.
		for _, early := range []bool{false, true} {
			synctest.Test(t, func(t *testing.T) {
				w := newPTWorld(t, ptOpts{dedicated: true, ownLoop: true, pfwd: func(f *PortForward) { f.Options.EarlyReturn = early }})
				ctx, cancel := context.WithCancel(context.Background())
				got := make(chan uint64, 1)
				var loop sync.WaitGroup
				defer loop.Wait()
				defer cancel()
				loop.Go(func() {
					pend, err := w.ln.Accept(ctx)
					if err != nil {
						return
					}
					// The target's connect takes 1 ms, as a real one does, so
					// the early DATA that arrived with the OPEN is in.
					time.Sleep(time.Millisecond)
					tc, err := w.echo.Dial(ctx, ptTarget)
					if err != nil {
						pend.Reject(uint32(CodeDialFailed), CodeDialFailed.String())
						return
					}
					sc, err := pend.Confirm()
					if err != nil {
						tc.Close()
						return
					}
					got <- sc.Status().EarlyBytes
					Forward(ctx, sc, tc)
				})
				w.serveTCP()
				c := w.pl.dial()
				const req = 1 << 10
				ptEcho(t, c, req, 7)
				want := uint64(0)
				if early {
					want = req
				}
				if n := <-got; n != want {
					t.Fatalf("EarlyReturn %v: the passive's EarlyBytes %d, want %d", early, n, want)
				}
				if err := w.stop(); !errors.Is(err, context.Canceled) {
					t.Fatalf("ServeTCP = %v", err)
				}
			})
		}
	})

	t.Run("idle", func(t *testing.T) {
		// IdleTimeout as l4.Dial and the Server: 0 → DefaultIdleTimeout; a
		// value is set; negative → none, so the dialer's Config applies.
		// The passive sets no limit, so the ingress's ends the session (a
		// reset of the client: an idle end is not a clean one). An
		// EarlyReturn session gets the limit too, and the idle end of a
		// session that opened is no dial failure.
		for _, r := range []struct {
			pf, cfg, want time.Duration // want 0: no end
			early         bool
		}{
			{30 * time.Second, 0, 30 * time.Second, false},
			{0, 0, DefaultIdleTimeout, false},
			{-1, 45 * time.Second, 45 * time.Second, false},
			{-1, 0, 0, false},
			{30 * time.Second, 0, 30 * time.Second, true},
		} {
			synctest.Test(t, func(t *testing.T) {
				w := newPTWorld(t, ptOpts{dialerCfg: rendr.Config{IdleTimeout: r.cfg}, pfwd: func(f *PortForward) {
					f.IdleTimeout = r.pf
					f.Options.EarlyReturn = r.early
				}})
				w.serveTCP()
				c := w.pl.dial()
				ptPing(t, c, 100)
				t0 := time.Now()
				const horizon = 15 * time.Minute
				err, at := ptWaitEnd(c, horizon)
				if r.want == 0 {
					if !errors.Is(err, os.ErrDeadlineExceeded) {
						t.Fatalf("IdleTimeout %v, Config %v: ended %v after %v, want no idle end", r.pf, r.cfg, err, at.Sub(t0))
					}
					ptPing(t, c, 100) // still forwarding
					return
				}
				if el := at.Sub(t0); !isReset(err) || el < r.want || el > r.want+5*time.Second {
					t.Fatalf("IdleTimeout %v, Config %v, EarlyReturn %v: %v after %v, want a reset at %v", r.pf, r.cfg, r.early, err, el, r.want)
				}
				waitFor(t, 10*time.Second, "Live 0", func() bool { return w.pf.Status().TCP.Live == 0 })
				if st := w.pf.Status().TCP; st.Failed != 0 || st.LastErr != nil {
					t.Fatalf("IdleTimeout %v, EarlyReturn %v: status %+v: the idle end of an open session counted as a dial failure", r.pf, r.early, st)
				}
			})
		}
	})

	t.Run("stop", func(t *testing.T) {
		// With EarlyReturn the fifth session is pending at the stop (its
		// OPEN unanswered): its end is not counted as a dial failure either.
		for _, early := range []bool{false, true} {
			synctest.Test(t, func(t *testing.T) { ptStopRow(t, early) })
		}
	})

	t.Run("carrier-closed", func(t *testing.T) {
		// A carrier whose Dial reports net.ErrClosed (an embedder tunnel that
		// is down) fails a Dial with ErrNoPath wrapping it while the Peer is
		// open: that connection's failure (reset, counted), never the
		// serve's end; the connection already forwarded keeps forwarding.
		synctest.Test(t, func(t *testing.T) {
			var broken atomic.Bool
			w := newPTWorld(t, ptOpts{dedicated: true, broken: &broken})
			w.serveTCP()
			c1 := w.pl.dial()
			ptPing(t, c1, 256)
			broken.Store(true)
			c2 := w.pl.dial()
			ptWantReset(t, "a Dial whose carrier is closed", c2, time.Minute)
			waitFor(t, 10*time.Second, "the failure counted", func() bool { return w.pf.Status().TCP.Failed == 1 })
			synctest.Wait()
			select {
			case err := <-w.served:
				w.served = nil
				t.Fatalf("ServeTCP returned %v with the Peer open: a carrier's net.ErrClosed ended the serve", err)
			default:
			}
			st := w.pf.Status().TCP
			if !errors.Is(st.LastErr, rendr.ErrNoPath) || !errors.Is(st.LastErr, net.ErrClosed) || st.Accepted != 2 || st.Live != 1 {
				t.Fatalf("status %+v: want 2 accepted, 1 live, LastErr ErrNoPath wrapping the carrier's net.ErrClosed", st)
			}
			ptPing(t, c1, 256) // still forwarding
			broken.Store(false)
			ptEcho(t, w.pl.dial(), 16<<10, 3) // and a new connection forwards
			if err := w.stop(); !errors.Is(err, context.Canceled) {
				t.Fatalf("ServeTCP = %v, want context.Canceled", err)
			}
		})
	})

	t.Run("backoff-stop", func(t *testing.T) {
		// A stop while the loop waits out a back-off returns at once, not
		// when the wait ends, and calls Accept no more.
		synctest.Test(t, func(t *testing.T) {
			w := newPTWorld(t, ptOpts{})
			for range 6 {
				w.pl.q <- ptAccept{err: ptTempErr{}}
			}
			w.serveTCP()
			// The sixth error returns at 5+10+20+40+80 = 155 ms; its 100 ms
			// wait runs until 255 ms.
			time.Sleep(200 * time.Millisecond)
			if st := w.pf.Status().TCP; st.AcceptNoise != 6 {
				t.Fatalf("status %+v: want 6 AcceptNoise, the loop in its sixth wait", st)
			}
			t0 := time.Now()
			err := w.stop()
			if el := time.Since(t0); !errors.Is(err, context.Canceled) || el != 0 || w.pl.closes.Load() != 1 {
				t.Fatalf("ServeTCP = %v %v after the cancel, %d Closes; want context.Canceled at once, ln closed once", err, el, w.pl.closes.Load())
			}
			if n := len(w.pl.acceptCalls()); n != 6 {
				t.Fatalf("%d Accept calls, want 6 (none after the stop)", n)
			}
		})
	})

	t.Run("accept-errors", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := newPTWorld(t, ptOpts{})
			// The first error comes with a conn (a listener that breaks
			// the contract): it is reset, not served. The fourth is a
			// timeout that does not call itself temporary (a deadline on an
			// embedder's listener): backed off as well.
			both, srv := rendrtest.TargetPipe(0)
			w.pl.q <- ptAccept{c: srv, err: ptTempErr{}}
			for i := range 6 {
				var err error = ptTempErr{}
				if i == 2 {
					err = ptTimeoutErr{}
				}
				w.pl.q <- ptAccept{err: err}
			}
			w.pl.q <- ptAccept{} // (nil, nil): a broken listener, retried
			c := w.pl.dial()
			w.serveTCP()
			ptPing(t, c, 256)
			synctest.Wait() // the loop waits in Accept again
			calls := w.pl.acceptCalls()
			ms := time.Millisecond
			want := []time.Duration{5 * ms, 10 * ms, 20 * ms, 40 * ms, 80 * ms, 100 * ms, 100 * ms, 100 * ms}
			if len(calls) != len(want)+1 {
				t.Fatalf("%d Accept calls returned, want %d", len(calls), len(want)+1)
			}
			for i, d := range want {
				if g := calls[i+1].Sub(calls[i]); g != d {
					t.Fatalf("Accept call %d returned %v after the previous one, want %v (all: %v)", i+2, g, d, calls)
				}
			}
			// After a connection the back-off starts again at 5 ms; a
			// permanent error ends the serve, resetting the live
			// connection.
			w.pl.q <- ptAccept{err: ptTempErr{}}
			w.pl.q <- ptAccept{err: ptTempErr{}}
			w.pl.q <- ptAccept{err: errPTPermanent}
			if err := w.result(time.Minute); !errors.Is(err, errPTPermanent) {
				t.Fatalf("ServeTCP = %v, want the permanent Accept error", err)
			}
			calls = w.pl.acceptCalls()
			n := len(calls)
			if g1, g2 := calls[n-2].Sub(calls[n-3]), calls[n-1].Sub(calls[n-2]); g1 != 5*ms || g2 != 10*ms {
				t.Fatalf("after a connection: gaps %v, %v, want 5 ms, 10 ms", g1, g2)
			}
			if err := ptEndNow(c); !isReset(err) {
				t.Fatalf("the live connection at the return: %v, want reset", err)
			}
			if err := ptEndNow(both); !isReset(err) {
				t.Fatalf("the conn returned with an Accept error: %v, want reset", err)
			}
			if st := w.pf.Status().TCP; st.AcceptNoise != 10 || st.Accepted != 1 || st.Live != 0 || w.pl.closes.Load() != 1 || len(w.requests()) != 1 {
				t.Fatalf("status %+v, %d Closes: want 10 AcceptNoise, 1 accepted, ln closed once", st, w.pl.closes.Load())
			}
		})
	})
	t.Run("listener-closed", func(t *testing.T) {
		// net.ErrClosed from a close by someone else ends the serve.
		synctest.Test(t, func(t *testing.T) {
			w := newPTWorld(t, ptOpts{})
			w.serveTCP()
			c := w.pl.dial()
			ptPing(t, c, 256)
			w.pl.q <- ptAccept{err: errPTClosed}
			if err := w.result(time.Minute); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("ServeTCP = %v, want net.ErrClosed", err)
			}
			if err := ptEndNow(c); !isReset(err) || w.pl.closes.Load() != 1 {
				t.Fatalf("the live connection: %v, %d Closes; want reset, ln closed once", err, w.pl.closes.Load())
			}
		})
	})

	t.Run("peer-closed", func(t *testing.T) {
		// A closed Peer (Dial's net.ErrClosed) ends the serve.
		synctest.Test(t, func(t *testing.T) {
			w := newPTWorld(t, ptOpts{})
			w.serveTCP()
			c := w.pl.dial()
			ptPing(t, c, 256)
			w.peer.Close()
			c2 := w.pl.dial()
			if err := w.result(time.Minute); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("ServeTCP = %v, want net.ErrClosed", err)
			}
			for i, cc := range []*rendrtest.TargetConn{c, c2} {
				if err := ptEndNow(cc); !isReset(err) {
					t.Fatalf("connection %d at the return: %v, want reset", i, err)
				}
			}
			if st := w.pf.Status().TCP; st.Failed != 0 || st.Live != 0 || w.pl.closes.Load() != 1 {
				t.Fatalf("status %+v, %d Closes: want no failure counted, nothing live, ln closed once", st, w.pl.closes.Load())
			}
		})
	})

	t.Run("accepted-at-stop", func(t *testing.T) {
		// A connection Accept returns as the serve stops is reset, not
		// dialled.
		synctest.Test(t, func(t *testing.T) {
			w := newPTWorld(t, ptOpts{})
			w.pl.before = func() { w.cancel() }
			c := w.pl.dial()
			w.serveTCP()
			if err := w.result(time.Minute); !errors.Is(err, context.Canceled) {
				t.Fatalf("ServeTCP = %v, want context.Canceled", err)
			}
			if err := ptEndNow(c); !isReset(err) {
				t.Fatalf("the connection accepted at the stop: %v, want reset", err)
			}
			if st := w.pf.Status().TCP; st.Accepted != 0 || len(w.requests()) != 0 {
				t.Fatalf("status %+v, %d requests: want it neither counted nor dialled", st, len(w.requests()))
			}
		})
	})

	t.Run("checks", func(t *testing.T) {
		// Before the first Accept: no Peer, an invalid target, a
		// non-loopback bind without AllowNonLoopback; ln closed once and
		// never accepted from. The bind check passes for loopback, a
		// Unix-domain listener and, with the flag, any address: a cancelled
		// ctx then returns context.Canceled.
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			peer := &rendr.Peer{}
			for _, r := range []struct {
				name   string
				pf     *PortForward
				addr   net.Addr
				target string
				want   error
			}{
				{"no peer", &PortForward{}, ptLoopback, ptTarget, errNoPeer},
				{"bad target", &PortForward{Peer: peer}, ptLoopback, "no-port", ErrBadAddress},
				{"port 0", &PortForward{Peer: peer}, ptLoopback, "target.test:0", ErrBadAddress},
				{"bracketed name", &PortForward{Peer: peer}, ptLoopback, "[target.test]:80", ErrBadAddress},
				{"non-loopback", &PortForward{Peer: peer}, &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 80}, ptTarget, ErrNonLoopback},
				{"unspecified", &PortForward{Peer: peer}, &net.TCPAddr{Port: 80}, ptTarget, ErrNonLoopback},
				{"ipv6 unspecified", &PortForward{Peer: peer}, &net.TCPAddr{IP: net.IPv6unspecified, Port: 80}, ptTarget, ErrNonLoopback},
				{"allowed", &PortForward{Peer: peer, AllowNonLoopback: true}, &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 80}, ptTarget, context.Canceled},
				{"ipv6 loopback", &PortForward{Peer: peer}, &net.TCPAddr{IP: net.IPv6loopback, Port: 80}, ptTarget, context.Canceled},
				{"unix", &PortForward{Peer: peer}, &net.UnixAddr{Name: "/run/pf.sock", Net: "unix"}, ptTarget, context.Canceled},
			} {
				l := newPTListener(r.addr)
				err := r.pf.ServeTCP(ctx, l, r.target)
				if !errors.Is(err, r.want) || l.closes.Load() != 1 {
					t.Errorf("%s: ServeTCP = %v, %d Closes; want %v, closed once", r.name, err, l.closes.Load(), r.want)
				}
				if r.want != context.Canceled && len(l.acceptCalls()) != 0 {
					t.Errorf("%s: %d Accept calls before the refusal", r.name, len(l.acceptCalls()))
				}
			}
		})
		// Real listeners: a loopback TCP one and a Unix-domain one pass the
		// checks and are closed by ServeTCP. Either failing to listen fails
		// the row; only a platform without Unix-domain sockets has no
		// Unix-domain row.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		pf := &PortForward{Peer: &rendr.Peer{}}
		rows := []struct{ network, addr string }{{"tcp", "127.0.0.1:0"}}
		switch runtime.GOOS {
		case "plan9", "js", "wasip1":
			t.Logf("no Unix-domain listener row: %s has no Unix-domain sockets", runtime.GOOS)
		default:
			// A short directory: a socket path holds about 100 bytes, which a
			// t.TempDir path on darwin nearly uses up.
			dir, err := os.MkdirTemp("", "pt")
			if err != nil {
				t.Fatalf("MkdirTemp: %v", err)
			}
			t.Cleanup(func() { os.RemoveAll(dir) })
			rows = append(rows, struct{ network, addr string }{"unix", filepath.Join(dir, "pf.sock")})
		}
		for _, r := range rows {
			ln, err := net.Listen(r.network, r.addr)
			if err != nil {
				t.Fatalf("%s listener: %v", r.network, err)
			}
			if err := pf.ServeTCP(ctx, ln, ptTarget); !errors.Is(err, context.Canceled) {
				t.Errorf("real %s listener: ServeTCP = %v, want context.Canceled", r.network, err)
			}
			if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
				t.Errorf("real %s listener: not closed by ServeTCP (Accept: %v)", r.network, err)
			}
		}
	})
}

// ptStopRow is the /stop subtest (EarlyReturn early): four connections
// forwarding, a fifth stuck in its dial (with EarlyReturn: pending, its
// OPEN unanswered), a sixth forwarding whose server end's Close is gated.
// After the cancel ServeTCP returns only once the gated teardown ran,
// every client reset, nothing counted as a failure, ln closed once.
func ptStopRow(t *testing.T, early bool) {
	var dialling atomic.Int32
	var w *ptWorld
	w = newPTWorld(t, ptOpts{
		hook: func(ctx context.Context, r Request) (net.Conn, error) {
			if dialling.Add(1) == 5 {
				<-ctx.Done() // the fifth connection's dial never completes
				return nil, ctx.Err()
			}
			return w.echo.Dial(ctx, r.Addr)
		},
		pfwd: func(f *PortForward) { f.Options.EarlyReturn = early },
	})
	w.serveTCP()
	var cs []*rendrtest.TargetConn
	for range 4 {
		c := w.pl.dial()
		ptPing(t, c, 512)
		cs = append(cs, c)
	}
	cs = append(cs, w.pl.dial())
	waitFor(t, 10*time.Second, "the fifth dial at the passive", func() bool { return dialling.Load() == 5 })
	// The sixth connection's teardown takes until release.
	slow, release := w.pl.dialGated()
	ptPing(t, slow, 512)
	cs = append(cs, slow)
	select {
	case err := <-w.served:
		t.Fatalf("EarlyReturn %v: ServeTCP returned %v before its ctx ended", early, err)
	default:
	}
	if st := w.pf.Status().TCP; st.Live != 6 || st.Accepted != 6 {
		t.Fatalf("EarlyReturn %v: status %+v: want 6 live (5 forwarding, 1 dialling)", early, st)
	}
	w.cancel()
	synctest.Wait()
	select {
	case err := <-w.served:
		t.Fatalf("EarlyReturn %v: ServeTCP returned %v while a connection's teardown still ran", early, err)
	default:
	}
	release()
	if err := w.result(time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatalf("EarlyReturn %v: ServeTCP = %v, want context.Canceled", early, err)
	}
	// At the return every connection has ended: each client is
	// reset already (none waits), and ln was closed once.
	for i, c := range cs {
		if err := ptEndNow(c); !isReset(err) {
			t.Fatalf("EarlyReturn %v: connection %d at ServeTCP's return: %v, want reset already", early, i, err)
		}
	}
	if st := w.pf.Status().TCP; st.Live != 0 || st.Failed != 0 || w.pl.closes.Load() != 1 {
		t.Fatalf("EarlyReturn %v: status %+v, %d Closes: want nothing live, the cancelled dial not a failure, ln closed once", early, st, w.pl.closes.Load())
	}
}
