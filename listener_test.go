package rendr

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// fakeListener is a scripted net.Listener source (L50). Accept returns a
// scripted result if one is queued, else a conn pushed into conns, else it
// blocks until Close — or, with hang, until release regardless of Close.
type fakeListener struct {
	conns   chan net.Conn
	script  chan acceptResult // returned before blocking
	hang    bool
	release chan struct{}
	closed  chan struct{}
	once    sync.Once
	accepts atomic.Int32
	closes  atomic.Int32
	mu      sync.Mutex
	calls   []time.Time // when Accept was called
	panics  bool
	repeat  *acceptResult // returned on every call (never blocks)
}

type acceptResult struct {
	c   net.Conn
	err error
}

func newFakeListener() *fakeListener {
	return &fakeListener{
		conns:   make(chan net.Conn, 16),
		script:  make(chan acceptResult, 16),
		release: make(chan struct{}),
		closed:  make(chan struct{}),
	}
}

func (l *fakeListener) Accept() (net.Conn, error) {
	l.accepts.Add(1)
	l.mu.Lock()
	l.calls = append(l.calls, time.Now())
	l.mu.Unlock()
	if l.panics {
		panic("fakeListener: Accept panics")
	}
	if l.repeat != nil {
		return l.repeat.c, l.repeat.err
	}
	select {
	case r := <-l.script:
		return r.c, r.err
	default:
	}
	if l.hang {
		<-l.release
		return nil, errors.New("fakeListener: released")
	}
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *fakeListener) Close() error {
	l.closes.Add(1)
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *fakeListener) Addr() net.Addr { return fakeAddr{} }

func (l *fakeListener) callTimes() []time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]time.Time(nil), l.calls...)
}

type fakeAddr struct{}

func (fakeAddr) Network() string { return "fake" }
func (fakeAddr) String() string  { return "fake" }

// emfile is the accept error of an exhausted fd table (a temporary error).
func emfile() error {
	return &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept", syscall.EMFILE)}
}

// pushProbe delivers a scripted probe carrier through src and runs it up
// to its first PONG.
func pushProbe(t testing.TB, rt *Runtime, src *fakeListener, inst [16]byte, id uint32) *wpDialer {
	t.Helper()
	a, b := net.Pipe()
	src.conns <- a
	d := &wpDialer{t: t, nc: b, inst: inst, id: id, txFseq: wire.FirstFseq, rxFseq: wire.FirstFseq}
	d.hello(rt)
	d.send(wire.TypePing, 0, wpPing(wire.Ping{ID: id, Nonce: uint64(id)}))
	d.expect(wire.TypePong)
	return d
}

// TestListenerClosedRefusesWork_L50: after Close, Handle returns
// net.ErrClosed and closes the conn exactly once, Accept returns
// net.ErrClosed, Close stays idempotent, and the Runtime forgets the
// Listener; Handle(nil) is an error that touches nothing.
func TestListenerClosedRefusesWork_L50(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		ln := wpListen(t, rt, ListenConfig{})
		if err := ln.Handle(nil); err == nil || errors.Is(err, net.ErrClosed) {
			t.Fatalf("Handle(nil) = %v", err)
		}
		for range 2 {
			if err := ln.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
		}
		a, b := net.Pipe()
		c := &countConn{Conn: a}
		if err := ln.Handle(c); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Handle after Close: %v", err)
		}
		var buf [1]byte
		if n, err := b.Read(buf[:]); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("pushed conn after Close: read (%d, %v)", n, err)
		}
		synctest.Wait()
		if n := c.closes.Load(); n != 1 {
			t.Fatalf("pushed conn closed %d times", n)
		}
		if pc, err := ln.Accept(context.Background()); pc != nil || !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept after Close: %v, %v", pc, err)
		}
		rt.mu.Lock()
		_, known := rt.listeners[ln]
		rt.mu.Unlock()
		if known {
			t.Fatal("the Runtime still holds a closed Listener")
		}
		rt.Close()
		wpNoState(t, rt)
	})
}

// TestAcceptContextAndClose_L50: Accept honours its ctx (an ended ctx
// returns ctx.Err() at once, a deadline returns at the deadline) and
// returns net.ErrClosed as soon as its Listener or the Runtime closes;
// it always returns exactly one of a PendingConn and an error.
func TestAcceptContextAndClose_L50(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		ln := wpListen(t, rt, ListenConfig{})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if pc, err := ln.Accept(ctx); pc != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("Accept(cancelled) = %v, %v", pc, err)
		}
		start := time.Now()
		ctx, cancel = context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		if pc, err := ln.Accept(ctx); pc != nil || !errors.Is(err, context.DeadlineExceeded) || time.Since(start) != 300*time.Millisecond {
			t.Fatalf("Accept(deadline) = %v, %v after %v", pc, err, time.Since(start))
		}

		accept := func(ln *Listener) <-chan error {
			ch := make(chan error, 1)
			go func() {
				pc, err := ln.Accept(context.Background())
				if pc != nil {
					err = errors.New("a PendingConn without a session")
				}
				ch <- err
			}()
			return ch
		}
		blocked := accept(ln)
		synctest.Wait()
		start = time.Now()
		ln.Close()
		if err := <-blocked; !errors.Is(err, net.ErrClosed) || time.Since(start) != 0 {
			t.Fatalf("blocked Accept at Listener.Close: %v after %v", err, time.Since(start))
		}
		ln2 := wpListen(t, rt, ListenConfig{})
		blocked = accept(ln2)
		synctest.Wait()
		rt.Close()
		if err := <-blocked; !errors.Is(err, net.ErrClosed) {
			t.Fatalf("blocked Accept at Runtime.Close: %v", err)
		}
	})
}

// TestAcceptCloseRace_L50: Accept racing Close (100 runs, four Accepts
// each, Close before, while and after they block): every Accept returns
// exactly one of (PendingConn, nil) or (nil, error) — here net.ErrClosed —
// and nothing leaks (the bubble ends with no goroutine left).
func TestAcceptCloseRace_L50(t *testing.T) {
	for i := range 100 {
		synctest.Test(t, func(t *testing.T) {
			rt := wpTestRuntime(t, Config{}, nil)
			ln := wpListen(t, rt, ListenConfig{})
			results := make(chan error, 4)
			for range 4 {
				go func() {
					pc, err := ln.Accept(context.Background())
					if (pc == nil) == (err == nil) {
						err = errors.New("Accept returned both or neither")
					}
					results <- err
				}()
			}
			if i%3 == 1 {
				synctest.Wait() // the Accepts block first
			}
			var wg sync.WaitGroup
			wg.Go(func() { ln.Close() })
			if i%3 == 2 {
				wg.Go(func() { rt.Close() })
			}
			for range 4 {
				if err := <-results; !errors.Is(err, net.ErrClosed) {
					t.Fatalf("run %d: Accept: %v", i, err)
				}
			}
			wg.Wait()
			rt.Close()
		})
	}

	// With three pending sessions queued (scripted OPENs): the ownership of
	// each is either still in the queue or with the application (L50).
	// Every Accept returns exactly one of a PendingConn or an error; a
	// session the application took is confirmed (its dialer gets
	// OPEN_ACK(OK)) unless Close refused it first (Confirm: net.ErrClosed,
	// dialer CAPACITY backlog); a session still queued is refused the same
	// way. Each dialer gets exactly one answer, OK only for a confirmed
	// session, and no slot or unit survives the Runtime. Both outcomes
	// occur.
	var oks, refusals int
	for i := range 100 {
		synctest.Test(t, func(t *testing.T) {
			rt := wpTestRuntime(t, Config{}, nil)
			ln := wpListen(t, rt, ListenConfig{})
			const sessions = 3
			answers := make(chan wire.OpenAck, sessions)
			var dialers sync.WaitGroup
			for k := range sessions {
				d := wpConnect(t, ln, wpInst(0x50), uint32(k+1))
				d.hello(rt)
				d.send(wire.TypeOpen, 0, wpOpen(wpSID(100*i+k), wire.KindStream, 1, nil))
				dialers.Go(func() {
					f := d.expect(wire.TypeOpenAck)
					a, err := wire.ParseOpenAck(f.Payload)
					if err != nil {
						t.Errorf("OPEN_ACK: %v", err)
					}
					answers <- a
					d.drain()
				})
			}
			synctest.Wait()
			var mu sync.Mutex
			var confirmed []*Conn
			var accepters sync.WaitGroup
			for range 4 {
				accepters.Go(func() {
					for {
						pc, err := ln.Accept(context.Background())
						if (pc == nil) == (err == nil) {
							t.Error("Accept returned both or neither")
							return
						}
						if err != nil {
							if !errors.Is(err, net.ErrClosed) {
								t.Errorf("Accept: %v", err)
							}
							return
						}
						c, err := pc.Confirm()
						switch {
						case err == nil:
							mu.Lock()
							confirmed = append(confirmed, c)
							mu.Unlock()
						case !errors.Is(err, net.ErrClosed):
							t.Errorf("Confirm: %v", err)
						}
					}
				})
			}
			if i%2 == 1 {
				synctest.Wait() // the Accepts run first
			}
			ln.Close()
			accepters.Wait()
			dialersDone := make(chan struct{})
			go func() {
				dialers.Wait()
				close(dialersDone)
			}()
			ok := 0
			for range sessions {
				switch a := <-answers; {
				case a.Status == wire.StatusOK:
					ok++
					oks++
				case a.Status == wire.StatusCapacity && a.Code == wire.CodeBacklog:
					refusals++
				default:
					t.Fatalf("run %d: a pending session was answered %+v", i, a)
				}
			}
			if ok != len(confirmed) {
				t.Fatalf("run %d: %d dialers got OK, %d sessions confirmed", i, ok, len(confirmed))
			}
			rt.Close()
			<-dialersDone
			wpNoState(t, rt)
		})
	}
	if oks == 0 || refusals == 0 {
		t.Fatalf("over 100 runs: %d sessions confirmed, %d refused; want both outcomes", oks, refusals)
	}
	t.Logf("over 100 runs: %d sessions confirmed, %d refused", oks, refusals)
}

// TestBlockedSourceAbandoned_L50: a source whose Accept ignores Close
// cannot hold Listener.Close: after the bound (AbandonWait) Close returns
// and the stuck accept goroutine is counted in Status.Abandoned until its
// Accept finally returns. The source is still closed exactly once, and a
// healthy source of the same Listener keeps admitting carriers meanwhile.
func TestBlockedSourceAbandoned_L50(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		blocked, good := newFakeListener(), newFakeListener()
		blocked.hang = true
		ln := wpListen(t, rt, ListenConfig{Sources: []Source{FromListener(blocked), FromListener(good)}})
		d := pushProbe(t, rt, good, wpInst(0x71), 1)
		synctest.Wait()
		if blocked.accepts.Load() != 1 {
			t.Fatalf("blocked source: %d Accept calls", blocked.accepts.Load())
		}
		start := time.Now()
		ln.Close()
		if el := time.Since(start); el != rt.eff.timing.AbandonWait {
			t.Fatalf("Listener.Close took %v, want the bound %v", el, rt.eff.timing.AbandonWait)
		}
		if st := rt.Status(); st.Abandoned != 1 {
			t.Fatalf("abandoned %d, want the stuck accept loop", st.Abandoned)
		}
		if blocked.closes.Load() != 1 || good.closes.Load() != 1 {
			t.Fatalf("sources closed %d and %d times", blocked.closes.Load(), good.closes.Load())
		}
		close(blocked.release)
		synctest.Wait()
		if st := rt.Status(); st.Abandoned != 0 {
			t.Fatalf("abandoned %d after the stuck Accept returned", st.Abandoned)
		}
		d.close()
		rt.Close()
		wpNoState(t, rt)
	})
}

// TestAcceptTemporaryErrors_L50: temporary accept errors (EMFILE) back off
// 5 ms, 10 ms, ... up to 100 ms between attempts and never stop the
// source; then (1000 runs under -race) Listener.Close and Runtime.Close
// racing an accept loop that spins on EMFILE never panic, close the source
// exactly once and join the loop.
func TestAcceptTemporaryErrors_L50(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		src := newFakeListener()
		for range 8 {
			src.script <- acceptResult{err: emfile()}
		}
		ln := wpListen(t, rt, ListenConfig{Sources: []Source{FromListener(src)}})
		time.Sleep(time.Second)
		synctest.Wait()
		calls := src.callTimes()
		want := []time.Duration{5, 10, 20, 40, 80, 100, 100, 100}
		if len(calls) != len(want)+1 {
			t.Fatalf("%d Accept calls, want %d", len(calls), len(want)+1)
		}
		for i, w := range want {
			if gap := calls[i+1].Sub(calls[i]); gap != w*time.Millisecond {
				t.Fatalf("gap %d: %v, want %v", i, gap, w*time.Millisecond)
			}
		}
		d := pushProbe(t, rt, src, wpInst(0x72), 1) // the source still works
		d.close()
		ln.Close()
		rt.Close()
		wpNoState(t, rt)
	})

	synctest.Test(t, func(t *testing.T) {
		r := rand.New(rand.NewPCG(50, 50))
		for i := range 1000 {
			rt := wpTestRuntime(t, Config{}, nil)
			src := newFakeListener()
			src.repeat = &acceptResult{err: emfile()}
			ln := wpListen(t, rt, ListenConfig{Sources: []Source{FromListener(src)}})
			time.Sleep(time.Duration(r.IntN(300)) * time.Millisecond)
			var wg sync.WaitGroup
			wg.Go(func() { ln.Close() })
			wg.Go(func() { rt.Close() })
			wg.Wait()
			if n := ln.loops.running(); n != 0 {
				t.Fatalf("run %d: %d accept goroutines left", i, n)
			}
			if n := src.closes.Load(); n != 1 {
				t.Fatalf("run %d: source closed %d times", i, n)
			}
			if st := rt.Status(); st.Abandoned != 0 {
				t.Fatalf("run %d: abandoned %d", i, st.Abandoned)
			}
		}
	})
}

// TestListenerSourceFailureIsolated_L50: one failing source never stops
// another (L50) and a misbehaving source cannot crash the process or leak
// conns (L51): a permanent error and a panic in Accept stop only that
// source (no retry), a conn returned together with an error is closed
// exactly once, (nil, nil) backs off like a temporary error instead of
// spinning, and a healthy source keeps admitting carriers.
func TestListenerSourceFailureIsolated_L50(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		failing, panicking, withConn, nilNil, good := newFakeListener(), newFakeListener(), newFakeListener(), newFakeListener(), newFakeListener()
		failing.script <- acceptResult{err: errors.New("fakeListener: permanent failure")}
		panicking.panics = true
		a, _ := net.Pipe()
		leaked := &countConn{Conn: a}
		withConn.script <- acceptResult{c: leaked, err: emfile()}
		nilNil.repeat = &acceptResult{}
		ln := wpListen(t, rt, ListenConfig{Sources: []Source{
			FromListener(failing), FromListener(panicking), FromListener(withConn), FromListener(nilNil), FromListener(good),
		}})
		time.Sleep(time.Second)
		synctest.Wait()
		if failing.accepts.Load() != 1 || panicking.accepts.Load() != 1 {
			t.Fatalf("a failed source was retried: %d and %d Accept calls", failing.accepts.Load(), panicking.accepts.Load())
		}
		if n := leaked.closes.Load(); n != 1 {
			t.Fatalf("a conn returned with an error was closed %d times", n)
		}
		if n := nilNil.accepts.Load(); n < 5 || n > 20 {
			t.Fatalf("(nil, nil) source: %d Accept calls in 1 s, want a backoff", n)
		}
		d := pushProbe(t, rt, good, wpInst(0x73), 1)
		d.close()
		ln.Close()
		rt.Close()
		wpNoState(t, rt)
	})
}

// TestListenerCloseKeepsAccepted_L50: closing a Listener never touches a
// session it already handed to the application (L50). A confirmed session
// keeps carrying data both ways after Listener.Close, while Accept returns
// net.ErrClosed; when its carrier is then killed, the dialer's JOIN arrives
// through another Listener of the same Runtime and is routed to the
// session by the Runtime's table (a carrier may arrive on any source):
// the session fails over (one death migration on both ends) and every byte
// arrives intact.
func TestListenerCloseKeepsAccepted_L50(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := wpTestRuntime(t, Config{}, nil)
		p := wpTestRuntime(t, Config{}, nil)
		ln1, ln2 := wpListen(t, p, ListenConfig{}), wpListen(t, p, ListenConfig{})
		var route atomic.Pointer[Listener]
		route.Store(ln1)
		link := rendrtest.NewLink(rendrtest.LinkConfig{Name: "a", Accept: func(c net.Conn) error { return route.Load().Handle(c) }})
		peer, err := d.NewPeer(PeerConfig{Carriers: []Carrier{e2eCarrier(link)}})
		if err != nil {
			t.Fatal(err)
		}
		dc, sc := e2eOpen(t, peer, ln1, DialOptions{})
		e2eExchange(t, dc, sc, 512<<10, 1)

		start := time.Now()
		if err := ln1.Close(); err != nil || time.Since(start) != 0 {
			t.Fatalf("Listener.Close = %v after %v", err, time.Since(start))
		}
		if pc, err := ln1.Accept(context.Background()); pc != nil || !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept after Close: %v, %v", pc, err)
		}
		e2eExchange(t, dc, sc, 512<<10, 2)

		route.Store(ln2)
		if n := link.Kill(); n != 1 {
			t.Fatalf("killed %d carriers", n)
		}
		e2eExchange(t, dc, sc, 2<<20, 3)
		for _, c := range []*Conn{dc, sc} {
			st := c.Status()
			if st.Migrations.Death != 1 || st.State != StateOpen || len(liveCarriers(st)) != 1 {
				t.Fatalf("%v after the failover: %+v", st.Role, st)
			}
		}
		if n := link.Stats().Dials; n != 2 {
			t.Fatalf("%d carrier dials, want the first and the JOIN", n)
		}
		e2eFinish(t, dc, sc)
		d.Close()
		p.Close()
		link.Close()
		wpNoState(t, d)
		wpNoState(t, p)
	})
}

// liveCarriers returns the carriers of st that are not dead.
func liveCarriers(st SessionStatus) []CarrierStatus {
	var out []CarrierStatus
	for _, c := range st.Carriers {
		if c.State != CarrierDead {
			out = append(out, c)
		}
	}
	return out
}

// TestListenerClosePendingGoingAway_L50: Listener.Close refuses every
// session that is still pending at once — one the application accepted but
// did not decide and one still queued — and returns within 100 ms (L50).
// Only the Listener closed, not the instance: the refusal is
// OPEN_ACK(CAPACITY, backlog), never GOING_AWAY, so the dialers' Dials
// return ErrCapacity and the dialer's Peer does not record the instance as
// gone away (D21 is Runtime.Close's). Confirm of the accepted PendingConn
// and Accept return net.ErrClosed, and the passive keeps two CAPACITY
// tombstones and no pending slot. The next Dial of the same Peer reaches the
// still running Runtime through its other Listener and carries data. When
// the Runtime itself closes, a pending session is answered GOING_AWAY: that
// Dial returns ErrCapacity, the Peer now records the instance (D21), and
// Confirm returns net.ErrClosed.
func TestListenerClosePendingGoingAway_L50(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := wpTestRuntime(t, Config{}, nil)
		p := wpTestRuntime(t, Config{}, nil)
		ln1, ln2 := wpListen(t, p, ListenConfig{}), wpListen(t, p, ListenConfig{})
		var route atomic.Pointer[Listener]
		route.Store(ln1)
		link := rendrtest.NewLink(rendrtest.LinkConfig{Name: "a", Accept: func(c net.Conn) error { return route.Load().Handle(c) }})
		t.Cleanup(link.Close)
		// Two sessions pending at once on carriers of their own: dedicated
		// (M3-D2; the mux case is TestMuxOpenAfterListenerClose_L50).
		peer, err := d.NewPeer(PeerConfig{Carriers: []Carrier{dedicated(e2eCarrier(link))}})
		if err != nil {
			t.Fatal(err)
		}
		r1 := e2eDialAsync(context.Background(), peer, DialOptions{})
		pc, err := ln1.Accept(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		r2 := e2eDialAsync(context.Background(), peer, DialOptions{Mode: ModeBond})
		synctest.Wait()
		if st := p.Status(); st.Sessions.Pending != 2 || st.AcceptBacklog[0] != 2 {
			t.Fatalf("before Close: %+v", st)
		}
		route.Store(ln2) // later carriers reach the Runtime through its other Listener
		start := time.Now()
		if err := ln1.Close(); err != nil || time.Since(start) > 100*time.Millisecond {
			t.Fatalf("Listener.Close = %v after %v", err, time.Since(start))
		}
		for i, res := range []<-chan dialResult{r1, r2} {
			if r := <-res; r.c != nil || !errors.Is(r.err, ErrCapacity) {
				t.Fatalf("Dial %d of a pending session at Listener.Close: %v, %v", i+1, r.c, r.err)
			}
		}
		if peer.goneAway(p.InstanceID()) {
			t.Fatal("a Listener's Close made the Peer record the running instance as gone away")
		}
		if c, err := pc.Confirm(); c != nil || !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Confirm after Listener.Close: %v, %v", c, err)
		}
		if err := pc.Reject(1, "late"); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Reject after Listener.Close: %v", err)
		}
		if pc2, err := ln1.Accept(context.Background()); pc2 != nil || !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept after Listener.Close: %v, %v", pc2, err)
		}
		synctest.Wait()
		if st := p.Status(); st.Sessions != (SessionCounts{Tombstones: 2}) || st.AcceptBacklog[0] != 0 {
			t.Fatalf("after Close: %+v", st)
		}

		// The instance runs on: the same Peer's next Dial reaches it.
		dc, sc := e2eOpen(t, peer, ln2, DialOptions{})
		if dc.PeerInstance() != p.InstanceID() {
			t.Fatalf("the Dial after Listener.Close reached %v, want %v", dc.PeerInstance(), p.InstanceID())
		}
		e2eExchange(t, dc, sc, 256<<10, 50)
		e2eFinish(t, dc, sc)

		// Runtime.Close: a pending session is answered GOING_AWAY, and only
		// now does the Peer record the instance as gone away.
		r3 := e2eDialAsync(context.Background(), peer, DialOptions{})
		pc3, err := ln2.Accept(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		p.Close()
		if r := <-r3; r.c != nil || !errors.Is(r.err, ErrCapacity) {
			t.Fatalf("Dial of a pending session at Runtime.Close: %v, %v", r.c, r.err)
		}
		if !peer.goneAway(p.InstanceID()) {
			t.Fatal("the Peer did not record the instance whose Runtime closed (D21)")
		}
		if c, err := pc3.Confirm(); c != nil || !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Confirm after Runtime.Close: %v, %v", c, err)
		}
		d.Close()
		link.Close()
		wpNoState(t, d)
		wpNoState(t, p)
	})
}

// TestAcceptSkipsEndedSessions_L50: Accept never returns a session that
// ended while it was queued (design §6.2): a queued session whose dialer
// withdrew it (RST withdrawn) and one whose AcceptTimeout expired, both
// before any Accept, are skipped — an Accept with a deadline times out
// with no PendingConn — and their backlog slots are free at once; a session
// queued after them is the one Accept returns. Stimulus proof: each was
// queued and held a backlog slot, and each dialer saw its session end
// (the CLOSE of the withdrawn one, CAPACITY(accept timeout)).
func TestAcceptSkipsEndedSessions_L50(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		ln := wpListen(t, rt, ListenConfig{AcceptTimeout: 200 * time.Millisecond})
		inst := wpInst(0x64)
		open := func(id uint32, sid int) *wpDialer {
			d := wpConnect(t, ln, inst, id)
			d.hello(rt)
			d.send(wire.TypeOpen, 0, wpOpen(wpSID(sid), wire.KindStream, 1, nil))
			return d
		}
		acceptNone := func(what string) {
			t.Helper()
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			if pc, err := ln.Accept(ctx); pc != nil || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Accept after %s: %v, %v; want no session", what, pc, err)
			}
		}
		queued := func(n int) {
			t.Helper()
			ln.mu.Lock()
			k := 0
			for it := ln.q[kindIdxStream].head; it != nil; it = it.next {
				k++
			}
			ln.mu.Unlock()
			if st := rt.Status(); k != n || st.AcceptBacklog[0] != n || st.Sessions.Pending != n {
				t.Fatalf("%d queued, status %+v; want %d", k, st, n)
			}
		}

		w := open(1, 1)
		synctest.Wait()
		queued(1)
		w.send(wire.TypeRst, 0, wpRst(uint32(AbortWithdrawn), ""))
		if seen := w.drain(); len(seen) == 0 || seen[len(seen)-1] != wire.TypeClose {
			t.Fatalf("the withdrawn session's carrier ended with %v, want its CLOSE", seen)
		}
		synctest.Wait()
		queued(0)
		acceptNone("a withdrawal")

		late := open(2, 2)
		synctest.Wait()
		queued(1)
		late.expectOpenAck(wire.StatusCapacity, wire.CodeAcceptTimeout) // 200 ms after the admission
		late.drain()
		synctest.Wait()
		queued(0)
		acceptNone("an AcceptTimeout")

		live := open(3, 3)
		pc, err := ln.Accept(context.Background())
		if err != nil || pc.ID() != SessionID(wpSID(3)) {
			t.Fatalf("Accept = %v, %v; want the live session", pc, err)
		}
		if err := pc.Reject(5, "seen"); err != nil {
			t.Fatal(err)
		}
		live.expectOpenAck(wire.StatusRejected, 5)
		live.drain()
		synctest.Wait()
		if st := rt.Status(); st.Sessions != (SessionCounts{Tombstones: 3}) || st.AcceptBacklog[0] != 0 {
			t.Fatalf("after the verdicts: %+v", st)
		}
		rt.Close()
		wpNoState(t, rt)
	})
}

// TestCarriersFromTwoSources_L50: carriers of one session may arrive
// through different sources of a Listener (L50: sessions are found by the
// Runtime, not by the source): a bond session over two factories whose
// carriers reach the passive through two FromListener sources holds both
// carriers in the one session on both ends, both carry data, and 8 MiB
// cross each way intact.
func TestCarriersFromTwoSources_L50(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := wpTestRuntime(t, Config{}, nil)
		p := wpTestRuntime(t, Config{}, nil)
		srcA, srcB := newFakeListener(), newFakeListener()
		ln := wpListen(t, p, ListenConfig{Sources: []Source{FromListener(srcA), FromListener(srcB)}})
		push := func(src *fakeListener) func(net.Conn) error {
			return func(c net.Conn) error {
				src.conns <- c
				return nil
			}
		}
		la := rendrtest.NewLink(rendrtest.LinkConfig{Name: "a", Accept: push(srcA)})
		lb := rendrtest.NewLink(rendrtest.LinkConfig{Name: "b", Accept: push(srcB)})
		for _, l := range []*rendrtest.Link{la, lb} {
			l.SetDelay(time.Millisecond, 0)
		}
		peer, err := d.NewPeer(PeerConfig{Carriers: []Carrier{e2eCarrier(la), e2eCarrier(lb)}})
		if err != nil {
			t.Fatal(err)
		}
		dc, sc := e2eOpen(t, peer, ln, DialOptions{Mode: ModeBond})
		time.Sleep(100 * time.Millisecond) // the second member joins
		e2eExchange(t, dc, sc, 8<<20, 5)
		for _, c := range []*Conn{dc, sc} {
			st := c.Status()
			live := liveCarriers(st)
			if len(live) != 2 {
				t.Fatalf("%v holds %d live carriers, want 2: %+v", st.Role, len(live), st.Carriers)
			}
			for _, cs := range live {
				if cs.TxBytes == 0 || cs.State != CarrierMember {
					t.Fatalf("%v carrier %d: %+v", st.Role, cs.ID, cs)
				}
			}
		}
		if la.Stats().Session.Bytes == 0 || lb.Stats().Session.Bytes == 0 || srcA.accepts.Load() < 2 || srcB.accepts.Load() < 2 {
			t.Fatalf("sources: A accepted %d (%d session bytes), B %d (%d)", srcA.accepts.Load(), la.Stats().Session.Bytes,
				srcB.accepts.Load(), lb.Stats().Session.Bytes)
		}
		e2eFinish(t, dc, sc)
		d.Close()
		p.Close()
		la.Close()
		lb.Close()
		wpNoState(t, d)
		wpNoState(t, p)
		if srcA.closes.Load() != 1 || srcB.closes.Load() != 1 {
			t.Fatalf("sources closed %d and %d times", srcA.closes.Load(), srcB.closes.Load())
		}
	})
}

// TestRejectedSessionEndsRejected_L50: a pending session this side's
// application rejects ends — in its EventSessionEnd — with an error that
// matches ErrRejected and names the code, not with the error of a second
// decision; a later Confirm or Reject still reports that second decision.
func TestRejectedSessionEndsRejected_L50(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var mu sync.Mutex
		var ends []error
		rt := wpTestRuntime(t, Config{OnEvent: func(ev Event) {
			if ev.Kind == EventSessionEnd {
				mu.Lock()
				ends = append(ends, ev.Err)
				mu.Unlock()
			}
		}}, nil)
		ln := wpListen(t, rt, ListenConfig{})
		d := wpConnect(t, ln, wpInst(0xa7), 1)
		d.hello(rt)
		d.send(wire.TypeOpen, 0, wpOpen(wpSID(1), wire.KindStream, 1, nil))
		pc, err := ln.Accept(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if err := pc.Reject(4242, "no route"); err != nil {
			t.Fatalf("Reject: %v", err)
		}
		d.expectOpenAck(wire.StatusRejected, 4242)
		d.drain()
		synctest.Wait()
		if err := pc.Reject(1, "again"); err == nil || errors.Is(err, ErrRejected) {
			t.Fatalf("a second Reject: %v, want the second-decision error", err)
		}
		rt.Close()
		synctest.Wait()
		mu.Lock()
		defer mu.Unlock()
		if len(ends) != 1 {
			t.Fatalf("%d session-end events, want 1: %v", len(ends), ends)
		}
		if err := ends[0]; !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "4242") {
			t.Fatalf("the rejected session's end error: %v, want one matching ErrRejected with code 4242", err)
		}
	})
}

// M4 WP1 (m4-design §A2.1, §A5.4, §A12.1): the root side of
// PendingConn.Context. Helpers start with "c4".

// c4PendingExit is one way a pending session leaves StatePending.
type c4PendingExit struct {
	name     string
	deadline bool // AcceptTimeout ended it: Err is DeadlineExceeded
	exit     func(t *testing.T, rt *Runtime, ln *Listener, pc *PendingConn, d *wpDialer)
}

func c4PendingExits() []c4PendingExit {
	return []c4PendingExit{
		{name: "Confirm", exit: func(t *testing.T, _ *Runtime, _ *Listener, pc *PendingConn, _ *wpDialer) {
			if _, err := pc.Confirm(); err != nil {
				t.Fatalf("Confirm: %v", err)
			}
		}},
		{name: "Reject", exit: func(t *testing.T, _ *Runtime, _ *Listener, pc *PendingConn, _ *wpDialer) {
			if err := pc.Reject(4000, "no"); err != nil {
				t.Fatalf("Reject: %v", err)
			}
		}},
		{name: "AcceptTimeout", deadline: true, exit: func(*testing.T, *Runtime, *Listener, *PendingConn, *wpDialer) {
			time.Sleep(c4AcceptTimeout)
		}},
		{name: "withdrawal", exit: func(t *testing.T, _ *Runtime, _ *Listener, _ *PendingConn, d *wpDialer) {
			d.send(wire.TypeRst, 0, wpRst(uint32(AbortWithdrawn), ""))
		}},
		{name: "Listener.Close", exit: func(t *testing.T, _ *Runtime, ln *Listener, _ *PendingConn, _ *wpDialer) {
			ln.Close()
		}},
		{name: "Runtime.Close", exit: func(t *testing.T, rt *Runtime, _ *Listener, _ *PendingConn, _ *wpDialer) {
			rt.Close()
		}},
	}
}

const c4AcceptTimeout = 2 * time.Second

// c4Pending admits one stream OPEN from a scripted dialer on ln and
// accepts it. The dialer's carrier is read in the background until the
// passive ends it (the returned channel closes then).
func c4Pending(t *testing.T, rt *Runtime, ln *Listener, sid int) (*PendingConn, *wpDialer, time.Time, <-chan struct{}) {
	t.Helper()
	d := wpConnect(t, ln, wpInst(0x4c), uint32(sid))
	d.hello(rt)
	admitted := time.Now()
	d.send(wire.TypeOpen, 0, wpOpen(wpSID(sid), wire.KindStream, 1, nil))
	pc, err := ln.Accept(t.Context())
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		d.drain()
	}()
	return pc, d, admitted, drained
}

// TestPendingContextDone (M4-D22, R1-8): each of the six exits from the
// pending phase closes the pending context's Done exactly once, at the
// exit (the AcceptTimeout one at the Deadline); Err is nil before, then
// context.DeadlineExceeded for AcceptTimeout and context.Canceled for every
// other exit; Deadline is the AcceptTimeout instant throughout; every call
// returns the same context; AfterFunc callbacks and derived contexts
// follow it once, and a stopped callback never runs.
func TestPendingContextDone(t *testing.T) {
	for _, x := range c4PendingExits() {
		t.Run(x.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				rt := wpTestRuntime(t, Config{}, nil)
				ln := wpListen(t, rt, ListenConfig{AcceptTimeout: c4AcceptTimeout})
				pc, d, admitted, drained := c4Pending(t, rt, ln, 1)
				ctx := pc.Context()
				if ctx != pc.Context() {
					t.Fatal("two calls returned different contexts")
				}
				dl, ok := ctx.Deadline()
				if !ok || dl.Before(admitted.Add(c4AcceptTimeout)) || dl.After(time.Now().Add(c4AcceptTimeout)) {
					t.Fatalf("Deadline %v (%v), want the AcceptTimeout instant, %v after the admission", dl.Sub(admitted), ok, c4AcceptTimeout)
				}
				if err := ctx.Err(); err != nil {
					t.Fatalf("Err while pending: %v", err)
				}
				var ran, stopped atomic.Int32
				context.AfterFunc(ctx, func() { ran.Add(1) })
				stop := context.AfterFunc(ctx, func() { stopped.Add(1) })
				if !stop() || stop() {
					t.Fatal("stop: want true once, then false")
				}
				child, cancel := context.WithCancel(ctx)
				defer cancel()
				timed, cancelT := context.WithTimeout(ctx, time.Hour) // later than the parent's deadline
				defer cancelT()
				synctest.Wait()
				select {
				case <-ctx.Done():
					t.Fatal("Done closed while pending")
				default:
				}

				x.exit(t, rt, ln, pc, d)
				synctest.Wait()
				select {
				case <-ctx.Done():
				default:
					t.Fatalf("Done still open after %s", x.name)
				}
				want := context.Canceled
				if x.deadline {
					want = context.DeadlineExceeded
					if now := time.Now(); !now.Equal(dl) {
						t.Fatalf("AcceptTimeout ended the pending phase %v off its Deadline", now.Sub(dl))
					}
				}
				if err := ctx.Err(); err != want {
					t.Fatalf("Err after %s: %v, want %v", x.name, err, want)
				}
				if dl2, ok2 := ctx.Deadline(); dl2 != dl || !ok2 {
					t.Fatalf("Deadline changed to %v (%v)", dl2, ok2)
				}
				if ran.Load() != 1 || stopped.Load() != 0 {
					t.Fatalf("AfterFunc ran %d times, the stopped one %d; want 1 and 0", ran.Load(), stopped.Load())
				}
				for _, c := range []context.Context{child, timed} {
					if err := c.Err(); err != want {
						t.Fatalf("a derived context's Err: %v, want %v", err, want)
					}
				}
				// Registered after the exit through the context's AfterFunc
				// method, as the context package does when the session leaves
				// pending between its Done check and that call (with Done
				// already closed, context.AfterFunc starts f itself and never
				// calls the method): f runs once on its own goroutine and stop
				// reports false.
				var late atomic.Int32
				af, ok := pc.Context().(interface{ AfterFunc(func()) func() bool })
				if !ok {
					t.Fatal("the pending context has no AfterFunc method")
				}
				stopLate := af.AfterFunc(func() { late.Add(1) })
				synctest.Wait()
				if late.Load() != 1 {
					t.Fatalf("an AfterFunc registered after the exit ran %d times, want 1", late.Load())
				}
				if stopLate() {
					t.Fatal("stop of an AfterFunc registered after the exit reported true")
				}
				rt.Close()
				d.close()
				<-drained
				synctest.Wait()
			})
		})
	}
}

// c4PropagateGoroutines counts the goroutines the context package started
// to watch a parent that has no AfterFunc method.
func c4PropagateGoroutines() int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return bytes.Count(buf[:n], []byte("created by context.(*cancelCtx).propagateCancel"))
		}
		buf = make([]byte, 2*len(buf))
	}
}

// TestPendingContextNoGoroutine (M4-D22, R1-8): context.AfterFunc and the
// contexts WithCancel, WithDeadline (earlier and later than the pending
// deadline) and WithTimeout derive from the pending context start no
// goroutine; they are cancelled through the session's registrations when
// the pending phase ends.
func TestPendingContextNoGoroutine(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		ln := wpListen(t, rt, ListenConfig{AcceptTimeout: c4AcceptTimeout})
		pc, d, _, drained := c4Pending(t, rt, ln, 1)
		ctx := pc.Context()
		synctest.Wait()
		before := c4PropagateGoroutines()
		var ran atomic.Int32
		context.AfterFunc(ctx, func() { ran.Add(1) })
		derived := make([]context.Context, 0, 4)
		c1, cancel1 := context.WithCancel(ctx)
		defer cancel1()
		c2, cancel2 := context.WithDeadline(ctx, time.Now().Add(time.Second))
		defer cancel2()
		c3, cancel3 := context.WithDeadline(ctx, time.Now().Add(time.Hour))
		defer cancel3()
		c4, cancel4 := context.WithTimeout(c1, time.Minute) // a grandchild
		defer cancel4()
		derived = append(derived, c1, c2, c3, c4)
		synctest.Wait()
		if n := c4PropagateGoroutines() - before; n != 0 {
			t.Fatalf("%d goroutines started to watch the pending context, want 0", n)
		}
		if _, err := pc.Confirm(); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if ran.Load() != 1 {
			t.Fatalf("AfterFunc ran %d times, want 1", ran.Load())
		}
		for i, c := range derived {
			if err := c.Err(); err != context.Canceled {
				t.Fatalf("derived context %d: Err %v, want context.Canceled", i, err)
			}
		}
		rt.Close()
		d.close()
		<-drained
		synctest.Wait()
	})
}

// TestAcceptSkipsWithdrawnQueued_L50 (design §6.2; L50): a queued session
// whose dialer withdrew it (RST withdrawn) has ended — its state is no
// longer pending — while its Registry.Ended, which unlinks it from the
// Accept queue and frees its backlog slot, is still running (held by
// Hooks.LeavePending). Accept, which finds it at the head of the queue,
// skips it and returns the live session queued after it; nothing else is
// accepted. Once Ended completes the withdrawn session's slot is free, its
// carrier ended with CLOSE, and a replay of its OPEN gets UNKNOWN_SESSION
// from the tombstone.
func TestAcceptSkipsWithdrawnQueued_L50(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gone, live := wpSID(1), wpSID(2)
		entered, release := make(chan struct{}), make(chan struct{})
		var releaseOnce sync.Once
		free := func() { releaseOnce.Do(func() { close(release) }) }
		var held atomic.Bool
		hooks := &testhooks.Hooks{LeavePending: func(sid [16]byte) {
			if sid == gone && held.CompareAndSwap(false, true) {
				close(entered)
				<-release
			}
		}}
		rt := wpTestRuntime(t, Config{}, &testhooks.Overrides{Hooks: hooks})
		t.Cleanup(free) // runs before the Runtime's own cleanup (LIFO)
		ln := wpListen(t, rt, ListenConfig{})
		inst := wpInst(0xb4)
		id := uint32(1)
		open := func(sid [16]byte) *wpDialer {
			d := wpConnect(t, ln, inst, id)
			id++
			d.hello(rt)
			d.send(wire.TypeOpen, 0, wpOpen(sid, wire.KindStream, 1, nil))
			return d
		}
		w := open(gone)
		synctest.Wait() // admitted and queued before the live one: the head of the queue
		l := open(live)
		synctest.Wait()
		w.send(wire.TypeRst, 0, wpRst(uint32(AbortWithdrawn), ""))
		drained := make(chan []wire.Type, 1)
		go func() { drained <- w.drain() }()
		select {
		case <-entered:
		case <-time.After(time.Minute):
			t.Fatal("stimulus: the withdrawn session's Registry.Ended never reached Hooks.LeavePending")
		}
		synctest.Wait()

		// Stimulus: the withdrawn session ended but is still queued at the
		// head, holding its slot, while its Ended is held.
		ln.mu.Lock()
		var queued []*session.Session
		for it := ln.q[kindIdxStream].head; it != nil; it = it.next {
			queued = append(queued, it.s)
		}
		ln.mu.Unlock()
		if len(queued) != 2 || queued[0].ID() != gone || queued[0].State() != session.StateEnded || queued[1].State() != session.StatePending {
			t.Fatalf("stimulus: %d queued sessions; want the ended withdrawn one at the head, then the live one", len(queued))
		}
		if st := rt.Status(); st.AcceptBacklog[0] != 2 || st.Sessions.Pending != 1 || st.Sessions.Tombstones != 1 {
			t.Fatalf("stimulus: %+v; want two backlog slots held, one pending session and the withdrawn one's tombstone", st)
		}

		pc, err := ln.Accept(context.Background())
		if err != nil || pc.ID() != SessionID(live) {
			var got SessionID
			if pc != nil {
				got = pc.ID()
			}
			t.Fatalf("Accept = %v, %v; want the live session %v", got, err, SessionID(live))
		}
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		if extra, err := ln.Accept(ctx); extra != nil || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("a second Accept: %v, %v; want nothing more", extra, err)
		}
		cancel()

		free()
		synctest.Wait()
		if st := rt.Status(); st.AcceptBacklog[0] != 1 || st.Sessions.Pending != 1 {
			t.Fatalf("after the withdrawn session's Ended: %+v; want only the accepted session's slot", st)
		}
		if seen := <-drained; len(seen) == 0 || seen[len(seen)-1] != wire.TypeClose {
			t.Fatalf("the withdrawn session's carrier ended with %v, want its CLOSE", seen)
		}
		if err := pc.Reject(5, "seen"); err != nil {
			t.Fatal(err)
		}
		l.expectOpenAck(wire.StatusRejected, 5)
		l.drain()
		r := open(gone)
		r.expectOpenAck(wire.StatusUnknownSession, 0)
		r.close()
		synctest.Wait()
		if st := rt.Status(); st.Sessions != (SessionCounts{Tombstones: 2}) || st.AcceptBacklog[0] != 0 {
			t.Fatalf("after the verdicts: %+v", st)
		}
		rt.Close()
		wpNoState(t, rt)
	})
}
