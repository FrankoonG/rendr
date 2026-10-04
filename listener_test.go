package rendr

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

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
	// dialer GOING_AWAY); a session still queued is refused GOING_AWAY.
	// Each dialer gets exactly one answer, OK only for a confirmed session,
	// and no slot or unit survives the Runtime. Both outcomes occur.
	var oks, refusals int
	for i := range 100 {
		synctest.Test(t, func(t *testing.T) {
			rt := wpTestRuntime(t, Config{}, nil)
			ln := wpListen(t, rt, ListenConfig{})
			const sessions = 3
			answers := make(chan wire.AckStatus, sessions)
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
					answers <- a.Status
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
				switch st := <-answers; st {
				case wire.StatusOK:
					ok++
					oks++
				case wire.StatusGoingAway:
					refusals++
				default:
					t.Fatalf("run %d: a pending session was answered %d", i, st)
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

// TestListenerClosePendingGoingAway_L50: Listener.Close answers every
// session that is still pending OPEN_ACK(GOING_AWAY) at once — one the
// application accepted but did not decide and one still queued — and
// returns within 100 ms (L50). The dialers' Dials return ErrCapacity, the
// dialer's Peer records the instance as gone away (D21), Confirm of the
// accepted PendingConn and Accept return net.ErrClosed, and the passive
// keeps two GOING_AWAY tombstones and no pending slot.
func TestListenerClosePendingGoingAway_L50(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
		peer := e.peer()
		r1 := e2eDialAsync(context.Background(), peer, DialOptions{})
		pc, err := e.ln.Accept(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		r2 := e2eDialAsync(context.Background(), peer, DialOptions{Mode: ModeBond})
		synctest.Wait()
		if st := e.p.Status(); st.Sessions.Pending != 2 || st.AcceptBacklog[0] != 2 {
			t.Fatalf("before Close: %+v", st)
		}
		start := time.Now()
		if err := e.ln.Close(); err != nil || time.Since(start) > 100*time.Millisecond {
			t.Fatalf("Listener.Close = %v after %v", err, time.Since(start))
		}
		for i, res := range []<-chan dialResult{r1, r2} {
			if r := <-res; r.c != nil || !errors.Is(r.err, ErrCapacity) {
				t.Fatalf("Dial %d of a pending session at Listener.Close: %v, %v", i+1, r.c, r.err)
			}
		}
		if !peer.goneAway(e.p.InstanceID()) {
			t.Fatal("the Peer did not record the instance that answered GOING_AWAY")
		}
		if c, err := pc.Confirm(); c != nil || !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Confirm after Listener.Close: %v, %v", c, err)
		}
		if pc2, err := e.ln.Accept(context.Background()); pc2 != nil || !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept after Listener.Close: %v, %v", pc2, err)
		}
		synctest.Wait()
		if st := e.p.Status(); st.Sessions != (SessionCounts{Tombstones: 2}) || st.AcceptBacklog[0] != 0 {
			t.Fatalf("after Close: %+v", st)
		}
		e.close()
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
