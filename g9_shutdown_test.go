package rendr

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestDialPausedAcrossClose_L52 (design §6.6, §6.8 step 7; L52): a Dial
// that passed Peer.Dial's checks and placed its MaxSessions placeholder
// but had not yet joined the Runtime's in-flight Dials — held there by
// Hooks.DialBegin — while Runtime.Close ran to its end leaves nothing
// behind. Close does not wait for it (nothing of it had begun); resumed, it
// returns net.ErrClosed like any Dial after Close — also when its ctx ended
// meanwhile, since no opening phase ran that the ctx could have ended — its
// placeholder's unit is free, it never dialled a carrier, it is no member
// of the in-flight Dials, and no rendr goroutine is left, also after every
// bound a session would have run into. Each case repeats the sequence on
// fresh Runtimes, so that a Dial that wrongly begins after Close is caught
// whichever of its own goroutines runs first.
func TestDialPausedAcrossClose_L52(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		name := "live ctx"
		if cancelled {
			name = "ctx ended meanwhile"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				for range 4 {
					g9DialAcrossClose(t, cancelled)
				}
			})
		})
	}
}

// g9DialAcrossClose runs one sequence of TestDialPausedAcrossClose_L52.
func g9DialAcrossClose(t *testing.T, cancelled bool) {
	t.Helper()
	paused, resume := make(chan struct{}), make(chan struct{})
	var pauseOnce, resumeOnce sync.Once
	free := func() { resumeOnce.Do(func() { close(resume) }) }
	hooks := &testhooks.Hooks{DialBegin: func() {
		held := false
		pauseOnce.Do(func() { held = true })
		if held {
			close(paused)
			<-resume
		}
	}}
	rt := wpTestRuntime(t, Config{}, &testhooks.Overrides{Hooks: hooks})
	t.Cleanup(free) // runs before the Runtime's own cleanup (LIFO)
	f := &countingFactory{name: "f", err: errors.New("refused")}
	peer, err := rt.NewPeer(PeerConfig{Carriers: []Carrier{f.carrier()}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res := e2eDialAsync(ctx, peer, DialOptions{})
	select {
	case <-paused:
	case r := <-res:
		t.Fatalf("stimulus: the Dial returned (%v, %v) without reaching Hooks.DialBegin", r.c, r.err)
	}
	if n := rt.table.inUse(); n != 1 {
		t.Fatalf("stimulus: %d MaxSessions units while the Dial is held, want its placeholder's", n)
	}
	start := time.Now()
	if err := rt.Close(); err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el != 0 {
		t.Fatalf("Runtime.Close took %v: it waited for a Dial that had not begun", el)
	}
	if cancelled {
		cancel()
	}
	free()
	if r := <-res; r.c != nil || !errors.Is(r.err, net.ErrClosed) {
		t.Fatalf("Dial resumed after Runtime.Close: %v, %v; want net.ErrClosed", r.c, r.err)
	}
	if n := rt.dial.running(); n != 0 {
		t.Fatalf("%d in-flight Dials after the Dial returned", n)
	}
	synctest.Wait()
	if n, left := rendrGoroutines(); n != 0 || f.calls.Load() != 0 {
		t.Fatalf("after the Dial returned: rendr goroutines %v, %d factory calls; want none", left, f.calls.Load())
	}
	time.Sleep(time.Minute) // past NoPathGrace, Linger and every join bound
	synctest.Wait()
	if n, left := rendrGoroutines(); n != 0 || f.calls.Load() != 0 || rt.dial.running() != 0 {
		t.Fatalf("a minute later: rendr goroutines %v, %d factory calls, %d in-flight Dials; want none", left, f.calls.Load(), rt.dial.running())
	}
	wpNoState(t, rt)
	if st := rt.Status(); st.Abandoned != 0 || st.Sessions.Tombstones != 0 {
		t.Fatalf("after Close: %+v", st)
	}
}

// g9HelloConn is the passive end of a net.Pipe for the handshake tests:
// ReadHello's last conn call — SetDeadline(zero), made after it read the
// first frame — waits at a gate the test opens, and the first SetDeadline
// after that call returned hangs until freed: a conn whose deadline setters
// hang once it was closed under them (L51).
type g9HelloConn struct {
	net.Conn
	atGate   chan struct{} // closed when ReadHello's SetDeadline(zero) arrived
	gate     chan struct{} // closed by openGate: that call proceeds
	release  chan struct{} // closed by free: the hanging call returns
	helloed  atomic.Bool   // ReadHello's SetDeadline(zero) returned
	hang     atomic.Bool   // the one hanging call was taken
	hanging  atomic.Int32  // calls hanging now
	closes   atomic.Int32  // Close calls (the embedder's Close; L51: once)
	gateOnce sync.Once
	freeOnce sync.Once
}

func newG9HelloConn(c net.Conn) *g9HelloConn {
	return &g9HelloConn{Conn: c, atGate: make(chan struct{}), gate: make(chan struct{}), release: make(chan struct{})}
}

func (c *g9HelloConn) SetDeadline(t time.Time) error {
	switch {
	case t.IsZero() && !c.helloed.Load():
		close(c.atGate) // ReadHello clears its deadline once
		<-c.gate
		err := c.Conn.SetDeadline(t)
		c.helloed.Store(true)
		return err
	case c.helloed.Load() && c.hang.CompareAndSwap(false, true):
		c.hanging.Add(1)
		<-c.release
		c.hanging.Add(-1)
		return net.ErrClosed
	}
	return c.Conn.SetDeadline(t)
}

func (c *g9HelloConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

// openGate lets ReadHello's held SetDeadline(zero) proceed (idempotent).
func (c *g9HelloConn) openGate() { c.gateOnce.Do(func() { close(c.gate) }) }

// free opens the gate and returns the hanging call (idempotent). It is also
// a cleanup, so that a test that failed anywhere — before it opened the
// gate included — still ends its bubble: the held ReadHello proceeds, and
// the call that would hang after it returns at once.
func (c *g9HelloConn) free() {
	c.openGate()
	c.freeOnce.Do(func() { close(c.release) })
}

// TestHelloOutlivingSlotJoinedByClose_L52 (design §6.1, §6.8 step 7; L52):
// a handshake whose slot is taken while ReadHello is still in its last
// conn call — after it read the whole OPEN — finds the slot gone when
// ReadHello returns its Hello: evicted by a newer handshake (the only slot,
// Handshake.MaxConcurrent 1), or drained by Runtime.Close. It kills the
// unstarted carrier and stays a member of the handshake group until that
// carrier is done, so Runtime.Close joins it. The carrier's closer hangs in
// the embedder's SetDeadline: Close returns only once the carrier's own
// bound (AbandonWait after the kill, before Close's cut) counted it, so
// that every rendr goroutine still alive when Close returns is counted in
// Status.Abandoned. The conn is closed exactly once (by the eviction or
// the drain), and when the hanging call returns nothing is left.
func TestHelloOutlivingSlotJoinedByClose_L52(t *testing.T) {
	const wait = 500 * time.Millisecond // < min(1 s, DeadMax): the carrier's bound ends before Close's cut
	for _, drained := range []bool{false, true} {
		name := "evicted"
		if drained {
			name = "drained by Runtime.Close"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				rt := wpTestRuntime(t, Config{Handshake: HandshakeLimits{MaxConcurrent: 1}}, &testhooks.Overrides{AbandonWait: wait})
				ln := wpListen(t, rt, ListenConfig{})
				a, b := net.Pipe()
				hc := newG9HelloConn(a)
				t.Cleanup(hc.free)
				if err := ln.Handle(hc); err != nil {
					t.Fatal(err)
				}
				d := &wpDialer{t: t, nc: b, inst: wpInst(0xb2), id: 1, txFseq: wire.FirstFseq, rxFseq: wire.FirstFseq}
				t.Cleanup(d.close)
				d.hello(rt)
				d.send(wire.TypeOpen, 0, wpOpen(wpSID(1), wire.KindStream, 1, nil))
				select {
				case <-hc.atGate:
				case <-time.After(time.Minute):
					t.Fatal("stimulus: ReadHello never cleared its deadline after it read the OPEN")
				}
				synctest.Wait()

				closed := make(chan struct{})
				closeRuntime := func() {
					go func() {
						rt.Close()
						close(closed)
					}()
				}
				start := time.Now()
				if drained {
					closeRuntime()
				} else {
					wpConnect(t, ln, wpInst(0xb3), 2) // takes the only slot: the held handshake is evicted
				}
				synctest.Wait()
				if st := rt.Status(); hc.closes.Load() != 1 || (!drained && st.HandshakeEvictions != 1) {
					t.Fatalf("stimulus: conn closed %d times, %+v; want the slot taken while ReadHello waits", hc.closes.Load(), st)
				}
				select {
				case <-closed:
					t.Fatal("Runtime.Close returned while a handshake was inside ReadHello")
				default:
				}
				hc.openGate() // ReadHello returns its Hello; the handshake finds its slot gone
				synctest.Wait()
				if n := hc.hanging.Load(); n != 1 {
					t.Fatalf("stimulus: %d calls hang in SetDeadline, want the discarded carrier's closer", n)
				}
				if !drained {
					closeRuntime()
				}
				<-closed
				el := time.Since(start)
				synctest.Wait() // time stands still: what runs now outlived Close
				n, left := rendrGoroutines()
				if ab := rt.Status().Abandoned; n != ab || ab == 0 {
					t.Fatalf("Runtime.Close returned after %v with rendr goroutines %v and %d counted in Status.Abandoned; want the hanging closer, counted", el, left, ab)
				}
				if bound := max(min(time.Second, rt.eff.cfg.DeadMax)+wait, 2*wait) + closeSlack; el > bound {
					t.Fatalf("Runtime.Close took %v, bound %v", el, bound)
				}
				hc.free()
				synctest.Wait()
				if n, left := rendrGoroutines(); n != 0 || rt.Status().Abandoned != 0 || hc.closes.Load() != 1 {
					t.Fatalf("after the hanging call returned: rendr goroutines %v, abandoned %d, conn closed %d times", left, rt.Status().Abandoned, hc.closes.Load())
				}
				wpNoState(t, rt)
			})
		})
	}
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
		for it := ln.head; it != nil; it = it.next {
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
