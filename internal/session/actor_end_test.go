package session

import (
	"context"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The end phase and the join of every goroutine the session owns (design
// §4.7, §6.8; C24, L51, L52).

// acSwitchFactory is a factory whose first dial uses link first and every
// later dial link next: a slot whose redial reaches another path.
func acSwitchFactory(name string, first, next *rendrtest.Link) carrier.Factory {
	var used atomic.Bool
	return carrier.Factory{Name: name, Dial: func(ctx context.Context) (net.Conn, error) {
		if used.CompareAndSwap(false, true) {
			return first.Dial(ctx)
		}
		return next.Dial(ctx)
	}}
}

// openSpec dials spec and confirms the passive side.
func (w *acWorld) openSpec(spec DialSpec, h healthSource) (dialer, passive *Session) {
	w.t.Helper()
	type res struct {
		s   *Session
		err error
	}
	ch := make(chan res, 1)
	go func() {
		s, err := w.dial(context.Background(), spec, h)
		ch <- res{s, err}
	}()
	passive = w.confirmNext()
	r := <-ch
	if r.err != nil {
		w.t.Fatalf("Dial: %v", r.err)
	}
	return r.s, passive
}

// TestActorCloseBoundKillsStuckClose: Shutdown while the dialer's carrier
// is stuck in a Hard-blocked embedder Write (it ignores deadlines and
// Close): the RST, GOAWAY and CLOSE can never be written, so at the close
// bound min(1 s, DeadMax) the actor kills the lane (C24, before the stall
// watchdog could); the stuck writer is abandoned AbandonWait later and
// Done closes then — inside Runtime.Close's 2 s join bound, with exactly
// that goroutine in the abandoned pool until the write returns.
func TestActorCloseBoundKillsStuckClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		w.a.cenv.Timing.WriteStall = 2 * time.Second // the stall watchdog fires after the close bound
		l1 := w.link("p1")
		a, _ := w.open(ModeSelector, nil, l1)
		synctest.Wait()
		a.mu.Lock()
		lane := a.ctl.active
		a.mu.Unlock()
		l1.BlockWrites(rendrtest.Up, rendrtest.BlockHard)
		start := time.Now()
		a.Shutdown()
		acDone(t, a, 5*time.Second)
		d := time.Since(start)
		bound := min(closeBound, w.a.cenv.Timing.DeadMax) + w.a.cenv.Timing.AbandonWait
		if d < bound || d > bound+50*time.Millisecond {
			t.Fatalf("Done %v after Shutdown, want the close bound plus AbandonWait (%v)", d, bound)
		}
		dead, cause, detail, at := lane.c.Death()
		if !dead || cause != carrier.CauseLocalClose || !strings.Contains(detail, "close bound") {
			t.Fatalf("the stuck lane ended with %v %q, want local_close at the close bound", cause, detail)
		}
		if k := at.Sub(start); k < closeBound || k > closeBound+50*time.Millisecond {
			t.Fatalf("killed %v after Shutdown, want at the close bound %v", k, closeBound)
		}
		if st := l1.Stats().Session; st.WritesBlocked == 0 {
			t.Fatal("no write was blocked (stimulus)")
		}
		if n := w.a.cenv.Abandon.Len(); n != 1 {
			t.Fatalf("abandoned pool %d after Done, want the stuck writer", n)
		}
		l1.Release()
		synctest.Wait()
		if n := w.a.cenv.Abandon.Len(); n != 0 {
			t.Fatalf("abandoned pool %d after the write returned, want 0", n)
		}
	})
}

// TestActorEndPhaseWakesOnLastJoin: in the end phase the actor waits for
// the Done of each carrier it removed. The test holds the actor right
// before it blocks — after it decided, in one look at its carriers, that it
// cannot exit yet and which Done it waits on — and lets exactly that last
// carrier finish then (its writer was stuck in a Hard-blocked Write after
// the close-bound Kill). The actor must wake at once and exit: a second,
// later look would find nothing left to wait on, and an actor that decided
// from it would sleep with no timer armed, so Done would never close (L52).
func TestActorEndPhaseWakesOnLastJoin(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		w.a.cenv.Timing.WriteStall = 2 * time.Second
		l1 := w.link("p1")
		a, _ := w.open(ModeSelector, nil, l1)
		synctest.Wait()
		a.mu.Lock()
		stuck := a.ctl.active.c
		a.mu.Unlock()
		l1.BlockWrites(rendrtest.Up, rendrtest.BlockHard)
		var fired atomic.Bool
		finished := make(chan time.Time, 1)
		hook := func(s *Session) {
			if s != a || fired.Load() {
				return
			}
			s.mu.Lock()
			reaped := s.ctl.state == StateEnded && len(s.lanes) == 0
			s.mu.Unlock()
			if !reaped {
				return
			}
			select {
			case <-stuck.Done():
				return // already joined: not the window under test
			default:
			}
			fired.Store(true)
			l1.Release() // the stuck Write returns: the carrier's last goroutine finishes now
			select {
			case <-stuck.Done():
			case <-time.After(5 * time.Second):
			}
			finished <- time.Now()
		}
		beforeWaitHook.Store(&hook)
		defer beforeWaitHook.Store(nil)
		a.Shutdown()
		acDone(t, a, 30*time.Second)
		var at time.Time
		select {
		case at = <-finished:
		default:
			t.Fatal("the actor never waited for the stuck carrier in the end phase (stimulus)")
		}
		if d := time.Since(at); d > 10*time.Millisecond {
			t.Fatalf("Done %v after the last carrier finished, want at once", d)
		}
		select {
		case <-stuck.Done():
		default:
			t.Fatal("the carrier released in the window is not done")
		}
	})
}

// acGoexitConn calls runtime.Goexit in its first Read: an embedder conn
// that ends the calling goroutine (L51).
type acGoexitConn struct {
	net.Conn
	reads *atomic.Int32
}

func (c *acGoexitConn) Read(p []byte) (int, error) {
	if c.reads.Add(1) == 1 {
		runtime.Goexit()
	}
	return c.Conn.Read(p)
}

// TestActorAttemptGoexitReported: the conn of a redial calls runtime.Goexit
// on the attempt goroutine while Establish reads its PREFACE_ACK.
// Establish closes that conn and releases its ID itself; the attempt's own
// deferred cleanup reports the attempt as failed, so the slot redials after
// its backoff and the session recovers well inside its grace; nothing is
// left in the abandoned pool and the CarrierID allocator.
func TestActorAttemptGoexitReported(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		l1 := w.link("p1")
		var goexit atomic.Bool
		var reads atomic.Int32
		var calls atomic.Int32
		f := carrier.Factory{Name: "p1", Dial: func(ctx context.Context) (net.Conn, error) {
			calls.Add(1)
			c, err := l1.Dial(ctx)
			if err == nil && goexit.CompareAndSwap(true, false) {
				return &acGoexitConn{Conn: c, reads: &reads}, nil
			}
			return c, err
		}}
		spec := w.spec(ModeSelector, l1)
		spec.Factories = []carrier.Factory{f}
		a, b := w.openSpec(spec, nil)
		goexit.Store(true)
		killed := time.Now()
		l1.Kill()
		acWaitFor(t, 3*time.Second, "the slot redialled after the Goexit and attached", func() bool { return acActive(a) != 0 })
		if reads.Load() == 0 {
			t.Fatal("the Goexit conn was never read (stimulus)")
		}
		if n := calls.Load(); n != 3 {
			t.Fatalf("%d factory calls, want the opening, the Goexit attempt and its successor", n)
		}
		if d := time.Since(killed); d > 2*time.Second {
			t.Fatalf("recovered %v after the death, want the slot's backoff", d)
		}
		if n := w.a.cenv.Abandon.Len(); n != 0 {
			t.Fatalf("abandoned pool %d, want 0", n)
		}
		st := a.Status()
		if st.MigDeath != 1 || st.Rejoins != 1 || st.State != StateOpen {
			t.Fatalf("after the recovery: %+v", st)
		}
		if we, re := acTransfer(a, b, 1<<20, 71, false); we != nil || re != nil {
			t.Fatalf("transfer: %v %v", we, re)
		}
	})
}

// TestActorAbandonsStuckAttempt: the session ends while a redial is stuck
// in a Hard-blocked handshake Write that ignores its deadline, its
// cancellation and Close: the attempt is cancelled at once; Establish
// closes the conn and abandons its hello writer AbandonWait later (design
// §0.8 V1), so the attempt returns and Done closes then, with exactly that
// stuck call counted in the abandoned pool (the actor's own abandonment
// waits 2·AbandonWait and never counts it a second time); when the write
// finally returns, it leaves the pool and the conn is closed.
func TestActorAbandonsStuckAttempt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		l1, l2 := w.link("p1"), w.link("p1-redial")
		l2.BlockWrites(rendrtest.Up, rendrtest.BlockHard)
		spec := w.spec(ModeSelector, l1)
		spec.Factories = []carrier.Factory{acSwitchFactory("p1", l1, l2)}
		a, _ := w.openSpec(spec, nil)
		l1.Kill()
		acWaitFor(t, time.Second, "the redial's handshake write blocked", func() bool {
			return l2.Stats().All.WritesBlocked > 0
		})
		start := time.Now()
		a.Shutdown()
		acDone(t, a, 5*time.Second)
		d := time.Since(start)
		if wait := w.a.cenv.Timing.AbandonWait; d < wait || d > wait+50*time.Millisecond {
			t.Fatalf("Done %v after Shutdown, want the attempt abandoned after AbandonWait %v", d, wait)
		}
		if n := w.a.cenv.Abandon.Len(); n != 1 {
			t.Fatalf("abandoned pool %d, want the stuck hello Write once", n)
		}
		l2.Release()
		acWaitFor(t, 5*time.Second, "the attempt left the pool", func() bool { return w.a.cenv.Abandon.Len() == 0 })
		for _, c := range l2.Carriers() {
			if !c.Closed {
				t.Fatalf("the abandoned attempt's conn was not closed: %+v", c)
			}
		}
	})
}
