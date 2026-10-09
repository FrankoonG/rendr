package carrier

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The WP9 pool rows (M3 design §A11.1; §A5.8, §A5.9, §A5.13 E2, E3, E9,
// E11, E16 … E18).

// TestPoolFastPath (M3-D16): once a trunk of the factory runs, an OPEN and
// a JOIN of other sessions are new views on it — no factory call, the
// trunk's CarrierID, handles 2 and 3 — and FastPaths counts them; the
// CarrierIDs reserved for their dials are released. A fast path whose
// response does not come is bounded by DialTimeout like Establish: a path
// failure at exactly DialTimeout, the trunk left running.
func TestPoolFastPath(t *testing.T) {
	t.Run("views", testPoolFastPathViews)
	t.Run("response bounded by DialTimeout", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pt := newPoolT(t, nil, nil)
			est1, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 1, [16]byte{})
			if err != nil || !est1.Fresh {
				t.Fatalf("first attempt: %v", err)
			}
			pt.attach(est1)
			pt.srv.mu.Lock()
			pt.srv.holdViews = true // the passive admits the view and never answers it
			pt.srv.mu.Unlock()
			dt := pt.env.Timing.withDefaults().DialTimeout
			ch := make(chan poolRes, 1)
			start := time.Now()
			pt.goAttempt(context.Background(), wire.TypeOpen, 2, ch)
			synctest.Wait()
			time.Sleep(dt - time.Millisecond)
			synctest.Wait()
			if n := pendingResults(ch); n != 0 || len(pt.srv.admitted()) != 1 {
				t.Fatalf("%d results before DialTimeout, %d views admitted", n, len(pt.srv.admitted()))
			}
			r := collect(t, ch, 1)[0]
			var ee *EstablishError
			if !errors.As(r.err, &ee) || ee.Cause != CauseTransportError || ee.Stage != "response" || !errors.Is(r.err, errDialTimeout) {
				t.Fatalf("fast path without a response: %v, want a DialTimeout path failure", r.err)
			}
			if d := r.at.Sub(start); d != dt {
				t.Fatalf("the fast path failed after %v, want DialTimeout %v", d, dt)
			}
			synctest.Wait()
			if d, st := pt.srv.dials.Load(), pt.p.Stats(); d != 1 || st.FastPaths != 1 || st.Carriers != 1 || st.Views != 1 {
				t.Fatalf("%d factory calls, stats %+v; want the fast path only and the trunk kept", d, st)
			}
			if est1.Conn.trunk.death.Load() != nil {
				t.Fatal("the trunk died with the unanswered view")
			}
			if n := pt.env.IDs.inUse(); n != 1 {
				t.Fatalf("%d CarrierIDs in use, want the trunk's only", n)
			}
		})
	})
}

func testPoolFastPathViews(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pt := newPoolT(t, nil, nil)
		est1, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 1, [16]byte{})
		if err != nil || !est1.Fresh || !isOK(est1) {
			t.Fatalf("first attempt: %v (fresh %v)", err, est1 != nil && est1.Fresh)
		}
		pt.attach(est1)
		synctest.Wait()
		est2, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 2, [16]byte{})
		if err != nil || !isOK(est2) {
			t.Fatalf("fast-path OPEN: %v", err)
		}
		est3, err := pt.attempt(context.Background(), 0, wire.TypeJoin, 3, est1.Conn.PeerInstance())
		if err != nil || !isOK(est3) || est3.Resp.Type != wire.TypeJoinAck {
			t.Fatalf("fast-path JOIN: %v", err)
		}
		if n := pt.srv.dials.Load(); n != 1 {
			t.Fatalf("%d factory calls, want 1 (the fast paths dial nothing)", n)
		}
		for i, e := range []*Established{est2, est3} {
			if e.Fresh || e.Conn.trunk != est1.Conn.trunk || e.Conn.Handle() != uint32(2+i) || e.Conn.ID() != est1.Conn.ID() {
				t.Fatalf("fast path %d: fresh %v, same trunk %v, handle %d, id %d/%d", i, e.Fresh, e.Conn.trunk == est1.Conn.trunk, e.Conn.Handle(), e.Conn.ID(), est1.Conn.ID())
			}
		}
		pt.attach(est2)
		pt.attach(est3)
		synctest.Wait()
		st := pt.p.Stats()
		if st.FastPaths != 2 || st.Coalesced != 0 || st.Carriers != 1 || st.Views != 3 {
			t.Fatalf("stats %+v, want 2 fast paths on 1 carrier with 3 views", st)
		}
		if n := pt.env.IDs.inUse(); n != 1 {
			t.Fatalf("%d CarrierIDs in use, want 1 (the fast paths released theirs)", n)
		}
		if got := est1.Conn.Shared(); got != 3 {
			t.Fatalf("Shared %d, want 3", got)
		}
	})
}

// TestPoolCoalescedDial (M3-D16, M3-D19; M3-D8): eight concurrent
// attempts on a factory without a trunk make one factory call; the seven
// waiters stay waiting until the claimant's session starts the fresh
// trunk, then open their views on it (handles 2 … 8). Each passive view
// sends data right after its OK response; the dialer attaches the views
// only later, and the trunk survives (the passive held each view until its
// go frame) with every byte delivered.
func TestPoolCoalescedDial(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const n = 8
		const offer = 64 << 10
		pt := newPoolT(t, nil, nil)
		pt.srv.offer = offer
		gate := make(chan struct{})
		pt.srv.setGate(gate)
		ch := make(chan poolRes, n)
		for i := 1; i <= n; i++ {
			pt.goAttempt(context.Background(), wire.TypeOpen, byte(i), ch)
		}
		synctest.Wait()
		if d, st := pt.srv.dials.Load(), pt.p.Stats(); d != 1 || st.Coalesced != n-1 {
			t.Fatalf("%d factory calls, Coalesced %d; want 1 and %d", d, st.Coalesced, n-1)
		}
		close(gate)
		synctest.Wait()
		if got := pendingResults(ch); got != 1 {
			t.Fatalf("%d results before the claimant's session started its trunk, want the claimant's only", got)
		}
		claim := collect(t, ch, 1)[0]
		if claim.err != nil || !claim.est.Fresh || !isOK(claim.est) {
			t.Fatalf("claimant: %v", claim.err)
		}
		time.Sleep(time.Second) // the session's start may come late: nobody dials meanwhile
		synctest.Wait()
		if d := pt.srv.dials.Load(); d != 1 || pendingResults(ch) != 0 {
			t.Fatalf("before the publication: %d factory calls, %d results", d, pendingResults(ch))
		}
		pt.attach(claim.est)
		rs := collect(t, ch, n-1)
		handles := map[uint32]bool{wire.SessionHandle: true}
		for _, r := range rs {
			if r.err != nil || !isOK(r.est) || r.est.Fresh || r.est.Conn.trunk != claim.est.Conn.trunk {
				t.Fatalf("waiter %d: %v (fresh %v)", r.sid, r.err, r.est != nil && r.est.Fresh)
			}
			handles[r.est.Conn.Handle()] = true
		}
		if len(handles) != n {
			t.Fatalf("handles %v, want %d distinct", handles, n)
		}
		time.Sleep(100 * time.Millisecond) // the views stay unattached while the passive's data waits
		synctest.Wait()
		var mvs []*mView
		for _, r := range rs {
			mvs = append(mvs, pt.attach(r.est))
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if dead, cause, detail, _ := claim.est.Conn.trunk.view1.Death(); dead || claim.est.Conn.trunk.death.Load() != nil {
			t.Fatalf("the trunk died: %v %s", cause, detail)
		}
		for i, mv := range mvs {
			if got := mv.ep.rxBytes.Load(); got != offer {
				t.Fatalf("view %d received %d bytes, want %d", rs[i].est.Conn.Handle(), got, offer)
			}
		}
		if d, st := pt.srv.dials.Load(), pt.p.Stats(); d != 1 || st.Carriers != 1 || st.Views != n || st.FastPaths != n-1 {
			t.Fatalf("%d factory calls, stats %+v", d, st)
		}
	})
}

// TestPoolCoalescedFailure (M3-D18): a transport failure of the shared dial
// fails each waiter once with that error (no waiter dials at once); a
// session-level refusal of the claimant's handle 1 releases the waiters at
// once (one of them dials, the others take its trunk), none fails.
func TestPoolCoalescedFailure(t *testing.T) {
	t.Run("transport", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pt := newPoolT(t, nil, nil)
			gate := make(chan struct{})
			pt.srv.setGate(gate)
			pt.srv.dialErr = errors.New("connection refused")
			ch := make(chan poolRes, 4)
			for i := 1; i <= 4; i++ {
				pt.goAttempt(context.Background(), wire.TypeOpen, byte(i), ch)
			}
			synctest.Wait()
			close(gate)
			rs := collect(t, ch, 4)
			synctest.Wait()
			var first error
			for _, r := range rs {
				var ee *EstablishError
				if !errors.As(r.err, &ee) || ee.Cause != CauseTransportError || ee.Stage != "dial" {
					t.Fatalf("attempt %d: %v, want the dial's transport failure", r.sid, r.err)
				}
				if first == nil {
					first = r.err
				} else if r.err != first {
					t.Fatalf("attempt %d failed with %v, not the shared dial's %v", r.sid, r.err, first)
				}
			}
			if d := pt.srv.dials.Load(); d != 1 {
				t.Fatalf("%d factory calls, want 1 (one dead path costs one dial)", d)
			}
			if n := pt.env.IDs.inUse(); n != 0 {
				t.Fatalf("%d CarrierIDs in use after the failures", n)
			}
		})
	})
	t.Run("refusal", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pt := newPoolT(t, nil, nil)
			pt.srv.status1 = func(n int) wire.AckStatus {
				if n == 1 {
					return wire.StatusRejected
				}
				return wire.StatusOK
			}
			gate := make(chan struct{})
			pt.srv.setGate(gate)
			ch := make(chan poolRes, 4)
			for i := 1; i <= 4; i++ {
				pt.goAttempt(context.Background(), wire.TypeOpen, byte(i), ch)
			}
			synctest.Wait()
			start := time.Now()
			close(gate)
			synctest.Wait()
			// The refused claimant and the second claimant (a released
			// waiter that dialled at once) both return before the remaining
			// waiters, which coalesce on the second's fresh trunk until its
			// Start; their results may reach the channel in either order.
			var first, second poolRes
			for _, r := range collect(t, ch, 2) {
				if r.err == nil && r.est.Fresh && isOK(r.est) {
					second = r
				} else {
					first = r
				}
			}
			if first.err != nil || first.est == nil || first.est.Fresh || isOK(first.est) {
				t.Fatalf("claimant: %v, want its REJECTED response", first.err)
			}
			first.est.Conn.Kill(CauseLocalClose, "refused") // the session drops a refused carrier
			if d := pt.srv.dials.Load(); d != 2 || time.Since(start) != 0 {
				t.Fatalf("%d factory calls %v after the refusal, want 2 at once", d, time.Since(start))
			}
			if second.est == nil {
				t.Fatalf("second claimant: %v", second.err)
			}
			pt.attach(second.est)
			for _, r := range collect(t, ch, 2) {
				if r.err != nil || !isOK(r.est) || r.est.Conn.trunk != second.est.Conn.trunk {
					t.Fatalf("waiter %d: %v", r.sid, r.err)
				}
			}
			if d := pt.srv.dials.Load(); d != 2 {
				t.Fatalf("%d factory calls, want 2", d)
			}
		})
	})
}

// TestPoolWaiterCancel (E17): a waiter whose session ends returns at once
// with its context's outcome and its CarrierID released; the dial goes on
// and serves the claimant.
func TestPoolWaiterCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pt := newPoolT(t, nil, nil)
		gate := make(chan struct{})
		pt.srv.setGate(gate)
		ch := make(chan poolRes, 2)
		pt.goAttempt(context.Background(), wire.TypeOpen, 1, ch)
		synctest.Wait()
		ctx, cancel := context.WithCancelCause(context.Background())
		pt.goAttempt(ctx, wire.TypeOpen, 2, ch)
		synctest.Wait()
		if n := pt.env.IDs.inUse(); n != 2 {
			t.Fatalf("%d CarrierIDs in use, want 2", n)
		}
		start := time.Now()
		cancel(ErrWithdrawn)
		w := collect(t, ch, 1)[0]
		var ee *EstablishError
		if w.sid != 2 || !errors.As(w.err, &ee) || ee.Cause != CauseLocalClose || !errors.Is(w.err, ErrWithdrawn) {
			t.Fatalf("waiter: sid %d, %v", w.sid, w.err)
		}
		if d := w.at.Sub(start); d > 100*time.Millisecond {
			t.Fatalf("the waiter returned %v after its cancellation", d)
		}
		if n := pt.env.IDs.inUse(); n != 1 {
			t.Fatalf("%d CarrierIDs in use, want the claimant's only", n)
		}
		close(gate)
		c := collect(t, ch, 1)[0]
		if c.err != nil || !c.est.Fresh || !isOK(c.est) {
			t.Fatalf("claimant: %v", c.err)
		}
		pt.attach(c.est)
		if d := pt.srv.dials.Load(); d != 1 {
			t.Fatalf("%d factory calls, want 1", d)
		}
	})
}

// TestPoolClaimantHangs_L20 (M3-D18; L20): a claimant whose factory call
// hangs keeps its waiters no longer than the attempt's DialTimeout from
// the start of their wait, and its DialTimeout expiry is a path failure:
// every waiter fails once (a hung path still backs off at the slots), and
// nobody dials meanwhile. Both a factory that honours its context and one
// that ignores it.
func TestPoolClaimantHangs_L20(t *testing.T) {
	for _, ignore := range []bool{false, true} {
		name := "honours ctx"
		if ignore {
			name = "ignores ctx"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				pt := newPoolT(t, nil, nil)
				hang := make(chan struct{})
				defer close(hang)
				if ignore {
					pt.srv.hang = hang
				} else {
					pt.srv.honorHang = true
				}
				dt := pt.env.Timing.withDefaults().DialTimeout
				ch := make(chan poolRes, 4)
				start := time.Now()
				for i := 1; i <= 4; i++ {
					pt.goAttempt(context.Background(), wire.TypeOpen, byte(i), ch)
				}
				synctest.Wait()
				time.Sleep(dt - time.Millisecond)
				synctest.Wait()
				if got := pendingResults(ch); got != 0 {
					t.Fatalf("%d results before DialTimeout", got)
				}
				rs := collect(t, ch, 4)
				for _, r := range rs {
					var ee *EstablishError
					if !errors.As(r.err, &ee) || ee.Cause != CauseTransportError {
						t.Fatalf("attempt %d: %v, want a path failure", r.sid, r.err)
					}
					if d := r.at.Sub(start); d > dt+2*time.Second {
						t.Fatalf("attempt %d returned after %v (DialTimeout %v)", r.sid, d, dt)
					}
				}
				waiters := 0
				for _, r := range rs {
					if d := r.at.Sub(start); d <= dt {
						waiters++
					}
				}
				if waiters < 3 {
					t.Fatalf("%d attempts returned within DialTimeout of their wait, want the 3 waiters", waiters)
				}
				if d := pt.srv.dials.Load(); d != 1 {
					t.Fatalf("%d factory calls during the hang, want 1", d)
				}
			})
		})
	}
}

// TestPoolClaimantEnds (E18, M3-D19, R1-8): the claimant's session
// discards the fresh trunk it got (its opening race was won elsewhere):
// the waiters keep waiting — nobody dials — until the discard, then retry
// at once, exactly one new factory call follows and nobody fails; and a
// claimant withdrawn by its own session while its factory call hangs
// releases the waiters within 1 virtual ms, again with exactly one new
// factory call and no failure.
func TestPoolClaimantEnds(t *testing.T) {
	t.Run("discarded", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pt := newPoolT(t, nil, nil)
			gate := make(chan struct{})
			pt.srv.setGate(gate)
			ch := make(chan poolRes, 4)
			for i := 1; i <= 4; i++ {
				pt.goAttempt(context.Background(), wire.TypeOpen, byte(i), ch)
			}
			synctest.Wait()
			close(gate)
			synctest.Wait()
			claim := collect(t, ch, 1)[0]
			if claim.err != nil || !claim.est.Fresh {
				t.Fatalf("claimant: %v", claim.err)
			}
			time.Sleep(time.Second) // the session decides late
			synctest.Wait()
			if d := pt.srv.dials.Load(); d != 1 || pendingResults(ch) != 0 || len(pt.p.listed(0)) != 0 {
				t.Fatalf("before the discard: %d factory calls, %d results, %d published", d, pendingResults(ch), len(pt.p.listed(0)))
			}
			start := time.Now()
			claim.est.Conn.Kill(CauseLocalClose, "dial result not attached") // the session's discard (M2)
			synctest.Wait()
			if d := pt.srv.dials.Load(); d != 2 || time.Since(start) != 0 {
				t.Fatalf("%d factory calls %v after the discard, want 2 at once", d, time.Since(start))
			}
			next := collect(t, ch, 1)[0]
			if next.err != nil || !next.est.Fresh || !isOK(next.est) {
				t.Fatalf("next claimant: %v", next.err)
			}
			pt.attach(next.est)
			for _, r := range collect(t, ch, 2) {
				if r.err != nil || !isOK(r.est) || r.est.Conn.trunk != next.est.Conn.trunk {
					t.Fatalf("waiter %d: %v", r.sid, r.err)
				}
			}
			if d := pt.srv.dials.Load(); d != 2 {
				t.Fatalf("%d factory calls, want 2", d)
			}
		})
	})
	// The claimant's own session cancels it while its factory call hangs:
	// by withdrawal (ErrWithdrawn), or by the session ending with a cause
	// of its own (R1-8: any cancellation that is not a deadline).
	for _, c := range []struct {
		name  string
		cause error
	}{
		{"withdrawn while hung", ErrWithdrawn},
		{"session ended while hung", errors.New("rendr: session ended")},
	} {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				pt := newPoolT(t, nil, nil)
				pt.srv.honorHang = true // the first factory call waits for its context
				ctx, cancel := context.WithCancelCause(context.Background())
				ch := make(chan poolRes, 4)
				pt.goAttempt(ctx, wire.TypeOpen, 1, ch)
				synctest.Wait()
				for i := 2; i <= 4; i++ {
					pt.goAttempt(context.Background(), wire.TypeOpen, byte(i), ch)
				}
				synctest.Wait()
				time.Sleep(time.Second)
				start := time.Now()
				cancel(c.cause)
				claim := collect(t, ch, 1)[0]
				if claim.sid != 1 || !errors.Is(claim.err, c.cause) {
					t.Fatalf("claimant: sid %d, %v", claim.sid, claim.err)
				}
				synctest.Wait()
				if d := pt.srv.dials.Load(); d != 2 || time.Since(start) > time.Millisecond {
					t.Fatalf("%d factory calls %v after the cancellation, want 2 within 1 ms", d, time.Since(start))
				}
				next := collect(t, ch, 1)[0]
				if next.err != nil || !next.est.Fresh {
					t.Fatalf("next claimant %d: %v", next.sid, next.err)
				}
				pt.attach(next.est)
				for _, r := range collect(t, ch, 2) {
					if r.err != nil || !isOK(r.est) {
						t.Fatalf("waiter %d: %v (a failure caused by another session's cancellation)", r.sid, r.err)
					}
				}
				if d := pt.srv.dials.Load(); d != 2 {
					t.Fatalf("%d factory calls, want 2", d)
				}
			})
		})
	}
	// The claimant's own session check rejects the PREFACE_ACK (a bound
	// instance or the gone-away set): a verdict of that session, not of the
	// path, so the waiters retry at once — one new factory call, no failure.
	t.Run("check rejects", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pt := newPoolT(t, nil, nil)
			gate := make(chan struct{})
			pt.srv.setGate(gate)
			errBound := errors.New("bound to another instance")
			ch := make(chan poolRes, 4)
			go func() {
				est, err := pt.attemptCheck(context.Background(), pt.p, 0, wire.TypeOpen, 1, [16]byte{}, func(*wire.PrefaceAck) error { return errBound })
				ch <- poolRes{sid: 1, est: est, err: err, at: time.Now()}
			}()
			synctest.Wait()
			for i := 2; i <= 4; i++ {
				pt.goAttempt(context.Background(), wire.TypeOpen, byte(i), ch)
			}
			synctest.Wait()
			start := time.Now()
			close(gate)
			rs := collect(t, ch, 2)
			if rs[0].sid != 1 {
				rs[0], rs[1] = rs[1], rs[0]
			}
			var ee *EstablishError
			if rs[0].sid != 1 || !errors.As(rs[0].err, &ee) || ee.Cause != CauseInstanceMismatch || !errors.Is(rs[0].err, errBound) {
				t.Fatalf("claimant: sid %d, %v", rs[0].sid, rs[0].err)
			}
			next := rs[1]
			if next.err != nil || !next.est.Fresh || !isOK(next.est) || next.at != start {
				t.Fatalf("next claimant %d: %v (after %v)", next.sid, next.err, next.at.Sub(start))
			}
			pt.attach(next.est)
			for _, r := range collect(t, ch, 2) {
				if r.err != nil || !isOK(r.est) || r.est.Conn.trunk != next.est.Conn.trunk {
					t.Fatalf("waiter %d: %v (a failure caused by another session's check)", r.sid, r.err)
				}
			}
			if d := pt.srv.dials.Load(); d != 2 {
				t.Fatalf("%d factory calls, want 2", d)
			}
		})
	})
}
