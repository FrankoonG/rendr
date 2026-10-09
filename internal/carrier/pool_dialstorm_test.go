package carrier

import (
	"bytes"
	"context"
	"errors"
	"net"
	"runtime"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Coalescing after a trunk death (M3-D18; B0.2 item 1: at most one dial
// per factory per kill; rendr-regress gold/G6-mixed-nat, defect B) and the
// goroutine cost of a pooled trunk.

// lateVerdict is a dialer's end of a pipe whose bytes after the
// PREFACE_ACK — the response to the first frame and everything after it —
// reach the reader delay after it first asks for them: the passive's
// verdict on handle 1 delayed (host load, or an application slow to
// Accept), with the PREFACE exchange itself prompt.
type lateVerdict struct {
	net.Conn
	delay time.Duration
	read  int // bytes returned so far (Establish reads on one goroutine)
	slept bool
}

func (c *lateVerdict) Read(p []byte) (int, error) {
	if c.read < wire.PrefaceLen && len(p) > wire.PrefaceLen-c.read {
		p = p[:wire.PrefaceLen-c.read] // never hand out response bytes with the PREFACE_ACK
	}
	if c.read >= wire.PrefaceLen && !c.slept {
		c.slept = true
		time.Sleep(c.delay)
	}
	n, err := c.Conn.Read(p)
	c.read += n
	return n, err
}

// lateVerdicts makes the verdict on handle 1 of the factory calls for which
// delay returns a positive duration (n counts from 1) late by that much.
func (s *poolServer) lateVerdicts(delay func(n int) time.Duration) {
	s.mu.Lock()
	s.wrap = func(n int, nc net.Conn) net.Conn {
		if d := delay(n); d > 0 {
			return &lateVerdict{Conn: nc, delay: d}
		}
		return nc
	}
	s.mu.Unlock()
}

// dueResults are the results of attempts a test started on one channel: a
// test takes them with get, and its end — also a failed one — waits for
// the rest (at most a virtual minute), so no attempt outlives the bubble
// and the harness's close kills every carrier they got.
type dueResults struct {
	ch  chan poolRes
	due int
}

func newDueResults(t *testing.T, n int) *dueResults {
	r := &dueResults{ch: make(chan poolRes, n), due: n}
	t.Cleanup(func() {
		for ; r.due > 0; r.due-- {
			select {
			case <-r.ch:
			case <-time.After(time.Minute):
				t.Errorf("%d attempts still running at the test's end", r.due)
				return
			}
		}
	})
	return r
}

// get receives n results.
func (r *dueResults) get(t *testing.T, n int) []poolRes {
	t.Helper()
	rs := collect(t, r.ch, n)
	r.due -= n
	return rs
}

// TestPoolJoinClaimantKeepsWaiters (M3-D18 as amended by WP DIALSTORM;
// B0.2 item 1): the verdict on a JOIN never waits for an application, so a
// claimant whose JOIN's verdict is slow (here 500 ms after its prompt
// PREFACE_ACK, five times the least verdict grace) keeps its waiters —
// four JOINs and four OPENs of other sessions — until its session starts
// the fresh trunk: one factory call, no waiter fails, and all nine
// sessions share that one trunk. Observed before the change: each waiter
// dialled its own carrier once the grace ran out (9 factory calls).
func TestPoolJoinClaimantKeepsWaiters(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const late = 500 * time.Millisecond
		pt := newPoolT(t, nil, nil)
		pt.srv.lateVerdicts(func(n int) time.Duration {
			if n == 1 {
				return late
			}
			return 0
		})
		claimed := newDueResults(t, 1)
		pt.goAttempt(context.Background(), wire.TypeJoin, 1, claimed.ch)
		synctest.Wait()
		waiters := newDueResults(t, 8)
		for i := 2; i <= 9; i++ {
			kind := wire.TypeJoin
			if i%2 == 1 {
				kind = wire.TypeOpen
			}
			pt.goAttempt(context.Background(), kind, byte(i), waiters.ch)
		}
		time.Sleep(late - 10*time.Millisecond)
		synctest.Wait()
		if d, n := pt.srv.dials.Load(), pendingResults(waiters.ch); d != 1 || n != 0 {
			t.Fatalf("%d factory calls and %d waiter results while the claimant's JOIN awaits its verdict, want 1 and 0", d, n)
		}
		claim := claimed.get(t, 1)[0]
		if claim.err != nil || !claim.est.Fresh || !isOK(claim.est) {
			t.Fatalf("claimant: %v", claim.err)
		}
		pt.attach(claim.est)
		for _, r := range waiters.get(t, 8) {
			if r.err != nil || !isOK(r.est) || r.est.Fresh || r.est.Conn.trunk != claim.est.Conn.trunk {
				t.Fatalf("waiter %d: %v (fresh %v)", r.sid, r.err, r.est != nil && r.est.Fresh)
			}
			pt.attach(r.est)
		}
		if d, st := pt.srv.dials.Load(), pt.p.Stats(); d != 1 || st.Carriers != 1 || st.Views != 9 || st.FastPaths != 8 {
			t.Fatalf("%d factory calls, stats %+v; want 1 call and one trunk with 9 views", d, st)
		}
	})
}

// TestPoolVerdictGraceJoinTakesOver (M3-D18 as amended by WP10 and WP
// DIALSTORM; B0.2 item 1): an OPEN claimant whose verdict is slow (its
// passive application has not accepted the session after 1 s) keeps its
// waiters for the verdict grace — two OPENs and, 10 ms later, four JOINs
// of other sessions. The OPENs' grace runs out first: they defer to the
// JOIN waiters and dial nothing. When the JOINs' grace runs out exactly
// one JOIN dials, in the claimant's place as the factory's dial in flight
// (its verdict waits for no application), and the other five wait for it
// and open their views on its trunk. Two factory calls in all — the
// claimant and one JOIN — nobody fails, and once the first session is
// answered its trunk is published beside the JOIN's. Observed before WP
// DIALSTORM: 7 factory calls; after its first round: 4 (each OPEN waiter
// dialled beside the claimant).
func TestPoolVerdictGraceJoinTakesOver(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const late = time.Second
		pt := newPoolT(t, nil, nil)
		pt.srv.lateVerdicts(func(n int) time.Duration {
			if n == 1 {
				return late
			}
			return 0
		})
		claimed := newDueResults(t, 1)
		pt.goAttempt(context.Background(), wire.TypeOpen, 1, claimed.ch)
		synctest.Wait()
		waiters := newDueResults(t, 6)
		kinds := map[byte]wire.Type{}
		start := time.Now()
		for i := byte(2); i <= 7; i++ {
			kinds[i] = wire.TypeOpen
			if i >= 4 {
				kinds[i] = wire.TypeJoin
			}
			if i == 4 {
				time.Sleep(10 * time.Millisecond) // the OPENs' grace runs out first
			}
			pt.goAttempt(context.Background(), kinds[i], i, waiters.ch)
		}
		time.Sleep(minVerdictGrace - 5*time.Millisecond) // the OPENs' grace ran out, the JOINs' not yet
		synctest.Wait()
		if d, n := pt.srv.dials.Load(), pendingResults(waiters.ch); d != 1 || n != 0 {
			t.Fatalf("%d factory calls and %d waiter results once the OPENs' grace ran out, want 1 and 0 (the OPENs defer to the JOINs)", d, n)
		}
		own := waiters.get(t, 1)[0]
		if own.err != nil || !own.est.Fresh || !isOK(own.est) || kinds[own.sid] != wire.TypeJoin {
			t.Fatalf("waiter %d (%v) after the grace: %v (fresh %v), want one JOIN's own fresh carrier", own.sid, kinds[own.sid], own.err, own.est != nil && own.est.Fresh)
		}
		if d := own.at.Sub(start); d < 10*time.Millisecond+minVerdictGrace || d > late/2 {
			t.Fatalf("the JOIN's own carrier came %v after the waiters' start, want after its verdict grace and well before the claimant", d)
		}
		synctest.Wait()
		if d, n := pt.srv.dials.Load(), pendingResults(waiters.ch); d != 2 || n != 0 {
			t.Fatalf("%d factory calls and %d further results after the grace, want 2 (the claimant and one JOIN) and 0", d, n)
		}
		pt.attach(own.est)
		for _, r := range waiters.get(t, 5) {
			if r.err != nil || !isOK(r.est) || r.est.Fresh || r.est.Conn.trunk != own.est.Conn.trunk {
				t.Fatalf("waiter %d (%v): %v (fresh %v), want a view on the JOIN's trunk", r.sid, kinds[r.sid], r.err, r.est != nil && r.est.Fresh)
			}
			pt.attach(r.est)
		}
		claim := claimed.get(t, 1)[0]
		if claim.err != nil || !claim.est.Fresh || !isOK(claim.est) {
			t.Fatalf("claimant: %v", claim.err)
		}
		pt.attach(claim.est)
		if d, st := pt.srv.dials.Load(), pt.p.Stats(); d != 2 || st.Carriers != 2 || st.Views != 7 || st.FastPaths != 5 {
			t.Fatalf("%d factory calls, stats %+v; want 2 calls and two trunks with 7 views", d, st)
		}
	})
}

// TestPoolVerdictGraceOpensBeside (WP10, kept by WP DIALSTORM;
// TestPoolVerdictGrace, E19): with no JOIN waiting, each OPEN waiter of a
// slow OPEN claimant dials beside it once its grace runs out — the
// passive application may accept the sessions in any order — and the
// claimant stays the factory's dial in flight. A JOIN that comes once those
// trunks are published opens a view on one of them without a call.
func TestPoolVerdictGraceOpensBeside(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const late = time.Second
		pt := newPoolT(t, nil, nil)
		pt.srv.lateVerdicts(func(n int) time.Duration {
			if n == 1 {
				return late
			}
			return 0
		})
		claimed := newDueResults(t, 1)
		pt.goAttempt(context.Background(), wire.TypeOpen, 1, claimed.ch)
		synctest.Wait()
		waiters := newDueResults(t, 2)
		start := time.Now()
		pt.goAttempt(context.Background(), wire.TypeOpen, 2, waiters.ch)
		pt.goAttempt(context.Background(), wire.TypeOpen, 3, waiters.ch)
		for _, r := range waiters.get(t, 2) {
			if r.err != nil || !r.est.Fresh || !isOK(r.est) {
				t.Fatalf("OPEN waiter %d after the grace: %v (fresh %v), want its own fresh carrier", r.sid, r.err, r.est != nil && r.est.Fresh)
			}
			if d := r.at.Sub(start); d < minVerdictGrace || d > late/2 {
				t.Fatalf("OPEN waiter %d returned %v after its start, want after the verdict grace and well before the claimant", r.sid, d)
			}
			pt.attach(r.est)
		}
		if !pt.p.inFlight(0) {
			t.Fatal("the slow claimant is no longer the factory's dial in flight")
		}
		est, err := pt.attempt(context.Background(), 0, wire.TypeJoin, 9, [16]byte{})
		if err != nil || est.Fresh || !isOK(est) {
			t.Fatalf("a JOIN beside the published trunks: %v (fresh %v), want a fast path", err, est != nil && est.Fresh)
		}
		pt.attach(est)
		claim := claimed.get(t, 1)[0]
		if claim.err != nil || !claim.est.Fresh || !isOK(claim.est) {
			t.Fatalf("claimant: %v", claim.err)
		}
		pt.attach(claim.est)
		if d, st := pt.srv.dials.Load(), pt.p.Stats(); d != 3 || st.Carriers != 3 || st.Views != 4 || st.FastPaths != 1 {
			t.Fatalf("%d factory calls, stats %+v; want 3 calls and three trunks with 4 views", d, st)
		}
	})
}

// TestPoolDeferredOpenDialsWhenJoinsLeave (WP DIALSTORM): an OPEN waiter
// whose grace ran out defers to the JOIN waiters of the slow OPEN claimant;
// when the last of them leaves without dialling (its context ended), the
// OPEN dials beside the claimant at once instead of waiting for the
// claimant's verdict.
func TestPoolDeferredOpenDialsWhenJoinsLeave(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const late = time.Second
		pt := newPoolT(t, nil, nil)
		pt.srv.lateVerdicts(func(n int) time.Duration {
			if n == 1 {
				return late
			}
			return 0
		})
		claimed := newDueResults(t, 1)
		pt.goAttempt(context.Background(), wire.TypeOpen, 1, claimed.ch)
		synctest.Wait()
		opens, joins := newDueResults(t, 1), newDueResults(t, 1)
		start := time.Now()
		pt.goAttempt(context.Background(), wire.TypeOpen, 2, opens.ch)
		time.Sleep(50 * time.Millisecond)
		jctx, jcancel := context.WithCancel(context.Background())
		defer jcancel()
		pt.goAttempt(jctx, wire.TypeJoin, 3, joins.ch)
		time.Sleep(minVerdictGrace - 30*time.Millisecond) // the OPEN's grace ran out 20 ms ago, the JOIN's not yet
		synctest.Wait()
		if d, n := pt.srv.dials.Load(), pendingResults(opens.ch)+pendingResults(joins.ch); d != 1 || n != 0 {
			t.Fatalf("%d factory calls and %d results while the OPEN defers to the JOIN, want 1 and 0", d, n)
		}
		left := time.Now()
		jcancel()
		if r := joins.get(t, 1)[0]; r.err == nil {
			t.Fatal("the cancelled JOIN got a carrier")
		}
		r := opens.get(t, 1)[0]
		if r.err != nil || !r.est.Fresh || !isOK(r.est) {
			t.Fatalf("OPEN waiter: %v (fresh %v), want its own fresh carrier", r.err, r.est != nil && r.est.Fresh)
		}
		if d := r.at.Sub(left); d > 50*time.Millisecond {
			t.Fatalf("the OPEN returned %v after the JOIN left (%v after its start), want at once", d, r.at.Sub(start))
		}
		pt.attach(r.est)
		claim := claimed.get(t, 1)[0]
		if claim.err != nil || !claim.est.Fresh {
			t.Fatalf("claimant: %v", claim.err)
		}
		pt.attach(claim.est)
		if d := pt.srv.dials.Load(); d != 2 {
			t.Fatalf("%d factory calls, want 2", d)
		}
	})
}

// TestPoolGraceKeptAcrossKick (WP DIALSTORM): a waiter's verdict grace
// counts from its first wait after the claimant's proof; a kick that wakes
// it earlier (here the only JOIN waiter leaving, 50 ms into the grace)
// does not start the grace again: the OPEN waiter dials beside the slow
// OPEN claimant when its first grace runs out.
func TestPoolGraceKeptAcrossKick(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const late = time.Second
		pt := newPoolT(t, nil, nil)
		pt.srv.lateVerdicts(func(n int) time.Duration {
			if n == 1 {
				return late
			}
			return 0
		})
		claimed := newDueResults(t, 1)
		pt.goAttempt(context.Background(), wire.TypeOpen, 1, claimed.ch)
		synctest.Wait()
		opens, joins := newDueResults(t, 1), newDueResults(t, 1)
		jctx, jcancel := context.WithCancel(context.Background())
		defer jcancel()
		start := time.Now()
		pt.goAttempt(context.Background(), wire.TypeOpen, 2, opens.ch)
		pt.goAttempt(jctx, wire.TypeJoin, 3, joins.ch)
		time.Sleep(minVerdictGrace / 2)
		jcancel()
		if r := joins.get(t, 1)[0]; r.err == nil {
			t.Fatal("the cancelled JOIN got a carrier")
		}
		r := opens.get(t, 1)[0]
		if r.err != nil || !r.est.Fresh || !isOK(r.est) {
			t.Fatalf("OPEN waiter: %v (fresh %v), want its own fresh carrier", r.err, r.est != nil && r.est.Fresh)
		}
		if d := r.at.Sub(start); d < minVerdictGrace || d >= minVerdictGrace+minVerdictGrace/4 {
			t.Fatalf("the OPEN dialled %v after its start, want when its first grace (%v) ran out", d, minVerdictGrace)
		}
		pt.attach(r.est)
		claim := claimed.get(t, 1)[0]
		if claim.err != nil || !claim.est.Fresh {
			t.Fatalf("claimant: %v", claim.err)
		}
		pt.attach(claim.est)
	})
}

// TestPoolJoinClaimantStall (WP DIALSTORM): the waiters of a JOIN
// claimant wait for its verdict as for its dial, but not past joinStall
// (the death deadline's floor, DeadMin: 3 s here) when its conn stalls
// after the PREFACE_ACK (here the response to its JOIN comes 8 s late: a
// path that broke after the PREFACE, or a passive stuck under load). Then
// exactly one waiter — two JOINs and two OPENs wait — dials in the
// claimant's place, and the other three open their views on that trunk
// instead of waiting for their DialTimeout (10 s). Two factory calls.
func TestPoolJoinClaimantStall(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const late = 8 * time.Second
		pt := newPoolT(t, nil, nil)
		stall := pt.env.Timing.DeadMin
		pt.srv.lateVerdicts(func(n int) time.Duration {
			if n == 1 {
				return late
			}
			return 0
		})
		claimed := newDueResults(t, 1)
		pt.goAttempt(context.Background(), wire.TypeJoin, 1, claimed.ch)
		synctest.Wait()
		waiters := newDueResults(t, 4)
		start := time.Now()
		for i := byte(2); i <= 5; i++ {
			kind := wire.TypeJoin
			if i%2 == 1 {
				kind = wire.TypeOpen
			}
			pt.goAttempt(context.Background(), kind, i, waiters.ch)
		}
		time.Sleep(stall - 10*time.Millisecond)
		synctest.Wait()
		if d, n := pt.srv.dials.Load(), pendingResults(waiters.ch); d != 1 || n != 0 {
			t.Fatalf("%d factory calls and %d results before the stall bound, want 1 and 0", d, n)
		}
		own := waiters.get(t, 1)[0]
		if own.err != nil || !own.est.Fresh || !isOK(own.est) {
			t.Fatalf("waiter %d after the stall bound: %v (fresh %v), want its own fresh carrier", own.sid, own.err, own.est != nil && own.est.Fresh)
		}
		if d := own.at.Sub(start); d < stall || d > stall+time.Second {
			t.Fatalf("the waiter's own carrier came %v after its start, want right after the stall bound (%v)", d, stall)
		}
		synctest.Wait()
		if d, n := pt.srv.dials.Load(), pendingResults(waiters.ch); d != 2 || n != 0 {
			t.Fatalf("%d factory calls and %d further results, want 2 and 0", d, n)
		}
		pt.attach(own.est)
		for _, r := range waiters.get(t, 3) {
			if r.err != nil || !isOK(r.est) || r.est.Fresh || r.est.Conn.trunk != own.est.Conn.trunk {
				t.Fatalf("waiter %d: %v (fresh %v), want a view on the replacing trunk", r.sid, r.err, r.est != nil && r.est.Fresh)
			}
			pt.attach(r.est)
		}
		// The stalled claimant's carrier, silent toward the passive past its
		// death deadline, was ended there: the claimant fails on its own.
		if claim := claimed.get(t, 1)[0]; claim.err == nil {
			t.Fatal("the stalled claimant got a carrier")
		}
		if d, st := pt.srv.dials.Load(), pt.p.Stats(); d != 2 || st.Carriers != 1 || st.Views != 4 {
			t.Fatalf("%d factory calls, stats %+v; want 2 calls and one trunk with 4 views", d, st)
		}
	})
}

// poolGoroutines returns the goroutines whose stack runs a method of Pool.
func poolGoroutines() int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	k := 0
	for _, g := range bytes.Split(buf, []byte("\n\n")) {
		if bytes.Contains(g, []byte("carrier.(*Pool).")) {
			k++
		}
	}
	return k
}

// TestPoolTrunkGoroutines (F44's goroutine bound, two per carrier; L52): a
// published pooled trunk costs exactly the goroutines of the same trunk
// outside any pool — its reader and writer on each end — and no pool
// goroutine runs once it is published. Pool.Wait still joins it:
// TestPoolClose. Observed before the change: the pool's watcher of every
// pooled trunk lived until the trunk's Done (one goroutine more per
// trunk).
func TestPoolTrunkGoroutines(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pt := newPoolT(t, nil, nil)
		est1, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 1, [16]byte{})
		if err != nil || !est1.Fresh {
			t.Fatalf("first trunk: %v", err)
		}
		pt.attach(est1)
		synctest.Wait()
		g0 := runtime.NumGoroutine()

		// The same factory's trunk outside the pool (no owner: no
		// publication, no pool goroutine).
		est2, err := Establish(context.Background(), pt.env, pt.p.fs[1], pt.env.IDs.Next(), wire.TypeOpen, poolPayload(wire.TypeOpen, 2), nil)
		if err != nil || !est2.Conn.Mux() {
			t.Fatalf("trunk outside the pool: %v", err)
		}
		pt.mu.Lock()
		pt.ests = append(pt.ests, est2)
		pt.mu.Unlock()
		pt.attach(est2)
		synctest.Wait()
		g1 := runtime.NumGoroutine()

		// A pooled trunk of the same factory.
		est3, err := pt.attempt(context.Background(), 1, wire.TypeOpen, 3, [16]byte{})
		if err != nil || !est3.Fresh || est3.Conn.trunk == est2.Conn.trunk {
			t.Fatalf("pooled trunk: %v", err)
		}
		pt.attach(est3)
		synctest.Wait()
		g2 := runtime.NumGoroutine()
		if len(pt.p.listed(1)) != 1 {
			t.Fatal("the pooled trunk was not published")
		}
		if bare, pooled := g1-g0, g2-g1; pooled != bare || bare != 4 {
			t.Fatalf("a trunk outside the pool costs %d goroutines, a pooled one %d; want 4 each (reader and writer per end)", bare, pooled)
		}
		if k := poolGoroutines(); k != 0 {
			t.Fatalf("%d pool goroutines run beside two published trunks, want none", k)
		}
	})
}

// stuckClose is a dialer conn whose Close waits for release (an embedder's
// slow Close).
type stuckClose struct {
	net.Conn
	release chan struct{}
}

func (c *stuckClose) Close() error {
	<-c.release
	return c.Conn.Close()
}

// TestPoolWaitJoinsWatchers (L52, F46: Runtime.Close joins every
// goroutine): Wait returns nil only once every trunk the pool dialled is
// done and the pool's watcher of every fresh trunk has ended. (a) A fresh
// trunk discarded unstarted after Close (its session's discard): Wait
// blocks while its watcher runs, and returns once the trunk is done and the
// watcher ended. (b) The same with the trunk's Close stuck in the
// embedder's conn (its Done open): Wait blocks until the Close returns.
// (c) A published trunk whose watcher has not ended yet when the trunk is
// done (its last view's hook counted the Done first): Wait blocks until
// the watcher ended. Each time no pool goroutine is left.
func TestPoolWaitJoinsWatchers(t *testing.T) {
	short := func(p *Pool) error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		return p.Wait(ctx)
	}
	t.Run("discarded", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pt := newPoolT(t, nil, nil)
			hold := make(chan struct{})
			pt.p.watchEnd = func(*Conn) { <-hold }
			est, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 1, [16]byte{})
			if err != nil || !est.Fresh {
				t.Fatalf("claimant: %v", err)
			}
			pt.p.Close()
			est.Conn.Kill(CauseLocalClose, "dial result not attached") // the session's discard
			select {
			case <-est.Conn.trunk.tdone:
			case <-time.After(time.Minute):
				t.Fatal("the discarded trunk is not done")
			}
			if err := short(pt.p); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Wait while the watcher runs: %v, want it blocked", err)
			}
			close(hold)
			if err := short(pt.p); err != nil {
				t.Fatalf("Wait once the watcher ended: %v", err)
			}
			if k := poolGoroutines(); k != 0 {
				t.Fatalf("%d pool goroutines after Wait, want none", k)
			}
		})
	})
	t.Run("discarded-close-stuck", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pt := newPoolT(t, nil, nil)
			release := make(chan struct{})
			pt.srv.mu.Lock()
			pt.srv.wrap = func(_ int, nc net.Conn) net.Conn { return &stuckClose{Conn: nc, release: release} }
			pt.srv.mu.Unlock()
			est, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 1, [16]byte{})
			if err != nil || !est.Fresh {
				t.Fatalf("claimant: %v", err)
			}
			pt.p.Close()
			est.Conn.Kill(CauseLocalClose, "dial result not attached") // the session's discard
			ctx, cancel := context.WithTimeout(context.Background(), pt.env.Timing.AbandonWait/2)
			defer cancel()
			if err := pt.p.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Wait while the discarded trunk's Close is stuck: %v, want it blocked", err)
			}
			close(release)
			if err := short(pt.p); err != nil {
				t.Fatalf("Wait once the Close returned: %v", err)
			}
			select {
			case <-est.Conn.trunk.tdone:
			default:
				t.Fatal("Wait returned before the discarded trunk was done")
			}
			if k := poolGoroutines(); k != 0 {
				t.Fatalf("%d pool goroutines after Wait, want none", k)
			}
		})
	})
	t.Run("published", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pt := newPoolT(t, nil, nil)
			hold := make(chan struct{})
			pt.p.watchEnd = func(*Conn) { <-hold }
			est, err := pt.attempt(context.Background(), 0, wire.TypeOpen, 1, [16]byte{})
			if err != nil || !est.Fresh {
				t.Fatalf("claimant: %v", err)
			}
			pt.attach(est) // published: the watcher reached watchEnd
			pt.p.Close()
			est.Conn.Kill(CauseLocalClose, "session ended") // the last view: the trunk retires
			select {
			case <-est.Conn.trunk.tdone:
			case <-time.After(time.Minute):
				t.Fatal("the trunk did not close at its last view")
			}
			synctest.Wait()
			pt.p.mu.Lock()
			live, watch := pt.p.live, pt.p.watch
			pt.p.mu.Unlock()
			if live != 0 || watch != 1 {
				t.Fatalf("stimulus: %d live trunks and %d watchers, want 0 and 1 (the trunk done before its watcher ended)", live, watch)
			}
			if err := short(pt.p); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Wait while the watcher runs: %v, want it blocked", err)
			}
			close(hold)
			if err := short(pt.p); err != nil {
				t.Fatalf("Wait once the watcher ended: %v", err)
			}
			if k := poolGoroutines(); k != 0 {
				t.Fatalf("%d pool goroutines after Wait, want none", k)
			}
		})
	})
}

// TestPoolKeepsNoDoneTrunk (invariant 4; L52): the pool keeps no record of
// a trunk past its Done, also after a spike. 16 sessions each hold a trunk
// of their own (one view per trunk) and all end at once; once the trunks
// are done the pool counts no live trunk, lists none, runs no goroutine,
// and Wait returns after Close. (Before WP DIALSTORM's review the pool kept
// a list for Wait that was swept only when it doubled: up to twice the peak
// of done trunks stayed referenced through a quiet period.)
func TestPoolKeepsNoDoneTrunk(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const n = 16
		pt := newPoolT(t, func(e *Env) { e.Timing.MuxMaxViews = 1 }, nil)
		var ests []*Established
		for i := range n {
			est, err := pt.attempt(context.Background(), 0, wire.TypeOpen, byte(i+1), [16]byte{})
			if err != nil || !est.Fresh {
				t.Fatalf("session %d: %v", i+1, err)
			}
			pt.attach(est)
			ests = append(ests, est)
		}
		if d, st := pt.srv.dials.Load(), pt.p.Stats(); d != n || st.Carriers != n {
			t.Fatalf("stimulus: %d factory calls, stats %+v; want %d trunks", d, st, n)
		}
		for _, est := range ests {
			est.Conn.Kill(CauseLocalClose, "session ended")
		}
		for i, est := range ests {
			select {
			case <-est.Conn.trunk.tdone:
			case <-time.After(time.Minute):
				t.Fatalf("session %d: the trunk did not close at its last view", i+1)
			}
		}
		synctest.Wait()
		pt.p.mu.Lock()
		live, watch, listed, extra, dialing := pt.p.live, pt.p.watch, len(pt.p.trunks[0]), len(pt.p.extra), pt.p.dialing[0]
		pt.p.mu.Unlock()
		if live != 0 || watch != 0 || listed != 0 || extra != 0 || dialing != nil {
			t.Fatalf("after %d done trunks: live %d, watchers %d, listed %d, extra %d, dial in flight %v; want none", n, live, watch, listed, extra, dialing != nil)
		}
		if k := poolGoroutines(); k != 0 {
			t.Fatalf("%d pool goroutines in the quiet period, want none", k)
		}
		pt.p.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := pt.p.Wait(ctx); err != nil {
			t.Fatalf("Wait after every trunk closed: %v", err)
		}
	})
}
