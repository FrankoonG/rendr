package carrier

import (
	"bytes"
	"context"
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
// DIALSTORM): an OPEN claimant whose verdict is slow (its passive
// application has not accepted the session after 1 s) releases its
// waiters after the verdict grace — two OPENs and, 10 ms later, four
// JOINs of other sessions. Each OPEN dials its own carrier beside the
// claimant (its verdict waits for the application too,
// TestPoolVerdictGrace); of the JOINs exactly one dials, in the
// claimant's place as the factory's dial in flight, and the other three
// wait for it and then open their views on the published trunks (the
// waiters' own, the oldest of the fullest first, M3-D17). (An OPEN whose grace
// runs out after a JOIN took that place waits for the JOIN's dial too:
// the scenario row's OPEN load.) Four factory calls in all, nobody fails, and once the first
// session is answered its trunk is published beside the others. Observed
// before the change: every waiter dialled its own carrier when the grace
// ran out (7 factory calls).
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
		own := waiters.get(t, 3) // the two OPENs' own carriers and one JOIN's
		joins := 0
		for _, r := range own {
			if r.err != nil || !r.est.Fresh || !isOK(r.est) {
				t.Fatalf("waiter %d (%v) after the grace: %v (fresh %v), want its own fresh carrier", r.sid, kinds[r.sid], r.err, r.est != nil && r.est.Fresh)
			}
			if d := r.at.Sub(start); d < minVerdictGrace || d > late/2 {
				t.Fatalf("waiter %d returned %v after the waiters' start, want after the verdict grace (%v) and well before the claimant", r.sid, d, minVerdictGrace)
			}
			if kinds[r.sid] == wire.TypeJoin {
				joins++
			}
		}
		synctest.Wait()
		if d, n := pt.srv.dials.Load(), pendingResults(waiters.ch); d != 4 || n != 0 || joins != 1 {
			t.Fatalf("%d factory calls (%d by JOINs) and %d further results after the grace, want 4 (one JOIN, both OPENs) and 0", d, joins, n)
		}
		ownTrunks := map[*trunk]bool{}
		for _, r := range own {
			pt.attach(r.est)
			ownTrunks[r.est.Conn.trunk] = true
		}
		for _, r := range waiters.get(t, 3) {
			if r.err != nil || !isOK(r.est) || r.est.Fresh || !ownTrunks[r.est.Conn.trunk] || kinds[r.sid] != wire.TypeJoin {
				t.Fatalf("waiter %d (%v): %v (fresh %v), want a view on a published trunk of the waiters", r.sid, kinds[r.sid], r.err, r.est != nil && r.est.Fresh)
			}
			pt.attach(r.est)
		}
		claim := claimed.get(t, 1)[0]
		if claim.err != nil || !claim.est.Fresh || !isOK(claim.est) {
			t.Fatalf("claimant: %v", claim.err)
		}
		pt.attach(claim.est)
		if d, st := pt.srv.dials.Load(), pt.p.Stats(); d != 4 || st.Carriers != 4 || st.Views != 7 || st.FastPaths != 3 {
			t.Fatalf("%d factory calls, stats %+v; want 4 calls and four trunks with 7 views", d, st)
		}
		if got := len(pt.p.listed(0)); got != 4 {
			t.Fatalf("%d published trunks, want all four", got)
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

// TestPoolTrackedBounded (invariant 4; L52): the pool's record of its
// trunks for Wait stays bounded by the trunks still running, not by every
// trunk it ever dialled: 64 sessions in a row each dial a trunk and end
// (the trunk closes at its last view), and at most 16 entries remain.
func TestPoolTrackedBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pt := newPoolT(t, nil, nil)
		for i := range 64 {
			est, err := pt.attempt(context.Background(), 0, wire.TypeOpen, byte(i+1), [16]byte{})
			if err != nil || !est.Fresh {
				t.Fatalf("session %d: %v", i+1, err)
			}
			pt.attach(est)
			est.Conn.Kill(CauseLocalClose, "session ended")
			select {
			case <-est.Conn.trunk.tdone:
			case <-time.After(time.Minute):
				t.Fatalf("session %d: the trunk did not close at its last view", i+1)
			}
		}
		pt.p.mu.Lock()
		n := len(pt.p.tracked)
		pt.p.mu.Unlock()
		if n > 16 {
			t.Fatalf("%d trunks tracked after 64 closed ones, want ≤ 16", n)
		}
		pt.p.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := pt.p.Wait(ctx); err != nil {
			t.Fatalf("Wait after every trunk closed: %v", err)
		}
	})
}
