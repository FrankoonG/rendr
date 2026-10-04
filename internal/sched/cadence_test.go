package sched

import (
	"math"
	"math/rand/v2"
	"testing"
	"time"
)

// TestBackoffFormula_L20: min(0.5 s·2ⁿ, cap) × U[0.8, 1.2) — the cap is
// applied before the jitter, so the longest interval is 1.2 × cap.
func TestBackoffFormula_L20(t *testing.T) {
	const cap = 4 * time.Second
	for _, tc := range []struct {
		n    int
		max  time.Duration
		u    float64
		want time.Duration
	}{
		{0, cap, 0, 400 * ms},
		{0, cap, 0.5, 500 * ms},
		{1, cap, 0.5, time.Second},
		{2, cap, 0.5, 2 * time.Second},
		{3, cap, 0.5, 4 * time.Second},
		{4, cap, 0.5, 4 * time.Second}, // capped
		{3, cap, 0, 3200 * ms},
		{9, cap, 0.75, 4400 * ms},
		{2, 1500 * ms, 0.5, 1500 * ms},                    // grace-limited cap: min(RejoinBackoffMax, grace/2)
		{-3, cap, 0.5, 500 * ms},                          // n < 0 counts as 0
		{1 << 30, cap, 0.5, cap},                          // no overflow
		{1 << 30, 0, 0.5, BackoffBase << maxBackoffShift}, // no cap: bounded exponent
		{1, cap, -1, 800 * ms},                            // u clamped to 0
		{1, cap, math.NaN(), 800 * ms},                    // NaN counts as 0
		{1, cap, 7, 1200 * ms},                            // u clamped to 1
		{5, cap, math.Nextafter(1, 0), time.Duration(float64(cap) * (0.8 + 0.4*math.Nextafter(1, 0)))},
	} {
		if got := Backoff(tc.n, tc.max, tc.u); got != tc.want {
			t.Errorf("Backoff(%d, %v, %v) = %v, want %v", tc.n, tc.max, tc.u, got, tc.want)
		}
	}
	// Over the whole u range the result stays within [0.8, 1.2)·min(0.5·2ⁿ, cap).
	r := rand.New(rand.NewPCG(20, 22))
	for i := 0; i < 10000; i++ {
		n, u := r.IntN(12), r.Float64()
		b := min(BackoffBase<<n, cap)
		if got := Backoff(n, cap, u); got < b*8/10 || got >= b*12/10 {
			t.Fatalf("Backoff(%d, cap, %v) = %v outside [0.8, 1.2)·%v", n, u, got, b)
		}
	}
}

type attemptStep struct {
	dur time.Duration // from start to Finish
	out Outcome
}

// TestRedialCadenceStartTimes_L20_L22 (plan §3.6): after a death the first
// attempt is immediate; after the n-th consecutive failure the next starts
// at max(previous start + min(0.5 s·2ⁿ, cap) × U[0.8, 1.2), previous end),
// measured between attempt starts, so an attempt hung until DialTimeout is
// followed at once by the next one; Refused resets n and counts as failure
// 0; there is never more than one attempt at a time per slot (L22).
func TestRedialCadenceStartTimes_L20_L22(t *testing.T) {
	const dialTimeout = 10 * time.Second
	fast := attemptStep{20 * ms, OutcomeFailed}
	hung := attemptStep{dialTimeout, OutcomeFailed}
	script := []attemptStep{
		fast, fast, fast, fast, fast, // 0.5, 1, 2, 4, 4 s (cap)
		hung,       // backoff 4 s < 10 s: next starts when it ends
		fast, fast, // keeps the capped interval
		{30 * ms, OutcomeRefused}, // PREFACE completed: n reset, counts as failure 0
		fast, fast,                // 1 s, 2 s again
		hung, hung, // back-to-back hung attempts
		fast,
		{40 * ms, OutcomeAttached},
	}
	for _, tc := range []struct {
		name string
		cap  time.Duration
	}{
		{"session slot, RejoinBackoffMax 4s", 4 * time.Second},
		{"session slot, grace 3s caps at 1.5s", 1500 * ms},
		{"probe slot, Probe.BackoffMax 8s", 8 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jitter := rand.New(rand.NewPCG(20, 22)) // the deterministic Env.Rand of a test Runtime
			// The slot's carrier attached a while ago and dies now: the
			// actor kicks the slot and the first attempt is immediate.
			var c Cadence
			death := simEpoch.Add(time.Minute)
			if id := c.Start(simEpoch); !c.Finish(simEpoch.Add(40*ms), id, OutcomeAttached, tc.cap, 0.5) {
				t.Fatal("initial attach rejected")
			}
			c.Kick()
			if ok, _ := c.Ready(death); !ok {
				t.Fatal("kicked slot not ready at the death")
			}
			now := death
			starts := make([]time.Time, 0, len(script))
			us := make([]float64, 0, len(script))
			for i, s := range script {
				ok, at := c.Ready(now)
				if !ok {
					if !at.After(now) {
						t.Fatalf("attempt %d: not ready at %v and no future readiness (%v)", i, now, at)
					}
					if ok2, _ := c.Ready(at.Add(-1)); ok2 {
						t.Fatalf("attempt %d: ready before the announced time %v", i, at)
					}
					now = at
					if ok, _ = c.Ready(now); !ok {
						t.Fatalf("attempt %d: not ready at the announced time %v", i, at)
					}
				}
				id := c.Start(now)
				starts = append(starts, now)
				// L22: joins on one slot are serialized; a running attempt
				// reports no readiness time (its Finish decides).
				if ok, at := c.Ready(now.Add(s.dur / 2)); ok || !at.IsZero() {
					t.Fatalf("attempt %d: second attempt allowed while one runs", i)
				}
				u := jitter.Float64()
				us = append(us, u)
				end := now.Add(s.dur)
				if !c.Finish(end, id, s.out, tc.cap, u) {
					t.Fatalf("attempt %d: Finish rejected its own id", i)
				}
				now = end
			}

			// The plan §3.6 formula, computed independently.
			n := 0
			want := death
			for i, s := range script {
				if !starts[i].Equal(want) {
					t.Fatalf("attempt %d (%v) started at +%v, want +%v", i, s.out, starts[i].Sub(death), want.Sub(death))
				}
				end := want.Add(s.dur)
				if s.out == OutcomeAttached {
					n, want = 0, end
					continue
				}
				if s.out == OutcomeRefused {
					n = 0
				}
				b := time.Duration(500) * time.Millisecond * time.Duration(1<<n)
				if b > tc.cap {
					b = tc.cap
				}
				next := want.Add(time.Duration(float64(b) * (0.8 + 0.4*us[i])))
				if next.Before(end) {
					next = end // never before the failed attempt ended
				}
				want = next
				n++
			}
			for i := 1; i < len(script); i++ {
				gap := starts[i].Sub(starts[i-1])
				if script[i-1] == hung && gap != dialTimeout {
					t.Fatalf("attempt %d followed a hung attempt after %v, want exactly DialTimeout", i, gap)
				}
				if gap > 12*tc.cap/10 && script[i-1] != hung {
					t.Fatalf("attempt %d: gap %v exceeds 1.2 × cap", i, gap)
				}
			}
			if c.Fails != 0 || c.Running {
				t.Fatalf("after attaching: Fails %d Running %v", c.Fails, c.Running)
			}
		})
	}
}

// TestCadenceKickAndStaleResults_L20: a Kick makes the next attempt
// immediate whether it arrives during a backoff or while an attempt runs;
// results of superseded attempts change nothing.
func TestCadenceKickAndStaleResults_L20(t *testing.T) {
	var c Cadence
	t0 := simEpoch
	if ok, _ := c.Ready(t0); !ok {
		t.Fatal("a new slot is not ready")
	}
	id1 := c.Start(t0)
	if !c.Finish(t0.Add(10*ms), id1, OutcomeFailed, 4*time.Second, 0.5) {
		t.Fatal("Finish rejected")
	}
	if ok, at := c.Ready(t0.Add(100 * ms)); ok || !at.Equal(t0.Add(500*ms)) {
		t.Fatalf("Ready during backoff = (%v, %v), want (false, +500ms)", ok, at)
	}
	// A death during the backoff: immediate.
	c.Kick()
	if ok, _ := c.Ready(t0.Add(100 * ms)); !ok {
		t.Fatal("Kick during backoff not immediate")
	}
	id2 := c.Start(t0.Add(100 * ms))
	// A Kick while the attempt runs survives its failure.
	c.Kick()
	if ok, _ := c.Ready(t0.Add(200 * ms)); ok {
		t.Fatal("Kick allowed a second concurrent attempt")
	}
	// Stale results: the superseded attempt and a wrong id change nothing.
	before := c
	if c.Finish(t0.Add(150*ms), id1, OutcomeAttached, 4*time.Second, 0.5) || c.Finish(t0.Add(150*ms), id2+1, OutcomeAttached, 4*time.Second, 0.5) {
		t.Fatal("stale result accepted")
	}
	if c != before {
		t.Fatalf("stale result changed the cadence: %+v → %+v", before, c)
	}
	if !c.Finish(t0.Add(300*ms), id2, OutcomeFailed, 4*time.Second, 0.5) {
		t.Fatal("current result rejected")
	}
	if ok, _ := c.Ready(t0.Add(300 * ms)); !ok {
		t.Fatal("a Kick received during the attempt was lost")
	}
	if c.Finish(t0.Add(300*ms), id2, OutcomeFailed, 4*time.Second, 0.5) {
		t.Fatal("a second Finish of the same attempt was accepted")
	}
	// Attached resets the failure count and needs no wait.
	id3 := c.Start(t0.Add(300 * ms))
	if !c.Finish(t0.Add(400*ms), id3, OutcomeAttached, 4*time.Second, 0.5) || c.Fails != 0 {
		t.Fatalf("after Attached: %+v", c)
	}
	if ok, _ := c.Ready(t0.Add(400 * ms)); !ok {
		t.Fatal("not ready after Attached")
	}
	// Attempt ids are unique per slot.
	if id1 == id2 || id2 == id3 || id3 != c.Attempt {
		t.Fatalf("ids %d %d %d (Attempt %d)", id1, id2, id3, c.Attempt)
	}
}
