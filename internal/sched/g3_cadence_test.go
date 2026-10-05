package sched

import (
	"math/rand/v2"
	"testing"
	"time"
)

// Refusal cadence (design §0.14 B6; plan §3.6 as amended): the first refusal
// since a slot last attached resets the failure count n — the PREFACE
// exchange completed — and counts as failure 0; every later refusal counts
// as a failure, failed attempts in between included, so a peer that keeps
// refusing is redialled at min(0.5 s·2ⁿ, cap) × U[0.8, 1.2) up to the cap
// instead of every ≈ 0.5 s for the session's whole life. Attached resets
// both; a Kick makes the next attempt immediate but keeps both.

// g3Step is one scripted attempt of a slot: how long it ran, how it ended,
// and whether the slot was kicked right after it ended (a death of the
// slot's carrier or the start of a no-path episode).
type g3Step struct {
	dur  time.Duration
	out  Outcome
	kick bool
}

// g3Refused, g3Failed and g3Attached are short attempts (one round trip).
var (
	g3Refused  = g3Step{dur: 20 * ms, out: OutcomeRefused}
	g3Failed   = g3Step{dur: 20 * ms, out: OutcomeFailed}
	g3Attached = g3Step{dur: 20 * ms, out: OutcomeAttached}
)

// g3Backoff is the plan §3.6 interval after failure number n (n from 0),
// computed independently of Backoff: min(0.5 s·2ⁿ, cap) × (0.8 + 0.4·u).
func g3Backoff(n int, cap time.Duration, u float64) time.Duration {
	d := 500 * time.Millisecond
	for i := 0; i < n && d < cap; i++ {
		d *= 2
	}
	d = min(d, cap)
	return time.Duration(float64(d) * (0.8 + 0.4*u))
}

// g3Drive runs script on c from start, starting every attempt at the
// earliest time Ready allows (and checking that Ready refuses it one
// nanosecond earlier and allows no second attempt while one runs). It
// returns the start time and the jitter of every attempt.
func g3Drive(t *testing.T, c *Cadence, start time.Time, cap time.Duration, script []g3Step, seed uint64) (starts []time.Time, us []float64) {
	t.Helper()
	jitter := rand.New(rand.NewPCG(seed, 6))
	now := start
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
		if ok, at := c.Ready(now.Add(s.dur / 2)); ok || !at.IsZero() {
			t.Fatalf("attempt %d: a second attempt allowed while one runs (L22)", i)
		}
		starts = append(starts, now)
		u := jitter.Float64()
		us = append(us, u)
		end := now.Add(s.dur)
		if !c.Finish(end, id, s.out, cap, u) {
			t.Fatalf("attempt %d: Finish rejected its own id", i)
		}
		if s.kick {
			c.Kick()
		}
		now = end
	}
	return starts, us
}

// g3Immediate in a list of expected exponents: the next attempt starts as
// soon as this one ended (it attached, or the slot was kicked).
const g3Immediate = -1

// g3Check requires every gap between consecutive starts to be the plan §3.6
// interval for the expected failure number exps[i] — max(start +
// g3Backoff(exps[i]), end of the attempt) — or the end of the attempt for
// g3Immediate.
func g3Check(t *testing.T, cap time.Duration, script []g3Step, exps []int, starts []time.Time, us []float64) {
	t.Helper()
	if len(exps) != len(script)-1 {
		t.Fatalf("test bug: %d expected gaps for %d attempts", len(exps), len(script))
	}
	for i, n := range exps {
		end := starts[i].Add(script[i].dur)
		want := end
		if n != g3Immediate {
			if next := starts[i].Add(g3Backoff(n, cap, us[i])); next.After(end) {
				want = next // never before the attempt ended (plan §3.6)
			}
		}
		if !starts[i+1].Equal(want) {
			t.Fatalf("attempt %d (after %v, outcome %d): started %v after the previous one, want %v (failure number %d)",
				i+1, script[i].dur, script[i].out, starts[i+1].Sub(starts[i]), want.Sub(starts[i]), n)
		}
	}
}

// TestCadenceRefusalsBackOff_L20 drives scripted slots through refusals,
// failures, attaches and kicks and checks every start against the amended
// plan §3.6 cadence, for the default session cap (RejoinBackoffMax 4 s) and
// a grace-limited one (NoPathGrace 3 s: cap 1.5 s).
func TestCadenceRefusalsBackOff_L20(t *testing.T) {
	const dialTimeout = 10 * time.Second
	R, F, A := g3Refused, g3Failed, g3Attached
	kicked := func(s g3Step) g3Step { s.kick = true; return s }
	hungR := g3Step{dur: dialTimeout, out: OutcomeRefused} // e.g. no OPEN_ACK within DialTimeout (G6)
	for _, tc := range []struct {
		name   string
		script []g3Step
		exps   []int // failure number of the backoff after each attempt but the last
	}{
		{
			// JOIN_ACK CAPACITY, instance mismatch: the interval doubles from
			// 0.5 s and stays at the cap.
			name:   "consecutive refusals grow to the cap",
			script: []g3Step{R, R, R, R, R, R, R, R, R, R},
			exps:   []int{0, 1, 2, 3, 4, 5, 6, 7, 8},
		},
		{
			// A completed PREFACE exchange after failed dials: the path works
			// again, so the first refusal starts the backoff over.
			name:   "a first refusal after failures resets n",
			script: []g3Step{F, F, F, F, R, R, R},
			exps:   []int{0, 1, 2, 3, 0, 1},
		},
		{
			// Unchanged by B6: the attempt that timed out waiting for OPEN_ACK
			// is the slot's first refusal, so the retry starts as soon as it
			// ended (design §6.2 timing check); a second one backs off.
			name:   "a hung first refusal is retried at once (G6)",
			script: []g3Step{hungR, R, R},
			exps:   []int{0, 1},
		},
		{
			// Unchanged by B6: OPEN_ACK CAPACITY CodeCarriers refuses one
			// carrier of the pending session; the slot retries after Backoff(0).
			name:   "a first refusal retries after Backoff(0) (P20)",
			script: []g3Step{R, A},
			exps:   []int{0},
		},
		{
			// After an attach the next refusal is a first one again, also
			// when failures come before it.
			name:   "attached resets the refusal memory",
			script: []g3Step{R, R, R, A, R, R, F, A, F, F, R, R},
			exps:   []int{0, 1, 2, g3Immediate, 0, 1, 2, g3Immediate, 0, 1, 0},
		},
		{
			// A failure after a refusal continues the count, and so does a
			// refusal after it: the peer still refuses (a factory that reaches
			// a refusing peer only every other time).
			name:   "failed after refused keeps growing",
			script: []g3Step{R, F, R, F, R, F, F, R, R},
			exps:   []int{0, 1, 2, 3, 4, 5, 6, 7},
		},
		{
			// A death or an episode start makes the next attempt immediate; a
			// refusal of that attempt still counts as a failure.
			name:   "a kick keeps the refusal memory",
			script: []g3Step{R, kicked(R), R, R, kicked(F), R},
			exps:   []int{0, g3Immediate, 2, 3, g3Immediate},
		},
	} {
		for _, cap := range []time.Duration{4 * time.Second, 1500 * ms} {
			t.Run(tc.name+"/cap "+cap.String(), func(t *testing.T) {
				var c Cadence
				starts, us := g3Drive(t, &c, simEpoch, cap, tc.script, 20)
				g3Check(t, cap, tc.script, tc.exps, starts, us)
			})
		}
	}
}

// TestCadenceRefusalNextAt_L20: after k consecutive refusals NextAt is
// LastStart + min(0.5 s·2^(k−1), cap) × (0.8 + 0.4·u) — the first refusal
// gives Backoff(0) —, so the interval grows to the cap and never beyond
// 1.2 × cap, and Fails counts every refusal; an Attached then clears NextAt
// and Fails, and the next refusal is a first one again.
func TestCadenceRefusalNextAt_L20(t *testing.T) {
	const cap = 4 * time.Second
	var c Cadence
	now := simEpoch
	for k := 1; k <= 12; k++ {
		ok, at := c.Ready(now)
		if !ok {
			now = at
		}
		id := c.Start(now)
		u := float64(k%5) / 5
		if !c.Finish(now.Add(5*ms), id, OutcomeRefused, cap, u) {
			t.Fatalf("refusal %d: Finish rejected", k)
		}
		want := now.Add(g3Backoff(k-1, cap, u))
		if !c.NextAt.Equal(want) || c.Fails != k {
			t.Fatalf("after %d refusals: NextAt +%v, Fails %d; want +%v, %d",
				k, c.NextAt.Sub(now), c.Fails, want.Sub(now), k)
		}
		if gap := c.NextAt.Sub(now); k >= 4 && (gap < cap*8/10 || gap >= cap*12/10) {
			t.Fatalf("after %d refusals the interval %v is not at the cap", k, gap)
		}
	}
	id := c.Start(c.NextAt)
	if !c.Finish(c.NextAt.Add(5*ms), id, OutcomeAttached, cap, 0.5) || c.Fails != 0 || !c.NextAt.IsZero() {
		t.Fatalf("after Attached: %+v", c)
	}
	id = c.Start(simEpoch.Add(time.Hour))
	if !c.Finish(simEpoch.Add(time.Hour+5*ms), id, OutcomeRefused, cap, 0.5) || c.Fails != 1 ||
		!c.NextAt.Equal(simEpoch.Add(time.Hour+g3Backoff(0, cap, 0.5))) {
		t.Fatalf("a first refusal after Attached: %+v, want Fails 1 and NextAt +%v", c, g3Backoff(0, cap, 0.5))
	}
}

// TestCadenceWithoutRefusalsUnchanged_L20: probe slots never report
// OutcomeRefused (a refused probe dial is a failure, carrier probe.go), so
// for them B6 must change nothing: random scripts of failures, hung
// attempts, attaches and kicks follow the original rule exactly — n counts
// the failures since the last attach and a kick only makes the next
// attempt immediate.
func TestCadenceWithoutRefusalsUnchanged_L20(t *testing.T) {
	const dialTimeout = 10 * time.Second
	r := rand.New(rand.NewPCG(3, 6))
	for run := range 200 {
		script := make([]g3Step, 2+r.IntN(30))
		for i := range script {
			s := g3Failed
			switch x := r.IntN(10); {
			case x == 0:
				s = g3Attached
			case x == 1:
				s.dur = dialTimeout // hung until DialTimeout
			case x == 2:
				s.dur = time.Duration(r.Int64N(int64(5 * time.Second)))
			}
			s.kick = r.IntN(8) == 0
			script[i] = s
		}
		exps := make([]int, len(script)-1)
		n := 0
		for i := range exps {
			if script[i].out == OutcomeAttached {
				n = 0
				exps[i] = g3Immediate
				continue
			}
			exps[i] = n
			n++
			if script[i].kick {
				exps[i] = g3Immediate
			}
		}
		cap := []time.Duration{time.Second, 4 * time.Second, 8 * time.Second}[run%3]
		var c Cadence
		starts, us := g3Drive(t, &c, simEpoch, cap, script, uint64(run))
		g3Check(t, cap, script, exps, starts, us)
	}
}
