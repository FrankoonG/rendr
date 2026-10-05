package sched

import (
	"fmt"
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
// both.
//
// Recovery window (design D27): a Kick of a slot that has dialled before —
// its carrier died, or a no-path episode started — opens a window of
// 4 × cap at the next attempt's start; refusals of attempts started inside
// it reset n as before B6, so the slot keeps redialling every Backoff(0)
// while the passive may still hold the dead carrier at its carrier limit.
// A Kick of a slot that never dialled (the bond's new member slots when the
// session opens) opens none.

// g3Span is the documented length of a recovery window in units of the
// slot's cap (4 × min(RejoinBackoffMax, NoPathGrace/2) for a session slot),
// stated here independently of the implementation's constant.
const g3Span = 4

// g3Step is one scripted attempt of a slot: how long it ran, how it ended,
// and whether the slot was kicked while it ran (kickDuring) or right after
// it ended (kick): a death of the slot's carrier or the start of a no-path
// episode.
type g3Step struct {
	dur        time.Duration
	out        Outcome
	kick       bool
	kickDuring bool
}

// g3Refused, g3Failed and g3Attached are short attempts (one round trip).
var (
	g3Refused  = g3Step{dur: 20 * ms, out: OutcomeRefused}
	g3Failed   = g3Step{dur: 20 * ms, out: OutcomeFailed}
	g3Attached = g3Step{dur: 20 * ms, out: OutcomeAttached}
)

// g3Kicked and g3KickedDuring return s with a kick after it ended or while
// it ran.
func g3Kicked(s g3Step) g3Step       { s.kick = true; return s }
func g3KickedDuring(s g3Step) g3Step { s.kickDuring = true; return s }

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
		if s.kickDuring {
			c.Kick()
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
// a grace-limited one (NoPathGrace 3 s: cap 1.5 s). A script with a kick
// ends inside the recovery window it opens (4 × cap ≥ 6 s);
// TestCadenceRecoveryWindowEnds_L20 covers the window's end.
func TestCadenceRefusalsBackOff_L20(t *testing.T) {
	const dialTimeout = 10 * time.Second
	R, F, A := g3Refused, g3Failed, g3Attached
	hungR := g3Step{dur: dialTimeout, out: OutcomeRefused} // e.g. no OPEN_ACK within DialTimeout (G6)
	for _, tc := range []struct {
		name      string
		kickFirst bool // the slot is kicked before its first attempt
		script    []g3Step
		exps      []int // failure number of the backoff after each attempt but the last
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
			// The bond's member slots are kicked when the session opens,
			// before they ever dialled: that first dial is no recovery, so a
			// passive at its carrier limit is redialled at the growing cadence.
			name:      "the kick of a slot that never dialled opens no window",
			kickFirst: true,
			script:    []g3Step{R, R, R, R, R, R},
			exps:      []int{0, 1, 2, 3, 4},
		},
		{
			// The carrier died (a death kick after the attach): the passive may
			// still hold it, so every refusal of the window resets n, and a
			// failure inside it counts as usual.
			name:   "a death opens a recovery window",
			script: []g3Step{g3Kicked(A), R, R, R, F, F, R, R},
			exps:   []int{g3Immediate, 0, 0, 0, 1, 2, 0},
		},
		{
			// A refused member slot kicked at the start of a no-path episode
			// (it dialled before): its refusals reset n from the kick on.
			name:   "an episode kick of a refused slot opens a recovery window",
			script: []g3Step{R, R, R, g3Kicked(R), R, R, R},
			exps:   []int{0, 1, 2, g3Immediate, 0, 0},
		},
		{
			// The episode starts while the death's first redial runs (the bond
			// case): the window opened at that redial's start covers its
			// refusal, and the next attempt is immediate.
			name:   "a kick while the window's first attempt runs",
			script: []g3Step{g3Kicked(A), g3KickedDuring(R), R, R},
			exps:   []int{g3Immediate, g3Immediate, 0},
		},
		{
			// A kick while an attempt runs outside any window: that attempt's
			// refusal still counts; the window opens at the next start.
			name:   "a kick during an attempt opens the window at the next start",
			script: []g3Step{R, R, g3KickedDuring(R), R, R, R},
			exps:   []int{0, 1, g3Immediate, 0, 0},
		},
		{
			// Attached closes the window: the next refusal is a first one, the
			// one after it backs off.
			name:   "attached closes the recovery window",
			script: []g3Step{g3Kicked(A), R, R, A, R, R, R},
			exps:   []int{g3Immediate, 0, 0, g3Immediate, 0, 1},
		},
	} {
		for _, cap := range []time.Duration{4 * time.Second, 1500 * ms} {
			t.Run(tc.name+"/cap "+cap.String(), func(t *testing.T) {
				var c Cadence
				if tc.kickFirst {
					c.Kick()
				}
				starts, us := g3Drive(t, &c, simEpoch, cap, tc.script, 20)
				for _, s := range tc.script {
					if end := starts[len(starts)-1]; (s.kick || s.kickDuring) && !end.Before(simEpoch.Add(g3Span*cap)) {
						t.Fatalf("test bug: the script runs past its recovery window (%v)", end.Sub(simEpoch))
					}
				}
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

// TestCadenceRecoveryWindowEnds_L20: a slot whose carrier died is refused
// for a long time (another member took the passive's last place). Every
// refusal of an attempt started before the window's end — 4 × cap after
// the first redial — keeps Backoff(0); from the first attempt started at
// or after it the count grows again (failure 1, 2, … up to the cap), so a
// persistent refusal after a death costs one window of fast redials, not a
// redial every 0.5 s for the session's whole life (B6).
func TestCadenceRecoveryWindowEnds_L20(t *testing.T) {
	for _, cap := range []time.Duration{4 * time.Second, 1500 * ms, 8 * time.Second} {
		t.Run("cap "+cap.String(), func(t *testing.T) {
			script := []g3Step{g3Kicked(g3Attached)}
			for range 80 {
				script = append(script, g3Refused)
			}
			var c Cadence
			starts, us := g3Drive(t, &c, simEpoch, cap, script, 7)
			window := starts[1].Add(g3Span * cap) // opened by the first redial
			inside, n := 0, 1
			for i := 1; i+1 < len(script); i++ {
				exp := 0
				if !starts[i].Before(window) {
					exp = n // the window's last refusal left n at 1
					n++
				} else {
					inside++
				}
				want := starts[i].Add(g3Backoff(exp, cap, us[i]))
				if !starts[i+1].Equal(want) {
					t.Fatalf("attempt %d (started +%v, window ends +%v): next after %v, want %v (failure number %d)",
						i, starts[i].Sub(starts[1]), window.Sub(starts[1]), starts[i+1].Sub(starts[i]), want.Sub(starts[i]), exp)
				}
			}
			if lo := int(g3Span * cap / (600 * ms)); inside < lo {
				t.Fatalf("only %d refusals inside the window, want at least %d", inside, lo)
			}
			if last := starts[len(starts)-1].Sub(starts[len(starts)-2]); last < cap*8/10 {
				t.Fatalf("the cadence did not settle at the cap: last interval %v", last)
			}
		})
	}
}

// TestCadenceRecoveryWindowBoundary_L20: the window covers the attempts
// started before recoverFrom + 4 × cap, exactly; a non-positive cap opens
// none.
func TestCadenceRecoveryWindowBoundary_L20(t *testing.T) {
	// kicked returns a slot whose carrier died after an attach, with the
	// window opened at t0 by the first redial and two refusals inside it.
	kicked := func(t *testing.T, max time.Duration) (*Cadence, time.Time) {
		t.Helper()
		var c Cadence
		id := c.Start(simEpoch)
		if !c.Finish(simEpoch.Add(5*ms), id, OutcomeAttached, max, 0.5) {
			t.Fatal("attach rejected")
		}
		c.Kick()
		t0 := simEpoch.Add(time.Minute)
		for _, at := range []time.Time{t0, t0.Add(time.Second)} {
			id = c.Start(at)
			if !c.Finish(at.Add(5*ms), id, OutcomeRefused, max, 0.5) {
				t.Fatal("refusal rejected")
			}
		}
		return &c, t0
	}
	const cap = 4 * time.Second
	for _, tc := range []struct {
		name  string
		at    time.Duration // start of the probed attempt after the window opened
		fails int           // Fails after its refusal: 1 inside the window, 2 outside
	}{
		{"last instant inside", g3Span*cap - 1, 1},
		{"window end", g3Span * cap, 2},
		{"long after", time.Hour, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, t0 := kicked(t, cap)
			if c.Fails != 1 {
				t.Fatalf("two refusals inside the window left Fails %d, want 1", c.Fails)
			}
			at := t0.Add(tc.at)
			id := c.Start(at)
			if !c.Finish(at.Add(5*ms), id, OutcomeRefused, cap, 0.5) {
				t.Fatal("refusal rejected")
			}
			if want := at.Add(g3Backoff(tc.fails-1, cap, 0.5)); c.Fails != tc.fails || !c.NextAt.Equal(want) {
				t.Fatalf("refusal started +%v after the window opened: Fails %d NextAt +%v; want Fails %d NextAt +%v",
					tc.at, c.Fails, c.NextAt.Sub(at), tc.fails, want.Sub(at))
			}
		})
	}
	t.Run("no cap: no window", func(t *testing.T) {
		c, _ := kicked(t, 0)
		if c.Fails != 2 {
			t.Fatalf("with no cap the second refusal after the death left Fails %d, want 2 (it counts)", c.Fails)
		}
	})
}

// TestCadenceWithoutRefusalsUnchanged_L20: probe slots never report
// OutcomeRefused (a refused probe dial is a failure, carrier probe.go), so
// for them B6 and the recovery window must change nothing: random scripts
// of failures, hung attempts, attaches and kicks (after or during an
// attempt) follow the original rule exactly — n counts the failures since
// the last attach and a kick only makes the next attempt immediate.
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
			s.kickDuring = r.IntN(8) == 0
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
			if script[i].kick || script[i].kickDuring {
				exps[i] = g3Immediate
			}
		}
		cap := []time.Duration{time.Second, 4 * time.Second, 8 * time.Second}[run%3]
		var c Cadence
		starts, us := g3Drive(t, &c, simEpoch, cap, script, uint64(run))
		g3Check(t, cap, script, exps, starts, us)
	}
}

// g3Model is an independent statement of the slot rules (plan §3.6 as
// amended by design §0.14 B6 and the D27 recovery window), used to check
// Cadence over random scripts.
type g3Model struct {
	n           int
	refused     bool      // refused since the last attach
	dialled     bool      // an attempt was started
	kickPending bool      // a kick of a dialled slot awaits the next start
	immediate   bool      // the next attempt may start at once
	window      time.Time // start of the recovery window (zero: none)
	next        time.Time // earliest next start when !immediate
}

func (m *g3Model) kick() {
	m.immediate = true
	if m.dialled {
		m.kickPending = true
	}
}

// run applies one attempt started at start and returns when the next one
// may start.
func (m *g3Model) run(start time.Time, s g3Step, cap time.Duration, u float64) time.Time {
	m.dialled, m.immediate = true, false
	if m.kickPending {
		m.kickPending, m.window = false, start
	}
	if s.kickDuring {
		m.kick()
	}
	end := start.Add(s.dur)
	backoff := func() {
		m.next = start.Add(g3Backoff(m.n, cap, u))
		if m.next.Before(end) {
			m.next = end
		}
		m.n++
	}
	switch s.out {
	case OutcomeAttached:
		m.n, m.refused, m.kickPending, m.window, m.next = 0, false, false, time.Time{}, end
	case OutcomeRefused:
		inWindow := !m.window.IsZero() && start.Before(m.window.Add(g3Span*cap))
		if !m.refused || inWindow {
			m.n = 0
		}
		m.refused = true
		backoff()
	default:
		backoff()
	}
	if s.kick {
		m.kick()
	}
	if m.immediate {
		return end
	}
	return m.next
}

// TestCadenceMatchesModel_L20: random scripts of refusals, failures,
// attaches, hung attempts and kicks (after and during attempts; also before
// the first one) start every attempt exactly when the model allows.
func TestCadenceMatchesModel_L20(t *testing.T) {
	const dialTimeout = 10 * time.Second
	r := rand.New(rand.NewPCG(20, 27))
	for run := range 400 {
		cap := []time.Duration{time.Second, 1500 * ms, 4 * time.Second, 8 * time.Second}[run%4]
		script := make([]g3Step, 2+r.IntN(60))
		for i := range script {
			s := g3Refused
			switch x := r.IntN(20); {
			case x < 4:
				s = g3Failed
			case x == 4:
				s = g3Attached
			case x == 5:
				s.dur = dialTimeout
			case x == 6:
				s.dur = time.Duration(r.Int64N(int64(6 * time.Second)))
			}
			s.kick = r.IntN(10) == 0
			s.kickDuring = r.IntN(16) == 0
			script[i] = s
		}
		t.Run(fmt.Sprintf("run %d", run), func(t *testing.T) {
			var c Cadence
			var m g3Model
			if run%5 == 0 {
				c.Kick()
				m.kick()
			}
			starts, us := g3Drive(t, &c, simEpoch, cap, script, uint64(run))
			want := starts[0]
			for i, s := range script {
				if !starts[i].Equal(want) {
					t.Fatalf("attempt %d (%+v) started at +%v, model +%v (cap %v)", i, s, starts[i].Sub(simEpoch), want.Sub(simEpoch), cap)
				}
				want = m.run(starts[i], s, cap, us[i])
			}
		})
	}
}
