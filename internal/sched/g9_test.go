package sched

import (
	"math"
	"math/rand/v2"
	"testing"
	"time"
)

// rttStats accumulates generated probe RTTs (stimulus proof).
type rttStats struct {
	n         int
	sum, sum2 float64
}

func (s *rttStats) add(d time.Duration) {
	x := float64(d)
	s.n++
	s.sum += x
	s.sum2 += x * x
}

func (s *rttStats) meanSD() (time.Duration, time.Duration) {
	m := s.sum / float64(s.n)
	return time.Duration(m), time.Duration(math.Sqrt(s.sum2/float64(s.n) - m*m))
}

// g9Phase2Paths returns the two G9 phase 2 probe carriers of one seed: both
// paths N(30 ms, 10 ms), each with its own random PING phase.
func g9Phase2Paths(seed uint64, st *rttStats) []simPath {
	ph := rand.New(rand.NewPCG(seed, 0))
	paths := make([]simPath, 2)
	for i := range paths {
		gen := normalRTT(seed, uint64(i+1), 30*ms, 10*ms)
		paths[i] = simPath{
			phase: time.Duration(ph.Int64N(int64(defInterval))),
			rtt: func(k int, send time.Duration) time.Duration {
				d := gen(k, send)
				if st != nil {
					st.add(d)
				}
				return d
			},
		}
	}
	return paths
}

// TestSelectorG9Statistics_L29 (plan §3.9, G9 phase 2): two paths whose
// probe RTTs are both N(30 ms, 10 ms), probed every Probe.Interval, 100
// fixed seeds × 10 virtual minutes from a cold start: at most 2 quality
// switches per seed, at least a Cooldown apart. The same samples fed
// through a one-sample window (no aggregation) flap, which proves the noise
// is a real stimulus for the comparator.
func TestSelectorG9Statistics_L29(t *testing.T) {
	start := time.Now()
	const seeds, dur = 100, 10 * time.Minute
	var st rttStats
	total, worst, evals := 0, 0, 0
	var shifts uint64
	for seed := uint64(1); seed <= seeds; seed++ {
		res := runSim(simConfig{
			sel: defaultSelectorParams(), agg: DefaultAggParams(), interval: defInterval, dur: dur,
			paths: g9Phase2Paths(seed, &st),
		})
		// Load: every probe carrier produced its ~300 samples, all of them
		// accepted, and the selector compared fresh evidence on both paths
		// at nearly every evaluation.
		for i, n := range res.samples {
			if n < 299 {
				t.Fatalf("seed %d path %d: %d samples in 10 minutes", seed, i, n)
			}
			shifts += res.shifts[i]
		}
		if res.allFresh < res.steps-3 { // only the first sample's step precedes the other path's first sample
			t.Fatalf("seed %d: both paths fresh at only %d of %d steps", seed, res.allFresh, res.steps)
		}
		n := len(res.switches)
		if n > 2 {
			t.Errorf("seed %d: %d quality switches (> 2): %+v", seed, n, res.switches)
		}
		for j := 1; j < n; j++ {
			if gap := res.switches[j].at - res.switches[j-1].at; gap < defCooldown {
				t.Errorf("seed %d: quality switches %v apart (< Cooldown)", seed, gap)
			}
		}
		total += n
		evals += res.evals
		if n > worst {
			worst = n
		}
	}
	// Stimulus: the generated probe RTTs really are N(30 ms, 10 ms).
	mean, sd := st.meanSD()
	if st.n < 2*seeds*299 || (mean-30*ms).Abs() > ms/2 || (sd-10*ms).Abs() > ms/2 {
		t.Fatalf("generated %d RTTs with mean %v sd %v, want N(30ms, 10ms)", st.n, mean, sd)
	}
	// Control: one-sample evidence on the same streams switches far more
	// than twice per run (msess-like behaviour, plan §4).
	ctlMin := math.MaxInt
	for seed := uint64(1); seed <= 10; seed++ {
		res := runSim(simConfig{
			sel: defaultSelectorParams(), agg: AggParams{Window: 1}, interval: defInterval, dur: dur,
			paths: g9Phase2Paths(seed, nil),
		})
		ctlMin = min(ctlMin, len(res.switches))
	}
	if ctlMin <= 2 {
		t.Fatalf("control without aggregation switched only %d times in a run: the noise is no stimulus", ctlMin)
	}
	t.Logf("%d seeds: %d quality switches (mean %.2f, max %d), %d level shifts, %d evaluations; RTT mean %v sd %v; control min %d switches/run",
		seeds, total, float64(total)/seeds, worst, shifts, evals, mean.Round(time.Microsecond), sd.Round(time.Microsecond), ctlMin)
	if el := time.Since(start); el >= 10*time.Second {
		t.Fatalf("statistics took %v (limit 10 s)", el)
	}
}

// g9StepCase drives one G9 phase 1 + phase 3 run: A (active) at 10 ms
// steps to 90 ms at t0; B stays at 30 ms; 5 s after the switch to B, A
// recovers to 10 ms. noise adds N(0, noise) to every sample (seeded).
type g9StepCase struct {
	name             string
	phaseA, phaseB   time.Duration
	t0               time.Duration
	noise            time.Duration
	seed             uint64
	wantExactTimings bool
}

func runG9Step(t *testing.T, tc g9StepCase) {
	t.Helper()
	jit := rand.New(rand.NewPCG(tc.seed, 77))
	noisy := func(d time.Duration) time.Duration {
		if tc.noise > 0 {
			d += time.Duration(jit.NormFloat64() * float64(tc.noise))
		}
		return d
	}
	recoverAt := time.Duration(-1) // set at the first switch decision
	type post struct{ send, rtt time.Duration }
	var degraded []post // A's samples sent after t0 and before recovery
	a := func(_ int, send time.Duration) time.Duration {
		switch {
		case send < tc.t0:
			return noisy(10 * ms)
		case recoverAt >= 0 && send >= recoverAt:
			return noisy(10 * ms)
		}
		d := noisy(90 * ms)
		degraded = append(degraded, post{send, d})
		return d
	}
	b := func(int, time.Duration) time.Duration { return noisy(30 * ms) }
	end := tc.t0 + 5*time.Minute
	res := runSim(simConfig{
		sel: defaultSelectorParams(), agg: DefaultAggParams(), interval: defInterval, dur: end,
		paths: []simPath{{phase: tc.phaseA, rtt: a}, {phase: tc.phaseB, rtt: b}},
		observe: func(now time.Time, _ int, _ []Summary, v Verdict) {
			if v.Switch && recoverAt < 0 {
				recoverAt = now.Sub(simEpoch) + 5*time.Second
			}
		},
	})
	if len(res.switches) != 2 {
		t.Fatalf("%s: switches %+v, want exactly the decision and one switch back", tc.name, res.switches)
	}
	sw1, sw2 := res.switches[0], res.switches[1]
	// Phase 1: the decision follows the step within Dwell + 2·Interval plus
	// the PONG flight time of the second degraded sample (plan §3.9).
	if len(degraded) < 2 {
		t.Fatalf("%s: only %d degraded samples (stimulus missing)", tc.name, len(degraded))
	}
	second := degraded[1]
	bound := defDwell + 2*defInterval + second.rtt
	if sw1.from != 0 || sw1.to != 1 || sw1.at < tc.t0 || sw1.at-tc.t0 > bound {
		t.Fatalf("%s: decision %+v at t0+%v, want A→B within %v of the step at %v", tc.name, sw1, sw1.at-tc.t0, bound, tc.t0)
	}
	// The level shift is declared at the second degraded sample; the dwell
	// runs from there, so the decision is exactly Dwell after it arrived.
	if tc.wantExactTimings && sw1.at != second.send+second.rtt+defDwell {
		t.Fatalf("%s: decision at %v, want %v (second degraded sample + Dwell)", tc.name, sw1.at, second.send+second.rtt+defDwell)
	}
	// Phase 3: A recovers 5 s after the switch, its dwell completes inside
	// the cooldown, and the single switch back happens exactly when the
	// cooldown ends.
	if sw2.from != 1 || sw2.to != 0 || sw2.at != sw1.at+defCooldown {
		t.Fatalf("%s: switch back %+v, want B→A at %v (one Cooldown after %v)", tc.name, sw2, sw1.at+defCooldown, sw1.at)
	}
	if res.finalAct != 0 || res.shifts[0] < 2 {
		t.Fatalf("%s: final active %d, A level shifts %d", tc.name, res.finalAct, res.shifts[0])
	}
}

// TestSelectorG9StepResponse_L29 (plan §3.9, G9 phases 1 and 3): one path
// steps from 10 to 90 ms while the other stays at 30 ms; the switch
// decision comes within Dwell + 2·Probe.Interval + 90 ms for every PING
// phase (including the worst one, a PING just before the step), and after
// the path recovers to 10 ms exactly one switch back follows, after
// Cooldown.
func TestSelectorG9StepResponse_L29(t *testing.T) {
	const phaseA = 300 * ms
	stepAt := 60*defInterval + phaseA // a PING of A is sent exactly here
	for _, d := range []time.Duration{0, 1, 500 * ms, time.Second, 1500 * ms, defInterval - 1} {
		// δ = time from the step to A's first PING after it.
		runG9Step(t, g9StepCase{
			name: "delta " + d.String(), phaseA: phaseA, phaseB: 1100 * ms,
			t0: stepAt - d, wantExactTimings: true,
		})
	}
	for seed := uint64(1); seed <= 20; seed++ {
		ph := rand.New(rand.NewPCG(seed, 3))
		runG9Step(t, g9StepCase{
			name:   "jitter seed",
			phaseA: time.Duration(ph.Int64N(int64(defInterval))),
			phaseB: time.Duration(ph.Int64N(int64(defInterval))),
			t0:     2*time.Minute + time.Duration(ph.Int64N(int64(defInterval))),
			noise:  300 * time.Microsecond,
			seed:   seed,
		})
	}
}

// TestSelectorG2Stimulus_L29 (plan §3.9, G2's quality stimulus): both paths
// at 20 ms; six times, 5 minutes apart, the active path gets +15 ms for
// 30 s (35 vs 20 ms satisfies Band and Floor). Every event switches exactly
// once during its stimulus and nothing switches back after the revert.
func TestSelectorG2Stimulus_L29(t *testing.T) {
	const events = 6
	event := func(e int) time.Duration { return 2*time.Minute + time.Duration(e)*5*time.Minute }
	run := func(name string, phaseA, phaseB, noise time.Duration, seed uint64) {
		jit := rand.New(rand.NewPCG(seed, 11))
		rttOf := func(path int) func(int, time.Duration) time.Duration {
			return func(_ int, send time.Duration) time.Duration {
				d := 20 * ms
				for e := 0; e < events; e++ {
					// Event e targets the path active at that time: A, B, A, ...
					if e%2 == path && send >= event(e) && send < event(e)+30*time.Second {
						d += 15 * ms
					}
				}
				if noise > 0 {
					d += time.Duration(jit.NormFloat64() * float64(noise))
				}
				return d
			}
		}
		res := runSim(simConfig{
			sel: defaultSelectorParams(), agg: DefaultAggParams(), interval: defInterval,
			dur:   event(events-1) + 5*time.Minute,
			paths: []simPath{{phase: phaseA, rtt: rttOf(0)}, {phase: phaseB, rtt: rttOf(1)}},
		})
		if len(res.switches) != events {
			t.Fatalf("%s: %d switches for %d quality events: %+v", name, len(res.switches), events, res.switches)
		}
		for e, sw := range res.switches {
			from := e % 2
			if sw.from != from || sw.to != 1-from || sw.at < event(e) || sw.at-event(e) > defDwell+2*defInterval+35*ms+5*noise {
				t.Fatalf("%s: event %d at %v: switch %+v, want %d→%d within Dwell + 2·Interval + 35 ms", name, e, event(e), sw, from, 1-from)
			}
		}
		// Stimulus: each event raised and restored its path, and both edges
		// were seen as level shifts.
		if res.shifts[0] < events || res.shifts[1] < events {
			t.Fatalf("%s: level shifts %v, want ≥ %d per path", name, res.shifts, events)
		}
	}
	for _, ph := range [][2]time.Duration{{0, time.Second}, {300 * ms, 310 * ms}, {1999 * ms, 7 * ms}} {
		run("phases "+ph[0].String()+"/"+ph[1].String(), ph[0], ph[1], 0, 0)
	}
	for seed := uint64(1); seed <= 20; seed++ {
		ph := rand.New(rand.NewPCG(seed, 5))
		run("jitter", time.Duration(ph.Int64N(int64(defInterval))), time.Duration(ph.Int64N(int64(defInterval))), 500*time.Microsecond, seed)
	}
}
