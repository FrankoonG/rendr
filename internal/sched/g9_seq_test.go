package sched

import (
	"fmt"
	"math/rand/v2"
	"testing"
	"time"
)

// TestSelectorStepResponseManyPaths_L29 (plan §3.9 phase-1 bound beyond
// G9's two paths): A (active, 10 ms) steps to 90 ms while two or three
// other paths are N(30 ms, 10 ms), so the identity of the best challenger
// keeps changing. Every challenger has its own dwell, so for every seed the
// decision comes exactly Dwell after A's level shift (its second degraded
// sample), within Dwell + 2·Interval + that sample's RTT of the step, and
// goes to one of the 30 ms paths. Stimulus: the best challenger changed
// during the dwell in a sizeable share of the runs; a dwell keyed to the
// best challenger's identity restarted in each of them.
func TestSelectorStepResponseManyPaths_L29(t *testing.T) {
	const seeds = 300
	for _, npaths := range []int{3, 4} {
		flipped := 0
		for seed := uint64(1); seed <= seeds; seed++ {
			ph := rand.New(rand.NewPCG(seed, 91))
			t0 := 5*time.Minute + time.Duration(ph.Int64N(int64(defInterval)))
			var degraded []time.Duration // arrivals of A's samples sent at or after t0
			paths := make([]simPath, npaths)
			paths[0] = simPath{phase: time.Duration(ph.Int64N(int64(defInterval))), rtt: func(_ int, send time.Duration) time.Duration {
				if send < t0 {
					return 10 * ms
				}
				degraded = append(degraded, send+90*ms)
				return 90 * ms
			}}
			for i := 1; i < npaths; i++ {
				paths[i] = simPath{phase: time.Duration(ph.Int64N(int64(defInterval))), rtt: normalRTT(seed, uint64(10+i), 30*ms, 10*ms)}
			}
			decision := time.Duration(-1)
			lastBest, flips := -1, 0
			res := runSim(simConfig{
				sel: defaultSelectorParams(), agg: DefaultAggParams(), interval: defInterval, dur: t0 + time.Minute,
				paths: paths,
				observe: func(now time.Time, active int, sums []Summary, v Verdict) {
					at := now.Sub(simEpoch)
					if decision >= 0 || active != 0 || len(degraded) < 2 || at < degraded[1] {
						return
					}
					// From A's level shift to the decision: the best challenger.
					best := -1
					var bestRTT time.Duration
					for i := 1; i < len(sums); i++ {
						if ev := Classify(sums[i], now, defFresh); ev.State == EvFresh && (best < 0 || ev.RTT < bestRTT) {
							best, bestRTT = i, ev.RTT
						}
					}
					if lastBest >= 0 && best != lastBest {
						flips++
					}
					lastBest = best
					if v.Switch {
						decision = at
					}
				},
			})
			name := fmt.Sprintf("%d paths, seed %d", npaths, seed)
			for i, n := range res.samples {
				if n < 180 {
					t.Fatalf("%s: path %d produced %d samples", name, i, n)
				}
			}
			if len(degraded) < 2 || res.shifts[0] != 1 || len(res.switches) == 0 {
				t.Fatalf("%s: degraded samples %d, A shifts %d, switches %+v", name, len(degraded), res.shifts[0], res.switches)
			}
			sw := res.switches[0]
			bound := defDwell + 2*defInterval + 90*ms
			if sw.from != 0 || sw.to == 0 || sw.at != decision || sw.at != degraded[1]+defDwell || sw.at-t0 > bound {
				t.Fatalf("%s: first switch %+v (decision %v) at t0+%v; want A→other exactly Dwell after the level shift at %v, within %v of t0",
					name, sw, decision, sw.at-t0, degraded[1], bound)
			}
			if flips > 0 {
				flipped++
			}
		}
		if flipped < seeds/20 {
			t.Fatalf("%d paths: the best challenger changed during the dwell in only %d of %d runs (no stimulus)", npaths, flipped, seeds)
		}
		t.Logf("%d paths: %d seeds, the best challenger changed during the dwell in %d", npaths, seeds, flipped)
	}
}

// TestSelectorG9Sequence_L29 (plan §10.3 G9, phases in order, virtual
// time): phase 1 — A (active, 10 ms) +80 ms at t0 while B stays at 30 ms:
// A→B within Dwell + 2·Interval + 90 ms; phase 2 — from a per-seed delay
// (0–30 s) after that switch, both paths N(30 ms, 10 ms) for 10 minutes: at
// most 2 quality switches; phase 3 — A back to 10 ms for 2 minutes: at most
// one switch, back to A, which ends active. Every two quality switches are
// at least a Cooldown apart. Unlike the cold start of
// TestSelectorG9Statistics_L29, phase 2 begins with windows full of nearly
// constant samples (σ at its 2 ms floor), where the noise soon declares
// level shifts that restart a window from two same-side outliers; this is
// the order the gold criterion runs.
func TestSelectorG9Sequence_L29(t *testing.T) {
	const seeds = 100
	var hist [4]int
	var shifts uint64
	var st rttStats
	for seed := uint64(1); seed <= seeds; seed++ {
		ph := rand.New(rand.NewPCG(seed, 9))
		t0 := 5*time.Minute + time.Duration(ph.Int64N(int64(defInterval)))
		d2 := time.Duration(ph.Int64N(int64(30 * time.Second)))
		jr := rand.New(rand.NewPCG(seed, 10))
		jit := func(d time.Duration) time.Duration {
			return d + time.Duration(jr.NormFloat64()*float64(300*time.Microsecond))
		}
		na, nb := normalRTT(seed, 21, 30*ms, 10*ms), normalRTT(seed, 22, 30*ms, 10*ms)
		p2, p3 := time.Duration(-1), time.Duration(-1) // set at the phase-1 decision
		second, secondRTT := time.Duration(-1), time.Duration(0)
		deg := 0 // A's degraded samples so far; the second one shifts its window
		a := func(k int, send time.Duration) time.Duration {
			switch {
			case p3 >= 0 && send >= p3:
				return jit(10 * ms)
			case p2 >= 0 && send >= p2:
				d := na(k, send)
				st.add(d)
				return d
			case send >= t0:
				d := jit(90 * ms)
				if deg++; deg == 2 {
					second, secondRTT = send+d, d
				}
				return d
			}
			return jit(10 * ms)
		}
		b := func(k int, send time.Duration) time.Duration {
			if p2 >= 0 && send >= p2 {
				d := nb(k, send)
				if p3 < 0 || send < p3 {
					st.add(d)
				}
				return d
			}
			return jit(30 * ms)
		}
		res := runSim(simConfig{
			sel: defaultSelectorParams(), agg: DefaultAggParams(), interval: defInterval,
			dur:   t0 + 15*time.Minute,
			paths: []simPath{{phase: time.Duration(ph.Int64N(int64(defInterval))), rtt: a}, {phase: time.Duration(ph.Int64N(int64(defInterval))), rtt: b}},
			observe: func(now time.Time, _ int, _ []Summary, v Verdict) {
				if v.Switch && p2 < 0 {
					p2 = now.Sub(simEpoch) + d2
					p3 = p2 + 10*time.Minute
				}
			},
		})
		name := fmt.Sprintf("seed %d", seed)
		if p3 < 0 || p3+2*time.Minute > t0+15*time.Minute || second < 0 {
			t.Fatalf("%s: phases not reached (p2 %v, p3 %v, second degraded sample %v)", name, p2, p3, second)
		}
		// Phase 1: B qualifies from A's level shift at the second degraded
		// sample, so the decision is exactly Dwell after it, within the
		// plan §3.9 bound Dwell + 2·Interval + that sample's flight time.
		sw := res.switches
		if sw[0].from != 0 || sw[0].to != 1 || sw[0].at != second+defDwell || sw[0].at-t0 > defDwell+2*defInterval+secondRTT {
			t.Fatalf("%s: phase 1 switch %+v at t0+%v, want A→B at %v, within %v of t0",
				name, sw[0], sw[0].at-t0, second+defDwell, defDwell+2*defInterval+secondRTT)
		}
		n2, n3 := 0, 0
		for j, s := range sw {
			if j > 0 && s.at-sw[j-1].at < defCooldown {
				t.Fatalf("%s: quality switches %v apart (< Cooldown): %+v", name, s.at-sw[j-1].at, sw)
			}
			switch {
			case s.at >= p3:
				n3++
				if s.to != 0 {
					t.Fatalf("%s: phase 3 switch %+v, want only back to A", name, s)
				}
			case s.at >= p2:
				n2++
			}
		}
		if n2 > 2 {
			t.Errorf("%s: %d quality switches in phase 2 (> 2): %+v", name, n2, sw)
		}
		if n3 > 1 || res.finalAct != 0 {
			t.Fatalf("%s: phase 3 switches %d, final active %d: %+v", name, n3, res.finalAct, sw)
		}
		hist[min(n2, 3)]++
		shifts += res.shifts[0] + res.shifts[1]
	}
	// Stimulus: the phase-2 RTTs really are N(30 ms, 10 ms) on both paths.
	mean, sd := st.meanSD()
	if st.n < 2*seeds*290 || (mean-30*ms).Abs() > ms/2 || (sd-10*ms).Abs() > ms/2 {
		t.Fatalf("phase 2: %d RTTs with mean %v sd %v, want N(30ms, 10ms)", st.n, mean, sd)
	}
	t.Logf("%d seeds: phase-2 quality switches 0/1/2/>2 = %v (mean %.2f), %d level shifts", seeds, hist, float64(hist[1]+2*hist[2]+3*hist[3])/seeds, shifts)
}
