package sched

import (
	"math/rand/v2"
	"testing"
	"time"
)

// TestSelectorClassUp_L28 (M2-D48; plan:125, plan:242): a packet session
// ranks its datagram factories as class 0 and its stream factories as
// class 1 (SetClasses). While it runs on a stream carrier, a datagram
// challenger with Fresh, unloaded evidence qualifies without Band and Floor
// — even four times slower, even against a held incumbent — and wins after
// exactly Dwell, an earlier quality switch's Cooldown still applying.
// Unknown, Stale, zero-sample, Held, loaded and failed datagram challengers
// never qualify (L28: such evidence never wins). A stream challenger never
// qualifies against a datagram incumbent, whatever either's evidence.
// Challengers of the active factory's own class keep Band and Floor; among
// qualified challengers the lower class wins. A factory the session may not
// dial (M2-D46) never becomes the target, even 100 times faster, when it
// has a class above the session's factories or is marked failed (the two
// ways SetClasses names). Every refused challenger has a control in which
// the same challenger switches, so each stimulus is real.
func TestSelectorClassUp_L28(t *testing.T) {
	p := defaultSelectorParams()
	const dg, st = 0, 1
	newSel := func(classes ...uint8) Selector {
		s := NewSelector(p)
		s.SetClasses(classes)
		return s
	}
	start := simEpoch

	t.Run("without band and floor", func(t *testing.T) {
		// The session fell back to stream factory 0 (20 ms); datagram
		// factory 1 measures 80 ms: band and floor both fail, yet it wins at
		// Dwell, and the faster stream path never takes it back.
		sums := func(now time.Time) ([]Summary, []bool) {
			return []Summary{freshSum(now, 20*ms), freshSum(now, 80*ms)}, nil
		}
		sel, active := newSel(st, dg), 0
		sw, evals := drive(&sel, &active, start, start.Add(5*time.Minute), time.Second, sums)
		if len(sw) != 1 || sw[0].from != 0 || sw[0].to != 1 || !sw[0].at.Equal(start.Add(p.Dwell)) {
			t.Fatalf("switches %+v, want exactly one, 0 → 1 at Dwell", sw)
		}
		if evals < 300 {
			t.Fatalf("only %d evaluations", evals)
		}
		// Control: the same evidence in a stream session (every class 0).
		sel, active = newSel(), 0
		if sw, _ := drive(&sel, &active, start, start.Add(5*time.Minute), time.Second, sums); len(sw) != 0 {
			t.Fatalf("stream session: switches %+v, want none (80 ms never beats 20 ms)", sw)
		}
	})

	t.Run("dwell, lapse and wake", func(t *testing.T) {
		sel := newSel(st, dg)
		t0 := start.Add(time.Hour)
		eval := func(now time.Time, ch Summary) Verdict {
			return sel.Evaluate(now, 0, []Summary{freshSum(now, 20*ms), ch}, nil)
		}
		if v := eval(t0, freshSum(t0, 80*ms)); v.Switch || !v.Wake.Equal(t0.Add(p.Dwell)) {
			t.Fatalf("t0: %+v, want no switch and a wake at the dwell end", v)
		}
		if v := eval(t0.Add(time.Second), freshSum(t0.Add(time.Second), 80*ms)); v.Switch {
			t.Fatal("switched before Dwell")
		}
		// A lapse: the datagram path's newest sample is loaded (a sibling
		// session saturates it, §8.4) — no target — then unloaded again.
		lapse := t0.Add(2 * time.Second)
		if v := eval(lapse, Summary{Seen: true, N: 32, Mean: 80 * ms, At: lapse.Add(-time.Second), LoadedAt: lapse}); v.Switch {
			t.Fatal("a loaded challenger switched")
		}
		again := t0.Add(2500 * ms)
		eval(again, freshSum(again, 80*ms))
		if v := eval(t0.Add(p.Dwell), freshSum(t0.Add(p.Dwell), 80*ms)); v.Switch || !v.Wake.Equal(again.Add(p.Dwell)) {
			t.Fatalf("the dwell survived a lapse: %+v, want a wake at %v", v, again.Add(p.Dwell))
		}
		if v := eval(again.Add(p.Dwell-1), freshSum(again.Add(p.Dwell-1), 80*ms)); v.Switch {
			t.Fatal("switched before the restarted dwell ended")
		}
		if v := eval(again.Add(p.Dwell), freshSum(again.Add(p.Dwell), 80*ms)); !v.Switch || v.To != 1 {
			t.Fatalf("restarted dwell: %+v, want a switch to 1", v)
		}
	})

	t.Run("cooldown", func(t *testing.T) {
		// Factories: 0 and 1 stream, 2 datagram. Stream 1 beats stream 0 by
		// band and floor: a quality switch at q1. The datagram path's probe
		// returns 1 s later (50 ms, slower than stream 1): its dwell ends at
		// q1 + 4 s, but the switch waits for q1 + Cooldown.
		q1 := start.Add(p.Dwell)
		dgFrom := q1.Add(time.Second)
		sums := func(now time.Time) ([]Summary, []bool) {
			s := []Summary{freshSum(now, 100*ms), freshSum(now, 10*ms), {}}
			if !now.Before(dgFrom) {
				s[2] = Summary{Seen: true, N: 1, Mean: 50 * ms, At: now}
			}
			return s, nil
		}
		sel, active := newSel(st, st, dg), 0
		sw, _ := drive(&sel, &active, start, start.Add(5*time.Minute), time.Second, sums)
		if len(sw) != 2 || sw[0].to != 1 || !sw[0].at.Equal(q1) || sw[1].from != 1 || sw[1].to != 2 || !sw[1].at.Equal(q1.Add(p.Cooldown)) {
			t.Fatalf("switches %+v, want 0 → 1 at %v and 1 → 2 at %v (the cooldown end)", sw, q1, q1.Add(p.Cooldown))
		}
		// A death switch starts no cooldown (D7): the datagram carrier died
		// and the session failed over to the stream factory at d; the
		// datagram probe recovers at r and wins Dwell later.
		sel = newSel(dg, st)
		d := start.Add(time.Minute)
		sel.Evaluate(d.Add(-time.Second), 0, []Summary{freshSum(d, 30*ms), freshSum(d, 30*ms)}, nil)
		sel.Switched(d, false)
		r := d.Add(5 * time.Second)
		active = 1
		sw, _ = drive(&sel, &active, d, d.Add(time.Minute), time.Second, func(now time.Time) ([]Summary, []bool) {
			s := []Summary{staleSum(now, 30*ms), freshSum(now, 30*ms)}
			if !now.Before(r) {
				s[0] = Summary{Seen: true, N: 1, Mean: 30 * ms, At: now}
			}
			return s, nil
		})
		if len(sw) != 1 || sw[0].to != 0 || !sw[0].at.Equal(r.Add(p.Dwell)) {
			t.Fatalf("after a death switch: %+v, want one switch to 0 at %v", sw, r.Add(p.Dwell))
		}
	})

	t.Run("only fresh unloaded evidence", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			sum    func(now time.Time) Summary
			failed bool
		}{
			{"unknown", func(time.Time) Summary { return Summary{} }, false},
			{"stale 1 ns", func(now time.Time) Summary { return staleSum(now, 1) }, false},
			{"zero samples", func(now time.Time) Summary { return Summary{Seen: true, N: 0, At: now.Add(-time.Second)} }, false},
			{"zero mean", func(now time.Time) Summary { return Summary{Seen: true, N: 32, At: now.Add(-time.Second)} }, false},
			{"held with a value", func(now time.Time) Summary { return heldSum(now, 5*ms) }, false},
			{"held without a value", func(now time.Time) Summary { return heldSum(now, 0) }, false},
			{"fresh, newest sample loaded", func(now time.Time) Summary {
				return Summary{Seen: true, N: 32, Mean: 5 * ms, At: now.Add(-2 * time.Second), LoadedAt: now.Add(-time.Second)}
			}, false},
			{"fresh but failed", func(now time.Time) Summary { return freshSum(now, 5*ms) }, true},
		} {
			sel, active := newSel(st, dg), 0
			sw, evals := drive(&sel, &active, start, start.Add(2*time.Minute), time.Second, func(now time.Time) ([]Summary, []bool) {
				return []Summary{freshSum(now, 20*ms), tc.sum(now)}, []bool{false, tc.failed}
			})
			if len(sw) != 0 {
				t.Errorf("%s datagram challenger: switches %+v, want none", tc.name, sw)
			}
			if evals < 120 {
				t.Errorf("%s: only %d evaluations", tc.name, evals)
			}
		}
		// Control: the same selector setup with Fresh unloaded evidence.
		sel, active := newSel(st, dg), 0
		sw, _ := drive(&sel, &active, start, start.Add(time.Minute), time.Second, func(now time.Time) ([]Summary, []bool) {
			return []Summary{freshSum(now, 20*ms), freshSum(now, 5*ms)}, nil
		})
		if len(sw) != 1 || sw[0].to != 1 || !sw[0].at.Equal(start.Add(p.Dwell)) {
			t.Fatalf("control: switches %+v, want one to 1 at Dwell", sw)
		}
	})

	t.Run("higher class never", func(t *testing.T) {
		// The session runs on datagram factory 0; stream factory 1 is Fresh
		// at 1 ns. In a stream session (control: equal classes) it would
		// win against each of these incumbents.
		for _, inc := range []struct {
			name string
			sum  func(now time.Time) Summary
		}{
			{"fresh 100 ms", func(now time.Time) Summary { return freshSum(now, 100*ms) }},
			{"stale", func(now time.Time) Summary { return staleSum(now, 10*ms) }},
			{"unknown", func(time.Time) Summary { return Summary{} }},
		} {
			sums := func(now time.Time) ([]Summary, []bool) {
				return []Summary{inc.sum(now), freshSum(now, 1)}, nil
			}
			sel, active := newSel(dg, st), 0
			if sw, _ := drive(&sel, &active, start, start.Add(5*time.Minute), time.Second, sums); len(sw) != 0 {
				t.Errorf("%s datagram incumbent: switches %+v, want none", inc.name, sw)
			}
			sel, active = newSel(dg, dg), 0
			if sw, _ := drive(&sel, &active, start, start.Add(time.Minute), time.Second, sums); len(sw) != 1 || sw[0].to != 1 {
				t.Errorf("%s, control (equal classes): switches %+v, want one to 1", inc.name, sw)
			}
		}
	})

	t.Run("ineligible factory never", func(t *testing.T) {
		// A stream session on a mixed Peer: stream factory 0 is active,
		// datagram factory 1 (1 ms, 100 times faster) is in the health
		// snapshot but the session may not dial it. Given class 255 above
		// the session's class 0, or marked failed, it never becomes the
		// target, whatever the incumbent's evidence; at class 0 and not
		// failed (the control) M1's rule switches to it at Dwell.
		const ineligible = 255
		for _, inc := range []struct {
			name string
			sum  func(now time.Time) Summary
		}{
			{"fresh 100 ms", func(now time.Time) Summary { return freshSum(now, 100*ms) }},
			{"held 100 ms", func(now time.Time) Summary { return heldSum(now, 100*ms) }},
			{"stale", func(now time.Time) Summary { return staleSum(now, 100*ms) }},
			{"unknown", func(time.Time) Summary { return Summary{} }},
		} {
			for _, way := range []struct {
				name    string
				classes []uint8
				failed  bool
			}{
				{"class 255", []uint8{0, ineligible}, false},
				{"marked failed", nil, true},
			} {
				sel, active := newSel(way.classes...), 0
				sw, evals := drive(&sel, &active, start, start.Add(5*time.Minute), time.Second, func(now time.Time) ([]Summary, []bool) {
					return []Summary{inc.sum(now), freshSum(now, ms)}, []bool{false, way.failed}
				})
				if len(sw) != 0 {
					t.Errorf("%s incumbent, %s: switches %+v, want none", inc.name, way.name, sw)
				}
				if evals < 300 {
					t.Errorf("%s incumbent, %s: only %d evaluations", inc.name, way.name, evals)
				}
			}
			sel, active := newSel(), 0
			sw, _ := drive(&sel, &active, start, start.Add(5*time.Minute), time.Second, func(now time.Time) ([]Summary, []bool) {
				return []Summary{inc.sum(now), freshSum(now, ms)}, []bool{false, false}
			})
			if len(sw) != 1 || sw[0].to != 1 || !sw[0].at.Equal(start.Add(p.Dwell)) {
				t.Errorf("%s incumbent, control (class 0, not failed): switches %+v, want one to 1 at Dwell", inc.name, sw)
			}
		}
	})

	t.Run("lower class wins among qualified", func(t *testing.T) {
		// Stream 1 (10 ms) qualifies against stream 0 (100 ms) by band and
		// floor, datagram 2 (50 ms) by class: both dwells end together and
		// the datagram factory wins; stream 1 never takes it back.
		sel, active := newSel(st, st, dg), 0
		sw, _ := drive(&sel, &active, start, start.Add(5*time.Minute), time.Second, func(now time.Time) ([]Summary, []bool) {
			return []Summary{freshSum(now, 100*ms), freshSum(now, 10*ms), freshSum(now, 50*ms)}, nil
		})
		if len(sw) != 1 || sw[0].to != 2 || !sw[0].at.Equal(start.Add(p.Dwell)) {
			t.Fatalf("switches %+v, want exactly one, to 2 at Dwell", sw)
		}
		// Among challengers of one class the lower RTT wins (M1).
		sel, active = newSel(st, dg, dg), 0
		sw, _ = drive(&sel, &active, start, start.Add(time.Minute), time.Second, func(now time.Time) ([]Summary, []bool) {
			return []Summary{freshSum(now, 10*ms), freshSum(now, 60*ms), freshSum(now, 40*ms)}, nil
		})
		if len(sw) != 1 || sw[0].to != 2 {
			t.Fatalf("two datagram challengers: switches %+v, want one to 2 (40 ms)", sw)
		}
	})

	t.Run("same class keeps band and floor", func(t *testing.T) {
		// Datagram 0 active (20 ms); datagram 1 at 16 ms misses the band;
		// stream 2 at 1 ns is of a higher class. From t1 datagram 1
		// measures 10 ms (band and floor hold) and wins Dwell later.
		t1 := start.Add(2 * time.Minute)
		sel, active := newSel(dg, dg, st), 0
		sw, _ := drive(&sel, &active, start, start.Add(5*time.Minute), time.Second, func(now time.Time) ([]Summary, []bool) {
			ch := freshSum(now, 16*ms)
			if !now.Before(t1) {
				ch = freshSum(now, 10*ms)
			}
			return []Summary{freshSum(now, 20*ms), ch, freshSum(now, 1)}, nil
		})
		if len(sw) != 1 || sw[0].to != 1 || !sw[0].at.Equal(t1.Add(p.Dwell)) {
			t.Fatalf("switches %+v, want one to 1 at %v", sw, t1.Add(p.Dwell))
		}
	})

	t.Run("class-up replaces a held incumbent", func(t *testing.T) {
		// The stream incumbent is loaded by the packet session itself (its
		// DGRAMs count as DATA on a stream carrier, M2-D26): Held, with or
		// without a value. M1 never replaces either by a 50-ms challenger;
		// the class rule does, after Dwell.
		for _, inc := range []struct {
			name string
			rtt  time.Duration
		}{{"held with a value", 5 * ms}, {"held without a value", 0}} {
			sums := func(now time.Time) ([]Summary, []bool) {
				return []Summary{heldSum(now, inc.rtt), freshSum(now, 50*ms)}, nil
			}
			sel, active := newSel(st, dg), 0
			if sw, _ := drive(&sel, &active, start, start.Add(time.Minute), time.Second, sums); len(sw) != 1 || sw[0].to != 1 || !sw[0].at.Equal(start.Add(p.Dwell)) {
				t.Errorf("%s: switches %+v, want one to 1 at Dwell", inc.name, sw)
			}
			sel, active = newSel(), 0
			if sw, _ := drive(&sel, &active, start, start.Add(time.Minute), time.Second, sums); len(sw) != 0 {
				t.Errorf("%s, control (stream session): switches %+v, want none", inc.name, sw)
			}
		}
	})

	t.Run("SetClasses", func(t *testing.T) {
		// Reset to all zero restores M1; entries beyond 16 are ignored and
		// missing ones are 0.
		sel := newSel(st, dg)
		sel.SetClasses(nil)
		active := 0
		if sw, _ := drive(&sel, &active, start, start.Add(time.Minute), time.Second, func(now time.Time) ([]Summary, []bool) {
			return []Summary{freshSum(now, 20*ms), freshSum(now, 80*ms)}, nil
		}); len(sw) != 0 {
			t.Fatalf("after SetClasses(nil): switches %+v", sw)
		}
		long := make([]uint8, 20)
		long[0] = st
		sel = newSel(long...)
		active = 0
		if sw, _ := drive(&sel, &active, start, start.Add(time.Minute), time.Second, func(now time.Time) ([]Summary, []bool) {
			return []Summary{freshSum(now, 20*ms), freshSum(now, 80*ms)}, nil
		}); len(sw) != 1 || sw[0].to != 1 {
			t.Fatalf("20 classes: switches %+v, want one to 1", sw)
		}
	})
}

// TestSelectorClassUpOnce_L29 (M2-D48; plan §3.9 virtual-time model): a
// packet session that fell back to its stream factory while the datagram
// path was down returns to the datagram factory exactly once — Dwell after
// the datagram probe's first sample — and never leaves it for quality,
// with noisy probes (stream N(30 ms, 10 ms); datagram N(30 ms, 10 ms) or
// N(80 ms, 10 ms)), 20 seeds × 10 virtual minutes each. Stimulus: with the
// 80-ms datagram path the stream path beats it by band and floor at nearly
// every evaluation after the return, which M1's rule would act on.
func TestSelectorClassUpOnce_L29(t *testing.T) {
	const seeds, dur, back = 20, 10 * time.Minute, time.Minute
	for _, dgMean := range []time.Duration{30 * ms, 80 * ms} {
		minBeaten, maxEvals := int(^uint(0)>>1), 0
		for seed := uint64(1); seed <= seeds; seed++ {
			ph := rand.New(rand.NewPCG(seed, 48))
			dgRTT := normalRTT(seed, 1, dgMean, 10*ms)
			var first time.Duration // the first datagram sample's arrival
			paths := []simPath{
				{phase: back + time.Duration(ph.Int64N(int64(defInterval))), rtt: func(k int, send time.Duration) time.Duration {
					d := dgRTT(k, send)
					if k == 0 {
						first = send + d
					}
					return d
				}},
				{phase: time.Duration(ph.Int64N(int64(defInterval))), rtt: normalRTT(seed, 2, 30*ms, 10*ms)},
			}
			beaten := 0 // evaluations on the datagram path that M1's rule would leave
			res := runSim(simConfig{
				sel: defaultSelectorParams(), agg: DefaultAggParams(), interval: defInterval, dur: dur,
				active: 1, classes: []uint8{0, 1}, paths: paths,
				observe: func(now time.Time, active int, sums []Summary, v Verdict) {
					ed, es := Classify(sums[0], now, defFresh), Classify(sums[1], now, defFresh)
					if active == 0 && ed.State == EvFresh && es.State == EvFresh && 4*es.RTT <= 3*ed.RTT && ed.RTT-es.RTT >= defFloor {
						beaten++
					}
				},
			})
			// Load: both probes produced their samples (the datagram one
			// from its return on).
			if res.samples[0] < 260 || res.samples[1] < 299 {
				t.Fatalf("datagram %v, seed %d: samples %v", dgMean, seed, res.samples)
			}
			if len(res.switches) != 1 || res.switches[0].from != 1 || res.switches[0].to != 0 || res.switches[0].at != first+defDwell || res.finalAct != 0 {
				t.Fatalf("datagram %v, seed %d: switches %+v (final %d), want exactly one 1 → 0 at %v", dgMean, seed, res.switches, res.finalAct, first+defDwell)
			}
			if dgMean == 80*ms && beaten < 500 {
				t.Fatalf("seed %d: the stream path beat the datagram path at only %d evaluations", seed, beaten)
			}
			minBeaten, maxEvals = min(minBeaten, beaten), max(maxEvals, res.evals)
		}
		t.Logf("datagram %v: the stream path would have won at ≥ %d evaluations per seed (≤ %d evaluations)", dgMean, minBeaten, maxEvals)
	}
}
