package sched

import (
	"testing"
	"time"
)

// TestSelectorBandAndFloor_L29 (plan §4): a challenger must beat the
// incumbent by the band (ch ≤ act×(1−Band)) and by the floor (act − ch ≥
// Floor), both inclusive. A pair meeting only one of them never switches
// over five minutes, including low-RTT LAN paths where 25% is less than
// 5 ms; a pair meeting both switches exactly once, at Dwell, including both
// exact boundaries.
func TestSelectorBandAndFloor_L29(t *testing.T) {
	p := defaultSelectorParams()
	for _, tc := range []struct {
		name        string
		act, ch     time.Duration
		band, floor bool // expected truth of each condition (checked below)
	}{
		{"band only: 12 vs 8 ms", 12 * ms, 8 * ms, true, false},
		{"band only, LAN: 4 vs 2 ms", 4 * ms, 2 * ms, true, false},
		{"band only, LAN: 6 vs 1.5 ms", 6 * ms, 1500 * time.Microsecond, true, false},
		{"band only: 1 ns short of the floor", 16 * ms, 11*ms + 1, true, false},
		{"floor only: 100 vs 76 ms", 100 * ms, 76 * ms, false, true},
		{"floor only: 1 ns short of the band", 40 * ms, 30*ms + 1, false, true},
		{"both: 15 vs 9 ms", 15 * ms, 9 * ms, true, true},
		{"both, band boundary: 40 vs 30 ms", 40 * ms, 30 * ms, true, true},
		{"both, floor boundary: 16 vs 11 ms", 16 * ms, 11 * ms, true, true},
		{"both boundaries: 20 vs 15 ms", 20 * ms, 15 * ms, true, true},
	} {
		// The table's own claims, in integer arithmetic (Band = 1/4).
		if band := 4*tc.ch <= 3*tc.act; band != tc.band {
			t.Fatalf("%s: band holds = %v, table says %v", tc.name, band, tc.band)
		}
		if floor := tc.act-tc.ch >= p.Floor; floor != tc.floor {
			t.Fatalf("%s: floor holds = %v, table says %v", tc.name, floor, tc.floor)
		}
		sel := NewSelector(p)
		active := 0
		start := simEpoch
		sw, evals := drive(&sel, &active, start, start.Add(5*time.Minute), time.Second, func(now time.Time) ([]Summary, []bool) {
			return []Summary{freshSum(now, tc.act), freshSum(now, tc.ch)}, nil
		})
		if evals < 300 {
			t.Fatalf("%s: only %d evaluations", tc.name, evals)
		}
		if !tc.band || !tc.floor {
			if len(sw) != 0 {
				t.Errorf("%s: switches %+v, want none (band %v, floor %v)", tc.name, sw, tc.band, tc.floor)
			}
			continue
		}
		if len(sw) != 1 || sw[0].to != 1 || !sw[0].at.Equal(start.Add(p.Dwell)) {
			t.Errorf("%s: switches %+v, want exactly one to 1 at Dwell", tc.name, sw)
		}
	}
}

// TestSelectorStaleEvidenceEndsDwell_L29: a dwell may run across the gap
// between two probe samples while the newest one is still within Fresh
// (the hold), but stale evidence never starts or extends one. A challenger
// whose evidence ages out before its dwell ends is cleared at the ageing
// instant, which Verdict.Wake names; a caller that missed that wake cannot
// carry the dwell across the stale gap either, nor across a new probe
// incarnation.
func TestSelectorStaleEvidenceEndsDwell_L29(t *testing.T) {
	p := defaultSelectorParams()
	e0 := simEpoch.Add(4 * time.Hour)
	// A (active, 100 ms) gets a sample at every evaluation; B (50 ms, far
	// better by band and floor) has its newest sample at bAt.
	eval := func(sel *Selector, now, bAt time.Time) Verdict {
		return sel.Evaluate(now, 0, []Summary{
			{Seen: true, N: 32, Mean: 100 * ms, At: now},
			{Seen: true, N: 32, Mean: 50 * ms, At: bAt},
		}, nil)
	}

	// Beyond the hold: B's newest sample is 9 s old and none follows. It
	// turns Stale at bAt + Fresh + 1 ns, before its dwell would end.
	sel := NewSelector(p)
	bAt := e0.Add(-9 * time.Second)
	ages := bAt.Add(p.Fresh + 1)
	if v := eval(&sel, e0, bAt); v.Switch || !v.Wake.Equal(ages) {
		t.Fatalf("stale soon: %+v, want no switch and a wake at the ageing instant %v", v, ages)
	}
	if ev := Classify(Summary{Seen: true, N: 32, Mean: 50 * ms, At: bAt}, ages, p.Fresh); ev.State != EvStale {
		t.Fatalf("B at the wake: %v, want stale", ev.State)
	}
	for _, at := range []time.Time{ages, e0.Add(p.Dwell), e0.Add(p.Dwell + time.Second), e0.Add(time.Minute)} {
		if v := eval(&sel, at, bAt); v.Switch {
			t.Fatalf("stale challenger switched at e0+%v", at.Sub(e0))
		}
	}

	// Within the hold: the newest sample is 6 s old and still Fresh when the
	// dwell ends, so the switch comes exactly at Dwell without a new sample.
	sel = NewSelector(p)
	bAt = e0.Add(-6 * time.Second)
	if v := eval(&sel, e0, bAt); v.Switch || !v.Wake.Equal(e0.Add(p.Dwell)) {
		t.Fatalf("within the hold: %+v, want a wake at the dwell end", v)
	}
	if v := eval(&sel, e0.Add(p.Dwell-1), bAt); v.Switch {
		t.Fatal("switched before Dwell")
	}
	if v := eval(&sel, e0.Add(p.Dwell), bAt); !v.Switch || v.To != 1 {
		t.Fatalf("within the hold at Dwell: %+v, want a switch to 1", v)
	}

	// A late caller skipped the ageing wake: B's old sample was Stale from
	// e0+1s+1ns and the next one arrived only at e0+1.5s. At e0+2s B is
	// Fresh again, but its dwell restarts there.
	bAt = e0.Add(-9 * time.Second)
	late := e0.Add(1500 * ms)
	sel = NewSelector(p)
	eval(&sel, e0, bAt)
	if v := eval(&sel, e0.Add(2*time.Second), late); v.Switch || !v.Wake.Equal(e0.Add(2*time.Second+p.Dwell)) {
		t.Fatalf("after a missed wake: %+v, want the dwell restarted at e0+2s", v)
	}
	if v := eval(&sel, e0.Add(p.Dwell), late); v.Switch {
		t.Fatal("a stale gap extended the dwell")
	}
	if v := eval(&sel, e0.Add(2*time.Second+p.Dwell), late); !v.Switch || v.To != 1 {
		t.Fatalf("restarted dwell: %+v, want a switch to 1", v)
	}
	// Control: the next sample arrived in time (exactly at the ageing
	// instant, which it covers): the same late caller keeps the dwell.
	sel = NewSelector(p)
	eval(&sel, e0, bAt)
	if v := eval(&sel, e0.Add(2*time.Second), ages); v.Switch {
		t.Fatal("switched before Dwell")
	}
	if v := eval(&sel, e0.Add(p.Dwell), ages); !v.Switch || v.To != 1 {
		t.Fatalf("continuous evidence, late caller: %+v, want a switch at Dwell", v)
	}
	// A new probe incarnation (Reset) whose first sample is older than the
	// one seen before: the evidence restarted, and so does the dwell.
	sel = NewSelector(p)
	eval(&sel, e0, e0.Add(-time.Second))
	eval(&sel, e0.Add(2*time.Second), e0.Add(-2*time.Second))
	if v := eval(&sel, e0.Add(p.Dwell), e0.Add(-2*time.Second)); v.Switch {
		t.Fatal("dwell carried across a new probe incarnation")
	}
	if v := eval(&sel, e0.Add(2*time.Second+p.Dwell), e0.Add(-2*time.Second)); !v.Switch {
		t.Fatalf("new incarnation: %+v, want a switch Dwell after it was seen", v)
	}
}

// TestSelectorLoadedChallengerNotTarget_L29 (§8.4): a path that another
// session of this Peer is loading cannot become a quality target, even
// while Classify still reports its pre-load value as Fresh (an unloaded
// sample within Probe.Fresh, a newer one loaded). A degrades from 8 to
// 50 ms while B's sibling load runs: B's pre-load 10 ms would qualify, but
// B is chosen only once an unloaded sample is newest again, Dwell after the
// load ended. Ranking (Dial, failover) still ranks B by its value. The
// control without the load switches during the protected window.
func TestSelectorLoadedChallengerNotTarget_L29(t *testing.T) {
	const (
		loadFrom = 60 * time.Second  // B's PINGs sent in [loadFrom, loadTo) are loaded
		loadTo   = 120 * time.Second //
		degrade  = 59 * time.Second  // A's PINGs sent from here measure 50 ms
		phaseB   = 1100 * ms
	)
	type outcome struct {
		res       simResult
		protected int // evaluations: B Fresh at 10 ms with a newer loaded sample, A Fresh at 50 ms
		rankedB   int // ... at which the failover ranking still puts B first
	}
	run := func(load bool) outcome {
		var o outcome
		a := simPath{phase: 100 * ms, rtt: stepRTT(8*ms, 50*ms, degrade)}
		b := simPath{phase: phaseB, rtt: func(_ int, send time.Duration) time.Duration {
			if load && send >= loadFrom && send < loadTo {
				return 150 * ms // the sibling's queueing (never enters the window)
			}
			return 10 * ms
		}}
		if load {
			b.loaded = func(_ int, send time.Duration) bool { return send >= loadFrom && send < loadTo }
		}
		o.res = runSim(simConfig{
			sel: defaultSelectorParams(), agg: DefaultAggParams(), interval: defInterval, dur: 4 * time.Minute,
			paths: []simPath{a, b},
			observe: func(now time.Time, active int, sums []Summary, v Verdict) {
				ea, eb := Classify(sums[0], now, defFresh), Classify(sums[1], now, defFresh)
				if active != 0 || eb != (Evidence{EvFresh, 10 * ms}) || !sums[1].LoadedAt.After(sums[1].At) || ea != (Evidence{EvFresh, 50 * ms}) {
					return
				}
				o.protected++
				if r := Rank([]Candidate{{Index: 0, Ev: ea}, {Index: 1, Ev: eb}}, nil); r[0] == 1 {
					o.rankedB++
				}
			},
		})
		return o
	}

	o := run(true)
	// Stimulus: B was loaded (30 samples), A's degradation was seen, and B
	// sat Fresh at its 10 ms pre-load value with a newer loaded sample
	// while A was at 50 ms for several evaluations (the window in which
	// Fresh-only eligibility would have picked it).
	if o.res.loaded[1] != 30 || o.res.shifts[0] != 1 || o.protected < 3 || o.rankedB != o.protected {
		t.Fatalf("loaded %v, A shifts %d, protected evaluations %d (ranked B first: %d)", o.res.loaded, o.res.shifts[0], o.protected, o.rankedB)
	}
	// B's first unloaded sample after the load: sent at the first PING time
	// at or after loadTo, back 10 ms later; the switch is Dwell after it.
	firstAfter := phaseB + (loadTo-phaseB+defInterval-1)/defInterval*defInterval
	want := firstAfter + 10*ms + defDwell
	if len(o.res.switches) != 1 || o.res.switches[0].to != 1 || o.res.switches[0].at != want {
		t.Fatalf("switches %+v, want exactly one to B at %v (Dwell after the load ended)", o.res.switches, want)
	}

	// Control: without the sibling load B wins during the same window.
	ctl := run(false)
	if len(ctl.res.switches) != 1 || ctl.res.switches[0].to != 1 || ctl.res.switches[0].at >= loadFrom+15*time.Second {
		t.Fatalf("control: switches %+v, want one to B soon after A degraded", ctl.res.switches)
	}
}
