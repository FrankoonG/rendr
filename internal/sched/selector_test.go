package sched

import (
	"testing"
	"time"
)

// Summaries built relative to an evaluation instant.

// freshSum: a full window of rtt whose newest sample is 1 s old.
func freshSum(now time.Time, rtt time.Duration) Summary {
	return Summary{Seen: true, N: 32, Mean: rtt, At: now.Add(-time.Second)}
}

// heldSum: the last unloaded sample (rtt) is a minute old, a loaded one is
// recent; rtt 0 means no unloaded sample ever (held without a value).
func heldSum(now time.Time, rtt time.Duration) Summary {
	s := Summary{Seen: true, LoadedAt: now.Add(-time.Second)}
	if rtt > 0 {
		s.N, s.Mean, s.At = 32, rtt, now.Add(-time.Minute)
	}
	return s
}

// staleSum: the newest sample (rtt) is a minute old.
func staleSum(now time.Time, rtt time.Duration) Summary {
	return Summary{Seen: true, N: 32, Mean: rtt, At: now.Add(-time.Minute)}
}

type evSwitch struct {
	at       time.Time
	from, to int
}

// drive evaluates sel at from, every step after it and at every
// Verdict.Wake until to, with the summaries sums(now) returns, and applies
// every Switch at once (Switched(now, true)), like the actor. It returns
// the switches and the number of evaluations.
func drive(sel *Selector, active *int, from, to time.Time, step time.Duration, sums func(now time.Time) ([]Summary, []bool)) ([]evSwitch, int) {
	var out []evSwitch
	evals := 0
	tick := from
	var wake time.Time
	for {
		now := tick
		if !wake.IsZero() && wake.Before(now) {
			now = wake
		}
		if now.After(to) {
			return out, evals
		}
		s, f := sums(now)
		v := sel.Evaluate(now, *active, s, f)
		evals++
		if v.Switch {
			out = append(out, evSwitch{at: now, from: *active, to: v.To})
			*active = v.To
			sel.Switched(now, true)
			v = sel.Evaluate(now, *active, s, f)
			evals++
		}
		wake = time.Time{}
		if v.Wake.After(now) {
			wake = v.Wake
		}
		if !now.Before(tick) {
			tick = tick.Add(step)
		}
	}
}

// TestSelectorChallengerNeedsFresh_L28: only Fresh unloaded evidence may
// challenge; Held (even with a much better held value), Stale (even 1 ns),
// Unknown, zero-sample and failed factories never do, for any length of
// time. A Fresh challenger replaces a Stale or Unknown incumbent after Dwell.
func TestSelectorChallengerNeedsFresh_L28(t *testing.T) {
	p := defaultSelectorParams()
	sel := NewSelector(p)
	active := 0
	start := simEpoch
	freshFrom := start.Add(2 * time.Minute) // factory 1 turns Fresh here
	sums := func(now time.Time) ([]Summary, []bool) {
		s := []Summary{
			freshSum(now, 50*ms), // active A
			heldSum(now, 10*ms),  // held with a much better value: no challenge
			staleSum(now, 1),     // stale 1 ns
			{},                   // unknown
			{Seen: true, N: 0, At: now.Add(-time.Second)}, // zero samples
			freshSum(now, 5*ms),                           // fresh and much better, but failed
		}
		if !now.Before(freshFrom) {
			s[1] = freshSum(now, 10*ms)
		}
		return s, []bool{false, false, false, false, false, true}
	}
	sw, evals := drive(&sel, &active, start, freshFrom.Add(-time.Nanosecond), time.Second, sums)
	if len(sw) != 0 {
		t.Fatalf("non-fresh or failed challengers switched: %+v", sw)
	}
	if evals < 120 {
		t.Fatalf("only %d evaluations over two minutes", evals)
	}
	// Stimulus control: the same factory with Fresh evidence qualifies
	// (10 ≤ 50·0.75 and 50 − 10 ≥ 5 ms) and wins after exactly Dwell.
	sw, _ = drive(&sel, &active, freshFrom, freshFrom.Add(time.Minute), time.Second, sums)
	if len(sw) != 1 || sw[0].to != 1 || !sw[0].at.Equal(freshFrom.Add(p.Dwell)) {
		t.Fatalf("fresh challenger: switches %+v, want one to 1 at %v", sw, freshFrom.Add(p.Dwell))
	}

	// A Fresh challenger replaces an unmeasured incumbent, even with a
	// worse RTT than the incumbent's old value (L28: stale evidence is
	// not protected).
	for _, inc := range []struct {
		name string
		sum  func(now time.Time) Summary
	}{
		{"stale incumbent", func(now time.Time) Summary { return staleSum(now, 10*ms) }},
		{"unknown incumbent", func(time.Time) Summary { return Summary{} }},
	} {
		sel := NewSelector(p)
		active := 0
		sw, _ := drive(&sel, &active, start, start.Add(time.Minute), time.Second, func(now time.Time) ([]Summary, []bool) {
			return []Summary{inc.sum(now), freshSum(now, 80*ms)}, nil
		})
		if len(sw) != 1 || sw[0].to != 1 || !sw[0].at.Equal(start.Add(p.Dwell)) {
			t.Fatalf("%s: switches %+v, want one to 1 after Dwell", inc.name, sw)
		}
	}
}

// TestSelectorDwellCooldown_L29: 30% better switches only after Dwell of
// continuous qualification, a second quality switch waits for Cooldown, a
// lapse or a different challenger restarts the dwell, the first quality
// switch needs no cooldown and death switches neither need nor start one
// (D7).
func TestSelectorDwellCooldown_L29(t *testing.T) {
	p := defaultSelectorParams()
	t0 := simEpoch
	at := func(d time.Duration) time.Time { return t0.Add(d) }
	sel := NewSelector(p)
	eval := func(now time.Time, active int, rtts ...time.Duration) Verdict {
		s := make([]Summary, len(rtts))
		for i, r := range rtts {
			s[i] = freshSum(now, r)
		}
		return sel.Evaluate(now, active, s, nil)
	}

	// B is 30% better than A (70 vs 100 ms): qualifies, dwell 3 s.
	if v := eval(at(0), 0, 100*ms, 70*ms); v.Switch || !v.Wake.Equal(at(p.Dwell)) {
		t.Fatalf("t=0: %+v, want no switch, wake at the dwell end", v)
	}
	for _, d := range []time.Duration{time.Second, 2 * time.Second, p.Dwell - 1} {
		if v := eval(at(d), 0, 100*ms, 70*ms); v.Switch {
			t.Fatalf("switched after %v < Dwell", d)
		}
	}
	v := eval(at(p.Dwell), 0, 100*ms, 70*ms)
	if !v.Switch || v.To != 1 {
		t.Fatalf("t=Dwell: %+v, want a switch to 1 (the first needs no cooldown)", v)
	}
	sel.Switched(at(p.Dwell), true)
	q1 := at(p.Dwell)

	// Now A is 30% better than B: it qualifies at once, but the second
	// quality switch must wait for Cooldown after the first.
	if v := eval(q1, 1, 49*ms, 70*ms); v.Switch || !v.Wake.Equal(q1.Add(p.Dwell)) {
		t.Fatalf("after the switch: %+v, want the dwell to restart", v)
	}
	// The dwell is done but the cooldown is not: the wake is the cooldown
	// end unless the evidence ages first (freshSum's sample is 1 s old, so
	// without a new sample it would turn Stale after Fresh − 1 s).
	dwellDone := q1.Add(p.Dwell)
	wantWake := earlier(q1.Add(p.Cooldown), dwellDone.Add(-time.Second+p.Fresh+1))
	if v := eval(dwellDone, 1, 49*ms, 70*ms); v.Switch || !v.Wake.Equal(wantWake) {
		t.Fatalf("dwell done within cooldown: %+v, want no switch and wake at %v", v, wantWake)
	}
	if v := eval(q1.Add(p.Cooldown-p.Fresh/2), 1, 49*ms, 70*ms); v.Switch || !v.Wake.Equal(q1.Add(p.Cooldown)) {
		t.Fatalf("late in the cooldown: %+v, want wake at the cooldown end %v", v, q1.Add(p.Cooldown))
	}
	if v := eval(q1.Add(p.Cooldown-1), 1, 49*ms, 70*ms); v.Switch {
		t.Fatal("second quality switch within Cooldown")
	}
	if v := eval(q1.Add(p.Cooldown), 1, 49*ms, 70*ms); !v.Switch || v.To != 0 {
		t.Fatalf("at the cooldown end: %+v, want a switch back to 0", v)
	}
	sel.Switched(q1.Add(p.Cooldown), true)
	q2 := q1.Add(p.Cooldown)

	// A lapse restarts the dwell: B qualifies, stops qualifying for one
	// evaluation, qualifies again; the dwell counts from the re-start.
	t1 := q2.Add(p.Cooldown) // cooldown over
	eval(t1, 0, 100*ms, 70*ms)
	eval(t1.Add(2*time.Second), 0, 100*ms, 70*ms)
	eval(t1.Add(2500*ms), 0, 100*ms, 80*ms) // 80 > 75: no longer qualifies
	eval(t1.Add(2600*ms), 0, 100*ms, 70*ms) // dwell restarts here
	if v := eval(t1.Add(p.Dwell), 0, 100*ms, 70*ms); v.Switch {
		t.Fatal("dwell survived a non-qualifying evaluation")
	}
	if v := eval(t1.Add(2600*ms+p.Dwell), 0, 100*ms, 70*ms); !v.Switch || v.To != 1 {
		t.Fatalf("restarted dwell: %+v, want a switch to 1", v)
	}
	sel.Switched(t1.Add(2600*ms+p.Dwell), true)

	// A different best challenger restarts the dwell (three factories).
	t2 := t1.Add(2600*ms + p.Dwell + p.Cooldown)
	eval(t2, 1, 100*ms, 100*ms, 70*ms)                   // C qualifies against B
	eval(t2.Add(2*time.Second), 1, 60*ms, 100*ms, 70*ms) // A is now the best: restart
	if v := eval(t2.Add(p.Dwell), 1, 60*ms, 100*ms, 70*ms); v.Switch {
		t.Fatal("dwell carried over to a different challenger")
	}
	if v := eval(t2.Add(2*time.Second+p.Dwell), 1, 60*ms, 100*ms, 70*ms); !v.Switch || v.To != 0 {
		t.Fatalf("new challenger after its own dwell: %+v, want a switch to 0", v)
	}
	sel.Switched(t2.Add(2*time.Second+p.Dwell), true)
	q3 := t2.Add(2*time.Second + p.Dwell)

	// D7: a death switch inside the cooldown neither resets nor extends it:
	// the next quality switch still waits for q3 + Cooldown, not for the
	// death time + Cooldown.
	death := q3.Add(5 * time.Second)
	sel.Switched(death, false) // the actor failed over to factory 1
	eval(death, 1, 100*ms, 100*ms, 60*ms)
	if v := eval(q3.Add(p.Cooldown-1), 1, 100*ms, 100*ms, 60*ms); v.Switch {
		t.Fatal("quality switch inside the cooldown of a quality switch")
	}
	if v := eval(q3.Add(p.Cooldown), 1, 100*ms, 100*ms, 60*ms); !v.Switch || v.To != 2 {
		t.Fatalf("after the quality cooldown: %+v, want a switch to 2", v)
	}

	// An incumbent change the selector was not told about (no Switched)
	// still restarts the dwell: qualification is measured per incumbent.
	sel3 := NewSelector(p)
	c0 := simEpoch.Add(2 * time.Hour)
	three := func(now time.Time) []Summary {
		return []Summary{freshSum(now, 100*ms), freshSum(now, 100*ms), freshSum(now, 70*ms)}
	}
	sel3.Evaluate(c0, 0, three(c0), nil)                    // C qualifies against A
	sel3.Evaluate(c0.Add(2*time.Second), 1, three(c0), nil) // now against B
	if v := sel3.Evaluate(c0.Add(p.Dwell), 1, three(c0.Add(p.Dwell)), nil); v.Switch {
		t.Fatal("dwell carried over to a different incumbent")
	}
	if v := sel3.Evaluate(c0.Add(2*time.Second+p.Dwell), 1, three(c0.Add(2*time.Second+p.Dwell)), nil); !v.Switch || v.To != 2 {
		t.Fatalf("dwell against the new incumbent: %+v", v)
	}

	// D7: death switches never start a cooldown: with only death switches
	// in the past, a qualifying challenger needs Dwell and nothing more.
	sel2 := NewSelector(p)
	d0 := simEpoch.Add(time.Hour)
	sel2.Switched(d0, false)
	s := func(now time.Time) []Summary { return []Summary{freshSum(now, 100*ms), freshSum(now, 70*ms)} }
	sel2.Evaluate(d0, 0, s(d0), nil)
	if v := sel2.Evaluate(d0.Add(p.Dwell), 0, s(d0.Add(p.Dwell)), nil); !v.Switch {
		t.Fatalf("death switch started a cooldown: %+v", v)
	}
}

// TestSelectorHoldsLoadedIncumbent_L29 (§8): an active path loaded by this
// Peer's own traffic keeps its pre-load value while its probe samples are
// loaded, so self-induced queueing cannot trigger a quality switch; a
// genuinely better Fresh path still wins against the held value.
func TestSelectorHoldsLoadedIncumbent_L29(t *testing.T) {
	const loadAt = 60 * time.Second
	type outcome struct {
		res      simResult
		heldEval int     // evaluations with A active and EvHeld at its pre-load value
		atSwitch EvState // A's evidence at the first switch
	}
	run := func(guard bool, b func(int, time.Duration) time.Duration) outcome {
		var o outcome
		a := simPath{phase: 100 * ms, rtt: stepRTT(20*ms, 150*ms, loadAt)}
		if guard {
			a.loaded = func(_ int, send time.Duration) bool { return send >= loadAt }
		}
		o.res = runSim(simConfig{
			sel: defaultSelectorParams(), agg: DefaultAggParams(), interval: defInterval, dur: 5 * time.Minute,
			paths: []simPath{a, {phase: 1100 * ms, rtt: b}},
			observe: func(now time.Time, active int, sums []Summary, v Verdict) {
				ev := Classify(sums[0], now, defFresh)
				if active == 0 && ev == (Evidence{EvHeld, 20 * ms}) {
					o.heldEval++
				}
				if v.Switch && o.atSwitch == EvUnknown {
					o.atSwitch = ev.State
				}
			},
		})
		return o
	}

	o := run(true, constRTT(30*ms))
	if len(o.res.switches) != 0 {
		t.Fatalf("self-load caused quality switches: %+v", o.res.switches)
	}
	// Stimulus and load: 120 loaded samples at 150 ms reached A's
	// aggregator, B kept fresh samples all along, and A was evaluated as
	// held at its pre-load value for the whole loaded period.
	if o.res.loaded[0] != 120 || o.res.samples[0] != 30 || o.res.samples[1] != 150 || o.res.shifts[0] != 0 {
		t.Fatalf("samples %v, loaded %v, shifts %v", o.res.samples, o.res.loaded, o.res.shifts)
	}
	if o.heldEval < 200 {
		t.Fatalf("A evaluated as held only %d times", o.heldEval)
	}
	end := simEpoch.Add(5 * time.Minute)
	if ev := Classify(o.res.final[0], end, defFresh); ev != (Evidence{EvHeld, 20 * ms}) {
		t.Fatalf("A at the end: %+v, want held at its pre-load 20 ms", ev)
	}

	// Control: the same RTTs without the loaded tag move A to 150 ms and
	// B (30 ms) takes over.
	ctl := run(false, constRTT(30*ms))
	if len(ctl.res.switches) != 1 || ctl.res.switches[0].to != 1 {
		t.Fatalf("guard-disabled control: switches %+v, want exactly one to B", ctl.res.switches)
	}

	// A Held incumbent is compared by its held value: when B improves to
	// 10 ms during the load (beating the held 20 ms by Band and Floor) it
	// wins, while A is still held.
	better := run(true, stepRTT(30*ms, 10*ms, loadAt+30*time.Second))
	if len(better.res.switches) != 1 || better.res.switches[0].to != 1 {
		t.Fatalf("better fresh challenger vs held incumbent: %+v", better.res.switches)
	}
	if better.atSwitch != EvHeld || better.res.switches[0].at < loadAt+30*time.Second {
		t.Fatalf("switch at %v with A %v, want after B improved and with A held", better.res.switches[0].at, better.atSwitch)
	}
}

// TestSelectorHeldWithoutValueNeverReplaced_L29 (§8): an active path whose
// probe incarnation never produced an unloaded sample is protected without
// a value for as long as loaded samples keep arriving; only when they stop
// and it turns Stale does a Fresh challenger replace it, after Dwell.
func TestSelectorHeldWithoutValueNeverReplaced_L29(t *testing.T) {
	const stop = 200 * time.Second
	a := simPath{
		phase:  100 * ms,
		rtt:    constRTT(50 * ms),
		loaded: func(int, time.Duration) bool { return true },
		until:  stop,
	}
	b := simPath{phase: 700 * ms, rtt: constRTT(5 * ms)}
	protected := 0 // evaluations: A active and held without a value, B fresh and far better
	res := runSim(simConfig{
		sel: defaultSelectorParams(), agg: DefaultAggParams(), interval: defInterval, dur: 5 * time.Minute,
		paths: []simPath{a, b},
		observe: func(now time.Time, active int, sums []Summary, v Verdict) {
			if active == 0 && Classify(sums[0], now, defFresh) == (Evidence{State: EvHeld}) &&
				Classify(sums[1], now, defFresh) == (Evidence{EvFresh, 5 * ms}) {
				protected++
			}
		},
	})
	if res.samples[0] != 0 || res.loaded[0] != 100 {
		t.Fatalf("A: %d unloaded, %d loaded samples; want 0 and 100", res.samples[0], res.loaded[0])
	}
	if protected < 200 {
		t.Fatalf("only %d protected evaluations", protected)
	}
	if len(res.switches) != 1 {
		t.Fatalf("switches %+v, want exactly one (after A turns stale)", res.switches)
	}
	// A's last loaded PONG: sent at 198.1 s, received 50 ms later. It is
	// Held until 10 s after that, Stale 1 ns later; B then needs Dwell.
	lastLoaded := 198100*ms + 50*ms
	want := lastLoaded + defFresh + 1 + defDwell
	if sw := res.switches[0]; sw.to != 1 || sw.at != want {
		t.Fatalf("switch %+v, want to 1 at %v (protection ended exactly when A turned stale)", sw, want)
	}
	if fa := res.final[0]; fa.N != 0 || !fa.LoadedAt.Equal(simEpoch.Add(lastLoaded)) {
		t.Fatalf("A's final summary %+v", fa)
	}
}

// TestSelectorWake: Verdict.Wake is the earliest of the dwell end, the
// cooldown end and the next ageing change, so the actor needs no other timer.
func TestSelectorWake(t *testing.T) {
	p := defaultSelectorParams()
	now := simEpoch.Add(time.Hour)
	sel := NewSelector(p)
	// No challenger: wake when the oldest fresh evidence ages.
	s := []Summary{
		{Seen: true, N: 4, Mean: 30 * ms, At: now.Add(-9 * time.Second)},
		{Seen: true, N: 4, Mean: 31 * ms, At: now.Add(-2 * time.Second)},
	}
	if v := sel.Evaluate(now, 0, s, nil); v.Switch || !v.Wake.Equal(now.Add(time.Second+1)) {
		t.Fatalf("ageing wake %+v, want %v", v, now.Add(time.Second+1))
	}
	// Dwell end earlier than any ageing.
	s[0].At = now
	s[1] = Summary{Seen: true, N: 4, Mean: 10 * ms, At: now}
	if v := sel.Evaluate(now, 0, s, nil); v.Switch || !v.Wake.Equal(now.Add(p.Dwell)) {
		t.Fatalf("dwell wake %+v", v)
	}
	// An active index out of range never switches.
	if v := sel.Evaluate(now, -1, s, nil); v.Switch {
		t.Fatalf("no active: %+v", v)
	}
	if v := sel.Evaluate(now, 5, s, nil); v.Switch {
		t.Fatalf("active out of range: %+v", v)
	}
	// No summaries at all: nothing to do, never wake.
	if v := sel.Evaluate(now, 0, nil, nil); v.Switch || !v.Wake.IsZero() {
		t.Fatalf("empty: %+v", v)
	}
}
