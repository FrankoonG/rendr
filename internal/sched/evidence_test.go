package sched

import (
	"testing"
	"time"
)

const ms = time.Millisecond

// addN adds n samples of rtt, one every step after *at, and fails the test
// on any rejection.
func addN(t *testing.T, a *Aggregator, at *time.Time, n int, step, rtt time.Duration, loaded bool) {
	t.Helper()
	for i := 0; i < n; i++ {
		*at = at.Add(step)
		if !a.Add(*at, rtt, loaded) {
			t.Fatalf("sample %d (%v, loaded=%v) rejected", i, rtt, loaded)
		}
	}
}

func checkCounts(t *testing.T, a *Aggregator, unloaded, loaded, shifts uint64) {
	t.Helper()
	u, l, s := a.Counts()
	if u != unloaded || l != loaded || s != shifts {
		t.Fatalf("Counts() = (%d, %d, %d), want (%d, %d, %d)", u, l, s, unloaded, loaded, shifts)
	}
}

// TestAggregatorExcludesLoaded_L28: a sample taken while this Peer's own
// traffic loaded the path (§8) never enters the window, never shifts it and
// only refreshes LoadedAt, so the path keeps its pre-load value (Held).
func TestAggregatorExcludesLoaded_L28(t *testing.T) {
	a := NewAggregator(DefaultAggParams())
	at := simEpoch
	addN(t, &a, &at, 10, 2*time.Second, 20*ms, false)
	before := a.Summary()
	if before.N != 10 || before.Mean != 20*ms || !before.At.Equal(at) || !before.LoadedAt.IsZero() {
		t.Fatalf("after 10 unloaded samples: %+v", before)
	}

	// Stimulus: 40 loaded samples at 300 ms, the self-induced queueing of a
	// bulk transfer: 280 ms above the window, far beyond 3σ.
	addN(t, &a, &at, 40, 2*time.Second, 300*ms, true)
	s := a.Summary()
	if s.N != before.N || s.Mean != before.Mean || !s.At.Equal(before.At) {
		t.Fatalf("loaded samples changed the window: before %+v, after %+v", before, s)
	}
	if !s.Seen || !s.LoadedAt.Equal(at) {
		t.Fatalf("LoadedAt = %v, want %v (Seen=%v)", s.LoadedAt, at, s.Seen)
	}
	checkCounts(t, &a, 10, 40, 0)
	// The last unloaded sample is 80 s old: the path is Held at its
	// pre-load value, not Fresh at 300 ms and not Stale.
	if ev := Classify(s, at, defFresh); ev != (Evidence{State: EvHeld, RTT: 20 * ms}) {
		t.Fatalf("Classify = %+v, want held 20ms", ev)
	}

	// A loaded sample between two deviating unloaded samples does not count
	// toward the level-shift run: the newest two *unloaded* samples decide.
	addN(t, &a, &at, 1, 2*time.Second, 300*ms, false)
	addN(t, &a, &at, 1, 2*time.Second, 20*ms, true)
	if s := a.Summary(); s.N != 11 {
		t.Fatalf("one deviating unloaded sample shifted the window: %+v", s)
	}
	addN(t, &a, &at, 1, 2*time.Second, 300*ms, false)
	if s := a.Summary(); s.N != 2 || s.Mean != 300*ms {
		t.Fatalf("two deviating unloaded samples did not shift the window: %+v", s)
	}
	checkCounts(t, &a, 12, 41, 1)

	// Control (guard disabled): the same 40 samples unloaded move the
	// evidence to 300 ms, proving the loaded flag is what kept it at 20 ms.
	b := NewAggregator(DefaultAggParams())
	bt := simEpoch
	addN(t, &b, &bt, 10, 2*time.Second, 20*ms, false)
	addN(t, &b, &bt, 40, 2*time.Second, 300*ms, false)
	if s := b.Summary(); s.Mean != 300*ms || s.N != 32 {
		t.Fatalf("control: %+v, want mean 300ms over a full window", s)
	}
	checkCounts(t, &b, 50, 0, 1)
	if ev := Classify(b.Summary(), bt, defFresh); ev != (Evidence{State: EvFresh, RTT: 300 * ms}) {
		t.Fatalf("control Classify = %+v", ev)
	}
}

// TestAggregatorRejectsUntimedSamples_L28: samples without a timestamp, with
// a non-positive RTT or older than the newest accepted sample are refused
// and change nothing; an equal timestamp is accepted.
func TestAggregatorRejectsUntimedSamples_L28(t *testing.T) {
	a := NewAggregator(DefaultAggParams())
	at := simEpoch.Add(time.Minute)
	if !a.Add(at, 25*ms, false) {
		t.Fatal("first sample rejected")
	}
	want := a.Summary()
	for _, tc := range []struct {
		name   string
		at     time.Time
		rtt    time.Duration
		loaded bool
	}{
		{"zero time", time.Time{}, 25 * ms, false},
		{"zero time loaded", time.Time{}, 25 * ms, true},
		{"zero rtt", at.Add(time.Second), 0, false},
		{"negative rtt", at.Add(time.Second), -ms, false},
		{"negative rtt loaded", at.Add(time.Second), -ms, true},
		{"older than newest", at.Add(-time.Nanosecond), 25 * ms, false},
		{"older than newest loaded", at.Add(-time.Second), 25 * ms, true},
	} {
		if a.Add(tc.at, tc.rtt, tc.loaded) {
			t.Errorf("%s: accepted", tc.name)
		}
	}
	if got := a.Summary(); got != want {
		t.Fatalf("rejected samples changed the summary: %+v, want %+v", got, want)
	}
	checkCounts(t, &a, 1, 0, 0)
	// The order check covers loaded and unloaded samples alike.
	if !a.Add(at.Add(time.Second), 25*ms, true) {
		t.Fatal("newer loaded sample rejected")
	}
	if a.Add(at.Add(time.Second-1), 25*ms, false) {
		t.Fatal("unloaded sample older than a loaded one accepted")
	}
	if !a.Add(at.Add(time.Second), 35*ms, false) {
		t.Fatal("sample with the newest timestamp rejected")
	}
	checkCounts(t, &a, 2, 1, 0)
}

// TestAggregatorWindowAndReset: the window averages the newest Window
// unloaded samples; Reset (a new probe incarnation) starts Unknown but keeps
// the counters.
func TestAggregatorWindowAndReset(t *testing.T) {
	a := NewAggregator(DefaultAggParams())
	at := simEpoch
	addN(t, &a, &at, 8, 2*time.Second, 34*ms, false) // 4 ms above: no level shift
	addN(t, &a, &at, 31, 2*time.Second, 30*ms, false)
	if s := a.Summary(); s.N != 32 || s.Mean != 30125*time.Microsecond {
		t.Fatalf("window = %+v, want N 32 mean 30.125ms (one 34 ms sample left)", s)
	}
	addN(t, &a, &at, 1, 2*time.Second, 30*ms, false)
	if s := a.Summary(); s.N != 32 || s.Mean != 30*ms {
		t.Fatalf("window = %+v, want the oldest samples dropped", s)
	}
	checkCounts(t, &a, 40, 0, 0)

	a.Reset()
	s := a.Summary()
	if s != (Summary{}) {
		t.Fatalf("Summary after Reset = %+v, want zero", s)
	}
	if ev := Classify(s, at, defFresh); ev.State != EvUnknown {
		t.Fatalf("Classify after Reset = %v", ev.State)
	}
	checkCounts(t, &a, 40, 0, 0)
	// A new incarnation is ordered on its own: its first sample is accepted
	// even if the previous incarnation's clock ran ahead.
	if !a.Add(at.Add(-time.Second), 12*ms, false) {
		t.Fatal("first sample after Reset rejected")
	}
	if s := a.Summary(); s.N != 1 || s.Mean != 12*ms {
		t.Fatalf("after Reset and one sample: %+v", s)
	}

	// Window is a parameter (G9 knob): a window of 4 averages 4 samples.
	w := NewAggregator(AggParams{Window: 4})
	wt := simEpoch
	addN(t, &w, &wt, 4, time.Second, 10*ms, false)
	addN(t, &w, &wt, 2, time.Second, 14*ms, false)
	if s := w.Summary(); s.N != 4 || s.Mean != 12*ms {
		t.Fatalf("window 4 = %+v, want mean 12ms", s)
	}
}

// TestAggregatorLevelShift_L29: plan §4 level shift — with at least
// MinEarlier earlier samples, the newest ShiftRun samples deviating in the
// same direction by more than SigmaK·max(σ, SigmaFloor) restart the window
// from those samples.
func TestAggregatorLevelShift_L29(t *testing.T) {
	t.Run("floor", func(t *testing.T) {
		// Constant earlier samples: σ = 0, the 2 ms floor gives 6 ms.
		a := NewAggregator(DefaultAggParams())
		at := simEpoch
		addN(t, &a, &at, 30, time.Second, 30*ms, false)
		addN(t, &a, &at, 1, time.Second, 37*ms, false)
		if s := a.Summary(); s.N != 31 {
			t.Fatalf("one deviating sample shifted: %+v", s)
		}
		addN(t, &a, &at, 1, time.Second, 37*ms, false)
		if s := a.Summary(); s.N != 2 || s.Mean != 37*ms {
			t.Fatalf("no shift after two deviating samples: %+v", s)
		}
		checkCounts(t, &a, 32, 0, 1)
		b := NewAggregator(DefaultAggParams())
		bt := simEpoch
		addN(t, &b, &bt, 30, time.Second, 30*ms, false)
		addN(t, &b, &bt, 2, time.Second, 36*ms, false) // exactly 6 ms: not more than the threshold
		if s := b.Summary(); s.N != 32 {
			t.Fatalf("deviation equal to the threshold shifted: %+v", s)
		}
	})
	t.Run("sigma", func(t *testing.T) {
		// Earlier samples alternate 20/40 ms: σ ≈ 10 ms, so 3σ ≈ 30 ms and a
		// +28 ms pair is ordinary noise while a +35 ms pair is a shift.
		mk := func(newest time.Duration) Summary {
			a := NewAggregator(DefaultAggParams())
			at := simEpoch
			for i := 0; i < 30; i++ {
				addN(t, &a, &at, 1, time.Second, time.Duration(20+20*(i%2))*ms, false)
			}
			addN(t, &a, &at, 2, time.Second, newest, false)
			return a.Summary()
		}
		if s := mk(58 * ms); s.N != 32 {
			t.Fatalf("+28 ms within 3σ shifted: %+v", s)
		}
		if s := mk(65 * ms); s.N != 2 || s.Mean != 65*ms {
			t.Fatalf("+35 ms beyond 3σ did not shift: %+v", s)
		}
	})
	t.Run("opposite directions", func(t *testing.T) {
		a := NewAggregator(DefaultAggParams())
		at := simEpoch
		addN(t, &a, &at, 10, time.Second, 50*ms, false)
		addN(t, &a, &at, 1, time.Second, 90*ms, false)
		addN(t, &a, &at, 1, time.Second, 10*ms, false)
		if s := a.Summary(); s.N != 12 {
			t.Fatalf("deviations in opposite directions shifted: %+v", s)
		}
	})
	t.Run("downward", func(t *testing.T) {
		// G9 phase 3: a path recovering from 90 ms to 10 ms.
		a := NewAggregator(DefaultAggParams())
		at := simEpoch
		addN(t, &a, &at, 32, time.Second, 90*ms, false)
		addN(t, &a, &at, 2, time.Second, 10*ms, false)
		if s := a.Summary(); s.N != 2 || s.Mean != 10*ms {
			t.Fatalf("downward step not detected: %+v", s)
		}
	})
	t.Run("min earlier", func(t *testing.T) {
		a := NewAggregator(DefaultAggParams())
		at := simEpoch
		addN(t, &a, &at, 2, time.Second, 30*ms, false)
		addN(t, &a, &at, 2, time.Second, 90*ms, false)
		if s := a.Summary(); s.N != 4 || s.Mean != 60*ms {
			t.Fatalf("shift declared with only 2 earlier samples: %+v", s)
		}
		b := NewAggregator(DefaultAggParams())
		bt := simEpoch
		addN(t, &b, &bt, 3, time.Second, 30*ms, false)
		addN(t, &b, &bt, 2, time.Second, 90*ms, false)
		if s := b.Summary(); s.N != 2 || s.Mean != 90*ms {
			t.Fatalf("no shift with 3 earlier samples: %+v", s)
		}
	})
	t.Run("shift run parameter", func(t *testing.T) {
		a := NewAggregator(AggParams{ShiftRun: 3})
		at := simEpoch
		addN(t, &a, &at, 10, time.Second, 30*ms, false)
		addN(t, &a, &at, 2, time.Second, 80*ms, false)
		if s := a.Summary(); s.N != 12 {
			t.Fatalf("ShiftRun 3 shifted after 2 samples: %+v", s)
		}
		addN(t, &a, &at, 1, time.Second, 80*ms, false)
		if s := a.Summary(); s.N != 3 || s.Mean != 80*ms {
			t.Fatalf("ShiftRun 3 did not shift after 3 samples: %+v", s)
		}
	})
}

// TestAggParamsDefaults: zero fields keep the plan §4 defaults (the
// testhooks convention) and Window is bounded by MaxAggWindow.
func TestAggParamsDefaults(t *testing.T) {
	if got, want := (AggParams{}).normalized(), DefaultAggParams(); got != want {
		t.Fatalf("zero params normalize to %+v, want %+v", got, want)
	}
	if got := (AggParams{Window: 1000}).normalized().Window; got != MaxAggWindow {
		t.Fatalf("Window 1000 normalizes to %d", got)
	}
	// A zero-value Aggregator works like a default one.
	var a Aggregator
	at := simEpoch
	addN(t, &a, &at, 40, time.Second, 10*ms, false)
	if s := a.Summary(); s.N != 32 || s.Mean != 10*ms {
		t.Fatalf("zero-value aggregator: %+v", s)
	}
	big := NewAggregator(AggParams{Window: MaxAggWindow + 5})
	bt := simEpoch
	addN(t, &big, &bt, 100, time.Second, 10*ms, false)
	if s := big.Summary(); s.N != MaxAggWindow {
		t.Fatalf("N = %d, want %d", s.N, MaxAggWindow)
	}
}

// TestClassifyHeld_L28: Fresh needs an unloaded value within Fresh; a path
// with only recent loaded samples is Held (with its earlier unloaded value,
// or protected without a value); evidence without a positive value never
// reads as a measurement; summaries age without republication.
func TestClassifyHeld_L28(t *testing.T) {
	now := simEpoch.Add(time.Hour)
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	for _, tc := range []struct {
		name string
		s    Summary
		want Evidence
	}{
		{"unknown", Summary{}, Evidence{State: EvUnknown}},
		{"unknown ignores fields", Summary{N: 3, Mean: 9 * ms, At: ago(time.Second)}, Evidence{State: EvUnknown}},
		{"fresh", Summary{Seen: true, N: 5, Mean: 20 * ms, At: ago(5 * time.Second)}, Evidence{EvFresh, 20 * ms}},
		{"fresh boundary inclusive", Summary{Seen: true, N: 5, Mean: 20 * ms, At: ago(defFresh)}, Evidence{EvFresh, 20 * ms}},
		{"fresh beats newer loaded", Summary{Seen: true, N: 5, Mean: 20 * ms, At: ago(time.Second), LoadedAt: now}, Evidence{EvFresh, 20 * ms}},
		{"held with value", Summary{Seen: true, N: 5, Mean: 20 * ms, At: ago(time.Minute), LoadedAt: ago(time.Second)}, Evidence{EvHeld, 20 * ms}},
		{"held boundary inclusive", Summary{Seen: true, N: 5, Mean: 20 * ms, At: ago(defFresh + 1), LoadedAt: ago(defFresh)}, Evidence{EvHeld, 20 * ms}},
		{"held without value", Summary{Seen: true, LoadedAt: ago(time.Second)}, Evidence{State: EvHeld}},
		{"stale", Summary{Seen: true, N: 5, Mean: 20 * ms, At: ago(defFresh + 1)}, Evidence{State: EvStale}},
		{"stale loaded too", Summary{Seen: true, N: 5, Mean: 20 * ms, At: ago(time.Minute), LoadedAt: ago(defFresh + 1)}, Evidence{State: EvStale}},
		{"stale 1ns value hidden", Summary{Seen: true, N: 3, Mean: 1, At: ago(time.Minute)}, Evidence{State: EvStale}},
		{"zero samples", Summary{Seen: true, N: 0, At: ago(time.Second)}, Evidence{State: EvStale}},
		{"zero mean", Summary{Seen: true, N: 4, Mean: 0, At: ago(time.Second)}, Evidence{State: EvStale}},
		{"zero samples while loaded", Summary{Seen: true, N: 0, Mean: 7 * ms, At: ago(time.Second), LoadedAt: ago(time.Second)}, Evidence{State: EvHeld}},
	} {
		if got := Classify(tc.s, now, defFresh); got != tc.want {
			t.Errorf("%s: Classify = %+v, want %+v", tc.name, got, tc.want)
		}
	}

	// Ageing without republication (D25): one summary seen at later times
	// goes Fresh → Held → Stale, and NextChange names each transition.
	s := Summary{Seen: true, N: 8, Mean: 25 * ms, At: ago(time.Second), LoadedAt: ago(500 * ms)}
	t1 := NextChange(s, now, defFresh)
	if want := s.At.Add(defFresh + 1); !t1.Equal(want) {
		t.Fatalf("NextChange(fresh) = %v, want %v", t1, want)
	}
	if ev := Classify(s, t1.Add(-1), defFresh); ev.State != EvFresh {
		t.Fatalf("just before the change: %v", ev.State)
	}
	if ev := Classify(s, t1, defFresh); ev != (Evidence{EvHeld, 25 * ms}) {
		t.Fatalf("at the change: %+v, want held", ev)
	}
	t2 := NextChange(s, t1, defFresh)
	if want := s.LoadedAt.Add(defFresh + 1); !t2.Equal(want) {
		t.Fatalf("NextChange(held) = %v, want %v", t2, want)
	}
	if ev := Classify(s, t2, defFresh); ev.State != EvStale {
		t.Fatalf("at the second change: %v, want stale", ev.State)
	}
	if t3 := NextChange(s, t2, defFresh); !t3.IsZero() {
		t.Fatalf("NextChange(stale) = %v, want never", t3)
	}
	// A loaded sample older than the unloaded one is no breakpoint: Fresh
	// goes straight to Stale.
	s2 := Summary{Seen: true, N: 8, Mean: 25 * ms, At: ago(time.Second), LoadedAt: ago(3 * time.Second)}
	if c := NextChange(s2, now, defFresh); !c.Equal(s2.At.Add(defFresh+1)) || Classify(s2, c, defFresh).State != EvStale {
		t.Fatalf("fresh→stale change at %v (%v)", c, Classify(s2, c, defFresh).State)
	}
	// Held without a value ages to Stale; Unknown never changes.
	s3 := Summary{Seen: true, LoadedAt: ago(time.Second)}
	if c := NextChange(s3, now, defFresh); !c.Equal(s3.LoadedAt.Add(defFresh + 1)) {
		t.Fatalf("held-without-value change at %v", c)
	}
	if c := NextChange(Summary{}, now, defFresh); !c.IsZero() {
		t.Fatalf("unknown changes at %v", c)
	}
}
