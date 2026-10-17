package l4

import (
	"sync"
	"testing"
	"time"
)

// TestFlowClassRules_L72 (M6-D9, R1-7, R1-10, R1-23; W1.3): the class
// tracker on its own, with explicit instants. promoteOnReply makes a flow
// a stream at the first datagram in the second direction (a seed counts
// as a direction seen); promoteActive at the first datagram of an activity
// period that has seen both directions and lasted 2 s, a gap of 2 s or
// more starting a new period. Each tracker reports the promotion exactly
// once, keeps the rule it read at its first call, and reports nothing
// after the promotion.
func TestFlowClassRules_L72(t *testing.T) {
	type step struct {
		at  time.Duration
		dir flowDir
	}
	out := func(at time.Duration) step { return step{at, towardSession} }
	in := func(at time.Duration) step { return step{at, towardLocal} }
	const none = -1
	rows := []struct {
		name  string
		rule  promoteMode
		seed  *step
		steps []step
		at    int // the index of the step that promotes, or none
	}{
		{"reply: one way never", promoteOnReply, nil, []step{out(0), out(time.Second), out(time.Hour)}, none},
		{"reply: the first reply", promoteOnReply, nil, []step{out(0), out(time.Second), in(2 * time.Second), in(3 * time.Second)}, 2},
		{"reply: after any gap", promoteOnReply, nil, []step{out(0), in(time.Hour)}, 1},
		{"reply: the seed is the first direction", promoteOnReply, &step{0, towardLocal}, []step{out(time.Millisecond)}, 0},
		{"reply: a seed of the reply direction", promoteOnReply, &step{0, towardSession}, []step{out(time.Second), in(2 * time.Second)}, 1},
		{"active: one exchange stays short", promoteActive, nil, []step{out(0), in(10 * time.Millisecond)}, none},
		{"active: both ways for 2 s", promoteActive, nil, []step{out(0), in(500 * time.Millisecond), out(time.Second), in(1500 * time.Millisecond), out(2 * time.Second), in(2500 * time.Millisecond)}, 4},
		{"active: one way for 2 s, then the reply", promoteActive, nil, []step{out(0), out(time.Second), out(1999 * time.Millisecond), in(2100 * time.Millisecond)}, 3},
		{"active: a reply after a 3-s gap is a new period", promoteActive, nil, []step{out(0), in(3 * time.Second), out(4 * time.Second), in(4500 * time.Millisecond)}, none},
		{"active: a gap just below 2 s keeps the period", promoteActive, nil, []step{out(0), in(1999 * time.Millisecond), out(3998 * time.Millisecond)}, 2},
		{"active: a gap of exactly 2 s starts a new one", promoteActive, nil, []step{out(0), in(time.Second), out(3 * time.Second), in(4 * time.Second)}, none},
		{"active: a reused source after a pause", promoteActive, nil, []step{out(0), in(5 * time.Millisecond), out(10 * time.Second), in(10*time.Second + 5*time.Millisecond), out(20 * time.Second), in(20*time.Second + 5*time.Millisecond)}, none},
		{"active: the seed opens the period", promoteActive, &step{0, towardLocal}, []step{out(time.Second), out(2 * time.Second)}, 1},
		{"active: instants out of order", promoteActive, nil, []step{out(0), in(1500 * time.Millisecond), out(1400 * time.Millisecond), in(2 * time.Second)}, 3},
		{"active: the latest instant only moves forward", promoteActive, nil, []step{out(0), out(time.Second), out(2500 * time.Millisecond), in(500 * time.Millisecond), out(3 * time.Second)}, 4},
	}
	t0 := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			pfRule(t, r.rule)
			var c flowClass
			if r.seed != nil && c.seed(t0.Add(r.seed.at), r.seed.dir) {
				t.Fatal("the seed alone promoted")
			}
			got := none
			for i, s := range r.steps {
				var p bool
				if s.dir == towardSession {
					p = c.out(t0.Add(s.at))
				} else {
					p = c.in(t0.Add(s.at))
				}
				if p {
					if got != none {
						t.Fatalf("promoted again at step %d (first at %d)", i, got)
					}
					got = i
				}
				if c.isStream() != (got != none) {
					t.Fatalf("step %d: isStream %v, promoted at %d", i, c.isStream(), got)
				}
			}
			if got != r.at {
				t.Fatalf("promoted at step %d, want %d", got, r.at)
			}
		})
	}

	t.Run("the rule is read once", func(t *testing.T) {
		pfRule(t, promoteActive)
		var c flowClass
		c.out(t0)
		ruleForTest.Store(uint32(promoteOnReply))
		if c.in(t0.Add(time.Millisecond)) {
			t.Fatal("the tracker switched rules after its first call")
		}
	})
	t.Run("the constant", func(t *testing.T) {
		// The delegate decision of 2026-10-17 (O-1 (a)): the Linux-NAT rule.
		if promoteRule != promoteActive || activeRule() != promoteActive || streamAfter != 2*time.Second {
			t.Fatalf("promoteRule %v, activeRule %v, streamAfter %v", promoteRule, activeRule(), streamAfter)
		}
	})
}

// TestFlowClassConcurrentOnce: the two movers of a flow call the tracker
// at once; the promotion is reported exactly once (run under -race too).
func TestFlowClassConcurrentOnce(t *testing.T) {
	for _, rule := range []promoteMode{promoteOnReply, promoteActive} {
		pfRule(t, rule)
		for range 200 {
			var c flowClass
			t0 := time.Now()
			var wg sync.WaitGroup
			var hits [2]int
			for g := range 2 {
				wg.Go(func() {
					for i := range 50 {
						at := t0.Add(time.Duration(i) * 100 * time.Millisecond)
						var p bool
						if g == 0 {
							p = c.out(at)
						} else {
							p = c.in(at)
						}
						if p {
							hits[g]++
						}
					}
				})
			}
			wg.Wait()
			if hits[0]+hits[1] != 1 || !c.isStream() {
				t.Fatalf("rule %d: promotions %v, stream %v", rule, hits, c.isStream())
			}
		}
	}
}

// TestFlowIdleLimits (M6-D8, R1-19): the classes' values for
// SetIdleTimeout (0: off).
func TestFlowIdleLimits(t *testing.T) {
	const s, m, h = time.Second, time.Minute, time.Hour
	for _, r := range []struct {
		in            FlowIdle
		short, stream time.Duration
	}{
		{FlowIdle{}, DefaultFlowShortIdle, DefaultFlowIdle},
		{FlowIdle{Short: 10 * s, Stream: 10 * s}, 10 * s, 10 * s},
		{FlowIdle{Short: s, Stream: 5 * s}, 10 * s, 10 * s},
		{FlowIdle{Short: 5 * m}, DefaultFlowIdle, DefaultFlowIdle},
		{FlowIdle{Short: 5 * m, Stream: 2 * m}, 2 * m, 2 * m},
		{FlowIdle{Short: 48 * h, Stream: 48 * h}, 24 * h, 24 * h},
		{FlowIdle{Stream: -1}, DefaultFlowShortIdle, 0},
		{FlowIdle{Short: 5 * m, Stream: -1}, 5 * m, 0},
		{FlowIdle{Short: -1}, 0, 0},
		{FlowIdle{Short: -1, Stream: 5 * m}, 0, 0},
	} {
		if short, stream := r.in.limits(); short != r.short || stream != r.stream {
			t.Errorf("%+v.limits() = %v, %v; want %v, %v", r.in, short, stream, r.short, r.stream)
		}
	}
}

// TestNoiseRun (M6-D15, M6-D25): a run of noise errors is read past for
// its first 64, then backs off 5 ms doubling to 100 ms; a datagram ends
// the run.
func TestNoiseRun(t *testing.T) {
	var r noiseRun
	want := func(i int) time.Duration {
		switch {
		case i <= noiseRunFree:
			return 0
		case i <= noiseRunFree+5:
			return noiseBackoffMin << (i - noiseRunFree - 1)
		}
		return noiseBackoffMax
	}
	for range 2 {
		for i := 1; i <= 200; i++ {
			if d := r.fail(); d != min(want(i), noiseBackoffMax) {
				t.Fatalf("error %d of a run: wait %v, want %v", i, d, min(want(i), noiseBackoffMax))
			}
		}
		r.ok()
	}
}
