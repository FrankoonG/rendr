package sched

import (
	"math"
	"testing"
	"time"
)

// TestCapacityDuplex (M3 estimator amendment): the reverse-path allowance
// is min(revRate, rate)·rev on top of plan §4's 2·rate·(minRTT + PingBusy +
// 50 ms), clamped like Capacity; it adds nothing for a non-positive or NaN
// rev, revRate or rate, and Capacity is CapacityDuplex without it.
func TestCapacityDuplex(t *testing.T) {
	const ms = time.Millisecond
	const floor, ceil = 128 << 10, 8 << 20
	const rate = 4 << 20 // 4 MiB/s: 2·rate·120 ms = 1,006,632.96 bytes
	base := Capacity(rate, 20*ms, 50*ms, floor, ceil)
	if base != 1006632 {
		t.Fatalf("premise: Capacity = %d, want 1006632", base)
	}
	for _, tc := range []struct {
		name    string
		rate    float64
		revRate float64
		rev     time.Duration
		want    int64
	}{
		{"300 ms at the rate", rate, rate, 300 * ms, 2264924},         // 1,006,632.96 + 1,258,291.2
		{"revRate above the rate", rate, 2 * rate, 300 * ms, 2264924}, // bounded by the rate
		{"revRate a quarter", rate, rate / 4, 300 * ms, 1321205},      // + 314,572.8
		{"no reverse queue", rate, rate, 0, base},
		{"negative rev", rate, rate, -time.Second, base},
		{"no delivered rate", rate, 0, 300 * ms, base},
		{"NaN delivered rate", rate, math.NaN(), 300 * ms, base},
		{"NaN rate", math.NaN(), rate, 300 * ms, floor},
		{"zero rate", 0, rate, 300 * ms, floor},
		{"huge rev", rate, rate, math.MaxInt64, ceil},
		{"infinite rates", math.Inf(1), math.Inf(1), ms, ceil},
	} {
		if got := CapacityDuplex(tc.rate, 20*ms, 50*ms, tc.revRate, tc.rev, floor, ceil); got != tc.want {
			t.Errorf("%s: CapacityDuplex = %d, want %d", tc.name, got, tc.want)
		}
	}
	// Capacity is CapacityDuplex without the allowance, for every input of
	// its own table's shape.
	for _, r := range []float64{0, 1, 1 << 20, 1e9, math.Inf(1), math.NaN()} {
		for _, m := range []time.Duration{0, ms, 100 * ms, math.MaxInt64} {
			if a, b := Capacity(r, m, 50*ms, floor, ceil), CapacityDuplex(r, m, 50*ms, 0, 0, floor, ceil); a != b {
				t.Errorf("rate %g minRTT %v: Capacity %d ≠ CapacityDuplex %d", r, m, a, b)
			}
		}
	}
}
