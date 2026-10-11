package sched

import (
	"math"
	"testing"
	"time"
)

// TestCapacityDuplex (M3 estimator amendment, M5-D63): the duplex
// allowance is min(revRate, rate)·rev + min(rate·lag, batch) on top of
// plan §4's 2·rate·(minRTT + PingBusy + 50 ms), clamped like Capacity. The
// reverse-queue term is priced at the delivered rate bounded by the
// estimate; the write-lag term at the estimate itself, at most one batch;
// the two add up. A non-positive or NaN rate or revRate adds no allowance;
// a non-positive rev, lag or batch adds nothing for its own term; and
// Capacity is CapacityDuplex without an allowance.
func TestCapacityDuplex(t *testing.T) {
	const ms = time.Millisecond
	const floor, ceil = 128 << 10, 8 << 20
	const batch = 256 << 10
	const rate = 4 << 20 // 4 MiB/s: 2·rate·120 ms = 1,006,632.96 bytes
	base := Capacity(rate, 20*ms, 50*ms, floor, ceil)
	if base != 1006632 {
		t.Fatalf("premise: Capacity = %d, want 1006632", base)
	}
	const rate2 = 2 << 20 // 2 MiB/s: 2·rate·120 ms = 503,316.48 bytes
	base2 := Capacity(rate2, 20*ms, 50*ms, floor, ceil)
	if base2 != 503316 {
		t.Fatalf("premise: Capacity at 2 MiB/s = %d, want 503316", base2)
	}
	for _, tc := range []struct {
		name     string
		rate     float64
		revRate  float64
		rev, lag time.Duration
		batch    int64
		want     int64
	}{
		{"300 ms at the rate", rate, rate, 300 * ms, 0, batch, 2264924},         // 1,006,632.96 + 1,258,291.2
		{"revRate above the rate", rate, 2 * rate, 300 * ms, 0, batch, 2264924}, // bounded by the rate
		{"revRate a quarter", rate, rate / 4, 300 * ms, 0, batch, 1321205},      // + 314,572.8
		{"no reverse queue", rate, rate, 0, 0, batch, base},
		{"negative rev", rate, rate, -time.Second, 0, batch, base},
		{"no delivered rate", rate, 0, 300 * ms, 0, batch, base},
		{"NaN delivered rate", rate, math.NaN(), 300 * ms, 0, batch, base},
		{"NaN rate", math.NaN(), rate, 300 * ms, 0, batch, floor},
		{"zero rate", 0, rate, 300 * ms, 0, batch, floor},
		{"huge rev", rate, rate, math.MaxInt64, 0, batch, ceil},
		{"infinite rates", math.Inf(1), math.Inf(1), ms, 0, batch, ceil},

		// The write-lag term: min(rate·lag, batch), priced at the estimate.
		{"lag 100 ms", rate2, rate2, 0, 100 * ms, batch, 713031},                        // 503,316.48 + 209,715.2
		{"lag 100 ms, revRate a quarter", rate2, rate2 / 4, 0, 100 * ms, batch, 713031}, // the estimate prices it
		{"lag 100 ms, revRate above the rate", rate2, 2 * rate2, 0, 100 * ms, batch, 713031},
		{"lag 200 ms: one batch", rate2, rate2, 0, 200 * ms, batch, base2 + batch}, // 419,430.4 > 262,144
		{"lag without a delivered rate", rate2, 0, 0, 100 * ms, batch, base2},
		{"lag with a NaN delivered rate", rate2, math.NaN(), 0, 100 * ms, batch, base2},
		{"lag with a zero rate", 0, rate2, 0, 100 * ms, batch, floor},
		{"lag with a NaN rate", math.NaN(), rate2, 0, 100 * ms, batch, floor},
		{"zero lag", rate2, rate2, 0, 0, batch, base2},
		{"negative lag", rate2, rate2, 0, -time.Second, batch, base2},
		{"lag without a batch", rate2, rate2, 0, 100 * ms, 0, base2},
		{"lag with a negative batch", rate2, rate2, 0, 100 * ms, -1, base2},
		{"huge lag", rate2, rate2, 0, math.MaxInt64, batch, base2 + batch},
		{"lag at infinite rates", math.Inf(1), math.Inf(1), 0, ms, batch, ceil},
		// Both terms add up: 503,316.48 + 629,145.6 + 209,715.2.
		{"rev 300 ms and lag 100 ms", rate2, rate2, 300 * ms, 100 * ms, batch, 1342177},
		{"rev and lag beyond the window", rate, rate, 2 * time.Second, time.Hour, 8 << 20, ceil},
	} {
		if got := CapacityDuplex(tc.rate, 20*ms, 50*ms, tc.revRate, tc.rev, tc.lag, tc.batch, floor, ceil); got != tc.want {
			t.Errorf("%s: CapacityDuplex = %d, want %d", tc.name, got, tc.want)
		}
	}
	// A lag of an hour at 1 GB/s adds exactly one batch (no Duration
	// conversion, so no overflow; the window here is far above the cap).
	const big = 1 << 40
	b9 := Capacity(1e9, 20*ms, 50*ms, floor, big)
	if b9 != 240000000 {
		t.Fatalf("premise: Capacity at 1 GB/s = %d, want 240000000", b9)
	}
	if got := CapacityDuplex(1e9, 20*ms, 50*ms, 1e9, 0, time.Hour, batch, floor, big); got != b9+batch {
		t.Errorf("lag 1 h at 1 GB/s: CapacityDuplex = %d, want %d (one batch more)", got, b9+batch)
	}
	// Capacity is CapacityDuplex without the allowance, for every input of
	// its own table's shape.
	for _, r := range []float64{0, 1, 1 << 20, 1e9, math.Inf(1), math.NaN()} {
		for _, m := range []time.Duration{0, ms, 100 * ms, math.MaxInt64} {
			if a, b := Capacity(r, m, 50*ms, floor, ceil), CapacityDuplex(r, m, 50*ms, 0, 0, 0, 0, floor, ceil); a != b {
				t.Errorf("rate %g minRTT %v: Capacity %d ≠ CapacityDuplex %d", r, m, a, b)
			}
			if a, b := Capacity(r, m, 50*ms, floor, ceil), CapacityDuplex(r, m, 50*ms, r, 0, 0, batch, floor, ceil); a != b {
				t.Errorf("rate %g minRTT %v: Capacity %d ≠ CapacityDuplex with zero rev and lag %d", r, m, a, b)
			}
		}
	}
}
