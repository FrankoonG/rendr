package sched

import (
	"math"
	"math/rand/v2"
	"slices"
	"testing"
	"time"
)

// TestDeathDeadlineTable_L25: D = clamp(max(DeadMin, 3·srtt +
// inflight/rate), DeadMin, DeadMax) with the default 3 s / 4 s, including
// the lesson's table rows (10 ms idle → 3 s; 1 s with 0.5 s of queued
// bytes → 3.5 s; 2 s → 4 s, the cap).
func TestDeathDeadlineTable_L25(t *testing.T) {
	const dmin, dmax = 3 * time.Second, 4 * time.Second
	for _, tc := range []struct {
		name     string
		srtt     time.Duration
		inflight int64
		rate     float64
		want     time.Duration
	}{
		{"srtt 10ms idle", 10 * ms, 0, 0, 3 * time.Second},
		{"srtt 1s, 0.5s of inflight", time.Second, 500_000, 1e6, 3500 * ms},
		{"srtt 2s capped", 2 * time.Second, 0, 0, 4 * time.Second},
		{"srtt 1.2s", 1200 * ms, 0, 1e6, 3600 * ms},
		{"srtt 900ms floored", 900 * ms, 0, 0, 3 * time.Second},
		{"unknown rate omits the inflight term", 10 * ms, 1 << 30, 0, 3 * time.Second},
		{"NaN rate omits the inflight term", 10 * ms, 1 << 30, math.NaN(), 3 * time.Second},
		{"infinite rate", time.Second, 1 << 30, math.Inf(1), 3 * time.Second},
		{"deep queue: inflight/rate dominates", 50 * ms, 24 << 20, 8 << 20, 3150 * ms},
		{"tiny rate saturates at the cap", 10 * ms, 1 << 40, 1e-9, 4 * time.Second},
		{"unknown srtt", 0, 0, 0, 3 * time.Second},
		{"negative srtt", -time.Second, 0, 0, 3 * time.Second},
		{"negative inflight", time.Second, -1 << 20, 1e3, 3 * time.Second},
	} {
		if got := DeathDeadline(tc.srtt, tc.inflight, tc.rate, dmin, dmax); got != tc.want {
			t.Errorf("%s: DeathDeadline = %v, want %v", tc.name, got, tc.want)
		}
	}
	// Unclamped test timings keep the formula; inverted bounds let the
	// upper bound (DeadMax, the G4 budget) win.
	if got := DeathDeadline(100*ms, 0, 0, 200*ms, 2*time.Second); got != 300*ms {
		t.Errorf("unclamped: %v, want 300ms", got)
	}
	if got := DeathDeadline(10*ms, 0, 0, 5*time.Second, 4*time.Second); got != 4*time.Second {
		t.Errorf("inverted bounds: %v, want the upper bound", got)
	}
	// Monotone in srtt and inflight, always within [DeadMin, DeadMax].
	r := rand.New(rand.NewPCG(25, 25))
	for i := 0; i < 10000; i++ {
		srtt := time.Duration(r.Int64N(int64(3 * time.Second)))
		inf := r.Int64N(64 << 20)
		rate := r.Float64() * 100e6
		d := DeathDeadline(srtt, inf, rate, dmin, dmax)
		if d < dmin || d > dmax {
			t.Fatalf("D(%v, %d, %v) = %v outside the bounds", srtt, inf, rate, d)
		}
		if d2 := DeathDeadline(srtt+ms, inf+1024, rate, dmin, dmax); d2 < d {
			t.Fatalf("not monotone: D(%v, %d) = %v > D(+1ms, +1KiB) = %v", srtt, inf, d, d2)
		}
	}
}

// TestStallWindowTable: one batch write may take clamp(max(WriteStall,
// 2·srtt + batch/rate), WriteStall, DeadMax) (plan §3.6).
func TestStallWindowTable(t *testing.T) {
	const ws, dmax = 2 * time.Second, 4 * time.Second
	for _, tc := range []struct {
		srtt  time.Duration
		batch int
		rate  float64
		want  time.Duration
	}{
		{20 * ms, 256 << 10, 25e6, 2 * time.Second},
		{900 * ms, 256 << 10, 0, 2 * time.Second},
		{1200 * ms, 0, 0, 2400 * ms},
		{500 * ms, 256 << 10, 128 << 10, 3 * time.Second},
		{10 * ms, 1 << 20, 1, 4 * time.Second},
		{3 * time.Second, 0, 0, 4 * time.Second},
	} {
		if got := StallWindow(tc.srtt, tc.batch, tc.rate, ws, dmax); got != tc.want {
			t.Errorf("StallWindow(%v, %d, %v) = %v, want %v", tc.srtt, tc.batch, tc.rate, got, tc.want)
		}
	}
}

// TestCapacityFormula: 2·rate·(minRTT + PingBusy + 50 ms), floor 128 KiB,
// never above the window (plan §4).
func TestCapacityFormula(t *testing.T) {
	const floor, ceil = 128 << 10, 8 << 20
	for _, tc := range []struct {
		name   string
		rate   float64
		minRTT time.Duration
		want   int64
	}{
		{"cold start: the floor", 0, 0, floor},
		{"slow path: the floor", 100e3, 20 * ms, floor},
		{"25 MB/s, 20 ms", 25e6, 20 * ms, 6_000_000},
		{"unknown minRTT counts 50 ms", 10e6, 0, 3_000_000},
		{"fast path: the window", 1e9, 20 * ms, ceil},
		{"NaN rate", math.NaN(), 20 * ms, floor},
		{"infinite rate", math.Inf(1), 20 * ms, ceil},
	} {
		if got := Capacity(tc.rate, tc.minRTT, 50*ms, floor, ceil); got != tc.want {
			t.Errorf("%s: Capacity = %d, want %d", tc.name, got, tc.want)
		}
	}
	// A window below the floor wins: the cap never exceeds the window.
	if got := Capacity(0, 0, 50*ms, floor, 64<<10); got != 64<<10 {
		t.Errorf("window below the floor: %d", got)
	}
}

// TestRescueWait: max(300 ms, 3 × the fastest srtt) (plan §4).
func TestRescueWait(t *testing.T) {
	for _, tc := range []struct{ fastest, want time.Duration }{
		{0, 300 * ms},
		{5 * ms, 300 * ms},
		{100 * ms, 300 * ms},
		{200 * ms, 600 * ms},
		{math.MaxInt64 / 2, math.MaxInt64},
	} {
		if got := RescueWait(tc.fastest, 300*ms); got != tc.want {
			t.Errorf("RescueWait(%v) = %v, want %v", tc.fastest, got, tc.want)
		}
	}
}

// TestAdvertiseWindow: full window up to 75% budget use, proportionally
// shrunk with a 64 KiB floor above it, zero at 100% (plan §3.7).
func TestAdvertiseWindow(t *testing.T) {
	const w, max = 8 << 20, 1 << 30
	for _, tc := range []struct {
		name   string
		window int64
		used   int64
		max    int64
		want   int64
	}{
		{"idle", w, 0, max, w},
		{"75% exactly", w, max / 4 * 3, max, w},
		{"just above 75%", w, max/4*3 + 1, max, w - 1},
		{"87.5%", w, max / 8 * 7, max, w / 2},
		{"99.9% hits the floor", w, max - max/1000, max, 64 << 10},
		{"100%", w, max, max, 0},
		{"over budget", w, max + 1, max, 0},
		{"negative use", w, -5, max, w},
		{"no budget", w, 1 << 40, 0, w},
		{"window below the floor", 32 << 10, max - 1, max, 32 << 10},
		{"zero window", 0, 0, max, 0},
	} {
		if got := AdvertiseWindow(tc.window, tc.used, tc.max); got != tc.want {
			t.Errorf("%s: AdvertiseWindow = %d, want %d", tc.name, got, tc.want)
		}
	}
	// Never above the window, never increasing with use.
	prev := int64(w)
	for used := int64(0); used <= max; used += max / 512 {
		got := AdvertiseWindow(w, used, max)
		if got > prev || got > w || got < 0 {
			t.Fatalf("used %d: %d (previous %d)", used, got, prev)
		}
		prev = got
	}
}

// TestSRTTOrder: lanes by srtt ascending, unknown (0) last, ties by index,
// reusing out without allocating.
func TestSRTTOrder(t *testing.T) {
	srtt := []time.Duration{30 * ms, 0, 10 * ms, 30 * ms, -1, 5 * ms}
	buf := make([]int, 0, 16)
	got := SRTTOrder(srtt, buf)
	if !slices.Equal(got, []int{5, 2, 0, 3, 1, 4}) {
		t.Fatalf("SRTTOrder = %v", got)
	}
	if n := testing.AllocsPerRun(100, func() { SRTTOrder(srtt, buf) }); n != 0 {
		t.Fatalf("SRTTOrder allocates %v times", n)
	}
	if got := SRTTOrder(nil, buf); len(got) != 0 {
		t.Fatalf("SRTTOrder(nil) = %v", got)
	}
}

// TestEpochAndPingIDWrap_L14: SCHED epochs and PING ids are u32 counters
// compared in serial arithmetic (EpochNewer is that order). Counters preset
// next to 2³² keep their order across the wrap, newest-wins application
// still lands on the latest value, and values half the space apart are
// unordered rather than silently misordered.
func TestEpochAndPingIDWrap_L14(t *testing.T) {
	for _, tc := range []struct {
		a, b uint32
		want bool
	}{
		{1, 0, true},
		{0, 1, false},
		{0, 0xFFFFFFFF, true}, // the wrap: 0 follows 2³²−1
		{0xFFFFFFFF, 0, false},
		{5, 5, false},
		{0x7FFFFFFF, 0, true}, // just under half the space ahead
		{0x80000000, 0, false},
		{0, 0x80000000, false},         // exactly half: neither is newer
		{0x7FFFFFEF, 0xFFFFFFF0, true}, // 0xFFFFFFF0 + 0x7FFFFFFF, wrapped
	} {
		if got := EpochNewer(tc.a, tc.b); got != tc.want {
			t.Errorf("EpochNewer(%#x, %#x) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}

	for _, preset := range []uint32{1, 0x7FFFFFF0, 0xFFFFFFF0, 0xFFFFFFFE} { // FirstEpoch / FirstPingID presets
		// Every newly allocated value is newer than all earlier ones in the
		// live range, including across the wrap.
		seq := make([]uint32, 64)
		for i := range seq {
			seq[i] = preset + uint32(i)
		}
		for i := range seq {
			for j := range seq {
				if got := EpochNewer(seq[i], seq[j]); got != (i > j) {
					t.Fatalf("preset %#x: EpochNewer(%#x, %#x) = %v", preset, seq[i], seq[j], got)
				}
			}
		}
		// Newest-wins application (the passive's SCHED rule, L45; a PONG
		// retiring older PING records) over shuffled deliveries ends on the
		// newest value however the wrap falls.
		r := rand.New(rand.NewPCG(uint64(preset), 14))
		for k := 0; k < 200; k++ {
			order := slices.Clone(seq[:1+r.IntN(len(seq))])
			newest := order[len(order)-1]
			r.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
			applied := order[0]
			for _, e := range order[1:] {
				if EpochNewer(e, applied) {
					applied = e
				}
			}
			if applied != newest {
				t.Fatalf("preset %#x: newest-wins applied %#x, want %#x", preset, applied, newest)
			}
		}
	}

	// Against an unwrapped model: inside any window narrower than 2³¹ the
	// serial order equals the integer order.
	r := rand.New(rand.NewPCG(14, 14))
	for i := 0; i < 100000; i++ {
		base := r.Uint32()
		d1, d2 := r.Uint32N(1<<31-1), r.Uint32N(1<<31-1)
		if got := EpochNewer(base+d1, base+d2); got != (d1 > d2) {
			t.Fatalf("base %#x d1 %d d2 %d: %v", base, d1, d2, got)
		}
	}
}

// TestPureCallsDoNotAllocate: the per-evaluation calls the actor and the
// health layer make (Add/Summary/Classify/NextChange/Evaluate/Rank) allocate
// nothing in steady state.
func TestPureCallsDoNotAllocate(t *testing.T) {
	a := NewAggregator(DefaultAggParams())
	at := simEpoch
	sel := NewSelector(defaultSelectorParams())
	sums := make([]Summary, 2)
	cs := make([]Candidate, 2)
	out := make([]int, 0, 16)
	failed := []bool{false, false}
	n := testing.AllocsPerRun(200, func() {
		at = at.Add(time.Second)
		a.Add(at, 30*ms, false)
		sums[0] = a.Summary()
		sums[1] = sums[0]
		_ = NextChange(sums[0], at, defFresh)
		v := sel.Evaluate(at, 0, sums, failed)
		_ = v
		for i := range cs {
			cs[i] = Candidate{Index: i, Ev: Classify(sums[i], at, defFresh)}
		}
		out = Rank(cs, out)
	})
	if n != 0 {
		t.Fatalf("steady-state calls allocate %v times per run", n)
	}
}
