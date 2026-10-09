package sched

import (
	"math"
	"math/big"
	"math/rand/v2"
	"slices"
	"testing"
	"time"
)

const (
	maxDur = time.Duration(math.MaxInt64)
	minDur = time.Duration(math.MinInt64)
)

// TestRTO_L12 (plan:300, PA-8, M2-D16; L12 "RTO = clamp(srtt + 4·rttvar,
// 200ms, 2s)", "RTT 400ms、rttvar 50ms 时首次重传约在 600ms"): RTOInitial
// (300 ms) until the carrier's first RTT sample, whatever its estimator
// holds; afterwards clamp(srtt + 4·rttvar, 200 ms, 2 s) — L12's RTT 400 ms
// with rttvar 50 ms gives 600 ms; every consecutive retransmission of the
// same frame doubles the timeout up to 2 s, so a frame lost for good is
// sent at 0, 0.3, 0.9, 2.1, 4.1, 6.1, 8.1 s (the H1 schedule of the M2
// design §A5.10) and never more often than every 2 s after that. The same
// rule holds with the bounds as arguments (RTOWithin, RTOBackoffWithin):
// the REL timer takes them from carrier.Timing, whose RelRTOInit,
// RelRTOMin and RelRTOMax test hooks may shrink (M2-D16).
func TestRTO_L12(t *testing.T) {
	if RTOInitial != 300*ms || RTOMin != 200*ms || RTOMax != 2*time.Second {
		t.Fatalf("constants: initial %v, min %v, max %v", RTOInitial, RTOMin, RTOMax)
	}

	// Before the first sample nothing the estimator holds matters.
	for _, e := range []struct{ srtt, rttvar time.Duration }{
		{0, 0}, {400 * ms, 50 * ms}, {10 * ms, ms}, {5 * time.Second, time.Second},
		{-time.Second, -time.Second}, {maxDur, maxDur}, {minDur, minDur},
	} {
		if got := RTO(e.srtt, e.rttvar, false); got != 300*ms {
			t.Errorf("RTO(%v, %v, unsampled) = %v, want 300ms", e.srtt, e.rttvar, got)
		}
	}

	// After it: the formula and its clamp, both bounds inclusive.
	for _, tc := range []struct {
		name               string
		srtt, rttvar, want time.Duration
	}{
		{"L12: RTT 400 ms, rttvar 50 ms", 400 * ms, 50 * ms, 600 * ms},
		{"zero estimator", 0, 0, 200 * ms},
		{"LAN: below the floor", 2 * ms, 500 * time.Microsecond, 200 * ms},
		{"exactly the floor", 120 * ms, 20 * ms, 200 * ms},
		{"1 ns above the floor", 200*ms + 1, 0, 200*ms + 1},
		{"srtt only", 250 * ms, 0, 250 * ms},
		{"rttvar only", 0, 100 * ms, 400 * ms},
		{"first sample of a 400-ms path (rttvar = rtt/2)", 400 * ms, 200 * ms, 1200 * ms},
		{"1 ns below the cap", 2*time.Second - 1, 0, 2*time.Second - 1},
		{"exactly the cap", 1600 * ms, 100 * ms, 2 * time.Second},
		{"above the cap", 1900 * ms, 100 * ms, 2 * time.Second},
		{"srtt alone above the cap", time.Hour, 0, 2 * time.Second},
		{"4·rttvar would overflow", 0, maxDur/4 + 1, 2 * time.Second},
		{"both maximal", maxDur, maxDur, 2 * time.Second},
		{"negative srtt counts as 0", -time.Hour, 100 * ms, 400 * ms},
		{"negative rttvar counts as 0", 300 * ms, -time.Hour, 300 * ms},
		{"both minimal", minDur, minDur, 200 * ms},
	} {
		if got := RTO(tc.srtt, tc.rttvar, true); got != tc.want {
			t.Errorf("%s: RTO(%v, %v) = %v, want %v", tc.name, tc.srtt, tc.rttvar, got, tc.want)
		}
	}
	// Against the formula in exact arithmetic for random estimator states
	// (non-negative, as an estimator produces them; any magnitude).
	r := rand.New(rand.NewPCG(12, 300))
	for i := 0; i < 20000; i++ {
		srtt, rttvar := randDur(r), randDur(r)
		sum := new(big.Int).Mul(big.NewInt(int64(rttvar)), big.NewInt(4))
		sum.Add(sum, big.NewInt(int64(srtt)))
		want := RTOMin
		switch {
		case sum.Cmp(big.NewInt(int64(RTOMax))) >= 0:
			want = RTOMax
		case sum.Cmp(big.NewInt(int64(RTOMin))) > 0:
			want = time.Duration(sum.Int64())
		}
		if got := RTO(srtt, rttvar, true); got != want {
			t.Fatalf("RTO(%d, %d) = %d, want %d", srtt, rttvar, got, want)
		}
	}

	// Backoff: min(rto·2ⁿ, 2 s), saturating for any n.
	for _, tc := range []struct {
		rto  time.Duration
		n    int
		want time.Duration
	}{
		{300 * ms, 0, 300 * ms}, {300 * ms, 1, 600 * ms}, {300 * ms, 2, 1200 * ms},
		{300 * ms, 3, 2 * time.Second}, {300 * ms, 4, 2 * time.Second}, {300 * ms, 100, 2 * time.Second},
		{600 * ms, 0, 600 * ms}, {600 * ms, 1, 1200 * ms}, {600 * ms, 2, 2 * time.Second},
		{200 * ms, 3, 1600 * ms}, {200 * ms, 4, 2 * time.Second},
		{1000*ms - 1, 1, 2*time.Second - 2}, {1000 * ms, 1, 2 * time.Second}, {1000*ms + 1, 1, 2 * time.Second},
		{RTOMax, 0, RTOMax}, {RTOMax, 1, RTOMax},
		{5 * time.Second, 0, RTOMax}, // a timeout above the cap is capped
		{maxDur, 0, RTOMax}, {maxDur, 1, RTOMax},
		{1, 30, 1 << 30}, {1, 31, RTOMax}, {1, 62, RTOMax}, {1, 63, RTOMax}, {1, 64, RTOMax},
		{1, 1000, RTOMax}, {1, math.MaxInt, RTOMax},
		{300 * ms, -1, 300 * ms}, {300 * ms, math.MinInt, 300 * ms}, // n < 0 counts as 0
		{0, 5, 0}, {-ms, 3, -ms}, // nothing to double
	} {
		if got := RTOBackoff(tc.rto, tc.n); got != tc.want {
			t.Errorf("RTOBackoff(%v, %d) = %v, want %v", tc.rto, tc.n, got, tc.want)
		}
	}
	for i := 0; i < 20000; i++ {
		rto, n := time.Duration(1+r.Int64N(int64(3*time.Second))), r.IntN(40)
		want := new(big.Int).Lsh(big.NewInt(int64(rto)), uint(n))
		if want.Cmp(big.NewInt(int64(RTOMax))) > 0 {
			want.SetInt64(int64(RTOMax))
		}
		if got := RTOBackoff(rto, n); int64(got) != want.Int64() {
			t.Fatalf("RTOBackoff(%d, %d) = %d, want %d", rto, n, got, want.Int64())
		}
	}

	// A frame lost for good (single flight: retransmission k re-arms the
	// timer at RTOBackoff(rto, k) after it is sent).
	copiesAt := func(rto time.Duration, copies int) []time.Duration {
		var out []time.Duration
		at := time.Duration(0)
		for k := 0; k < copies; k++ {
			out = append(out, at)
			at += RTOBackoff(rto, k)
		}
		return out
	}
	for _, tc := range []struct {
		name string
		rto  time.Duration
		want []time.Duration
	}{
		{"before any sample (H1, the first REL)", RTO(400*ms, 50*ms, false),
			[]time.Duration{0, 300 * ms, 900 * ms, 2100 * ms, 4100 * ms, 6100 * ms, 8100 * ms, 10100 * ms}},
		{"L12: RTT 400 ms, rttvar 50 ms", RTO(400*ms, 50*ms, true),
			[]time.Duration{0, 600 * ms, 1800 * ms, 3800 * ms, 5800 * ms, 7800 * ms}},
		{"floor", RTO(ms, 0, true),
			[]time.Duration{0, 200 * ms, 600 * ms, 1400 * ms, 3000 * ms, 5000 * ms, 7000 * ms}},
	} {
		got := copiesAt(tc.rto, len(tc.want))
		for k := range tc.want {
			if got[k] != tc.want[k] {
				t.Errorf("%s: copies at %v, want %v", tc.name, got, tc.want)
				break
			}
		}
	}

	// Timing bounds: the defaults shrunk tenfold (RelRTOInit 30 ms,
	// RelRTOMin 20 ms, RelRTOMax 200 ms), as a test hook sets them.
	const tInit, tLo, tHi = 30 * ms, 20 * ms, 200 * ms
	for _, tc := range []struct {
		name               string
		srtt, rttvar, want time.Duration
		sampled            bool
	}{
		{"before a sample", 40 * ms, 5 * ms, tInit, false},
		{"before a sample, any estimator", maxDur, maxDur, tInit, false},
		{"L12 tenfold: RTT 40 ms, rttvar 5 ms", 40 * ms, 5 * ms, 60 * ms, true},
		{"below the floor", 2 * ms, 500 * time.Microsecond, tLo, true},
		{"exactly the floor", 12 * ms, 2 * ms, tLo, true},
		{"1 ns above the floor", tLo + 1, 0, tLo + 1, true},
		{"1 ns below the cap", tHi - 1, 0, tHi - 1, true},
		{"exactly the cap", 160 * ms, 10 * ms, tHi, true},
		{"above the cap", 190 * ms, 10 * ms, tHi, true},
		{"srtt alone at the cap", tHi, 0, tHi, true},
		{"4·rttvar would overflow", 0, maxDur/4 + 1, tHi, true},
		{"both maximal", maxDur, maxDur, tHi, true},
		{"negative counts as 0", minDur, minDur, tLo, true},
	} {
		if got := RTOWithin(tc.srtt, tc.rttvar, tc.sampled, tInit, tLo, tHi); got != tc.want {
			t.Errorf("Timing bounds, %s: RTOWithin(%v, %v, sampled %v) = %v, want %v", tc.name, tc.srtt, tc.rttvar, tc.sampled, got, tc.want)
		}
	}
	for _, initial := range []time.Duration{ms, 5 * time.Second} { // the configured value, inside the clamp or not
		if got := RTOWithin(400*ms, 50*ms, false, initial, tLo, tHi); got != initial {
			t.Errorf("Timing bounds: RTOWithin(unsampled, initial %v) = %v", initial, got)
		}
	}
	for _, tc := range []struct {
		rto  time.Duration
		n    int
		want time.Duration
	}{
		{tInit, 0, 30 * ms}, {tInit, 1, 60 * ms}, {tInit, 2, 120 * ms}, {tInit, 3, tHi}, {tInit, 1000, tHi},
		{100 * ms, 1, tHi}, {100*ms + 1, 1, tHi}, {100*ms - 1, 1, tHi - 2},
		{300 * ms, 0, tHi}, {maxDur, 0, tHi}, {1, 63, tHi}, {1, math.MaxInt, tHi},
		{tInit, -1, tInit}, {0, 3, 0}, {-ms, 3, -ms},
	} {
		if got := RTOBackoffWithin(tc.rto, tc.n, tHi); got != tc.want {
			t.Errorf("Timing bounds: RTOBackoffWithin(%v, %d, %v) = %v, want %v", tc.rto, tc.n, tHi, got, tc.want)
		}
	}
	// A cap near the int64 limit: the doubling saturates exactly there.
	for _, tc := range []struct {
		rto  time.Duration
		n    int
		want time.Duration
	}{
		{1, 62, 1 << 62}, {1, 63, maxDur}, {2, 61, 1 << 62}, {2, 62, maxDur}, {maxDur, 0, maxDur}, {maxDur, 1, maxDur},
	} {
		if got := RTOBackoffWithin(tc.rto, tc.n, maxDur); got != tc.want {
			t.Errorf("RTOBackoffWithin(%d, %d, max) = %d, want %d", tc.rto, tc.n, got, tc.want)
		}
	}
	var at time.Duration // a frame lost for good under the shrunk bounds
	var tenfold []time.Duration
	rto := RTOWithin(40*ms, 5*ms, false, tInit, tLo, tHi)
	for k := 0; k < 6; k++ {
		tenfold = append(tenfold, at)
		at += RTOBackoffWithin(rto, k, tHi)
	}
	if want := []time.Duration{0, 30 * ms, 90 * ms, 210 * ms, 410 * ms, 610 * ms}; !slices.Equal(tenfold, want) {
		t.Errorf("Timing bounds, before any sample: copies at %v, want %v", tenfold, want)
	}
	// Against min(max(srtt + 4·rttvar, lo), hi) and min(rto·2ⁿ, hi) in exact
	// arithmetic for random bounds 0 < lo ≤ hi of any magnitude.
	for i := 0; i < 20000; i++ {
		lo, hi := max(randDur(r), 1), max(randDur(r), 1)
		if lo > hi {
			lo, hi = hi, lo
		}
		srtt, rttvar := randDur(r), randDur(r)
		sum := new(big.Int).Mul(big.NewInt(int64(rttvar)), big.NewInt(4))
		sum.Add(sum, big.NewInt(int64(srtt)))
		var want time.Duration
		switch {
		case sum.Cmp(big.NewInt(int64(hi))) >= 0:
			want = hi
		case sum.Cmp(big.NewInt(int64(lo))) <= 0:
			want = lo
		default:
			want = time.Duration(sum.Int64())
		}
		if got := RTOWithin(srtt, rttvar, true, tInit, lo, hi); got != want {
			t.Fatalf("RTOWithin(%d, %d, [%d, %d]) = %d, want %d", srtt, rttvar, lo, hi, got, want)
		}
		b, n := max(randDur(r), 1), r.IntN(70)
		bw := new(big.Int).Lsh(big.NewInt(int64(b)), uint(n))
		if bw.Cmp(big.NewInt(int64(hi))) > 0 {
			bw.SetInt64(int64(hi))
		}
		if got := RTOBackoffWithin(b, n, hi); int64(got) != bw.Int64() {
			t.Fatalf("RTOBackoffWithin(%d, %d, %d) = %d, want %d", b, n, hi, got, bw.Int64())
		}
	}
}

// TestRTTVar_L12 (RFC 6298 §2; M2 design §A5.11 "first sample rtt/2, then
// ¾·rttvar + ¼·|srtt − rtt|"): the first sample sets rttvar to half of it;
// every later one moves rttvar a quarter of the way to the sample's
// distance from the previous srtt, rounded down to the nanosecond and
// without overflow for any argument. Driven with the carrier estimator's
// srtt (first sample, then ⅞·srtt + ⅛·rtt), a steady 400-ms path's RTO
// starts at 1.2 s and reaches L12's "≈ 600 ms" after six samples; a path
// with jitter keeps its RTO above its RTT by about four times the jitter.
func TestRTTVar_L12(t *testing.T) {
	// The first sample ignores whatever was stored before.
	for _, e := range []struct{ rttvar, srtt, rtt, want time.Duration }{
		{0, 0, 400 * ms, 200 * ms},
		{time.Hour, time.Hour, 400 * ms, 200 * ms},
		{0, 0, 3, 1},
		{0, 0, 0, 0}, // a sub-tick PONG (Windows, zero-delay links: Y6)
		{0, 0, maxDur, maxDur / 2},
		{50 * ms, 50 * ms, -ms, 0}, // negative counts as 0
	} {
		if got := RTTVar(e.rttvar, e.srtt, e.rtt, true); got != e.want {
			t.Errorf("RTTVar(%v, %v, %v, first) = %v, want %v", e.rttvar, e.srtt, e.rtt, got, e.want)
		}
	}
	// Later samples.
	for _, e := range []struct {
		name                    string
		rttvar, srtt, rtt, want time.Duration
	}{
		{"steady: ¾ of the variance remains", 50 * ms, 400 * ms, 400 * ms, 37500 * time.Microsecond},
		{"late sample", 50 * ms, 400 * ms, 600 * ms, 87500 * time.Microsecond},
		{"early sample (|srtt − rtt|)", 50 * ms, 600 * ms, 400 * ms, 87500 * time.Microsecond},
		{"from zero", 0, 400 * ms, 480 * ms, 20 * ms},
		{"settled", 20 * ms, 400 * ms, 420 * ms, 20 * ms},
		{"rounded down", 1, 0, 0, 0},
		{"rounded down (3)", 3, 0, 1, 2}, // (9 + 1)/4 = 2.5
		{"exact quarter", 4, 0, 4, 4},
		{"all maximal", maxDur, maxDur, 0, maxDur},
		{"maximal variance, no distance", maxDur, 5 * ms, 5 * ms, maxDur - maxDur/4 - 1}, // ⌊3·(2⁶³−1)/4⌋
		{"maximal distance", 0, maxDur, 0, maxDur / 4},
		{"negative rttvar counts as 0", -time.Hour, 400 * ms, 480 * ms, 20 * ms},
		{"negative srtt counts as 0", 0, minDur, 80 * ms, 20 * ms},
		{"negative rtt counts as 0", 0, 80 * ms, minDur, 20 * ms},
	} {
		if got := RTTVar(e.rttvar, e.srtt, e.rtt, false); got != e.want {
			t.Errorf("%s: RTTVar(%v, %v, %v) = %v, want %v", e.name, e.rttvar, e.srtt, e.rtt, got, e.want)
		}
	}
	// Against ⌊(3·rttvar + |srtt − rtt|)/4⌋ in exact arithmetic, for any
	// non-negative magnitudes; the result lies between rttvar and the
	// distance (a convex combination).
	r := rand.New(rand.NewPCG(12, 6298))
	for i := 0; i < 50000; i++ {
		v, s, x := randDur(r), randDur(r), randDur(r)
		d := s - x
		if d < 0 {
			d = -d
		}
		want := new(big.Int).Mul(big.NewInt(int64(v)), big.NewInt(3))
		want.Add(want, big.NewInt(int64(d)))
		want.Rsh(want, 2) // non-negative: the floor
		got := RTTVar(v, s, x, false)
		if int64(got) != want.Int64() {
			t.Fatalf("RTTVar(%d, %d, %d) = %d, want %d", v, s, x, got, want.Int64())
		}
		if got < min(v, d) || got > max(v, d) {
			t.Fatalf("RTTVar(%d, %d, %d) = %d outside [%d, %d]", v, s, x, got, min(v, d), max(v, d))
		}
	}

	// The estimator loop of a carrier: rttvar first (against the old srtt),
	// then srtt; RTO after each PONG. Steady 400 ms: 1.2 s, 1 s, 850 ms,
	// 737.5 ms, 653.1 ms, 589.8 ms, … towards 400 ms, never below it.
	type est struct {
		srtt, rttvar time.Duration
		n            int
	}
	pong := func(e *est, rtt time.Duration) {
		e.rttvar = RTTVar(e.rttvar, e.srtt, rtt, e.n == 0)
		if e.n == 0 {
			e.srtt = rtt
		} else {
			e.srtt = (7*e.srtt + rtt) / 8
		}
		e.n++
	}
	var e est
	wantRTO := []time.Duration{1200 * ms, 1000 * ms, 850 * ms, 737500 * time.Microsecond, 653125 * time.Microsecond}
	for k, w := range wantRTO {
		pong(&e, 400*ms)
		if got := RTO(e.srtt, e.rttvar, e.n > 0); got != w {
			t.Fatalf("steady 400 ms, sample %d: RTO %v (srtt %v, rttvar %v), want %v", k+1, got, e.srtt, e.rttvar, w)
		}
	}
	pong(&e, 400*ms)
	if got := RTO(e.srtt, e.rttvar, true); got < 580*ms || got > 600*ms {
		t.Fatalf("steady 400 ms, sample 6: RTO %v, want ≈ 590 ms (L12's ≈ 600 ms)", got)
	}
	prev := RTO(e.srtt, e.rttvar, true)
	for k := 0; k < 200; k++ {
		pong(&e, 400*ms)
		got := RTO(e.srtt, e.rttvar, true)
		if got > prev || got < 400*ms {
			t.Fatalf("steady 400 ms, sample %d: RTO %v after %v", k+7, got, prev)
		}
		prev = got
	}
	if prev > 400*ms+ms {
		t.Fatalf("steady 400 ms: RTO settles at %v, want 400 ms", prev)
	}
	// A jittery path (RTT uniform in 400 ± 50 ms), against the RFC 6298
	// recurrence in float64: each integer step of srtt and of rttvar loses
	// less than 1 ns and ⅞ and ¾ contract the error, so it stays below
	// 8 ns on srtt and 12 ns on rttvar. The RTO settles near srtt + 4·E|srtt
	// − rtt| ≈ 400 + 4·25 ms.
	jr := rand.New(rand.NewPCG(400, 50))
	var je est
	var fs, fv float64
	var sumRTO time.Duration
	const samples, settle = 1000, 50
	for k := 0; k < samples; k++ {
		rtt := 350*ms + time.Duration(jr.Int64N(int64(100*ms)))
		pong(&je, rtt)
		if k == 0 {
			fs, fv = float64(rtt), float64(rtt)/2
		} else {
			fv = 0.75*fv + 0.25*math.Abs(fs-float64(rtt))
			fs = (7*fs + float64(rtt)) / 8
		}
		if diff := math.Abs(float64(je.rttvar) - fv); diff > 16 {
			t.Fatalf("jitter, sample %d: rttvar %d ns, RFC recurrence %.1f ns", k+1, je.rttvar, fv)
		}
		if k >= settle {
			sumRTO += RTO(je.srtt, je.rttvar, true)
		}
	}
	if mean := sumRTO / (samples - settle); mean < 480*ms || mean > 520*ms {
		t.Fatalf("jitter ±50 ms: mean RTO %v, want ≈ 500 ms", mean)
	}
}

// randDur returns a non-negative duration whose magnitude is spread over
// every power of two, so both small values and values near the int64 limit
// occur often.
func randDur(r *rand.Rand) time.Duration {
	return time.Duration(r.Int64() >> r.UintN(64))
}
