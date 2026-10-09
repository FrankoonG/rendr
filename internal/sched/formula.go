package sched

import "time"

// minAdvertise is the plan §3.7 floor of a window shrunk by memory pressure.
const minAdvertise = 64 << 10

// Plan §4 capacity formula constants: the fixed slack added to minRTT +
// PingBusy, and the minRTT assumed while none was measured.
const (
	capSlack      = 50 * time.Millisecond
	capUnknownRTT = 50 * time.Millisecond
)

// estimateNs returns k·srtt + bytes/rate in nanoseconds; non-positive srtt,
// bytes or rate (and a NaN rate) contribute nothing. It is computed in
// float64 so that a tiny rate cannot overflow a Duration: the result is
// clamped by the caller before conversion.
func estimateNs(k float64, srtt time.Duration, bytes int64, rate float64) float64 {
	d := 0.0
	if srtt > 0 {
		d = k * float64(srtt)
	}
	if bytes > 0 && rate > 0 {
		d += float64(bytes) / rate * float64(time.Second)
	}
	return d
}

// clampNs clamps d (nanoseconds, never NaN) to [min, max] and converts it;
// when min > max the upper bound wins (it is the hard limit, e.g. DeadMax
// inside the G4 budget). The bounds are returned as integers, never through
// float64: float64(math.MaxInt64) rounds up to 2⁶³, which converts to a
// negative Duration, so a "disabled" bound of MaxInt64 would otherwise turn
// into a huge negative deadline.
func clampNs(d float64, min, max time.Duration) time.Duration {
	if d >= float64(max) { // also +Inf
		return max
	}
	r := time.Duration(d) // d < float64(max) ≤ 2⁶³: in range
	if r < min {
		r = min
	}
	if r > max { // inverted bounds
		r = max
	}
	return r
}

// DeathDeadline is how long the oldest committed PING may stay unanswered
// (plan §3.6; L25): clamp(max(min, 3·srtt + inflight/rate), min, max). The
// inflight/rate term is omitted while rate is 0.
func DeathDeadline(srtt time.Duration, inflight int64, rate float64, min, max time.Duration) time.Duration {
	return clampNs(estimateNs(3, srtt, inflight, rate), min, max)
}

// StallWindow bounds one batch write (plan §3.6; L24):
// clamp(max(min, 2·srtt + batch/rate), min, max) with min = WriteStall and
// max = DeadMax. The batch/rate term is omitted while rate is 0.
func StallWindow(srtt time.Duration, batch int, rate float64, min, max time.Duration) time.Duration {
	return clampNs(estimateNs(2, srtt, int64(batch), rate), min, max)
}

// Capacity is a carrier's in-flight cap (plan §4):
// clamp(2·rate·(minRTT + pingBusy + 50 ms), floor, ceil); minRTT 0 counts as
// 50 ms. It is CapacityDuplex without a reverse-path allowance.
//
// When floor > ceil the ceiling wins: the cap never exceeds the window.
func Capacity(rate float64, minRTT, pingBusy time.Duration, floor, ceil int64) int64 {
	return CapacityDuplex(rate, minRTT, pingBusy, 0, 0, floor, ceil)
}

// CapacityDuplex is the in-flight cap with an allowance for the reverse
// path (M3 estimator amendment): clamp(2·rate·(minRTT + pingBusy + 50 ms) +
// min(revRate, rate)·rev, floor, ceil), where rev is the queueing delay our
// PONGs meet on their way back behind the peer's own DATA (bulk both ways
// on one carrier) and revRate the rate this side delivered recently; a
// non-positive (or NaN) rev, revRate or rate adds nothing.
//
// A byte is proven a forward trip, the reverse queue and the rest of the
// return trip after it is written. A cap sized from minRTT alone leaves
// the side whose PONGs wait behind the peer's queue capped below the link;
// its rate samples, taken while the peer is BUSY, measure what it achieved
// and lower the cap again, until the estimate settles near CapFloor/srtt
// (TestMuxBulkBothWaysKeepsTheLink). Both sides see the same round trip, so
// no function of it alone can tell the reverse queue from the forward one;
// rev is measured one way (the carrier's noteOWD). The allowance counts
// once: it covers a delay the writer does not cause. Its rate is the
// delivered average, bounded by the estimate, because the estimate is a
// decaying maximum that bulk both ways overestimates (ACK compression:
// TestByteClockDuplexRateBounded_L32 bounds it at 3× the link and logs
// peaks near 2×, TestDuplexKeepsBothDirections_L15 up to 2.6×): each
// side's allowance is the other side's queue, so an overestimated
// multiplier would feed the two queues into each other.
//
// Its price is latency. With bulk both ways over a bottleneck deeper than
// the cap, a side's bytes in flight, rate·(minRTT + q_fwd + q_rev), equal
// the cap 2·rate·(minRTT + pingBusy + 50 ms) + rate·q_rev, so each
// direction's standing queue settles near minRTT + 2·pingBusy + 100 ms and
// the round trip near 3·minRTT + 4·pingBusy + 200 ms (460 ms on a 20-ms
// path with the default PingBusy, against about 240 ms for bulk one way),
// less where the bottleneck's buffer or the window is smaller;
// TestDuplexKeepsBothDirections_L15 holds it within 1.5× of that.
func CapacityDuplex(rate float64, minRTT, pingBusy time.Duration, revRate float64, rev time.Duration, floor, ceil int64) int64 {
	if minRTT <= 0 {
		minRTT = capUnknownRTT
	}
	if pingBusy < 0 {
		pingBusy = 0
	}
	c := 0.0
	if rate > 0 { // also false for NaN
		// Nanoseconds first (summed in float64, so no Duration overflow),
		// then one division: exact for every realistic rate, so table
		// values do not drift by one byte.
		c = 2 * rate * (float64(minRTT) + float64(pingBusy) + float64(capSlack)) / float64(time.Second)
	}
	if rev > 0 && revRate > 0 && rate > 0 { // also false for NaN
		c += min(revRate, rate) * float64(rev) / float64(time.Second)
	}
	if c >= float64(ceil) { // also +Inf; the integer bound, as in clampNs
		return ceil
	}
	r := int64(c) // c < float64(ceil) ≤ 2⁶³: in range
	if r < floor {
		r = floor
	}
	if r > ceil { // floor above the window
		r = ceil
	}
	return r
}

// RescueWait is how long the bond window head may stay stuck before it is
// duplicated on another member (plan §4): max(min, 3 × fastest srtt), with
// min = 300 ms in production.
func RescueWait(fastest, min time.Duration) time.Duration {
	const maxDur = time.Duration(1<<63 - 1)
	if fastest > maxDur/3 {
		return maxDur
	}
	if w := 3 * fastest; w > min {
		return w
	}
	return min
}

// AdvertiseWindow is the window a receiver may advertise under memory
// pressure (plan §3.7): used ≤ 75% of max → window; 75% < used < 100% →
// max(64 KiB, window·(1 − used/max)/0.25); used ≥ max → 0. Callers apply it
// to the right edge, which never retracts (design §4.12).
//
// The result never exceeds window (the 64 KiB floor yields to a smaller
// configured window); a non-positive max means no budget limit.
func AdvertiseWindow(window, used, max int64) int64 {
	if window <= 0 {
		return 0
	}
	if max <= 0 {
		return window
	}
	u := float64(used) / float64(max)
	switch {
	case u <= 0.75:
		return window
	case u >= 1:
		return 0
	}
	w := int64(float64(window) * (1 - u) / 0.25)
	if w < minAdvertise {
		w = minAdvertise
	}
	if w > window {
		w = window
	}
	return w
}

// SRTTOrder writes lane indexes 0..len(srtt)-1 into out ordered by srtt
// ascending, unknown (0) srtt last, ties by index; out is reused.
func SRTTOrder(srtt []time.Duration, out []int) []int {
	n := len(srtt)
	if cap(out) < n {
		out = make([]int, n)
	}
	out = out[:n]
	for i := range out {
		out[i] = i
	}
	for i := 1; i < n; i++ { // insertion sort: few lanes, no allocation
		p := out[i]
		j := i
		for j > 0 && srttLess(srtt, p, out[j-1]) {
			out[j] = out[j-1]
			j--
		}
		out[j] = p
	}
	return out
}

// srttLess orders lane a before lane b: known (positive) srtt first by
// value, then unknown, ties by index.
func srttLess(srtt []time.Duration, a, b int) bool {
	ka, kb := srtt[a] > 0, srtt[b] > 0
	if ka != kb {
		return ka
	}
	if ka && srtt[a] != srtt[b] {
		return srtt[a] < srtt[b]
	}
	return a < b
}

// EpochNewer reports whether SCHED epoch a is newer than b in serial
// arithmetic (L14, L45).
func EpochNewer(a, b uint32) bool { return a != b && int32(a-b) > 0 }
