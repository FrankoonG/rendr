package sched

import "time"

// DeathDeadline is how long the oldest committed PING may stay unanswered
// (plan §3.6; L25): clamp(max(min, 3·srtt + inflight/rate), min, max). The
// inflight/rate term is omitted while rate is 0.
func DeathDeadline(srtt time.Duration, inflight int64, rate float64, min, max time.Duration) time.Duration {
	panic("unimplemented: M1b")
}

// StallWindow bounds one batch write (plan §3.6; L24):
// clamp(max(min, 2·srtt + batch/rate), min, max) with min = WriteStall and
// max = DeadMax. The batch/rate term is omitted while rate is 0.
func StallWindow(srtt time.Duration, batch int, rate float64, min, max time.Duration) time.Duration {
	panic("unimplemented: M1b")
}

// Capacity is a carrier's in-flight cap (plan §4):
// clamp(2·rate·(minRTT + pingBusy + 50 ms), floor, ceil); minRTT 0 counts as
// 50 ms.
func Capacity(rate float64, minRTT, pingBusy time.Duration, floor, ceil int64) int64 {
	panic("unimplemented: M1b")
}

// RescueWait is how long the bond window head may stay stuck before it is
// duplicated on another member (plan §4): max(min, 3 × fastest srtt), with
// min = 300 ms in production.
func RescueWait(fastest, min time.Duration) time.Duration {
	panic("unimplemented: M1b")
}

// AdvertiseWindow is the window a receiver may advertise under memory
// pressure (plan §3.7): used ≤ 75% of max → window; 75% < used < 100% →
// max(64 KiB, window·(1 − used/max)/0.25); used ≥ max → 0. Callers apply it
// to the right edge, which never retracts (design §4.12).
func AdvertiseWindow(window, used, max int64) int64 {
	panic("unimplemented: M1b")
}

// SRTTOrder writes lane indexes 0..len(srtt)-1 into out ordered by srtt
// ascending, unknown (0) srtt last, ties by index; out is reused.
func SRTTOrder(srtt []time.Duration, out []int) []int {
	panic("unimplemented: M1b")
}

// EpochNewer reports whether SCHED epoch a is newer than b in serial
// arithmetic (L14, L45).
func EpochNewer(a, b uint32) bool { return a != b && int32(a-b) > 0 }
