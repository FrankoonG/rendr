package sched

import "time"

// Reliable control sublayer timing (plan:300; M2-D16). Pure functions of
// their arguments; they allocate nothing.
const (
	// RTOMin and RTOMax clamp the retransmission timeout (plan:300).
	RTOMin = 200 * time.Millisecond
	RTOMax = 2 * time.Second
	// RTOInitial is the timeout before a carrier's first RTT sample
	// (srtt₀ 100 ms + 4 × rttvar₀ 50 ms): the first copy of an H1 or of a
	// REL is resent after 300 ms (PA-8).
	RTOInitial = 300 * time.Millisecond
)

// RTO returns clamp(srtt + 4·rttvar, RTOMin, RTOMax), or RTOInitial while
// sampled is false (no PING/PONG sample yet on the carrier).
//
// A negative srtt or rttvar, which no estimator produces, counts as 0, and
// the sum cannot overflow: the result always lies in [RTOMin, RTOMax].
func RTO(srtt, rttvar time.Duration, sampled bool) time.Duration {
	if !sampled {
		return RTOInitial
	}
	// Bounding each term by RTOMax first keeps the sum exact up to RTOMax
	// and at most 5·RTOMax, far from overflow.
	srtt = min(max(srtt, 0), RTOMax)
	rttvar = min(max(rttvar, 0), RTOMax)
	return min(max(srtt+4*rttvar, RTOMin), RTOMax)
}

// RTOBackoff returns min(rto·2ⁿ, RTOMax): the timeout of the n-th
// consecutive retransmission (n ≥ 0) of the same frame.
//
// The doubling saturates at RTOMax for every n, however large. A negative n
// counts as 0; a non-positive rto, which RTO never returns, has nothing to
// double and is returned unchanged.
func RTOBackoff(rto time.Duration, n int) time.Duration {
	if rto <= 0 {
		return rto
	}
	if n < 0 {
		n = 0
	}
	// rto·2ⁿ ≤ RTOMax exactly when rto ≤ ⌊RTOMax/2ⁿ⌋; a shift by 63 or more
	// leaves 0, so the shift below never overflows.
	if rto > RTOMax>>uint(n) {
		return RTOMax
	}
	return rto << uint(n)
}

// RTTVar returns the RFC 6298 update of rttvar for a new sample rtt against
// the previous srtt: rtt/2 for the first sample (first true), else
// ¾·rttvar + ¼·|srtt − rtt|.
//
// srtt is the value from before this sample: RFC 6298 §2.3 updates RTTVAR
// before SRTT. The result is rounded down to the nanosecond and computed
// without overflow; negative arguments, which no estimator produces, count
// as 0.
func RTTVar(rttvar, srtt, rtt time.Duration, first bool) time.Duration {
	rtt = max(rtt, 0)
	if first {
		return rtt / 2
	}
	rttvar, srtt = max(rttvar, 0), max(srtt, 0)
	d := srtt - rtt // both non-negative: no overflow
	if d < 0 {
		d = -d
	}
	// ⌊(3·rttvar + d)/4⌋ by quarters: with rttvar = 4q + r and d = 4p + s
	// it is 3q + p + ⌊(3r + s)/4⌋, which never exceeds the int64 range.
	return 3*(rttvar/4) + d/4 + (3*(rttvar%4)+d%4)/4
}
