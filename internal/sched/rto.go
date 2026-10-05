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
func RTO(srtt, rttvar time.Duration, sampled bool) time.Duration {
	panic("unimplemented: M2")
}

// RTOBackoff returns min(rto·2ⁿ, RTOMax): the timeout of the n-th
// consecutive retransmission (n ≥ 0) of the same frame.
func RTOBackoff(rto time.Duration, n int) time.Duration {
	panic("unimplemented: M2")
}

// RTTVar returns the RFC 6298 update of rttvar for a new sample rtt against
// the previous srtt: rtt/2 for the first sample (first true), else
// ¾·rttvar + ¼·|srtt − rtt|.
func RTTVar(rttvar, srtt, rtt time.Duration, first bool) time.Duration {
	panic("unimplemented: M2")
}
