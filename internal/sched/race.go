package sched

import "time"

// Race is the staggered candidate race used by the dialer for the opening
// phase of Dial and for selector death failover (plan §3.2): the first
// candidate starts at once, and whenever Stagger passes without a winner the
// next candidate (in rank order, cycling) whose slot is ready starts too.
// The first attempt to attach wins; the session discards the Race then.
type Race struct {
	// unexported state (order, cursor, last start, stagger) is defined by the implementation.
	_ struct{}
}

// NewRace returns a race over order (factory indexes, best first, fixed at
// the instant the race starts) with the given stagger, started at now. It
// copies order into a fixed array inside the Race (at most 16 entries, the
// Peer factory limit; no allocation), so the caller may reuse its ranking
// buffer (Rank's out) at once.
func NewRace(order []int, stagger time.Duration, now time.Time) Race {
	panic("unimplemented: M1b")
}

// Next decides whether to start an attempt now. outstanding is the number of
// this race's attempts still in flight. ready(idx) reports whether factory
// idx's slot may start an attempt now, and otherwise when it can. If
// outstanding > 0 and fewer than Stagger has passed since the last start,
// Next returns wake = last start + Stagger. Otherwise it returns the first
// ready candidate after the cursor (cycling) with start = true and records
// the start; if none is ready, wake is the earliest readiness.
func (r *Race) Next(now time.Time, outstanding int, ready func(idx int) (ok bool, at time.Time)) (idx int, start bool, wake time.Time) {
	panic("unimplemented: M1b")
}
