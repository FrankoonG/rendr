package sched

import "time"

// maxRaceOrder is the Peer factory limit: a race never has more candidates.
const maxRaceOrder = 16

// Race is the staggered candidate race used by the dialer for the opening
// phase of Dial and for selector death failover (plan §3.2): the first
// candidate starts at once, and whenever Stagger passes without a winner the
// next candidate (in rank order, cycling) whose slot is ready starts too.
// The first attempt to attach wins; the session discards the Race then.
type Race struct {
	order   [maxRaceOrder]int // candidates, best first (a copy: C27)
	n       int               // valid entries of order
	cursor  int               // position of the next candidate to consider
	stagger time.Duration
	last    time.Time // start of the latest attempt (valid when started)
	started bool
}

// NewRace returns a race over order (factory indexes, best first, fixed at
// the instant the race starts) with the given stagger, started at now. It
// copies order into a fixed array inside the Race (at most 16 entries, the
// Peer factory limit; no allocation), so the caller may reuse its ranking
// buffer (Rank's out) at once.
func NewRace(order []int, stagger time.Duration, now time.Time) Race {
	// now needs no record: the first Next call starts the first ready
	// candidate at once, whatever its time.
	r := Race{stagger: stagger}
	r.n = copy(r.order[:], order)
	return r
}

// Next decides whether to start an attempt now. outstanding is the number of
// this race's attempts still in flight. ready(idx) reports whether factory
// idx's slot may start an attempt now, and otherwise when it can. If
// outstanding > 0 and fewer than Stagger has passed since the last start,
// Next returns wake = last start + Stagger. Otherwise it returns the first
// ready candidate after the cursor (cycling) with start = true and records
// the start; if none is ready, wake is the earliest readiness.
//
// When start is true, wake is now + Stagger: the earliest instant at which
// the race may want another attempt while this one is outstanding. idx is
// −1 whenever start is false.
func (r *Race) Next(now time.Time, outstanding int, ready func(idx int) (ok bool, at time.Time)) (idx int, start bool, wake time.Time) {
	if r.n == 0 {
		return -1, false, time.Time{}
	}
	if outstanding > 0 && r.started {
		if end := r.last.Add(r.stagger); now.Before(end) {
			return -1, false, end
		}
	}
	for k := 0; k < r.n; k++ {
		pos := (r.cursor + k) % r.n
		cand := r.order[pos]
		ok, at := ready(cand)
		if ok {
			r.cursor = (pos + 1) % r.n
			r.last, r.started = now, true
			return cand, true, now.Add(r.stagger)
		}
		if at.After(now) { // a readiness that is not in the future is no wake time
			wake = earlier(wake, at)
		}
	}
	return -1, false, wake
}
