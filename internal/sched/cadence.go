package sched

import "time"

// BackoffBase is the first backoff step of the redial cadence (plan §3.6).
const BackoffBase = 500 * time.Millisecond

// Backoff returns min(BackoffBase·2ⁿ, max) × (0.8 + 0.4·u) for the n-th
// consecutive failure (n from 0) and u ∈ [0,1): the cap is applied before
// the jitter, so the longest interval is 1.2 × max.
func Backoff(n int, max time.Duration, u float64) time.Duration {
	panic("unimplemented: M1b")
}

// Outcome is how one dial attempt of a slot ended.
type Outcome uint8

// Attempt outcomes.
const (
	// OutcomeFailed: the PREFACE exchange did not complete (factory error,
	// transport error, timeout, malformed answer).
	OutcomeFailed Outcome = iota + 1
	// OutcomeRefused: the PREFACE exchange completed but the carrier was not
	// attached (CAPACITY, a timeout waiting for OPEN_ACK, instance mismatch).
	// It resets the failure count (plan §3.6) and then counts as failure 0.
	OutcomeRefused
	// OutcomeAttached: the carrier was attached (OPEN_ACK/JOIN_ACK OK).
	OutcomeAttached
)

// Cadence is the redial state of one slot (plan §3.6; L20, L22): at most one
// attempt at a time; the first attempt after a death or at the start of a
// no-path episode is immediate (Kick); after the n-th consecutive failure the
// next attempt starts at max(LastStart + Backoff(n), end of the failed
// attempt). Attempt ids make late results of superseded attempts
// detectable. It is a value type owned by the session actor (or the health
// layer for probe slots).
type Cadence struct {
	Fails     int       // consecutive failures (n)
	Running   bool      // an attempt is in flight
	Immediate bool      // the next attempt may start now regardless of backoff
	Attempt   uint64    // id of the latest attempt
	LastStart time.Time // start of the latest attempt
	NextAt    time.Time // earliest start of the next attempt (when !Immediate)
}

// Ready reports whether an attempt may start at now; if not and no attempt
// is running, at is when it can.
func (c *Cadence) Ready(now time.Time) (ok bool, at time.Time) {
	panic("unimplemented: M1b")
}

// Start records an attempt starting at now and returns its id.
func (c *Cadence) Start(now time.Time) uint64 {
	panic("unimplemented: M1b")
}

// Finish records the end of attempt id at now. It returns false (and changes
// nothing) for a stale id. Attached resets Fails; Refused resets Fails and
// then counts failure 0; Failed computes NextAt with Backoff(Fails, max, u)
// and increments Fails.
func (c *Cadence) Finish(now time.Time, id uint64, o Outcome, max time.Duration, u float64) bool {
	panic("unimplemented: M1b")
}

// Kick makes the next attempt immediate (a carrier of this slot died, or a
// no-path episode started). It is not gated by health failed marks.
func (c *Cadence) Kick() { c.Immediate = true }
