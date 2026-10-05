package sched

import "time"

// BackoffBase is the first backoff step of the redial cadence (plan §3.6).
const BackoffBase = 500 * time.Millisecond

// maxBackoffShift bounds the exponent: BackoffBase·2³² (≈ 68 years) is past
// every cap and still far from overflowing a Duration, even ×1.2.
const maxBackoffShift = 32

// Backoff returns min(BackoffBase·2ⁿ, max) × (0.8 + 0.4·u) for the n-th
// consecutive failure (n from 0) and u ∈ [0,1): the cap is applied before
// the jitter, so the longest interval is 1.2 × max.
//
// A non-positive max means no cap; u outside [0,1] (or NaN) is clamped.
func Backoff(n int, max time.Duration, u float64) time.Duration {
	if n < 0 {
		n = 0
	} else if n > maxBackoffShift {
		n = maxBackoffShift
	}
	d := BackoffBase << uint(n)
	if max > 0 && d > max {
		d = max
	}
	switch {
	case !(u >= 0): // negative or NaN
		u = 0
	case u > 1:
		u = 1
	}
	return time.Duration(float64(d) * (0.8 + 0.4*u))
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
	// It resets the failure count (plan §3.6) and then counts as failure 0
	// when it is the first refusal since the slot last attached, or when its
	// attempt started inside a recovery window (Cadence); every other
	// refusal counts as a failure, also after failed attempts in between, so
	// a peer that keeps refusing is redialled at the growing cadence up to
	// the cap.
	OutcomeRefused
	// OutcomeAttached: the carrier was attached (OPEN_ACK/JOIN_ACK OK).
	OutcomeAttached
)

// Cadence is the redial state of one slot (plan §3.6; L20, L22): at most one
// attempt at a time; the first attempt after a death or at the start of a
// no-path episode is immediate (Kick); after the n-th consecutive failure the
// next attempt starts at max(LastStart + Backoff(n), end of the failed
// attempt). A refusal resets n when it is the first since the slot last
// attached or falls inside a recovery window; other refusals count as
// failures (OutcomeRefused; design §0.14 B6). Attempt ids make late results
// of superseded attempts detectable. It is a value type owned by the
// session actor (or the health layer for probe slots, which never report
// OutcomeRefused).
//
// Recovery window: a Kick of a slot that has dialled before (its carrier
// died, or a no-path episode started) opens a window of recoverSpan × max
// (the cap passed to Finish) at the next attempt's start. Refusals of
// attempts started inside it reset n, so the slot keeps redialling every
// Backoff(0) while the passive may still hold the dead carrier and refuse
// with CAPACITY until its own death deadline (design D27: the session's
// carriers fill the passive's MaxCarriersPerSession); the first attempt
// after the passive dropped it attaches within Backoff(0). With the
// default timing the window spans the whole no-path episode (4 × 4 s ≥
// NoPathGrace 15 s). A slot refused beyond the window backs off, and so
// does a slot that is refused without having dialled before its kick (the
// bond's kick of a new member slot when the session opens is its first
// dial, not a recovery).
type Cadence struct {
	Fails     int       // consecutive failures (n), refusals included; one that resets n is failure 0
	Running   bool      // an attempt is in flight
	Immediate bool      // the next attempt may start now regardless of backoff
	Attempt   uint64    // id of the latest attempt
	LastStart time.Time // start of the latest attempt
	NextAt    time.Time // earliest start of the next attempt (when !Immediate)

	// refused: an attempt was refused since the slot last attached (or
	// since it was created). Only Attached clears it; a failure or a Kick
	// does not, so a refusing peer reached between failed dials still
	// backs off.
	refused bool
	// kicked: a Kick reached the slot after it had dialled; the next Start
	// opens a recovery window. Attached clears it.
	kicked bool
	// recoverFrom is the start of the current recovery window (zero: none).
	// Attached closes it.
	recoverFrom time.Time
}

// recoverSpan is the length of a slot's recovery window in units of its cap
// (Cadence). For a session slot the cap is min(RejoinBackoffMax,
// NoPathGrace/2), so the window spans the default no-path episode (4 × 4 s
// against 15 s) and, whenever the cap is NoPathGrace/2, two episodes.
const recoverSpan = 4

// Ready reports whether an attempt may start at now; if not and no attempt
// is running, at is when it can.
func (c *Cadence) Ready(now time.Time) (ok bool, at time.Time) {
	switch {
	case c.Running:
		return false, time.Time{} // one attempt at a time (L22); its Finish decides
	case c.Immediate, c.NextAt.IsZero(), !now.Before(c.NextAt):
		return true, time.Time{}
	}
	return false, c.NextAt
}

// Start records an attempt starting at now and returns its id. The first
// attempt after a Kick of a slot that had dialled opens a recovery window.
func (c *Cadence) Start(now time.Time) uint64 {
	c.Running = true
	c.Immediate = false
	if c.kicked {
		c.kicked = false
		c.recoverFrom = now
	}
	c.Attempt++
	c.LastStart = now
	return c.Attempt
}

// Finish records the end of attempt id at now. It returns false (and changes
// nothing) for a stale id. Attached resets Fails, the refusal memory and the
// recovery window. A Refused that is the first since the last Attached, or
// whose attempt started inside the recovery window (before recoverFrom +
// recoverSpan × max), resets Fails and then counts failure 0; Failed, and
// every other Refused, compute NextAt with Backoff(Fails, max, u) and
// increment Fails, so persistent refusals grow the interval to the cap like
// failures do (design §0.14 B6; plan §3.6 amended: a completed PREFACE
// exchange resets n at the first refusal and during a recovery window).
//
// A Kick that arrived while the attempt ran survives it: the next attempt is
// then immediate. An unknown outcome counts as a failure.
func (c *Cadence) Finish(now time.Time, id uint64, o Outcome, max time.Duration, u float64) bool {
	if !c.Running || id != c.Attempt {
		return false
	}
	c.Running = false
	switch o {
	case OutcomeAttached:
		c.Fails = 0
		c.refused, c.kicked = false, false
		c.recoverFrom = time.Time{}
		c.NextAt = time.Time{}
	case OutcomeRefused:
		if !c.refused || c.recovering(max) {
			c.Fails = 0 // the PREFACE exchange completed (plan §3.6)
		}
		c.refused = true
		c.backoff(now, max, u)
	default:
		c.backoff(now, max, u)
	}
	return true
}

// recovering reports that the attempt that just ended started inside the
// recovery window; a non-positive max gives no window.
func (c *Cadence) recovering(max time.Duration) bool {
	return !c.recoverFrom.IsZero() && c.LastStart.Before(c.recoverFrom.Add(recoverSpan*max))
}

// backoff schedules the next start after failure number c.Fails, measured
// between attempt starts but never before the failed attempt ended (plan
// §3.6: a hung attempt is not followed by another backoff).
func (c *Cadence) backoff(now time.Time, max time.Duration, u float64) {
	next := c.LastStart.Add(Backoff(c.Fails, max, u))
	if next.Before(now) {
		next = now
	}
	c.NextAt = next
	c.Fails++
}

// Kick makes the next attempt immediate (a carrier of this slot died, or a
// no-path episode started). It is not gated by health failed marks. It
// keeps Fails and the refusal memory. On a slot that has dialled before it
// opens a recovery window at the next Start (Cadence); on a slot that never
// started an attempt it does not (the bond's kick of a new member slot when
// the session opens is its first dial, not a recovery).
func (c *Cadence) Kick() {
	c.Immediate = true
	if c.Attempt > 0 {
		c.kicked = true
	}
}
