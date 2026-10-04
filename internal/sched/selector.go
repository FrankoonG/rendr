package sched

import "time"

// SelectorParams are the selector quality parameters (plan §4). Band, Floor,
// Dwell and Cooldown are owner-fixed; Fresh is Probe.Fresh.
type SelectorParams struct {
	Band     float64       // 0.25: challenger RTT ≤ active RTT × (1 − Band) ...
	Floor    time.Duration // 5 ms: ... and active RTT − challenger RTT ≥ Floor
	Dwell    time.Duration // 3 s: qualification must hold continuously this long
	Cooldown time.Duration // 15 s: minimum time between two quality switches
	Fresh    time.Duration // Probe.Fresh: freshness window used to classify summaries
}

// Selector is the quality-switch state of one dialer selector session: the
// dwell candidate, when its qualification began, and the time of the last
// quality switch. It is a value type owned by the session actor.
type Selector struct {
	p SelectorParams
	// unexported state is defined by the implementation.
}

// NewSelector returns a selector with no candidate and no previous quality
// switch: the first quality switch needs no cooldown (design decision D7).
func NewSelector(p SelectorParams) Selector { return Selector{p: p} }

// Verdict is the result of one evaluation.
type Verdict struct {
	Switch bool      // start a planned switch to factory To now
	To     int       // target factory index (valid when Switch)
	Wake   time.Time // evaluate again at this time even without new evidence; zero = never
}

// Evaluate applies the quality rule at now. active is the active factory;
// sum and failed are indexed by factory; summaries are classified with
// Classify(·, now, Fresh). The challenger is the best-ranked factory other
// than active that is not failed and is EvFresh (Unknown, Stale and Held
// evidence never challenge: L28). It qualifies iff
//   - active is EvFresh, or EvHeld with RTT > 0 (compared by its held
//     value): ch.RTT ≤ act.RTT×(1−Band) and act.RTT − ch.RTT ≥ Floor; or
//   - active is EvStale or EvUnknown (a fresh challenger replaces an
//     unmeasured incumbent).
//
// An EvHeld active without a value is never replaced (§8). The same
// challenger must qualify at every evaluation for Dwell; a different
// challenger or a non-qualifying evaluation restarts the dwell. A switch is
// also held back until Cooldown has elapsed since the last quality switch.
// Wake is the earliest of the dwell end, the cooldown end and the next
// ageing change (NextChange) of any factory's evidence.
func (s *Selector) Evaluate(now time.Time, active int, sum []Summary, failed []bool) Verdict {
	panic("unimplemented: M1b")
}

// Switched records that the active factory changed at now. quality reports a
// quality switch (it starts the cooldown); any change clears the dwell
// candidate. Death switches pass quality=false and neither need nor start a
// cooldown (D7).
func (s *Selector) Switched(now time.Time, quality bool) {
	panic("unimplemented: M1b")
}
