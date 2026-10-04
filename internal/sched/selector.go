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

	cand      int       // dwell candidate factory (valid when hasCand)
	candAct   int       // the active factory the candidate qualified against
	candSince time.Time // start of the candidate's continuous qualification
	hasCand   bool
	lastQual  time.Time // last quality switch (valid when hasQual)
	hasQual   bool      // D7: no quality switch yet → the first needs no cooldown
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
	v := Verdict{Wake: s.ageWake(now, sum)}
	if active < 0 || active >= len(sum) {
		// No active factory to defend: the session is not routing through a
		// quality-managed lane (opening phase, no-path episode). Nothing to do.
		s.hasCand = false
		return v
	}
	act := Classify(sum[active], now, s.p.Fresh)
	ch, chEv, ok := s.challenger(now, active, sum, failed)
	if !ok || !s.qualifies(act, chEv) {
		s.hasCand = false
		return v
	}
	if !s.hasCand || s.cand != ch || s.candAct != active {
		// A new challenger, or the incumbent changed without Switched: the
		// dwell measures continuous qualification against this incumbent.
		s.hasCand, s.cand, s.candAct, s.candSince = true, ch, active, now
	}
	if end := s.candSince.Add(s.p.Dwell); now.Before(end) {
		v.Wake = earlier(v.Wake, end)
		return v
	}
	if s.hasQual {
		if end := s.lastQual.Add(s.p.Cooldown); now.Before(end) {
			v.Wake = earlier(v.Wake, end)
			return v
		}
	}
	v.Switch, v.To = true, ch
	return v
}

// challenger returns the best-ranked non-failed EvFresh factory other than
// active: lowest RTT, ties by index, which is Less restricted to Fresh
// candidates.
func (s *Selector) challenger(now time.Time, active int, sum []Summary, failed []bool) (int, Evidence, bool) {
	best := -1
	var bestEv Evidence
	for i := range sum {
		if i == active || (i < len(failed) && failed[i]) {
			continue
		}
		ev := Classify(sum[i], now, s.p.Fresh)
		if ev.State != EvFresh || ev.RTT <= 0 {
			continue
		}
		if best < 0 || ev.RTT < bestEv.RTT {
			best, bestEv = i, ev
		}
	}
	return best, bestEv, best >= 0
}

// qualifies applies the band and floor to a Fresh challenger ch against the
// active factory's evidence act.
func (s *Selector) qualifies(act, ch Evidence) bool {
	switch act.State {
	case EvFresh, EvHeld:
		if act.RTT <= 0 {
			return false // Held without a value is never replaced (§8)
		}
		return float64(ch.RTT) <= float64(act.RTT)*(1-s.p.Band) && act.RTT-ch.RTT >= s.p.Floor
	}
	return true // Unknown or Stale incumbent: any Fresh challenger replaces it
}

// ageWake is the earliest ageing change of any factory's evidence after now.
func (s *Selector) ageWake(now time.Time, sum []Summary) time.Time {
	var w time.Time
	for i := range sum {
		w = earlier(w, NextChange(sum[i], now, s.p.Fresh))
	}
	return w
}

// earlier returns the earlier of two times, a zero time meaning "never".
func earlier(a, b time.Time) time.Time {
	if a.IsZero() || (!b.IsZero() && b.Before(a)) {
		return b
	}
	return a
}

// Switched records that the active factory changed at now. quality reports a
// quality switch (it starts the cooldown); any change clears the dwell
// candidate. Death switches pass quality=false and neither need nor start a
// cooldown (D7).
func (s *Selector) Switched(now time.Time, quality bool) {
	s.hasCand = false
	if quality {
		s.lastQual, s.hasQual = now, true
	}
}
