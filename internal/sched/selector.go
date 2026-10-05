package sched

import "time"

// maxFactories is the Peer factory limit (1–16 carriers per Peer). The
// selector keeps one dwell clock per factory in fixed arrays, and a race
// never has more candidates.
const maxFactories = 16

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
// dwell candidates (every qualifying challenger, each with the start of its
// continuous qualification against the incumbent) and the time of the last
// quality switch. It is a value type owned by the session actor.
type Selector struct {
	p SelectorParams

	inc      int                     // the incumbent the dwell clocks run against
	qual     uint32                  // bit i: factory i qualified at the latest evaluation
	since    [maxFactories]time.Time // start of factory i's continuous qualification
	seen     [maxFactories]time.Time // factory i's newest unloaded sample at the latest evaluation
	lastQual time.Time               // last quality switch (valid when hasQual)
	hasQual  bool                    // D7: no quality switch yet → the first needs no cooldown

	// class is the kind class per factory (M2-D48; zero for every factory
	// of a stream session). A challenger of a lower class than the active
	// factory qualifies without Band and Floor (still EvFresh, unloaded,
	// with dwell and cooldown): a packet session that fell back to a stream
	// carrier returns to a datagram carrier. A challenger of a higher class
	// never qualifies (Evaluate).
	class [maxFactories]uint8
}

// SetClasses records the kind class of every factory (index i of c is
// factory i; at most 16). A selector whose classes are all 0 — every stream
// session, and every session before this call — behaves as in M1.
func (s *Selector) SetClasses(c []uint8) {
	s.class = [maxFactories]uint8{}
	copy(s.class[:], c)
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
// Classify(·, now, Fresh). A challenger is a factory other than active that
// is not failed, is EvFresh and whose newest sample is unloaded (Unknown,
// Stale and Held evidence never challenge: L28; a path this Peer's own
// sessions are loading is no quality target even while its pre-load value
// is still Fresh: §8.4). Its kind class (SetClasses; M2-D48) is compared
// with the active factory's first. A challenger of a higher class never
// qualifies. A challenger of a lower class qualifies without Band and Floor,
// whatever the active factory's evidence: a packet session that fell back
// to a stream carrier returns to a datagram carrier once one is measured
// healthy. A challenger of the same class qualifies iff
//   - active is EvFresh, or EvHeld with RTT > 0 (compared by its held
//     value): ch.RTT ≤ act.RTT×(1−Band) and act.RTT − ch.RTT ≥ Floor; or
//   - active is EvStale or EvUnknown (a fresh challenger replaces an
//     unmeasured incumbent).
//
// A same-class challenger never replaces an EvHeld active without a value
// (§8). Every challenger has its own dwell: it starts at the first
// evaluation at which the challenger qualifies against this incumbent and
// restarts whenever an evaluation finds it not qualifying, or finds that
// its evidence expired since the previous evaluation (stale evidence never
// extends a dwell, even when the caller missed the ageing Wake: L29). Rank
// changes among qualifying challengers restart nothing, so near-equal
// challengers cannot keep each other's dwell from completing. The switch
// goes to the best-ranked challenger (lowest class, then lowest RTT, ties
// by index: the order of Less) whose own dwell is complete, once Cooldown
// has elapsed since the last quality switch; a class-up switch is a quality
// switch like any other. Wake is the earliest of the next dwell end, the
// cooldown end and the next ageing change (NextChange) of any factory's
// evidence. Factories beyond the 16-factory Peer limit never challenge.
func (s *Selector) Evaluate(now time.Time, active int, sum []Summary, failed []bool) Verdict {
	v := Verdict{Wake: s.ageWake(now, sum)}
	if active < 0 || active >= len(sum) {
		// No active factory to defend: the session is not routing through a
		// quality-managed lane (opening phase, no-path episode). Nothing to do.
		s.qual = 0
		return v
	}
	if active != s.inc {
		// The incumbent changed without Switched: qualification is measured
		// against one incumbent, so every dwell restarts.
		s.qual, s.inc = 0, active
	}
	n := min(len(sum), maxFactories)
	s.qual &= 1<<n - 1 // factories no longer present keep no clock
	act := Classify(sum[active], now, s.p.Fresh)
	actClass := s.classOf(active)
	best := -1
	var bestRTT time.Duration
	var dwellEnd time.Time // earliest end of a dwell still running
	for i := 0; i < n; i++ {
		if i == active {
			continue
		}
		bit := uint32(1) << i
		ev, ok := s.challenger(now, i, sum, failed)
		if !ok || !s.qualifies(act, actClass, ev, s.class[i]) {
			s.qual &^= bit
			continue
		}
		if s.qual&bit == 0 || s.gap(i, sum[i].At) {
			s.qual |= bit
			s.since[i] = now
		}
		s.seen[i] = sum[i].At
		if end := s.since[i].Add(s.p.Dwell); now.Before(end) {
			dwellEnd = earlier(dwellEnd, end)
			continue
		}
		// Best-ranked first (Less among Fresh challengers): lowest class,
		// then lowest RTT; i ascends, so ties keep the lowest index.
		if best < 0 || s.class[i] < s.class[best] || (s.class[i] == s.class[best] && ev.RTT < bestRTT) {
			best, bestRTT = i, ev.RTT
		}
	}
	if best < 0 {
		v.Wake = earlier(v.Wake, dwellEnd)
		return v
	}
	if s.hasQual {
		if end := s.lastQual.Add(s.p.Cooldown); now.Before(end) {
			v.Wake = earlier(v.Wake, end)
			return v
		}
	}
	v.Switch, v.To = true, best
	return v
}

// challenger returns factory i's evidence and whether it may challenge: not
// failed, EvFresh with a positive value, and its newest sample unloaded.
// The last condition is §8.4: when a sibling session starts loading a
// path, Classify keeps reporting its pre-load value as Fresh for up to
// Probe.Fresh, but a path this Peer saturates must not become a quality
// target (ranking for Dial and failover is unaffected).
func (s *Selector) challenger(now time.Time, i int, sum []Summary, failed []bool) (Evidence, bool) {
	if i < len(failed) && failed[i] {
		return Evidence{}, false
	}
	ev := Classify(sum[i], now, s.p.Fresh)
	return ev, ev.State == EvFresh && ev.RTT > 0 && !sum[i].LoadedAt.After(sum[i].At)
}

// gap reports whether factory i's evidence may have been Stale at some
// instant since the previous evaluation, which saw its newest unloaded
// sample at s.seen[i]: the sample now newest (at) arrived only after that
// one had aged out (Classify turns it Stale at seen + Fresh + 1 ns), or it
// is older than the one seen (a new probe incarnation, Reset). A caller
// that evaluates at every Verdict.Wake never sees a gap here, because the
// ageing instant itself clears the challenger; the check keeps a late
// caller from extending a dwell across stale evidence (L29).
func (s *Selector) gap(i int, at time.Time) bool {
	return at.Before(s.seen[i]) || at.After(s.seen[i].Add(s.p.Fresh+1))
}

// classOf returns factory i's kind class; a factory beyond the 16-factory
// Peer limit counts as class 0.
func (s *Selector) classOf(i int) uint8 {
	if i < 0 || i >= maxFactories {
		return 0
	}
	return s.class[i]
}

// qualifies applies the class rule (M2-D48) and then the band and floor to
// a Fresh, unloaded challenger ch of class chClass against the active
// factory's evidence act and class actClass.
func (s *Selector) qualifies(act Evidence, actClass uint8, ch Evidence, chClass uint8) bool {
	switch {
	case chClass > actClass:
		return false // a higher class never qualifies
	case chClass < actClass:
		return true // class-up: no Band, no Floor; dwell and cooldown still apply
	}
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
// quality switch (it starts the cooldown); any change restarts every dwell.
// Death switches pass quality=false and neither need nor start a cooldown
// (D7).
func (s *Selector) Switched(now time.Time, quality bool) {
	s.qual = 0
	if quality {
		s.lastQual, s.hasQual = now, true
	}
}
