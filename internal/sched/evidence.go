package sched

import (
	"math"
	"time"
)

// MaxAggWindow bounds AggParams.Window (the ring is a fixed array).
const MaxAggWindow = 64

// AggParams configures the evidence aggregator (plan §4). These are the G9
// tuning knobs; Band, Floor, Dwell and Cooldown are owner-fixed and live in
// SelectorParams.
type AggParams struct {
	Window     int           // samples averaged (32); 1..MaxAggWindow
	MinEarlier int           // earlier samples needed before a level shift can be declared (3)
	ShiftRun   int           // newest samples that must deviate in the same direction (2)
	SigmaK     float64       // deviation threshold in standard deviations (3)
	SigmaFloor time.Duration // lower bound of the earlier samples' standard deviation (2 ms)
}

// DefaultAggParams returns the plan §4 aggregator parameters.
func DefaultAggParams() AggParams {
	return AggParams{Window: 32, MinEarlier: 3, ShiftRun: 2, SigmaK: 3, SigmaFloor: 2 * time.Millisecond}
}

// normalized replaces every unset (zero) or invalid field with its default
// and bounds Window by MaxAggWindow. A zero field keeps the default, as
// testhooks.Overrides documents for the aggregator knobs.
func (p AggParams) normalized() AggParams {
	d := DefaultAggParams()
	switch {
	case p.Window <= 0:
		p.Window = d.Window
	case p.Window > MaxAggWindow:
		p.Window = MaxAggWindow
	}
	if p.MinEarlier <= 0 {
		p.MinEarlier = d.MinEarlier
	}
	if p.ShiftRun <= 0 {
		p.ShiftRun = d.ShiftRun
	}
	if !(p.SigmaK > 0) || math.IsInf(p.SigmaK, 0) { // also rejects NaN
		p.SigmaK = d.SigmaK
	}
	if p.SigmaFloor <= 0 {
		p.SigmaFloor = d.SigmaFloor
	}
	return p
}

// Summary is the time-independent state of one factory's aggregator; it is
// what the health layer publishes. Classify turns it into Evidence at a
// given time, so published evidence ages correctly without republication.
type Summary struct {
	Seen     bool          // any sample (loaded or not) since the last Reset
	Mean     time.Duration // mean of the unloaded window; valid when N > 0
	N        int           // unloaded samples in the window
	At       time.Time     // newest unloaded sample (zero if none)
	LoadedAt time.Time     // newest loaded sample (zero if none)
}

// EvState classifies a factory's evidence at a point in time.
type EvState uint8

// Evidence states.
const (
	// EvUnknown: no sample since the probe incarnation started (Reset).
	EvUnknown EvState = iota
	// EvFresh: the newest unloaded sample is within Fresh; RTT is the window mean.
	EvFresh
	// EvHeld: no unloaded sample within Fresh, but a loaded one is: the path is
	// alive and loaded by this Peer's own sessions (§8). RTT is the window
	// mean of earlier unloaded samples, or 0 if there were none ("protected
	// without a value").
	EvHeld
	// EvStale: samples were seen, none (loaded or not) within Fresh.
	EvStale
)

// String returns "unknown", "fresh", "held" or "stale".
func (s EvState) String() string {
	switch s {
	case EvFresh:
		return "fresh"
	case EvHeld:
		return "held"
	case EvStale:
		return "stale"
	}
	return "unknown"
}

// Evidence is a factory's classified evidence at one instant.
type Evidence struct {
	State EvState
	RTT   time.Duration // EvFresh: window mean; EvHeld: window mean or 0; otherwise 0
}

// valued reports whether s carries an unloaded RTT value. A summary that
// claims a recent sample but holds no positive mean is zero-sample evidence
// and never counts as a measurement (L28: an unmeasured RTT must not read as
// 0, "infinitely fast").
func valued(s Summary) bool {
	return s.N > 0 && s.Mean > 0 && !s.At.IsZero()
}

// within reports whether t is set and at most fresh before now (inclusive).
func within(now, t time.Time, fresh time.Duration) bool {
	return !t.IsZero() && now.Sub(t) <= fresh
}

// Classify returns the evidence of s at now for the freshness window fresh
// (Probe.Fresh): Unknown if !s.Seen; Fresh if now − s.At ≤ fresh; else Held
// if now − s.LoadedAt ≤ fresh; else Stale.
//
// A summary without a positive window mean (N = 0 or Mean ≤ 0, which no
// Aggregator produces) is zero-sample evidence: never Fresh, and Held only
// without a value (L28).
func Classify(s Summary, now time.Time, fresh time.Duration) Evidence {
	if !s.Seen {
		return Evidence{State: EvUnknown}
	}
	if valued(s) && within(now, s.At, fresh) {
		return Evidence{State: EvFresh, RTT: s.Mean}
	}
	if within(now, s.LoadedAt, fresh) {
		ev := Evidence{State: EvHeld}
		if valued(s) {
			ev.RTT = s.Mean
		}
		return ev
	}
	return Evidence{State: EvStale}
}

// NextChange returns the earliest time after now at which Classify(s, ·,
// fresh) changes by ageing alone (s.At + fresh or s.LoadedAt + fresh), or the
// zero time if it never will.
//
// Classify's freshness bound is inclusive, so the class first differs one
// nanosecond after each boundary; that instant is returned, which lets a
// timer armed at the result observe the change instead of re-arming at the
// same boundary forever.
func NextChange(s Summary, now time.Time, fresh time.Duration) time.Time {
	if !s.Seen {
		return time.Time{}
	}
	var c [2]time.Time
	n := 0
	if valued(s) {
		c[n] = s.At.Add(fresh).Add(1)
		n++
	}
	if !s.LoadedAt.IsZero() {
		c[n] = s.LoadedAt.Add(fresh).Add(1)
		n++
	}
	if n == 2 && c[1].Before(c[0]) {
		c[0], c[1] = c[1], c[0]
	}
	cur := Classify(s, now, fresh)
	// Classify is piecewise constant between these breakpoints, so the first
	// breakpoint after now whose class differs is the next change.
	for i := 0; i < n; i++ {
		if c[i].After(now) && Classify(s, c[i], fresh) != cur {
			return c[i]
		}
	}
	return time.Time{}
}

// Aggregator keeps the last Window unloaded probe RTT samples of one factory
// and detects level shifts (plan §4). It is a value type owned by exactly one
// goroutine (the Peer health layer).
type Aggregator struct {
	p AggParams

	ring     [MaxAggWindow]time.Duration // unloaded window; ring[(head+i)%p.Window], i = 0 is the oldest
	head     int                         // ring index of the oldest sample
	n        int                         // samples in the window
	seen     bool                        // any accepted sample since the last Reset
	last     time.Time                   // newest accepted sample (loaded or not)
	at       time.Time                   // newest unloaded sample
	loadedAt time.Time                   // newest loaded sample

	unloaded, loaded, shifts uint64 // since construction; Reset keeps them
}

// NewAggregator returns an empty aggregator. Zero or invalid parameters take
// their DefaultAggParams values; Window is bounded by MaxAggWindow.
func NewAggregator(p AggParams) Aggregator { return Aggregator{p: p.normalized()} }

// Reset empties the window: a new probe-carrier incarnation starts Unknown
// (L23). Counters are kept.
func (a *Aggregator) Reset() {
	a.head, a.n = 0, 0
	a.seen = false
	a.last, a.at, a.loadedAt = time.Time{}, time.Time{}, time.Time{}
}

// Add records one sample taken at at (PONG arrival) with rtt measured from
// the PING's write commit (L23). It rejects (returns false) a zero at, a
// non-positive rtt and an at earlier than the newest accepted sample (L28).
// A loaded sample (§8) only refreshes LoadedAt and the loaded counter: it
// never enters the window and cannot trigger a level shift. An unloaded
// sample enters the ring (the oldest drops out beyond Window); when at least
// MinEarlier earlier samples exist and the newest ShiftRun samples all
// deviate from the earlier samples' mean in the same direction by more than
// SigmaK·max(σ, SigmaFloor) (σ = standard deviation of the earlier samples),
// the earlier samples are discarded and the window restarts from the newest
// ShiftRun.
func (a *Aggregator) Add(at time.Time, rtt time.Duration, loaded bool) bool {
	if a.p.Window <= 0 { // zero value, not built by NewAggregator
		a.p = a.p.normalized()
	}
	if at.IsZero() || rtt <= 0 || at.Before(a.last) {
		return false
	}
	a.last = at
	a.seen = true
	if loaded {
		a.loadedAt = at
		a.loaded++
		return true
	}
	a.at = at
	a.unloaded++
	w := a.p.Window
	if a.n < w {
		a.ring[(a.head+a.n)%w] = rtt
		a.n++
	} else {
		a.ring[a.head] = rtt
		a.head = (a.head + 1) % w
	}
	a.levelShift()
	return true
}

// sample returns the i-th sample of the window, 0 being the oldest.
func (a *Aggregator) sample(i int) float64 {
	return float64(a.ring[(a.head+i)%a.p.Window])
}

// levelShift applies the plan §4 level-shift rule to the current window.
// σ is the sample standard deviation (n − 1) of the earlier samples: with
// as few as MinEarlier of them the population formula would understate the
// spread and declare spurious shifts.
func (a *Aggregator) levelShift() {
	run := a.p.ShiftRun
	e := a.n - run // earlier samples
	if e <= 0 || e < a.p.MinEarlier {
		return
	}
	var sum float64
	for i := 0; i < e; i++ {
		sum += a.sample(i)
	}
	mean := sum / float64(e)
	var ss float64
	for i := 0; i < e; i++ {
		d := a.sample(i) - mean
		ss += d * d
	}
	sigma := 0.0
	if e > 1 {
		sigma = math.Sqrt(ss / float64(e-1))
	}
	if f := float64(a.p.SigmaFloor); sigma < f {
		sigma = f
	}
	thr := a.p.SigmaK * sigma
	up, down := true, true
	for i := e; i < a.n; i++ {
		d := a.sample(i) - mean
		up = up && d > thr
		down = down && d < -thr
	}
	if up || down {
		a.head = (a.head + e) % a.p.Window
		a.n = run
		a.shifts++
	}
}

// Summary returns the current time-independent state.
func (a *Aggregator) Summary() Summary {
	s := Summary{Seen: a.seen, N: a.n, At: a.at, LoadedAt: a.loadedAt}
	if a.n > 0 {
		var sum float64
		for i := 0; i < a.n; i++ {
			sum += a.sample(i)
		}
		s.Mean = time.Duration(math.Round(sum / float64(a.n)))
	}
	return s
}

// Counts returns the number of accepted unloaded and loaded samples and of
// level shifts since construction.
func (a *Aggregator) Counts() (unloaded, loaded, shifts uint64) {
	return a.unloaded, a.loaded, a.shifts
}
