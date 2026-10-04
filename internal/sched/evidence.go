package sched

import "time"

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

// Classify returns the evidence of s at now for the freshness window fresh
// (Probe.Fresh): Unknown if !s.Seen; Fresh if now − s.At ≤ fresh; else Held
// if now − s.LoadedAt ≤ fresh; else Stale.
func Classify(s Summary, now time.Time, fresh time.Duration) Evidence {
	panic("unimplemented: M1b")
}

// NextChange returns the earliest time after now at which Classify(s, ·,
// fresh) changes by ageing alone (s.At + fresh or s.LoadedAt + fresh), or the
// zero time if it never will.
func NextChange(s Summary, now time.Time, fresh time.Duration) time.Time {
	panic("unimplemented: M1b")
}

// Aggregator keeps the last Window unloaded probe RTT samples of one factory
// and detects level shifts (plan §4). It is a value type owned by exactly one
// goroutine (the Peer health layer).
type Aggregator struct {
	p AggParams
	// unexported state (ring, counters, timestamps) is defined by the implementation.
}

// NewAggregator returns an empty aggregator.
func NewAggregator(p AggParams) Aggregator { return Aggregator{p: p} }

// Reset empties the window: a new probe-carrier incarnation starts Unknown
// (L23). Counters are kept.
func (a *Aggregator) Reset() {
	panic("unimplemented: M1b")
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
	panic("unimplemented: M1b")
}

// Summary returns the current time-independent state.
func (a *Aggregator) Summary() Summary {
	panic("unimplemented: M1b")
}

// Counts returns the number of accepted unloaded and loaded samples and of
// level shifts since construction.
func (a *Aggregator) Counts() (unloaded, loaded, shifts uint64) {
	panic("unimplemented: M1b")
}
