package carrier

import (
	"context"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/sched"
)

// HealthParams configures the Peer health layer (plan §3.9).
type HealthParams struct {
	Interval      time.Duration   // Probe.Interval: probe PING cadence
	Fresh         time.Duration   // Probe.Fresh
	BackoffMax    time.Duration   // Probe.BackoffMax: probe redial cadence cap
	DialWait      time.Duration   // Probe.DialWait: WaitFirst bound
	IdleStop      time.Duration   // probing stops after this long without Use or a live session (5 min)
	LoadThreshold int64           // self-load threshold (64 KiB)
	Agg           sched.AggParams // evidence aggregator knobs
	Rand          func() float64  // jitter source U[0,1)
}

// Health is the Peer health layer: for a Peer with ≥ 2 factories, one
// goroutine that keeps one probe carrier per factory (PING every
// Interval), feeds probe samples (tagged loaded via the factory's Gauge)
// into one sched.Aggregator per factory, keeps failed marks, and publishes
// an immutable Snapshot through an atomic pointer. A single-factory Health
// is inert: no goroutine, no probe carrier, WaitFirst returns at once.
type Health struct {
	_ struct{} // unexported state is defined by the implementation
}

// NewHealth returns a Health for the Peer's factories; nothing runs until Use.
func NewHealth(env *Env, factories []Factory, p HealthParams) *Health {
	panic("unimplemented: M1b")
}

// Gauges returns one Gauge per factory (stable for the Peer's lifetime;
// nil for a single-factory Peer).
func (h *Health) Gauges() []*Gauge {
	panic("unimplemented: M1b")
}

// Use records that a Dial is starting: (re)start probing and reset the idle
// stop. No-op on an inert or closed Health.
func (h *Health) Use() {
	panic("unimplemented: M1b")
}

// Hold keeps probing alive while a session of this Peer lives; release is
// idempotent.
func (h *Health) Hold() (release func()) {
	panic("unimplemented: M1b")
}

// WaitFirst waits for the first batch of probe evidence (plan §3.9). It
// returns at once when every factory already has a sample or a failure
// since probing last (re)started, or when Probe.DialWait has already passed
// since that (re)start; otherwise it returns when one of those holds or ctx
// ends. Only Dials during a cold start (or a restart after IdleStop) can
// therefore wait, never longer than DialWait; steady-state Dials do not.
// Immediate on an inert or closed Health.
func (h *Health) WaitFirst(ctx context.Context) {
	panic("unimplemented: M1b")
}

// Snapshot returns the current immutable snapshot (lock-free).
func (h *Health) Snapshot() *Snapshot {
	panic("unimplemented: M1b")
}

// Subscribe rings b after every published snapshot (coalesced) until cancel
// is called.
func (h *Health) Subscribe(b Doorbell) (cancel func()) {
	panic("unimplemented: M1b")
}

// MarkFailed sets factory i's failed mark (a session carrier of i died).
// The mark only demotes i in the ranking; it never blocks a dial (plan §3.9).
func (h *Health) MarkFailed(i int, reason string) {
	panic("unimplemented: M1b")
}

// Succeeded clears factory i's failed mark: any dial on i completed the
// PREFACE exchange (plan §3.6).
func (h *Health) Succeeded(i int) {
	panic("unimplemented: M1b")
}

// Close stops probing, retires the probe carriers and joins the health
// goroutine and the probe attempts (bounded). Idempotent.
func (h *Health) Close() {
	panic("unimplemented: M1b")
}

// Snapshot is an immutable view of a Peer's evidence. Summaries are
// time-independent; consumers classify them at their own now with
// sched.Classify(sum, now, Fresh), so published evidence ages into Stale
// without a new publication.
type Snapshot struct {
	Version uint64          // increases with every publication
	Probing bool            // the health goroutine runs
	Fresh   time.Duration   // Probe.Fresh
	Sum     []sched.Summary // per factory
	Failed  []bool          // per factory
	Info    []FactoryInfo   // per factory, for PeerStatus
}

// Evidence classifies factory i at now.
func (s *Snapshot) Evidence(i int, now time.Time) sched.Evidence {
	return sched.Classify(s.Sum[i], now, s.Fresh)
}

// FactoryInfo carries the PeerStatus counters of one factory.
type FactoryInfo struct {
	Samples, LoadedSamples, Attempts uint64
	FailReason                       string
	ProbeCarrier                     uint32 // 0 when none
}
