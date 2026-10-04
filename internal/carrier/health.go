package carrier

import (
	"context"
	"math"
	"math/rand/v2"
	"sync"
	"sync/atomic"
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
	Rand          func() float64  // jitter source U[0,1); must be safe for concurrent use
}

// Defaults for zero HealthParams fields (plan §4). package rendr always
// fills HealthParams; the defaults only keep a partially filled one (a
// component test) usable. DialWait has none: zero means "never wait"
// (Probe.DialWait ranges over 0–5 s).
const (
	defProbeFresh      = 10 * time.Second
	defProbeBackoffMax = 4 * time.Second
	defProbeIdleStop   = 5 * time.Minute
	defLoadThreshold   = 64 << 10
)

// withDefaults returns p with every zero or negative field replaced by its
// default (the aggregator normalizes its own knobs).
func (p HealthParams) withDefaults() HealthParams {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&p.Interval, defProbeInterval)
	def(&p.Fresh, defProbeFresh)
	def(&p.BackoffMax, defProbeBackoffMax)
	def(&p.IdleStop, defProbeIdleStop)
	if p.DialWait < 0 {
		p.DialWait = 0
	}
	if p.LoadThreshold <= 0 {
		p.LoadThreshold = defLoadThreshold
	}
	if p.Rand == nil {
		p.Rand = rand.Float64
	}
	return p
}

// Health is the Peer health layer: for a Peer with ≥ 2 factories, one
// goroutine that keeps one probe carrier per factory (PING every
// Interval), feeds probe samples (tagged loaded via the factory's Gauge)
// into one sched.Aggregator per factory, keeps failed marks, and publishes
// an immutable Snapshot through an atomic pointer. A single-factory Health
// is inert: no goroutine, no probe carrier, WaitFirst returns at once.
//
// Concurrency (design §3.2, §7.8): every mutable field lives under mu, a
// leaf lock: nothing else is locked and no conn or factory is called while
// it is held (the conn methods used under it — ID, Factory, Death,
// PeerGoAway — are lock-free). Probing runs on one goroutine per run (a
// run is one stretch of probing between a (re)start by Use or Hold and the
// idle stop or Close); probe attempts run on their own goroutines and post
// their results under mu; probe carriers report PING commits and PONGs
// through the PingObserver on their own goroutines (also under mu, never
// blocking). Every state change publishes a new Snapshot before mu is
// released, so a caller that changed a mark reads it back at once (the
// death step ranks the dead factory last right after MarkFailed, §7.3).
type Health struct {
	env      *Env          // the probe carriers' Env: the Runtime's, with Timing.ProbeInterval = Interval
	p        HealthParams  // with defaults
	facs     []Factory     // the Peer's factories; Index is the position
	gauges   []*Gauge      // one per factory; nil when inert
	inert    bool          // fewer than 2 factories: nothing is probed
	obs      PingObserver  // this Health as the probe carriers' observer
	closedCh chan struct{} // closed by Close (releases WaitFirst)

	snap atomic.Pointer[Snapshot]

	mu      sync.Mutex
	closed  bool
	run     *healthRun   // the current run; nil while not probing
	runs    []*healthRun // every run whose goroutine has not exited (Close joins them)
	holds   int          // live sessions (Hold)
	lastUse time.Time    // latest Use, Hold or release
	fac     []factoryState
	subs    map[*healthSub]struct{}
	version uint64
}

// factoryState is one factory's evidence, mark and counters (under
// Health.mu). It outlives runs: a restart keeps the counters and the marks;
// a new probe incarnation resets the aggregator and its PING records (L23).
type factoryState struct {
	agg   sched.Aggregator
	conn  *Conn // the current probe incarnation (nil: none); the observer ignores every other Conn
	pings [pingRingSize]probePing
	pHead int
	pN    int
	early probeEarly // a PONG that overtook its PingCommitted callback; reset per incarnation

	failed   bool
	reason   string
	markAt   time.Time // when the mark was (last) set
	attempts uint64    // probe attempts started
	first    bool      // WaitFirst: a sample or a failure since the current run started

	// The gauge's volume counters at the latest probe PING commit of any
	// incarnation (volAt zero: none yet): the start of the interval over
	// which the next PING measures the level before its flight.
	volAt        time.Time
	volTx, volRx uint64
}

// probePing is the gauge state when one probe PING was committed (§8.2).
type probePing struct {
	id     uint32
	loaded bool   // the gauge was loaded at the commit
	epoch  uint64 // the gauge epoch at the commit
	tx, rx uint64 // the gauge's volume counters at the commit
	// idle is how long no DATA had moved at the commit, calm how long no
	// carrier had been backlogged (0: one was); forever: never.
	idle, calm time.Duration
	// prior is the DATA (both directions) the factory's session carriers
	// moved from the previous probe PING commit to this one, over priorSpan
	// (zero: no previous commit).
	prior     uint64
	priorSpan time.Duration
}

// forever is probePing.idle and .calm when the event never happened.
const forever = time.Duration(math.MaxInt64)

// since returns how long before at the event at t happened: forever for a
// zero t, 0 for a t after at (a reading taken a moment after at).
func since(at, t time.Time) time.Duration {
	if t.IsZero() {
		return forever
	}
	return max(at.Sub(t), 0)
}

// probeEarly is a matched probe PONG that arrived before its PING's
// PingCommitted callback. The carrier writer makes a PING's PONG matchable
// (it records the commit under Conn.mu) before it calls PingCommitted, so
// on a path faster than that gap the reader reports the PONG first. Its
// sample waits for the callback, which always follows the commit, so the
// commit-time gauge state still tags it (§8.2). Such a flight is shorter
// than the callback's own delay: the volume rule never applies to it.
type probeEarly struct {
	ok     bool
	id     uint32
	rtt    time.Duration
	at     time.Time
	loaded bool   // the gauge was loaded at the arrival
	epoch  uint64 // the gauge epoch at the arrival
}

// pushPing records a committed PING (FIFO; the oldest goes when full, as
// the carrier never keeps more than pingRingSize PINGs outstanding).
func (f *factoryState) pushPing(p probePing) {
	if f.pN == len(f.pings) {
		f.pHead = (f.pHead + 1) % len(f.pings)
		f.pN--
	}
	f.pings[(f.pHead+f.pN)%len(f.pings)] = p
	f.pN++
}

// takePing removes the record of PING id and every older one (a PONG
// answers its PING and, on a FIFO stream, every PING before it).
func (f *factoryState) takePing(id uint32) (probePing, bool) {
	for k := range f.pN {
		p := f.pings[(f.pHead+k)%len(f.pings)]
		if p.id == id {
			f.pHead = (f.pHead + k + 1) % len(f.pings)
			f.pN -= k + 1
			return p, true
		}
	}
	return probePing{}, false
}

// healthSub is one Subscribe registration.
type healthSub struct{ b Doorbell }

// NewHealth returns a Health for the Peer's factories; nothing runs until Use.
func NewHealth(env *Env, factories []Factory, p HealthParams) *Health {
	p = p.withDefaults()
	penv := *env
	penv.Timing.ProbeInterval = p.Interval
	if penv.IDs == nil { // a component test's Env: probe attempts still need CarrierIDs
		penv.IDs = NewIDAllocator(0)
	}
	n := len(factories)
	h := &Health{
		env:      &penv,
		p:        p,
		facs:     make([]Factory, n),
		inert:    n < 2,
		closedCh: make(chan struct{}),
		fac:      make([]factoryState, n),
		subs:     make(map[*healthSub]struct{}),
	}
	h.obs = healthObserver{h}
	for i, f := range factories {
		f.Index = i
		h.facs[i] = f
		h.fac[i].agg = sched.NewAggregator(p.Agg)
	}
	if !h.inert {
		h.gauges = make([]*Gauge, n)
		for i := range h.gauges {
			h.gauges[i] = NewGauge()
		}
	}
	h.mu.Lock()
	h.publishLocked()
	h.mu.Unlock()
	return h
}

// Gauges returns one Gauge per factory (stable for the Peer's lifetime;
// nil for a single-factory Peer).
func (h *Health) Gauges() []*Gauge {
	return h.gauges
}

// Use records that a Dial is starting: (re)start probing and reset the idle
// stop. No-op on an inert or closed Health.
func (h *Health) Use() {
	if h.inert {
		return
	}
	now := time.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.touchLocked(now)
	if h.run == nil {
		h.startRunLocked(now)
	}
}

// Hold keeps probing alive while a session of this Peer lives; release is
// idempotent. Probing (re)starts if it was not running, and the idle stop
// counts from the last release (or Use, whichever is later).
func (h *Health) Hold() (release func()) {
	if h.inert {
		return func() {}
	}
	now := time.Now()
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return func() {}
	}
	h.holds++
	h.touchLocked(now)
	if h.run == nil {
		h.startRunLocked(now)
	}
	h.mu.Unlock()
	var once sync.Once
	return func() { once.Do(h.release) }
}

// release ends one Hold; the run re-arms its idle stop.
func (h *Health) release() {
	now := time.Now()
	h.mu.Lock()
	h.holds--
	h.touchLocked(now)
	r := h.run
	h.mu.Unlock()
	if r != nil {
		r.bell.Ring()
	}
}

func (h *Health) touchLocked(now time.Time) {
	if now.After(h.lastUse) {
		h.lastUse = now
	}
}

// WaitFirst waits for the first batch of probe evidence (plan §3.9). It
// returns at once when every factory already has a sample or a failure
// since probing last (re)started, or when Probe.DialWait has already passed
// since that (re)start; otherwise it returns when one of those holds or ctx
// ends. Only Dials during a cold start (or a restart after IdleStop) can
// therefore wait, never longer than DialWait; steady-state Dials do not.
// Immediate on an inert or closed Health.
func (h *Health) WaitFirst(ctx context.Context) {
	if h.inert {
		return
	}
	now := time.Now()
	h.mu.Lock()
	r := h.run
	if h.closed || r == nil || r.firstClosed {
		h.mu.Unlock()
		return
	}
	wait := r.started.Add(h.p.DialWait).Sub(now)
	first := r.first
	h.mu.Unlock()
	if wait <= 0 {
		return
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-first:
	case <-t.C:
	case <-ctx.Done():
	case <-h.closedCh:
	}
}

// Snapshot returns the current immutable snapshot (lock-free).
func (h *Health) Snapshot() *Snapshot {
	return h.snap.Load()
}

// Subscribe rings b after every published snapshot (coalesced) until cancel
// is called. Ring runs with the Health's lock held: per the Doorbell
// contract it must not block, and it must not call back into Health.
// cancel is idempotent; once it returned, b is never rung again.
func (h *Health) Subscribe(b Doorbell) (cancel func()) {
	s := &healthSub{b: b}
	h.mu.Lock()
	h.subs[s] = struct{}{}
	h.mu.Unlock()
	return func() {
		h.mu.Lock()
		delete(h.subs, s)
		h.mu.Unlock()
	}
}

// MarkFailed sets factory i's failed mark (a session carrier of i died).
// The mark only demotes i in the ranking; it never blocks a dial (plan §3.9).
// The mark is in the snapshot when MarkFailed returns. It is cleared by
// Succeeded, by a probe dial of i that started after the mark, or by a
// probe PONG whose PING was committed after the mark (a round trip that
// happened after the failure; plan §3.9 "标记之后的下一个成功 PING/PONG").
func (h *Health) MarkFailed(i int, reason string) {
	now := time.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	if i < 0 || i >= len(h.fac) {
		return
	}
	h.markLocked(i, reason, now)
	h.publishLocked()
}

// Succeeded clears factory i's failed mark: any dial on i completed the
// PREFACE exchange (plan §3.6).
func (h *Health) Succeeded(i int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if i < 0 || i >= len(h.fac) || !h.fac[i].failed {
		return
	}
	h.clearLocked(i)
	h.publishLocked()
}

// Close stops probing, retires the probe carriers and joins the health
// goroutine and the probe attempts (bounded). Idempotent.
//
// Bounds (design §3.1, §6.8 steps 4 and 7): probe carriers retire with
// CLOSE; those whose CLOSE is still unwritten after min(1 s, DeadMax) are
// killed, and every carrier's Done is itself bounded (a goroutine stuck in
// an embedder call is abandoned after AbandonWait); attempts are cancelled
// (GuardedDial and Establish count their own stuck helper goroutines) and
// one whose goroutine is itself still inside an embedder call
// 2·AbandonWait after the cancellation is counted in Env.Abandon. Every
// account is settled when Close returns. Concurrent calls all return after
// the joins.
func (h *Health) Close() {
	h.mu.Lock()
	if !h.closed {
		h.closed = true
		close(h.closedCh)
		h.run = nil
		for _, r := range h.runs {
			r.stopLocked()
		}
		h.publishLocked()
	}
	runs := append([]*healthRun(nil), h.runs...)
	h.mu.Unlock()
	for _, r := range runs {
		<-r.done
	}
}

// markLocked sets factory i's failed mark at now; a failure is first
// evidence for WaitFirst.
func (h *Health) markLocked(i int, reason string, now time.Time) {
	f := &h.fac[i]
	f.failed, f.reason, f.markAt = true, reason, now
	h.noteFirstLocked(i)
}

func (h *Health) clearLocked(i int) {
	f := &h.fac[i]
	f.failed, f.reason, f.markAt = false, "", time.Time{}
}

// noteFirstLocked records first evidence of factory i for the current run.
// Once every factory has some, the next publication releases WaitFirst:
// after the snapshot that holds the evidence is stored, never before, so a
// Dial woken by it ranks with that evidence (Snapshot is lock-free).
// Every caller publishes afterwards.
func (h *Health) noteFirstLocked(i int) {
	r := h.run
	if r == nil || r.firstClosed {
		return
	}
	h.fac[i].first = true
	for j := range h.fac {
		if !h.fac[j].first {
			return
		}
	}
	r.firstDue = true
}

// publishLocked stores a new immutable snapshot and rings the subscribers.
// Summaries are time-independent (D25): consumers classify them at their
// own now, so evidence ages into Stale without a new publication.
func (h *Health) publishLocked() {
	h.version++
	n := len(h.fac)
	s := &Snapshot{
		Version: h.version,
		Probing: h.run != nil,
		Fresh:   h.p.Fresh,
		Sum:     make([]sched.Summary, n),
		Failed:  make([]bool, n),
		Info:    make([]FactoryInfo, n),
	}
	for i := range h.fac {
		f := &h.fac[i]
		s.Sum[i] = f.agg.Summary()
		s.Failed[i] = f.failed
		unloaded, loaded, _ := f.agg.Counts()
		s.Info[i] = FactoryInfo{Samples: unloaded + loaded, LoadedSamples: loaded, Attempts: f.attempts, FailReason: f.reason}
		if f.conn != nil {
			s.Info[i].ProbeCarrier = f.conn.ID()
		}
	}
	h.snap.Store(s)
	if r := h.run; r != nil && r.firstDue {
		r.closeFirstLocked()
	}
	for sub := range h.subs {
		sub.b.Ring()
	}
}

// healthObserver is the PingObserver of a Health's probe carriers. Its
// callbacks run on the carrier's writer (PingCommitted) and reader (Pong)
// goroutines; they take only the Health's leaf lock and never block (V16).
type healthObserver struct{ h *Health }

func (o healthObserver) PingCommitted(c *Conn, id uint32, at time.Time) {
	o.h.pingCommitted(c, id, at)
}

func (o healthObserver) Pong(c *Conn, id uint32, rtt time.Duration, at time.Time) {
	o.h.pong(c, id, rtt, at)
}

// pingCommitted records the factory gauge's state at the commit (at) of
// probe PING id (§8.2) — its load state and, for volumeLoaded, its volume
// counters, how long no DATA had moved and no carrier had been backlogged,
// and the DATA moved since the previous probe PING commit — or completes
// the sample of a PONG that overtook this callback. Callbacks of an
// incarnation that is no longer current change nothing (L21, L23).
func (h *Health) pingCommitted(c *Conn, id uint32, at time.Time) {
	i := c.Factory()
	if i < 0 || i >= len(h.gauges) {
		return
	}
	g := h.gauges[i].read(h.p.LoadThreshold)
	h.mu.Lock()
	defer h.mu.Unlock()
	f := &h.fac[i]
	if f.conn != c {
		return
	}
	rec := probePing{id: id, loaded: g.loaded, epoch: g.epoch, tx: g.tx, rx: g.rx, idle: since(at, g.movedAt), calm: since(at, g.calmAt)}
	if g.backlogged {
		rec.calm = 0
	}
	if !f.volAt.IsZero() {
		rec.prior, rec.priorSpan = grown(g.tx, f.volTx)+grown(g.rx, f.volRx), at.Sub(f.volAt)
	}
	f.volAt, f.volTx, f.volRx = at, g.tx, g.rx
	if e := f.early; e.ok && e.id == id {
		f.early = probeEarly{}
		h.sampleLocked(i, e.at, e.rtt, e.loaded || g.loaded || e.epoch != g.epoch)
		return
	}
	f.pushPing(rec)
}

// pong turns a matched probe PONG into a sample (design §7.8, §8.2). at is
// the reader goroutine's own clock reading at the PONG's arrival (W12: a
// future stamp is impossible), rtt counts from the PING's write commit
// (L23). The sample is loaded when the factory's gauge was loaded at the
// commit or at the arrival, or its epoch changed in between (a load episode
// shorter than one probe RTT), or by the volume rule (volumeLoaded: the
// Peer's traffic rose during the flight faster than the gauge could see
// it). A PONG of an incarnation that is no longer current gives nothing
// (L21, L23). A PONG without its commit record overtook its PingCommitted
// callback: the sample waits for it (probeEarly).
//
// A round trip shorter than the clock's resolution measures 0 (Windows'
// monotonic clock advances in steps of about 0.3–0.5 ms, so a loopback or
// LAN probe usually reads 0; so does a zero-delay link in a synctest
// bubble). It is still a round trip: it counts as 1 ns, because
// sched.Aggregator rejects a zero RTT as untimed, which would leave such a
// path without evidence for good and make every cold-start Dial wait the
// whole Probe.DialWait.
func (h *Health) pong(c *Conn, id uint32, rtt time.Duration, at time.Time) {
	rtt = max(rtt, time.Nanosecond)
	i := c.Factory()
	if i < 0 || i >= len(h.gauges) {
		return
	}
	g := h.gauges[i].read(h.p.LoadThreshold)
	h.mu.Lock()
	defer h.mu.Unlock()
	f := &h.fac[i]
	if f.conn != c {
		return
	}
	rec, ok := f.takePing(id)
	if !ok {
		f.early = probeEarly{ok: true, id: id, rtt: rtt, at: at, loaded: g.loaded, epoch: g.epoch}
		return
	}
	loaded := g.loaded || rec.loaded || rec.epoch != g.epoch ||
		h.volumeLoaded(&rec, grown(g.tx, rec.tx)+grown(g.rx, rec.rx), rtt)
	h.sampleLocked(i, at, rtt, loaded)
}

// grown returns how far a volume counter grew from then to now. The two
// readings come from different goroutines (the probe carrier's writer at
// the commit, its reader at the arrival) and are taken before Health.mu, so
// a PONG that raced its PingCommitted callback can carry the earlier
// reading: that counts as no growth.
func grown(now, then uint64) uint64 {
	if now < then {
		return 0
	}
	return now - then
}

// volumeLoaded is the volume rule of the self-load guard (design §8.2,
// added for §0.13 A7a): a probe sample is also loaded when the factory's
// session carriers moved at least LoadThreshold of DATA, both directions
// together, between its PING's commit and its PONG's arrival (moved),
// unless that traffic was established before the commit (established).
//
// The volume covers what the instantaneous rule cannot see yet. A download
// that starts at a probe PING's commit queues the PONG behind the passive's
// first burst (its capacity), yet when the PONG arrives the dialer's gauge
// still shows nothing: no forward bytes in flight, a reverse bound of 0
// (rxRate is refreshed only when the session carrier's own PONG arrives,
// behind the same burst) and no backlog (the passive's first BUSY PING is
// still on its way). The burst itself reached the dialer before the PONG,
// so the moved volume is at least the burst. Light interactive traffic
// stays far below the threshold (G2, G9: 1 KiB each way every 100 ms moves
// a few KiB in a 20–100 ms flight) and follows the instantaneous rule
// alone. LoadThreshold = MaxInt64 disables this rule with the rest of the
// guard.
func (h *Health) volumeLoaded(rec *probePing, moved uint64, rtt time.Duration) bool {
	return moved >= uint64(h.p.LoadThreshold) && !h.established(rec, rtt)
}

// established reports that the traffic before probe PING rec's commit was
// application-limited traffic the instantaneous rule had already
// classified (§8.1 item 2), so the volume rule leaves the sample to it. A
// fixed rate moves more per flight as the RTT grows, so without this
// exception every sample of an echo of 256 KiB/s on a path whose RTT rose
// to 300 ms (77 KiB each way per flight, never backlogged) would be loaded
// and the selector could never leave the path. Bursty traffic needs it too:
// while an application sends a 64 KiB message every second, every sample
// whose flight a message overlaps would be loaded — all of them when the
// message period divides Probe.Interval.
//
// The traffic is established when the session carriers moved DATA since
// the previous probe PING commit (prior, over priorSpan), none of them was
// backlogged at the commit or within one flight (rtt) before it, and either
//   - regular: at least LoadThreshold moved and none of them was backlogged
//     since the previous commit, however bursty the traffic; or
//   - steady: at the rate it moved, L = prior/priorSpan, one flight carries
//     at least LoadThreshold (L·rtt) and the carriers had not been silent
//     at the commit for as long as LoadThreshold takes at that rate
//     (L·idle), a continuous flow that may have hit its capacity cap now
//     and then (a capacity that gets no BUSY sample decays).
//
// A transfer that restarts after a pause behind a saturating one is not
// established: its predecessor was backlogged in the interval (not
// regular), and the restart came either after a silence as long as
// LoadThreshold takes at that rate (not steady) or within one flight of the
// predecessor's backlog report clearing. Traffic that rises from a trickle
// is not established either. Known gaps: a transfer that starts at a probe
// PING while unbacklogged traffic of at least LoadThreshold per probe
// interval flows on the same factory still gets an unloaded sample (§8.4);
// and with a Probe.Interval shorter than the RTT, an echo whose reverse
// direction falls silent for one RTT after the RTT rose loses a sample or
// two to the volume rule.
func (h *Health) established(rec *probePing, rtt time.Duration) bool {
	if rec.prior == 0 || rec.calm < rtt {
		return false
	}
	thr := uint64(h.p.LoadThreshold)
	if rec.priorSpan <= 0 || (rec.prior >= thr && rec.calm >= rec.priorSpan) {
		return true // regular (or no time base to judge it: the instantaneous rule decides)
	}
	p, span, t := float64(rec.prior), float64(rec.priorSpan), float64(thr)
	return p*float64(rtt) >= t*span && p*float64(rec.idle) < t*span // steady
}

// sampleLocked adds one probe sample of factory i and publishes the
// change. A sample whose PING was committed (at − rtt) after the failed mark
// clears it: a round trip that happened after the failure (plan §3.9).
func (h *Health) sampleLocked(i int, at time.Time, rtt time.Duration, loaded bool) {
	f := &h.fac[i]
	changed := false
	if f.failed && !at.Add(-rtt).Before(f.markAt) {
		h.clearLocked(i)
		changed = true
	}
	if f.agg.Add(at, rtt, loaded) {
		h.noteFirstLocked(i)
		changed = true
	}
	if changed {
		h.publishLocked()
	}
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
	Samples, LoadedSamples, Attempts uint64 // probe samples (loaded included), the loaded ones, probe attempts started
	FailReason                       string // why the failed mark is set ("" when it is not)
	ProbeCarrier                     uint32 // 0 when none
}
