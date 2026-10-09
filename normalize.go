package rendr

import (
	"math"
	"math/rand/v2"
	"strconv"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/udpflow"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Configuration defaults and clamp ranges (plan §4). The four fields whose
// range includes zero (RetireGrace, Selector.Floor, Probe.DialWait,
// Handshake.MaxMetadata) select zero with a negative value; IdleTimeout is
// off (0) by default.
const (
	defNoPathGrace, minNoPathGrace, maxNoPathGrace                = 15 * time.Second, 3 * time.Second, 300 * time.Second
	defRejoinBackoffMax, minRejoinBackoffMax, maxRejoinBackoffMax = 4 * time.Second, 1 * time.Second, 8 * time.Second
	defJoinStagger, minJoinStagger, maxJoinStagger                = 1 * time.Second, 100 * time.Millisecond, 10 * time.Second
	defRetireGrace, maxRetireGrace                                = 2 * time.Second, 30 * time.Second

	defBand, minBand, maxBand                   = 0.25, 0.05, 0.90
	defFloor, maxFloor                          = 5 * time.Millisecond, 1 * time.Second
	defDwell, minDwell, maxDwell                = 3 * time.Second, 500 * time.Millisecond, 60 * time.Second
	defCooldown, minCooldown, maxCooldown       = 15 * time.Second, 1 * time.Second, 600 * time.Second
	defPingBusy, minPingBusy, maxPingBusy       = 50 * time.Millisecond, 10 * time.Millisecond, 500 * time.Millisecond
	defPingIdle, minPingIdle, maxPingIdle       = 10 * time.Second, 1 * time.Second, 60 * time.Second
	defDeadMin, minDeadMin, maxDeadMin          = 3 * time.Second, 500 * time.Millisecond, 10 * time.Second
	defDeadMax, minDeadMax, maxDeadMax          = 4 * time.Second, 500 * time.Millisecond, 30 * time.Second // and ≥ DeadMin (constraint 1)
	defWriteStall, minWriteStall, maxWriteStall = 2 * time.Second, 500 * time.Millisecond, 30 * time.Second // and ≤ DeadMax (constraint 1)

	defProbeInterval, minProbeInterval, maxProbeInterval       = 2 * time.Second, 500 * time.Millisecond, 30 * time.Second
	defProbeFresh, minProbeFresh, maxProbeFresh                = 10 * time.Second, 1 * time.Second, 120 * time.Second // and ≥ 2×Interval (constraint 7)
	defProbeBackoffMax, minProbeBackoffMax, maxProbeBackoffMax = 4 * time.Second, 1 * time.Second, 8 * time.Second
	defProbeDialWait, maxProbeDialWait                         = 800 * time.Millisecond, 5 * time.Second

	defDialTimeout, minDialTimeout, maxDialTimeout = 10 * time.Second, 1 * time.Second, 60 * time.Second
	defLinger, minLinger, maxLinger                = 30 * time.Second, 1 * time.Second, 300 * time.Second
	minIdleTimeout, maxIdleTimeout                 = 10 * time.Second, 24 * time.Hour

	defWindow, minWindow, maxWindow                      = 8 << 20, 256 << 10, 64 << 20
	defMaxCarriers, minMaxCarriers, maxMaxCarriers       = 6, 1, 16
	defMaxSessions, minMaxSessions, maxMaxSessions       = 10000, 1, 1000000
	defMaxBuffered, minMaxBuffered, maxMaxBuffered int64 = 1 << 30, 64 << 20, 64 << 30

	defHandshakeTimeout, minHandshakeTimeout, maxHandshakeTimeout = 10 * time.Second, 1 * time.Second, 60 * time.Second
	defMaxConcurrent, minMaxConcurrent, maxMaxConcurrent          = 256, 1, 65536
	defMaxMetadata, maxMaxMetadata                                = 4096, 65535

	defSlPerInstance, minSlPerInstance, maxSlPerInstance = 16, 1, 1024
	defSlTotal, minSlTotal, maxSlTotal                   = 1024, 1, 65536
	defSlIdle                                            = 30 * time.Second // and ≥ 3×max(PingIdle, Probe.Interval) (constraint 5)

	defAcceptBacklog, minAcceptBacklog, maxAcceptBacklog = 128, 1, 65536
	defAcceptTimeout, minAcceptTimeout, maxAcceptTimeout = 10 * time.Second, 100 * time.Millisecond, 60 * time.Second

	// Packet sessions and datagram carriers (M2-D64, M2 design §A7.4).
	defPacketPing, minPacketPing, maxPacketPing                   = time.Second, 200 * time.Millisecond, 10 * time.Second // and ≤ DeadMin/2 (constraint 2)
	defPacketQueue, minPacketQueue, maxPacketQueue                = 1 << 20, 64 << 10, 64 << 20                           // and ≥ MaxPayload + 64 (constraint 8)
	defPacketMaxAge, minPacketMaxAge, maxPacketMaxAge             = 100 * time.Millisecond, 10 * time.Millisecond, 2 * time.Second
	defPacketMaxPayload, minPacketMaxPayload, maxPacketMaxPayload = wire.MaxPacketPayload, wire.MinPacketPayload, wire.MaxPacketPayload
	packetQueueSlack                                              = 64 // Packet.Queue ≥ MaxPayload + this (a datagram's queue charge is max(len, 64), M2-D32)

	// minPassiveRetain and maxPassiveRetain clamp the retain_ms a passive
	// receives in OPEN (P15).
	minPassiveRetain, maxPassiveRetain = 1 * time.Second, 400 * time.Second
)

// Internal constants (plan §4 internal constants, design §3–§8). They are not
// configurable; testhooks.Overrides may replace them in tests.
const (
	defRetainSlack       = 5 * time.Second        // the "+5 s" of PassiveRetain (plan §3.6; P16)
	defAckEvery          = 64 << 10               // ACK after this many delivered bytes
	defAckDelay          = 20 * time.Millisecond  // ... or this long after the first unacknowledged delivery
	defRescueMin         = 300 * time.Millisecond // bond rescue threshold floor
	defWindowReadvertise = 200 * time.Millisecond // window re-advertisement cadence under memory pressure (D18)
	defAbandonWait       = 1 * time.Second        // bound on joining a goroutine stuck in embedder code
	defAbandonLimit      = 256                    // abandoned-call pool limit (D20)
	defEventQueue        = 256                    // OnEvent queue capacity (L53)
	defCapFloor          = 128 << 10              // per-carrier capacity floor
	defBatchBudget       = 256 << 10              // DATA payload per batch write
	defSegment           = carrier.ChunkSize      // largest DATA payload per frame (64 KiB)
	defLoadThreshold     = 64 << 10               // self-load guard threshold (§8)
	defProbeIdleStop     = 5 * time.Minute        // probing stops after this long unused (§7.8)
	defFirstEpoch        = 1                      // first SCHED epoch a dialer publishes
	defOffsetLimit       = uint64(1) << 62        // stream offset limit (L14)

	// M2 internal values (M2 design §A7.4).
	defRelRTOInit    = 300 * time.Millisecond // REL and H1 timeout before the first RTT sample
	defRelRTOMin     = 200 * time.Millisecond // REL timeout clamp, lower
	defRelRTOMax     = 2 * time.Second        // REL timeout clamp, upper
	defMTUProbeEvery = 10                     // every n-th PacketPing-cadence PING is an MTU probe
	defMTUProbeFails = 3                      // consecutive unanswered probes that kill
	defPackEvery     = 256                    // PACK after this many datagrams
	defFinWaitMax    = time.Second            // upper clamp of the EOF straggler wait
	defFlowSlack     = 2 * time.Second        // flow tombstones: max(Handshake.Timeout, DialTimeout) + this (R1-11)
)

// effective is the configuration a Runtime runs with (design §10.4): the
// normalized Config (steps 1–2) with the testhooks overrides folded in
// (step 5), and every parameter set derived from it (step 3). It is
// immutable once normalize returned; package rendr only reads it. Overrides
// are applied before the derivation, so a test value reaches every derived
// structure (carrier timing, health, session templates).
type effective struct {
	// cfg is the normalized Config. Its zero-able fields keep the selected
	// zero (RetireGrace, Selector.Floor, Probe.DialWait,
	// Handshake.MaxMetadata), IdleTimeout 0 means off; every other field is
	// non-zero and inside its range unless an override set it. OnEvent is
	// passed through. It is an output, never an input: normalizing it again
	// would turn those selected zeros back into defaults.
	cfg Config

	timing  carrier.Timing       // carrier.Env.Timing
	presets carrier.Presets      // carrier.Env.Presets (zero = production values)
	health  carrier.HealthParams // carrier.NewHealth parameters (Agg and Rand included)

	// params is the session template: every session.Params field that does
	// not depend on the Dial or the OPEN. Role, Mode, Grace, Retain,
	// BackoffMax, AcceptTimeout and TombstoneTTL are filled per session by
	// dialerParams and passiveParams (design §10.4 step 4).
	params session.Params

	// packet is the template of a packet session's frozen packet
	// configuration (M2-D64): MaxPayload is Config.Packet.MaxPayload, which
	// DialPacket replaces by its offer and the admission by the accepted
	// value. flow bounds every FromPacketConn source (M2-D59).
	packet session.PacketParams
	flow   udpflow.Limits

	retainSlack    time.Duration    // the "+5 s" of PassiveRetain
	eventQueue     int              // OnEvent queue capacity
	abandonLimit   int              // carrier.NewAbandonPool limit
	firstCarrierID uint32           // carrier.NewIDAllocator first ID (0 = 1)
	rand           func() float64   // U[0,1) jitter source (session.Env.Rand)
	hooks          *testhooks.Hooks // carrier.Env.Hooks and session.Env.Hooks; nil in production
}

// normalize implements design §10.4 for a Runtime: (1) zero → default,
// negative → zero for the four zero-able fields, clamp to the plan §4
// range; (2) the cross-parameter constraints of plan §3.6 in their fixed
// order; (5) the testhooks overrides when ov is non-nil (unclamped, not
// recorded); (3) the derived parameter sets. It returns every adjustment of
// steps 1–2 as "Field: old → new (reason)". It is a pure function: the same
// input always yields the same effective value (Rand and Hooks are passed
// through).
func normalize(cfg Config, ov *testhooks.Overrides) (effective, []string) {
	var a adjuster
	c := cfg

	// Step 1: per field.
	clampField(&a, "NoPathGrace", &c.NoPathGrace, defNoPathGrace, minNoPathGrace, maxNoPathGrace, false, fmtDur)
	clampField(&a, "RejoinBackoffMax", &c.RejoinBackoffMax, defRejoinBackoffMax, minRejoinBackoffMax, maxRejoinBackoffMax, false, fmtDur)
	clampField(&a, "JoinStagger", &c.JoinStagger, defJoinStagger, minJoinStagger, maxJoinStagger, false, fmtDur)
	clampField(&a, "RetireGrace", &c.RetireGrace, defRetireGrace, 0, maxRetireGrace, true, fmtDur)

	clampBand(&a, "Selector.Band", &c.Selector.Band)
	clampField(&a, "Selector.Floor", &c.Selector.Floor, defFloor, 0, maxFloor, true, fmtDur)
	clampField(&a, "Selector.Dwell", &c.Selector.Dwell, defDwell, minDwell, maxDwell, false, fmtDur)
	clampField(&a, "Selector.Cooldown", &c.Selector.Cooldown, defCooldown, minCooldown, maxCooldown, false, fmtDur)

	clampField(&a, "PingBusy", &c.PingBusy, defPingBusy, minPingBusy, maxPingBusy, false, fmtDur)
	clampField(&a, "PingIdle", &c.PingIdle, defPingIdle, minPingIdle, maxPingIdle, false, fmtDur)
	clampField(&a, "DeadMin", &c.DeadMin, defDeadMin, minDeadMin, maxDeadMin, false, fmtDur)
	clampField(&a, "DeadMax", &c.DeadMax, defDeadMax, minDeadMax, maxDeadMax, false, fmtDur)
	clampField(&a, "WriteStall", &c.WriteStall, defWriteStall, minWriteStall, maxWriteStall, false, fmtDur)

	clampField(&a, "Probe.Interval", &c.Probe.Interval, defProbeInterval, minProbeInterval, maxProbeInterval, false, fmtDur)
	clampField(&a, "Probe.Fresh", &c.Probe.Fresh, defProbeFresh, minProbeFresh, maxProbeFresh, false, fmtDur)
	clampField(&a, "Probe.BackoffMax", &c.Probe.BackoffMax, defProbeBackoffMax, minProbeBackoffMax, maxProbeBackoffMax, false, fmtDur)
	clampField(&a, "Probe.DialWait", &c.Probe.DialWait, defProbeDialWait, 0, maxProbeDialWait, true, fmtDur)

	clampField(&a, "DialTimeout", &c.DialTimeout, defDialTimeout, minDialTimeout, maxDialTimeout, false, fmtDur)
	clampField(&a, "Linger", &c.Linger, defLinger, minLinger, maxLinger, false, fmtDur)
	clampIdle(&a, "IdleTimeout", &c.IdleTimeout)

	clampField(&a, "Window", &c.Window, defWindow, minWindow, maxWindow, false, fmtInt)
	clampField(&a, "MaxCarriersPerSession", &c.MaxCarriersPerSession, defMaxCarriers, minMaxCarriers, maxMaxCarriers, false, fmtInt)
	clampField(&a, "MaxSessions", &c.MaxSessions, defMaxSessions, minMaxSessions, maxMaxSessions, false, fmtInt)
	clampField(&a, "MaxBufferedBytes", &c.MaxBufferedBytes, defMaxBuffered, minMaxBuffered, maxMaxBuffered, false, fmtInt)

	clampField(&a, "Handshake.Timeout", &c.Handshake.Timeout, defHandshakeTimeout, minHandshakeTimeout, maxHandshakeTimeout, false, fmtDur)
	clampField(&a, "Handshake.MaxConcurrent", &c.Handshake.MaxConcurrent, defMaxConcurrent, minMaxConcurrent, maxMaxConcurrent, false, fmtInt)
	clampField(&a, "Handshake.MaxMetadata", &c.Handshake.MaxMetadata, defMaxMetadata, 0, maxMaxMetadata, true, fmtInt)

	clampField(&a, "Sessionless.PerInstance", &c.Sessionless.PerInstance, defSlPerInstance, minSlPerInstance, maxSlPerInstance, false, fmtInt)
	clampField(&a, "Sessionless.Total", &c.Sessionless.Total, defSlTotal, minSlTotal, maxSlTotal, false, fmtInt)
	if c.Sessionless.Idle == 0 { // its only bound is constraint 5
		c.Sessionless.Idle = defSlIdle
	}

	clampField(&a, "PacketPing", &c.PacketPing, defPacketPing, minPacketPing, maxPacketPing, false, fmtDur)
	clampField(&a, "Packet.Queue", &c.Packet.Queue, defPacketQueue, minPacketQueue, maxPacketQueue, false, fmtInt)
	clampField(&a, "Packet.MaxAge", &c.Packet.MaxAge, defPacketMaxAge, minPacketMaxAge, maxPacketMaxAge, false, fmtDur)
	clampField(&a, "Packet.MaxPayload", &c.Packet.MaxPayload, defPacketMaxPayload, minPacketMaxPayload, maxPacketMaxPayload, false, fmtInt)

	// Step 2: cross-parameter constraints (plan §3.6; design §7.9), in this
	// order. Each lowers or raises only the dependent field, and every
	// adjusted value stays inside the field's own range (DeadMin ≥ 500 ms
	// gives DeadMin/4 ≥ 125 ms ≥ min PingBusy; NoPathGrace ≥ 3 s gives
	// NoPathGrace/2 ≥ 1.5 s ≥ min RejoinBackoffMax; 2×Interval ≤ 60 s ≤ max
	// Fresh), so step 1 never has to run again. The normalized Config is a
	// fixed point when fed back as an input with each selected zero of the
	// four zero-able fields written as a negative value: nothing changes or
	// is recorded (TestConfigNormalizeIdempotent). Fed back unchanged, such
	// a zero would select the default again, so an effective cfg is never
	// re-normalized.
	if c.DeadMax < c.DeadMin {
		a.record("DeadMax", fmtDur(c.DeadMax), fmtDur(c.DeadMin), "constraint 1: DeadMax ≥ DeadMin")
		c.DeadMax = c.DeadMin
	}
	if c.WriteStall > c.DeadMax {
		a.record("WriteStall", fmtDur(c.WriteStall), fmtDur(c.DeadMax), "constraint 1: WriteStall ≤ DeadMax")
		c.WriteStall = c.DeadMax
	}
	if lim := c.DeadMin / 4; c.PingBusy > lim {
		a.record("PingBusy", fmtDur(c.PingBusy), fmtDur(lim), "constraint 2: PingBusy ≤ DeadMin/4")
		c.PingBusy = lim
	}
	if lim := c.DeadMin / 2; c.PacketPing > lim {
		a.record("PacketPing", fmtDur(c.PacketPing), fmtDur(lim), "constraint 2: PacketPing ≤ DeadMin/2")
		c.PacketPing = lim
	}
	if lim := c.NoPathGrace / 2; c.RejoinBackoffMax > lim {
		a.record("RejoinBackoffMax", fmtDur(c.RejoinBackoffMax), fmtDur(lim), "constraint 3: RejoinBackoffMax ≤ NoPathGrace/2")
		c.RejoinBackoffMax = lim
	}
	if lim := 3 * max(c.PingIdle, c.Probe.Interval); c.Sessionless.Idle < lim {
		a.record("Sessionless.Idle", fmtDur(c.Sessionless.Idle), fmtDur(lim), "constraint 5: Sessionless.Idle ≥ 3×max(PingIdle, Probe.Interval)")
		c.Sessionless.Idle = lim
	}
	if lim := 2 * c.Probe.Interval; c.Probe.Fresh < lim {
		a.record("Probe.Fresh", fmtDur(c.Probe.Fresh), fmtDur(lim), "constraint 7: Probe.Fresh ≥ 2×Probe.Interval")
		c.Probe.Fresh = lim
	}
	if lim := c.Packet.MaxPayload + packetQueueSlack; c.Packet.Queue < lim {
		a.record("Packet.Queue", fmtInt(c.Packet.Queue), fmtInt(lim), "constraint 8: Packet.Queue ≥ Packet.MaxPayload + 64")
		c.Packet.Queue = lim
	}

	e := effective{
		retainSlack:  defRetainSlack,
		eventQueue:   defEventQueue,
		abandonLimit: defAbandonLimit,
		rand:         rand.Float64,
	}
	k := internalConstants{
		ackEvery: defAckEvery, ackDelay: defAckDelay, rescueMin: defRescueMin,
		windowReadvertise: defWindowReadvertise, abandonWait: defAbandonWait,
		capFloor: defCapFloor, batchBudget: defBatchBudget, segment: defSegment,
		loadThreshold: defLoadThreshold, idleStop: defProbeIdleStop,
		agg: sched.DefaultAggParams(), firstEpoch: defFirstEpoch, offsetLimit: defOffsetLimit,
		packetActive: c.PingIdle, relRTOInit: defRelRTOInit, relRTOMin: defRelRTOMin, relRTOMax: defRelRTOMax,
		mtuProbeEvery: defMTUProbeEvery, mtuProbeFails: defMTUProbeFails, packEvery: defPackEvery,
		finWaitMax: defFinWaitMax, dedupBits: wire.DefaultSeqWindowBits,
		flowPerSource: udpflow.DefaultPerSource, flowPerSourceJoin: udpflow.DefaultPerSourceJoin,
		flowInbox: udpflow.DefaultInbox,
	}

	// Step 5: overrides, last, unclamped and not recorded (a zero field
	// keeps the normalized value). They are folded in before step 3 so that
	// they reach every derived structure.
	if ov != nil {
		applyOverrides(&c, &e, &k, ov)
	}

	// Step 3: derived values (not configurable).
	e.cfg = c
	e.timing = carrier.Timing{
		PingBusy:         c.PingBusy,
		PingIdle:         c.PingIdle,
		DeadMin:          c.DeadMin,
		DeadMax:          c.DeadMax,
		WriteStall:       c.WriteStall,
		DialTimeout:      c.DialTimeout,
		HandshakeTimeout: c.Handshake.Timeout,
		ProbeInterval:    c.Probe.Interval,
		SessionlessIdle:  c.Sessionless.Idle,
		AbandonWait:      k.abandonWait,
		Window:           int64(c.Window),
		CapFloor:         k.capFloor,
		BatchBudget:      k.batchBudget,
		Segment:          k.segment,
		PacketPing:       c.PacketPing,
		PacketActive:     k.packetActive,
		RelRTOInit:       k.relRTOInit,
		RelRTOMin:        k.relRTOMin,
		RelRTOMax:        k.relRTOMax,
		MTUProbeEvery:    k.mtuProbeEvery,
		MTUProbeFails:    k.mtuProbeFails,
	}
	if ov != nil {
		// M3 mux constants (M3-D50): internal, overridden by tests only; a
		// zero field keeps carrier.Timing's default.
		e.timing.MuxMaxViews = ov.MuxMaxViews
		e.timing.MuxMaxViewsDatagram = ov.MuxMaxViewsDatagram
		e.timing.MuxQuantum = ov.MuxQuantum
		e.timing.MuxRefusalRing = ov.MuxRefusalRing
	}
	e.health = carrier.HealthParams{
		Interval:      c.Probe.Interval,
		Fresh:         c.Probe.Fresh,
		BackoffMax:    c.Probe.BackoffMax,
		DialWait:      c.Probe.DialWait,
		IdleStop:      k.idleStop,
		LoadThreshold: k.loadThreshold,
		Agg:           k.agg,
		Rand:          e.rand,
	}
	e.params = session.Params{
		Window:      int64(c.Window),
		JoinStagger: c.JoinStagger,
		RetireGrace: c.RetireGrace,
		Linger:      c.Linger,
		IdleTimeout: c.IdleTimeout,
		Selector: sched.SelectorParams{
			Band:     c.Selector.Band,
			Floor:    c.Selector.Floor,
			Dwell:    c.Selector.Dwell,
			Cooldown: c.Selector.Cooldown,
			Fresh:    c.Probe.Fresh,
		},
		MaxCarriers:       c.MaxCarriersPerSession,
		AckEvery:          k.ackEvery,
		AckDelay:          k.ackDelay,
		RescueMin:         k.rescueMin,
		WindowReadvertise: k.windowReadvertise,
		FirstOffset:       k.firstOffset,
		OffsetLimit:       k.offsetLimit,
		FirstEpoch:        k.firstEpoch,
	}
	e.packet = session.PacketParams{
		MaxPayload: c.Packet.MaxPayload,
		Queue:      c.Packet.Queue,
		MaxAge:     c.Packet.MaxAge,
		PacketPing: c.PacketPing,
		PackEvery:  k.packEvery,
		FinWaitMax: k.finWaitMax,
		DedupBits:  k.dedupBits,
		FirstSeq:   k.firstSeq,
	}
	e.flow = udpflow.Limits{
		MaxFlows:      k.flowMaxFlows,
		PerSource:     k.flowPerSource,
		PerSourceJoin: k.flowPerSourceJoin,
		Inbox:         k.flowInbox,
		TombstoneTTL:  k.flowTombstoneTTL,
		Tombstones:    udpflow.DefaultTombstones,
	}
	if e.flow.MaxFlows == 0 {
		e.flow.MaxFlows = flowCap(c)
	}
	if e.flow.TombstoneTTL == 0 {
		e.flow.TombstoneTTL = addSat(max(c.Handshake.Timeout, c.DialTimeout), defFlowSlack)
	}
	return e, a.out
}

// flowCap is the flow bound of one FromPacketConn source (M2-D59):
// min(65,536, MaxSessions × MaxCarriersPerSession + Sessionless.Total +
// Handshake.MaxConcurrent), computed in 64 bits so that test overrides
// cannot overflow it.
func flowCap(c Config) int {
	n := int64(c.MaxSessions)*int64(c.MaxCarriersPerSession) + int64(c.Sessionless.Total) + int64(c.Handshake.MaxConcurrent)
	return int(min(max(n, 1), udpflow.MaxFlowsCap))
}

// internalConstants collects the plan §4 internal constants that only
// testhooks can change, between the override step and the derivation.
type internalConstants struct {
	ackEvery          int
	ackDelay          time.Duration
	rescueMin         time.Duration
	windowReadvertise time.Duration
	abandonWait       time.Duration
	capFloor          int64
	batchBudget       int
	segment           int
	loadThreshold     int64
	idleStop          time.Duration
	agg               sched.AggParams
	firstOffset       uint64
	offsetLimit       uint64
	firstEpoch        uint32

	// M2: datagram carriers, packet sessions and udpflow sources.
	packetActive      time.Duration
	relRTOInit        time.Duration
	relRTOMin         time.Duration
	relRTOMax         time.Duration
	mtuProbeEvery     int
	mtuProbeFails     int
	packEvery         int
	finWaitMax        time.Duration
	dedupBits         int
	firstSeq          uint64
	flowMaxFlows      int // 0: flowCap
	flowPerSource     int
	flowPerSourceJoin int
	flowInbox         int
	flowTombstoneTTL  time.Duration // 0: max(Handshake.Timeout, DialTimeout) + 2 s
}

// applyOverrides folds ov into the normalized config and the internal
// constants (design §10.4 step 5).
func applyOverrides(c *Config, e *effective, k *internalConstants, ov *testhooks.Overrides) {
	override(&c.NoPathGrace, ov.NoPathGrace)
	override(&c.RejoinBackoffMax, ov.RejoinBackoffMax)
	override(&c.JoinStagger, ov.JoinStagger)
	override(&c.RetireGrace, ov.RetireGrace)
	override(&c.PingBusy, ov.PingBusy)
	override(&c.PingIdle, ov.PingIdle)
	override(&c.DeadMin, ov.DeadMin)
	override(&c.DeadMax, ov.DeadMax)
	override(&c.WriteStall, ov.WriteStall)
	override(&c.Probe.Interval, ov.ProbeInterval)
	override(&c.Probe.Fresh, ov.ProbeFresh)
	override(&c.Probe.BackoffMax, ov.ProbeBackoffMax)
	override(&c.Probe.DialWait, ov.ProbeDialWait)
	override(&c.DialTimeout, ov.DialTimeout)
	override(&c.Linger, ov.Linger)
	override(&c.IdleTimeout, ov.IdleTimeout)
	override(&c.Handshake.Timeout, ov.HandshakeTimeout)
	override(&c.Sessionless.Idle, ov.SessionlessIdle)
	override(&c.Selector.Dwell, ov.SelectorDwell)
	override(&c.Selector.Cooldown, ov.SelectorCooldown)
	override(&c.Selector.Floor, ov.SelectorFloor)
	override(&c.Selector.Band, ov.SelectorBand)
	override(&c.Window, ov.Window)
	override(&c.MaxCarriersPerSession, ov.MaxCarriersPerSession)
	override(&c.MaxSessions, ov.MaxSessions)
	override(&c.MaxBufferedBytes, ov.MaxBufferedBytes)
	override(&c.PacketPing, ov.PacketPing)
	override(&c.Packet.Queue, ov.PacketQueue)
	override(&c.Packet.MaxAge, ov.PacketMaxAge)
	override(&c.Packet.MaxPayload, ov.PacketMaxPayload)

	override(&e.retainSlack, ov.RetainSlack)
	override(&e.eventQueue, ov.EventQueue)
	override(&e.abandonLimit, ov.AbandonLimit)
	override(&e.firstCarrierID, ov.FirstCarrierID)
	if ov.Rand != nil {
		e.rand = ov.Rand
	}
	e.hooks = ov.Hooks
	e.presets = carrier.Presets{FirstFseq: ov.FirstFseq, FirstPingID: ov.FirstPingID, FirstCseq: ov.FirstCseq, FirstHandle: ov.FirstHandle}

	override(&k.ackEvery, ov.AckEvery)
	override(&k.ackDelay, ov.AckDelay)
	override(&k.rescueMin, ov.RescueMin)
	override(&k.windowReadvertise, ov.WindowReadvertise)
	override(&k.abandonWait, ov.AbandonWait)
	override(&k.capFloor, ov.CapFloor)
	override(&k.batchBudget, ov.BatchBudget)
	override(&k.segment, ov.Segment)
	override(&k.loadThreshold, ov.LoadThreshold)
	override(&k.idleStop, ov.ProbeIdleStop)
	override(&k.agg.Window, ov.AggWindow)
	override(&k.agg.MinEarlier, ov.AggMinEarlier)
	override(&k.agg.ShiftRun, ov.AggShiftRun)
	override(&k.agg.SigmaK, ov.AggSigmaK)
	override(&k.agg.SigmaFloor, ov.AggSigmaFloor)
	override(&k.firstOffset, ov.FirstOffset)
	override(&k.offsetLimit, ov.OffsetLimit)
	override(&k.firstEpoch, ov.FirstEpoch)

	k.packetActive = c.PingIdle // PacketActive = PingIdle (after the PingIdle override) unless set itself
	override(&k.packetActive, ov.PacketActive)
	override(&k.relRTOInit, ov.RelRTOInit)
	override(&k.relRTOMin, ov.RelRTOMin)
	override(&k.relRTOMax, ov.RelRTOMax)
	override(&k.mtuProbeEvery, ov.MTUProbeEvery)
	override(&k.mtuProbeFails, ov.MTUProbeFails)
	override(&k.packEvery, ov.PackEvery)
	override(&k.finWaitMax, ov.FinWaitMax)
	override(&k.dedupBits, ov.DedupBits)
	override(&k.firstSeq, ov.FirstSeq)
	override(&k.flowMaxFlows, ov.FlowMaxFlows)
	override(&k.flowPerSource, ov.FlowPerSource)
	override(&k.flowPerSourceJoin, ov.FlowPerSourceJoin)
	override(&k.flowInbox, ov.FlowInbox)
	override(&k.flowTombstoneTTL, ov.FlowTombstoneTTL)
}

// override replaces *p with v unless v is the zero value ("a zero field
// keeps the normalized value").
func override[T comparable](p *T, v T) {
	var zero T
	if v != zero {
		*p = v
	}
}

// passiveRetain is PassiveRetain for a dialer session with NoPathGrace
// grace: grace + PingIdle + DeadMax + slack (plan §3.6 constraint 4). It is
// what the dialer announces in OPEN; the passive clamps it (P15).
func (e *effective) passiveRetain(grace time.Duration) time.Duration {
	return addSat(addSat(addSat(grace, e.cfg.PingIdle), e.cfg.DeadMax), e.retainSlack)
}

// dialerParams returns the frozen Params of one dialer session (design
// §6.6; §10.4 step 4, not recorded): grace is DialOptions.NoPathGrace —
// clamped to 3 s–300 s when non-zero, the Runtime's NoPathGrace when zero;
// BackoffMax = min(RejoinBackoffMax, grace/2) (constraint 3 per session);
// Retain = PassiveRetain(grace). mode 0 selects ModeSelector; the caller
// rejects modes other than 0, 1 and 2 before (ErrProtocol).
func (e *effective) dialerParams(mode Mode, grace time.Duration) session.Params {
	g := e.cfg.NoPathGrace
	if grace != 0 {
		g = clampDur(grace, minNoPathGrace, maxNoPathGrace)
	}
	if mode == 0 {
		mode = ModeSelector
	}
	p := e.params
	p.Role = session.RoleDialer
	p.Mode = session.Mode(mode)
	p.Grace = g
	p.BackoffMax = min(e.cfg.RejoinBackoffMax, g/2)
	p.Retain = e.passiveRetain(g)
	return p
}

// passiveParams returns the frozen Params of a passive session admitted
// with OPEN.retain_ms (design §6.2, §6.5; P15): Grace = clamp(retain, 1 s,
// 400 s) — a 0 never means immediate expiry —, TombstoneTTL = Grace +
// Linger (plan §3.6 constraint 6), AcceptTimeout from the admitting
// Listener. A passive session never dials, so Retain and BackoffMax are 0.
func (e *effective) passiveParams(mode Mode, retainMs uint32, acceptTimeout time.Duration) session.Params {
	p := e.params
	p.Role = session.RolePassive
	p.Mode = session.Mode(mode)
	p.Grace = clampDur(time.Duration(retainMs)*time.Millisecond, minPassiveRetain, maxPassiveRetain)
	p.TombstoneTTL = addSat(p.Grace, e.cfg.Linger)
	p.AcceptTimeout = acceptTimeout
	return p
}

// packetParams turns p into the Params of a packet session (M2-D1) whose
// MaxPayload is maxPayload: the dialer's offer (M2-D49) or the passive's
// accepted value.
func (e *effective) packetParams(p session.Params, maxPayload int) session.Params {
	p.Kind = wire.KindDatagram
	p.Packet = e.packet
	p.Packet.MaxPayload = maxPayload
	return p
}

// normalizeListen normalizes the ListenConfig of the i-th Listen call
// (design §10.4): AcceptBacklog 128 (1–65536), AcceptTimeout 10 s (0.1–60
// s), then the testhooks AcceptTimeout override. Adjustments are prefixed
// "Listen[i]." for Status.ConfigAdjustments. Sources is copied.
func normalizeListen(i int, cfg ListenConfig, ov *testhooks.Overrides) (ListenConfig, []string) {
	a := adjuster{prefix: "Listen[" + strconv.Itoa(i) + "]."}
	out := ListenConfig{
		Sources:       append([]Source(nil), cfg.Sources...),
		AcceptBacklog: cfg.AcceptBacklog,
		AcceptTimeout: cfg.AcceptTimeout,
	}
	clampField(&a, "AcceptBacklog", &out.AcceptBacklog, defAcceptBacklog, minAcceptBacklog, maxAcceptBacklog, false, fmtInt)
	clampField(&a, "AcceptTimeout", &out.AcceptTimeout, defAcceptTimeout, minAcceptTimeout, maxAcceptTimeout, false, fmtDur)
	if ov != nil {
		override(&out.AcceptTimeout, ov.AcceptTimeout)
	}
	return out, a.out
}

// adjuster collects "Field: old → new (reason)" records.
type adjuster struct {
	prefix string
	out    []string
}

func (a *adjuster) record(field, from, to, reason string) {
	a.out = append(a.out, a.prefix+field+": "+from+" → "+to+" ("+reason+")")
}

// clampField applies step 1 to one integer or duration field: zero selects
// def; when negZero (the range includes zero) a negative value selects zero;
// otherwise a value outside [lo, hi] is clamped and recorded.
func clampField[T ~int | ~int64](a *adjuster, name string, p *T, def, lo, hi T, negZero bool, format func(T) string) {
	v := *p
	switch {
	case v == 0:
		*p = def
		return
	case v < 0 && negZero:
		*p = 0
		return
	case v < lo:
		*p = lo
	case v > hi:
		*p = hi
	default:
		return
	}
	a.record(name, format(v), format(*p), "range "+format(lo)+".."+format(hi))
}

// clampBand applies step 1 to Selector.Band: 0 selects the default, NaN is
// replaced by the default, and out-of-range values (including ±Inf) are
// clamped; the last two are recorded.
func clampBand(a *adjuster, name string, p *float64) {
	v := *p
	switch {
	case v == 0:
		*p = defBand
		return
	case math.IsNaN(v):
		*p = defBand
	case v < minBand:
		*p = minBand
	case v > maxBand:
		*p = maxBand
	default:
		return
	}
	a.record(name, fmtFloat(v), fmtFloat(*p), "range "+fmtFloat(minBand)+".."+fmtFloat(maxBand))
}

// clampIdle applies step 1 to IdleTimeout: 0 is off (the default);
// negative turns it off; (0, 10 s) is raised to 10 s and > 24 h lowered to
// 24 h. Every change is recorded.
func clampIdle(a *adjuster, name string, p *time.Duration) {
	v := *p
	switch {
	case v == 0:
		return
	case v < 0:
		*p = 0
	case v < minIdleTimeout:
		*p = minIdleTimeout
	case v > maxIdleTimeout:
		*p = maxIdleTimeout
	default:
		return
	}
	a.record(name, fmtDur(v), fmtDur(*p), "range 0 or "+fmtDur(minIdleTimeout)+".."+fmtDur(maxIdleTimeout))
}

func clampDur(v, lo, hi time.Duration) time.Duration { return min(max(v, lo), hi) }

// addSat adds y to x, saturating at the maximum duration instead of
// wrapping (derived values of extreme test overrides stay huge, not negative).
func addSat(x, y time.Duration) time.Duration {
	s := x + y
	if y > 0 && s < x {
		return math.MaxInt64
	}
	return s
}

func fmtDur(d time.Duration) string      { return d.String() }
func fmtInt[T ~int | ~int64](v T) string { return strconv.FormatInt(int64(v), 10) }
func fmtFloat(f float64) string          { return strconv.FormatFloat(f, 'g', -1, 64) }
