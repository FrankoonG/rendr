package rendr

import "time"

// Config configures a Runtime. The zero value of every field selects its
// default; out-of-range values are clamped to the plan §4 range and every
// change (clamp or cross-parameter constraint) is recorded in
// Status.ConfigAdjustments as "Field: old → new (reason)". For the four
// fields whose range includes zero (RetireGrace, Selector.Floor,
// Probe.DialWait, Handshake.MaxMetadata) a negative value selects zero.
// Configuration is frozen when the Runtime is built; each session also
// snapshots it at Dial or OPEN (L20).
//
// M2 adds PacketPing and Packet (packet sessions); they are not declared
// before their milestone.
type Config struct {
	NoPathGrace      time.Duration // 15 s; 3 s–300 s; counted from the death of the last carrier
	RejoinBackoffMax time.Duration // 4 s; 1 s–8 s and ≤ NoPathGrace/2; redial cadence cap (plan §3.6)
	JoinStagger      time.Duration // 1 s; 0.1 s–10 s; failover race stagger
	RetireGrace      time.Duration // 2 s; 0–30 s; old carrier's retirement bound after a planned switch

	Selector SelectorPolicy

	PingBusy time.Duration // 50 ms; 10 ms–500 ms and ≤ DeadMin/4
	PingIdle time.Duration // 10 s; 1 s–60 s

	DeadMin    time.Duration // 3 s; 0.5 s–10 s
	DeadMax    time.Duration // 4 s; DeadMin–30 s
	WriteStall time.Duration // 2 s; 0.5 s–DeadMax

	Probe ProbePolicy

	DialTimeout time.Duration // 10 s; 1 s–60 s; bounds one factory call and one whole dial attempt
	Linger      time.Duration // 30 s; 1 s–300 s; Close's background delivery bound
	IdleTimeout time.Duration // 0 = off; else 10 s–24 h

	Window                int   // 8 MiB; 256 KiB–64 MiB; per session per direction
	MaxCarriersPerSession int   // 6; 1–16
	MaxSessions           int   // 10000; 1–1,000,000; open, pending, lingering and orphaned sessions of both roles
	MaxBufferedBytes      int64 // 1 GiB; 64 MiB–64 GiB; send and receive buffers of all sessions

	Handshake   HandshakeLimits
	Sessionless SessionlessLimits

	// OnEvent, if set, is called with every event on a single worker
	// goroutine fed by a bounded queue (256); a full queue drops and counts
	// (Status.EventsDropped; the Seq gap shows the drop); a panic is
	// recovered and counted (Status.CallbackPanics), and so is a
	// runtime.Goexit, after which a new worker continues with the next
	// event. Runtime.Close stops the queue: events already queued are still
	// delivered, later ones are discarded without being counted. OnEvent is
	// never called with a rendr lock held and may call any rendr method,
	// including Close.
	OnEvent func(Event)
}

// SelectorPolicy are the selector quality-switch parameters (owner-fixed
// defaults, plan §4). Death switches bypass all of them.
type SelectorPolicy struct {
	Band     float64       // 0.25; 0.05–0.90: a challenger's RTT must be ≤ active × (1 − Band) ...
	Floor    time.Duration // 5 ms; 0–1 s: ... and at least Floor lower
	Dwell    time.Duration // 3 s; 0.5 s–60 s: continuously qualified this long
	Cooldown time.Duration // 15 s; 1 s–600 s: minimum time between two quality switches
}

// ProbePolicy configures the Peer health layer (plan §3.9). A Peer with one
// carrier factory never probes.
type ProbePolicy struct {
	Interval   time.Duration // 2 s; 0.5 s–30 s: probe PING cadence
	Fresh      time.Duration // 10 s; 2×Interval–120 s: sample freshness
	BackoffMax time.Duration // 4 s; 1 s–8 s: probe redial cadence cap
	DialWait   time.Duration // 800 ms; 0–5 s: how long Dial waits for first samples
}

// HandshakeLimits bound pre-admission resources (plan §3.5, L48).
type HandshakeLimits struct {
	Timeout       time.Duration // 10 s; 1 s–60 s: PREFACE + first frame + verdict write
	MaxConcurrent int           // 256; 1–65536: handshake slots per Runtime (the oldest is evicted when full)
	MaxMetadata   int           // 4096; 0–65535: OPEN metadata bytes
}

// SessionlessLimits bound probe carriers held by a passive Runtime (plan §3.5).
type SessionlessLimits struct {
	PerInstance int           // 16; 1–1024: per dialer InstanceID
	Total       int           // 1024; 1–65536: per Runtime
	Idle        time.Duration // 30 s; ≥ 3×max(PingIdle, Probe.Interval): closed after this long without a PING
}
