package rendr

import "time"

// Config configures a Runtime. Field comments give each default, then its
// range. The zero value of every field selects its default; out-of-range
// values are clamped to the range and every change (clamp or
// cross-parameter constraint) is recorded in Status.ConfigAdjustments as
// "Field: old → new (reason)". For the four fields whose range includes
// zero (RetireGrace, Selector.Floor, Probe.DialWait, Handshake.MaxMetadata)
// a negative value selects zero. Configuration is frozen when the Runtime
// is built; each session also snapshots it at Dial or OPEN.
//
// PacketPing and Packet configure packet sessions and datagram carriers
// (milestone M2).
type Config struct {
	NoPathGrace      time.Duration // 15 s; 3 s–300 s; counted from the death of the last carrier
	RejoinBackoffMax time.Duration // 4 s; 1 s–8 s and ≤ NoPathGrace/2; redial backoff cap, also for repeated refusals
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

	// IdleTimeout (0 = off; else 10 s–24 h) ends a session with
	// ErrIdleTimeout, and the peer's with AbortIdle, once for this long no
	// application Read or Write moved bytes and none of this side's data was
	// acknowledged as delivered. Data that still reaches the peer
	// application keeps the session alive; a peer application that stops
	// reading lets it time out. It does not end a finished exchange (both
	// FINs delivered and this side's FIN acknowledged): Linger bounds the
	// wait for the peer's final confirmation, and that end is io.EOF.
	IdleTimeout time.Duration

	Window                int // 8 MiB; 256 KiB–64 MiB; per session per direction
	MaxCarriersPerSession int // 6; 1–16; carriers per session; a passive refuses more (see ModeBond)
	MaxSessions           int // 10000; 1–1,000,000; open, pending, lingering and orphaned sessions of both roles

	// MaxBufferedBytes (1 GiB; 64 MiB–64 GiB) is the budget for the
	// sessions' data buffers. Send buffers stay within it: Write waits while
	// it is used up. Receive buffers are bounded by the windows this side
	// advertised instead: once the budget is more than 75 % used, the
	// windows advertised from then on shrink (to 0 when it is full), but
	// windows already advertised are honoured, so receive memory is bounded
	// by about MaxSessions × 2 × Window, not by this budget. Every carrier
	// other than a bare carrier/tcp connection also copies each batch it
	// writes into a buffer of up to 512 KiB, held while the conn's Write
	// runs; that buffer is charged to this budget unconditionally, so it
	// counts toward the 75 % threshold and can take the use past
	// MaxBufferedBytes. The reader stage of every live carrier (about
	// 16 KiB) is accounted apart and never shrinks a window;
	// Status.BufferedBytes reports both.
	MaxBufferedBytes int64

	Handshake   HandshakeLimits
	Sessionless SessionlessLimits

	// PacketPing (1 s; 0.2 s–10 s and ≤ DeadMin/2) is the PING cadence of
	// a datagram carrier that moved a datagram within PingIdle, and the
	// delay of a packet session's accounting frame (plan:188, plan:301).
	PacketPing time.Duration
	Packet     PacketPolicy

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

// PacketPolicy configures packet sessions (plan:285–287). A session fixes
// its values at Dial or OPEN.
type PacketPolicy struct {
	// Queue (1 MiB; 64 KiB–64 MiB, and at least MaxPayload + 64) bounds the
	// datagram bytes queued per direction, and Queue/64 datagrams; a full
	// queue drops its oldest datagram (WriteTo never blocks).
	Queue int
	// MaxAge (100 ms; 10 ms–2 s): a datagram not handed to a carrier within
	// this is dropped.
	MaxAge time.Duration
	// MaxPayload (65,507; 512–65,507) is the largest datagram this side
	// offers (dialer) or accepts (passive); a session's limit is fixed at
	// OPEN from it and its carriers' budgets (PacketConn.MaxPayload).
	MaxPayload int
}

// SelectorPolicy are the selector's quality-switch parameters. Death
// switches bypass all of them.
//
// Quality switching compares only probe samples that this Peer's own
// traffic did not load (the self-load guard), so that a bulk transfer does
// not make the selector flee from the queueing it causes itself. A sample is
// loaded when this Peer's session carriers on the probed path were
// backlogged (data queued for writing at either end) with at least 64 KiB in
// flight, both directions together, when its PING was sent or its PONG
// arrived, or became backlogged in between. It is also loaded by volume:
// when they moved at least 64 KiB of data during the probe's round trip and
// that traffic was not already flowing before it (less than 64 KiB moved
// since the previous probe PING, or since the latest backlog ended). Loaded
// samples are counted in FactoryStatus.LoadedSamples and never compared.
//
// Limitation: a path that degrades while this Peer's own traffic saturates
// it, in either direction, cannot be told apart from self-induced queueing.
// The selector keeps the last unloaded measurement and leaves the path only
// through death detection (a PING timeout within DeadMax, or a write
// stall), or after the traffic becomes application-limited again. A
// candidate path saturated by another session of the same Peer cannot
// become a quality target, because its samples are loaded. Traffic of other
// Peers on a shared bottleneck is genuine congestion from this Peer's point
// of view.
//
// The volume rule has gaps. (1) Unbacklogged traffic of this Peer on the
// path, other sessions included, of 64 KiB or more since the later of the
// previous probe PING and the end of the latest backlog (about 32 KiB/s at
// the default Probe.Interval of 2 s) counts as already flowing, so a
// transfer that starts at a probe PING meanwhile gets an unloaded first
// sample. (2) With a Probe.Interval shorter than the RTT, an echo can lose a
// sample or two after its RTT rises. (3) An application-limited flow that
// cycles through backlog episodes loses the samples taken in and right
// after an episode, and in pauses between writes of 64 KiB or more, so its
// quality switch can come a probe interval or two later.
type SelectorPolicy struct {
	Band     float64       // 0.25; 0.05–0.90: a challenger's RTT must be ≤ active × (1 − Band) ...
	Floor    time.Duration // 5 ms; 0–1 s: ... and at least Floor lower
	Dwell    time.Duration // 3 s; 0.5 s–60 s: continuously qualified this long
	Cooldown time.Duration // 15 s; 1 s–600 s: minimum time between two quality switches
}

// ProbePolicy configures the Peer health layer. While a Peer with two or
// more carrier factories is in use (it has a live session, or a Dial or a
// session end in the last 5 minutes), it keeps one sessionless probe
// carrier per factory and sends a PING on each every Interval. The
// round-trip samples rank the factories for Dial and failover and drive
// selector quality switches (see SelectorPolicy and FactoryStatus). A Peer
// with one carrier factory never probes.
type ProbePolicy struct {
	Interval   time.Duration // 2 s; 0.5 s–30 s: probe PING cadence
	Fresh      time.Duration // 10 s; 2×Interval–120 s: sample freshness
	BackoffMax time.Duration // 4 s; 1 s–8 s: probe redial cadence cap
	DialWait   time.Duration // 800 ms; 0–5 s: how long Dial waits for first samples
}

// HandshakeLimits bound what a Runtime spends on a carrier it accepted
// before admitting it (the PREFACE, the first frame and the written
// verdict), and the OPEN metadata it sends or accepts.
type HandshakeLimits struct {
	Timeout       time.Duration // 10 s; 1 s–60 s: PREFACE + first frame + verdict write
	MaxConcurrent int           // 256; 1–65536: handshake slots per Runtime (the oldest is evicted when full)
	MaxMetadata   int           // 4096; 0–65535: OPEN metadata bytes
}

// SessionlessLimits bound the sessionless probe carriers that dialers'
// Peers keep on a passive Runtime (see ProbePolicy).
type SessionlessLimits struct {
	PerInstance int           // 16; 1–1024: per dialer InstanceID
	Total       int           // 1024; 1–65536: per Runtime
	Idle        time.Duration // 30 s; ≥ 3×max(PingIdle, Probe.Interval): closed after this long without a PING
}
