package rendr

import (
	"net"
	"time"
)

// Conn is a stream-oriented rendr connection. It is a net.Conn that
// survives underlying path changes.
//
// Hard contract (CLAUDE.md, hard rule #1): no Read/Write/Close on this
// interface returns an error caused by a migration. A migration in
// flight may pause individual Read/Write calls but never surfaces a
// reset / SO_ERROR / read-zero / write-error. If the migration budget
// (90s) elapses without a usable path, Read/Write will then return a
// real error and the Conn is dead.
type Conn interface {
	net.Conn

	// Paths returns a snapshot of the currently-attached path set.
	Paths() []PathInfo

	// FlowID returns the 16-byte flow identifier assigned at
	// handshake. It is invariant for the Conn's lifetime and serves
	// as the demux key on the server side across path migration.
	FlowID() [16]byte

	// Status returns a minimal runtime snapshot for embedders:
	// local capabilities, peer kind/caps, and attached path state.
	Status() Status
}

// StreamHalfCloser is implemented by rendr stream connections. CloseWrite
// sends an ordered FIN without closing the receive direction.
type StreamHalfCloser interface {
	CloseWrite() error
}

// PacketConn is the datagram analogue of Conn.
type PacketConn interface {
	net.PacketConn

	Paths() []PathInfo
	FlowID() [16]byte
	Status() Status
}

// MigrationController is the optional explicit selector-control surface shared
// by stream and packet sessions. Normal applications do not need this
// interface; rendr's scheduler and recovery planner select targets
// automatically.
type MigrationController interface {
	// SelectTarget selects one immediate child of the named selector. Both
	// arguments are logical target names from the session's frozen Target graph;
	// they are never physical path IDs. targetName may name a Path, Bond, Race,
	// or nested Selector target.
	SelectTarget(selectorName, targetName string) error
}

// PathController is the optional dynamic path-set surface shared by stream
// and packet sessions. AddPath can only restore a leaf that belongs to the
// session's frozen target graph.
type PathController interface {
	// AddPath dials a new path matching spec and joins it to the
	// existing engine via BRIDGE_TAG. Returns the new path id on
	// success. This is the G5 "path recovery" primitive: after a
	// path death, dial a fresh replacement (typically same spec)
	// to bring the path set back to its original cardinality.
	AddPath(spec PathSpec) (uint32, error)

	// RemovePath gracefully detaches the named path. If it is the
	// active path, the engine first failovers to another attached
	// path. Returns ErrLastPath if id is the only attached path;
	// in that case callers who want full teardown should call Close.
	// AddPath/RemovePath are the symmetric primitives for runtime
	// path-set management; the engine itself never calls RemovePath.
	RemovePath(pathID uint32) error
}

// ConnectionObserver exposes coherent migration and scheduling telemetry
// without granting mutation. It is implemented by both Conn and PacketConn
// concrete values and is intentionally separate from the application data
// interfaces.
type ConnectionObserver interface {
	ActivePath() uint32
	// State returns the bridge lifecycle stage as a short string:
	// "init", "handshaking", "active", "migrating", "closing",
	// "dead". Production monitoring uses this for a liveness
	// check that doesn't require sending traffic.
	State() string

	// RecvQueueHWM returns the high-water mark of the reorder
	// buffer over this Conn's lifetime. A consistently-growing HWM
	// in race mode indicates "dedup window overflow" - the receiver
	// is buffering more out-of-order frames than the path RTT skew
	// should produce, suggesting a path is dropping or stuck.
	// Production dashboards consult this to spot the condition.
	RecvQueueHWM() int

	// RecvDups returns the cumulative count of frames whose SEQ
	// had already been delivered (or was already buffered in the
	// reorder window). For race mode this is the duplicate-frames-
	// reaped counter; for any mode it surfaces accidental
	// retransmits.
	RecvDups() uint64

	// BondStuckSkips returns the cumulative count of round-robin
	// slots that bond dispatch bypassed because the candidate
	// path's probe-measured RTT exceeded best_rtt *
	// BondStuckRTTMultiplier. Always zero outside bond mode.
	BondStuckSkips() uint64

	// MigrationCount returns the cumulative number of committed
	// migrations since this Conn was established (initial activation
	// is not counted). Explicit target changes, death-driven failover,
	// and in-place leaf mobility all contribute.
	MigrationCount() uint64

	// OnMigrate registers fn to fire (in its own goroutine) on every
	// committed migration. oldID equals newID for in-place leaf
	// mobility. The returned cancel function unsubscribes. Use this
	// instead of polling MigrationCount for push-based observation.
	OnMigrate(fn func(oldID, newID uint32, cause string)) (cancel func())

	// Stats returns a one-call observation. Topology membership and lifecycle,
	// replay occupancy, and root-delivery evidence share one stable physical
	// topology epoch. Per-path transport counters and quality, plus monotonic
	// receive and scheduler counters, are point observations within that
	// boundary rather than one transactionally frozen sample.
	Stats() ConnStats
}

// ConnStats is the one-call snapshot returned by ConnectionObserver.Stats.
// Layout is stable; fields are added to the end for forward
// compatibility.
type ConnStats struct {
	FlowID     [16]byte
	State      string
	ActivePath uint32
	// EffectivePaths identifies the newest physical incarnation of every leaf
	// currently authorized by the recursive target graph. A selector normally
	// yields one ID; bond and race branches may yield several.
	EffectivePaths []uint32
	Paths          []PathInfo
	RecvQueueHWM   int
	RecvDups       uint64
	BondStuckSkips uint64
	MigrationCount uint64
	// CreatedAt is the wall-clock time at which this connection's
	// engine was constructed. Use time.Since(s.CreatedAt) to compute
	// connection age.
	CreatedAt time.Time
	// PeerCaps are the proto.Caps* bits advertised by the peer's
	// initial HELLO. TUN/l3ingress uses this to reject
	// PreserveL3Identity flows before silently losing L3 metadata.
	PeerCaps uint32
	// PeerInstanceID is the peer's runtime instance id, learned from
	// HELLO/HELLO_ACK. Zero means unknown or legacy peer.
	PeerInstanceID InstanceID
	// TXReplay exposes read-only bounded retransmission occupancy and ACK
	// progress. Limits are factual implementation bounds, not tuning knobs.
	TXReplay ReplayStats
	// RootDelivery reports proof-valid unique application bytes for the local
	// sender's currently published root-selector generation. It is zero for a
	// non-selector root or before the first selector DATA publication.
	RootDelivery RootDeliveryStats
}

// ReplayStats describes the sender's bounded application replay-credit
// domain. Control-frame reserve is accounted separately by the protocol.
type ReplayStats struct {
	FrameLimit         uint64
	ByteLimit          uint64
	FramesInUse        uint64
	BytesInUse         uint64
	FramesHighWater    uint64
	BytesHighWater     uint64
	PublishedNext      uint64
	AckNext            uint64
	CreditWaiters      uint64
	BackpressureEvents uint64
	Generation         uint64
}

// RootDeliveryStats is read-only sender evidence for one root selector's
// current immediate child. Names come from the connection's frozen local
// graph; physical path IDs and protocol-internal target identities are not
// exposed.
type RootDeliveryStats struct {
	TargetName         string
	SelectorName       string
	SelectorGeneration uint64
	EvidenceEpoch      uint64
	Attributable       bool
	PublishedBytes     uint64
	AckedBytes         uint64
	DemandBytes        uint64
}
