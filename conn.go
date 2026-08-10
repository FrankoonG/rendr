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

// PacketConn is the datagram analogue of Conn.
type PacketConn interface {
	net.PacketConn

	Paths() []PathInfo
	FlowID() [16]byte
	Status() Status
}

// MigrationController is the optional explicit migration surface shared by
// stream and packet sessions. Normal applications do not need this interface;
// rendr's scheduler and recovery planner migrate automatically.
type MigrationController interface {
	Migrate(pathID uint32) error
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

	// Mode returns the current operational mode
	// (selector/race/bond).
	Mode() Mode

	// Stats returns a coherent one-call snapshot of everything a
	// monitoring layer wants to see: flow id, mode, lifecycle
	// state, path list (with per-path counters + quality), active
	// path id, and recv-queue high-water mark. The contents are
	// also obtainable individually but Stats avoids torn reads
	// across getters.
	Stats() ConnStats
}

// ConnStats is the one-call snapshot returned by ConnectionObserver.Stats.
// Layout is stable; fields are added to the end for forward
// compatibility.
type ConnStats struct {
	FlowID         [16]byte
	State          string
	Mode           Mode
	ActivePath     uint32
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
}
