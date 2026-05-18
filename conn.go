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

	// SetMode atomically switches the operational mode.
	// Some transitions are illegal at runtime: race → bond is rejected
	// (race has no per-path sequencing; bond requires it). bond → prime
	// and prime ↔ race are allowed. SetMode returns nil on success or
	// an error describing the rejection cause.
	SetMode(Mode) error

	// FlowID returns the 16-byte flow identifier assigned at handshake.
	// It is invariant for the Conn's lifetime (see docs/architecture.md
	// "不变量").
	FlowID() [16]byte
}

// PacketConn is the datagram analogue of Conn.
type PacketConn interface {
	net.PacketConn

	Paths() []PathInfo
	SetMode(Mode) error
	FlowID() [16]byte
}

// AdminConn extends Conn with operations that are not part of the
// normal application surface: explicit path migration, active-path
// introspection, and dynamic path attach. Tools that drive
// migration externally (chaos harness, runtime balancers, debug
// UIs) assert to this interface.
//
// Application code should NOT depend on AdminConn; the engine
// reserves the right to migrate on its own and an external migrate
// can race with internal scheduling.
type AdminConn interface {
	Conn
	Migrate(pathID uint32) error
	ActivePath() uint32

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

	// State returns the bridge lifecycle stage as a short string:
	// "init", "handshaking", "active", "migrating", "closing",
	// "dead". Production monitoring uses this for a liveness
	// check that doesn't require sending traffic.
	State() string

	// RecvQueueHWM returns the high-water mark of the reorder
	// buffer over this Conn's lifetime. docs/modes.md flags
	// "dedup window overflow" as a hard race-mode bug; this is
	// the observability hook the chaos harness and production
	// dashboards consult to spot it.
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

	// MigrationCount returns the cumulative number of active-path
	// changes since this Conn was established (initial activation
	// is not counted). Both explicit Migrate calls and death-
	// driven failover contribute. Production dashboards use this
	// to detect churn that may need human attention.
	MigrationCount() uint64

	// OnMigrate registers fn to fire (in its own goroutine) on every
	// active-path change. cause is "explicit" for Migrate-driven
	// transitions and "death" for failover via onPathDeath. The
	// returned cancel function unsubscribes. Use this instead of
	// polling MigrationCount when you want push-based notification
	// (e.g. metrics, structured logs).
	OnMigrate(fn func(oldID, newID uint32, cause string)) (cancel func())

	// Mode returns the current operational mode (prime/race/bond).
	// Symmetric counterpart to SetMode; lets callers verify a
	// mode transition succeeded.
	Mode() Mode

	// Stats returns a coherent one-call snapshot of everything a
	// monitoring layer wants to see: flow id, mode, lifecycle
	// state, path list (with per-path counters + quality), active
	// path id, and recv-queue high-water mark. The contents are
	// also obtainable individually but Stats avoids torn reads
	// across getters.
	Stats() ConnStats
}

// ConnStats is the one-call snapshot returned by AdminConn.Stats.
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
}
