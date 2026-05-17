package rendr

import (
	"context"
	"time"
)

// Dialer is the entry point for constructing a rendr Conn.
//
// Dialer is intentionally minimal: the path set is fixed at dial time.
// The engine will not discover paths on its own; the embedder feeds
// candidate PathSpecs and the engine decides when to actually attach
// each (see docs/modes.md).
type Dialer struct {
	// Mode is the initial operational mode.
	Mode Mode

	// Paths are the candidate paths for this connection.
	Paths []PathSpec

	// Hysteresis (prime only): the new path must beat the current by
	// this fraction of the current score before a switch is allowed.
	// Default 0.25.
	Hysteresis float64

	// Dwell (prime only): minimum time the engine must stay on a path
	// after attaching to it. Default 5s.
	Dwell time.Duration

	// Cooldown (prime only): minimum gap between two successive
	// migrations regardless of quality. Default 30s.
	Cooldown time.Duration

	// MigrationBudget caps how long the engine will hold a Conn open
	// after all paths have died. Default and maximum 90s, per
	// CLAUDE.md hard rule #4. Lower values are allowed; higher ones
	// will be clamped to 90s.
	MigrationBudget time.Duration
}

// Dial establishes a rendr Conn using d's configuration. The engine
// performs the HELLO handshake on the first path and then attaches
// remaining Paths according to Mode.
//
// The implementation lives in the engine and transport sub-packages.
// This stub is unimplemented in M0; M1 wires it up against the
// double-ended TCP termination path.
func (d *Dialer) Dial(ctx context.Context) (Conn, error) {
	return nil, ErrNotImplemented
}

// Listener accepts inbound rendr Conns. The set of acceptable
// transports is determined by registering transport adapters on the
// Listener (see transport.Registry).
type Listener interface {
	Accept(ctx context.Context) (Conn, error)
	Close() error
	// FlowIDs returns the live flow_id set for diagnostics.
	FlowIDs() [][16]byte
}
