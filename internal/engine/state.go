package engine

import "time"

// BridgeState is the lifecycle stage of a single rendr Conn as seen
// by the server-side bridge table (or the client-side mirror).
type BridgeState uint8

const (
	BridgeInit BridgeState = iota
	BridgeHandshaking
	BridgeActive
	// BridgeMigrating: all known paths have died and the engine is
	// holding the application Conn open within MigrationBudget,
	// waiting for any path to come back or a new one to attach.
	BridgeMigrating
	BridgeClosing
	BridgeDead
)

func (s BridgeState) String() string {
	switch s {
	case BridgeInit:
		return "init"
	case BridgeHandshaking:
		return "handshaking"
	case BridgeActive:
		return "active"
	case BridgeMigrating:
		return "migrating"
	case BridgeClosing:
		return "closing"
	case BridgeDead:
		return "dead"
	default:
		return "?"
	}
}

// Limits codifies the engine's safety knobs. Values are the
// CLAUDE.md hard defaults; the engine clamps caller-supplied values
// to these limits.
type Limits struct {
	// MigrationBudget: max time a Conn may have zero usable paths
	// before being torn down. Hard rule #4: 90s.
	MigrationBudget time.Duration

	// ZombieMaxMigrations: number of consecutive completed migrations
	// with zero payload-through before declaring the peer dead. Hard
	// rule #5: 2.
	ZombieMaxMigrations int

	// ZombieCooldown: how long the engine waits before retrying a
	// migration once zombie protection trips. Hard rule #5: 30s.
	ZombieCooldown time.Duration

	// PrimeHysteresis: prime mode requires score(primary) >
	// score(other) * (1 + Hysteresis) for the dwell window before
	// switching. Default 0.25.
	PrimeHysteresis float64

	// PrimeDwell: minimum duration a candidate must remain the
	// best-scoring path before the engine migrates to it. Default 5s.
	PrimeDwell time.Duration

	// PrimeCooldown: minimum gap between two successive prime-mode
	// migrations regardless of score. Default 30s.
	PrimeCooldown time.Duration

	// BondStuckRTTMultiplier: in bond mode, a path whose latest
	// probe-measured RTT exceeds best_path_rtt * Multiplier is
	// skipped on round-robin to keep its slow frames from inflating
	// the receiver's reorder window. Default 3.0. A path with zero
	// RTT reading (unmeasured) is never considered stuck.
	BondStuckRTTMultiplier float64
}

// DefaultLimits returns the project-mandated default limits.
// Changing these requires updating CLAUDE.md.
func DefaultLimits() Limits {
	return Limits{
		MigrationBudget:     90 * time.Second,
		ZombieMaxMigrations: 2,
		ZombieCooldown:      30 * time.Second,
		PrimeHysteresis:        0.25,
		PrimeDwell:             5 * time.Second,
		PrimeCooldown:          30 * time.Second,
		BondStuckRTTMultiplier: 3.0,
	}
}

// Clamp tightens user-supplied limits to the project caps.
// MigrationBudget can be lower than 90s but not higher. The prime
// knobs (hysteresis, dwell, cooldown) accept caller-supplied values
// down to short values so tests can drive prime in seconds rather
// than dozens of seconds; only zero / negative get the default.
func (l Limits) Clamp() Limits {
	def := DefaultLimits()
	if l.MigrationBudget <= 0 || l.MigrationBudget > def.MigrationBudget {
		l.MigrationBudget = def.MigrationBudget
	}
	if l.ZombieMaxMigrations <= 0 {
		l.ZombieMaxMigrations = def.ZombieMaxMigrations
	}
	if l.ZombieCooldown <= 0 {
		l.ZombieCooldown = def.ZombieCooldown
	}
	if l.PrimeHysteresis <= 0 {
		l.PrimeHysteresis = def.PrimeHysteresis
	}
	if l.PrimeDwell <= 0 {
		l.PrimeDwell = def.PrimeDwell
	}
	if l.PrimeCooldown <= 0 {
		l.PrimeCooldown = def.PrimeCooldown
	}
	if l.BondStuckRTTMultiplier <= 1.0 {
		l.BondStuckRTTMultiplier = def.BondStuckRTTMultiplier
	}
	return l
}
