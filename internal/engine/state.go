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
}

// DefaultLimits returns the project-mandated default limits.
// Changing these requires updating CLAUDE.md.
func DefaultLimits() Limits {
	return Limits{
		MigrationBudget:     90 * time.Second,
		ZombieMaxMigrations: 2,
		ZombieCooldown:      30 * time.Second,
	}
}

// Clamp tightens user-supplied limits to the project caps.
// MigrationBudget can be lower than 90s but not higher.
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
	return l
}
