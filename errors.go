package rendr

import "errors"

// Sentinel errors surfaced by the rendr API. The set is small on
// purpose: the contract is that migrations do not surface errors at
// all (CLAUDE.md hard rule #1), so the only errors that ever escape
// the API are end-of-life errors.
var (
	// ErrMigrationBudgetExceeded means all paths died and no new one
	// became usable within the configured MigrationBudget. The Conn
	// is dead.
	ErrMigrationBudgetExceeded = errors.New("rendr: migration budget exceeded")

	// ErrZombie means the connection completed two consecutive
	// migrations without delivering any payload, so the engine
	// concluded the remote peer is dead and stopped trying
	// (CLAUDE.md hard rule #5).
	ErrZombie = errors.New("rendr: zombie connection detected")

	// ErrModeSwitchIllegal is returned by Conn.SetMode for transitions
	// that the engine refuses (e.g. race → bond).
	ErrModeSwitchIllegal = errors.New("rendr: illegal mode transition")

	// ErrPeerProtoVersion means the remote announced a protocol
	// version this build cannot speak.
	ErrPeerProtoVersion = errors.New("rendr: incompatible protocol version")

	// ErrNotImplemented is a build-stage placeholder used by API
	// surfaces whose implementations land in later milestones.
	ErrNotImplemented = errors.New("rendr: not implemented in this milestone")
)
