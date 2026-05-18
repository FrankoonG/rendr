package rendr

import (
	"errors"
	"net"

	"github.com/FrankoonG/rendr/internal/engine"
)

// Sentinel errors surfaced by the rendr API. The set is small on
// purpose: the contract is that migrations do not surface errors at
// all (CLAUDE.md hard rule #1), so the only errors that ever escape
// the API are end-of-life errors.
//
// The three end-of-life errors live in internal/engine so the engine
// can return them directly; rendr re-exports the same value so
// callers can errors.Is against rendr.ErrFoo and have it match what
// the engine returned.
var (
	ErrMigrationBudgetExceeded = engine.ErrMigrationBudgetExceeded
	ErrZombie                  = engine.ErrZombie
	ErrPeerProtoVersion        = engine.ErrPeerProtoVersion
	ErrLastPath                = engine.ErrLastPath
	ErrPacketTooLarge          = engine.ErrPacketTooLarge

	// ErrReadDeadlineExceeded is the sentinel returned by Read /
	// ReadFrom when a SetReadDeadline-set deadline elapses before
	// payload is ready. Implements net.Error with Timeout()==true so
	// idiomatic timeout checks via errors.As work transparently.
	ErrReadDeadlineExceeded net.Error = engine.ErrReadDeadlineExceeded

	// ErrModeSwitchIllegal is returned by Conn.SetMode for transitions
	// that the engine refuses (e.g. race -> bond).
	ErrModeSwitchIllegal = errors.New("rendr: illegal mode transition")

	// ErrNotImplemented is a build-stage placeholder used by API
	// surfaces whose implementations land in later milestones.
	ErrNotImplemented = errors.New("rendr: not implemented in this milestone")
)
