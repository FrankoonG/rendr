package engine

import "errors"

// Sentinel errors the engine surfaces upward. The top-level rendr
// package re-exports these as rendr.ErrMigrationBudgetExceeded etc.
// so callers can errors.Is against the rendr.* symbol without
// reaching into internal/engine.
var (
	ErrMigrationBudgetExceeded = errors.New("rendr: migration budget exceeded")
	ErrZombie                  = errors.New("rendr: zombie connection detected")
	ErrPeerProtoVersion        = errors.New("rendr: incompatible protocol version")

	// ErrLastPath is returned by RemovePath when the named path is
	// the only attached path. Callers who want to fully tear down
	// the connection should call Close instead.
	ErrLastPath = errors.New("rendr: cannot remove the only attached path")
)
