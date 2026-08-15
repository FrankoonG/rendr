package engine

import "errors"

// Sentinel errors the engine surfaces upward. The top-level rendr
// package re-exports these as rendr.ErrMigrationBudgetExceeded etc.
// so callers can errors.Is against the rendr.* symbol without
// reaching into internal/engine.
var (
	ErrMigrationBudgetExceeded         = errors.New("rendr: migration budget exceeded")
	ErrZombie                          = errors.New("rendr: zombie connection detected")
	ErrPeerProtoVersion                = errors.New("rendr: incompatible protocol version")
	ErrPeerProtocol                    = errors.New("rendr: peer protocol violation")
	ErrPeerClosed                      = errors.New("rendr: peer requested close")
	ErrGracefulCloseTimeout            = errors.New("rendr: graceful close was not acknowledged")
	ErrPolicyRejected                  = errors.New("rendr: peer rejected policy transaction")
	ErrPolicyOutcomeUnknown            = errors.New("rendr: policy transaction outcome is unknown")
	ErrSelectorDecisionUnavailable     = errors.New("rendr: selector decision is temporarily unavailable")
	ErrPathAdmissionOutcomeUnknown     = errors.New("rendr: path admission outcome is unknown")
	ErrPathAdmissionRejected           = errors.New("rendr: path admission rejected")
	ErrSequenceExhausted               = errors.New("rendr: frame sequence space exhausted")
	errPathAdmissionRouteChanged       = errors.New("engine: path admission route changed")
	errPolicySelectionLeafMobilityHeld = errors.New("engine: selector branch is held by leaf mobility")

	// ErrLastPath is returned by RemovePath when the named path is
	// the only attached path. Callers who want to fully tear down
	// the connection should call Close instead.
	ErrLastPath = errors.New("rendr: cannot remove the only attached path")

	// ErrPacketTooLarge is returned when a packet plus the session DATA
	// envelope cannot fit the engine or carrier frame budget. Packet mode
	// preserves boundaries 1-to-1, so it rejects instead of fragmenting.
	ErrPacketTooLarge = errors.New("rendr: packet exceeds session payload budget")

	// ErrStreamHalfCloseUnsupported is returned when a directional stream FIN
	// is requested for a packet session.
	ErrStreamHalfCloseUnsupported = errors.New("rendr: stream half-close is unavailable in packet mode")

	// ErrRecvWindowExceeded is recorded when the peer sends frames so
	// far ahead of the current receive head that the bounded reorder
	// buffer would otherwise grow without limit.
	ErrRecvWindowExceeded = errors.New("rendr: receive reorder window exceeded")
)
