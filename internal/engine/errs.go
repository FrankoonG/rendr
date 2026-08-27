package engine

import (
	"errors"
	"fmt"

	"github.com/FrankoonG/rendr/proto"
)

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
	ErrSelectorStateEpochExhausted     = errors.New("rendr: selector state epoch space exhausted")
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

	// ErrPacketPathCapacityUnavailable is returned when packet admission cannot
	// obtain a positive complete-frame capacity from transport.PacketPathConn.
	// Unknown capacity is never interpreted as unlimited.
	ErrPacketPathCapacityUnavailable = errors.New("rendr: packet path frame capacity is unavailable")

	// ErrStreamHalfCloseUnsupported is returned when a directional stream FIN
	// is requested for a packet session.
	ErrStreamHalfCloseUnsupported = errors.New("rendr: stream half-close is unavailable in packet mode")

	// ErrRecvWindowExceeded is recorded when the peer sends frames so
	// far ahead of the current receive head that the bounded reorder
	// buffer would otherwise grow without limit.
	ErrRecvWindowExceeded = errors.New("rendr: receive reorder window exceeded")
)

// PolicyRejectionError preserves the peer's wire-level policy rejection.
// Unwrap keeps errors.Is(err, ErrPolicyRejected) compatible for callers that
// do not need to distinguish retryable transaction races from final rejects.
type PolicyRejectionError struct {
	Phase  proto.PolicyAckPhase
	Code   proto.PolicyAckCode
	Reason string
}

func (e *PolicyRejectionError) Error() string {
	return fmt.Sprintf("%v (phase=%d code=%d): %s", ErrPolicyRejected, e.Phase, e.Code, e.Reason)
}

func (e *PolicyRejectionError) Unwrap() error {
	return ErrPolicyRejected
}

// IsRetryablePolicyRejection reports whether a fresh transaction may resolve
// the peer state represented by err. An explicit Reject is terminal.
func IsRetryablePolicyRejection(err error) bool {
	var rejection *PolicyRejectionError
	if !errors.As(err, &rejection) {
		return false
	}
	switch rejection.Code {
	case proto.PolicyAckCodeBusy, proto.PolicyAckCodeStale, proto.PolicyAckCodeSuperseded:
		return true
	default:
		return false
	}
}
