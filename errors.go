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
	// ErrDialCleanupCapacity means the process cannot reserve another durable
	// teardown owner before a Dial would invoke external or peer-visible work.
	ErrDialCleanupCapacity             = errors.New("rendr: canceled Dial cleanup authority is at capacity")
	ErrMigrationBudgetExceeded         = engine.ErrMigrationBudgetExceeded
	ErrZombie                          = engine.ErrZombie
	ErrPeerProtoVersion                = engine.ErrPeerProtoVersion
	ErrPeerProtocol                    = engine.ErrPeerProtocol
	ErrPeerClosed                      = engine.ErrPeerClosed
	ErrGracefulCloseTimeout            = engine.ErrGracefulCloseTimeout
	ErrLastPath                        = engine.ErrLastPath
	ErrPacketTooLarge                  = engine.ErrPacketTooLarge
	ErrPacketPathCapacityUnavailable   = engine.ErrPacketPathCapacityUnavailable
	ErrRecvWindowExceeded              = engine.ErrRecvWindowExceeded
	ErrPathAdmissionOutcomeUnknown     = engine.ErrPathAdmissionOutcomeUnknown
	ErrPathAdmissionRejected           = engine.ErrPathAdmissionRejected
	ErrSequenceExhausted               = engine.ErrSequenceExhausted
	ErrSelectorStateEpochExhausted     = engine.ErrSelectorStateEpochExhausted
	ErrMigrationObserverLagged         = engine.ErrMigrationObserverLagged
	ErrMigrationObserverCallbackFailed = engine.ErrMigrationObserverCallbackFailed
	ErrMigrationObserverLimit          = engine.ErrMigrationObserverLimit
	// ErrPacketDestinationMismatch is returned when PacketConn.WriteTo is
	// given a non-nil address other than the session's logical peer.
	ErrPacketDestinationMismatch = errors.New("rendr: packet destination does not match session peer")

	// ErrReadDeadlineExceeded is the sentinel returned by Read /
	// ReadFrom when a SetReadDeadline-set deadline elapses before
	// payload is ready. Implements net.Error with Timeout()==true so
	// idiomatic timeout checks via errors.As work transparently.
	ErrReadDeadlineExceeded net.Error = engine.ErrReadDeadlineExceeded

	// ErrWriteDeadlineExceeded is returned by Write / WriteTo when an
	// application write deadline expires. A non-zero byte count means complete
	// stream frames, or one complete datagram, were already accepted.
	ErrWriteDeadlineExceeded net.Error = engine.ErrWriteDeadlineExceeded
)

// PacketDestinationError describes a rejected PacketConn.WriteTo destination.
// It unwraps to ErrPacketDestinationMismatch for errors.Is checks.
type PacketDestinationError struct {
	ExpectedNetwork string
	ExpectedAddress string
	ActualNetwork   string
	ActualAddress   string
}

func (e *PacketDestinationError) Error() string {
	return ErrPacketDestinationMismatch.Error()
}

func (e *PacketDestinationError) Unwrap() error {
	return ErrPacketDestinationMismatch
}
