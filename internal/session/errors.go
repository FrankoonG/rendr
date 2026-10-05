package session

import (
	"fmt"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// sessionError is a sentinel error that is also a net.Error with
// Timeout() == false (plan §6).
type sessionError struct{ msg string }

func (e *sessionError) Error() string   { return e.msg }
func (e *sessionError) Timeout() bool   { return false }
func (e *sessionError) Temporary() bool { return false }

// Application-visible errors (plan §6). All match with errors.Is; the coded
// ones also with errors.As. rendr re-exports these exact values.
var (
	// ErrNoPath: no carrier for NoPathGrace (passive: PassiveRetain) since the
	// last one was declared dead; or Dial: no OPEN completed within NoPathGrace.
	ErrNoPath error = &sessionError{"rendr: no path"}
	// ErrSessionLost: deterministic loss — the bound instance answered
	// UNKNOWN_SESSION, the peer restarted (plan §3.4), or a pending session
	// was withdrawn by its dialer.
	ErrSessionLost error = &sessionError{"rendr: session lost"}
	// ErrAborted: the session was reset, by the peer or, for
	// AbortExhausted, by this side; *AbortError matches it. A peer reset
	// that arrives once our DONE was sent (both FINs delivered, ours
	// acknowledged) ends the session with io.EOF instead.
	ErrAborted error = &sessionError{"rendr: session aborted"}
	// ErrRejected: Dial was rejected by the peer application; *RejectError matches it.
	ErrRejected error = &sessionError{"rendr: rejected"}
	// ErrCapacity: Dial refused for capacity (CAPACITY, GOING_AWAY, accept
	// timeout, local MaxSessions, abandoned-call pool full).
	ErrCapacity error = &sessionError{"rendr: capacity"}
	// ErrVersion: Dial got a well-formed PREFACE_ACK VERSION or FEATURE.
	ErrVersion error = &sessionError{"rendr: incompatible version"}
	// ErrProtocol: Dial or JOIN got BAD_REQUEST (a code other than
	// CodeMetadataSize), or an invalid local argument would have caused one.
	ErrProtocol error = &sessionError{"rendr: protocol error"}
	// ErrMetadataTooLarge: Dial metadata exceeds the local or the peer's
	// Handshake.MaxMetadata.
	ErrMetadataTooLarge error = &sessionError{"rendr: metadata too large"}
	// ErrIdleTimeout: Config.IdleTimeout expired (the peer receives RST(Idle)).
	ErrIdleTimeout error = &sessionError{"rendr: idle timeout"}
)

// AbortCode is an RST code; values below 256 are reserved for rendr and
// equal the wire.Rst* constants.
type AbortCode uint32

// Reserved abort codes.
const (
	AbortClosed    = AbortCode(wire.RstClosed)    // the peer closed while we were still sending to it
	AbortLinger    = AbortCode(wire.RstLinger)    // the peer's linger expired before its data/FIN were delivered
	AbortGoingAway = AbortCode(wire.RstGoingAway) // the peer Runtime is closing (also implied by GOAWAY from the bound instance)
	AbortExhausted = AbortCode(wire.RstExhausted) // a stream offset reached the offset limit (L14)
	AbortIdle      = AbortCode(wire.RstIdle)      // the peer's IdleTimeout expired
	AbortWithdrawn = AbortCode(wire.RstWithdrawn) // the dialer abandoned Dial after its OPEN may have been admitted (L49)
)

// AbortError is the error of a reset session.
type AbortError struct {
	Code   AbortCode
	Msg    string // ≤ 255 bytes, from the RST
	Remote bool   // true: an RST (or GOAWAY) was received; false: this side ended with Code
}

// Error implements error.
func (e *AbortError) Error() string {
	if e.Remote {
		return fmt.Sprintf("rendr: session aborted by peer (code %d): %s", e.Code, e.Msg)
	}
	return fmt.Sprintf("rendr: session aborted (code %d): %s", e.Code, e.Msg)
}

// Is reports target == ErrAborted.
func (e *AbortError) Is(target error) bool { return target == ErrAborted }

// Timeout implements net.Error (always false).
func (e *AbortError) Timeout() bool { return false }

// Temporary implements net.Error (always false).
func (e *AbortError) Temporary() bool { return false }

// RejectError is the error of a Dial rejected by the peer application
// (PendingConn.Reject).
type RejectError struct {
	Code uint32 // the application's code
	Msg  string // ≤ 255 bytes
}

// Error implements error.
func (e *RejectError) Error() string {
	return fmt.Sprintf("rendr: rejected by peer (code %d): %s", e.Code, e.Msg)
}

// Is reports target == ErrRejected.
func (e *RejectError) Is(target error) bool { return target == ErrRejected }

// Timeout implements net.Error (always false): like every other Dial error
// (plan §6, design §0.7 W3), a rejection is final, not a timeout.
func (e *RejectError) Timeout() bool { return false }

// Temporary implements net.Error (always false).
func (e *RejectError) Temporary() bool { return false }
