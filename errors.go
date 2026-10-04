package rendr

import "github.com/FrankoonG/rendr/v2/internal/session"

// Errors (plan §6). They are the same values the core produces, so
// errors.Is and errors.As match. Every sentinel below implements net.Error
// with Timeout() == false, and so do *AbortError and *RejectError. Deadline
// expiry is os.ErrDeadlineExceeded (Timeout() == true) and never ends a
// session; use after Close, Write after CloseWrite and calls after
// Runtime.Close return net.ErrClosed; only the peer's FIN at the contiguous
// delivery point yields io.EOF.
var (
	// ErrNoPath: no carrier for NoPathGrace (passive: PassiveRetain) since the
	// last one was declared dead; or Dial: no OPEN completed within NoPathGrace.
	ErrNoPath = session.ErrNoPath
	// ErrSessionLost: deterministic loss — the bound peer instance answered
	// UNKNOWN_SESSION, or the peer restarted (a redialled carrier reached a
	// new instance while none was alive), or the dialer withdrew a pending
	// session (Confirm/Reject).
	ErrSessionLost = session.ErrSessionLost
	// ErrAborted: the peer reset the session (its linger expired, it closed
	// while we were still sending, its Runtime closed, its IdleTimeout
	// fired); errors.As yields *AbortError.
	ErrAborted = session.ErrAborted
	// ErrRejected: Dial was rejected by the peer application; errors.As
	// yields *RejectError.
	ErrRejected = session.ErrRejected
	// ErrCapacity: Dial refused for capacity: CAPACITY or GOING_AWAY from the
	// peer, the peer's AcceptTimeout, local MaxSessions, or the local
	// abandoned-call pool is full.
	ErrCapacity = session.ErrCapacity
	// ErrVersion: the peer answered PREFACE_ACK VERSION or FEATURE.
	ErrVersion = session.ErrVersion
	// ErrProtocol: the peer answered BAD_REQUEST, or a local argument (such
	// as an unknown Mode) would have caused one.
	ErrProtocol = session.ErrProtocol
	// ErrMetadataTooLarge: DialOptions.Metadata exceeds the local or the
	// peer's Handshake.MaxMetadata.
	ErrMetadataTooLarge = session.ErrMetadataTooLarge
	// ErrIdleTimeout: Config.IdleTimeout expired; the peer gets AbortIdle.
	ErrIdleTimeout = session.ErrIdleTimeout
)

// AbortCode is an RST code. Values below 256 are reserved for rendr.
type AbortCode = session.AbortCode

// Reserved abort codes.
const (
	AbortClosed    = session.AbortClosed    // the peer closed while we were still sending to it
	AbortLinger    = session.AbortLinger    // the peer's linger expired before its data and FIN were delivered
	AbortGoingAway = session.AbortGoingAway // the peer Runtime is closing (also GOAWAY from the bound instance)
	AbortExhausted = session.AbortExhausted // a stream offset reached 2^62
	AbortIdle      = session.AbortIdle      // the peer's IdleTimeout expired
	AbortWithdrawn = session.AbortWithdrawn // the dialer abandoned Dial after its OPEN may have been admitted
)

// AbortError is the error of a reset session: Code, the peer's message, and
// whether the reset came from the peer (Remote) or was decided locally.
// errors.Is(err, ErrAborted) is true for every *AbortError.
type AbortError = session.AbortError

// RejectError is the Dial error when the peer application called
// PendingConn.Reject(Code, Msg). errors.Is(err, ErrRejected) is true; like
// every Dial error it is a net.Error with Timeout() == false.
type RejectError = session.RejectError
