package rendr

import "github.com/FrankoonG/rendr/v2/internal/session"

// Session and Dial errors. They are the same values the core produces, so
// errors.Is and errors.As match. Every sentinel below implements net.Error
// with Timeout() == false, and so do *AbortError and *RejectError. Deadline
// expiry is os.ErrDeadlineExceeded (Timeout() == true) and never ends a
// session; use after Close, Write after CloseWrite and calls after
// Runtime.Close return net.ErrClosed; only the peer's FIN at the contiguous
// delivery point yields io.EOF.
var (
	// ErrNoPath: no carrier for NoPathGrace (passive: PassiveRetain, see the
	// package documentation) since the last one was declared dead; or Dial:
	// no OPEN completed within NoPathGrace.
	ErrNoPath = session.ErrNoPath
	// ErrSessionLost: deterministic loss — the bound peer instance answered
	// UNKNOWN_SESSION, or the peer restarted (a redialled carrier reached a
	// new instance while none was alive), or the dialer withdrew a pending
	// session (Confirm/Reject).
	ErrSessionLost = session.ErrSessionLost
	// ErrAborted: the session was reset, by the peer (its linger expired, it
	// closed while we were still sending, its Runtime closed, its
	// IdleTimeout fired, ...) or, for AbortExhausted, by this side;
	// errors.As yields *AbortError. A peer reset that arrives once this side
	// has sent its final confirmation (both FINs were delivered and this
	// side's FIN was acknowledged, so the peer only gave up waiting for that
	// confirmation) ends the session with io.EOF instead.
	ErrAborted = session.ErrAborted
	// ErrRejected: Dial was rejected by the peer application; errors.As
	// yields *RejectError.
	ErrRejected = session.ErrRejected
	// ErrCapacity: Dial refused for capacity: CAPACITY from the peer (its
	// MaxSessions, a full backlog or a closed Listener, its AcceptTimeout),
	// GOING_AWAY from the peer (its Runtime is closing), local MaxSessions,
	// or the local abandoned-call pool is full.
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

// AbortCode is an RST code: why a session was reset. Its underlying type is
// uint32. Values below 256 are reserved for rendr, which uses 1
// (AbortClosed), 2 (AbortLinger), 3 (AbortGoingAway), 4 (AbortExhausted),
// 5 (AbortIdle) and 6 (AbortWithdrawn).
type AbortCode = session.AbortCode

// Reserved abort codes.
const (
	AbortClosed    = session.AbortClosed    // 1: the peer closed while we were still sending to it
	AbortLinger    = session.AbortLinger    // 2: the peer's linger expired before its data and FIN were delivered
	AbortGoingAway = session.AbortGoingAway // 3: the peer Runtime is closing (also GOAWAY from the bound instance)
	AbortExhausted = session.AbortExhausted // 4: a stream offset reached 2^62
	AbortIdle      = session.AbortIdle      // 5: the peer's IdleTimeout expired
	AbortWithdrawn = session.AbortWithdrawn // 6: the dialer abandoned Dial after its OPEN may have been admitted
)

// AbortError is the error of a reset session. errors.Is(err, ErrAborted) is
// true for every *AbortError, and it is a net.Error with Timeout() == false.
// It is a struct with these fields:
//
//	Code   AbortCode // why the session was reset (see the reserved codes)
//	Msg    string    // the reset's message, at most 255 bytes
//	Remote bool      // true: the peer reset it or is going away; false: this side reset it (AbortExhausted)
type AbortError = session.AbortError

// RejectError is the Dial error when the peer application called
// PendingConn.Reject. errors.Is(err, ErrRejected) is true; like every Dial
// error it is a net.Error with Timeout() == false. It is a struct with these
// fields:
//
//	Code uint32 // the code passed to Reject
//	Msg  string // the message passed to Reject, truncated to 255 bytes
type RejectError = session.RejectError
