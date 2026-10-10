package l4

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/FrankoonG/rendr/v2"
)

// Server defaults.
const (
	DefaultIdleTimeout = 10 * time.Minute // the L4 stream idle default (plan:660)
	DefaultDialTimeout = 5 * time.Second  // below the Listener's AcceptTimeout (10 s)
	DefaultMaxConns    = 10000
)

// maxHookCalls bounds the custom Dial hook calls a Server runs at once, in
// flight or abandoned (M4-D28, R1-9); at the cap a request is rejected
// CodeCapacity without calling the hook.
const maxHookCalls = 192

// Server serves L4 sessions; the zero value is ready. A Server must not be
// copied after first use.
type Server struct {
	// Dial opens the target. nil: a net.Dialer's DialContext on "tcp" and
	// r.Addr. It should honour ctx; a call still running one second after
	// its budget is abandoned and answered CodeTimeout, and the conn it
	// returns later is closed. Return an error wrapping ErrDenied to refuse
	// by policy (CodeNotAllowed). A panic is answered CodeDialFailed. ctx
	// bounds the dial only; it is cancelled after the dial returns, and the
	// returned conn must not depend on it. At most 192 calls run at
	// once, abandoned ones included.
	Dial func(ctx context.Context, r Request) (net.Conn, error)
	// DialTimeout bounds one target dial (0: DefaultDialTimeout; clamped to
	// 0.5–30 s) and never runs past the pending session's AcceptTimeout
	// minus 250 ms, so a slow target is answered CodeTimeout.
	DialTimeout time.Duration
	// IdleTimeout is set on every served session (0: DefaultIdleTimeout;
	// negative: none).
	IdleTimeout time.Duration
	// MaxConns bounds the sessions this Server dials for or forwards at once
	// (0: DefaultMaxConns); a session beyond it is rejected CodeCapacity at
	// once.
	MaxConns int
}

// Serve accepts stream sessions from ln until ctx is done or Accept fails
// and handles each on its own goroutine (see Handle). Cancelling ctx
// resets every connection it serves. Serve returns after every connection
// it started has ended, with ctx.Err() or Accept's error (net.ErrClosed
// after Listener.Close or Runtime.Close; confirmed connections keep running
// until they end or ctx is done). Packet sessions are never accepted.
// Abandoned Dial hook calls may outlive Serve; Status counts them.
//
// Not implemented yet: it returns errors.ErrUnsupported at once.
func (s *Server) Serve(ctx context.Context, ln *rendr.Listener) error {
	return errors.ErrUnsupported // M4 WP5
}

// Handle serves one pending session and returns when its connection
// ended: the OPEN's metadata names the target (malformed: rejected with the
// matching code), the target is dialled while the session is pending, the
// session is confirmed after the target connected (a dial failure is
// rejected with the matching code), and Forward runs until it ends. Use it
// to serve L4 sessions from a Listener shared with other sessions (Match
// tells them apart).
//
// Not implemented yet: it rejects p with CodeDialFailed.
func (s *Server) Handle(ctx context.Context, p *rendr.PendingConn) {
	_ = p.Reject(uint32(CodeDialFailed), "l4: not implemented") // M4 WP5
}

// Status returns a snapshot of the Server's counters.
//
// Not implemented yet: it returns the zero ServerStatus.
func (s *Server) Status() ServerStatus {
	return ServerStatus{} // M4 WP5
}

// Serve is (&Server{}).Serve(ctx, ln).
func Serve(ctx context.Context, ln *rendr.Listener) error {
	return (&Server{}).Serve(ctx, ln)
}

// ServerStatus counts what a Server does.
type ServerStatus struct {
	Dialing, Live       int    // sessions being dialled for; connections being forwarded
	Hooks               int    // custom hook calls running, in flight or abandoned (≤ 192)
	Abandoned           int    // hook calls still running past their bound
	Confirmed, Rejected uint64 // totals
	Unconfirmed         uint64 // dialled, then reset because Confirm failed
	Lost                uint64 // the pending phase ended during the dial; no Reject sent
	ByCode              map[RejectCode]uint64
	Panics              uint64 // recovered hook panics and Goexits
	LastErr             error  // the last raw dial error (never sent to the dialer)
}
