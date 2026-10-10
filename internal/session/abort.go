package session

import (
	"errors"
	"time"
)

// The core API that package l4 needs (M4 design §A2.3, §A5.4, §A7.6; WP1):
// the application's Abort, the per-session idle override and the pending
// session's context (done channel, deadline, cause and AfterFunc
// registrations). The wave-0 skeleton declares every name; WP1 implements
// them. Until then Abort and SetIdleTimeout return errors.ErrUnsupported,
// the pending phase has no done channel a caller can observe, and the
// actor's hooks below change nothing.

// Abort resets the session now (M4-D20): an RST with code (≥ 256; smaller
// codes are rendr's) and msg (at most 255 bytes) goes to the peer; data
// not yet delivered in either direction is discarded; this side's calls
// return net.ErrClosed; Done closes once the carriers are released. It is
// idempotent; after the session ended it does nothing; after Close it
// replaces the linger with the reset; on a dialer session returned by
// Dial with EarlyReturn that has no verdict yet it withdraws the OPEN.
// Abort, Close, CloseWrite and a peer's RST resolve to one end
// (terminationLocked: the incoming RST first, then st.abortReq).
func (s *Session) Abort(code uint32, msg string) error {
	return errors.ErrUnsupported // M4 WP1
}

// SetIdleTimeout overrides Params.IdleTimeout for this session from now on
// (M4-D21) with Config.IdleTimeout's meaning and clamp: 0 turns idle
// expiry off; any other value is clamped to Params.MinIdleTimeout (10 s
// when 0) … 24 h. The idle clock is not restarted; the actor is rung so
// that a parked one re-arms its deadline (M3-D42). It returns
// net.ErrClosed once the session has ended.
func (s *Session) SetIdleTimeout(d time.Duration) error {
	return errors.ErrUnsupported // M4 WP1
}

// PendingDone returns a channel that is closed exactly once, when this
// passive session leaves StatePending for any reason: Confirm, Reject,
// AcceptTimeout, RefusePending, the dialer's withdrawal, Shutdown (M4-D22).
// nil for a dialer session (never closed).
func (s *Session) PendingDone() <-chan struct{} {
	return nil // M4 WP1: ctl.pendingDone
}

// PendingDeadline returns the AcceptTimeout instant of a started passive
// session (the pending context's Deadline); the zero time for a dialer or
// a session not started yet.
func (s *Session) PendingDeadline() time.Time {
	if s.p.Role != RolePassive {
		return time.Time{}
	}
	if a := s.mb.actor.Load(); a != nil {
		// Start sets acceptBy before it publishes the actor and never
		// changes it afterwards.
		return a.acceptBy
	}
	return time.Time{}
}

// PendingErr returns nil while the passive session is pending, then why
// the pending phase ended as the pending context reports it (R1-8):
// context.DeadlineExceeded when AcceptTimeout ended it, else
// context.Canceled.
func (s *Session) PendingErr() error {
	return nil // M4 WP1: ctl.pendingErr
}

// PendingAfterFunc registers f to run once when the passive session leaves
// StatePending (at once, on its own goroutine, if it already left) and
// returns stop, which unregisters f and reports whether it did so before f
// ran (the context.AfterFunc contract; R1-8: the pending context
// implements AfterFunc with it, so context.AfterFunc and child contexts
// start no goroutine). f runs on the actor goroutine after the session
// lock was released; it must not block.
func (s *Session) PendingAfterFunc(f func()) (stop func() bool) {
	return func() bool { return true } // M4 WP1: ctl.pendingHooks
}

// leavePendingLocked runs at every exit from StatePending (Confirm, the
// dialer's first OPEN_ACK(OK), and terminateLocked for every refusal,
// withdrawal and shutdown), before the state changes: it records
// ctl.pendingErr, closes ctl.pendingDone once and defers the
// pendingHooks until the session lock is released (a.later). It is an
// actor method because only the actor can defer calls past the lock.
func (a *actor) leavePendingLocked() {
	// M4 WP1
}

// idleTimeout is the session's IdleTimeout as terminationLocked applies
// it: st.idleOverride once SetIdleTimeout set it (≥ 0), else
// Params.IdleTimeout.
func (a *actor) idleTimeout() time.Duration {
	return a.s.p.IdleTimeout // M4 WP1: st.idleOverride
}
