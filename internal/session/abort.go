package session

import (
	"context"
	"errors"
	"math"
	"net"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The core API that package l4 needs (M4 design §A2.3, §A5.4, §A7.6; WP1):
// the application's Abort, the per-session idle override and the pending
// session's context (done channel, deadline, cause and AfterFunc
// registrations).

// errAbortPacket is Abort's error on a packet session: the reset is a
// stream feature (rendr.Conn); a PacketConn has no Abort.
var errAbortPacket = errors.New("rendr: Abort is for stream sessions")

// noFinOff is the FIN offset Abort records when no FIN was requested yet:
// no send cursor reaches it, so the FIN is never due (finDueLocked,
// raceFinDueLocked) and a CloseWrite racing the Abort cannot request one
// (closeWriteLocked returns once fin.requested is set). The peer then
// never reads io.EOF from an aborted session.
const noFinOff = math.MaxUint64

// Abort resets the session now (M4-D20): an RST with code (≥ 256; smaller
// codes are rendr's) and msg (at most 255 bytes) goes to the peer; data
// not yet delivered in either direction is discarded; this side's calls
// return net.ErrClosed; Done closes once the carriers are released. It is
// idempotent; after the session ended it does nothing; after Close it
// replaces the linger with the reset; on a dialer session returned by
// Dial with EarlyReturn that has no verdict yet it withdraws the OPEN.
// Abort, Close, CloseWrite and a peer's RST resolve to one end
// (terminationLocked: the incoming RST first, then st.abortReq).
//
// Under s.mu it records st.abortReq, closes the application side as Close
// does (blocked and later calls return net.ErrClosed) but requests no FIN
// (noFinOff), and rings the actor, whose next step ends the session with
// the RST (terminationLocked's abort case; earlyCloseLocked's withdrawal
// for a dialer still opening). The code range is the root's check; msg is
// cut to wire.MaxMsg bytes.
func (s *Session) Abort(code uint32, msg string) error {
	if s.pk != nil {
		return errAbortPacket
	}
	if len(msg) > wire.MaxMsg {
		msg = msg[:wire.MaxMsg]
	}
	s.mu.Lock()
	st := &s.st
	if st.ended || st.abortReq != nil {
		s.mu.Unlock()
		return nil
	}
	st.abortReq = &wire.Rst{Code: code, Msg: []byte(msg)}
	if !st.closed {
		st.closed = true
		st.closedAt = time.Now()
	}
	if !st.fin.requested {
		st.fin.requested = true
		st.fin.off = noFinOff
	}
	if st.rwaiting {
		streamSignal(st.rwake)
	}
	if st.wwaiting {
		streamSignal(st.wwake)
	}
	if c := s.closing; c != nil {
		// Calls waiting for rsem or wsem return net.ErrClosed now, as
		// after Close (acquireLocked checks st.closed first).
		s.closing = nil
		close(c)
	}
	s.mu.Unlock()
	s.ringActor()
	return nil
}

// SetIdleTimeout overrides Params.IdleTimeout for this session from now on
// (M4-D21) with Config.IdleTimeout's meaning and clamp: 0 turns idle
// expiry off (a negative value too); any other value is clamped to
// Params.MinIdleTimeout (10 s when 0) … 24 h. The idle clock is not
// restarted; the actor is rung so that a parked one re-arms its deadline
// (M3-D42). It returns net.ErrClosed once the session has ended.
func (s *Session) SetIdleTimeout(d time.Duration) error {
	d = clampIdleOverride(d, s.p.MinIdleTimeout)
	s.mu.Lock()
	if s.st.ended {
		s.mu.Unlock()
		return net.ErrClosed
	}
	s.st.idleOverride = d
	s.mu.Unlock()
	s.ringActor()
	return nil
}

// Idle override bounds (Config.IdleTimeout's range).
const (
	defMinIdleOverride = 10 * time.Second
	maxIdleOverride    = 24 * time.Hour
)

// clampIdleOverride applies SetIdleTimeout's clamp: ≤ 0 is off; else
// [floor (10 s when 0), 24 h].
func clampIdleOverride(d, floor time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	if floor <= 0 {
		floor = defMinIdleOverride
	}
	return min(max(d, floor), maxIdleOverride)
}

// PendingDone returns a channel that is closed exactly once, when this
// passive session leaves StatePending for any reason: Confirm, Reject,
// AcceptTimeout, RefusePending, the dialer's withdrawal, Shutdown (M4-D22).
// nil for a dialer session (never closed).
func (s *Session) PendingDone() <-chan struct{} {
	return s.ctl.pendingDone // made by NewPending before the session is shared; never replaced
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
// context.Canceled. A dialer session always returns nil.
func (s *Session) PendingErr() error {
	s.mu.Lock()
	err := s.ctl.pendingErr
	s.mu.Unlock()
	return err
}

// PendingAfterFunc registers f to run once when the passive session leaves
// StatePending (at once, on its own goroutine, if it already left) and
// returns stop, which unregisters f and reports whether it did so before f
// ran (the context.AfterFunc contract; R1-8: the pending context
// implements AfterFunc with it, so context.AfterFunc and child contexts
// start no goroutine). f runs on the actor goroutine after the session
// lock was released; it must not block. On a dialer session f never runs.
func (s *Session) PendingAfterFunc(f func()) (stop func() bool) {
	h := &pendingHook{f: f}
	s.mu.Lock()
	ctl := &s.ctl
	if ctl.pendingErr != nil {
		s.mu.Unlock()
		go f()
		return func() bool { return false }
	}
	if ctl.pendingDone != nil {
		ctl.pendingHooks = append(ctl.pendingHooks, h)
	}
	s.mu.Unlock()
	return func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		if h.f == nil {
			return false // it ran (or was handed to the actor), or stop ran before
		}
		h.f = nil
		hs := s.ctl.pendingHooks
		for i, x := range hs {
			if x == h {
				// A stopped registration leaves the list at once, so a
				// caller that registers and stops repeatedly (child
				// contexts cancelled before the verdict) keeps it short.
				last := len(hs) - 1
				hs[i] = hs[last]
				hs[last] = nil
				s.ctl.pendingHooks = hs[:last]
				break
			}
		}
		return true
	}
}

// leavePendingLocked runs at every exit from StatePending (Confirm, the
// dialer's first OPEN_ACK(OK), and terminateLocked for every refusal,
// withdrawal and shutdown), before the state changes: it records
// ctl.pendingErr, closes ctl.pendingDone once and defers the
// pendingHooks until the session lock is released (a.later). It is an
// actor method because only the actor can defer calls past the lock.
//
// The cause is read from the verdict its caller recorded first:
// refusePendingLocked's AcceptTimeout answer (CAPACITY, CodeAcceptTimeout,
// pendingLocked) is the only DeadlineExceeded; Confirm, Reject, the
// Listener's and the Runtime's refusals and the withdrawal are Canceled.
// A dialer session has no pending context (pendingDone nil).
func (a *actor) leavePendingLocked() {
	ctl := &a.s.ctl
	if ctl.pendingDone == nil || ctl.pendingErr != nil {
		return
	}
	ctl.pendingErr = context.Canceled
	if v := a.verdict; a.decided && !v.Opened && v.Status == wire.StatusCapacity && v.Code == wire.CodeAcceptTimeout {
		ctl.pendingErr = context.DeadlineExceeded
	}
	close(ctl.pendingDone)
	for i, h := range ctl.pendingHooks {
		if f := h.f; f != nil {
			h.f = nil // its stop now reports false
			a.later = append(a.later, f)
		}
		ctl.pendingHooks[i] = nil
	}
	ctl.pendingHooks = nil
}

// idleTimeout is the session's IdleTimeout as terminationLocked applies
// it: st.idleOverride once SetIdleTimeout set it (≥ 0), else
// Params.IdleTimeout.
func (a *actor) idleTimeout() time.Duration {
	if d := a.s.st.idleOverride; d >= 0 {
		return d
	}
	return a.s.p.IdleTimeout
}
