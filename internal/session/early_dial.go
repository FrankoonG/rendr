package session

import "time"

// EarlyReturn on the dialer (M4 design §A4.1 … §A4.3; WP9a): the deferred
// opening and its trigger, the pre-verdict admission cap, the session's one
// early span, the winning lane's in-flight span, and Close and Abort
// before the verdict. The wave-0 skeleton places the hooks; until WP9a
// they change nothing (package rendr refuses EarlyReturn, so no session is
// deferred).

// triggerOpen starts the opening of a session that Dial returned with
// EarlyReturn: the first caller to clear dialer.deferred posts startOpen
// (M4-D9). Read and CloseWrite call it first; Write calls it right after a
// round's bytes were committed, so the first attempt's early span
// includes them (R1-15). It never blocks and takes only the mailbox's leaf
// lock, so callers may hold s.mu. A no-op for every other session.
func (s *Session) triggerOpen() {
	// M4 WP9a
}

// earlyCapLocked bounds Write's reservation while a dialer session is
// pending (M4-D10, R1-2): room is what the window leaves; the result keeps
// resEnd ≤ Params.EarlyDataMax until the verdict (0: the Write waits for
// it on wwake, which the verdict rings). It returns room unchanged for
// every session that is not a pending dialer.
func (s *Session) earlyCapLocked(room int64) int64 {
	return room // M4 WP9a
}

// earlyCloseLocked is terminationLocked's branch for a dialer still in its
// opening phase (M4-D12): after a Close before the verdict it withdraws
// once now ≥ closeAt + Linger, else arms that deadline; a Close before any
// trigger ends the session locally (nothing sent); an Abort before the
// verdict (st.abortReq: terminationLocked's abort case is not reached
// while the dialer opens) withdraws at once (M4-D20).
func (a *actor) earlyCloseLocked(now time.Time) {
	// M4 WP9a
}

// onStartOpenLocked handles startOpen: the deferred opening starts — the
// opening race and cadence that Dial runs today, openBy = now + Grace —
// and the first attempt fixes the session's early span (R1-2).
func (a *actor) onStartOpenLocked(now time.Time) {
	// M4 WP9a
}

// PeerBound reports whether the session is bound to its peer instance:
// always for a passive session; for a dialer once its first OPEN_ACK(OK)
// was accepted (before Dial returns, except with EarlyReturn: M4-D15).
// PeerInstance is final once it reports true.
func (s *Session) PeerBound() bool {
	return s.p.Role == RolePassive || s.bound.Load()
}
