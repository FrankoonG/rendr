package session

import (
	"time"

	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// FIN, CloseWrite, Close, RST, DONE and the stream's end (design §4.7).
//
// Our FIN carries the reserved end at the first CloseWrite or Close (D9):
// a Write round already holding a reservation commits below it, every later
// round returns net.ErrClosed, and Fill sends the FIN only after every byte
// below it was sent once and no retransmission is queued (L03, L04, L10).
// The peer's FIN yields io.EOF only at the contiguous delivery point (L02).
// DONE (D4): once our FIN is acknowledged and the peer's FIN is delivered,
// and an ACK carrying FIN_DELIVERED was placed, one more ACK carries
// FIN_DELIVERED|DONE; the actor ends the session when DONE went both ways.

// pendingLocked: a passive session still waiting for its verdict (only RST
// may arrive on its carriers).
func (s *Session) pendingLocked() bool {
	return s.p.Role == RolePassive && s.ctl.state == StatePending
}

// finDueLocked: Fill step 6's condition on a data lane.
func (s *Session) finDueLocked() bool {
	st := &s.st
	return st.fin.requested && !st.fin.acked && st.fin.lane == nil && st.retx.empty() && st.sNext >= st.fin.off
}

// finLocked processes a FIN received on a lane.
func (s *Session) finLocked(off uint64) error {
	st := &s.st
	if st.peerFinSet {
		if off != st.peerFin {
			return errFinConflict
		}
		if st.peerFinDelivered {
			// A FIN resent over another carrier (L05): answer it again.
			s.bumpNowLocked()
		}
		return nil
	}
	switch {
	case off < st.highest():
		return errFinBelowData
	case off > st.rightEdge:
		return errFinBeyondWindow
	}
	st.peerFin = off
	st.peerFinSet = true
	s.peerFinCheckLocked()
	return nil
}

// peerFinCheckLocked delivers the peer's FIN once rRead reached it: the ACK
// with FIN_DELIVERED is queued before any Read can return io.EOF (L05) and
// a reader waiting for the EOF condition is woken.
func (s *Session) peerFinCheckLocked() {
	st := &s.st
	if !st.peerFinSet || st.peerFinDelivered || st.rRead != st.peerFin {
		return
	}
	st.peerFinDelivered = true
	st.ackFlags |= wire.FlagAckFinDelivered
	s.bumpNowLocked()
	st.facts |= factPeerFinDelivered
	s.ringActor()
	if st.rwaiting {
		streamSignal(st.rwake)
	}
}

// maybeDoneLocked queues the final ACK with FIN_DELIVERED|DONE when its
// three conditions hold (D4).
func (s *Session) maybeDoneLocked() {
	st := &s.st
	if st.doneQueued || !st.fin.acked || !st.peerFinDelivered || !st.finDelivSent {
		return
	}
	st.doneQueued = true
	st.ackFlags |= wire.FlagAckDone
	s.bumpNowLocked()
}

// rstLocked stores the first RST received (the actor ends the session with
// *AbortError{Remote: true}; no RST is sent back).
func (s *Session) rstLocked(p []byte) error {
	r, err := wire.ParseRst(p)
	if err != nil {
		return err
	}
	st := &s.st
	if st.rstIn == nil {
		st.rstIn = &wire.Rst{Code: r.Code, Msg: append([]byte(nil), r.Msg...)}
		st.facts |= factRst
		s.ringActor()
	}
	return nil
}

// errSchedCounts: a SCHED claims more migrations than SCHEDs were published
// up to its epoch (design §0.14 B1).
var errSchedCounts error = violation("SCHED migration counts exceed its epoch")

// schedLocked stores the newest SCHED received (passive only; the actor
// applies it, L45). A SCHED not newer than the reference — the newest SCHED
// stored or applied; before any, the passive's initial applied epoch
// FirstEpoch − 1 — is ignored. A newer one whose counts sum to more than
// the SCHEDs the dialer can have published up to its epoch
// (schedCountsFit) is a violation of the carrier that delivered it: the
// session survives (invariant 6), nothing is stored, and the passive's
// counters stay as they are (§0.14 B1).
//
// The bound holds for every SCHED a dialer sends, also resent, reordered
// or after a loss: a selector dialer counts each migration together with
// its own publication in one critical section (lostActiveLocked, the race
// winner's attach, qualitySwitchLocked; the opening publication counts
// nothing), Fill sends the counts belonging to the epoch it sends, and bond
// sends zero. It depends only on the SCHED itself, FirstEpoch and the
// migrations this passive followed, which never decrease, so no SCHED
// received earlier — a forged one within the bound included — can make a
// later legitimate one fail it. For that reason a count below an earlier
// SCHED's is no violation either: the passive cannot tell which of two
// disagreeing SCHEDs is forged, and following never lowers a counter. The
// applied epoch and the counters are actor state, read here under s.mu.
func (s *Session) schedLocked(flags uint8, p []byte) error {
	if s.p.Role == RoleDialer {
		return errSchedOnDialer
	}
	sc, err := wire.ParseSched(p)
	if err != nil {
		return err
	}
	c := &s.ctl
	ref := c.epoch
	if c.schedInSet && !sched.EpochNewer(c.epoch, c.schedIn.Epoch) {
		ref = c.schedIn.Epoch
	}
	if !sched.EpochNewer(sc.Epoch, ref) {
		return nil // stale, or a copy of the reference
	}
	var followed [3]uint64 // a bond passive follows no counts (bond sends zero)
	if s.p.Mode != ModeBond {
		followed = [3]uint64{c.migDeath, c.migQuality, c.migExplicit}
	}
	if !schedCountsFit(&sc, s.p.FirstEpoch, followed) {
		return errSchedCounts
	}
	c.schedIn = sc
	c.schedInCause = wire.SchedCause(flags & wire.SchedCauseMask)
	c.schedInSet = true
	s.st.facts |= factSched
	s.ringActor()
	return nil
}

// schedCountsFit reports whether the counts of sc, a SCHED newer than the
// applied one, sum to at most the number of SCHEDs the dialer can have
// published up to sc.Epoch (each publication counts at most one
// migration). That number is congruent to sc.Epoch − (first − 1) modulo
// 2³². It exceeds f, the sum of the migrations the passive followed (they
// were counted with publications up to the applied epoch, and sc is
// newer), by at most 2³²: fewer than 2³¹ epochs lie between the two, and
// only the opening publication counts nothing. So it is the smallest such
// number above f, also once the epochs wrapped. Forged SCHEDs within the
// bound may raise f, which only loosens it; a bound beyond 2⁶⁴ binds
// nothing.
func schedCountsFit(sc *wire.Sched, first uint32, followed [3]uint64) bool {
	var f uint64
	for _, n := range followed {
		if f+n < f {
			return true
		}
		f += n
	}
	room := f + 1 + uint64(sc.Epoch-(first-1)-uint32(f+1))
	if room <= f {
		return true
	}
	for _, n := range [...]uint64{sc.Death, sc.Quality, sc.Explicit} {
		if n > room {
			return false
		}
		room -= n // the running sum never wraps
	}
	return true
}

// closeWriteLocked requests our FIN at the reserved end (idempotent) and
// wakes a blocked Write (it returns net.ErrClosed) and the data lanes.
func (s *Session) closeWriteLocked(now time.Time) {
	st := &s.st
	if st.fin.requested {
		return
	}
	st.fin.requested = true
	st.fin.off = st.resEnd
	st.facts |= factCloseWrite
	if st.wwaiting {
		streamSignal(st.wwake)
	}
	s.wakeDataLocked(now)
}

// closeLocked is Close under s.mu: CloseWrite semantics, discard mode
// (buffered and future in-order bytes are consumed on arrival; the peer
// keeps being acknowledged), both waiters woken, fact factClose.
func (s *Session) closeLocked(now time.Time) {
	st := &s.st
	if st.closed {
		return
	}
	st.closed = true
	st.closedAt = now
	s.closeWriteLocked(now)
	st.discard = true
	s.consumeAllLocked()
	if st.rwaiting {
		streamSignal(st.rwake)
	}
	if st.wwaiting {
		streamSignal(st.wwake)
	}
	st.facts |= factClose
}
