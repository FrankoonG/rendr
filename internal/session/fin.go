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

// schedLocked stores the newest SCHED received (passive only; the actor
// validates the epoch order and applies it, L45).
func (s *Session) schedLocked(flags uint8, p []byte) error {
	if s.p.Role == RoleDialer {
		return errSchedOnDialer
	}
	sc, err := wire.ParseSched(p)
	if err != nil {
		return err
	}
	c := &s.ctl
	if !c.schedInSet || sched.EpochNewer(sc.Epoch, c.schedIn.Epoch) {
		c.schedIn = sc
		c.schedInCause = wire.SchedCause(flags & wire.SchedCauseMask)
		c.schedInSet = true
		s.st.facts |= factSched
		s.ringActor()
	}
	return nil
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
