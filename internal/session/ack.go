package session

import (
	"math"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// ACK (design §4.6). An ACK is session state, not a queued frame: a bump
// increments ackGen and the duty lane (ackLane) places one ACK carrying the
// values current at placement (latest wins) once its ackSent differs. The
// duty lane is a qualifying lane whose writer is not blocked, so an ACK
// never waits behind a stuck carrier for more than PingBusy (L08; D5).
//
// Receiver cadence: a bump once AckEvery bytes were delivered since the
// last bump, else an ACK delay armed at the first unacknowledged delivery
// that the duty lane's writer timer fires (b.WakeAt), never the actor.
// Urgent bumps: FIN delivered, DONE queued, SCHED applied, a lane attached
// or died, duplicate DATA, the first DATA after an attach, re-advertisement.
//
// Sender side: Delivered beyond sNext and a regression on the same carrier
// are violations of that carrier (L13, P3); lower ACKs from other carriers
// merge by max.

// bumpNowLocked schedules an ACK at once: ackGen++, ackBumped = rRead, the
// ACK delay disarmed, and the duty lane (re-chosen if it no longer
// qualifies) woken if idle.
func (s *Session) bumpNowLocked() {
	st := &s.st
	st.ackGen++
	st.ackBumped = st.rRead
	st.ackDelayAt = time.Time{}
	s.ensureAckLaneLocked()
	if l := st.ackLane; l != nil && l.idle {
		l.idle = false
		l.port.Wake()
	}
	if l := st.gapLane; l != nil && l.idle {
		l.idle = false
		l.port.Wake()
	}
}

// gapAckLocked runs after every Data call on lane l that started at offset
// off while the in-order end was tail (design §0.13 A4; L34). A bond
// receiver holding out-of-order data lacks bytes that some lane carries; if
// that lane is the ACK duty lane and its path stalled while its conn still
// accepts writes, the duty never moves (its writes do not block) and every
// ACK sits in the stalled path: the sender's acknowledged front goes stale
// and its rescue duplicates bytes this side already has. So while
// out-of-order data is held, a lane other than the duty lane that delivers
// DATA beyond the in-order end becomes the gap lane and carries every ACK
// as well (Fill), over the path that evidently delivers; it is woken when
// it owes one. The gap lane is dropped once nothing is held out of order
// (or with its lane, laneGoneLocked). A selector receiver never holds
// out-of-order data, and in a healthy bond out-of-order data mostly arrives
// on the lowest-srtt lane, which usually holds the duty: the extra ACKs are
// rare.
func (s *Session) gapAckLocked(l *lane, off, tail uint64) {
	st := &s.st
	if len(st.ooq.s) == 0 || st.ended {
		st.gapLane = nil
		return
	}
	if off <= tail || l == st.ackLane {
		return
	}
	st.gapLane = l
	if l.ackSent != st.ackGen && l.idle {
		l.idle = false
		l.port.Wake()
	}
}

// ackCadenceLocked applies the delivery cadence after rRead advanced.
func (s *Session) ackCadenceLocked() {
	st := &s.st
	if st.rRead-st.ackBumped >= s.ackEvery() {
		s.bumpNowLocked()
		return
	}
	if st.rRead > st.ackBumped && st.ackDelayAt.IsZero() {
		st.ackDelayAt = time.Now().Add(s.ackDelay())
		s.ensureAckLaneLocked()
		// Once: its Fill arms the writer timer (b.WakeAt) for ackDelayAt —
		// the gap lane's too (§0.13 A4).
		if l := st.ackLane; l != nil && l.idle {
			l.idle = false
			l.port.Wake()
		}
		if l := st.gapLane; l != nil && l.idle {
			l.idle = false
			l.port.Wake()
		}
	}
}

// ackQualifiesLocked: l may carry the session's ACKs — it is live, has sent
// (passive) or received (dialer) its first response frame, that frame was
// not a refusal (nothing follows a refusal), and it has not written CLOSE.
func (s *Session) ackQualifiesLocked(l *lane) bool {
	if l.state == LaneDead {
		return false
	}
	if s.p.Role == RolePassive {
		if !l.firstSent || refusedLocked(l) {
			return false
		}
	} else if l.state == LaneJoining {
		return false
	}
	return !l.port.CloseSent()
}

// ackKeepLocked: the current duty lane keeps the duty.
func (s *Session) ackKeepLocked(l *lane) bool {
	return s.ackQualifiesLocked(l) && !l.retireCalled && !l.port.WriteBlocked()
}

// chooseAckLaneLocked returns the best qualifying lane other than skip: in
// srtt order, the first lane neither write-blocked nor retiring (Retire
// called); else the first writable retiring lane (it still carries frames
// until its CLOSE, and Fill places a pending delayed ACK there before the
// CLOSE); else the first blocked one, preferring one that is not retiring;
// nil if none qualifies. Writability comes first (§4.6: an ACK never waits
// behind a blocked carrier while a writable lane qualifies).
func (s *Session) chooseAckLaneLocked(skip *lane) *lane {
	s.refreshOrderLocked(time.Now(), false)
	var best *lane
	bestRank := 4
	for _, l := range s.st.order {
		if l == skip || !s.ackQualifiesLocked(l) {
			continue
		}
		rank := 0
		if l.port.WriteBlocked() {
			rank = 2
		}
		if l.retireCalled {
			rank++
		}
		if rank < bestRank {
			best, bestRank = l, rank
			if rank == 0 {
				break
			}
		}
	}
	return best
}

// ensureAckLaneLocked keeps the current duty lane while it qualifies, is
// not retiring and is not write-blocked; otherwise it moves the duty to the
// best qualifying lane (chooseAckLaneLocked, which may keep the current
// one if nothing better exists) or clears it.
func (s *Session) ensureAckLaneLocked() {
	st := &s.st
	cur := st.ackLane
	if cur != nil && s.ackKeepLocked(cur) {
		return
	}
	if l := s.chooseAckLaneLocked(nil); l != nil {
		st.ackLane = l
	} else if cur != nil && !s.ackQualifiesLocked(cur) {
		st.ackLane = nil
	}
}

// raiseEdgeLocked raises the right edge to rRead + the window advertisable
// at the current Budget usage (never retracting it, P10) and returns the
// window rightEdge − rRead.
func (s *Session) raiseEdgeLocked() uint64 {
	st := &s.st
	var used, max int64
	if b := s.env.Carrier.Budget; b != nil {
		used, max = b.Used(), b.Max()
	}
	if e := st.rRead + uint64(sched.AdvertiseWindow(s.window(), used, max)); e > st.rightEdge {
		st.rightEdge = e
	}
	return st.rightEdge - st.rRead
}

// fillAckLocked is Fill step 4 on the duty lane l: the ACK-delay rule, then
// one ACK if l owes one. On a lane on which Retire was called a pending
// delayed ACK is due at once: its writer appends CLOSE after a Fill that
// placed nothing and then exits, dropping the WakeAt, so the ACK would wait
// for the next 64 KiB or urgent bump (the actor sets retireCalled before it
// calls Conn.Retire).
func (s *Session) fillAckLocked(l *lane, b *carrier.Batch) {
	st := &s.st
	if !st.ackDelayAt.IsZero() {
		if l.retireCalled || !b.Now().Before(st.ackDelayAt) {
			st.ackGen++
			st.ackBumped = st.rRead
			st.ackDelayAt = time.Time{}
		} else {
			b.WakeAt(st.ackDelayAt)
		}
	}
	if l.ackSent == st.ackGen {
		return
	}
	// The edge is raised only if the ACK is placed: the receiver's fatal
	// threshold is the largest edge actually advertised.
	edge := st.rightEdge
	win := s.raiseEdgeLocked()
	a := wire.Ack{Delivered: st.rRead, Window: uint32(min(win, math.MaxUint32))}
	if s.p.Role == RolePassive {
		a.EpochEcho = s.ctl.epoch
	}
	flags := st.ackFlags
	if !b.AddAck(wire.SessionHandle, flags, &a) {
		st.rightEdge = edge
		return
	}
	l.ackSent = st.ackGen
	prev := st.lastWin
	st.lastWin = int64(a.Window)
	if floor := s.readvertiseFloor(); prev >= floor && st.lastWin < floor {
		s.ringActor() // W6: the actor arms its re-advertisement deadline
	}
	if flags&wire.FlagAckFinDelivered != 0 && !st.finDelivSent {
		st.finDelivSent = true
		s.maybeDoneLocked()
	}
	if flags&wire.FlagAckDone != 0 && !st.doneSent {
		st.doneSent = true
		st.doneSentAt = b.Now()
		st.facts |= factDoneSent
		s.ringActor()
	}
}

// ackLocked processes an ACK received on lane l (design §4.6 sender side).
func (s *Session) ackLocked(l *lane, flags uint8, a *wire.Ack) error {
	st := &s.st
	finDelivered := flags&wire.FlagAckFinDelivered != 0
	switch {
	case a.Delivered > st.sNext:
		return errAckBeyondSent
	case a.Delivered < l.lastAck:
		return errAckRegression
	case finDelivered && (!st.fin.requested || a.Delivered < st.fin.off):
		return errFinDeliveredEarly
	}
	l.lastAck = a.Delivered
	var now time.Time
	if a.Delivered > st.sBase {
		now = time.Now()
		s.advanceSendLocked(a.Delivered, now)
	}
	if lim := a.Delivered + uint64(a.Window); lim > st.peerLimit {
		// The peer's right edge never retracts (P10): max merge. Growth
		// that makes more committed bytes sendable wakes the data lanes.
		before := max(st.sNext, min(st.end, st.peerLimit))
		st.peerLimit = lim
		if min(st.end, lim) > before {
			if now.IsZero() {
				now = time.Now()
			}
			s.wakeDataLocked(now)
		}
	}
	if finDelivered && !st.fin.acked {
		st.fin.acked = true
		if fl := st.fin.lane; fl != nil {
			fl.finHere = false
			st.fin.lane = nil
		}
		st.facts |= factFinAcked
		s.ringActor()
		s.maybeDoneLocked()
	}
	if flags&wire.FlagAckDone != 0 && !st.peerDone {
		st.peerDone = true
		st.facts |= factPeerDone
		s.ringActor()
	}
	if s.p.Role == RoleDialer && sched.EpochNewer(a.EpochEcho, st.echoIn) && !sched.EpochNewer(a.EpochEcho, s.ctl.epoch) {
		// An echo of an epoch never published is ignored, so a passive that
		// echoes its initial value cannot run the counter ahead.
		st.echoIn = a.EpochEcho
		st.facts |= factEcho
		s.ringActor()
	}
	return nil
}
