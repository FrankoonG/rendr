package session

import (
	"math"
	"net"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// Stream helpers the actor calls (design §4.0). Every helper is called with
// s.mu held, never blocks, and changes stream (S) state only as documented
// here.

// initStreamLocked initializes the stream once, before the session is
// visible to any other goroutine (Dial, NewPending): every offset — cbase,
// sBase, sNext, end, resEnd, rRead, rTail, rightEdge and peerLimit — is
// Params.FirstOffset; lastWin is W (nothing advertised yet, so nothing to
// re-advertise); the chunk ring gets capacity W/C + 2; rwake and wwake are
// made (cap 1); the deadline timers and the srtt order slice are prepared.
// Nothing is charged to the Budget.
func (s *Session) initStreamLocked() {
	st := &s.st
	off := s.p.FirstOffset
	st.cbase, st.sBase, st.sNext, st.end, st.resEnd = off, off, off, off, off
	st.rRead, st.rTail, st.rightEdge, st.peerLimit = off, off, off, off
	w := s.window()
	st.chunks = chunkRing{b: make([]*carrier.Buf, w/chunkSize+2)}
	st.rwake = make(chan struct{}, 1)
	st.wwake = make(chan struct{}, 1)
	st.lastWin = w
	// The first echo a dialer accepts is FirstEpoch (serial arithmetic).
	st.echoIn = s.p.FirstEpoch - 1
	now := time.Now()
	st.lastData, st.lastAdvance = now, now
	st.order = make([]*lane, 0, 4)
	// Deadline timers are created by the first Set*Deadline with a future
	// time (§3.6); a zero deadline needs none.
}

// openWindowLocked raises rightEdge to rRead + sched.AdvertiseWindow(W,
// Budget.Used, Budget.Max), never retracting it (P10), records rightEdge −
// rRead in lastWin and returns it: the window the dialer puts in OPEN (at
// Dial) and the passive in every OPEN_ACK(OK) (Confirm, duplicate OPENs on
// an open session). It is called by the actor or before the actor's first
// step, so a window below 64 KiB reaches the actor through readvertiseLocked
// in that same or its first step, without a ring.
func (s *Session) openWindowLocked() uint32 {
	w := min(s.raiseEdgeLocked(), math.MaxUint32)
	s.st.lastWin = int64(w)
	return uint32(w)
}

// peerWindowLocked applies the peer's initial window w: peerLimit =
// max(peerLimit, sBase + w). The passive calls it at NewPending
// (OPEN.window), the dialer at binding (the first OPEN_ACK(OK)).
func (s *Session) peerWindowLocked(w uint32) {
	st := &s.st
	if lim := st.sBase + uint64(w); lim > st.peerLimit {
		st.peerLimit = lim
		if st.end > st.sNext {
			s.wakeDataLocked(time.Now())
		}
	}
}

// applyRxNextLocked applies a JOIN rxNext (passive, inside Session.Join) or
// a JOIN_ACK rxNext (dialer actor) exactly like ACK steps 1 and 3 (design
// §4.6): rx > sNext returns an error (the passive answers BAD_REQUEST; the
// dialer kills that carrier with protocol_violation) and changes nothing;
// rx > sBase advances sBase to rx (trims spans, frees chunks, counts the
// acknowledged bytes, sets lastAdvance, wakes the application writer and
// the data lanes). It never touches peerLimit.
func (s *Session) applyRxNextLocked(rx uint64) error {
	st := &s.st
	if rx > st.sNext {
		return errRxNextBeyondSent
	}
	if rx > st.sBase && !st.ended {
		now := time.Now()
		s.advanceSendLocked(rx, now)
		if s.pullableLocked() > 0 {
			s.wakeDataLocked(now)
		}
	}
	return nil
}

// requeueLocked moves l's unacknowledged DATA spans (l.infl clipped to
// sBase) into retx and clears l.infl, returning the number of bytes
// requeued. The actor calls it when l loses data eligibility (planned
// switch, passive SCHED move, retirement, peer CLOSE); laneGoneLocked does
// the same on a lane's end. Acknowledged bytes are never requeued (L10).
func (s *Session) requeueLocked(l *lane) (bytes uint64) {
	st := &s.st
	l.infl.trimBelow(st.sBase)
	for _, sp := range l.infl.s {
		st.retx.add(sp.off, sp.n)
		bytes += sp.n
	}
	l.infl.reset()
	if bytes > 0 && !st.ended {
		s.wakeDataLocked(time.Now())
	}
	return bytes
}

// laneGoneLocked removes an ended lane from the stream. It requires
// l.state == LaneDead and !l.data, which the actor sets just before in the
// same critical section (design §4.0 C1: a Fill of l that runs afterwards
// appends nothing). It requeues l.infl (returning the bytes requeued),
// clears fin.lane and l.finHere if our FIN went out on l (so the FIN is
// re-sent at the same offset after the replay), removes l from st.order and
// from every duty (the ACK duty moves to another lane with a re-ACK bump,
// §4.6), and wakes the surviving data lanes.
func (s *Session) laneGoneLocked(l *lane) (requeued uint64) {
	if l.state != LaneDead || l.data {
		panic("rendr/session: laneGoneLocked on a lane that is not dead and data-ineligible")
	}
	st := &s.st
	st.orderRemove(l)
	if st.fin.lane == l {
		st.fin.lane = nil
	}
	l.finHere = false
	if st.rescue.holder == l {
		st.rescue = rescueSlot{} // its spans are requeued: the replay resends the head
	}
	if st.ackLane == l {
		st.ackLane = nil
	}
	requeued = s.requeueLocked(l)
	if !st.ended {
		s.bumpNowLocked() // re-ACK on a lane's death (L11), also moving the duty
		if requeued == 0 && s.finDueLocked() {
			s.wakeDataLocked(time.Now())
		}
	}
	return requeued
}

// laneAddedLocked registers a lane the actor just added to s.lanes: an
// urgent re-ACK bump, ackOnData = true so the first in-order DATA after the
// attach is acknowledged at once (L11, L19), an order refresh and a new
// choice of the ACK duty lane (§4.6). It does not make l data-eligible;
// routing (lane.data) is the actor's.
func (s *Session) laneAddedLocked(l *lane) {
	st := &s.st
	for _, o := range st.order {
		if o == l {
			return
		}
	}
	st.order = append(st.order, l)
	s.refreshOrderLocked(time.Now(), true)
	st.ackOnData = true
	if !st.ended {
		s.bumpNowLocked()
	}
}

// routingChangedLocked wakes the lanes that gained data eligibility after
// the actor changed routing (lane.data, ctl.active), following the wake
// policy of design §4.11 (selector: the active lane; bond: srtt-ordered
// lanes until the spare capacity covers the pending bytes). The actor also
// calls it after setting st.rescue, so the rescue span counts as pending.
func (s *Session) routingChangedLocked() {
	if !s.st.ended {
		s.wakeDataLocked(time.Now())
	}
}

// bumpAckLocked schedules an ACK (design §4.6). A bump increments ackGen,
// records ackBumped = rRead, clears ackDelayAt and wakes the duty lane if
// it is idle. urgent bumps at once (FIN delivered, DONE queued, SCHED
// applied, a lane attached or died, duplicate DATA, window
// re-advertisement); otherwise the delivery cadence of §4.6 applies
// (AckEvery, else the ACK delay).
func (s *Session) bumpAckLocked(urgent bool) {
	if urgent {
		s.bumpNowLocked()
	} else {
		s.ackCadenceLocked()
	}
}

// endLocked makes the stream terminal (design §4.7): ended = true, endErr =
// err; it wakes every waiter, releases the send chunks (unless wcopying:
// then wfreePending, and the copier releases them) and the receive buffers
// (unless rcopying: then rfreePending, and the reader releases them), and
// stops the deadline timers. A second call changes nothing (no buffer is
// released twice).
func (s *Session) endLocked(err error) {
	st := &s.st
	if st.ended {
		return
	}
	if err == nil {
		err = net.ErrClosed
	}
	st.ended = true
	st.endErr = err
	if st.rwaiting {
		streamSignal(st.rwake)
	}
	if st.wwaiting {
		streamSignal(st.wwake)
	}
	if st.wcopying {
		st.wfreePending = true
	} else {
		st.releaseChunks()
	}
	if st.rcopying {
		st.rfreePending = true
		st.releaseOOO() // a Read copies only from inq
	} else {
		st.releaseRecv()
	}
	st.retx.reset()
	st.rescue = rescueSlot{}
	st.stopDeadlinesLocked()
}

// pendingBytesLocked returns the bytes waiting to be sent: committed but
// never sent (end − sNext) plus queued for retransmission (retx).
func (s *Session) pendingBytesLocked() uint64 {
	return s.st.end - s.st.sNext + s.st.retx.bytes()
}

// takeFactsLocked returns the fact bits (fact*) recorded since the last
// call and clears them.
func (s *Session) takeFactsLocked() uint32 {
	f := s.st.facts
	s.st.facts = 0
	return f
}

// rescueHolderLocked finds the lane whose infl covers sBase (design §4.11)
// and returns it with the span to duplicate, which starts at sBase and lies
// inside that lane's infl; ok is false when no lane holds sBase (not sent
// yet, or requeued). The actor calls it when the head has been stuck since
// lastAdvance for sched.RescueWait and was not rescued at this sBase, then
// sets st.rescue = {sp, holder} and wakes the other data lanes. How an idle
// actor learns that data became outstanding is described with the fact bits
// in state.go.
//
// The span is the stuck segment: from sBase to the end of the holder's
// span, its chunk or one DATA segment, whichever comes first, so a rescue
// duplicates at most one frame (as msess did).
func (s *Session) rescueHolderLocked() (holder *lane, sp span, ok bool) {
	st := &s.st
	if st.sBase >= st.sNext || st.ended {
		return nil, span{}, false
	}
	x := st.sBase
	for _, l := range st.order {
		for _, h := range l.infl.s {
			if h.off > x {
				break
			}
			if x < h.end() {
				e := min(h.end(), st.chunkEnd(x), x+s.segment())
				return l, span{x, e - x}, true
			}
		}
	}
	return nil, span{}, false
}

// readvertiseLocked is the actor's window re-advertisement step at now
// (design D18, §4.6, §4.12). While lastWin, the window last advertised, is
// below 64 KiB, it bumps an urgent ACK when the right edge can advance at
// the current Budget usage (rRead + sched.AdvertiseWindow(W, Budget.Used,
// Budget.Max) > rightEdge); it changes nothing else.
//
// It returns lastWin < 64 KiB as it stands after that bump (false once the
// stream ended). A bump only queues an ACK, and lastWin changes only when
// Fill places one, so the actor, which calls readvertiseLocked in every
// step, keeps its Params.WindowReadvertise deadline armed until an ACK
// carrying at least 64 KiB has actually been placed. If the Budget fills up
// again before the queued ACK is placed, that ACK carries a small window,
// lastWin stays below 64 KiB and the next deadline retries. (Reporting
// instead whether the window advertisable now is below 64 KiB would let the
// actor disarm before the ACK is placed and leave the peer stalled at
// window 0 with nothing left to wake either side.)
//
// Fill rings the actor (ringActor) when an ACK it places takes lastWin from
// 64 KiB or more to below it, so an idle actor arms the deadline; an ACK
// that leaves lastWin below 64 KiB needs no ring because the deadline is
// still armed.
//
// "64 KiB" is min(64 KiB, W): a smaller configured window (tests) can never
// advertise more than itself.
func (s *Session) readvertiseLocked(now time.Time) bool {
	st := &s.st
	if st.ended {
		return false
	}
	floor := s.readvertiseFloor()
	if st.lastWin >= floor {
		return false
	}
	edge := st.rightEdge
	if s.raiseEdgeLocked(); st.rightEdge > edge {
		// The edge is only advertisable now: the ACK that carries it raises
		// it again when placed (the fatal threshold is the largest edge
		// actually advertised).
		st.rightEdge = edge
		s.bumpNowLocked()
	}
	return true
}
