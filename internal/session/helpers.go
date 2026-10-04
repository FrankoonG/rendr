package session

import "time"

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
	panic("unimplemented: M1b")
}

// openWindowLocked raises rightEdge to rRead + sched.AdvertiseWindow(W,
// Budget.Used, Budget.Max), never retracting it (P10), records rightEdge −
// rRead in lastWin and returns it: the window the dialer puts in OPEN (at
// Dial) and the passive in every OPEN_ACK(OK) (Confirm, duplicate OPENs on
// an open session). It is called by the actor or before the actor's first
// step, so a window below 64 KiB reaches the actor through readvertiseLocked
// in that same or its first step, without a ring.
func (s *Session) openWindowLocked() uint32 {
	panic("unimplemented: M1b")
}

// peerWindowLocked applies the peer's initial window w: peerLimit =
// max(peerLimit, sBase + w). The passive calls it at NewPending
// (OPEN.window), the dialer at binding (the first OPEN_ACK(OK)).
func (s *Session) peerWindowLocked(w uint32) {
	panic("unimplemented: M1b")
}

// applyRxNextLocked applies a JOIN rxNext (passive, inside Session.Join) or
// a JOIN_ACK rxNext (dialer actor) exactly like ACK steps 1 and 3 (design
// §4.6): rx > sNext returns an error (the passive answers BAD_REQUEST; the
// dialer kills that carrier with protocol_violation) and changes nothing;
// rx > sBase advances sBase to rx (trims spans, frees chunks, counts the
// acknowledged bytes, sets lastAdvance, wakes the application writer and
// the data lanes). It never touches peerLimit.
func (s *Session) applyRxNextLocked(rx uint64) error {
	panic("unimplemented: M1b")
}

// requeueLocked moves l's unacknowledged DATA spans (l.infl clipped to
// sBase) into retx and clears l.infl, returning the number of bytes
// requeued. The actor calls it when l loses data eligibility (planned
// switch, passive SCHED move, retirement, peer CLOSE); laneGoneLocked does
// the same on a lane's end. Acknowledged bytes are never requeued (L10).
func (s *Session) requeueLocked(l *lane) (bytes uint64) {
	panic("unimplemented: M1b")
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
	panic("unimplemented: M1b")
}

// laneAddedLocked registers a lane the actor just added to s.lanes: an
// urgent re-ACK bump, ackOnData = true so the first in-order DATA after the
// attach is acknowledged at once (L11, L19), an order refresh and a new
// choice of the ACK duty lane (§4.6). It does not make l data-eligible;
// routing (lane.data) is the actor's.
func (s *Session) laneAddedLocked(l *lane) {
	panic("unimplemented: M1b")
}

// routingChangedLocked wakes the lanes that gained data eligibility after
// the actor changed routing (lane.data, ctl.active), following the wake
// policy of design §4.11 (selector: the active lane; bond: srtt-ordered
// lanes until the spare capacity covers the pending bytes).
func (s *Session) routingChangedLocked() {
	panic("unimplemented: M1b")
}

// bumpAckLocked schedules an ACK (design §4.6). A bump increments ackGen,
// records ackBumped = rRead, clears ackDelayAt and wakes the duty lane if
// it is idle. urgent bumps at once (FIN delivered, DONE queued, SCHED
// applied, a lane attached or died, duplicate DATA, window
// re-advertisement); otherwise the delivery cadence of §4.6 applies
// (AckEvery, else the ACK delay).
func (s *Session) bumpAckLocked(urgent bool) {
	panic("unimplemented: M1b")
}

// endLocked makes the stream terminal (design §4.7): ended = true, endErr =
// err; it wakes every waiter, releases the send chunks (unless wcopying:
// then wfreePending, and the copier releases them) and the receive buffers
// (unless rcopying: then rfreePending, and the reader releases them), and
// stops the deadline timers. A second call changes nothing (no buffer is
// released twice).
func (s *Session) endLocked(err error) {
	panic("unimplemented: M1b")
}

// pendingBytesLocked returns the bytes waiting to be sent: committed but
// never sent (end − sNext) plus queued for retransmission (retx).
func (s *Session) pendingBytesLocked() uint64 {
	panic("unimplemented: M1b")
}

// takeFactsLocked returns the fact bits (fact*) recorded since the last
// call and clears them.
func (s *Session) takeFactsLocked() uint32 {
	panic("unimplemented: M1b")
}

// rescueHolderLocked finds the lane whose infl covers sBase (design §4.11)
// and returns it with the span to duplicate, which starts at sBase and lies
// inside that lane's infl; ok is false when no lane holds sBase (not sent
// yet, or requeued). The actor calls it when the head has been stuck since
// lastAdvance for sched.RescueWait and was not rescued at this sBase, then
// sets st.rescue = {sp, holder} and wakes the other data lanes. How an idle
// actor learns that data became outstanding is described with the fact bits
// in state.go.
func (s *Session) rescueHolderLocked() (holder *lane, sp span, ok bool) {
	panic("unimplemented: M1b")
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
func (s *Session) readvertiseLocked(now time.Time) bool {
	panic("unimplemented: M1b")
}
