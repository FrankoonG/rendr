package session

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Passive sessions on the actor side (design §6.2, §6.3; D8, D28): the
// pending phase and its verdicts, adopted carriers (JOINs and duplicate
// OPENs), and the confirmation of a lane once its first response frame was
// placed. A pending session survives the death of its carriers; it ends
// only by a verdict executed here — Confirm, Reject, AcceptTimeout
// (CAPACITY), RefusePending (its Listener closed: CAPACITY, or GOING_AWAY
// while the Runtime closes), Shutdown (GOING_AWAY) — or by the dialer's
// RST(AbortWithdrawn).

// errDecided is Confirm's or Reject's error when a verdict already ran.
var errDecided = errors.New("rendr: pending session already confirmed or rejected")

// verdictErr maps a pending session's end verdict to the error a later
// Confirm or Reject returns (§9).
func verdictErr(v Verdict) error {
	switch {
	case v.Opened, v.Status == wire.StatusRejected:
		return errDecided
	case v.Status == wire.StatusCapacity:
		return ErrCapacity
	case v.Status == wire.StatusGoingAway:
		return net.ErrClosed
	}
	return ErrSessionLost // withdrawn by the dialer
}

// rejectedErr is the end error of a pending session that this side's
// application rejected: it matches ErrRejected and names the application's
// code. (A later Confirm or Reject still gets errDecided from verdictErr.)
func rejectedErr(v Verdict) error {
	return fmt.Errorf("rendr: session rejected by this side (code %d): %w", v.Code, ErrRejected)
}

// pendingErr is the error of a Confirm or Reject arriving after a verdict.
func (a *actor) pendingErr() error {
	if !a.ending {
		return errDecided
	}
	return verdictErr(a.verdict)
}

// reply sends Confirm's or Reject's answer after the lock is released,
// before the step's Registry calls (capacity 1: never blocks).
func (a *actor) reply(ch chan error, err error) {
	a.answer(func() { ch <- err })
}

// pendingLocked runs the pending phase's deadlines: the dialer's RST
// withdraws the session; AcceptTimeout answers CAPACITY (G6).
func (a *actor) pendingLocked(now time.Time) {
	if a.s.st.rstIn != nil {
		a.withdrawnLocked(now)
		return
	}
	if !now.Before(a.acceptBy) {
		a.refusePendingLocked(now, wire.OpenAck{Status: wire.StatusCapacity, Code: wire.CodeAcceptTimeout}, false)
		return
	}
	a.want(a.acceptBy)
}

// pendingFactsLocked applies the facts of the pending phase that a carrier
// or the stream already recorded — the dialer's RST(AbortWithdrawn), its
// GOAWAY — before a verdict command of the same step runs: a Confirm or
// Reject queued behind a withdrawal must answer ErrSessionLost, never open
// a withdrawn session (§6.2).
func (a *actor) pendingFactsLocked(now time.Time) {
	s := a.s
	if a.ending || s.ctl.state != StatePending {
		return
	}
	if s.st.rstIn != nil {
		a.withdrawnLocked(now)
		return
	}
	for _, l := range s.lanes {
		if l.c.PeerGoAway() {
			a.peerGoAwayLocked(now)
			return
		}
	}
}

// withdrawnLocked ends a pending session withdrawn by its dialer
// (RST(AbortWithdrawn), or its GOAWAY): every carrier retires without an
// answer; the tombstone answers UNKNOWN_SESSION; Confirm and Reject return
// ErrSessionLost.
func (a *actor) withdrawnLocked(now time.Time) {
	a.decided = true
	a.verdict = Verdict{Status: wire.StatusUnknownSession}
	a.terminateLocked(now, ErrSessionLost, nil, false)
}

// refusePendingLocked executes a refusing verdict: ack becomes the first
// frame of every OPEN carrier still waiting for one, then every carrier
// retires (§6.2). The tombstone repeats ack.
func (a *actor) refusePendingLocked(now time.Time, ack wire.OpenAck, goAway bool) {
	s := a.s
	a.decided = true
	a.verdict = Verdict{Status: ack.Status, Code: ack.Code, Msg: string(ack.Msg)}
	for _, l := range s.lanes {
		if l.state != LaneDead && !l.firstSent && l.first.t == 0 {
			l.first = firstFrame{t: wire.TypeOpenAck, openAck: ack}
		}
	}
	end := verdictErr(a.verdict)
	if ack.Status == wire.StatusRejected {
		end = rejectedErr(a.verdict)
	}
	a.terminateLocked(now, end, nil, goAway)
}

// onConfirmLocked is PendingConn.Confirm: OPEN_ACK(OK, window) becomes the
// first frame of every OPEN carrier and their writers are released; the
// epoch-0 sender is the oldest live OPEN carrier (selector) or all of them
// (bond). It routes at once — its DATA may follow the OPEN_ACK in the same
// batch — so it is reported routed (active, or a bond member) in this same
// critical section (L27); its CarrierUp follows once the OPEN_ACK is
// placed. With no carrier alive the no-path episode starts now. The reply
// precedes Registry.Opened (a slow Registry never delays Confirm).
func (a *actor) onConfirmLocked(now time.Time, c *confirm) {
	s := a.s
	ctl := &s.ctl
	a.pendingFactsLocked(now)
	if a.ending || a.decided || ctl.state != StatePending {
		a.reply(c.reply, a.pendingErr())
		return
	}
	a.decided, a.opened = true, true
	a.openedAt = now
	ctl.state = StateOpen
	win := s.openWindowLocked()
	var sender *lane
	for _, l := range s.lanes {
		if l.state == LaneDead || l.retireCalled || l.firstSent || l.first.t != 0 {
			continue // a retired carrier closes without an answer
		}
		if s.pk != nil {
			win = s.laneWindowLocked(l) // each OPEN carrier's own cmtu_acc (R1-5)
		}
		l.first = firstFrame{t: wire.TypeOpenAck, openAck: wire.OpenAck{Status: wire.StatusOK, Window: win}}
		if s.aliveLocked(l) {
			if s.p.Mode == ModeBond {
				l.data = true
				l.state = LaneMember
			} else if sender == nil {
				sender = l
			}
		}
		wakeLaneLocked(l)
	}
	if sender != nil {
		sender.data = true
		sender.state = LaneActive
		ctl.active = sender
		a.named = sender.id
	}
	s.routingChangedLocked()
	a.dirty = true
	a.reply(c.reply, nil)
	a.registry(func(r Registry) { r.Opened(s) })
	if !a.hasAliveLocked() {
		a.episodeStartLocked(now, now)
	}
}

// onRejectLocked is PendingConn.Reject: OPEN_ACK(REJECTED, code,
// msg[:255]) on every OPEN carrier; the tombstone repeats it. The reply
// precedes Registry.Ended (as Confirm's precedes Opened), so a caller
// never waits for Registry.Ended.
func (a *actor) onRejectLocked(now time.Time, c *reject) {
	a.pendingFactsLocked(now)
	if a.ending || a.decided || a.s.ctl.state != StatePending {
		a.reply(c.reply, a.pendingErr())
		return
	}
	msg := c.msg
	if len(msg) > wire.MaxMsg {
		msg = msg[:wire.MaxMsg]
	}
	a.reply(c.reply, nil)
	a.refusePendingLocked(now, wire.OpenAck{Status: wire.StatusRejected, Code: c.code, Msg: []byte(msg)}, false)
}

// onRefuseLocked is RefusePending (Listener.Close: CAPACITY, or GOING_AWAY
// while the Runtime closes). Its reply, too, precedes Registry.Ended.
func (a *actor) onRefuseLocked(now time.Time, c *refuse) {
	a.pendingFactsLocked(now)
	ok := !a.ending && !a.decided && a.s.ctl.state == StatePending
	ch := c.reply
	a.answer(func() { ch <- ok })
	if ok {
		a.refusePendingLocked(now, wire.OpenAck{Status: c.status, Code: c.code}, false)
	}
}

// onAdoptLocked attaches a carrier admitted by Join or AttachOpen
// (§6.3): JOIN_ACK(OK, rxNext = rRead) or, on an open session,
// OPEN_ACK(OK, window) becomes its first frame; a duplicate OPEN on a
// pending session is parked until the verdict. The carrier starts held: its
// first response is the first frame on the wire. Once the session ended the
// carrier gets the session's answer instead.
func (a *actor) onAdoptLocked(now time.Time, ad *adopt) {
	s := a.s
	ctl := &s.ctl
	if ctl.adopting > 0 {
		ctl.adopting--
	}
	if a.ending {
		a.refuseAdopt(ad)
		return
	}
	a.gen++
	l := a.newLaneLocked(now, ad.conn, -1, a.gen, LaneJoining)
	a.unconfirmed = append(a.unconfirmed, l)
	switch {
	case ad.kind == adoptJoin:
		l.first = firstFrame{t: wire.TypeJoinAck, joinAck: wire.JoinAck{Status: wire.StatusOK, RxNext: s.joinAckRxLocked(l)}}
	case ctl.state != StatePending:
		l.first = firstFrame{t: wire.TypeOpenAck, openAck: wire.OpenAck{Status: wire.StatusOK, Window: s.laneWindowLocked(l)}}
	}
	ad.conn.Start(s.endpoint(l), &s.mb, carrier.StartOptions{Hold: true})
	if ctl.state != StatePending {
		a.episodeEndLocked(now)
	}
}

// joinAckRxLocked is JOIN_ACK(OK).rxNext for the adopted JOIN lane l:
// rRead on a stream session (§6.3); on a packet session cmtu_acc, the
// budget Join fixed on l's carrier (SetBudget, so its RecvLimit; 0 on a
// stream carrier), never an offset (M2-D11, M2-D50).
func (s *Session) joinAckRxLocked(l *lane) uint64 {
	if s.pk != nil {
		return uint64(laneRecvLimit(l))
	}
	return s.st.rRead
}

// refuseAdopt answers an adopted carrier of an ended session and closes it:
// JOIN_ACK(UNKNOWN_SESSION), or the session's verdict to a duplicate OPEN.
// The carrier joins the exit join (§6.8).
func (a *actor) refuseAdopt(ad *adopt) {
	defer a.dropConn(ad.conn)
	if ad.kind == adoptJoin {
		var p [wire.JoinAckLen]byte
		n := wire.PutJoinAck(p[:], &wire.JoinAck{Status: wire.StatusUnknownSession})
		ad.conn.WriteAndClose(wire.TypeJoinAck, 0, wire.SessionHandle, p[:n], time.Time{})
		return
	}
	oa := a.verdict.OpenAck()
	p := make([]byte, wire.OpenAckFixedLen+len(oa.Msg))
	n := wire.PutOpenAck(p, &oa)
	ad.conn.WriteAndClose(wire.TypeOpenAck, 0, wire.SessionHandle, p[:n], time.Time{})
}

// lanesConfirmedLocked handles factLaneConfirmed on the passive: a lane
// whose first response (an OK) was placed joins the routing (L22: a carrier
// is confirmed before it carries data) and is announced (CarrierUp); the
// epoch-0 sender already routes since Confirm and is only announced. A
// refused lane is dropped from the list unannounced; a dead lane already
// left it when it died (removeLaneLocked), so the dead case below is only a
// guard.
func (a *actor) lanesConfirmedLocked(now time.Time) {
	route := false
	k := 0
	for _, l := range a.unconfirmed {
		switch {
		case l.state == LaneDead || refusedLocked(l):
		case !l.firstSent:
			a.unconfirmed[k] = l
			k++
		default:
			if l.state == LaneJoining {
				l.state = LaneMember
				a.s.pktMemberConfirmedLocked(l)
			}
			a.dirty, route = true, true
			a.event(now, EventCarrierUp, l.id, 0, 0, carrier.CauseNone, nil)
		}
	}
	clear(a.unconfirmed[k:])
	a.unconfirmed = a.unconfirmed[:k]
	if route {
		a.passiveRouteLocked(now)
	}
}
