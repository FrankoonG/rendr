package session

import (
	"errors"
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
// (CAPACITY), RefusePending/Shutdown (GOING_AWAY) — or by the dialer's
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

// pendingErr is the error of a Confirm or Reject arriving after a verdict.
func (a *actor) pendingErr() error {
	if !a.ending {
		return errDecided
	}
	return verdictErr(a.verdict)
}

// reply sends Confirm's or Reject's answer after the lock is released
// (capacity 1: never blocks).
func (a *actor) reply(ch chan error, err error) {
	a.later = append(a.later, func() { ch <- err })
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
	a.terminateLocked(now, verdictErr(a.verdict), nil, goAway)
}

// onConfirmLocked is PendingConn.Confirm: OPEN_ACK(OK, window) becomes the
// first frame of every OPEN carrier and their writers are released; the
// epoch-0 sender is the oldest live OPEN carrier (selector) or all of them
// (bond). With no carrier alive the no-path episode starts now.
func (a *actor) onConfirmLocked(now time.Time, c *confirm) {
	s := a.s
	ctl := &s.ctl
	if a.ending || a.decided || ctl.state != StatePending {
		a.reply(c.reply, a.pendingErr())
		return
	}
	a.decided, a.opened = true, true
	ctl.state = StateOpen
	win := s.openWindowLocked()
	var sender *lane
	for _, l := range s.lanes {
		if l.state == LaneDead || l.firstSent || l.first.t != 0 {
			continue
		}
		l.first = firstFrame{t: wire.TypeOpenAck, openAck: wire.OpenAck{Status: wire.StatusOK, Window: win}}
		if s.aliveLocked(l) {
			if s.p.Mode == ModeBond {
				l.data = true
			} else if sender == nil {
				sender = l
			}
		}
		wakeLaneLocked(l)
	}
	if sender != nil {
		sender.data = true
		ctl.active = sender
		a.named = sender.id
	}
	s.routingChangedLocked()
	a.dirty = true
	a.reply(c.reply, nil) // before Opened: a slow Registry never delays Confirm
	a.registry(func(r Registry) { r.Opened(s) })
	if !a.hasAliveLocked() {
		a.episodeStartLocked(now, now)
	}
}

// onRejectLocked is PendingConn.Reject: OPEN_ACK(REJECTED, code,
// msg[:255]) on every OPEN carrier; the tombstone repeats it.
func (a *actor) onRejectLocked(now time.Time, c *reject) {
	if a.ending || a.decided || a.s.ctl.state != StatePending {
		a.reply(c.reply, a.pendingErr())
		return
	}
	msg := c.msg
	if len(msg) > wire.MaxMsg {
		msg = msg[:wire.MaxMsg]
	}
	a.refusePendingLocked(now, wire.OpenAck{Status: wire.StatusRejected, Code: c.code, Msg: []byte(msg)}, false)
	a.reply(c.reply, nil)
}

// onRefuseLocked is RefusePending (Listener.Close: GOING_AWAY).
func (a *actor) onRefuseLocked(now time.Time, c *refuse) {
	ok := !a.ending && !a.decided && a.s.ctl.state == StatePending
	if ok {
		a.refusePendingLocked(now, wire.OpenAck{Status: c.status, Code: c.code}, false)
	}
	ch := c.reply
	a.later = append(a.later, func() { ch <- ok })
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
	switch {
	case ad.kind == adoptJoin:
		l.first = firstFrame{t: wire.TypeJoinAck, joinAck: wire.JoinAck{Status: wire.StatusOK, RxNext: s.st.rRead}}
	case ctl.state != StatePending:
		l.first = firstFrame{t: wire.TypeOpenAck, openAck: wire.OpenAck{Status: wire.StatusOK, Window: s.openWindowLocked()}}
	}
	ad.conn.Start(l, &s.mb, carrier.StartOptions{Hold: true})
	if ctl.state != StatePending {
		a.episodeEndLocked(now)
	}
}

// refuseAdopt answers an adopted carrier of an ended session and closes it:
// JOIN_ACK(UNKNOWN_SESSION), or the session's verdict to a duplicate OPEN.
func (a *actor) refuseAdopt(ad *adopt) {
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
// is confirmed before it carries data) and is announced.
func (a *actor) lanesConfirmedLocked(now time.Time) {
	s := a.s
	route := false
	for _, l := range s.lanes {
		if l.state != LaneJoining || !l.firstSent || refusedLocked(l) {
			continue
		}
		l.state = LaneMember
		if l == s.ctl.active {
			l.state = LaneActive
		}
		a.dirty, route = true, true
		a.event(now, EventCarrierUp, l.id, 0, 0, carrier.CauseNone, nil)
	}
	if route {
		a.passiveRouteLocked(now)
	}
}
