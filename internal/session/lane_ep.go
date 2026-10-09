package session

import (
	"math"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// A lane is its carrier's endpoint (design §4.0); the methods below are
// stream code. The carrier calls them from its writer (Fill, and
// WriteBlocked via the watchdog) and its reader (Data, Control), never while
// holding its own lock; each takes s.mu. They use the lane's port (the
// carrier, or a fake in the stream's unit tests), never the c argument.
var _ carrier.Endpoint = (*lane)(nil)

// Handle returns the session handle the lane uses on its carrier: the
// view's (M3-D4) — wire.SessionHandle on a dedicated carrier, the handle
// the dialer allocated on a MUX trunk. Every session frame the lane places
// carries it. It is read through the lane's port (the carrier itself in
// production); a port without a handle (the stream's fakes) or a bare
// Conn's 0 means wire.SessionHandle. It runs for every frame placed: the
// production port is checked by its concrete type first (one word
// compare; the handle is an immutable field of the view), and only a fake
// pays for the interface assertion.
func (l *lane) Handle() uint32 {
	if c, ok := l.port.(*carrier.Conn); ok {
		if h := c.Handle(); h != 0 {
			return h
		}
		return wire.SessionHandle
	}
	if hp, ok := l.port.(interface{ Handle() uint32 }); ok {
		if h := hp.Handle(); h != 0 {
			return h
		}
	}
	return wire.SessionHandle
}

// muxFillLocked applies the two Fill rules of a view on a started MUX
// trunk (M3-D8, PA-27) before the lane's own Fill, and reports whether
// that Fill may run: a passive view held after its OK response places
// nothing until the dialer's first frame for it arrived (the carrier's
// writer does not call it then; this is the lane's own guard); a dialer
// lane that owes its go frame places it first — an ACK for a stream
// session, a PACK for a packet session (REL-wrapped on a datagram trunk,
// plain on a stream trunk, R1-12) — and nothing else in a call that could
// not place it, unless the call's datagram batch only lacked REL room.
//
// That exception (m3 DGMUX, L40): the REL window is the trunk's, shared by
// every view, and a lost REL holds it for a REL RTO (RelRTOMin 200 ms at
// least), longer than Packet.MaxAge. Holding the lane's frames behind the
// go frame then dropped every datagram the application wrote right after
// DialPacket, and holding the passive (which places nothing until a
// dialer frame arrives) dropped every datagram its application wrote
// right after Confirm. A datagram batch that refuses the go PACK for REL
// room only lets the lane's packet Fill run (standIn): its datagrams (and
// anything else unreliable) leave now, and if it placed nothing, the go
// PACK's content leaves once as a plain PACK (placeStandInLocked, at most
// once per lane); any of these that arrives ends the passive's hold as a
// first frame does. The go PACK stays owed and is placed first by the
// next call with REL room (the refusal REL-marked the view, so the RACK
// that frees room re-readies it). The go frame keeps its purpose — one
// reliable frame that ends the hold although every unreliable one was
// lost — and REL its bounds. A full batch refuses the plain frames too,
// so it needs no rule of its own. A dedicated carrier and handle 1 of a
// trunk owe nothing.
func (s *Session) muxFillLocked(l *lane, b *carrier.Batch) (run, standIn bool) {
	if l.c != nil && l.c.HeldAfterResponse() {
		return false, false
	}
	if !l.goOwed {
		return true, false
	}
	if l.state == LaneDead || s.st.ended {
		return false, false
	}
	if !s.placeGoLocked(l, b, true) {
		// The go frame stays first, except on a datagram batch that
		// refused it for REL room only (only a packet session has one).
		relOnly := b.Datagram() && b.RelRoom() == 0
		return relOnly, relOnly
	}
	l.goOwed = false
	return true, false
}

// placeStandInLocked places the stand-in of lane l's owed go frame (m3
// DGMUX, L40): its go PACK unreliable, once per lane, after a packet Fill
// that found no REL room for the go PACK and placed nothing else, so that
// the passive's hold ends although the dialer has nothing to send. The go
// PACK stays owed.
func (s *Session) placeStandInLocked(l *lane, b *carrier.Batch) {
	if !l.goStandIn && s.placeGoLocked(l, b, false) {
		l.goStandIn = true
	}
}

// placeGoLocked places lane l's go frame (M3-D8): for a stream session an
// ACK of what this side delivered so far with its current right edge (the
// window already advertised, never a new one: the peer's limit is a max
// merge, P10); for a packet session a PACK of the datagrams received so
// far. It carries no flags and changes no ACK duty state: the passive
// reads it as an ordinary ACK or PACK that ends its response hold. reliable
// asks for the REL-wrapped PACK on a datagram batch (the go frame; false
// for its stand-in).
func (s *Session) placeGoLocked(l *lane, b *carrier.Batch, reliable bool) bool {
	st := &s.st
	if pk := s.pk; pk != nil {
		pa := wire.Pack{Received: pk.rxCount}
		if pk.rxCount > 0 {
			pa.HighestSeq = pk.rxHigh
		}
		return b.AddPack(l.Handle(), 0, &pa, reliable)
	}
	win := uint64(0)
	if st.rightEdge > st.rRead {
		win = st.rightEdge - st.rRead
	}
	a := wire.Ack{Delivered: st.rRead, Window: uint32(min(win, math.MaxUint32))}
	return b.AddAck(l.Handle(), 0, &a)
}

// Fill appends the lane's frames to b in one s.mu section (design §4.3):
// nothing on a LaneDead lane (§4.0 C1); the pending first response
// (OPEN_ACK or JOIN_ACK; fact factLaneConfirmed), and nothing at all while a
// held passive carrier has none yet, nor ever after a refusal (a non-OK
// first response, which stays in l.first as the marker); RST once (then
// nothing else); the
// dialer's pending SCHED; the ACK on the duty lane (with the ACK-delay
// rule, b.WakeAt; an ACK that takes lastWin from 64 KiB or more to below it
// rings the actor, see readvertiseLocked); then, if l.data, DATA — the
// rescue span if l may send it (rescueSenderLocked: never its holder while
// another data lane exists), retransmissions lowest first, new
// data up to min(end, peerLimit), cut at chunk boundaries and bounded by
// b.Room() and the carrier's capacity (b.MarkCapBlocked when data waits on
// the cap); then the FIN when due. It sets l.idle when it appended nothing.
func (l *lane) Fill(c *carrier.Conn, b *carrier.Batch) {
	s := l.s
	s.mu.Lock()
	if run, _ := s.muxFillLocked(l, b); run {
		s.fillLocked(l, b) // a stream session: never a stand-in
	}
	s.mu.Unlock()
}

// Data accepts one CRC-verified DATA frame at stream offset off (design
// §4.4). With buf non-nil, p aliases buf.B and buf's reference moves to the
// stream (kept or released, also on error); with buf nil, p is valid only
// during the call and payloads below 16 KiB are copied into runs. DATA on a
// pending session, beyond rightEdge, or conflicting with bytes already held
// returns an error, which kills only this carrier (L13, L15).
func (l *lane) Data(c *carrier.Conn, off uint64, p []byte, buf *carrier.Buf) error {
	s := l.s
	s.mu.Lock()
	tail := s.st.rTail
	err := s.dataLocked(off, p, buf)
	if err == nil {
		s.gapAckLocked(l, off, tail)
	}
	s.mu.Unlock()
	return err
}

// Control accepts one CRC-verified session control frame (design §4.6,
// §4.7, §7.5): ACK (sender side; beyond sNext or a regression on this lane
// is a violation), FIN, RST (rstIn, fact factRst) and, on the passive,
// SCHED (stored in ctl.schedIn, fact factSched). Any other session type
// after establishment, and a SCHED received by a dialer, is a violation: the
// error kills only this carrier.
func (l *lane) Control(c *carrier.Conn, h wire.Header, p []byte) error {
	s := l.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.ended {
		return nil // the session is over; its carriers are being retired
	}
	if h.Type == wire.TypeRst {
		return s.rstLocked(p)
	}
	if s.pendingLocked() {
		return errDataBeforeOpen // only RST may precede the verdict
	}
	switch h.Type {
	case wire.TypeAck:
		a, err := wire.ParseAck(p)
		if err != nil {
			return err
		}
		return s.ackLocked(l, h.Flags, &a)
	case wire.TypeFin:
		off, err := wire.ParseFin(p)
		if err != nil {
			return err
		}
		return s.finLocked(off)
	case wire.TypeSched:
		return s.schedLocked(h.Flags, p)
	}
	return errUnexpectedFrame
}

// WriteBlocked is called by the carrier's watchdog when the current batch
// write has been in progress for PingBusy (design §4.6, §4.8): duties held
// by this lane move to a non-blocked lane — a leaving one (Retire called,
// or dropped by the applied SCHED: ackLeavingLocked) if no other is
// writable — which is woken (the ACK duty, also while ackDelayAt is armed,
// C30), and fact factWriteBlocked tells the actor to move a SCHED resend.
// It must not block.
func (l *lane) WriteBlocked(c *carrier.Conn) {
	s := l.s
	s.mu.Lock()
	st := &s.st
	if st.ackLane == l {
		if n := s.chooseAckLaneLocked(l); n != nil && !n.port.WriteBlocked() {
			st.ackLane = n
			if n.ackSent != st.ackGen || !st.ackDelayAt.IsZero() {
				// A pending delayed ACK has not bumped ackGen yet: the new
				// duty lane's Fill re-arms b.WakeAt(ackDelayAt) (C30).
				n.idle = false
				n.port.Wake()
			}
		}
	}
	if s.p.Mode == ModeBond && !st.ended {
		s.wakeDataLocked(time.Now()) // pending bytes go to the other members
	}
	st.facts |= factWriteBlocked
	s.mu.Unlock()
	s.ringActor()
}
