package session

import (
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

// Handle returns the session handle the lane uses on its carrier
// (wire.SessionHandle in M1).
func (l *lane) Handle() uint32 {
	return wire.SessionHandle
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
	s.fillLocked(l, b)
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
