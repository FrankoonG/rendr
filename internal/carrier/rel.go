package carrier

import (
	"time"

	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The reliable control sublayer of datagram carriers (M2-D16…M2-D18; M2
// design §A5.9 and Revision 1, R1-2, R1-3, R1-17, R1-18).

// relState is the REL sublayer of one carrier, both directions (rel.go,
// WP3a): sender — next and oldest unacknowledged cseq, ≤ wire.RelWindow
// entries of at most wire.RelMaxPayload bytes, the retransmission count of
// the oldest, its due time and the blocked flag; receiver — the cumulative
// point, ≤ wire.RelWindow − 1 held inner frames and the RACK-due flag.
// Only the oldest unacknowledged cseq is ever retransmitted; SACK bits are
// validated and otherwise ignored (R1-18). The retransmission timer is
// armed after the datagram carrying a new REL was attempted — written,
// refused as too large or lost to noise — and only while una ≠ next; it is
// cleared when una reaches next (R1-2). The handshakes set the start values
// with initSend and initRecv (R1-3).
//
// Every field is guarded by Conn.mu except held, the payloads of the
// out-of-order RELs, which only the reader goroutine touches (their
// presence, heldMask, is under Conn.mu for the writer's RACK).
type relState struct {
	// Sender.
	next, una uint32                  // next cseq to assign; oldest unacknowledged (una == next: nothing outstanding)
	slot      [wire.RelWindow]relSlot // the REL payload of cseq c at slot[c mod RelWindow] while outstanding
	backoff   int                     // consecutive retransmissions of una
	due       time.Time               // when una is retransmitted; zero: not armed (R1-2)
	blocked   bool                    // a reliable Add* found no REL room: a RACK with progress wakes the writer

	// Receiver.
	cum      uint32                  // highest cseq dispatched in order
	heldMask uint8                   // bit c mod RelWindow: cseq c (cum + 2 … cum + 8) is held
	rackDue  bool                    // a RACK is due (after every REL, duplicates included)
	held     [wire.RelWindow]relHeld // reader-owned copies of the held RELs
}

// relSlot is one REL payload (cseq · itype · iflags · ihandle · ipayload).
type relSlot struct {
	n uint16
	b [wire.RelMaxPayload]byte
}

// relHeld is a REL received out of order: its payload and outer fseq.
type relHeld struct {
	relSlot
	fseq uint32
}

// initSend sets the sender's start: next = una = next (the first cseq this
// side will assign). Called by the handshakes before the Conn is returned
// (R1-3's table: FirstCseq + 1 on a dialer whose H1 carried REL{FirstCseq},
// FirstCseq otherwise).
func (r *relState) initSend(next uint32) {
	r.next, r.una = next, next
	r.backoff, r.due, r.blocked = 0, time.Time{}, false
}

// initRecv sets the receiver's cumulative point: the cseq of the last REL
// of the peer already dispatched by the handshake (R1-3's table:
// FirstCseq where the handshake carried a REL{FirstCseq} in that
// direction, FirstCseq − 1 where it carried none — probe handshakes).
func (r *relState) initRecv(cum uint32) {
	r.cum, r.heldMask, r.rackDue = cum, 0, false
}

// room returns the REL frames that may still be reserved (Conn.mu).
func (r *relState) room() int {
	return wire.RelWindow - int(r.next-r.una)
}

// outstanding reports whether a REL waits for its RACK (Conn.mu).
func (r *relState) outstanding() bool { return r.una != r.next }

// RelRoom returns the REL frames a reliable frame could still reserve on
// this carrier now: wire.RelWindow minus those outstanding; 0 on stream
// carriers and on a dead carrier. A session whose reliable PACK found no REL
// room on its duty lane moves the PACK duty to a live lane whose RelRoom is
// positive (R1-17). It takes Conn.mu (Session.mu → Conn.mu).
func (c *Conn) RelRoom() int {
	if c.dg == nil || c.death.Load() != nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closeSent.Load() {
		return 0 // nothing follows our CLOSE
	}
	return c.dg.rel.room()
}

// relRTOLocked returns the carrier's REL timeout: RelRTOInit before the
// first RTT sample, else clamp(srtt + 4·rttvar, RelRTOMin, RelRTOMax)
// (M2-D16; integration 1, D4: only through sched.RTOWithin).
func (c *Conn) relRTOLocked() time.Duration {
	st := &c.st
	return sched.RTOWithin(st.srtt, st.rttvar, st.rttSeen, c.tm.RelRTOInit, c.tm.RelRTOMin, c.tm.RelRTOMax)
}

// relSealLocked stamps the cseqs of the round's new REL frames in insertion
// order and copies each REL payload into its send slot (§A5.8 relSeal). The
// round reserved at most room() of them (SetDatagram), so no outstanding
// slot is overwritten.
func (c *Conn) relSealLocked(b *Batch) {
	r := &c.dg.rel
	for k := range b.relCount() {
		cs := r.next
		p := b.relPayload(k, cs)
		s := &r.slot[cs%wire.RelWindow]
		s.n = uint16(copy(s.b[:], p))
		r.next++
	}
}

// relRetxDueLocked reports whether una is due for retransmission at now.
func (c *Conn) relRetxDueLocked(now time.Time) bool {
	r := &c.dg.rel
	return r.outstanding() && !r.due.IsZero() && !now.Before(r.due)
}

// relAttemptedLocked runs after the round's datagrams were attempted —
// written, refused or lost to noise — at at (R1-2): a retransmission
// re-arms the timer with the next backed-off timeout whatever its outcome,
// and a new REL arms it when it is not armed; nothing is armed while no REL
// is outstanding.
func (c *Conn) relAttemptedLocked(retx bool, at time.Time) {
	r := &c.dg.rel
	if !r.outstanding() {
		r.due, r.backoff = time.Time{}, 0
		return
	}
	if retx {
		r.backoff++
		r.due = at.Add(sched.RTOBackoffWithin(c.relRTOLocked(), r.backoff, c.tm.RelRTOMax))
		return
	}
	if r.due.IsZero() {
		r.due = at.Add(c.relRTOLocked())
	}
}

// relWakeLocked returns when the writer must run for the REL sublayer
// (zero: never): the retransmission time of una while one is outstanding.
func (c *Conn) relWakeLocked() time.Time {
	r := &c.dg.rel
	if !r.outstanding() {
		return time.Time{}
	}
	return r.due
}

// rackLocked builds the RACK of the receiver's state (§A5.9): cumAck = cum,
// sack bit i ⇔ cseq cum + 2 + i held.
func (r *relState) rackLocked() wire.Rack {
	var sack uint32
	for i := range uint32(wire.RelWindow - 1) {
		if r.heldMask&(1<<((r.cum+2+i)%wire.RelWindow)) != 0 {
			sack |= 1 << i
		}
	}
	return wire.Rack{CumAck: r.cum, Sack: sack}
}

// relOnRack applies a RACK the reader received at now (§A5.9): a cumAck or
// a set sack bit naming a cseq not yet sent is a violation; a cumAck at or
// beyond una frees the slots through it; a lower one is stale and
// ignored; sack bits are otherwise ignored (R1-18). Progress resets the
// backoff, re-arms or clears the timer and wakes a writer that found no
// REL room; the RACK that covers our CLOSE may complete a retirement
// (R1-4). It reports whether the reader continues.
func (c *Conn) relOnRack(p []byte, now time.Time) bool {
	rk, err := wire.ParseRack(p)
	if err != nil {
		c.violation("RACK: %v", err)
		return false
	}
	r := &c.dg.rel
	c.mu.Lock()
	last := r.next - 1 // the highest cseq sent
	if wire.SeqLess(last, rk.CumAck) {
		c.mu.Unlock()
		c.violation("RACK: cumAck %d beyond the last cseq sent %d", rk.CumAck, last)
		return false
	}
	for i := range uint32(wire.RelWindow - 1) {
		if rk.Sack&(1<<i) != 0 && !wire.SeqLess(rk.CumAck+2+i, r.next) {
			c.mu.Unlock()
			c.violation("RACK: sack bit %d names cseq %d, never sent", i, rk.CumAck+2+i)
			return false
		}
	}
	var wake, finish bool
	if !wire.SeqLess(rk.CumAck, r.una) { // cumAck ≥ una: progress
		r.una = rk.CumAck + 1
		r.backoff = 0
		if r.outstanding() {
			r.due = now.Add(c.relRTOLocked())
		} else {
			r.due = time.Time{}
		}
		if r.blocked && r.room() > 0 {
			r.blocked, wake = false, true
		}
		finish = c.dgRetireDoneLocked()
	}
	c.mu.Unlock()
	if wake {
		c.Wake()
	}
	if finish {
		c.finishRetire("retired: CLOSE exchange complete")
		return false
	}
	return true
}

// relOnRel applies one REL frame the reader received (§A5.9 receiver): a
// duplicate or a held cseq makes a RACK due and is never dispatched; after
// the peer's CLOSE nothing new is taken (M2-D30); a cseq beyond cum +
// RelWindow, a malformed REL and a wrapped handshake frame are violations;
// a later cseq is held; the next one is dispatched with every held
// successor, cum advancing after each endpoint call returned (a RACK covers
// dispatched frames only, M2-D17). It reports whether the reader continues.
func (c *Conn) relOnRel(f *wire.Frame, now time.Time) bool {
	h, inner, err := wire.ParseRel(f.Payload)
	if err != nil {
		c.violation("REL: %v", err)
		return false
	}
	dg := c.dg
	r := &dg.rel
	c.mu.Lock()
	d := int32(h.Cseq - r.cum)
	if d <= 0 || (d <= wire.RelWindow && d >= 2 && r.heldMask&(1<<(h.Cseq%wire.RelWindow)) != 0) {
		r.rackDue = true // a duplicate: answered again, never dispatched
		c.mu.Unlock()
		c.Wake()
		return true
	}
	c.mu.Unlock()
	if dg.peerClosed {
		c.dgDropped(1) // nothing new follows the peer's CLOSE (M2-D30)
		return true
	}
	if d > wire.RelWindow {
		c.violation("REL: cseq %d beyond the window (cum %d)", h.Cseq, r.cum)
		return false
	}
	switch h.Type {
	case wire.TypeOpen, wire.TypeOpenAck, wire.TypeJoin, wire.TypeJoinAck:
		c.violation("REL{%v} after the handshake", h.Type)
		return false
	}
	if d >= 2 {
		s := &r.held[h.Cseq%wire.RelWindow]
		s.n = uint16(copy(s.b[:], f.Payload))
		s.fseq = f.Fseq
		c.mu.Lock()
		r.heldMask |= 1 << (h.Cseq % wire.RelWindow)
		r.rackDue = true
		c.mu.Unlock()
		c.Wake()
		return true
	}
	// d == 1: the next in order.
	if !c.relDispatch(h, inner, f.Fseq, now) {
		return false
	}
	c.relAdvance(h.Cseq)
	for !dg.peerClosed {
		next := r.cum + 1
		bit := uint8(1) << (next % wire.RelWindow)
		c.mu.Lock()
		has := r.heldMask&bit != 0
		c.mu.Unlock()
		if !has {
			break
		}
		s := &r.held[next%wire.RelWindow]
		hh, in, err := wire.ParseRel(s.b[:s.n]) // validated at arrival
		if err != nil {
			c.violation("REL: %v", err)
			return false
		}
		if !c.relDispatch(hh, in, s.fseq, now) {
			return false
		}
		c.relAdvance(next)
	}
	return true
}

// relAdvance records that cseq was dispatched: cum moves to it, its held
// mark (if any) is cleared and a RACK becomes due. It runs only after the
// endpoint call for cseq returned.
func (c *Conn) relAdvance(cseq uint32) {
	r := &c.dg.rel
	c.mu.Lock()
	r.cum = cseq
	r.heldMask &^= 1 << (cseq % wire.RelWindow)
	r.rackDue = true
	c.mu.Unlock()
	c.Wake()
}

// relDispatch dispatches one in-order inner frame (§A5.7): CLOSE and
// GOAWAY set the carrier flags — the peer's CLOSE is only recorded here,
// its retirement completes in the writer after the RACK covering it was
// written or in the reader on the RACK of our CLOSE (R1-4); FIN, RST,
// SCHED and PACK go to the endpoint (a violation on a carrier without a
// session). It reports whether the reader continues.
func (c *Conn) relDispatch(h wire.RelHead, inner []byte, fseq uint32, now time.Time) bool {
	switch h.Type {
	case wire.TypeClose:
		reason, err := wire.ParseClose(inner)
		if err != nil {
			c.violation("REL{CLOSE}: %v", err)
			return false
		}
		dg := c.dg
		dg.peerClosed, dg.peerCloseFseq = true, fseq
		dg.peerCloseReason.Store(uint32(reason))
		c.mu.Lock()
		dg.peerCloseCseq, dg.peerCloseSeen = h.Cseq, true
		c.mu.Unlock()
		c.peerClosed.Store(true)
		c.ring()
		if c.ep == nil {
			// A probe or sessionless carrier has no session to drain: it
			// answers the peer's CLOSE with its own at once (M1).
			c.Retire(wire.CloseRetire)
		}
		return true
	case wire.TypeGoAway:
		if _, err := wire.ParseGoAway(inner); err != nil {
			c.violation("REL{GOAWAY}: %v", err)
			return false
		}
		c.peerGoAway.Store(true)
		c.ring()
		return true
	}
	if c.ep == nil {
		c.violation("REL{%v} on a carrier without a session", h.Type)
		return false
	}
	hdr := wire.Header{Type: h.Type, Flags: h.Flags, Len: uint32(len(inner)), Fseq: fseq, Handle: h.Handle}
	if err := c.ep.Control(c, hdr, inner); err != nil {
		c.violation("%v: %v", h.Type, err)
		return false
	}
	return true
}
