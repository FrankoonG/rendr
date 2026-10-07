package carrier

import (
	"errors"
	"os"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The writer of a datagram carrier (M2-D12, M2-D25, M2-D29; M2 design §A5.8
// and Revision 1, R1-2, R1-4, R1-8). writeRound stays the shared loop and
// hands a datagram carrier's rounds to dgWriteRound.

// dgWriteRound runs one round of a datagram carrier: death checks; under
// Conn.mu the datagram mode (budget, REL room), the H2 repeat and the
// rebind challenge (datagrams of their own), and the carrier control —
// RACK, PONG, the challenge PONG, the REL retransmission, a due PING (none
// while held), GOAWAY; Fill (held, R1-8: the first response releases the
// hold in this round and the first PING may follow it); CLOSE last when
// retiring. After our CLOSE the rounds place only RACKs and REL
// retransmissions (M2-D31). It returns false when the writer must exit:
// the carrier ended.
func (c *Conn) dgWriteRound(w *writer) bool {
	if c.death.Load() != nil {
		return false
	}
	now := time.Now()
	if c.checkDeadlines(now) {
		return false
	}
	dg := c.dg
	b := w.b
	b.Reset(now)
	w.ping, w.pingJudged, w.pingAtEnd, w.pingEnd, w.close = false, false, false, false, false
	w.probe, w.retx, w.rack, w.pingAt, w.rackAt = false, false, false, -1, -1
	closing := c.closeSent.Load()

	c.mu.Lock()
	st := &c.st
	room := dg.rel.room()
	if closing {
		room = 0 // nothing new follows our CLOSE
	}
	b.SetDatagram(int(dg.budget.Load()), room)
	h2 := dg.hs.repeatH2
	dg.hs.repeatH2 = false
	chal, cand, nonce := c.chalSendLocked(now)
	kill := c.dgControlLocked(w, b, now, closing)
	retiring, reason := st.retiring, st.reason
	c.mu.Unlock()
	if kill {
		c.Kill(CausePingTimeout, "mtu probe")
		return false
	}

	if !closing {
		epFrames := false
		if c.ep != nil {
			n := b.Len()
			c.ep.Fill(c, b)
			epFrames = b.Len() > n
			if w.held && epFrames {
				// The first response released the hold (R1-8); the first
				// PING may follow it (the dialer keeps the response
				// datagram's tail, R1-1).
				w.held = false
				dg.held.Store(false)
				if !retiring {
					c.mu.Lock()
					kill = c.dgPingLocked(w, b, now)
					c.mu.Unlock()
					if kill {
						b.ReleaseRefs()
						c.Kill(CausePingTimeout, "mtu probe")
						return false
					}
				}
			}
		}
		if retiring && !epFrames && b.addClose(reason) {
			w.close = true // REL{CLOSE}: the last frame we place
		}
	}
	if b.relCount() > 0 || b.relRefused() {
		c.mu.Lock()
		c.relSealLocked(b)
		if b.relRefused() {
			// A reliable frame found no REL room: a RACK with progress wakes
			// the writer (§A5.9); room freed since SetDatagram wakes it now.
			if dg.rel.room() > 0 {
				c.Wake()
			} else {
				dg.rel.blocked = true
			}
		}
		c.mu.Unlock()
	}
	if b.Len() == 0 && !h2 && !chal {
		return c.dgSleep(w, now)
	}
	if b.Len() > 0 {
		w.fseq = b.seal(w.fseq)
	}
	return c.dgWriteBatch(w, b, now, h2, chal, cand, nonce)
}

// dgControlLocked appends the round's carrier control (§A5.8): the RACK
// when one is due (latest state wins); in closing rounds only the REL
// retransmission besides it; otherwise the PONG (its pad clamped to this
// side's budget, M2-D24), the challenge PONG, the REL retransmission, a due
// PING (never while held or retiring) and GOAWAY. kill reports a fourth
// unanswered MTU probe.
func (c *Conn) dgControlLocked(w *writer, b *Batch, now time.Time, closing bool) (kill bool) {
	dg := c.dg
	st := &c.st
	if r := &dg.rel; r.rackDue {
		rk := r.rackLocked()
		if b.addRack(&rk) {
			r.rackDue = false
			w.rack, w.rackCum, w.rackAt = true, rk.CumAck, b.Len()-1
		}
	}
	if closing {
		c.dgRetxLocked(w, b, now)
		return false
	}
	if st.pongDue {
		p := st.pong
		p.Pad = min(p.Pad, max(int(dg.budget.Load())-wire.FrameOverhead-wire.PingFixedLen, 0))
		if b.addPong(&p) {
			st.pongDue = false
		}
	}
	if ch := &dg.chal; ch.pongDue && b.addPong(&ch.pong) {
		ch.pongDue = false
	}
	c.dgRetxLocked(w, b, now)
	if !st.retiring && !w.held {
		kill = c.dgPingLocked(w, b, now)
	}
	if st.goAway && !st.goAwaySent && b.addGoAway(wire.GoAwayShutdown) {
		st.goAwaySent = true
	}
	return kill
}

// dgRetxLocked appends the retransmission of una when its timer expired:
// a new outer frame around the byte-identical REL payload (PA-21); one per
// round, single flight (M2-D16).
func (c *Conn) dgRetxLocked(w *writer, b *Batch, now time.Time) {
	r := &c.dg.rel
	if !c.relRetxDueLocked(now) {
		return
	}
	s := &r.slot[r.una%wire.RelWindow]
	if b.addRelRetx(s.b[:s.n]) {
		w.retx, w.retxCseq = true, r.una
	}
}

// dgPingLocked appends a due PING (cadence, retry or MTU probe); kill
// reports a fourth unanswered MTU probe.
func (c *Conn) dgPingLocked(w *writer, b *Batch, now time.Time) (kill bool) {
	k, _ := c.dgPingDueLocked(now)
	if k == pingNone {
		return false
	}
	kill = c.dgEncodePingLocked(w, b, now, k)
	if w.ping {
		w.pingAt = b.Len() - 1
	}
	return kill
}

// dgWriteBatch writes the round's datagrams (§A5.8): the stored H2 first and
// alone, the challenge alone to its candidate, then the sealed frames packed
// into datagrams under the budget (M2-D12), each built once in the writer's
// scratch after Headroom() bytes and handed to WriteDatagram with
// Hooks.BeforeWrite before it (M2-D29). One stall window and one
// SetWriteDeadline cover the round. Per datagram: written; refused as too
// large — the budget shrinks (M2-D25), its DGRAM counts Refused and its
// PING record goes; lost to noise — Dropped; any other error ends the
// carrier (an invalid count included: never retried, L42). The commit
// follows under Conn.mu: the PING commit (L23), the REL timer per R1-2,
// the CLOSE and the retirement checks (R1-4).
func (c *Conn) dgWriteBatch(w *writer, b *Batch, now time.Time, h2, chal bool, cand PeerKey, nonce uint64) bool {
	dg := c.dg
	io := dg.io
	c.mu.Lock()
	srtt := c.st.srtt
	c.mu.Unlock()
	stall := sched.StallWindow(srtt, b.wireLen(), 0, c.tm.WriteStall, c.tm.DeadMax)
	gen := c.wstate.Load() >> 1
	c.armWatchdog(gen, now, stall)
	_ = io.SetWriteDeadline(now.Add(stall)) // a transport without deadlines still has the watchdog's stage 2
	hr := io.Headroom()
	hook := c.env.Hooks
	var fatal error
	var txb uint64
	rackWritten := false
	if h2 {
		d := append(w.dscratch.B[:hr], dg.hs.h2()...)
		if hook != nil && hook.BeforeWrite != nil {
			hook.BeforeWrite(c.id, 1, len(d))
		}
		fatal = c.dgControlWritten(io.WriteDatagram(d))
	}
	if fatal == nil && chal {
		var pp [wire.PingFixedLen]byte
		wire.PutPing(pp[:], &wire.Ping{ID: 0, TS: uint64(now.Sub(c.base)), Nonce: nonce})
		d := wire.AppendFrame(w.dscratch.B[:hr], wire.Header{Type: wire.TypePing, Fseq: w.fseq}, pp[:])
		w.fseq++
		if hook != nil && hook.BeforeWrite != nil {
			hook.BeforeWrite(c.id, 1, len(d))
		}
		fatal = c.dgControlWritten(io.WriteDatagramTo(d, cand))
	}
	budget := int(dg.budget.Load())
	for i := 0; fatal == nil && i < b.Len(); {
		end, _ := b.nextDatagram(i, budget)
		d := b.appendDatagram(w.dscratch.B[:hr], i, end)
		if hook != nil && hook.BeforeWrite != nil {
			hook.BeforeWrite(c.id, end-i, len(d))
		}
		err := io.WriteDatagram(d)
		n, hasDgram := b.datagramDgram(end)
		switch {
		case err == nil:
			dg.ctr.datagrams.Add(1)
			if hasDgram {
				dg.lastDgram.Store(c.dgSince(now))
				txb += uint64(n)
			}
			if w.rackAt >= i && w.rackAt < end {
				rackWritten = true
			}
		case errors.Is(err, wire.ErrDatagramTooLarge):
			if hasDgram {
				dg.ctr.refused.Add(1)
			}
			if w.ping && w.pingAt >= i && w.pingAt < end {
				c.mu.Lock()
				c.dgUnsentPingLocked(w) // it never left; a probe counts unanswered
				c.mu.Unlock()
			}
			if c.dgShrink(err) {
				fatal = errBudgetFloor
				break
			}
			budget = int(dg.budget.Load())
		case errors.Is(err, ErrNoise):
			c.dgDropped(1) // this datagram is lost; the carrier lives
		default:
			fatal = err
		}
		i = end
	}
	end := time.Now()
	c.disarmWatchdog(gen)
	b.ReleaseRefs() // the writes returned: the chunk references go
	if fatal != nil {
		if fatal == errBudgetFloor {
			c.Kill(CauseTransportError, fatal.Error())
			return false
		}
		if c.endIfPeerClosed("write ended (" + fatal.Error() + ")") {
			return false
		}
		cause := CauseTransportError
		if errors.Is(fatal, os.ErrDeadlineExceeded) {
			cause = CauseWriteStall
		}
		c.Kill(cause, "write: "+fatal.Error())
		return false
	}
	if w.close {
		c.closeSent.Store(true) // attempted: REL{CLOSE} is retransmitted until RACKed
	}
	c.mu.Lock()
	c.commitLocked(w, b, end)
	c.st.txBytes += txb
	c.relAttemptedLocked(w.retx, end)
	if rackWritten && dg.peerCloseSeen && !wire.SeqLess(w.rackCum, dg.peerCloseCseq) {
		dg.peerCloseRacked = true
	}
	finish := c.dgRetireDoneLocked()
	c.mu.Unlock()
	if w.retx {
		dg.ctr.retransmits.Add(1)
		if hook != nil && hook.RelRetransmit != nil {
			hook.RelRetransmit(c.id, w.retxCseq)
		}
	}
	if w.ping {
		if o := c.opts.Observer; o != nil {
			o.PingCommitted(c, w.pingID, end)
		}
	}
	if finish {
		c.finishRetire("retired: CLOSE exchange complete")
		return false
	}
	if w.close {
		c.dgCloseWritten()
	}
	return c.death.Load() == nil
}

// errBudgetFloor: a refusal lowered the budget below wire.ControlFloor.
var errBudgetFloor = errors.New("datagram budget below the control floor")

// dgControlWritten classifies the result of a datagram the writer sends
// outside the batch (the H2 repeat, a rebind challenge): too large, noise
// and a transport that cannot rebind lose that datagram only; any other
// error ends the carrier.
func (c *Conn) dgControlWritten(err error) error {
	switch {
	case err == nil:
		c.dg.ctr.datagrams.Add(1)
		return nil
	case errors.Is(err, wire.ErrDatagramTooLarge), errors.Is(err, ErrNoise), errors.Is(err, ErrNoRebind):
		c.dgDropped(1)
		return nil
	}
	return err
}

// dgShrink applies a size refusal (M2-D25): DatagramTooLargeError{Max} with
// 0 < Max < budget lowers the budget to Max (never raised); Max 0 lowers
// nothing (the MTU probe decides). It reports a budget below
// wire.ControlFloor (the carrier dies).
func (c *Conn) dgShrink(err error) bool {
	var te *wire.DatagramTooLargeError
	if !errors.As(err, &te) || te.Max <= 0 {
		return false
	}
	b := &c.dg.budget
	for {
		cur := b.Load()
		if int32(te.Max) >= cur || b.CompareAndSwap(cur, int32(te.Max)) {
			break
		}
	}
	return int(b.Load()) < wire.ControlFloor
}

// dgCloseWritten runs after the round that placed our CLOSE (M2-D31, R1-4):
// the retirement completes when the CLOSE exchange does (dgRetireDoneLocked)
// or at min(max(2·srtt + 100 ms, 3·RTO), 2 s) from now.
func (c *Conn) dgCloseWritten() {
	c.mu.Lock()
	bound := min(max(2*c.st.srtt+100*time.Millisecond, 3*c.relRTOLocked()), dgRetireMax)
	c.mu.Unlock()
	c.jmu.Lock()
	if !c.join.doneClosed {
		c.join.drain = time.AfterFunc(bound, func() { c.finishRetire("retired: drain bound after CLOSE") })
	}
	c.jmu.Unlock()
}

// dgRetireMax caps the datagram retirement after our CLOSE (M2-D31).
const dgRetireMax = 2 * time.Second

// dgRetireDoneLocked reports whether the datagram retirement is complete
// (R1-4): our CLOSE was RACKed (it is our last REL, so nothing is
// outstanding), the peer's CLOSE was dispatched and a written datagram
// carried a RACK covering it.
func (c *Conn) dgRetireDoneLocked() bool {
	dg := c.dg
	return c.closeSent.Load() && !dg.rel.outstanding() && dg.peerCloseSeen && dg.peerCloseRacked
}

// dgSleep waits for a wake, the carrier's death or the earliest timed event
// (dgNextWakeLocked, the endpoint's WakeAt) and returns true. A timer that
// fires for an event that went away meanwhile — a REL timeout the RACK
// cleared (R1-2) — starts no round: the sleep re-checks what is due and
// goes on sleeping, so a carrier with nothing outstanding neither writes
// nor wakes its endpoint (M2-D65).
func (c *Conn) dgSleep(w *writer, now time.Time) bool {
	wt := w.b.WakeTime()
	if !wt.After(now) {
		wt = time.Time{} // a WakeAt at or before the round's own time was served by Fill
	}
	for {
		if !wt.IsZero() && !now.Before(wt) {
			return true
		}
		c.mu.Lock()
		at := c.dgNextWakeLocked(now, w)
		c.mu.Unlock()
		if !at.IsZero() && !at.After(now) {
			return true
		}
		if !wt.IsZero() && (at.IsZero() || wt.Before(at)) {
			at = wt
		}
		if at.IsZero() {
			select {
			case <-c.wake:
			case <-c.dying:
			}
			return true
		}
		w.timer.Reset(at.Sub(now))
		select {
		case <-c.wake:
			w.timer.Stop()
			return true
		case <-c.dying:
			w.timer.Stop()
			return true
		case <-w.timer.C:
		}
		now = time.Now()
	}
}

// dgNextWakeLocked returns the earliest timed event of a datagram carrier
// (zero: none): the next PING or PING retry (not while held, retiring or
// closing), the death deadline of the oldest PING, the sessionless idle
// limit, the REL retransmission (only while a REL is outstanding: M2-D65)
// and the rebind challenge.
func (c *Conn) dgNextWakeLocked(now time.Time, w *writer) time.Time {
	st := &c.st
	var at time.Time
	earliest := func(t time.Time) {
		if !t.IsZero() && (at.IsZero() || t.Before(at)) {
			at = t
		}
	}
	if !st.retiring && !w.held && !c.closeSent.Load() {
		k, t := c.dgPingDueLocked(now)
		if k != pingNone {
			return now
		}
		earliest(t)
	}
	_, t, _ := c.deathDueLocked(now)
	earliest(t)
	if c.opts.Sessionless && !st.retiring {
		earliest(st.lastPingRx.Add(c.tm.SessionlessIdle))
	}
	earliest(c.relWakeLocked())
	earliest(c.chalWakeLocked(now))
	return at
}
