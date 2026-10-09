package carrier

import (
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// DETACH and the ends of a view (M3 design §A3.4, §A5.4, §A5.5; M3-D6,
// M3-D7, M3-D61, M3-D62; R1-2, R1-3, R1-5, R1-9). DETACH 0x36 is a
// carrier-level frame (handle 0, payload handle · reason), REL-wrapped on
// datagram trunks, legal only on MUX trunks, at most once per direction
// per handle. A side places nothing for h after its DETACH(h); a view
// retires when its DETACH was written (datagram: RACKed) and the peer's
// was dispatched, or at the DETACH bound after ours (the trunk lives).
//
// On a view of a started MUX trunk Kill, Retire, GoAway and WriteAndClose
// are view-scoped: they end the view and queue its DETACH; the trunk and
// its other views are untouched (R1-2). KillTrunk kills the physical
// carrier.

// detachReasonOf maps a CLOSE reason to the DETACH reason of a view's
// planned end: CloseRetire is a planned lane retirement, anything else an
// ended view. The reason is informational on the receiver (R1-5 rule 3).
func detachReasonOf(r wire.CloseReason) wire.DetachReason {
	if r == wire.CloseRetire {
		return wire.DetachRetired
	}
	return wire.DetachEnded
}

// killView is Kill on a view of a started MUX trunk (R1-2): the view's end
// record (once), then no further Fill and its DETACH(ended) queued — none
// for a view whose first frame was never placed (a handle gap), and a
// refusal instead for a passive view that has not answered yet (a dialer
// awaiting its response must get one, R1-9). Done closes once the view's
// calls drained (M3-D13). The bell rings once.
func (c *Conn) killView(cause Cause, detail string) bool {
	if !c.end.CompareAndSwap(nil, &deathRecord{cause: cause, detail: detail, at: time.Now()}) {
		return false
	}
	t := c.trunk
	var p postList
	t.mx.Lock()
	t.abandonLocked(c, wire.DetachEnded, &p)
	t.finishLocked(c, &p)
	t.mx.Unlock()
	t.runPost(&p)
	c.ring()
	t.wakeWriter()
	return true
}

// abandonLocked ends the view's part in the writer: no further Fill; per
// state, its DETACH(r) queued, its first frame dropped (opening), or a
// refusal queued (a passive view that has not answered). A dialer attempt
// waiting for the response is released.
func (t *trunk) abandonLocked(v *Conn, r wire.DetachReason, p *postList) {
	v.vx.fillOK.Store(false)
	v.vx.retireQ.Store(false)
	t.leaveLiveLocked(v)
	t.unreadyLocked(v)
	if v.vx.resp != nil && !v.vx.respGot {
		select {
		case <-v.vx.resp:
		default:
			close(v.vx.resp)
		}
	}
	if v.vx.detQ || v.vx.detSent.Load() || v.vx.refused {
		return
	}
	switch v.state {
	case viewOpening:
		// Never placed: a legal handle gap; the opens FIFO drops it.
		v.state = viewGone
		t.removeLocked(v)
		t.finishLocked(v, p)
	case viewPending, viewJoining:
		if v.vx.needResp.Load() && !v.vx.peerDet.Load() {
			// The dialer awaits a response for this handle: answer it
			// before the handle ends (a refusal, no DETACH, M3-D7). The
			// code is CodeBacklog, not CodeMuxFull: the trunk is not
			// full, and CodeMuxFull would mark it unusable at the dialer.
			typ := respTypeOf(v.vx.first)
			v.vx.last = &lastFrame{t: typ}
			v.vx.last.p = refusalPayload(typ, wire.StatusCapacity, wire.CodeBacklog)
			v.vx.detQ = true
			t.ms.lasts = append(t.ms.lasts, v)
			t.markWorkLocked()
			return
		}
		fallthrough
	case viewAwaiting, viewAttachedPending, viewLive, viewHeld:
		v.state = viewRetiring
		v.held.Store(false)
		v.vx.reason, v.vx.detQ = r, true
		t.ms.detq = append(t.ms.detq, v)
		t.markWorkLocked()
	}
}

// refusalPayload encodes the payload of a refusal response of type typ.
func refusalPayload(typ wire.Type, st wire.AckStatus, code uint32) []byte {
	if typ == wire.TypeJoinAck {
		b := make([]byte, wire.JoinAckLen)
		wire.PutJoinAck(b, &wire.JoinAck{Status: st})
		return b
	}
	b := make([]byte, wire.OpenAckFixedLen)
	n := wire.PutOpenAck(b, &wire.OpenAck{Status: st, Code: code})
	return b[:n]
}

// retireView is Retire on a view of a started MUX trunk (§A5.5): a live
// view keeps its Fill until a call places nothing, then its DETACH(r)
// follows (M2's CLOSE rule, per view); a view that carries no session
// frames yet (opening, awaiting, attached-pending, pending, joining, held)
// is abandoned at once. The view's end record becomes CauseRetired when
// the DETACH exchange completes or at the DETACH bound.
func (c *Conn) retireView(r wire.DetachReason) {
	t := c.trunk
	var p postList
	t.mx.Lock()
	switch {
	case c.vx.detQ || c.vx.detSent.Load() || c.vx.refused || !c.vx.inTable:
	case c.state == viewLive && c.vx.attached,
		(c.state == viewPending || c.state == viewJoining) && c.vx.attached && c.vx.needResp.Load():
		// A live view keeps its Fill until a call places nothing; so does
		// a passive view whose session attached it but whose verdict is not
		// placed yet: the verdict its session set (REJECTED, AcceptTimeout,
		// GOING_AWAY, a JOIN's answer) is its first and last frame, before
		// its DETACH or, for a refusal, instead of it (M3-D7; WP10).
		if !c.vx.retireQ.Load() {
			c.vx.reason = r
			c.vx.retireQ.Store(true)
			t.markWorkLocked()
			t.readyLocked(c)
		}
	default:
		t.abandonLocked(c, r, &p)
	}
	t.mx.Unlock()
	t.runPost(&p)
	t.wakeWriter()
}

// goAwayView is GoAway on a view of a started MUX trunk: GOAWAY once on the
// trunk (no view is opened or admitted after it) and the view's
// retirement; the trunk closes at its last view (M3-D26).
func (c *Conn) goAwayView() {
	t := c.trunk
	t.mu.Lock()
	t.st.goAway = true
	t.mu.Unlock()
	c.retireView(wire.DetachEnded)
}

// writeAndCloseView is WriteAndClose on a view of a started MUX trunk
// (R1-2): the frame is placed as the view's last session frame, then
// DETACH(ended) — none when the frame is the view's first response and a
// refusal (M3-D7). The view's end record becomes CauseLocalClose once the
// frame is placed, or at deadline (zero: now + 1 s), when the frame is
// dropped and only the DETACH follows. A frame for a view whose first
// frame was never placed is dropped with it (a handle gap); so is the
// frame of a held passive view (OK placed, no go frame yet), which may
// place nothing but its DETACH(ended) (M3-D8, R1-9). The handle argument
// is ignored: a view places frames for its own handle.
func (c *Conn) writeAndCloseView(typ wire.Type, flags uint8, payload []byte, deadline time.Time) {
	t := c.trunk
	if deadline.IsZero() {
		deadline = time.Now().Add(drainMax)
	}
	var p postList
	t.mx.Lock()
	if c.vx.detQ || c.vx.detSent.Load() || c.vx.refused || !c.vx.inTable || c.vx.fin.Load() {
		t.mx.Unlock()
		return
	}
	if c.state == viewOpening {
		t.abandonLocked(c, wire.DetachEnded, &p)
		t.mx.Unlock()
		t.runPost(&p)
		c.endView(CauseLocalClose, "closed before its first frame was placed")
		return
	}
	if c.state == viewHeld || c.held.Load() {
		t.abandonLocked(c, wire.DetachEnded, &p)
		t.mx.Unlock()
		t.runPost(&p)
		c.endView(CauseLocalClose, "closed while held: its frame dropped, DETACH only (R1-9)")
		t.wakeWriter()
		return
	}
	c.vx.fillOK.Store(false)
	c.vx.retireQ.Store(false)
	t.leaveLiveLocked(c)
	t.unreadyLocked(c)
	lf := &lastFrame{t: typ, flags: flags, p: append([]byte(nil), payload...)}
	c.vx.last, c.vx.detQ = lf, true
	t.ms.lasts = append(t.ms.lasts, c)
	t.markWorkLocked()
	lf.timer = time.AfterFunc(time.Until(deadline), func() { c.lastExpired(lf) })
	t.mx.Unlock()
	t.wakeWriter()
}

// lastExpired runs at a WriteAndClose deadline: a frame still unplaced is
// dropped, the view's end record becomes CauseLocalClose and only its
// DETACH follows.
func (c *Conn) lastExpired(lf *lastFrame) {
	t := c.trunk
	var p postList
	t.mx.Lock()
	if c.vx.last != lf {
		t.mx.Unlock()
		return
	}
	c.vx.last = nil
	t.dropLastLocked(c)
	c.vx.detQ = false
	t.abandonLocked(c, wire.DetachEnded, &p)
	t.mx.Unlock()
	t.runPost(&p)
	c.endView(CauseLocalClose, "WriteAndClose deadline passed before its frame was placed")
}

// dropLastLocked removes v from the last frames' queue.
func (t *trunk) dropLastLocked(v *Conn) {
	q := t.ms.lasts
	for i, w := range q {
		if w == v {
			copy(q[i:], q[i+1:])
			q[len(q)-1] = nil
			t.ms.lasts = q[:len(q)-1]
			return
		}
	}
}

// endView publishes v's end record (once), finishes it and rings its bell.
func (c *Conn) endView(cause Cause, detail string) {
	if !c.end.CompareAndSwap(nil, &deathRecord{cause: cause, detail: detail, at: time.Now()}) {
		return
	}
	c.trunk.finish(c)
	c.ring()
}

// endViewLocked is endView under mx (the Done close and the ring run at
// runPost).
func (t *trunk) endViewLocked(v *Conn, cause Cause, detail string, p *postList) {
	if !v.end.CompareAndSwap(nil, &deathRecord{cause: cause, detail: detail, at: time.Now()}) {
		if !v.vx.fin.Load() {
			t.finishLocked(v, p)
		}
		return
	}
	t.finishLocked(v, p)
	p.bells = append(p.bells, v)
}

// placeControlLocked places the round's mux control frames (§A5.3) in
// this order: the views' last frames (each followed by its DETACH when
// one is due), the DETACHes due, the refusal answers, the first frames of
// new handles in allocation order; then it completes the retiring views
// whose exchange ended or whose DETACH bound passed.
func (t *trunk) placeControlLocked(b *Batch, rd *roundData, nowNs int64, p *postList) {
	ms := &t.ms
	// Last frames (WriteAndClose).
	for len(ms.lasts) > 0 {
		v := ms.lasts[0]
		lf := v.vx.last
		if lf == nil {
			t.popLastLocked()
			continue
		}
		ok, skip := b.addLast(lf.t, lf.flags, v.handle, lf.p)
		if !ok && !skip {
			break
		}
		t.popLastLocked()
		v.vx.last = nil
		if lf.timer != nil {
			lf.timer.Stop()
		}
		if !skip {
			v.vx.lastSent = true
		}
		if !skip && v.vx.needResp.Load() && (lf.t == wire.TypeOpenAck || lf.t == wire.TypeJoinAck) {
			v.vx.needResp.Store(false)
			if len(lf.p) > 0 && wire.AckStatus(lf.p[0]) != wire.StatusOK {
				t.refusedLocked(v, p) // the refusal ends the handle: no DETACH (M3-D7)
				t.endViewLocked(v, CauseLocalClose, "closed after a refusal", p)
				continue
			}
		}
		t.endViewLocked(v, CauseLocalClose, "closed after a "+lf.t.String(), p)
		v.state = viewRetiring
		v.vx.reason = wire.DetachEnded
		ms.detq = append(ms.detq, v)
	}
	// DETACHes due.
	for len(ms.detq) > 0 {
		v := ms.detq[0]
		if !v.vx.detSent.Load() && v.vx.inTable && !t.placeDetachLocked(v, b, rd, nowNs, p) {
			break
		}
		copy(ms.detq, ms.detq[1:])
		ms.detq[len(ms.detq)-1] = nil
		ms.detq = ms.detq[:len(ms.detq)-1]
	}
	// Refusal answers (passive).
	for t.refN > 0 {
		r := &t.refusals[t.refHead]
		if !b.addAnswer(r.handle, &r.a) {
			break
		}
		*r = refusal{}
		t.refHead = (t.refHead + 1) % len(t.refusals)
		t.refN--
	}
	// First frames of new handles, in allocation order (§A3.2).
	for ms.opN > 0 {
		v := t.opens[ms.opHead]
		if v.state == viewOpening {
			if !v.vx.queued || !b.addFirst(v.vx.first, v.handle, v.vx.firstP) {
				break // a later handle never overtakes an earlier one
			}
			v.state = viewAwaiting
		}
		t.opens[ms.opHead] = nil
		ms.opHead = (ms.opHead + 1) % len(t.opens)
		ms.opN--
	}
	// Retirements: the exchange complete, or the DETACH bound passed.
	ms.detWake = 0
	for i := 0; i < len(ms.retiring); {
		v := ms.retiring[i]
		switch {
		case v.vx.peerDet.Load() && (t.dg == nil || wire.SeqLess(v.vx.detCseq, rd.una)):
			t.completeLocked(v, "retired: DETACH exchange complete", p)
		case nowNs >= v.vx.detBound:
			t.expireLocked(v, p)
		default:
			if ms.detWake == 0 || v.vx.detBound < ms.detWake {
				ms.detWake = v.vx.detBound
			}
			i++
			continue
		}
	}
	ms.work.Store(len(ms.lasts) > 0 || len(ms.detq) > 0 || t.refN > 0 || ms.opN > 0 ||
		len(ms.retiring) > 0 || t.view1.vx.retireQ.Load())
}

func (t *trunk) popLastLocked() {
	q := t.ms.lasts
	copy(q, q[1:])
	q[len(q)-1] = nil
	t.ms.lasts = q[:len(q)-1]
}

// placeDetachLocked places DETACH(v) in b: the view is retiring with our
// DETACH placed; on a stream trunk with the peer's DETACH already in, the
// exchange is complete; otherwise it waits (the datagram trunk also for
// the RACK of our REL{DETACH}) until the DETACH bound (§A5.5). False when
// the batch has no room for it (it stays due).
func (t *trunk) placeDetachLocked(v *Conn, b *Batch, rd *roundData, nowNs int64, p *postList) bool {
	reason := v.vx.reason
	if reason == 0 {
		reason = wire.DetachEnded
	}
	if !b.addDetach(v.handle, reason) {
		return false
	}
	v.vx.detSent.Store(true)
	v.vx.detQ = true
	v.vx.fillOK.Store(false)
	v.vx.retireQ.Store(false)
	v.vx.detAt = nowNs
	v.state = viewRetiring
	t.leaveLiveLocked(v)
	t.unreadyLocked(v)
	p.hooks = append(p.hooks, detachEvent{h: v.handle, sent: true})
	if t.dg != nil {
		v.vx.detCseq = rd.relNext + uint32(b.relCount()-1)
		t.ms.awaitAck.Add(1)
	}
	if v.vx.peerDet.Load() && t.dg == nil {
		t.completeLocked(v, "retired: DETACH exchange complete", p)
		return true
	}
	if rd.goAway {
		// The trunk goes away (our GOAWAY: Runtime.Close, M3-D26): the
		// peer's sessions end on it, so no DETACH exchange is waited for —
		// the view ends with its DETACH placed, its late crossing frames
		// tolerated, and the trunk's CLOSE follows at its last view
		// without waiting for a DETACH bound (WP10).
		if !v.vx.peerDet.Load() {
			t.tolerateLocked(v.handle, true)
		}
		if t.dg != nil {
			t.ms.awaitAck.Add(-1)
		}
		v.state = viewGone
		t.removeLocked(v)
		t.endViewLocked(v, CauseRetired, "retired: DETACH placed while going away", p)
		return true
	}
	v.vx.detBound = nowNs + int64(t.detachBound(rd))
	t.ms.retiring = append(t.ms.retiring, v)
	if t.ms.detWake == 0 || v.vx.detBound < t.ms.detWake {
		t.ms.detWake = v.vx.detBound
	}
	t.markWorkLocked()
	return true
}

// detachBound is the bound for the peer's DETACH after ours (§A5.5): the
// trunk's own retirement bound after its CLOSE — min(2·srtt + 100 ms, 1 s)
// on a stream trunk, min(max(2·srtt + 100 ms, 3·RTO), 2 s) on a datagram
// trunk (the carrier has no RetireGrace of its own).
func (t *trunk) detachBound(rd *roundData) time.Duration {
	d := 2*rd.srtt + 100*time.Millisecond
	if t.dg != nil {
		return min(max(d, 3*rd.rto), dgRetireMax)
	}
	return min(d, drainMax)
}

// retireDrainedLocked places a retiring view's DETACH right after a Fill
// that placed nothing (its last frames are out: M2's CLOSE rule, per
// view), or queues it for the next round when the batch has no room.
func (t *trunk) retireDrainedLocked(v *Conn, b *Batch, rd *roundData, nowNs int64, p *postList) {
	if !v.vx.retireQ.Load() || v.vx.detQ || v.vx.detSent.Load() || !v.vx.inTable {
		return
	}
	if v.vx.needResp.Load() {
		// A passive view whose session set no verdict to place: the dialer
		// awaits a response for the handle, so it gets a refusal, never a
		// DETACH (R1-9; abandonLocked).
		v.vx.retireQ.Store(false)
		t.abandonLocked(v, v.vx.reason, p)
		return
	}
	v.vx.retireQ.Store(false)
	v.vx.fillOK.Store(false)
	v.state = viewRetiring
	v.vx.detQ = true
	if t.placeDetachLocked(v, b, rd, nowNs, p) {
		return
	}
	t.ms.detq = append(t.ms.detq, v)
	t.markWorkLocked()
	t.wakeWriter()
}

// completeLocked ends a retiring view: gone, out of the table, its end
// record CauseRetired unless it ended before (R1-3), its Done once the
// calls drained.
func (t *trunk) completeLocked(v *Conn, detail string, p *postList) {
	for i, w := range t.ms.retiring {
		if w == v {
			copy(t.ms.retiring[i:], t.ms.retiring[i+1:])
			t.ms.retiring[len(t.ms.retiring)-1] = nil
			t.ms.retiring = t.ms.retiring[:len(t.ms.retiring)-1]
			break
		}
	}
	if t.dg != nil && v.vx.detSent.Load() && v.state == viewRetiring {
		t.ms.awaitAck.Add(-1)
	}
	v.state = viewGone
	t.removeLocked(v)
	t.endViewLocked(v, CauseRetired, detail, p)
}

// expireLocked retires v at its DETACH bound (§A5.5): the peer's DETACH
// has not arrived (or, on a datagram trunk, our REL{DETACH} is not yet
// acknowledged). Without the peer's DETACH its handle is tolerated for every
// session frame and the DETACH: the peer may still be sending what it placed
// before ours reached it (§A3.3: legal), so a late frame is dropped, never a
// violation; the peer's DETACH clears the entry.
func (t *trunk) expireLocked(v *Conn, p *postList) {
	if !v.vx.peerDet.Load() {
		t.tolerateLocked(v.handle, true)
	}
	t.completeLocked(v, "retired: DETACH bound", p)
}

// refusedLocked ends a view through a refusal response: gone without a
// DETACH, its handle tolerated (a crossing RST or DETACH of the dialer is
// dropped).
func (t *trunk) refusedLocked(v *Conn, p *postList) {
	v.vx.refused = true
	v.vx.fillOK.Store(false)
	v.vx.retireQ.Store(false)
	v.held.Store(false)
	v.state = viewGone
	t.removeLocked(v)
	t.tolerateLocked(v.handle, false)
}

// The tolerance ring: handles whose crossing frames are legal although no
// view holds them any more — a refused handle (the dialer's RST and DETACH
// may cross the refusal) and a view retired at the DETACH bound (the
// peer's frames and DETACH may still come). The ring holds MuxMaxViews
// entries (the kind's): the oldest entry is overwritten.

func (t *trunk) tolerateLocked(h uint32, all bool) {
	n := t.maxViews()
	if t.ms.tol == nil {
		t.ms.tol = make([]tolEntry, n)
	}
	t.ms.tol[t.ms.tolHead] = tolEntry{h: h, all: all}
	t.ms.tolHead = (t.ms.tolHead + 1) % n
}

// toleratedLocked reports whether a frame of type typ for h is a tolerated
// crossing frame: h is in the ring, and the entry covers every session
// frame or typ is an RST, a response or the DETACH. With drop (the
// handle's last frame, its DETACH) the entry leaves the ring.
func (t *trunk) toleratedLocked(h uint32, typ wire.Type, drop bool) bool {
	if h == 0 {
		return false
	}
	for i, e := range t.ms.tol {
		if e.h != h {
			continue
		}
		if !e.all && typ != wire.TypeRst && typ != wire.TypeOpenAck && typ != wire.TypeJoinAck && typ != wire.TypeDetach {
			return false
		}
		if drop {
			t.ms.tol[i] = tolEntry{}
		}
		return true
	}
	return false
}

// The receiving side of DETACH (§A3.4; R1-5, R1-9).

// onDetach handles a DETACH dispatched on the reader (a stream frame or a
// REL's inner frame). It returns illegal "" when the frame was handled,
// else the §A3.3 rule it broke (violation on a stream trunk, a counted
// drop on a datagram trunk); a malformed payload or a DETACH on a
// dedicated carrier is a violation on either.
func (t *trunk) onDetach(p []byte) (illegal string, violation bool) {
	d, err := wire.ParseDetach(p)
	if err != nil {
		return "DETACH: " + err.Error(), true
	}
	if !t.mux {
		return "DETACH on a dedicated carrier", true
	}
	var una uint32
	if t.dg != nil {
		t.mu.Lock()
		una = t.dg.rel.una
		t.mu.Unlock()
	}
	pl := &t.ms.rpost
	t.mx.Lock()
	why := t.onDetachLocked(d, una, pl)
	t.mx.Unlock()
	t.runPost(pl)
	t.wakeWriter()
	return why, false
}

func (t *trunk) onDetachLocked(d wire.Detach, una uint32, p *postList) string {
	v := t.lookupLocked(d.Handle)
	if v == nil {
		if t.toleratedLocked(d.Handle, wire.TypeDetach, true) {
			return ""
		}
		return "DETACH for an unknown handle"
	}
	if v.vx.peerDet.Load() {
		return "a second DETACH for the handle"
	}
	if v.state == viewOpening || v.state == viewAwaiting {
		return "DETACH for a view awaiting its response" // R1-9: a compliant passive answers first
	}
	if v.state == viewGone || v.state == viewDead {
		return "DETACH for an ended view"
	}
	v.vx.peerDet.Store(true)
	p.hooks = append(p.hooks, detachEvent{h: d.Handle})
	t.leaveLiveLocked(v)
	if v.vx.detSent.Load() {
		if t.dg == nil || wire.SeqLess(v.vx.detCseq, una) {
			t.completeLocked(v, "retired: DETACH exchange complete", p)
		}
		return ""
	}
	p.bells = append(p.bells, v) // the lane leaves as for the peer's CLOSE
	if v.vx.detQ {
		return "" // ours is queued: its placement completes the exchange
	}
	switch v.state {
	case viewLive:
		if v.vx.attached && !v.vx.retireQ.Load() {
			// Our last frames, then our DETACH (M1's answer to CLOSE).
			v.vx.reason = wire.DetachEnded
			v.vx.retireQ.Store(true)
			t.markWorkLocked()
			t.readyLocked(v)
		}
	default:
		// attached-pending, pending, joining, held: the view ends; we
		// answer DETACH(ended) (R1-5, R1-9). A passive view that has not
		// answered keeps needResp: its session's Fill may be placing its
		// first response right now (the writer read needResp before this
		// dispatch, or reads it after), and a refusal it places ends the
		// handle — responsePlacedLocked then withdraws the queued DETACH,
		// which the dialer, having ended the handle at the refusal, would
		// take for a DETACH of an unknown handle and kill the trunk for
		// (M3-D7; DEFECT A, TestPassiveResponseCrossesPeerDetach_R1_9).
		// abandonLocked queues the DETACH, not a refusal: peerDet is set.
		t.abandonLocked(v, wire.DetachEnded, p)
	}
	return ""
}

// relAcked runs on the reader after a RACK moved una (datagram trunks):
// retiring views whose REL{DETACH} it covers and whose peer DETACH arrived
// complete.
func (t *trunk) relAcked(una uint32) {
	if t.ms.awaitAck.Load() == 0 {
		return
	}
	pl := &t.ms.rpost
	t.mx.Lock()
	for i := 0; i < len(t.ms.retiring); {
		v := t.ms.retiring[i]
		if v.vx.peerDet.Load() && wire.SeqLess(v.vx.detCseq, una) {
			t.completeLocked(v, "retired: DETACH exchange complete", pl)
			continue
		}
		i++
	}
	t.mx.Unlock()
	t.runPost(pl)
}
