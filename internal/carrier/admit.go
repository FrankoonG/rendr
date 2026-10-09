package carrier

import (
	"errors"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Passive admission on a live trunk, the refusal ring and the response
// hold (M3 design §A5.4, §A5.6; M3-D7, M3-D8, M3-D12, M3-D21; R1-4), and
// the dialer's side of a view's response (§A5.8).

// admitMux handles an OPEN or JOIN for a new handle h on a started passive
// MUX trunk, on the reader (§A5.6): the handle becomes the largest seen;
// the view cap (views plus queued answers), the payload decode, our GOAWAY,
// a retiring trunk and a Runtime without passive mux are refused through
// the refusal ring; otherwise a new view (pending for an OPEN, joining for
// a JOIN; shim endpoint) is inserted under mx and, with mx released,
// handed to Env.Admit (R1-17). It never blocks; a full refusal ring kills
// the trunk ("mux flood").
func (t *trunk) admitMux(h uint32, hdr wire.Header, p []byte) {
	t.mu.Lock()
	goAway, retiring := t.st.goAway, t.st.retiring
	t.mu.Unlock()
	t.mx.Lock()
	t.maxHandle = max(t.maxHandle, h)
	full := t.nviews+t.refN >= t.maxViews()
	t.mx.Unlock()
	ans := Answer{Type: respTypeOf(hdr.Type)}
	switch {
	case full:
		ans.Status, ans.Code = wire.StatusCapacity, wire.CodeMuxFull
	case decodeFirst(hdr.Type, p) != nil:
		ans.Status, ans.Code = wire.StatusBadRequest, wire.CodeBadValue
	case t.dg != nil && hdr.Type == wire.TypeOpen && p[16] == byte(wire.KindStream):
		// A datagram trunk carries packet sessions only (M3-D24; a JOIN's
		// kind is its session's, checked by the root).
		ans.Status, ans.Code = wire.StatusBadRequest, wire.CodeBadKind
	case goAway:
		ans.Status = wire.StatusGoingAway
	case retiring || t.closeSent.Load() || t.env.Admit == nil:
		ans.Status, ans.Code = wire.StatusCapacity, wire.CodeMuxFull
	default:
		st := viewPending
		if hdr.Type == wire.TypeJoin {
			st = viewJoining
		}
		t.mx.Lock()
		v := t.newViewLocked(h, st)
		v.vx.first = hdr.Type
		v.vx.needResp.Store(true)
		t.mx.Unlock()
		if hk := t.env.Hooks; hk != nil && hk.BeforeAdmit != nil {
			hk.BeforeAdmit(t.id, h)
		}
		t.env.Admit(v, hdr, p)
		return
	}
	t.refuse(h, ans)
}

// decodeFirst validates an OPEN or JOIN payload (M1: nothing is allocated
// for a handle before its first frame decoded).
func decodeFirst(typ wire.Type, p []byte) error {
	if typ == wire.TypeJoin {
		_, err := wire.ParseJoin(p)
		return err
	}
	_, err := wire.ParseOpen(p, wire.MaxMetadata)
	return err
}

// refuseMux queues the refusal a for handle h, a handle that never becomes
// a view (R1-4): a view admitted for h and not yet answered leaves the
// table first. When the ring is full the peer had more handles outstanding
// than a compliant dialer can: the trunk is killed ("mux flood") and
// false returned.
func (t *trunk) refuse(h uint32, a Answer) bool {
	if a.Type != wire.TypeJoinAck {
		a.Type = wire.TypeOpenAck
	}
	if a.Status == wire.StatusOK {
		a.Status = wire.StatusCapacity // a refusal is never OK
	}
	var p postList
	t.mx.Lock()
	if v := t.lookupLocked(h); v != nil && v != t.view1 && v.vx.needResp.Load() {
		v.vx.needResp.Store(false)
		v.vx.refused = true
		v.vx.fillOK.Store(false)
		v.state = viewGone
		t.removeLocked(v)
		t.endViewLocked(v, CauseLocalClose, "refused at admission", &p)
	}
	n := t.tm.MuxRefusalRing
	if n <= 0 {
		n = t.maxViews() // R1-4: what a compliant dialer can have outstanding
	}
	if t.refusals == nil {
		t.refusals = make([]refusal, n)
	}
	if t.refN >= len(t.refusals) {
		t.mx.Unlock()
		t.runPost(&p)
		t.killFlood("mux flood: more refused handles outstanding than the refusal ring holds")
		return false
	}
	t.refusals[(t.refHead+t.refN)%len(t.refusals)] = refusal{handle: h, a: a}
	t.refN++
	t.tolerateLocked(h, false)
	t.markWorkLocked()
	t.mx.Unlock()
	t.runPost(&p)
	t.wakeWriter()
	return true
}

// killFlood kills the physical carrier with protocol_violation.
func (t *trunk) killFlood(detail string) {
	t.view1.killCarrier(CauseProtocolViolation, detail)
}

// responsePlacedLocked runs when a passive view's Fill placed its first
// response (M3-D7, M3-D8): an OK response holds the view until the
// dialer's first frame for it (its go frame) — nothing else is placed for
// it meanwhile; a refusal ends the handle without a DETACH.
func (t *trunk) responsePlacedLocked(v *Conn, typ wire.Type, st wire.AckStatus, p *postList) {
	if !v.vx.needResp.Load() {
		return
	}
	v.vx.needResp.Store(false)
	if st != wire.StatusOK {
		t.refusedLocked(v, p)
		t.endViewLocked(v, CauseLocalClose, "closed after a refusal", p)
		return
	}
	if v.state == viewPending || v.state == viewJoining {
		v.state = viewHeld
		v.held.Store(true)
		v.vx.fillOK.Store(false) // R1-1's ready set skips it until the go frame
		if v.vx.retireQ.Load() {
			// Its session ended while the OK was due: held, it places its
			// DETACH(ended) only (R1-9).
			t.abandonLocked(v, wire.DetachEnded, p)
		}
	}
}

// onResponse applies the response of a dialer view (reader): OPEN_ACK for
// an OPEN, JOIN_ACK for a JOIN, decoded canonically. OK makes the view
// attached-pending (the attempt returns it; it stays dark until its
// session's Start); a refusal ends the handle (M3-D7) — CodeListenerClosed
// marks the trunk unusable for OPENs (R1-10), CodeMuxFull full until a
// view leaves. A response that crossed our DETACH (we abandoned the view)
// ends it when it is a refusal and is ignored otherwise (the passive's
// DETACH follows). It returns the rule a malformed response broke.
func (t *trunk) onResponse(v *Conn, hdr wire.Header, p []byte) error {
	var st wire.AckStatus
	var code uint32
	switch hdr.Type {
	case wire.TypeOpenAck:
		a, err := wire.ParseOpenAck(p)
		if err != nil {
			return err
		}
		st, code = a.Status, a.Code
	case wire.TypeJoinAck:
		a, err := wire.ParseJoinAck(p)
		if err != nil {
			return err
		}
		st = a.Status
	default:
		return errors.New("not a response")
	}
	pl := &t.ms.rpost
	t.mx.Lock()
	v.vx.respGot = true
	switch v.state {
	case viewAwaiting:
		v.vx.rhdr, v.vx.rp = hdr, append([]byte(nil), p...)
		if st == wire.StatusOK {
			v.state = viewAttachedPending
		} else {
			if code == wire.CodeListenerClosed && v.vx.first == wire.TypeOpen {
				t.openFull = true
			}
			if code == wire.CodeMuxFull && st == wire.StatusCapacity {
				t.ms.full = true
			}
			v.vx.refused = true
			v.state = viewGone
			t.removeLocked(v)
			t.endViewLocked(v, CauseLocalClose, "refused by the passive", pl)
		}
		close(v.vx.resp)
	case viewRetiring:
		if st != wire.StatusOK {
			t.completeLocked(v, "retired: refused after we abandoned it", pl)
		}
	}
	t.mx.Unlock()
	t.runPost(pl)
	return nil
}

// errShim: a frame reached a view that no session attached.
var errShim = errors.New("frame for a view no session attached")

// shim endpoint methods (the type is declared in trunk.go): it places
// nothing and refuses every frame; the reader's classification never
// dispatches to an unattached view, so these are a backstop.

func (e *shimEndpoint) fill(c *Conn, b *Batch) {}
func (e *shimEndpoint) data(c *Conn, off uint64, p []byte, buf *Buf) error {
	buf.Release()
	return errShim
}
func (e *shimEndpoint) control(c *Conn, h wire.Header, p []byte) error { return errShim }
func (e *shimEndpoint) dgram(c *Conn, seq uint64, p []byte, buf *Buf) error {
	buf.Release()
	return errShim
}
