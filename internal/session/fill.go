package session

import (
	"sync/atomic"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// fillLocked is lane.Fill under s.mu (design §4.3), in one lock section
// per batch; nothing in it blocks. Every Add* result is checked (W5): a
// frame that does not fit stays due for the next round, and the writer
// self-continues because this round appended something.
func (s *Session) fillLocked(l *lane, b *carrier.Batch) {
	// 0. C1: a Fill racing the actor's death step must not pull requeued
	// spans or the FIN back onto the dead lane.
	if l.state == LaneDead {
		return
	}
	start := b.Len()
	if s.fillControlLocked(l, b) && l.data {
		// 5. DATA, then 6. the FIN.
		s.fillDataLocked(l, b)
		if st := &s.st; s.finDueLocked() && b.AddFin(wire.SessionHandle, st.fin.off) {
			st.fin.lane = l
			l.finHere = true
		}
	}
	// 7.
	l.idle = b.Len() == start
}

// refusedLocked reports that l's first response frame, already placed, was
// a refusal (a non-OK OPEN_ACK or JOIN_ACK). Fill keeps that frame in
// l.first as the marker (an accepted one is cleared), so nothing ever
// follows a refusal on the wire and the lane never carries the ACK duty.
func refusedLocked(l *lane) bool {
	return l.firstSent && l.first.t != 0
}

// fillControlLocked appends Fill steps 1–4: the passive's first response
// frame (nothing at all while a held carrier has none yet), the RST, the
// dialer's pending SCHED and the ACK on the duty lane. It reports whether
// DATA and the FIN may follow (not before the first response frame, after
// a refusal, after an RST or after the end).
func (s *Session) fillControlLocked(l *lane, b *carrier.Batch) bool {
	st := &s.st
	h := wire.SessionHandle
	if s.p.Role == RolePassive && !l.firstSent {
		placed, ok := false, false
		switch l.first.t {
		case wire.TypeOpenAck:
			placed = b.AddOpenAck(h, &l.first.openAck)
			ok = l.first.openAck.Status == wire.StatusOK
		case wire.TypeJoinAck:
			placed = b.AddJoinAck(h, &l.first.joinAck)
			ok = l.first.joinAck.Status == wire.StatusOK
		}
		if !placed {
			return false // held: the first response is the first frame on the wire
		}
		l.firstSent = true
		st.facts |= factLaneConfirmed
		s.ringActor()
		if !ok {
			return false // nothing follows a refusal (l.first stays as its marker)
		}
		l.first = firstFrame{}
		if st.ackLane == nil {
			s.ensureAckLaneLocked()
		}
	} else if refusedLocked(l) {
		return false // nothing follows a refusal, in any later Fill either
	}
	if r := s.ctl.rst; r != nil {
		if !l.rstSent {
			rr := wire.Rst{Code: r.Code, Msg: r.Msg[:min(len(r.Msg), wire.MaxMsg)]}
			if b.AddRst(h, &rr) {
				l.rstSent = true
			}
		}
		return false // nothing follows an RST
	}
	if st.ended {
		return false
	}
	if s.p.Role == RoleDialer && l.schedSent != s.ctl.epoch && s.ctl.set.N > 0 {
		if b.AddSched(h, s.ctl.cause, &s.ctl.set) {
			l.schedSent = s.ctl.epoch
		}
	}
	if l == st.ackLane {
		s.fillAckLocked(l, b)
	}
	return true
}

// rescueSendHook is a test seam: when a test stores {s, fn}, fn runs under
// s.mu each time a lane of s places (part of) the rescue duplicate in a
// batch, with holder reporting that the lane is the rescue's holder (it
// sends its own duplicate: no other data lane exists). Production never
// sets it (one atomic load per placed rescue).
var rescueSendHook atomic.Pointer[rescueHook]

// rescueHook is the value of rescueSendHook.
type rescueHook struct {
	s  *Session
	fn func(l *lane, holder bool)
}

// fillDataLocked is Fill step 5 on a data lane: the rescue duplicate if l
// may send it (rescueSenderLocked: any data lane but the holder of the
// stuck head, the holder only while it is the only data lane and
// interleaved DATA is unacknowledged), then retransmissions lowest first (a
// replay completes before new data, the FIN and retirement, L10), then new
// bytes up to min(end, peerLimit). It stops at the batch's DATA budget, a
// full batch or the carrier's capacity cap; at the cap with bytes still
// pullable it marks the batch cap-blocked, so the PONG that frees capacity
// wakes the writer (§4.10).
//
// It also keeps st.interleaved (bond): cleared while everything sent is
// acknowledged (sBase == sNext: nothing can be held out of order), set when
// DATA is placed while another data lane exists. Every byte sent goes
// through here, so whenever bytes are unacknowledged the flag tells whether
// any of them left while another data lane existed.
func (s *Session) fillDataLocked(l *lane, b *carrier.Batch) {
	st := &s.st
	if st.sBase == st.sNext {
		st.interleaved = false
	}
	left := l.port.Capacity() - l.port.Inflight()
	sent := false
	if st.rescue.set && left > 0 && s.rescueSenderLocked(l) {
		sp, holder := st.rescue.sp, st.rescue.holder == l
		for sp.n > 0 {
			k := s.addDataLocked(l, b, sp.off, sp.n, true, &sent)
			if k == 0 {
				break
			}
			sp.off, sp.n = sp.off+k, sp.n-k
			left -= int64(k)
		}
		switch {
		case sp.n > 0:
			st.rescue.sp = sp
		case holder:
			// The holder's own duplicate went out: keep its record (not
			// set), so the actor can have another data lane, once one
			// exists, rescue the head once more: the holder may be stuck
			// itself (rescueLocked, L34).
			st.rescue = rescueSlot{holder: l}
		default:
			st.rescue = rescueSlot{}
		}
		if hk := rescueSendHook.Load(); hk != nil && hk.s == s && sent {
			hk.fn(l, holder)
		}
	}
	for left > 0 && !st.retx.empty() {
		sp := st.retx.s[0]
		k := s.addDataLocked(l, b, sp.off, sp.n, true, &sent)
		if k == 0 {
			break
		}
		st.retx.takeFront(k)
		left -= int64(k)
	}
	for left > 0 {
		lim := min(st.end, st.peerLimit)
		if st.sNext >= lim {
			break
		}
		k := s.addDataLocked(l, b, st.sNext, lim-st.sNext, false, &sent)
		if k == 0 {
			break
		}
		st.sNext += k
		left -= int64(k)
	}
	if s.p.Mode == ModeBond && sent && !st.interleaved && s.otherDataLaneLocked(l) {
		st.interleaved = true
	}
	if left <= 0 && (s.pullableLocked() > 0 || (st.rescue.set && s.rescueSenderLocked(l))) {
		b.MarkCapBlocked()
	}
}

// addDataLocked appends one DATA frame for up to n bytes at off — cut at
// the chunk boundary (one frame references one chunk) and at the segment
// size — and records it in l.infl. A segment is never cut to fill a
// partly used batch: it waits for the next one; only a batch budget below
// one segment cuts the round's first frame to fit. It returns the bytes
// appended (0: stop).
func (s *Session) addDataLocked(l *lane, b *carrier.Batch, off, n uint64, retx bool, sent *bool) uint64 {
	st := &s.st
	n = min(n, st.chunkEnd(off)-off, s.segment())
	if room := uint64(max(b.Room(), 0)); n > room {
		if *sent || room == 0 {
			return 0
		}
		n = room
	}
	chunk, pos := st.chunkFor(off)
	if !b.AddData(wire.SessionHandle, off, chunk.B[pos:pos+int(n)], chunk, retx) {
		return 0
	}
	*sent = true
	l.infl.add(off, n)
	if retx {
		st.retxBytes += n
	}
	return n
}
