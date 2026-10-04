package session

import (
	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// The receive path (design §4.4). Every DATA frame arrives whole and
// CRC-verified. Payloads of at least 16 KiB come in a reader-owned Buf whose
// reference moves to the stream (kept by reference: rendr never copies bulk
// received bytes); smaller ones are copied under the lock into 16 KiB runs
// that grow at their end (P17). inq holds the in-order segments covering
// [rRead, rTail); ooq the out-of-order ones beyond rTail (ascending,
// non-overlapping). Bytes that overlap held bytes are compared once; a
// mismatch is a violation that kills only the delivering carrier, and the
// first copy stays authoritative (L13).
//
// Copy limit. One Data call copies fewer than 16 KiB under the lock (§3.2,
// P17): copyBudget covers both the frame's own small pieces and the run
// merges below. A payload without a Buf (below 16 KiB, valid only during
// the call) is copied in any case, so its length is reserved first. A
// referenced frame that overlaps held bytes is placed in pieces: a piece
// below 16 KiB is copied into a run, as a small payload would be, rather
// than pinning the frame's whole buffer for a few bytes — but only while
// the limit allows; later small pieces of that frame are kept by reference.
// Such a reference pins at most one buffer per frame that contributed at
// least 16 KiB of new bytes in that call (for 64 KiB segments, a buffer at
// most 4× those bytes).
//
// Receive charge (design §0.8 V3, D13). st.oooCap is the size-class
// capacity held by inq and ooq together, counted per segment: a buffer
// shared by several pieces of one frame counts once per piece, so the count
// never understates the Budget charge the segments cause. Out-of-order data
// may fill it only up to recvLimit, 2·W: a piece that would need more is
// dropped and counted in oooDropped (never a violation: the sender still
// holds the bytes, and its retransmission fills the hole). In-order data
// inside the advertised window is always taken; when it pushes the charge
// above 2·W, out-of-order segments are shed, highest first and counted the
// same way, until it fits again (shedLocked, at the end of the Data call).
// So between Data calls the receive charge is at most 2·W whenever
// out-of-order data is held; a session's Budget footprint adds its
// carriers' reader stages, one run per lane (D29). The charge of inq alone
// is not capped (the window bounds its bytes, and they cannot be refused):
// it exceeds 2·W only through referenced buffers larger than the bytes they
// hold (class rounding, frames that overlapped held bytes), the runs between
// such references, or promoted runs the copy limit of one call left
// unmerged.
//
// Promotion merge (V3). A segment that becomes contiguous moves from ooq to
// inq; if it fits the free room of the in-order tail run and the call's
// copy limit allows, it is copied into that run and its buffer reference
// dropped. Small frames that arrived out of order thus end up packed into
// runs as densely as in-order ones, instead of each keeping a 16 KiB run
// for its few bytes while freeing the out-of-order allowance for more of
// the same (measured at up to 164× Budget charge per buffered byte before
// V3).

// recvLimit is the cap on the receive charge that out-of-order data may
// fill: 2·W (V3).
func (s *Session) recvLimit() int64 {
	return 2 * s.window()
}

// dataLocked implements lane.Data under s.mu.
func (s *Session) dataLocked(off uint64, p []byte, buf *carrier.Buf) error {
	st := &s.st
	if st.ended {
		buf.Release()
		return nil
	}
	if s.pendingLocked() {
		buf.Release()
		return errDataBeforeOpen
	}
	end := off + uint64(len(p))
	switch {
	case len(p) == 0 || end < off:
		buf.Release()
		return errDataLength
	case end > st.rightEdge:
		buf.Release()
		return errWindow
	case st.peerFinSet && end > st.peerFin:
		buf.Release()
		return errDataBeyondFin
	}
	if off < st.rTail {
		if a, b := max(off, st.rRead), min(end, st.rTail); a < b && !st.inq.equal(a, p[a-off:b-off]) {
			buf.Release()
			return errConflict
		}
		if end <= st.rTail {
			// A duplicate of received bytes: the sender may have missed an
			// ACK; answer at once.
			buf.Release()
			s.bumpNowLocked()
			return nil
		}
	}
	if !st.ooq.equal(off, p) {
		buf.Release()
		return errConflict
	}

	// Place the parts of [max(off, rTail), end) no segment holds yet.
	ref := buf // the reference the first referencing piece takes over
	tail := st.rTail
	budget := copyBudget // bytes this call may still copy (file comment)
	if buf == nil {
		budget -= len(p) // copied in any case: p is valid only during the call
	}
	for pos := off; pos < end; {
		if pos < st.rTail {
			// Held in order (compared above, or just moved in from ooq
			// after an in-order piece filled the gap before it).
			pos = st.rTail
			continue
		}
		i := st.ooq.after(pos)
		stop := end
		if i < len(st.ooq.s) {
			sg := &st.ooq.s[i]
			if sg.off <= pos {
				pos = sg.end()
				continue
			}
			stop = min(stop, sg.off)
		}
		piece := p[pos-off : stop-off]
		if pos == st.rTail {
			ref = s.appendInOrderLocked(pos, piece, buf, ref, &budget)
		} else {
			ref = s.insertOOOLocked(i, pos, piece, buf, ref, &budget)
		}
		pos = stop
	}
	if ref != nil {
		ref.Release() // no piece kept a reference
	}
	if st.rTail == tail {
		return nil // nothing in order: out-of-order admission kept the cap
	}
	if st.discard {
		if s.consumeAllLocked() > 0 {
			st.discardedAfterClose = true
			st.facts |= factDiscardedAfterClose
			s.ringActor()
		}
		s.shedLocked()
		return nil
	}
	s.shedLocked()
	if st.rwaiting {
		streamSignal(st.rwake)
	}
	if st.ackOnData {
		st.ackOnData = false
		s.bumpNowLocked() // the first in-order DATA after an attach (L11, L19)
	}
	return nil
}

// takeRef returns the reference a piece of buf keeps: the one moved in by
// Data for the first piece (ref non-nil), a new one for later pieces.
func takeRef(buf, ref *carrier.Buf) *carrier.Buf {
	if ref == nil {
		buf.Ref()
	}
	return nil
}

// keepByRef decides whether a piece of a DATA frame is kept by reference
// (true) or copied into runs, charging a copy to budget, the bytes the
// current Data call may still copy (see the file comment). Without buf the
// payload is valid only during the call and below 16 KiB: it is always
// copied, and dataLocked reserved its bytes before placing any piece.
func keepByRef(piece []byte, buf *carrier.Buf, budget *int) bool {
	if buf == nil {
		return false
	}
	if len(piece) >= runSize || len(piece) > *budget {
		return true
	}
	*budget -= len(piece)
	return false
}

// tailRun returns the in-order tail segment if it is a run with free room
// that ends at pos, else nil.
func (st *stream) tailRun(pos uint64) *seg {
	if st.inq.n == 0 {
		return nil
	}
	if t := st.inq.back(); t.run && len(t.b) < runSize && t.end() == pos {
		return t
	}
	return nil
}

// growRun copies the head of q into the free room of run t and returns the
// number of bytes copied.
func growRun(t *seg, q []byte) int {
	m := copy(t.buf.B[len(t.b):runSize], q)
	t.b = t.buf.B[:len(t.b)+m]
	return m
}

// newRunLocked copies the head of q into a new run at off and returns it
// with the number of bytes copied. The run is charged to the Budget
// unconditionally (its bytes lie inside an advertised window) and to
// st.oooCap; callers placing out-of-order bytes check recvLimit first.
func (s *Session) newRunLocked(off uint64, q []byte) (seg, int) {
	rb := s.env.Carrier.Bufs.Get(runSize, s.env.Carrier.Budget)
	m := copy(rb.B[:runSize], q)
	s.st.oooCap += int64(cap(rb.B))
	return seg{off: off, b: rb.B[:m], buf: rb, run: true}, m
}

// appendInOrderLocked appends piece at pos == rTail to inq — by reference,
// or copied into the in-order tail run and new runs (keepByRef) — then
// promotes every out-of-order segment that became contiguous
// (promoteLocked). It returns the reference still unused (see dataLocked).
func (s *Session) appendInOrderLocked(pos uint64, piece []byte, buf, ref *carrier.Buf, budget *int) *carrier.Buf {
	st := &s.st
	if keepByRef(piece, buf, budget) {
		ref = takeRef(buf, ref)
		st.inq.push(seg{off: pos, b: piece, buf: buf})
		st.oooCap += int64(cap(buf.B))
	} else {
		for q := piece; len(q) > 0; {
			var m int
			if t := st.tailRun(pos); t != nil {
				m = growRun(t, q)
			} else {
				var sg seg
				sg, m = s.newRunLocked(pos, q)
				st.inq.push(sg)
			}
			q, pos = q[m:], pos+uint64(m)
		}
	}
	st.rTail += uint64(len(piece))
	st.rxBytes += uint64(len(piece))
	s.promoteLocked(budget)
	return ref
}

// promoteLocked moves every out-of-order segment that became contiguous
// (it starts at rTail) into inq (V3). A segment that fits the free room of
// the in-order tail run is merged into it — copied, and its buffer
// reference dropped — while budget, the bytes the current Data call may
// still copy, allows; any other segment is appended as it is and becomes
// the new tail, so the segments after it can merge into it if it is a run
// with room.
func (s *Session) promoteLocked(budget *int) {
	st := &s.st
	k := 0
	for ; k < len(st.ooq.s) && st.ooq.s[k].off == st.rTail; k++ {
		sg := &st.ooq.s[k]
		n := len(sg.b)
		if t := st.tailRun(st.rTail); t != nil && n <= runSize-len(t.b) && n <= *budget {
			growRun(t, sg.b)
			*budget -= n
			st.oooCap -= segCap(sg)
			sg.buf.Release()
		} else {
			st.inq.push(*sg)
		}
		st.rTail += uint64(n)
		st.rxBytes += uint64(n)
	}
	if k > 0 {
		st.ooq.removeFront(k)
	}
}

// insertOOOLocked inserts piece at pos (> rTail) before out-of-order
// segment i: by reference (keepByRef), or appended to the run that ends
// exactly at pos (if it has room) and otherwise copied into new runs. A new
// buffer is taken only while the receive charge stays within recvLimit;
// bytes beyond it are dropped and counted (D13, V3: never a violation; the
// sender still holds them). It returns the reference still unused.
func (s *Session) insertOOOLocked(i int, pos uint64, piece []byte, buf, ref *carrier.Buf, budget *int) *carrier.Buf {
	st := &s.st
	limit := s.recvLimit()
	if keepByRef(piece, buf, budget) {
		if c := int64(cap(buf.B)); st.oooCap+c <= limit {
			ref = takeRef(buf, ref)
			st.ooq.insert(i, seg{off: pos, b: piece, buf: buf})
			st.oooCap += c
		} else {
			st.oooDropped += uint64(len(piece))
		}
		return ref
	}
	for q := piece; len(q) > 0; {
		if i > 0 {
			if t := &st.ooq.s[i-1]; t.run && len(t.b) < runSize && t.end() == pos {
				m := growRun(t, q)
				q, pos = q[m:], pos+uint64(m)
				continue
			}
		}
		if st.oooCap+runCap > limit {
			st.oooDropped += uint64(len(q))
			break
		}
		sg, m := s.newRunLocked(pos, q)
		st.ooq.insert(i, sg)
		q, pos, i = q[m:], pos+uint64(m), i+1
	}
	return ref
}

// shedLocked restores the receive cap after in-order data took room (V3):
// while the receive charge exceeds recvLimit, the highest out-of-order
// segment is released and its bytes are counted in oooDropped. In-order
// bytes are never shed: the window admitted them, and only the application
// frees them.
func (s *Session) shedLocked() {
	st := &s.st
	limit := s.recvLimit()
	for n := len(st.ooq.s); n > 0 && st.oooCap > limit; n-- {
		sg := &st.ooq.s[n-1]
		st.oooCap -= segCap(sg)
		st.oooDropped += uint64(len(sg.b))
		sg.buf.Release()
		*sg = seg{}
		st.ooq.s = st.ooq.s[:n-1]
	}
}

// consumeAllLocked delivers every in-order byte without a reader (discard
// mode after Close, §4.7): rRead = rTail, the bytes count as delivered,
// their buffers are released (or, during a Read copy, by that Read), the
// ACK cadence runs and a FIN at the new rRead is delivered. It returns the
// bytes consumed.
func (s *Session) consumeAllLocked() uint64 {
	st := &s.st
	d := st.rTail - st.rRead
	if d == 0 {
		return 0
	}
	st.rRead = st.rTail
	st.delivered += d
	if st.rcopying {
		st.rfreePending = true
	} else {
		st.releaseConsumed()
	}
	s.ackCadenceLocked()
	s.peerFinCheckLocked()
	return d
}

// releaseConsumed releases every in-order segment wholly below rRead.
func (st *stream) releaseConsumed() {
	for st.inq.n > 0 && st.inq.s[st.inq.head].end() <= st.rRead {
		sg := st.inq.popFront()
		st.oooCap -= segCap(&sg)
		sg.buf.Release()
	}
}

// releaseOOO releases every out-of-order segment.
func (st *stream) releaseOOO() {
	for i := range st.ooq.s {
		sg := &st.ooq.s[i]
		st.oooCap -= segCap(sg)
		sg.buf.Release()
	}
	st.ooq.removeFront(len(st.ooq.s))
}

// releaseRecv releases every received buffer (session end) and makes the
// unread bytes unreadable: after a non-local end the next Read returns the
// end error, not stale data (§4.5).
func (st *stream) releaseRecv() {
	for st.inq.n > 0 {
		sg := st.inq.popFront()
		st.oooCap -= segCap(&sg)
		sg.buf.Release()
	}
	st.releaseOOO()
	st.rTail = st.rRead
}
