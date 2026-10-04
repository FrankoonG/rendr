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
// non-overlapping), their class capacity bounded by 2·W (D13). Bytes that
// overlap held bytes are compared once; a mismatch is a violation that
// kills only the delivering carrier, and the first copy stays authoritative
// (L13).
//
// A referenced frame that overlaps held bytes is placed in pieces. A piece
// below 16 KiB is copied into a run, as a small payload would be, rather
// than pinning the frame's whole buffer for a few bytes — but only while
// the bytes copied by this Data call stay below 16 KiB (copyBudget), so no
// call copies 16 KiB or more under the lock (§3.2, P17); later small pieces
// of that frame are kept by reference. Such a reference pins at most one
// buffer per frame that contributed at least 16 KiB of new bytes in that
// call (for 64 KiB segments, a buffer at most 4× those bytes).

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
	budget := copyBudget
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
		return nil
	}
	if st.discard {
		if s.consumeAllLocked() > 0 {
			st.discardedAfterClose = true
			st.facts |= factDiscardedAfterClose
			s.ringActor()
		}
		return nil
	}
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
// payload is valid only during the call and below 16 KiB: always copied.
func keepByRef(piece []byte, buf *carrier.Buf, budget *int) bool {
	if buf != nil && (len(piece) >= runSize || len(piece) > *budget) {
		return true
	}
	*budget -= len(piece)
	return false
}

// appendInOrderLocked appends piece at pos == rTail to inq — by reference
// or copied into the tail run or new runs (keepByRef) — then moves every
// out-of-order segment that became contiguous into inq. It returns the
// reference still unused (see dataLocked).
func (s *Session) appendInOrderLocked(pos uint64, piece []byte, buf, ref *carrier.Buf, budget *int) *carrier.Buf {
	st := &s.st
	if keepByRef(piece, buf, budget) {
		ref = takeRef(buf, ref)
		st.inq.push(seg{off: pos, b: piece, buf: buf})
	} else {
		for q := piece; len(q) > 0; {
			if st.inq.n > 0 {
				if t := st.inq.back(); t.run && len(t.b) < runSize && t.end() == pos {
					m := copy(t.buf.B[len(t.b):runSize], q)
					t.b = t.buf.B[:len(t.b)+m]
					q, pos = q[m:], pos+uint64(m)
					continue
				}
			}
			rb := s.env.Carrier.Bufs.Get(runSize, s.env.Carrier.Budget)
			m := copy(rb.B[:runSize], q)
			st.inq.push(seg{off: pos, b: rb.B[:m], buf: rb, run: true})
			q, pos = q[m:], pos+uint64(m)
		}
	}
	st.rTail += uint64(len(piece))
	st.rxBytes += uint64(len(piece))
	k := 0
	for k < len(st.ooq.s) && st.ooq.s[k].off == st.rTail {
		sg := &st.ooq.s[k]
		st.oooCap -= segCap(sg)
		st.inq.push(*sg)
		st.rTail = sg.end()
		st.rxBytes += uint64(len(sg.b))
		k++
	}
	if k > 0 {
		st.ooq.removeFront(k)
	}
	return ref
}

// insertOOOLocked inserts piece at pos (> rTail) before out-of-order
// segment i, within the 2·W capacity cap: by reference (keepByRef), or
// appended to the run that ends exactly at pos (if it has room) and
// otherwise copied into a new run. Bytes beyond the cap are dropped and
// counted (D13: never a violation; the sender still holds them). It
// returns the reference still unused.
func (s *Session) insertOOOLocked(i int, pos uint64, piece []byte, buf, ref *carrier.Buf, budget *int) *carrier.Buf {
	st := &s.st
	limit := 2 * s.window()
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
				m := copy(t.buf.B[len(t.b):runSize], q)
				t.b = t.buf.B[:len(t.b)+m]
				q, pos = q[m:], pos+uint64(m)
				continue
			}
		}
		if st.oooCap+runCap > limit {
			st.oooDropped += uint64(len(q))
			break
		}
		rb := s.env.Carrier.Bufs.Get(runSize, s.env.Carrier.Budget)
		m := copy(rb.B[:runSize], q)
		st.ooq.insert(i, seg{off: pos, b: rb.B[:m], buf: rb, run: true})
		st.oooCap += segCap(&st.ooq.s[i])
		q, pos, i = q[m:], pos+uint64(m), i+1
	}
	return ref
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
		sg.buf.Release()
	}
}

// releaseOOO releases every out-of-order segment.
func (st *stream) releaseOOO() {
	for i := range st.ooq.s {
		st.ooq.s[i].buf.Release()
	}
	st.ooq.removeFront(len(st.ooq.s))
	st.oooCap = 0
}

// releaseRecv releases every received buffer (session end) and makes the
// unread bytes unreadable: after a non-local end the next Read returns the
// end error, not stale data (§4.5).
func (st *stream) releaseRecv() {
	for st.inq.n > 0 {
		sg := st.inq.popFront()
		sg.buf.Release()
	}
	st.releaseOOO()
	st.rTail = st.rRead
}
