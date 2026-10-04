package session

import (
	"sync/atomic"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// The receive path (design §4.4, §0.8 V3). Every DATA frame arrives whole
// and CRC-verified: a payload of at least 16 KiB in a reader-owned Buf whose
// reference moves to the stream, a smaller one as a slice valid only during
// the call. inq holds the in-order segments covering [rRead, rTail); ooq the
// out-of-order ones beyond rTail (ascending, non-overlapping; neighbours may
// touch). Bytes that overlap held bytes are compared once; a mismatch is a
// violation that kills only the delivering carrier, and the first copy stays
// authoritative (L13).
//
// Segments. A segment is a run — a 16 KiB-class buffer into which the
// stream copies small payloads, from the buffer's first byte — or a
// reference to one received frame's buffer. No two segments share a buffer,
// so the receive charge below is exact. Every segment may grow at its end
// into the rest of its buffer: a run up to 16 KiB, a reference up to the
// buffer's capacity (the reader hands the whole buffer over and touches it
// no more, and no other segment uses it).
//
// Copy limit (§3.2, P17). One Data call copies fewer than 16 KiB under the
// lock, its own new bytes and the merges below together (rcall). A payload
// without a Buf is below 16 KiB and always copied. A frame with a Buf is
// kept by reference when its new bytes (those no segment holds yet) reach
// the limit, or when that costs no more than copying them: the held
// segments it would replace charge at least its buffer and it would hold at
// least half of that buffer (heldRange.byRef). Otherwise its new bytes are
// copied and its buffer released at once. A frame kept by reference is one
// segment, from its first new byte, that replaces every held segment it
// covers (they hold the same bytes, which were compared): it holds at least
// 16 KiB of its frame or at least half its buffer, and pins no other buffer.
//
// Merging. Copied bytes first go into the room of the segment that ends
// where they begin; a new run is taken when there is none. When a placement
// closes a gap, the segments that now follow it contiguously are merged into
// it — copied, their buffers released — while they fit its room and the
// call's copy limit allows: in ooq as out-of-order data arrives, so
// out-of-order runs stay dense in any arrival order, and on promotion, when
// segments become contiguous with rTail and move to inq. A segment that does
// not fit moves as it is, and the next ones can merge into it.
//
// Receive charge (D13, V3). st.oooCap is the size-class capacity held by inq
// and ooq together: exactly the Budget charge of the session's receive
// buffers. Out-of-order data takes a new buffer only while the charge stays
// within recvLimit, 2·W; bytes that would need more are dropped and counted
// in oooDropped (never a violation). In-order data inside the advertised
// window is always taken; when it pushes the charge above 2·W, out-of-order
// segments are shed, highest first and counted the same way (shedLocked).
// So between Data calls the charge is at most 2·W whenever out-of-order data
// is held; a session's Budget footprint adds its carriers' reader stages,
// one run per lane (D29). With nothing held out of order the charge is the
// in-order queue's alone, which nothing can shed: the window bounds its
// bytes, and dense runs, references holding whole frames (class rounding
// stays below 2×) and the room a reference offers to the bytes after it keep
// the charge within about 2× those bytes — except a frame kept by reference
// for at least 16 KiB of new bytes while other segments held the rest of it
// (up to 4× for the 64 KiB frames rendr senders produce, more for larger
// frames).
//
// Recovery. Dropped and shed bytes are not lost to the stream: the sender
// still holds them unacknowledged. They return only when another carrier
// retransmits them — a bond rescue sent on a lane other than the one whose
// spans hold them (§4.11), or the requeue and replay after that lane dies
// or loses data eligibility. While that lane is the only data lane and stays
// healthy, nothing resends them.

// recvLimit is the cap on the receive charge that out-of-order data may
// fill: 2·W (V3).
func (s *Session) recvLimit() int64 {
	return 2 * s.window()
}

// recvCopyHook is a test seam: when a test stores {s, fn}, fn runs at the
// end of every placement by one of s's Data calls, under s.mu, with the
// payload bytes that call copied (the copy limit). Production never sets it.
var recvCopyHook atomic.Pointer[recvHook]

// recvHook is the value of recvCopyHook.
type recvHook struct {
	s  *Session
	fn func(copied int)
}

// rcall is the copy state of one Data call (the copy limit, file comment).
type rcall struct {
	left   int // bytes the call may still copy: its own new bytes are reserved first, merges take the rest
	copied int // payload bytes copied (the call's own and the merged ones)
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

	// Place the bytes of [max(off, rTail), end) no segment holds yet.
	tail := st.rTail
	c := rcall{left: copyBudget}
	h := st.heldIn(max(off, st.rTail), end)
	n := h.newBytes()
	if buf != nil && n > 0 && (n > copyBudget || h.byRef(int64(cap(buf.B)))) {
		s.keepRefLocked(off, p, buf, &h, n, &c)
	} else {
		c.left -= int(n) // the frame's own new bytes are copied in any case
		s.copyPiecesLocked(off, p, &c)
		buf.Release()
	}
	if hk := recvCopyHook.Load(); hk != nil && hk.s == s {
		hk.fn(c.copied)
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
		s.shedLocked() // a Read copy in flight defers the release of inq
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

// heldRange describes the held out-of-order bytes inside a frame's range
// [start, end), start = max(off, rTail): the frame's new bytes all lie in
// [s0, x) — a segment straddling start moves s0 to its end, one straddling
// end moves x to its start — and ooq[a:b] are the segments inside [s0, x),
// holding bytes payload bytes and charge capacity.
type heldRange struct {
	s0, x  uint64
	a, b   int
	bytes  uint64
	charge int64
}

// heldIn returns the heldRange of [start, end).
func (st *stream) heldIn(start, end uint64) heldRange {
	h := heldRange{s0: start, x: end}
	l := st.ooq.s
	i := st.ooq.after(start)
	if i < len(l) && l[i].off < start {
		h.s0 = l[i].end()
		i++
	}
	h.a, h.b = i, i
	for ; h.b < len(l) && l[h.b].off < end; h.b++ {
		sg := &l[h.b]
		if sg.end() > end {
			h.x = sg.off
			break
		}
		h.bytes += uint64(len(sg.b))
		h.charge += segCap(sg)
	}
	return h
}

// newBytes returns the bytes of [s0, x) no segment holds.
func (h *heldRange) newBytes() uint64 {
	if h.s0 >= h.x {
		return 0
	}
	return h.x - h.s0 - h.bytes
}

// byRef reports whether keeping a frame whose buffer has capacity c by
// reference (over [s0, x), replacing the held segments there) is preferable
// to copying its new bytes although the copy limit would allow it: the
// replaced segments charge at least as much, and the reference holds at
// least half its buffer (copying could merge sparse held runs denser).
func (h *heldRange) byRef(c int64) bool {
	return h.charge >= c && 2*int64(h.x-h.s0) >= c
}

// keepRefLocked keeps the frame's [s0, x) by reference as one segment that
// replaces the held segments ooq[a:b] it covers; n is the frame's new bytes.
// In order it is always taken. Out of order it is taken only while the
// receive charge stays within recvLimit; otherwise its new bytes are dropped
// and counted (the held segments stay) and the buffer is released.
func (s *Session) keepRefLocked(off uint64, p []byte, buf *carrier.Buf, h *heldRange, n uint64, c *rcall) {
	st := &s.st
	sg := seg{off: h.s0, b: p[h.s0-off : h.x-off], buf: buf}
	charge := int64(cap(buf.B))
	if h.s0 == st.rTail {
		st.releaseOOORange(h.a, h.b) // a == 0: ooq starts beyond rTail
		st.inq.push(sg)
		st.oooCap += charge
		st.rxBytes += h.x - h.s0
		st.rTail = h.x
		s.promoteLocked(c)
		return
	}
	if st.oooCap-h.charge+charge > s.recvLimit() {
		st.oooDropped += n
		buf.Release()
		return
	}
	st.releaseOOORange(h.a, h.b)
	st.ooq.insert(h.a, sg)
	st.oooCap += charge
	s.mergeFollowersLocked(h.a, c)
}

// copyPiecesLocked copies every part of p (at off) that no segment holds:
// in order (appendCopyLocked) or out of order (insertCopyLocked), each piece
// running up to the next held segment.
func (s *Session) copyPiecesLocked(off uint64, p []byte, c *rcall) {
	st := &s.st
	end := off + uint64(len(p))
	for pos := off; pos < end; {
		if pos < st.rTail {
			// Held in order (compared, or just promoted from ooq after an
			// in-order piece filled the gap before it).
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
			s.appendCopyLocked(pos, piece, c)
		} else {
			s.insertCopyLocked(i, pos, piece, c)
		}
		pos = stop
	}
}

// segRoom returns the bytes sg can still grow by at its end: a run up to
// 16 KiB, a reference up to its buffer's capacity.
func segRoom(sg *seg) int {
	if sg.run {
		return runSize - len(sg.b)
	}
	return cap(sg.b) - len(sg.b)
}

// growSeg copies the head of q into t's room and returns the bytes copied.
func growSeg(t *seg, q []byte) int {
	n := len(t.b)
	m := copy(t.b[n:n+segRoom(t)], q)
	t.b = t.b[:n+m]
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

// appendCopyLocked copies piece, at pos == rTail, to the end of inq — into
// the tail segment's room, then new runs — and promotes what became
// contiguous.
func (s *Session) appendCopyLocked(pos uint64, piece []byte, c *rcall) {
	st := &s.st
	for q := piece; len(q) > 0; {
		var m int
		if st.inq.n > 0 && segRoom(st.inq.back()) > 0 {
			m = growSeg(st.inq.back(), q) // the tail ends at rTail == pos
		} else {
			var sg seg
			sg, m = s.newRunLocked(pos, q)
			st.inq.push(sg)
		}
		c.copied += m
		q, pos = q[m:], pos+uint64(m)
	}
	st.rTail += uint64(len(piece))
	st.rxBytes += uint64(len(piece))
	s.promoteLocked(c)
}

// insertCopyLocked copies piece, at pos (> rTail), into ooq before segment
// i: into the room of the segment that ends exactly at pos, then into new
// runs while the receive charge stays within recvLimit — bytes beyond it are
// dropped and counted (D13, V3: never a violation; the sender still holds
// them). If the piece closed the gap to the next segment, the segments that
// now follow contiguously are merged (mergeFollowersLocked).
func (s *Session) insertCopyLocked(i int, pos uint64, piece []byte, c *rcall) {
	st := &s.st
	for q := piece; len(q) > 0; {
		if i > 0 {
			if t := &st.ooq.s[i-1]; t.end() == pos && segRoom(t) > 0 {
				m := growSeg(t, q)
				c.copied += m
				q, pos = q[m:], pos+uint64(m)
				continue
			}
		}
		if st.oooCap+runCap > s.recvLimit() {
			st.oooDropped += uint64(len(q))
			return // a gap remains: nothing to merge
		}
		sg, m := s.newRunLocked(pos, q)
		c.copied += m
		st.ooq.insert(i, sg)
		q, pos, i = q[m:], pos+uint64(m), i+1
	}
	s.mergeFollowersLocked(i-1, c)
}

// mergeFollowersLocked merges the out-of-order segments that follow ooq[k]
// contiguously into it — copied, their buffers released — while they fit its
// room and the call's copy limit allows.
func (s *Session) mergeFollowersLocked(k int, c *rcall) {
	st := &s.st
	t := &st.ooq.s[k]
	j := k + 1
	for ; j < len(st.ooq.s); j++ {
		sg := &st.ooq.s[j]
		n := len(sg.b)
		if sg.off != t.end() || n > segRoom(t) || n > c.left {
			break
		}
		growSeg(t, sg.b)
		c.left -= n
		c.copied += n
		st.oooCap -= segCap(sg)
		sg.buf.Release()
	}
	st.ooq.cut(k+1, j)
}

// promoteLocked moves every out-of-order segment that became contiguous
// (it starts at rTail) into inq (V3). A segment that fits the room of the
// in-order tail is merged into it — copied, its buffer released — while the
// call's copy limit allows; any other one is appended as it is and becomes
// the tail the next ones can merge into. inq is not empty (an in-order
// placement precedes every promotion).
func (s *Session) promoteLocked(c *rcall) {
	st := &s.st
	k := 0
	for ; k < len(st.ooq.s) && st.ooq.s[k].off == st.rTail; k++ {
		sg := &st.ooq.s[k]
		n := len(sg.b)
		if t := st.inq.back(); n <= segRoom(t) && n <= c.left {
			growSeg(t, sg.b)
			c.left -= n
			c.copied += n
			st.oooCap -= segCap(sg)
			sg.buf.Release()
		} else {
			st.inq.push(*sg)
		}
		st.rTail += uint64(n)
		st.rxBytes += uint64(n)
	}
	st.ooq.removeFront(k)
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

// releaseOOORange releases the out-of-order segments ooq[a:b] and removes
// them.
func (st *stream) releaseOOORange(a, b int) {
	for i := a; i < b; i++ {
		sg := &st.ooq.s[i]
		st.oooCap -= segCap(sg)
		sg.buf.Release()
	}
	st.ooq.cut(a, b)
}

// releaseOOO releases every out-of-order segment.
func (st *stream) releaseOOO() {
	st.releaseOOORange(0, len(st.ooq.s))
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

// cut removes l.s[i:j] (their buffers are the caller's).
func (l *segList) cut(i, j int) {
	if i >= j {
		return
	}
	n := i + copy(l.s[i:], l.s[j:])
	clear(l.s[n:])
	l.s = l.s[:n]
}
