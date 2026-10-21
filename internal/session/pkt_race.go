package session

import (
	"math"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// The packet race (M3 design §A6.4; M3-D32, L39, L40). Every race data lane
// places every datagram of the one tx ring from its own cursor lane.rpos
// (an absolute ring position: pring.pos is the head's). A datagram's seq is
// assigned at its first placement, dense from FirstSeq (M2-D34), and its
// copies reuse it (pring.seq), so the receiver's SeqWindow delivers each
// datagram once and counts the copies as Duplicates. A datagram's
// placements are counted in its cell (pkt_unsent.go): Sent counts the
// datagrams with a placement that may have left, Race.Copies the other
// such placements, and a dying carrier's hand-back lowers the count. The
// head advances past a descriptor once every live race data lane's cursor
// is beyond it, or when it ages out or is evicted; a descriptor leaves the
// queue counted as a drop only if no placement of it may have left (never
// placed, or every placement handed back), except that the head moves one
// whose every placement came back to the redo list while a live lane can
// carry it. txBig is unused: each lane filters by its own budget.
// Everything here runs with s.mu held and allocates nothing after the
// session's first race Fill (the seq and cell arrays, then only the rare
// ring doubling and a high-water mark of the cell pool).

// raceInit allocates the seq and cell arrays of a race session's tx ring
// (its first Fill; every descriptor queued before was never placed).
func (q *pring) raceInit() {
	if q.seq == nil {
		q.seq = make([]uint64, len(q.desc))
		q.cell = make([]int32, len(q.desc))
	}
}

// raceIdx returns the ring index of absolute position p (q.pos ≤ p <
// q.pos + q.n).
func (q *pring) raceIdx(p uint64) int {
	return (q.head + int(p-q.pos)) & (len(q.desc) - 1)
}

// raceHeadLocked advances the tx head (M3-D32): past every descriptor all
// live race data lanes passed, and past every head older than MaxAge. A
// popped descriptor a placement of which may have left was sent. One no
// placement of which may have left is counted once: DropAge (or DropNoPath
// when queued before the latest no-path episode ended) when it aged, else
// DropTooLarge — no live lane can carry it (M3 design §A6.4) — except that
// a datagram whose every placement a dying carrier handed back joins the
// redo list while a live lane can carry it (pktCarriableLocked): its
// placing members may still be live, their death steps not run yet (a
// writer may hand back before the actor reaps its lane; pkt_unsent.go),
// and a member that joins later places it again. It reports whether it
// moved one there. Without a live data lane it does nothing: the actor's
// no-path step ages the queue (pktAgeLocked). O(lanes) plus the
// descriptors popped.
func (s *Session) raceHeadLocked(nowNs int64) (moved bool) {
	pk := s.pk
	q := &pk.tx
	lo, live := q.pos+uint64(q.n), false
	for _, l := range s.st.order {
		if l.data && l.state != LaneDead {
			live = true
			lo = min(lo, max(l.rpos, q.pos))
		}
	}
	if !live {
		return false
	}
	maxAge := int64(s.pktMaxAge())
	noPathEnd := pk.noPathEnd.Sub(pk.base).Nanoseconds()
	for q.n > 0 {
		d := q.front()
		aged := pk.ageOn && nowNs-d.at > maxAge // nothing ages before a lane could place (pktAgeStartLocked)
		if q.pos >= lo && !aged {
			break
		}
		at := d.at
		switch {
		case q.headPlaced():
			q.pop().ext.Release() // a placement of it may have left: it was sent
			continue
		case !aged && q.seq != nil && q.seq[q.head] != 0 && s.pktCarriableLocked(int(d.n)):
			moved = s.raceRedoHeadLocked() || moved
			continue
		}
		q.pop().ext.Release()
		switch {
		case !aged:
			pk.ctr.DropTooLarge++
		case at < noPathEnd:
			pk.ctr.DropNoPath++
		default:
			pk.ctr.DropAge++
		}
	}
	return moved
}

// raceRedoHeadLocked moves the tx head, a race datagram every placement of
// which a dying carrier handed back, to the redo list with its bytes, its
// enqueue time, its wide mark and a reference on its cell, or counts it
// DropQueue (pktRedoLocked); it reports whether it joined the list. A
// race Fill runs the head step before placeRedoLocked, and lanes and
// cursors do not change under s.mu, so the head step inside that loop's
// routing call (pktOtherCarrierLocked) has nothing to move: the redo head
// placeRedoLocked decides on stays its head.
func (s *Session) raceRedoHeadLocked() bool {
	q := &s.pk.tx
	d := q.front()
	r := predo{seq: q.seq[q.head] - 1, at: d.at, cell: q.cell[q.head], wide: d.wide}
	q.cellRef(r.cell) // the redo entry's; the pop drops the descriptor's
	r.body, r.buf = q.popRef()
	return s.pktRedoLocked(r)
}

// raceFillDgramsLocked is fillDgramLocked on a race data lane (M3-D32): from
// the lane's cursor forward it skips a descriptor older than MaxAge (a slow
// lane never sends stale copies, L40) and, on a datagram lane, one larger
// than its budget (another lane may carry it, L37); it places the rest —
// the seq assigned at the first placement, a copy reusing it (Race.Copies)
// — until the batch is full or, on a stream lane, its capacity share
// (Capacity − Inflight − Taken, M3-D11) is used. The returned DGRAMs whose
// descriptor left the ring go first (placeRedoLocked). It reports whether a
// DGRAM was placed. Sent counts each datagram once while a placement of it
// may have left (unique, M3-D35; pktPlacedLocked).
func (s *Session) raceFillDgramsLocked(l *lane, b *carrier.Batch) (placed bool) {
	st, pk := &s.st, s.pk
	q := &pk.tx
	q.raceInit()
	nowNs := b.Now().Sub(pk.base).Nanoseconds()
	maxAge := int64(s.pktMaxAge())
	s.raceHeadLocked(nowNs)
	dg := b.Datagram()
	left := int64(math.MaxInt64)
	if !dg {
		left = l.port.Capacity() - l.port.Inflight() - int64(b.Taken())
	}
	if p, stop := s.placeRedoLocked(l, b, dg, &left); stop {
		return p
	} else if p {
		placed = true
	}
	limit := s.offsetLimit()
	p := max(l.rpos, q.pos)
	for tail := q.pos + uint64(q.n); p < tail; p++ {
		i := q.raceIdx(p)
		d := &q.desc[i]
		n := int(d.n)
		if nowNs-d.at > maxAge {
			// Defensive: raceHeadLocked above already popped every aged
			// head, and the descriptors behind one are younger (queued in
			// time order), so no stale descriptor is reached here today.
			// MaxAge's rule is the head's (TestRacePacketSkipStale_L40).
			continue
		}
		if n > b.DgramRoom() {
			if dg {
				continue // too large for this lane's budget: another lane may carry it
			}
			break // a stream batch is full: the writer self-continues
		}
		if int64(n) > left {
			b.MarkCapBlocked() // the PONG that frees capacity wakes the writer
			l.capMarked = true
			break
		}
		seq := q.seq[i]
		if seq == 0 && pk.nextSeq >= limit {
			st.exhausted = true // L14: the actor ends with one RST(Exhausted)
			st.facts |= factExhausted
			s.ringActor()
			break
		}
		first := seq == 0
		if first {
			seq = pk.nextSeq + 1
		}
		body, buf := q.data(d)
		if !b.AddDgram(l.Handle(), seq-1, body, buf) {
			break // the batch is full: the writer self-continues
		}
		if first {
			q.seq[i] = seq
			q.cellNew(i)
			pk.nextSeq++
		}
		s.pktPlacedLocked(l, dg, seq-1, d.at, d.wide, q.cell[i])
		left -= int64(n)
		placed = true
	}
	l.rpos = p
	if s.raceHeadLocked(nowNs) { // this lane's cursor moved: the head may follow
		// A datagram this lane skipped joined the redo list for a member
		// that can carry it (raceHeadLocked): wake the members.
		s.raceWakeDataLocked()
	}
	return placed
}

// raceDgramDueLocked reports whether race data lane l has something to
// place now: a queued datagram beyond its cursor, or our FIN.
func (s *Session) raceDgramDueLocked(l *lane) bool {
	q := &s.pk.tx
	return s.pk.redoN() > 0 || max(l.rpos, q.pos) < q.pos+uint64(q.n) || s.racePktFinDueLocked(l, time.Since(s.pk.base).Nanoseconds())
}

// racePktFinDueLocked is the packet FIN rule of a race data lane (M3-D30,
// M3-D32): each member places our FIN once, after its cursor reached the
// queue's end, no returned DGRAM waits (they leave first, as the queued
// ones do: L40, pkt_unsent.go) and no queued datagram that may still be
// placed lacks its seq or had every placement handed back. A datagram this
// lane skipped as too large may still get the next seq on another lane,
// and the FIN's final seq must cover it; one whose every placement a dying
// carrier returned never left, and a member behind it places it, then our
// FIN. An aged one never will (every lane skips it, the head drops it);
// the age clause decides where no head step ran first — a control pass
// (R1-1 rule 5) and the wake policy (raceDgramDueLocked).
func (s *Session) racePktFinDueLocked(l *lane, nowNs int64) bool {
	st, pk := &s.st, s.pk
	q := &pk.tx
	if !st.fin.requested || st.fin.acked || l.finHere || pk.txBig.n > 0 || pk.redoN() > 0 || max(l.rpos, q.pos) < q.pos+uint64(q.n) {
		return false
	}
	if q.seq == nil {
		return true
	}
	maxAge := int64(s.pktMaxAge())
	for p := q.pos; p < q.pos+uint64(q.n); p++ {
		i := q.raceIdx(p)
		if (q.seq[i] == 0 || q.cellAt(q.cell[i]).pc == 0) && nowNs-q.desc[i].at <= maxAge {
			return false
		}
	}
	return true
}
