package session

import (
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// Datagrams a dying carrier never wrote (M5 pktloss; L39: only data in
// flight on a dead carrier may be lost, and counted). A datagram carrier
// whose round ends it — a fatal write error, or its death record found
// before a write — hands back the DGRAMs it placed and did not write
// (carrier.DgramReturner). Such a datagram is not in flight: rendr knows
// it never left.
//
// The placement record. A datagram lane keeps its last MaxBatchFrames DGRAM
// placements (pplace: the seq, the enqueue time, the wide mark and, in
// race, the datagram's placement count). A carrier round holds at most
// MaxBatchFrames frames, so every DGRAM a dying carrier hands back is
// found there: it keeps its enqueue time — MaxAge counts from WriteTo
// (plan:286, M2-D35), also after a hand-back — and its wide mark
// (W4-REL-5). A seq the record does not hold (a test calling Unsent
// directly) ages from the hand-back and is not wide.
//
// Selector and bond: the datagram leaves Sent and joins the redo list
// (ordered by enqueue time); the next live data lane that fills places it
// again, seq unchanged, before the datagrams queued behind it. Or it is
// counted where the queue would count it: DropAge or DropNoPath once it is
// older than MaxAge since its WriteTo (DropNoPath when it was queued before
// the latest no-path episode ended, or ages while no data lane exists),
// DropTooLarge when no live lane can carry it (M2-D45; a wide one waits
// for a member that can carry it at all), DropQueue when the redo list is
// full, the session ended or the peer's FIN arrived (PA-6: nothing queued
// is worth sending). Sent counts it again at the re-placement, so Sent −
// PeerReceived covers only the datagrams a transport accepted, and the
// send-side identity holds.
//
// Race: a datagram's placements are counted in its cell (pcell, taken at
// its first placement): pc, the placements not handed back. A placement
// counts Sent when pc was 0 and Race.Copies otherwise; a hand-back lowers
// pc. While pc stays above 0, another placement left or is in a round that
// may still hand it back, and the returned copy only leaves Race.Copies.
// At 0 the datagram leaves Sent: while its descriptor is queued the ring
// keeps it (a member whose cursor has not passed it places it again, or
// the head counts it as never placed); otherwise it joins the redo list as
// above. So Sent counts the datagrams with a placement that may have left
// and Race.Copies the other such placements: exact for hand-backs (the
// carriers' refusals stay attributed by raceRefused, an upper bound). A
// dead lane's record keeps its cells for the maxDying latest deaths, since
// the last round of its carrier may still come back.
//
// At-most-once holds: a returned datagram never left, and its seq is still
// delivered once by the receiver's dedup window if a transport lied. The
// FIN waits for the redo list as for the queue (L40; M2 design §A5.6).

// maxRedo bounds the redo list: a dying carrier returns at most one
// round's DGRAMs (≤ MaxBatchFrames), and a few carriers may die together.
const maxRedo = 4 * carrier.MaxBatchFrames

// redoMin is the redo ring's first length; a full ring doubles, up to
// maxRedo (both powers of two), so the list's storage never exceeds maxRedo
// entries (invariant 4).
const redoMin = 16

// recLen is the length of a datagram lane's placement record: one carrier
// round's frames at most.
const recLen uint64 = carrier.MaxBatchFrames

// maxDying bounds the dead datagram lanes of a race session whose
// placement records keep their cells (a hand-back follows its carrier's
// death record within the carrier's last round): the most carriers a
// session may hold, MaxCarriersPerSession's largest value, can die
// together and still be counted exactly.
const maxDying = 16

// predo is one returned DGRAM waiting in the redo list: its seq, its bytes
// with the reference that holds them, its enqueue time (ns since the
// session's base), its wide mark and, in race, a reference on its cell.
type predo struct {
	seq  uint64
	body []byte
	buf  *carrier.Buf
	at   int64
	cell int32
	wide bool
}

// release drops r's references: its bytes and its cell.
func (r predo) release(q *pring) {
	r.buf.Release()
	q.cellUnref(r.cell)
}

// pplace is one DGRAM placement in a datagram lane's placement record.
type pplace struct {
	seq  uint64
	at   int64 // the datagram's enqueue time, ns since the session's base
	cell int32 // race: a reference on its cell (0: none)
	wide bool
}

// pcell is a race datagram's placement count, in the tx ring's cell pool
// (pring.cells; a cell number is its index + 1): pc counts its placements
// that were not handed back, refs who may still read it — its descriptor
// while queued (queued), each placement-record entry and a redo entry. The
// last reference frees it.
type pcell struct {
	pc, refs uint32
	queued   bool
}

// cellNew gives the descriptor at ring index i a fresh cell (pc 0),
// referenced by the descriptor while it is queued. The pool grows only when
// the live cells' high-water mark rises; at most the placed descriptors,
// recLen per placement record (live data lanes and maxDying dead ones)
// and maxRedo redo entries hold cells.
func (q *pring) cellNew(i int) {
	var c int32
	if n := len(q.cfree); n > 0 {
		c, q.cfree = q.cfree[n-1], q.cfree[:n-1]
	} else {
		q.cells = append(q.cells, pcell{})
		c = int32(len(q.cells))
	}
	q.cells[c-1] = pcell{refs: 1, queued: true}
	q.cell[i] = c
}

// cellAt returns cell c (c > 0).
func (q *pring) cellAt(c int32) *pcell { return &q.cells[c-1] }

// cellRef takes a reference on cell c (0: none).
func (q *pring) cellRef(c int32) {
	if c != 0 {
		q.cells[c-1].refs++
	}
}

// cellUnref drops a reference on cell c (0: none); the last frees it.
func (q *pring) cellUnref(c int32) {
	if c == 0 {
		return
	}
	p := &q.cells[c-1]
	p.refs--
	if p.refs == 0 {
		q.cfree = append(q.cfree, c)
	}
}

// record adds a DGRAM placement to l's placement record (allocated at the
// lane's first: recLen entries of 24 bytes), with a reference on its cell.
// The entry it overwrites is recLen placements old: a round holds at most
// recLen frames, so that entry's round has settled and nothing hands it
// back any more.
func (l *lane) record(q *pring, seq uint64, at int64, wide bool, cell int32) {
	if l.rec == nil {
		l.rec = make([]pplace, recLen)
	}
	e := &l.rec[l.recN%recLen]
	q.cellUnref(e.cell)
	q.cellRef(cell)
	*e = pplace{seq: seq, at: at, cell: cell, wide: wide}
	l.recN++
}

// recFind returns l's record entry of the DGRAM of seq seq, newest first
// (nil: none — never recorded, or overwritten).
func (l *lane) recFind(seq uint64) *pplace {
	for k := range min(l.recN, recLen) {
		if e := &l.rec[(l.recN-1-k)%recLen]; e.seq == seq {
			return e
		}
	}
	return nil
}

// recRelease drops the cell references of placement record rec; its
// entries keep their seq, enqueue time and wide mark.
func recRelease(q *pring, rec []pplace) {
	for i := range rec {
		q.cellUnref(rec[i].cell)
		rec[i].cell = 0
	}
}

// pktPlacedLocked counts the DGRAM of seq seq (enqueued at at; wide) that
// lane l just placed and, on a datagram batch (dg), records it there:
// Sent, or with a race cell Sent when no placement of the datagram may
// have left yet (pc 0) and Race.Copies otherwise (M3-D35).
func (s *Session) pktPlacedLocked(l *lane, dg bool, seq uint64, at int64, wide bool, cell int32) {
	pk := s.pk
	if cell == 0 {
		pk.ctr.Sent++
	} else {
		c := pk.tx.cellAt(cell)
		if c.pc == 0 {
			pk.ctr.Sent++
		} else {
			pk.copies++
		}
		c.pc++
	}
	if dg {
		l.record(&pk.tx, seq, at, wide, cell)
	}
}

// Unsent implements carrier.DgramReturner.
func (p *plane) Unsent(c *carrier.Conn, seq uint64, d []byte, buf *carrier.Buf) {
	l := (*lane)(p)
	s := l.s
	s.mu.Lock()
	s.pktUnsentLocked(l, seq, d, buf)
	s.mu.Unlock()
	s.ringActor() // without a data lane the actor ages it (pktAgeOutLocked)
}

// pktUnsentLocked takes back the DGRAM of seq seq that lane l's carrier
// placed and never wrote (buf's reference moves here).
func (s *Session) pktUnsentLocked(l *lane, seq uint64, d []byte, buf *carrier.Buf) {
	pk, st := s.pk, &s.st
	r := predo{seq: seq, body: d, buf: buf, at: time.Since(pk.base).Nanoseconds()}
	if e := l.recFind(seq); e != nil {
		r.at, r.wide, r.cell = e.at, e.wide, e.cell
		e.cell = 0 // its reference moves to r
	}
	queued := false
	if r.cell != 0 {
		c := pk.tx.cellAt(r.cell)
		c.pc--
		if c.pc > 0 {
			// Another placement left, or is in a round that may hand it
			// back too: one placement fewer left (Race.Copies), and the
			// datagram stays counted once in Sent.
			if pk.copies > 0 {
				pk.copies--
			}
			r.release(&pk.tx)
			return
		}
		queued = c.queued
	}
	if pk.ctr.Sent > 0 {
		pk.ctr.Sent-- // no placement of it left: counted again when it is placed again
	}
	switch {
	case queued:
		// Its descriptor is still queued: the ring keeps it. A member
		// whose cursor has not passed it places it again, or the head
		// counts it as never placed.
		r.release(&pk.tx)
	case st.ended || st.peerFinSet || pk.redoN() >= maxRedo:
		r.release(&pk.tx)
		pk.ctr.DropQueue++
		return
	default:
		pk.redoPush(r)
	}
	s.pktWakeLocked(time.Now())
}

// pktLaneGoneLocked is the packet part of the death step of lane l
// (laneGoneLocked). In race, a datagram lane's placement record keeps its
// cells while its carrier may still hand back DGRAMs of its last round:
// the records of the maxDying latest such deaths keep them (the record
// only, not the lane or its carrier), an older one's are dropped (a
// hand-back even later then counts as one of a datagram placed once).
func (s *Session) pktLaneGoneLocked(l *lane) {
	pk := s.pk
	if l.rec == nil || pk.tx.cells == nil {
		return
	}
	if len(pk.dying) == maxDying {
		recRelease(&pk.tx, pk.dying[0])
		copy(pk.dying, pk.dying[1:])
		pk.dying = pk.dying[:maxDying-1]
	}
	pk.dying = append(pk.dying, l.rec)
}

// redoN returns the returned DGRAMs waiting for a lane.
func (pk *packet) redoN() int { return pk.redoLen }

// redoAt returns the k-th waiting returned DGRAM, oldest first (k < redoN).
func (pk *packet) redoAt(k int) *predo {
	return &pk.redo[(pk.redoHead+k)&(len(pk.redo)-1)]
}

// redoPush adds r to the redo list (redoN < maxRedo) in enqueue-time order,
// so its head is the oldest, as the queue's (MaxAge is checked at the head:
// hand-backs from several carriers interleave). A full ring doubles.
func (pk *packet) redoPush(r predo) {
	if pk.redoLen == len(pk.redo) {
		d := make([]predo, max(redoMin, 2*len(pk.redo)))
		for k := range pk.redoLen {
			d[k] = *pk.redoAt(k)
		}
		pk.redo, pk.redoHead = d, 0
	}
	k := pk.redoLen
	for ; k > 0 && pk.redoAt(k-1).at > r.at; k-- {
		*pk.redoAt(k) = *pk.redoAt(k - 1)
	}
	*pk.redoAt(k) = r
	pk.redoLen++
}

// redoPop removes the oldest waiting returned DGRAM and returns it; its
// references move to the caller.
func (pk *packet) redoPop() predo {
	e := pk.redoAt(0)
	r := *e
	*e = predo{}
	pk.redoHead = (pk.redoHead + 1) & (len(pk.redo) - 1)
	pk.redoLen--
	return r
}

// placeRedoLocked places the returned DGRAMs on data lane l first (they are
// older than every queued datagram) with the queue's rules
// (placeDgramsLocked): aged out after MaxAge since WriteTo (DropNoPath when
// queued before the latest no-path episode ended, else DropAge), too large
// for a datagram batch's DgramRoom (left to another live lane that can
// place it now, or for a wide one that can carry it at all, else
// DropTooLarge), beyond a stream lane's capacity left (the batch is marked
// cap-blocked). It reports whether it placed one and whether l's Fill must
// stop (a full batch, the capacity, or another lane takes the head).
func (s *Session) placeRedoLocked(l *lane, b *carrier.Batch, dg bool, left *int64) (placed, stop bool) {
	pk := s.pk
	if pk.redoN() == 0 {
		return false, false
	}
	nowNs := b.Now().Sub(pk.base).Nanoseconds()
	maxAge := int64(s.pktMaxAge())
	noPathEnd := pk.noPathEnd.Sub(pk.base).Nanoseconds()
	for pk.redoN() > 0 {
		r := pk.redoAt(0)
		n := len(r.body)
		if nowNs-r.at > maxAge {
			at := r.at
			pk.redoPop().release(&pk.tx)
			if at < noPathEnd {
				pk.ctr.DropNoPath++
			} else {
				pk.ctr.DropAge++
			}
			continue
		}
		if dg && n > b.DgramRoom() {
			if s.pktOtherCarrierLocked(l, n, r.wide) {
				return placed, true
			}
			pk.redoPop().release(&pk.tx)
			pk.ctr.DropTooLarge++
			continue
		}
		if int64(n) > *left {
			b.MarkCapBlocked()
			l.capMarked = true
			return placed, true
		}
		if !b.AddDgram(l.Handle(), r.seq, r.body, r.buf) {
			return placed, true // the batch is full: the writer self-continues
		}
		e := pk.redoPop()
		s.pktPlacedLocked(l, dg, e.seq, e.at, e.wide, e.cell)
		e.release(&pk.tx) // the batch holds its own reference, the record its own on the cell
		*left -= int64(n)
		placed = true
	}
	return placed, false
}

// pktRedoAgeLocked is the actor's no-path ageing of the redo list
// (pktAgeOutLocked): heads older than MaxAge since their WriteTo are
// dropped as DropNoPath (no data lane exists); it returns when the next one
// ages out (zero: none).
func (s *Session) pktRedoAgeLocked(nowNs int64) time.Time {
	pk := s.pk
	maxAge := s.pktMaxAge()
	for pk.redoN() > 0 {
		at := pk.redoAt(0).at
		if nowNs-at <= int64(maxAge) {
			return pk.base.Add(time.Duration(at) + maxAge + 1)
		}
		pk.redoPop().release(&pk.tx)
		pk.ctr.DropNoPath++
	}
	return time.Time{}
}

// pktRedoReleaseLocked drops the redo list at the session's end or at the
// peer's FIN (nothing queued is worth sending): DropQueue each.
func (s *Session) pktRedoReleaseLocked() {
	pk := s.pk
	for pk.redoN() > 0 {
		pk.redoPop().release(&pk.tx)
		pk.ctr.DropQueue++
	}
}

// pktRedoBytes returns the bytes of the returned DGRAMs waiting for a lane.
func (pk *packet) pktRedoBytes() int64 {
	var n int64
	for k := range pk.redoN() {
		n += int64(len(pk.redoAt(k).body))
	}
	return n
}

// pktTxHeadLocked returns the size of the next datagram the tx side places
// (a returned DGRAM first, else tx's head; −1 when neither waits).
func (s *Session) pktTxHeadLocked() int {
	pk := s.pk
	if pk.redoN() > 0 {
		return len(pk.redoAt(0).body)
	}
	if pk.tx.n > 0 {
		return int(pk.tx.front().n)
	}
	return -1
}
