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
// it never left. It goes back to the session, which re-places it, seq
// unchanged, on the next live data lane that fills — before the datagrams
// queued behind it — or counts it where the queue would: DropAge or
// DropNoPath once it is older than MaxAge since the hand-back (M2-D35),
// DropTooLarge when no live lane can carry it (M2-D45), DropQueue when the
// redo list is full or the session ended. Sent leaves it at the hand-back
// and counts it again at the re-placement, so Sent − PeerReceived covers
// only the datagrams a transport accepted (and the send-side identity
// holds). At-most-once holds: the datagram never left, and its seq is
// still delivered once by the receiver's dedup window if a transport
// lied. A race datagram whose other live members carry (or will carry)
// their copies is not re-placed: one placement fewer left (Race.Copies is
// an upper bound).

// maxRedo bounds the redo list: a dying carrier returns at most one
// round's DGRAMs (≤ MaxBatchFrames), and a few carriers may die together.
const maxRedo = 4 * carrier.MaxBatchFrames

// predo is one returned DGRAM: its seq, its bytes with the reference that
// holds them, and when it was handed back (ns since the session's base).
type predo struct {
	seq  uint64
	body []byte
	buf  *carrier.Buf
	at   int64
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
	if s.p.Mode == ModeRace && s.raceCoveredLocked(l, seq) {
		buf.Release()
		if pk.copies > 0 {
			pk.copies-- // this placement never left; the datagram is counted once in Sent
		}
		return
	}
	if pk.ctr.Sent > 0 {
		pk.ctr.Sent-- // it never left: counted again when it is placed again
	}
	if st.ended || pk.redoN() >= maxRedo {
		buf.Release()
		pk.ctr.DropQueue++
		return
	}
	if pk.redoHead > 0 && pk.redoHead == len(pk.redo) {
		pk.redo, pk.redoHead = pk.redo[:0], 0
	}
	pk.redo = append(pk.redo, predo{seq: seq, body: d, buf: buf, at: time.Since(pk.base).Nanoseconds()})
	s.pktWakeLocked(time.Now())
}

// raceCoveredLocked reports whether another copy of the race datagram of
// seq seq that lane l returned will leave: a race data lane other than l
// is live (its cursor has placed, or will place, its own copy of every
// datagram l placed, M3-D32), or another dying member already returned
// its copy (it waits in the redo list).
func (s *Session) raceCoveredLocked(l *lane, seq uint64) bool {
	for _, o := range s.st.order {
		if o != l && o.data && o.state != LaneDead && !laneEnded(o) {
			return true
		}
	}
	pk := s.pk
	for _, r := range pk.redo[pk.redoHead:] {
		if r.seq == seq {
			return true
		}
	}
	return false
}

// redoN returns the returned DGRAMs waiting for a lane.
func (pk *packet) redoN() int { return len(pk.redo) - pk.redoHead }

// redoPop removes the head of the redo list and returns it; its reference
// moves to the caller.
func (pk *packet) redoPop() predo {
	r := pk.redo[pk.redoHead]
	pk.redo[pk.redoHead] = predo{}
	pk.redoHead++
	if pk.redoHead == len(pk.redo) {
		pk.redo, pk.redoHead = pk.redo[:0], 0
	}
	return r
}

// placeRedoLocked places the returned DGRAMs on data lane l first (their
// seqs are older than every queued datagram's) with the queue's rules
// (placeDgramsLocked): aged out after MaxAge (DropNoPath when handed back
// before the latest no-path episode ended, else DropAge), too large for a
// datagram batch's DgramRoom (left to another live lane that can place it
// now, else DropTooLarge), beyond a stream lane's capacity left (the batch
// is marked cap-blocked). It reports whether it placed one and whether l's
// Fill must stop (a full batch, the capacity, or another lane takes the
// head).
func (s *Session) placeRedoLocked(l *lane, b *carrier.Batch, dg bool, left *int64) (placed, stop bool) {
	pk := s.pk
	if pk.redoN() == 0 {
		return false, false
	}
	nowNs := b.Now().Sub(pk.base).Nanoseconds()
	maxAge := int64(s.pktMaxAge())
	noPathEnd := pk.noPathEnd.Sub(pk.base).Nanoseconds()
	for pk.redoN() > 0 {
		r := &pk.redo[pk.redoHead]
		n := len(r.body)
		if nowNs-r.at > maxAge {
			at := r.at
			pk.redoPop().buf.Release()
			if at < noPathEnd {
				pk.ctr.DropNoPath++
			} else {
				pk.ctr.DropAge++
			}
			continue
		}
		if dg && n > b.DgramRoom() {
			if s.pktOtherCarrierLocked(l, n, false) {
				return placed, true
			}
			pk.redoPop().buf.Release()
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
		pk.redoPop().buf.Release() // the batch holds its own reference
		pk.ctr.Sent++
		*left -= int64(n)
		placed = true
	}
	return placed, false
}

// pktRedoAgeLocked is the actor's no-path ageing of the redo list
// (pktAgeOutLocked): heads older than MaxAge are dropped as DropNoPath (no
// data lane exists); it returns when the next one ages out (zero: none).
func (s *Session) pktRedoAgeLocked(nowNs int64) time.Time {
	pk := s.pk
	maxAge := s.pktMaxAge()
	for pk.redoN() > 0 {
		at := pk.redo[pk.redoHead].at
		if nowNs-at <= int64(maxAge) {
			return pk.base.Add(time.Duration(at) + maxAge + 1)
		}
		pk.redoPop().buf.Release()
		pk.ctr.DropNoPath++
	}
	return time.Time{}
}

// pktRedoReleaseLocked drops the redo list at the session's end or at the
// peer's FIN (nothing queued is worth sending): DropQueue each.
func (s *Session) pktRedoReleaseLocked() {
	pk := s.pk
	for pk.redoN() > 0 {
		pk.redoPop().buf.Release()
		pk.ctr.DropQueue++
	}
}

// pktRedoBytes returns the bytes of the returned DGRAMs waiting for a lane.
func (pk *packet) pktRedoBytes() int64 {
	var n int64
	for _, r := range pk.redo[pk.redoHead:] {
		n += int64(len(r.body))
	}
	return n
}

// pktTxHeadLocked returns the size of the next datagram the tx side places
// (a returned DGRAM first, else tx's head; −1 when neither waits).
func (s *Session) pktTxHeadLocked() int {
	pk := s.pk
	if pk.redoN() > 0 {
		return len(pk.redo[pk.redoHead].body)
	}
	if pk.tx.n > 0 {
		return int(pk.tx.front().n)
	}
	return -1
}
