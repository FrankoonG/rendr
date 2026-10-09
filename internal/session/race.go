package session

import (
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Race (M3 design §A6; M3-D28 … M3-D35). Every member carries every byte
// (stream) or datagram (packet); members are chosen as bond's, one per fate
// group. Stream: each data lane sends from its own cursor lane.rnext over
// the one send ring, clamped to the acknowledged front sBase, so a slow
// member never drags a fast one; the receiver de-duplicates by offset and
// compares an overlap while the first copy is still held. Packet: each data
// lane places from its own cursor lane.rpos over the one tx ring; a
// datagram's seq is fixed at its first placement and shared by its copies
// (pkt_race.go). The ACK (stream) and PACK (packet) duty sits on the
// fastest live lane. Session counters count unique delivery
// (stream.copyBytes, packet.copies and stream.dupBytes hold the extra);
// carrier counters count physical copies (L35).

// errRaceMismatch: a copy of stream bytes this side still holds differs
// from the first copy (M3-D31, L13). The delivering carrier is killed
// (protocol_violation; on a MUX trunk the whole trunk, M3-D15) and the
// first copy stays authoritative.
var errRaceMismatch error = violation("race copy mismatch")

// raceAttachLocked starts the race cursors of the new lane l (M3-D30,
// M3-D32): l.rnext at sBase (a new lane replays from the ACK point, L10)
// and l.rpos at the tx ring's head. Every attach of a lane calls it; it
// does nothing for a session that is not a race session. s.mu held.
//
// The cursors are also clamped at every Fill (to sBase and to the ring's
// head), so a lane attached without this call — the passive's — starts at
// the same place.
func (s *Session) raceAttachLocked(l *lane) {
	if s.p.Mode != ModeRace {
		return
	}
	if s.pk != nil {
		l.rpos = s.pk.tx.pos
		return
	}
	l.rnext = s.st.sBase
}

// raceAckLaneLocked returns the lane that carries a race session's ACK
// (stream) or PACK (packet) duty (M3-D33, PA-33): the live lane that is not
// write-blocked with the lowest SRTT, ties by rank, then attach order; nil
// when no lane qualifies. The duty code re-chooses it at every ACK or PACK
// placement decision and at lane attach and death. s.mu held.
//
// "Live" is ackQualifiesLocked (confirmed, not refused, CLOSE unwritten)
// and not leaving (Retire called, or dropped by the passive's applied
// SCHED): a leaving or blocked lane carries the duty only through M1's
// fallback (chooseAckLaneLocked) when no lane qualifies here. An unknown
// SRTT (0) ranks after every known one. Rank is the dialer's factory
// index; passive lanes (factory −1) tie and keep their attach order.
func (s *Session) raceAckLaneLocked() *lane {
	var best *lane
	var bestRTT time.Duration
	for _, l := range s.lanes {
		if !s.ackQualifiesLocked(l) || s.ackLeavingLocked(l) || l.port.WriteBlocked() {
			continue
		}
		r := l.port.SRTT()
		if best == nil || srttBefore(r, bestRTT) || (r == bestRTT && l.factory < best.factory) {
			best, bestRTT = l, r
		}
	}
	return best
}

// raceFillDataLocked is Fill step 5 on a race data lane (M3-D30): DATA from
// the lane's cursor, clamped to the acknowledged front (a slow lane skips
// what the peer already delivered, L08), up to min(end, peerLimit) — the
// window is consumed by the furthest cursor — within the lane's share of
// its carrier's capacity, Capacity − Inflight − Taken (M3-D11). Bytes
// below sNext are copies of what another lane already placed
// (stream.copyBytes, M3-D35); bytes the death of the last data lane
// requeued (stream.retx) are retransmissions instead, never copies, and the
// cursor passes the queue without sending them twice. sNext is the
// furthest cursor. At the cap with bytes still pullable it marks the batch
// cap-blocked, so the PONG that frees capacity wakes the writer (§4.10).
func (s *Session) raceFillDataLocked(l *lane, b *carrier.Batch) {
	st := &s.st
	left := l.port.Capacity() - l.port.Inflight() - int64(b.Taken())
	from := max(l.rnext, st.sBase)
	lim := min(st.end, st.peerLimit)
	sent := false
	for left > 0 && from < lim {
		n, retx := lim-from, false
		st.retx.trimBelow(from) // this lane already sent them, and it lives
		if !st.retx.empty() {
			if sp := st.retx.s[0]; sp.off <= from {
				n, retx = min(n, sp.end()-from), true
			} else {
				n = min(n, sp.off-from)
			}
		}
		k := s.addDataLocked(l, b, from, n, retx, &sent)
		if k == 0 {
			break
		}
		if retx {
			st.retx.trimBelow(from + k)
		} else if from < st.sNext {
			st.copyBytes += min(k, st.sNext-from)
		}
		from += k
		left -= int64(k)
	}
	l.rnext = from
	st.sNext = max(st.sNext, from)
	if left <= 0 && from < lim {
		b.MarkCapBlocked()
	}
}

// raceFinDueLocked is Fill step 6 on a race data lane: each data member
// places our FIN once, after its own cursor reached the FIN offset (M3-D30),
// so the death of the member that carried it first never delays the
// stream's end. The receiver merges equal FINs (M1).
func (s *Session) raceFinDueLocked(l *lane) bool {
	st := &s.st
	return st.fin.requested && !st.fin.acked && !l.finHere && max(l.rnext, st.sBase) >= st.fin.off
}

// racePullableLocked is pullableLocked for a race session: the bytes the
// least advanced live data lane could still send (each lane carries every
// byte), or the bytes beyond sNext when no data lane exists.
func (s *Session) racePullableLocked() uint64 {
	st := &s.st
	lim := min(st.end, st.peerLimit)
	from := st.sNext
	for _, l := range st.order {
		if l.data && l.state != LaneDead {
			from = min(from, max(l.rnext, st.sBase))
		}
	}
	if lim > from {
		return lim - from
	}
	return 0
}

// raceWakeDataLocked is the race wake policy (M3-D30): every member carries
// every byte, so every idle data lane that is not write-blocked and has
// bytes, datagrams or the FIN to place is woken (≤ MaxCarriers lanes).
// wakeDataLocked and pktWakeDataLocked call it for a race session.
func (s *Session) raceWakeDataLocked() {
	st := &s.st
	if st.ended {
		return
	}
	for _, l := range st.order {
		if !l.data || l.state == LaneDead || !l.idle || l.port.WriteBlocked() {
			continue
		}
		if s.pk != nil {
			if !s.raceDgramDueLocked(l) {
				continue
			}
		} else if lim := min(st.end, st.peerLimit); max(l.rnext, st.sBase) >= lim && !s.raceFinDueLocked(l) {
			continue
		}
		l.idle = false
		l.port.Wake()
	}
}

// raceDupLocked is the receiver's duplicate rule (M3-D31): every session
// counts the bytes of a DATA frame it already held (DupBytes, M3-D35); a
// selector or bond session answers a whole duplicate with an immediate ACK
// (its sender may have missed one), while a race session does not — its
// members deliver every byte twice, and the ACK cadence already covers the
// first copy.
func (s *Session) raceDupLocked(n uint64, whole bool) {
	s.st.dupBytes += n
	if whole && s.p.Mode != ModeRace {
		s.bumpNowLocked()
	}
}

// raceFinLocked places our FIN on race data lane l when it is due there
// (raceFinDueLocked) and reports whether it did.
func (s *Session) raceFinLocked(l *lane, b *carrier.Batch) bool {
	st := &s.st
	if !s.raceFinDueLocked(l) || !b.AddFin(wire.SessionHandle, st.fin.off) {
		return false
	}
	st.fin.lane = l
	l.finHere = true
	return true
}
