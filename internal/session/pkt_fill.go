package session

import (
	"math"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The packet send path after WriteTo (M2 design §A5.2): Fill, the wake
// policy, the routing summary (dgMax, mixed) and MaxAge.

// fillPacketLocked is plane.Fill under s.mu, in one lock section per batch
// (≤ 64 DGRAMs: the batch's frame limit). Steps 1–4 are the stream's
// (fillControlLocked: the passive's first response, RST, the dialer's
// SCHED, and on the duty lane the PACK, fillPackLocked); then, on a data
// lane, the DGRAMs and the FIN once nothing is queued. On a datagram batch
// the reliable frames (first response, RST, SCHED, FIN, a reliable PACK)
// are REL frames (the batch's datagram mode).
func (s *Session) fillPacketLocked(l *lane, b *carrier.Batch) {
	if l.state == LaneDead {
		return // C1: never place anything on a lane the actor declared dead
	}
	start := b.Len()
	if s.fillControlLocked(l, b) && l.data {
		s.fillDgramLocked(l, b)
		st, pk := &s.st, s.pk
		if st.fin.requested && !st.fin.acked && st.fin.lane == nil && pk.tx.n == 0 && pk.txBig.n == 0 {
			if !pk.finPlaced {
				st.fin.off = pk.nextSeq // the final seq is fixed at its first placement (M2-D34)
				pk.finPlaced = true
			}
			if b.AddFin(wire.SessionHandle, st.fin.off) {
				st.fin.lane = l
				l.finHere = true
			}
		}
	}
	l.idle = b.Len() == start
}

// fillDgramLocked places queued datagrams on data lane l: a stream lane
// pulls txBig first, then tx; a datagram lane tx only. The seq is assigned
// here (M2-D34). A head older than MaxAge is dropped (M2-D35); a head
// above a datagram batch's DgramRoom (only after a budget shrink, D7) is
// left to another live data lane that can carry it, else dropped
// (DropTooLarge, M2-D45); on a stream lane DGRAM bytes are DATA and wait
// for the carrier's capacity (M2-D26). It stops at a full batch.
func (s *Session) fillDgramLocked(l *lane, b *carrier.Batch) {
	if s.placeDgramsLocked(l, b) {
		l.lastDgramAt = b.Now()
		if s.pk.stale == l {
			s.pk.stale = nil // the minimum share is served (R1-19)
		}
	}
}

// placeDgramsLocked is fillDgramLocked's loop; it reports whether a DGRAM
// was placed.
func (s *Session) placeDgramsLocked(l *lane, b *carrier.Batch) (placed bool) {
	st, pk := &s.st, s.pk
	dg := b.Datagram()
	nowNs := b.Now().Sub(pk.base).Nanoseconds()
	maxAge := int64(s.pktMaxAge())
	noPathEnd := pk.noPathEnd.Sub(pk.base).Nanoseconds()
	left := int64(math.MaxInt64)
	if !dg {
		left = l.port.Capacity() - l.port.Inflight()
	}
	limit := s.offsetLimit()
	queues := [2]*pring{&pk.txBig, &pk.tx}
	first := 0
	if dg {
		first = 1 // only stream lanes pull txBig
	}
	for _, q := range queues[first:] {
		for q.n > 0 {
			d := q.front()
			n, at := int(d.n), d.at
			if nowNs-at > maxAge {
				q.evict()
				if at < noPathEnd {
					pk.ctr.DropNoPath++
				} else {
					pk.ctr.DropAge++ // a data lane exists: this one
				}
				continue
			}
			if dg && n > b.DgramRoom() {
				if s.pktOtherCarrierLocked(l, n) {
					return placed // that lane takes the head; nothing overtakes it here
				}
				q.evict()
				pk.ctr.DropTooLarge++
				continue
			}
			if int64(n) > left {
				b.MarkCapBlocked() // the PONG that frees capacity wakes the writer
				return placed
			}
			if pk.nextSeq >= limit {
				st.exhausted = true // L14: the actor ends with one RST(Exhausted)
				st.facts |= factExhausted
				s.ringActor()
				return placed
			}
			body, buf := q.data(d)
			if !b.AddDgram(wire.SessionHandle, pk.nextSeq, body, buf) {
				return placed // the batch is full: the writer self-continues
			}
			q.pop().ext.Release() // the batch holds its own reference
			pk.nextSeq++
			pk.ctr.Sent++
			left -= int64(n)
			placed = true
		}
	}
	return placed
}

// pktAgeQueueLocked drops q's heads older than MaxAge at nowNs (ns since
// the base), counting each DropNoPath when it was queued before the latest
// no-path episode ended or no data lane exists now, else DropAge
// (M2-D35). noData forces DropNoPath (the actor's no-path step).
func (s *Session) pktAgeQueueLocked(q *pring, nowNs int64, noData bool) {
	pk := s.pk
	maxAge := int64(s.pktMaxAge())
	if q.n == 0 || nowNs-q.front().at <= maxAge {
		return
	}
	noPathEnd := pk.noPathEnd.Sub(pk.base).Nanoseconds()
	if !noData {
		noData = !s.pktHasDataLaneLocked()
	}
	for q.n > 0 && nowNs-q.front().at > maxAge {
		at := q.front().at
		q.evict()
		if noData || at < noPathEnd {
			pk.ctr.DropNoPath++
		} else {
			pk.ctr.DropAge++
		}
	}
}

// pktHasDataLaneLocked reports whether a live data lane exists.
func (s *Session) pktHasDataLaneLocked() bool {
	for _, l := range s.st.order {
		if l.data && l.state != LaneDead {
			return true
		}
	}
	return false
}

// pktOtherCarrierLocked reports whether a live data lane other than l can
// carry an n-byte datagram now — a datagram data lane whose DgramMax is at
// least n, else a stream data lane with spare capacity for it, either not
// write-blocked — and wakes it (M2-D45). Datagram lanes come first, as in
// the wake walk (§A5.2): a datagram that fits a datagram member never
// moves to a stream member because a smaller datagram member pulled it
// (integration 2; TestPacketCapacityAgreement_L37). It recomputes the
// routing summary first, so two lanes never defer to each other. A capable member that
// cannot write now does not hold the queue behind the head until MaxAge:
// the head is dropped as too large instead (a budget shrink is rare; the
// datagrams behind it are not held up).
func (s *Session) pktOtherCarrierLocked(l *lane, n int) bool {
	s.pktRouteLocked()
	for pass := range 2 {
		for _, o := range s.st.order {
			if o == l || !o.data || o.state == LaneDead {
				continue
			}
			if _, dg := pktDgramLane(o); dg != (pass == 0) {
				continue
			}
			if !s.pktCanPlaceLocked(o, n) {
				continue
			}
			if o.idle {
				o.idle = false
				o.port.Wake()
			}
			return true
		}
	}
	return false
}

// pktRouteLocked is pktRecomputeLocked (§A5.2): pk.dgMax = the largest
// DgramMax over live datagram data lanes (0: none); pk.mixed = bond with
// live data lanes of both kinds. When no live stream data lane is left,
// txBig is dropped (DropTooLarge: no live carrier can carry it). The
// remembered stale lane is forgotten once it is no data lane.
func (s *Session) pktRouteLocked() {
	pk := s.pk
	dgMax, stream, dgram := 0, false, false
	for _, l := range s.st.order {
		if !l.data || l.state == LaneDead {
			continue
		}
		if pp, dg := pktDgramLane(l); dg {
			dgram = true
			dgMax = max(dgMax, pp.DgramMax())
		} else {
			stream = true
		}
	}
	pk.dgMax = dgMax
	pk.mixed = s.p.Mode == ModeBond && stream && dgram
	if !stream && pk.txBig.n > 0 {
		pk.ctr.DropTooLarge += uint64(pk.txBig.releaseAll())
	}
	if sl := pk.stale; sl != nil && (!sl.data || sl.state == LaneDead) {
		pk.stale = nil
	}
}

// pktWakeDataLocked is pktWakeLocked (M2 design §A5.2, R1-19; L08): it
// wakes only idle lanes, with a coalescing Wake, and walks no further than
// the queue needs.
//
// Selector: the active data lane (or the first data lane) if idle.
//
// Bond: first the minimum share (R1-19): a live data lane that is not
// write-blocked and placed no DGRAM within PacketPing/4 — one that never
// placed one first, then the stalest — is found by a scan that runs at
// most once per PacketPing/8 and is remembered until it places a DGRAM;
// when it is idle it is woken and counts as the walk's first member (with
// at most a batch queued it is then the only lane woken, so it takes
// them). Then, for each queue that holds datagrams, the walk visits the
// data lanes in srtt order, datagram lanes first then stream lanes (txBig:
// stream lanes only), skipping write-blocked ones, waking the idle ones
// until one batch (64 frames) per visited writer covers the queue
// (M2-D43). With nothing queued and the FIN due, the first data lane that
// is not write-blocked is woken.
func (s *Session) pktWakeDataLocked(now time.Time) {
	st, pk := &s.st, s.pk
	if st.ended {
		return
	}
	if s.p.Mode != ModeBond {
		l := s.ctl.active
		if l == nil || !l.data || l.state == LaneDead {
			l = nil
			for _, o := range st.order {
				if o.data && o.state != LaneDead {
					l = o
					break
				}
			}
		}
		if l != nil && l.idle {
			l.idle = false
			l.port.Wake()
		}
		return
	}
	s.refreshOrderLocked(now, false)
	if pk.tx.n == 0 && pk.txBig.n == 0 {
		if st.fin.requested && !st.fin.acked && st.fin.lane == nil {
			s.pktWalkLocked(1, false, nil, 0, -1)
		}
		return
	}
	var counted *lane
	covered := 0
	if pk.tx.n > 0 {
		if sl := s.pktStaleLocked(now); sl != nil && sl.idle {
			sl.idle = false
			sl.port.Wake()
			counted, covered = sl, carrier.MaxBatchFrames
		}
		if covered < pk.tx.n {
			s.pktWalkLocked(pk.tx.n, false, counted, covered, int(pk.tx.front().n))
		}
	}
	if pk.txBig.n > 0 {
		s.pktWalkLocked(pk.txBig.n, true, nil, 0, int(pk.txBig.front().n))
	}
}

// pktWalkLocked is the bond walk of pktWakeDataLocked for need queued
// datagrams whose head has head bytes (−1: the FIN, no capacity needed):
// skip is a lane already counted (covered includes it). A stream lane
// without spare capacity for the head is skipped like a write-blocked one:
// it could place nothing, so it covers nothing (a stalled member absorbs
// at most its capacity, L32; as M1's wakeDataLocked counts spare capacity).
func (s *Session) pktWalkLocked(need int, streamOnly bool, skip *lane, covered, head int) {
	for pass := range 2 {
		if streamOnly && pass == 0 {
			continue
		}
		for _, l := range s.st.order {
			if l == skip || !l.data || l.state == LaneDead {
				continue
			}
			if _, dg := pktDgramLane(l); dg != (pass == 0) {
				continue
			}
			if !s.pktCanPlaceLocked(l, head) {
				continue
			}
			if l.idle {
				l.idle = false
				l.port.Wake()
			}
			covered += carrier.MaxBatchFrames
			if covered >= need {
				return
			}
		}
	}
}

// pktCanPlaceLocked reports whether lane l can place an n-byte datagram
// now: it is not write-blocked and, on a datagram lane, n fits its
// DgramMax — a smaller member never takes the head only to defer it
// (integration 2) — or, on a stream lane, its spare capacity (Capacity −
// Inflight) holds n bytes (n < 0: no size or capacity needed).
func (s *Session) pktCanPlaceLocked(l *lane, n int) bool {
	if l.port.WriteBlocked() {
		return false
	}
	if n < 0 {
		return true
	}
	if pp, dg := pktDgramLane(l); dg {
		return pp.DgramMax() >= n
	}
	return l.port.Capacity()-l.port.Inflight() >= int64(n)
}

// pktStaleLocked returns the bond lane the minimum share serves now
// (R1-19), or nil: the remembered one while it is a live data lane that can
// place tx's head now (pktCanPlaceLocked), else the result of a scan for
// the live data lane that can place it and placed no DGRAM within
// PacketPing/4 — never-placed lanes first, then the oldest lastDgramAt.
// The scan runs at most once per PacketPing/max(8, 4·lanes): one stale
// lane is served per scan, so with k members each is served at least every
// max((k−1)·period, PacketPing/4 + period) < PacketPing/2 for every bond up
// to MaxCarriersPerSession (and beyond). Called with tx non-empty.
func (s *Session) pktStaleLocked(now time.Time) *lane {
	pk := s.pk
	head := int(pk.tx.front().n)
	if sl := pk.stale; sl != nil {
		if sl.data && sl.state != LaneDead && s.pktCanPlaceLocked(sl, head) {
			return sl
		}
		pk.stale = nil // it cannot place now: a capacity-blocked member never holds the share
	}
	pp := s.pktPing()
	if !pk.staleScanAt.IsZero() && now.Sub(pk.staleScanAt) < pp/time.Duration(max(8, 4*len(s.st.order))) {
		return nil
	}
	pk.staleScanAt = now
	var best *lane
	for _, l := range s.st.order {
		if !l.data || l.state == LaneDead {
			continue
		}
		if !l.lastDgramAt.IsZero() && now.Sub(l.lastDgramAt) < pp/4 {
			continue
		}
		if best != nil && !l.lastDgramAt.Before(best.lastDgramAt) {
			continue
		}
		if !s.pktCanPlaceLocked(l, head) {
			continue
		}
		best = l
	}
	pk.stale = best
	return best
}
