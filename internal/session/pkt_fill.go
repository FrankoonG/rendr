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
	l.capMarked = false
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
// above a datagram batch's DgramRoom (after a budget shrink, D7, or on the
// smaller member of a mixed-budget bond) is left to another live data lane
// that can place it now, else dropped (DropTooLarge, M2-D45;
// pktOtherCarrierLocked); on a stream lane DGRAM bytes are DATA and wait
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
				// A wide head (queued above the smallest member's DgramMax:
				// a mixed-budget bond) waits for a member that can carry it
				// at all; any other head is one a budget shrink left behind
				// and waits only for a member that can place it now
				// (W4-REL-5, L37).
				if s.pktOtherCarrierLocked(l, n, d.wide) {
					return placed // that lane takes the head; nothing overtakes it here
				}
				q.evict()
				pk.ctr.DropTooLarge++
				continue
			}
			if int64(n) > left {
				b.MarkCapBlocked() // the PONG that frees capacity wakes the writer
				l.capMarked = true
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

// pktOtherCarrierLocked reports whether a live data lane other than l
// (nil: any) can carry an n-byte datagram and wakes it (M2-D45). Datagram
// lanes come first, as in the wake walk (§A5.2): a datagram that fits a
// datagram member never moves to a stream member because a smaller
// datagram member pulled it (integration 2;
// TestPacketCapacityAgreement_L37). It recomputes the routing summary
// first, so two lanes never defer to each other.
//
// With ever false (Fill) only a lane that can place the head now counts
// (pktCanPlaceLocked: a datagram data lane whose DgramMax is at least n,
// else a stream data lane with spare capacity for it, either not
// write-blocked). A capable member that cannot write now does not hold the
// queue behind the head until MaxAge: the head is dropped as too large
// instead, and the datagrams behind it are not held up
// (TestPacketShrinkDropsAtOnce_L37). That is the rule for a head a budget
// shrink left behind. A head of a mixed-budget bond — queued above the
// smallest live datagram member's DgramMax (pdesc.wide) — is filled with
// ever true instead: a smaller member's Fill for another reason (its PACK
// duty, a control frame) leaves it for the larger member even while that
// one is write-blocked or at its capacity, rather than dropping it as
// DropTooLarge (W4-REL-5; TestPacketFallbackWriteBlocked_L08, extra-fill).
// It is still dropped when no live member can carry it at all.
//
// With ever true (the wake policy's fallback decision) a lane that could
// carry the head at all counts too — a datagram data lane whose DgramMax
// is at least n, or a stream data lane, write-blocked or at its capacity:
// the first that can place it now is woken, else the first that can carry
// it. Waking a lane that cannot place now is harmless (a write-blocked
// writer fills again when its write returns) and keeps a stream lane at
// its capacity live: its Fill marks the batch cap-blocked, so the PONG
// that frees capacity wakes it (TestPacketFallbackWriteBlocked_L08).
func (s *Session) pktOtherCarrierLocked(l *lane, n int, ever bool) bool {
	s.pktRouteLocked()
	var capable *lane // the first lane that can carry the head, not now
	for pass := range 2 {
		for _, o := range s.st.order {
			if o == l || !o.data || o.state == LaneDead {
				continue
			}
			pp, dg := pktDgramLane(o)
			if dg != (pass == 0) || (dg && pp.DgramMax() < n) {
				continue
			}
			if s.pktCanPlaceLocked(o, n) {
				pktWakeIdle(o)
				return true
			}
			if capable == nil {
				capable = o
			}
		}
	}
	if !ever || capable == nil {
		return false
	}
	pktWakeIdle(capable)
	return true
}

// pktWakeIdle wakes l when it is idle (a coalescing Wake).
func pktWakeIdle(l *lane) {
	if l.idle {
		l.idle = false
		l.port.Wake()
	}
}

// pktBigPushedLocked follows WriteTo's push into txBig: the first datagram
// of a held txBig (pk.bigHeld) rings the actor, which arms its MaxAge
// (pktAgeBigLocked): no lane pulls it until the awaited SCHED.
func (s *Session) pktBigPushedLocked() {
	if s.pk.bigHeld && s.pk.txBig.n == 1 {
		s.ringActor()
	}
}

// pktRouteLocked is pktRecomputeLocked (§A5.2): pk.dgMax and pk.dgMin =
// the largest and smallest DgramMax over live datagram data lanes (0:
// none); pk.mixed = bond with
// live datagram data lanes and a stream member — a live stream data lane,
// or (passive) a confirmed stream member awaiting the SCHED that routes it
// (C4-F2: Status lists it as a member, and the dialer lists it in its next
// SCHED, plan:147); pk.bigHeld = mixed by awaiting members only: txBig
// waits for their SCHED, its heads aged out by the actor at MaxAge
// (pktAgeBigLocked). When no stream member is left, txBig is dropped
// (DropTooLarge: no live carrier can carry it, L37). The remembered stale
// lane is forgotten once it is no data lane.
func (s *Session) pktRouteLocked() {
	pk := s.pk
	dgMax, dgMin, stream, held, dgram := 0, 0, false, false, false
	for _, l := range s.st.order {
		if l.state == LaneDead {
			continue
		}
		pp, dg := pktDgramLane(l)
		if l.data {
			l.awaitSched = false // routed: no longer awaiting its SCHED
		} else {
			held = held || (!dg && l.awaitSched && l.state == LaneMember && !l.port.CloseSent())
			continue
		}
		if dg {
			m := pp.DgramMax()
			if !dgram || m < dgMin {
				dgMin = m
			}
			dgram = true
			dgMax = max(dgMax, m)
		} else {
			stream = true
		}
	}
	pk.dgMax, pk.dgMin = dgMax, dgMin
	pk.mixed = s.p.Mode == ModeBond && (stream || held) && dgram
	pk.bigHeld = pk.mixed && !stream
	if !stream && !held && pk.txBig.n > 0 {
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
// it is woken when idle and counts as the walk's first member on every
// WriteTo until then, woken or still pending (with at most a batch queued
// it is then the only lane woken, so it takes them). Then, for each queue that holds datagrams, the walk visits the
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
		if sl := s.pktStaleLocked(now); sl != nil {
			if sl.idle {
				sl.idle = false
				sl.port.Wake()
			}
			// Woken earlier and not run yet, it still covers a batch: the
			// burst behind it waits for its Fill instead of waking a faster
			// member whose writer would drain it first.
			counted, covered = sl, carrier.MaxBatchFrames
		}
		if head := int(pk.tx.front().n); covered < pk.tx.n && !s.pktWalkLocked(pk.tx.n, false, counted, covered, head) &&
			!s.pktOtherCarrierLocked(nil, head, true) {
			// No live data lane can ever carry the head: it is larger than
			// every datagram member's DgramMax and no stream member is left
			// (a budget shrink, or a mixed bond whose stream members are
			// gone). Wake a datagram member anyway: its Fill drops the head
			// as DropTooLarge (M2-D45) and places what follows, instead of
			// the head holding every datagram behind it until MaxAge. A
			// member that can carry it but cannot place it now (write-
			// blocked, at its capacity) was woken instead, and no smaller
			// member is woken only to drop the head: it waits for that
			// member unless a smaller member fills for another reason
			// (pktOtherCarrierLocked; TestPacketFallbackWriteBlocked_L08).
			s.pktWakeDgramLocked()
		}
	}
	if pk.txBig.n > 0 && !s.pktWalkLocked(pk.txBig.n, true, nil, 0, int(pk.txBig.front().n)) {
		s.pktWakeCappedLocked()
	}
}

// pktWakeCappedLocked follows a txBig walk that found no stream member
// able to place the head now: it wakes the first live stream data lane
// that is idle, not write-blocked and not already marked cap-blocked by its
// latest Fill (lane.capMarked). Its Fill places nothing beyond its capacity
// and marks the batch cap-blocked, so the PONG that frees capacity wakes
// its writer (M1's wake policy, and tx's fallback through
// pktOtherCarrierLocked, wake such a lane too). Without it, a member whose
// previous Fill had emptied txBig was woken by nothing when its capacity
// freed, and the queued datagrams waited for a later WriteTo or aged out
// (TestPacketCappedStreamLaneWoken_L32). A marked lane is not woken again:
// one wake per capacity episode.
func (s *Session) pktWakeCappedLocked() {
	for _, l := range s.st.order {
		if !l.data || l.state == LaneDead || l.capMarked || l.port.WriteBlocked() {
			continue
		}
		if _, dg := pktDgramLane(l); !dg {
			if l.idle {
				l.idle = false
				l.port.Wake()
			}
			return
		}
	}
}

// pktWalkLocked is the bond walk of pktWakeDataLocked for need queued
// datagrams whose head has head bytes (−1: the FIN, no capacity needed):
// skip is a lane already counted (covered includes it). A stream lane
// without spare capacity for the head is skipped like a write-blocked one:
// it could place nothing, so it covers nothing (a stalled member absorbs
// at most its capacity, L32; as M1's wakeDataLocked counts spare capacity).
// It reports whether a lane could place the head; skip counts as one (the
// minimum share's lane, chosen because it can).
func (s *Session) pktWalkLocked(need int, streamOnly bool, skip *lane, covered, head int) bool {
	found := skip != nil
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
			found = true
			covered += carrier.MaxBatchFrames
			if covered >= need {
				return true
			}
		}
	}
	return found
}

// pktWakeDgramLocked wakes the first live datagram data lane that is not
// write-blocked (srtt order).
func (s *Session) pktWakeDgramLocked() {
	for _, l := range s.st.order {
		if !l.data || l.state == LaneDead || l.port.WriteBlocked() {
			continue
		}
		if _, dg := pktDgramLane(l); dg {
			if l.idle {
				l.idle = false
				l.port.Wake()
			}
			return
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
