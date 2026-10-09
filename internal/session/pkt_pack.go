package session

import (
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// PACK (M2 design §A5.5; M2-D39; PA-3, PA-5; R1-17). A PACK rides M1's
// ACK-duty machinery: it is session state, not a queued frame — a bump
// increments ackGen and the duty lane places one PACK carrying the values
// current at placement (latest wins). It reports the accepted datagrams
// (highest seq, distinct count), the passive's applied SCHED epoch and the
// end flags FIN_DELIVERED and DONE. On a datagram batch a PACK carrying a
// flag, or an epoch echo not yet carried reliably on its lane, is
// REL-wrapped. PACK is accounting, SCHED echo and end signalling only: it
// is no liveness signal (PA-5), and PACKs merge by maximum — a lower one
// is never a violation (datagram carriers reorder).

// placePackLocked is fillPackLocked (Fill step 4 on the duty lane l): the
// PACK-delay rule, then one PACK if l owes one.
func (s *Session) placePackLocked(l *lane, b *carrier.Batch) {
	st, pk := &s.st, s.pk
	if !st.ackDelayAt.IsZero() {
		if l.retireCalled || !b.Now().Before(st.ackDelayAt) {
			st.ackGen++
			st.ackDelayAt = time.Time{}
		} else {
			b.WakeAt(st.ackDelayAt)
		}
	}
	if l.ackSent == st.ackGen {
		return
	}
	pa := wire.Pack{Received: pk.rxCount}
	if pk.rxCount > 0 {
		pa.HighestSeq = pk.rxHigh
	}
	passive := s.p.Role == RolePassive
	if passive {
		pa.EpochEcho = s.ctl.epoch
	}
	var flags uint8
	if st.ackFlags&wire.FlagAckFinDelivered != 0 {
		flags |= wire.FlagPackFinDelivered
	}
	if st.ackFlags&wire.FlagAckDone != 0 {
		flags |= wire.FlagPackDone
	}
	reliable := flags != 0 || (passive && pa.EpochEcho != l.echoRel)
	if !b.AddPack(l.Handle(), flags, &pa, reliable) {
		if reliable && b.Datagram() && b.RelRoom() == 0 {
			s.movePackDutyLocked(l) // R1-17
		}
		return // otherwise the batch is full: it stays due
	}
	l.ackSent = st.ackGen
	if pk.rxSince > 0 {
		pk.rxSince = 0
		if now := b.Now(); now.After(st.lastData) {
			st.lastData = now // the datagrams this PACK reports (M2-D41)
		}
	}
	if reliable && passive && b.Datagram() {
		l.echoRel = pa.EpochEcho
	}
	if flags&wire.FlagPackFinDelivered != 0 && !st.finDelivSent {
		st.finDelivSent = true
		s.maybeDoneLocked()
	}
	if flags&wire.FlagPackDone != 0 && !st.doneSent {
		st.doneSent = true
		st.doneSentAt = b.Now()
		st.facts |= factDoneSent
		s.ringActor()
	}
}

// movePackDutyLocked hands the PACK duty from l, whose datagram batch had
// no REL room for a reliable PACK, to the best other lane that can carry
// it now (R1-17): qualifying for the duty (ackQualifiesLocked), not
// write-blocked, and either a stream lane or a datagram lane whose carrier
// has REL room (Conn.RelRoom, Session.mu → Conn.mu), preferring one that is
// not leaving, in srtt order; the new duty lane is woken if idle. With
// none, the duty stays: the RACK that frees room wakes l's writer.
func (s *Session) movePackDutyLocked(l *lane) {
	st := &s.st
	var best *lane
	bestRank := 2
	for _, o := range st.order {
		if o == l || !s.ackQualifiesLocked(o) || o.port.WriteBlocked() {
			continue
		}
		if pp, dg := pktDgramLane(o); dg && pp.RelRoom() <= 0 {
			continue
		}
		rank := 0
		if s.ackLeavingLocked(o) {
			rank = 1
		}
		if rank < bestRank {
			best, bestRank = o, rank
			if rank == 0 {
				break
			}
		}
	}
	if best == nil {
		return
	}
	st.ackLane = best
	if best.idle {
		best.idle = false
		best.port.Wake()
	}
}

// packCadenceLocked is pktPackCadenceLocked, called per accepted datagram
// (rxSince already counts it): at PackEvery datagrams since the last PACK
// an urgent bump; else the first unreported datagram arms the PACK delay
// (PacketPing) and wakes the duty lane once, whose Fill arms its writer
// timer (b.WakeAt). Only that first datagram and every PackEvery-th one
// read the clock, and the idle clock moves with them (M2-D41): while the
// PACK cannot be placed, a busy receiver still moves it every PackEvery
// datagrams. (The residual lag — at most PacketPing, or PackEvery
// datagrams while no duty lane can place the PACK — is why IdleTimeout
// should be at least 2·PacketPing.)
func (s *Session) packCadenceLocked() {
	st, pk := &s.st, s.pk
	switch every := s.pktPackEvery(); {
	case pk.rxSince%every == 0:
		if pk.rxSince == every {
			s.bumpNowLocked()
		}
		if now := time.Now(); now.After(st.lastData) {
			st.lastData = now
		}
	case pk.rxSince < every && st.ackDelayAt.IsZero():
		now := time.Now()
		st.ackDelayAt = now.Add(s.pktPing())
		if now.After(st.lastData) {
			st.lastData = now
		}
		s.ensureAckLaneLocked()
		if l := st.ackLane; l != nil && l.idle {
			l.idle = false
			l.port.Wake()
		}
	}
}

// packLocked processes a PACK received on a lane (§A5.5 receipt; the
// checks of §A3.2): a report of a seq never sent — more datagrams than
// seqs assigned, or a highest seq outside the assigned range — and
// FIN_DELIVERED before our FIN was placed are violations of the delivering
// carrier; everything else merges by maximum.
func (s *Session) packLocked(flags uint8, pa *wire.Pack) error {
	st, pk := &s.st, s.pk
	first := s.p.Packet.FirstSeq
	switch {
	case pa.Received > pk.nextSeq-first:
		return errPackBeyondSent
	case pa.Received > 0 && (pa.HighestSeq >= pk.nextSeq || pa.HighestSeq < first):
		return errPackBeyondSent
	case flags&wire.FlagPackFinDelivered != 0 && !pk.finPlaced:
		return errFinDeliveredEarly
	}
	if pa.Received > 0 {
		pk.peerHi = max(pk.peerHi, pa.HighestSeq)
	}
	pk.ctr.PeerReceived = max(pk.ctr.PeerReceived, pa.Received)
	if flags&wire.FlagPackFinDelivered != 0 && !st.fin.acked {
		st.fin.acked = true
		if fl := st.fin.lane; fl != nil {
			fl.finHere = false
			st.fin.lane = nil
		}
		st.facts |= factFinAcked
		s.ringActor()
		s.maybeDoneLocked()
	}
	if flags&wire.FlagPackDone != 0 && !st.peerDone {
		st.peerDone = true
		st.facts |= factPeerDone
		s.ringActor()
	}
	if s.p.Role == RoleDialer && sched.EpochNewer(pa.EpochEcho, st.echoIn) && !sched.EpochNewer(pa.EpochEcho, s.ctl.epoch) {
		// As ackLocked: an echo of an epoch never published is ignored.
		st.echoIn = pa.EpochEcho
		st.facts |= factEcho
		s.ringActor()
	}
	return nil
}
