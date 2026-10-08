package session

import (
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The end of a packet session (M2 design §A5.6; M2-D40, M2-D41; PA-6):
// M1's DONE exchange over the packet plane. Close requests our FIN and
// discards what was received; the peer's FIN closes both directions (our
// FIN follows at once, WriteTo returns net.ErrClosed); the peer's FIN is
// delivered once the receive queue is empty and every seq below the final
// one was accepted, or the straggler bound finWaitAt passed, or this side
// closed. From there maybeDoneLocked and terminationLocked run unchanged:
// the reliable PACK carries FIN_DELIVERED and DONE (REL on datagram
// carriers). Packet sessions never set discardedAfterClose, so they never
// take the RST(Closed) rule.

// pktCloseAppLocked is pktCloseLocked: returns at once (L03); idempotent.
// Queued tx datagrams still leave while younger than MaxAge, then the FIN.
func (s *Session) pktCloseAppLocked(now time.Time) {
	st, pk := &s.st, s.pk
	if st.closed {
		return
	}
	st.closed, st.closedAt = true, now
	st.fin.requested = true
	pk.rx.releaseAll() // discarded, uncounted (M2-D37)
	if st.peerFinSet && !st.peerFinDelivered {
		s.pktDeliverFinLocked()
	}
	if st.rwaiting {
		streamSignal(st.rwake)
	}
	if st.wwaiting {
		streamSignal(st.wwake)
	}
	st.facts |= factClose
	s.ringActor()
	s.pktWakeLocked(now)
}

// pktFinLocked processes the peer's FIN carrying its final seq (the first
// seq it never assigned). A different final seq than an earlier FIN's, a
// final seq below an accepted datagram or below FirstSeq, and one beyond
// the offset limit are violations of the delivering carrier. A repeated
// FIN after delivery is answered again (an urgent PACK, L05).
func (s *Session) pktFinLocked(final uint64) error {
	st, pk := &s.st, s.pk
	if st.peerFinSet {
		if final != st.peerFin {
			return errFinConflict
		}
		if st.peerFinDelivered {
			s.bumpNowLocked() // a FIN resent over another carrier: answer it again
		}
		return nil
	}
	switch {
	case final < s.p.Packet.FirstSeq || (pk.rxCount > 0 && final <= pk.rxHigh):
		return errFinBelowData
	case final > s.offsetLimit():
		return errFinBeyondWindow
	}
	now := time.Now()
	st.peerFin, st.peerFinSet = final, true
	if !st.fin.requested {
		// The peer closed: it reads nothing more, so nothing queued is
		// worth sending and our FIN follows at once (PA-6).
		st.fin.requested = true
		pk.ctr.DropQueue += uint64(pk.tx.releaseAll() + pk.txBig.releaseAll())
	}
	if st.closed {
		s.pktDeliverFinLocked()
	} else {
		pk.finWaitAt = now.Add(s.pktFinWaitLocked())
	}
	st.facts |= factPktFin // the actor arms finWaitAt
	s.ringActor()
	if st.rwaiting {
		streamSignal(st.rwake)
	}
	if st.wwaiting {
		streamSignal(st.wwake)
	}
	s.pktFinCheckLocked(now)
	s.pktWakeLocked(now)
	return nil
}

// pktFinWaitLocked is the EOF straggler bound after the peer's FIN:
// clamp(2·max live-lane srtt, 50 ms, FinWaitMax) (M2-D40).
func (s *Session) pktFinWaitLocked() time.Duration {
	var srtt time.Duration
	for _, l := range s.st.order {
		if l.state != LaneDead {
			srtt = max(srtt, l.port.SRTT())
		}
	}
	return min(max(2*srtt, finWaitMin), s.pktFinWaitMax())
}

// pktFinCheckLocked is pktPeerFinCheckLocked: the peer's FIN is delivered
// once nothing more can come (L40) — the receive queue is empty and either
// every seq below the final one was accepted or finWaitAt passed — so
// ReadFrom returns io.EOF only after every queued datagram.
func (s *Session) pktFinCheckLocked(now time.Time) {
	st, pk := &s.st, s.pk
	if !st.peerFinSet || st.peerFinDelivered || st.ended || pk.rx.n > 0 {
		return
	}
	if pk.rxCount >= st.peerFin-s.p.Packet.FirstSeq || !now.Before(pk.finWaitAt) {
		s.pktDeliverFinLocked()
	}
}

// pktDeliverFinLocked marks the peer's FIN delivered: the PACK with
// FIN_DELIVERED is queued (an urgent bump) before any ReadFrom can return
// io.EOF, and a waiting reader is woken.
func (s *Session) pktDeliverFinLocked() {
	st := &s.st
	st.peerFinDelivered = true
	st.ackFlags |= wire.FlagAckFinDelivered
	s.bumpNowLocked()
	st.facts |= factPeerFinDelivered
	s.ringActor()
	if st.rwaiting {
		streamSignal(st.rwake)
	}
}

// pktReleaseLocked is pktEndLocked: every ring released (a datagram a
// ReadFrom detached holds its own reference), the still-queued tx
// datagrams counted DropQueue and the still-queued rx datagrams, which the
// application never read, DropRecvQueue (after the end nothing is queued:
// Received = returned + DropRecvQueue, §A7.2), both waiters woken.
func (s *Session) pktReleaseLocked() {
	st, pk := &s.st, s.pk
	pk.ctr.DropQueue += uint64(pk.tx.releaseAll() + pk.txBig.releaseAll())
	pk.ctr.DropRecvQueue += uint64(pk.rx.releaseAll())
	pk.stale = nil
	if st.rwaiting {
		streamSignal(st.rwake)
	}
	if st.wwaiting {
		streamSignal(st.wwake)
	}
}

// pktAgeOutLocked is pktAgeLocked, the actor's no-path ageing step: the
// tx datagrams older than MaxAge are dropped (DropNoPath: no data lane
// exists) and the time the next queued one ages out is returned (zero:
// nothing queued).
func (s *Session) pktAgeOutLocked(now time.Time) time.Time {
	pk := s.pk
	nowNs := now.Sub(pk.base).Nanoseconds()
	maxAge := s.pktMaxAge()
	var next time.Time
	for _, q := range [2]*pring{&pk.tx, &pk.txBig} {
		s.pktAgeQueueLocked(q, nowNs, true)
		if q.n > 0 {
			t := pk.base.Add(time.Duration(q.front().at) + maxAge + 1)
			if next.IsZero() || t.Before(next) {
				next = t
			}
		}
	}
	return next
}

// pktAgeBigLocked is the actor's ageing of a held txBig (pk.bigHeld,
// C4-F2): no stream data lane pulls it until the awaited SCHED routes a
// member, so its heads older than MaxAge are dropped here (DropAge: a data
// lane exists, M2-D35) and the time the next one ages out is returned
// (zero: none queued). Emptied here, txBig no longer holds the FIN back:
// the wake policy runs.
func (s *Session) pktAgeBigLocked(now time.Time) time.Time {
	pk := s.pk
	q := &pk.txBig
	if q.n == 0 {
		return time.Time{}
	}
	s.pktAgeQueueLocked(q, now.Sub(pk.base).Nanoseconds(), false)
	if q.n == 0 {
		s.pktWakeLocked(now)
		return time.Time{}
	}
	return pk.base.Add(time.Duration(q.front().at) + s.pktMaxAge() + 1)
}

// pktPendingBytesLocked returns the bytes of the datagrams queued for
// sending (pendingBytesLocked of a packet session, §A5.1).
func (s *Session) pktPendingBytesLocked() uint64 {
	return uint64(s.pk.tx.bytes + s.pk.txBig.bytes)
}
