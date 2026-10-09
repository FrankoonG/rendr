package session

import (
	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The packet receive path (M2 design §A5.3; M2-D36, M2-D37; R1-12).

// datagramLocked accepts one CRC-verified DGRAM with session seq seq
// (plane.Datagram under s.mu). With buf nil, d is valid only during the
// call and is copied into an rx chunk (the reader hands datagrams below
// BigData this way); with buf non-nil, d aliases buf.B and buf's reference
// moves to the session (queued by reference, or released). An error is a
// violation of the delivering carrier (§A3.2); the session survives.
//
// Accounting: a new seq counts Received (and PACK's received), a seq seen
// within the dedup window Duplicates — also after the peer's FIN was
// delivered (a slow race member's copies, M3-D35) — one older than the
// window, or a new one after the peer's FIN was delivered, DropLate
// (nothing is returned after io.EOF, R1-12), an eviction by the full
// receive queue DropRecvQueue; after this side's Close an accepted
// datagram is discarded uncounted (M2-D37).
//
// The idle clock (M2-D41) moves on an accepted datagram without a clock
// read per datagram: the first unreported datagram reads the clock for
// the PACK cadence and sets lastData; the PACK that reports the rest sets
// it again at its placement (fillPackLocked).
func (s *Session) datagramLocked(seq uint64, d []byte, buf *carrier.Buf) error {
	st, pk := &s.st, s.pk
	var err error
	switch {
	case st.ended:
	case s.pendingLocked():
		err = errDataBeforeOpen // no DGRAM before the verdict
	case len(d) > pk.maxPayload:
		err = errDgramTooLarge
	case seq >= s.offsetLimit():
		err = errDgramBeyondLimit // L14
	case st.peerFinSet && seq >= st.peerFin:
		err = errDgramBeyondFin
	case st.peerFinDelivered:
		if pk.dedup.Accept(seq) == wire.WindowDuplicate {
			pk.ctr.Duplicates++ // a copy of a received datagram (M3-D35)
		} else {
			pk.ctr.DropLate++ // a straggler after io.EOF was decided (R1-12)
		}
	default:
		switch pk.dedup.Accept(seq) {
		case wire.WindowDuplicate:
			pk.ctr.Duplicates++
		case wire.WindowLate:
			pk.ctr.DropLate++
		default:
			s.acceptDatagramLocked(seq, d, buf)
			return nil
		}
	}
	buf.Release()
	return err
}

// acceptDatagramLocked counts a new seq and queues the datagram for
// ReadFrom (discarded after this side's Close).
func (s *Session) acceptDatagramLocked(seq uint64, d []byte, buf *carrier.Buf) {
	st, pk := &s.st, s.pk
	pk.ctr.Received++
	if pk.rxCount == 0 || seq > pk.rxHigh {
		pk.rxHigh = seq
	}
	pk.rxCount++
	st.rxBytes += uint64(len(d))
	pk.rxSince++
	s.packCadenceLocked()
	if st.closed {
		buf.Release() // after this side's Close: discarded, uncounted (M2-D37)
		return
	}
	env := s.env.Carrier
	if buf != nil {
		buf.B = d // the owner slices B (carrier.Buf): exactly the datagram
	}
	slot, evicted, ok := pk.rx.push(len(d), 0, buf, env.Bufs, env.Budget)
	pk.ctr.DropRecvQueue += uint64(evicted)
	if !ok {
		pk.ctr.DropRecvQueue++ // the chunk pool refused even after one eviction
		return
	}
	copy(slot, d) // slot is nil when buf was queued by reference
	if st.rwaiting {
		streamSignal(st.rwake)
	}
}
