package session

import (
	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Early data on the passive (M4 design §A5.1 … §A5.3; M4-D2, M4-D5, M4-D6,
// M4-D8). A dialer that opens with EarlyReturn sends its first bytes as
// DATA frames directly behind an OPEN whose flag bit 0 (EARLY) is set, on
// the same carrier, before the passive's verdict. The pending session's
// first carrier reader runs from Start (its writer is held), so those
// frames reach dataLocked's pending branch, earlyDataLocked:
//
//   - They are legal only on a lane whose own first frame was an
//     OPEN(EARLY) (lane.early: NewPending, or a duplicate OPEN through
//     AttachOpenEarly) and only within the first wire.EarlyWindow bytes of
//     the stream, counted from Params.FirstOffset (0 in production). DATA
//     on any other lane — a duplicate OPEN without the flag, a JOIN lane —
//     or beyond that bound stays errDataBeforeOpen (M1): it kills only the
//     delivering carrier, and the pending session survives (a compliant
//     retry still opens).
//   - Legal early DATA takes the ordinary receive path (offset dedup, the
//     compare-while-held of L13 and M3-D31, the receive charge) with the
//     right edge raised to the early bound: nothing is acknowledged — the
//     writer is held until the verdict, and an ACK reports delivered bytes
//     only — and the bytes are readable only on the Conn that Confirm
//     returns, in order, from the stream's first byte.
//   - st.earlyBytes is the bytes taken before the verdict — received in
//     order or held out of order (SessionStatus.EarlyBytes, M4-D18); it is
//     frozen at the verdict, since only the pending branch sets it.
//   - Confirm advertises at least the early bound (openWindowLocked,
//     M4-D6), so the dialer's limit covers what it may already have sent
//     also when memory pressure shrinks the normal window (L13, L15).
//   - A refusal (Reject, AcceptTimeout, CAPACITY, GOING_AWAY, the dialer's
//     withdrawal) ends the session as before: the held bytes are released
//     with its receive state (releaseRecv), and early DATA that still
//     arrives meets st.ended in dataLocked and is discarded, never a
//     violation; the carrier's retirement drain consumes what is still in
//     flight (M4-D8).
//
// Memory (L48): a pending session holds at most wire.EarlyWindow early
// bytes, charged to the Runtime budget like any received bytes, so a
// Listener's pending sessions hold at most AcceptBacklog × EarlyWindow
// bytes of early data. rendr's dialer sends them as one DATA frame, kept by
// reference in one buffer of the 64 KiB size class: 64 KiB + ClassSlack of
// charge. Other framings cost more per byte (class rounding, by-reference
// frames just above 16 KiB), and sparse out-of-order frames would each take
// a 16 KiB run: while the session is pending, out-of-order data may fill
// the receive charge only up to earlyRecvLimit (recvLimit), beyond which it
// is dropped as V3 drops it (never a violation; a compliant dialer sends
// its early span in order from the first byte), and in-order data sheds it.
// So a pending session's receive charge stays within about 2 × EarlyWindow
// whatever the framing.

// earlyRecvLimit is recvLimit while a passive session is pending: twice
// the early span.
const earlyRecvLimit = 2 * wire.EarlyWindow

// earlyEnd is the end of the early span on this session's stream: no
// pre-verdict DATA may reach beyond it (M4-D2).
func (s *Session) earlyEnd() uint64 {
	return s.p.FirstOffset + wire.EarlyWindow
}

// earlyDataLocked is dataLocked's pending branch (M4-D5): DATA that lane l
// delivered before the verdict. It is legal only when l.early and off +
// len(p) ≤ the early end: then the normal receive path runs with the right
// edge raised to at least the early end, nothing is acknowledged before
// the verdict and st.earlyBytes holds the bytes taken; otherwise it is
// errDataBeforeOpen (the carrier dies, the pending session survives). It
// owns buf as dataLocked does.
func (s *Session) earlyDataLocked(l *lane, off uint64, p []byte, buf *carrier.Buf) error {
	st := &s.st
	lim := s.earlyEnd()
	if end := off + uint64(len(p)); !l.early || end < off || end > lim {
		buf.Release()
		return errDataBeforeOpen
	}
	if st.rightEdge < lim {
		st.rightEdge = lim // never retracted (P10); Confirm advertises it
	}
	err := s.recvDataLocked(off, p, buf)
	// Every byte received before the verdict is early: the in-order ones
	// (rxBytes) and those held out of order; bytes dropped or shed are
	// not taken (they come again after the verdict, as ordinary DATA).
	st.earlyBytes = st.rxBytes + st.ooq.bytes()
	return err
}

// earlyWindowLocked raises the right edge of a session that took an
// OPEN(EARLY) to at least the early end before Confirm computes its window
// (M4-D6): the OPEN_ACK(OK) window never falls below the early bytes the
// dialer may have sent, also when memory pressure shrinks the normal one.
func (s *Session) earlyWindowLocked() {
	if !s.st.earlyOpen || s.pk != nil {
		return
	}
	if lim := s.earlyEnd(); s.st.rightEdge < lim {
		s.st.rightEdge = lim
	}
}

// bytes returns the payload bytes the list holds.
func (l *segList) bytes() uint64 {
	var n uint64
	for i := range l.s {
		n += uint64(len(l.s[i].b))
	}
	return n
}
