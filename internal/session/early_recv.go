package session

import "github.com/FrankoonG/rendr/v2/internal/carrier"

// Early data on the passive (M4 design §A5.1 … §A5.3; WP9b): the
// pre-verdict acceptance of DATA on a lane whose first frame was an
// OPEN(EARLY) within wire.EarlyWindow (earlyDataLocked, called from
// dataLocked's pending branch), the EarlyBytes count (st.earlyBytes) and
// the window floor at Confirm (openWindowLocked, M4-D6). The wave-0
// skeleton declares the lane and stream fields (lane.early, st.earlyOpen,
// st.earlyBytes) and PassiveSpec.Early; until WP9b every pre-verdict DATA
// stays errDataBeforeOpen (M1).

// earlyDataLocked is dataLocked's pending branch (M4-D5): DATA that lane l
// delivered before the verdict. It is legal only when l.early and off +
// len(p) ≤ wire.EarlyWindow: then the normal receive path runs with the
// right edge raised to at least EarlyWindow, nothing is acknowledged
// before the verdict and st.earlyBytes counts the new bytes; otherwise it
// is errDataBeforeOpen (the carrier dies, the pending session survives).
// It owns buf as dataLocked does.
func (s *Session) earlyDataLocked(l *lane, off uint64, p []byte, buf *carrier.Buf) error {
	buf.Release()
	return errDataBeforeOpen // M4 WP9b
}
