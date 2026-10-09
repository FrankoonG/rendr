package carrier

import "github.com/FrankoonG/rendr/v2/internal/wire"

// dedicatedOK reports whether a frame of type t with handle h may arrive
// where only view 1 exists: on a dedicated (non-MUX) carrier, and in every
// handshake (a carrier's first frame and its response are view 1's on a
// MUX trunk too). Since M3 the codec accepts any non-zero handle on a
// session frame and knows DETACH (0x36), so the rules M2 got from the codec
// are the carrier's (M3 design §A3.2): such a frame carries session handle
// 1 and is never DETACH. The decoding sites keep M2's outcome: a dropped and
// counted datagram rest for bare frames on datagram carriers and in the
// datagram handshake walks, a refused handshake for first frames and
// responses. Stream frames and REL inner frames after the handshake are
// judged by the trunk's routing and legality rules (route, classify,
// onDetach), which already end in M2's violation.
func dedicatedOK(t wire.Type, h uint32) bool {
	if t == wire.TypeDetach {
		return false
	}
	return t.Extension() || t.CarrierLevel() || h == wire.SessionHandle
}
