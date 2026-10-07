package session

// Packet-session errors (plan §6; M2-D62). rendr re-exports these exact
// values; both are net.Error with Timeout() == false and change nothing
// (no queue, no counter, no carrier).
var (
	// ErrPacketTooLarge: WriteTo of more than the session's MaxPayload.
	ErrPacketTooLarge error = &sessionError{"rendr: datagram larger than the session's MaxPayload"}
	// ErrPacketDestinationMismatch: WriteTo to an address other than nil or
	// the session's logical peer address; no method of that address runs
	// (L38).
	ErrPacketDestinationMismatch error = &sessionError{"rendr: WriteTo address is not the session's peer"}
)

// Carrier violations detected by the packet plane (M2 design §A3.2,
// §A3.6): the delivering carrier is killed, the session survives
// (invariant 6).
var (
	errDataOnPacket     error = violation("DATA on a packet session")
	errAckOnPacket      error = violation("ACK on a packet session")
	errDgramTooLarge    error = violation("DGRAM larger than the session's MaxPayload")
	errDgramBeyondLimit error = violation("DGRAM seq at or beyond the offset limit")
	errDgramBeyondFin   error = violation("DGRAM seq at or beyond the peer's final seq")
	errPackBeyondSent   error = violation("PACK reports a seq never sent")
)
