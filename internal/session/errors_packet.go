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
