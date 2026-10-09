package session

// Race (M3 design §A6; M3-D28 … M3-D35). Every member carries every byte
// (stream) or datagram (packet); members are chosen as bond's, one per fate
// group. Stream: each data lane sends from its own cursor lane.rnext over
// the one send ring, clamped to the acknowledged front sBase, so a slow
// member never drags a fast one; the receiver de-duplicates by offset and
// compares an overlap while the first copy is still held. Packet: each data
// lane places from its own cursor lane.rpos over the one tx ring; a
// datagram's seq is fixed at its first placement and shared by its copies.
// The ACK (stream) and PACK (packet) duty sits on the fastest live lane.
// Session counters count unique delivery (stream.copyBytes and
// stream.dupBytes hold the extra); carrier counters count physical copies
// (L35).

// raceAttachLocked starts the race cursors of the new lane l (M3-D30,
// M3-D32): l.rnext at sBase (a new lane replays from the ACK point, L10)
// and l.rpos at the tx ring's head. Every attach of a lane calls it; it
// does nothing for a session that is not a race session. s.mu held.
func (s *Session) raceAttachLocked(l *lane) {
	if s.p.Mode != ModeRace {
		return
	}
	panic("unimplemented: M3")
}

// raceAckLaneLocked returns the lane that carries a race session's ACK
// (stream) or PACK (packet) duty (M3-D33, PA-33): the live lane that is not
// write-blocked with the lowest SRTT, ties by rank, then attach order; nil
// when no lane qualifies. The duty code re-chooses it at every ACK or PACK
// placement decision and at lane attach and death. s.mu held.
func (s *Session) raceAckLaneLocked() *lane {
	panic("unimplemented: M3")
}
