package carrier

import "github.com/FrankoonG/rendr/v2/internal/wire"

// Datagram mode of a Batch (M2 design §A5.8). On a datagram carrier the
// writer puts its batch in datagram mode for each round (SetDatagram): the
// reliable control frames (OPEN_ACK, JOIN_ACK, FIN, RST, SCHED, CLOSE,
// GOAWAY, and a PACK the session asks to be reliable) are then reserved as
// REL frames (the writer assigns the cseqs before sealing and stores the
// payload for retransmission, M2-D16), and a reliable Add* returns false
// once the round's REL room is used, so the frame stays due in the session
// (W5). Frames are packed into datagrams after sealing (M2-D12). A stream
// batch carries DGRAM and PACK as ordinary frames.
//
// Ownership (M2 design Revision 1, R1-20): the whole Batch — this file,
// batch.go's seal and Add* changes — belongs to WP3c in wave 1, so that the
// session's Fill (WP6a) and the datagram writer (WP3a) build against a
// working batch in wave 2. The writer-side methods at the end of this file
// are the WP3c ↔ WP3a contract.

// SetDatagram puts the batch in datagram mode for this round: frameBudget
// is the carrier's current send budget (Conn.MTU), relRoom the REL frames
// it may still place (wire.RelWindow minus those outstanding). Reset ends
// datagram mode. The writer calls it; session tests call it to drive Fill
// on a datagram batch.
func (b *Batch) SetDatagram(frameBudget, relRoom int) {
	panic("unimplemented: M2")
}

// Datagram reports whether the batch is in datagram mode this round.
func (b *Batch) Datagram() bool {
	panic("unimplemented: M2")
}

// DgramRoom returns the largest application datagram AddDgram still takes:
// in datagram mode the frame budget minus wire.DgramOverhead while a frame
// slot is free; in stream mode min(Room(), wire.MaxPacketPayload), counting
// DGRAM bytes as DATA (M2-D26).
func (b *Batch) DgramRoom() int {
	panic("unimplemented: M2")
}

// RelRoom returns the REL frames a reliable Add* may still reserve this
// round (datagram mode); 0 in stream mode (nothing is wrapped).
func (b *Batch) RelRoom() int {
	panic("unimplemented: M2")
}

// AddDgram appends one DGRAM: seq ‖ body, where body references packet
// queue storage held by ref (one Buf reference per (batch, chunk), released
// by ReleaseRefs; nil ref takes none). An empty body is legal. On a stream
// batch body counts against Room() and as DATA (submitted, capacity, byte
// clock: M2-D26); on a datagram batch it travels as the last frame of its
// own datagram (M2-D12). False when the batch is full or body exceeds
// DgramRoom().
func (b *Batch) AddDgram(handle uint32, seq uint64, body []byte, ref *Buf) bool {
	panic("unimplemented: M2")
}

// AddPack appends a PACK with header flags (wire.FlagPackFinDelivered,
// wire.FlagPackDone). reliable asks for REL wrapping in datagram mode (a
// PACK with flags is always wrapped there; M2-D39); false when the batch is
// full or no REL room is left for a wrapped one.
func (b *Batch) AddPack(handle uint32, flags uint8, p *wire.Pack, reliable bool) bool {
	panic("unimplemented: M2")
}

// The writer side of the datagram mode (WP3c ↔ WP3a; M2 design §A5.8,
// Revision 1, R1-20). The writer calls them on its goroutine in the order
// Reset → SetDatagram → carrier control and Fill → relPayload for every new
// REL (under Conn.mu: relSeal) → seal → nextDatagram/appendDatagram per
// datagram → ReleaseRefs. The H2 repeat and the rebind challenge are not
// batch frames: the writer sends those datagrams itself.

// relCount returns the number of new REL frames this round — the reliable
// frames reserved by Add* calls in datagram mode, retransmissions
// excluded — in insertion order.
func (b *Batch) relCount() int {
	panic("unimplemented: M2")
}

// relPayload stamps cseq on the k-th new REL frame (0 ≤ k < relCount(),
// insertion order) and returns its REL payload — cseq · itype · iflags ·
// ihandle · ipayload, at most wire.RelMaxPayload bytes, aliasing the arena
// until Reset — which relSeal copies into the send slot.
func (b *Batch) relPayload(k int, cseq uint32) []byte {
	panic("unimplemented: M2")
}

// addRelRetx appends a retransmission of an outstanding REL: a new outer
// REL frame (its own fseq at seal) around p, a payload relPayload returned
// in an earlier round (copied into the arena, byte-identical: PA-21). It
// takes no REL room; false when the batch is full.
func (b *Batch) addRelRetx(p []byte) bool {
	panic("unimplemented: M2")
}

// addRack appends a RACK (carrier level, handle 0); false when the batch
// is full.
func (b *Batch) addRack(r *wire.Rack) bool {
	panic("unimplemented: M2")
}

// nextDatagram returns the end (exclusive) of the sealed frames [i, end)
// that form the next datagram under the packing rules of M2-D12 for frame
// budget budget — frames whole and in insertion order; at most one DGRAM,
// as the last frame; a padded PING or PONG alone — and its length in rendr
// bytes. i < end always: a single frame above budget (only after a budget
// shrink) forms a datagram of its own, which the transport then refuses.
func (b *Batch) nextDatagram(i, budget int) (end, n int) {
	panic("unimplemented: M2")
}

// appendDatagram appends the wire bytes of the sealed frames [i, end) to
// dst — arena runs and DGRAM bodies copied once — and returns dst. With
// cap(dst) ≥ len(dst) + n it allocates nothing.
func (b *Batch) appendDatagram(dst []byte, i, end int) []byte {
	panic("unimplemented: M2")
}
