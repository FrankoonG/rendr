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
