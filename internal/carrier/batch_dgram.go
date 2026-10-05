package carrier

import (
	"encoding/binary"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

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
//
// Every frame of a datagram batch is a whole outer frame: a REL frame is a
// carrier-level control frame (handle 0) whose arena payload is the REL
// payload — cseq u32 · itype u8 · iflags u8 · ihandle u32 · ipayload — and
// a DGRAM is laid out as DATA is: header ‖ seq ‖ referenced body ‖
// trailer. Nothing here allocates.

// SetDatagram puts the batch in datagram mode for this round: frameBudget
// is the carrier's current send budget (Conn.MTU), relRoom the REL frames
// it may still place (wire.RelWindow minus those outstanding). Reset ends
// datagram mode. The writer calls it; session tests call it to drive Fill
// on a datagram batch. It must be called on an empty batch, right after
// Reset: a frame reserved before it would not be REL-wrapped. It panics
// on a batch that holds frames, a budget outside 0…wire.MaxDatagram or a
// REL room outside 0…wire.RelWindow (programming errors).
func (b *Batch) SetDatagram(frameBudget, relRoom int) {
	if b.n != 0 {
		panic("rendr/carrier: SetDatagram on a batch that already holds frames")
	}
	if frameBudget < 0 || frameBudget > wire.MaxDatagram {
		panic("rendr/carrier: SetDatagram frame budget outside 0..wire.MaxDatagram")
	}
	if relRoom < 0 || relRoom > wire.RelWindow {
		panic("rendr/carrier: SetDatagram REL room outside 0..wire.RelWindow")
	}
	b.dgram, b.frameBudget, b.relRoom = true, frameBudget, relRoom
}

// Datagram reports whether the batch is in datagram mode this round.
func (b *Batch) Datagram() bool {
	return b.dgram
}

// DgramRoom returns the largest application datagram AddDgram still takes:
// in datagram mode the frame budget minus wire.DgramOverhead (each DGRAM
// travels as the last frame of a datagram of its own, so the value depends
// on the carrier's budget, never on what the batch already holds); in
// stream mode min(Room(), wire.MaxPacketPayload), counting DGRAM bytes as
// DATA (M2-D26). Neither value reports a full batch — AddDgram refuses
// that — so a datagram above DgramRoom in datagram mode means the budget
// shrank below it (M2-D45), never that the batch filled up.
func (b *Batch) DgramRoom() int {
	if b.dgram {
		return max(b.frameBudget-wire.DgramOverhead, 0)
	}
	return min(b.Room(), wire.MaxPacketPayload)
}

// RelRoom returns the REL frames a reliable Add* may still reserve this
// round (datagram mode); 0 in stream mode (nothing is wrapped). It counts
// the REL window only: a reliable Add* can still fail on a full batch while
// RelRoom is positive, and a stream batch reports 0 whatever it holds, so a
// caller that asks why a reliable frame was refused tests Datagram() too
// (only a datagram batch refuses for lack of REL room; R1-17).
func (b *Batch) RelRoom() int {
	if !b.dgram {
		return 0
	}
	return b.relRoom - b.nrel
}

// AddDgram appends one DGRAM: seq ‖ body, where body references packet
// queue storage held by ref (one Buf reference per (batch, chunk), released
// by ReleaseRefs; nil ref takes none). An empty body is legal. On a stream
// batch body counts against Room() and as DATA (submitted, capacity, byte
// clock: M2-D26); on a datagram batch it travels as the last frame of its
// own datagram (M2-D12). False when the batch is full or body exceeds
// DgramRoom(). It panics on handle 0 or a body above
// wire.MaxPacketPayload (programming errors: no session accepts one).
func (b *Batch) AddDgram(handle uint32, seq uint64, body []byte, ref *Buf) bool {
	if len(body) > wire.MaxPacketPayload {
		panic("rendr/carrier: DGRAM body beyond wire.MaxPacketPayload")
	}
	if handle == 0 {
		panic("rendr/carrier: session frame with handle 0")
	}
	if b.Full() || len(body) > b.DgramRoom() {
		return false
	}
	took := b.holdRef(ref)
	f, p := b.reserve(wire.TypeDgram, 0, handle, wire.DgramPrefixLen, len(body))
	wire.PutDgramSeq(p, seq)
	f.off, f.body, f.chunk, f.ref = seq, body, ref, took
	b.bodies += len(body)
	b.dgBytes += len(body)
	if !b.dgram {
		b.data += len(body) // DATA on a stream carrier (M2-D26)
	}
	return true
}

// holdRef makes sure the batch holds a reference on ref for a DGRAM body:
// one per (batch, chunk) (M2 design §A4.5), checked against the chunk of
// the latest DGRAM first (consecutive datagrams share a chunk), then
// against the earlier DGRAMs of the round. It reports whether this call
// took the reference (the frame that took it releases it). A nil ref takes
// none.
func (b *Batch) holdRef(ref *Buf) bool {
	if ref == nil || ref == b.lastRef {
		return false
	}
	b.lastRef = ref
	for i := b.n - 1; i >= 0; i-- {
		if f := &b.frames[i]; f.ref && f.chunk == ref {
			return false
		}
	}
	ref.Ref()
	return true
}

// AddPack appends a PACK with header flags (wire.FlagPackFinDelivered,
// wire.FlagPackDone). reliable asks for REL wrapping in datagram mode (a
// PACK with flags is always wrapped there; M2-D39); false when the batch is
// full or no REL room is left for a wrapped one. A stream batch carries
// every PACK as an ordinary frame.
func (b *Batch) AddPack(handle uint32, flags uint8, p *wire.Pack, reliable bool) bool {
	if flags&^(wire.FlagPackFinDelivered|wire.FlagPackDone) != 0 {
		panic("rendr/carrier: undefined PACK flags")
	}
	var q []byte
	var ok bool
	if b.dgram && (reliable || flags != 0) {
		q, ok = b.addSessionRel(wire.TypePack, flags, handle, wire.PackLen)
	} else {
		q, ok = b.addSession(wire.TypePack, flags, handle, wire.PackLen)
	}
	if ok {
		wire.PutPack(q, p)
	}
	return ok
}

// addReliable reserves a reliable control frame of type t with an n-byte
// payload and returns that payload for encoding: on a stream batch the
// ordinary frame (addControl); on a datagram batch a REL frame around it
// (outer header REL, handle 0) whose REL payload is the head — cseq 0
// until relPayload stamps it, itype t, iflags, ihandle — followed by the
// inner payload. ok is false when the frame count or the control arena is
// exhausted or, on a datagram batch, the round's REL room is used (then
// relRefused reports it). It panics on a REL payload above
// wire.RelMaxPayload (only OPEN and JOIN, which travel in the handshake's
// first datagram, could be that large).
func (b *Batch) addReliable(t wire.Type, flags uint8, handle uint32, n int) (p []byte, ok bool) {
	if !b.dgram {
		return b.addControl(t, flags, handle, n)
	}
	if b.nrel >= b.relRoom {
		b.relBlocked = true
		return nil, false
	}
	m := wire.RelHeadLen + n
	if m > wire.RelMaxPayload {
		panic("rendr/carrier: REL payload beyond wire.RelMaxPayload")
	}
	q, ok := b.addControl(wire.TypeRel, 0, 0, m)
	if !ok {
		return nil, false
	}
	wire.PutRelHead(q, &wire.RelHead{Type: t, Flags: flags, Handle: handle})
	b.relIdx[b.nrel] = uint8(b.n - 1)
	b.nrel++
	return q[wire.RelHeadLen:], true
}

// relInner returns the inner frame header a REL payload p carries (M2
// design §A3.3: cseq u32 · itype u8 · iflags u8 · ihandle u32 · ipayload):
// type, flags, handle and the inner payload length (Frame's view).
func relInner(p []byte) wire.Header {
	return wire.Header{
		Type:   wire.Type(p[4]),
		Flags:  p[5],
		Len:    uint32(len(p) - wire.RelHeadLen),
		Handle: binary.BigEndian.Uint32(p[6:10]),
	}
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
	return b.nrel
}

// relPayload stamps cseq on the k-th new REL frame (0 ≤ k < relCount(),
// insertion order) and returns its REL payload — cseq · itype · iflags ·
// ihandle · ipayload, at most wire.RelMaxPayload bytes, aliasing the arena
// until Reset — which relSeal copies into the send slot.
func (b *Batch) relPayload(k int, cseq uint32) []byte {
	if k < 0 || k >= b.nrel {
		panic("rendr/carrier: relPayload index out of range")
	}
	f := &b.frames[b.relIdx[k]]
	start := int(f.head) + wire.HeaderLen
	end := start + int(f.ctl)
	p := b.arena[start:end:end]
	binary.BigEndian.PutUint32(p[0:4], cseq) // the REL payload starts with its cseq (§A3.3)
	b.relStamped |= 1 << k
	return p
}

// addRelRetx appends a retransmission of an outstanding REL: a new outer
// REL frame (its own fseq at seal) around p, a payload relPayload returned
// in an earlier round (copied into the arena, byte-identical: PA-21). It
// takes no REL room; false when the batch is full. It panics on a stream
// batch or a payload outside wire.RelHeadLen…wire.RelMaxPayload.
func (b *Batch) addRelRetx(p []byte) bool {
	if !b.dgram {
		panic("rendr/carrier: REL retransmission on a stream batch")
	}
	if len(p) < wire.RelHeadLen || len(p) > wire.RelMaxPayload {
		panic("rendr/carrier: REL payload length outside wire.RelHeadLen..wire.RelMaxPayload")
	}
	q, ok := b.addControl(wire.TypeRel, 0, 0, len(p))
	if ok {
		copy(q, p)
	}
	return ok
}

// addRack appends a RACK (carrier level, handle 0); false when the batch
// is full. It panics on a stream batch (RACK exists on datagram carriers
// only).
func (b *Batch) addRack(r *wire.Rack) bool {
	if !b.dgram {
		panic("rendr/carrier: RACK on a stream batch")
	}
	q, ok := b.addControl(wire.TypeRack, 0, 0, wire.RackLen)
	if ok {
		wire.PutRack(q, r)
	}
	return ok
}

// nextDatagram returns the end (exclusive) of the sealed frames [i, end)
// that form the next datagram under the packing rules of M2-D12 for frame
// budget budget — frames whole and in insertion order; at most one DGRAM,
// as the last frame; a padded PING or PONG alone — and its length in rendr
// bytes. i < end always: a single frame above budget (only after a budget
// shrink) forms a datagram of its own, which the transport then refuses.
// A new datagram starts when the next frame does not fit the budget, when
// the current one ends with a DGRAM, or when the next frame or the previous
// one travels alone. It panics unless 0 ≤ i < Len().
func (b *Batch) nextDatagram(i, budget int) (end, n int) {
	if i < 0 || i >= b.n {
		panic("rendr/carrier: nextDatagram index out of range")
	}
	for end = i; end < b.n; {
		f := &b.frames[end]
		size := wire.FrameOverhead + int(f.hdr.Len)
		alone := f.alone()
		if end > i && (alone || n+size > budget) {
			break
		}
		n += size
		end++
		if alone || f.hdr.Type == wire.TypeDgram {
			break
		}
	}
	return end, n
}

// alone reports whether f travels in a datagram of its own: a padded PING
// or PONG — an MTU probe or the PONG answering one (M2-D12, M2-D24).
func (f *bframe) alone() bool {
	return (f.hdr.Type == wire.TypePing || f.hdr.Type == wire.TypePong) && f.hdr.Len > wire.PingFixedLen
}

// appendDatagram appends the wire bytes of the sealed frames [i, end) to
// dst — arena runs and DGRAM bodies copied once — and returns dst. With
// cap(dst) ≥ len(dst) + n it allocates nothing. It runs before ReleaseRefs
// (which drops the DGRAM bodies) and panics unless 0 ≤ i < end ≤ Len().
func (b *Batch) appendDatagram(dst []byte, i, end int) []byte {
	if i < 0 || end > b.n || i >= end {
		panic("rendr/carrier: appendDatagram range out of bounds")
	}
	seg := int(b.frames[i].head)
	last := &b.frames[end-1]
	stop := int(last.head) + wire.HeaderLen + int(last.ctl) + wire.TrailerLen
	for k := i; k < end; k++ {
		f := &b.frames[k]
		if len(f.body) == 0 {
			continue
		}
		cut := int(f.head) + wire.HeaderLen + int(f.ctl)
		dst = append(dst, b.arena[seg:cut]...)
		dst = append(dst, f.body...)
		seg = cut
	}
	return append(dst, b.arena[seg:stop]...)
}

// Writer-side helpers beyond the contract names (WP3c; used by the datagram
// writer as it needs them).

// datagramDgram reports whether the datagram whose last frame is end − 1
// carries a DGRAM — always its last frame (M2-D12) — and that DGRAM's
// application bytes (Stats.TxBytes, Refused). Valid after ReleaseRefs too.
func (b *Batch) datagramDgram(end int) (n int, ok bool) {
	f := &b.frames[end-1]
	if f.hdr.Type != wire.TypeDgram {
		return 0, false
	}
	return int(f.hdr.Len) - wire.DgramPrefixLen, true
}

// dgramBytes returns the DGRAM body bytes added this round, in both modes
// (on a stream batch dataBytes includes them as well; on a datagram batch
// it does not: nothing is submitted there, M2-D26).
func (b *Batch) dgramBytes() int {
	return b.dgBytes
}

// relRefused reports that a reliable Add* found no REL room this round:
// that frame stayed due in the session and only a RACK that frees room can
// let it out, so the writer marks its REL sender blocked (a RACK with
// progress then wakes it; M2 design §A5.9).
func (b *Batch) relRefused() bool {
	return b.relBlocked
}
