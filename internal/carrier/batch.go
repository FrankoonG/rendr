package carrier

import (
	"net"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Batch limits (plan §3.8).
const (
	// MaxBatchFrames bounds the frames of one batch.
	MaxBatchFrames = 64
	// ControlArena bounds the control-frame payload bytes of one batch.
	ControlArena = 8 << 10
)

const (
	// defaultBatchBudget is the DATA payload budget NewBatch uses for a
	// non-positive argument (Timing.BatchBudget's default).
	defaultBatchBudget = 256 << 10
	// arenaSize holds every control payload (≤ ControlArena) plus, for each
	// frame, its header, DATA offset and trailer, so the per-frame bytes
	// never compete with control payloads for room.
	arenaSize = ControlArena + MaxBatchFrames*(wire.DataHeadLen+wire.TrailerLen)
)

// zeroPad is the zero padding a padded PING or PONG references instead of
// copying it into the arena (a PONG echoes the peer's pad length, which may
// exceed ControlArena).
var zeroPad [wire.MaxPingPad]byte

// bframe is one appended frame. Its header, in-arena payload part (control
// payload, or DATA's 8-byte offset) and trailer occupy
// arena[head : head+HeaderLen+ctl+TrailerLen] in that order; a frame with a
// body (DATA bytes or PING/PONG padding) goes on the wire as header ‖
// in-arena part ‖ body ‖ trailer, so the arena is split at the body.
type bframe struct {
	hdr   wire.Header // Type, Flags, Len, Handle; Fseq once sealed
	head  int32       // arena offset of the header
	ctl   int32       // in-arena payload bytes after the header
	off   uint64      // DATA: stream offset
	body  []byte      // DATA bytes (alias chunk.B) or zero padding (alias zeroPad)
	chunk *Buf        // DATA: the referenced chunk until ReleaseRefs
	retx  bool        // DATA: retransmitted bytes
}

// Batch is the writer-owned, reused set of frames of one physical write.
// The endpoint fills it under the session lock with cheap bookkeeping only;
// the writer then stamps fseq, encodes headers, computes CRC32C and writes,
// all outside every lock. Frames are written in insertion order. A Batch
// allocates nothing in steady state.
//
// Each round is Reset → (carrier control, Endpoint.Fill) → encode and write
// → ReleaseRefs. NewBatch, Reset, Frame, WakeTime and CapBlocked also let
// package session drive Endpoint.Fill directly in its tests and inspect
// exactly what was appended (design §16.2 WP4).
type Batch struct {
	now        time.Time
	wake       time.Time
	capBlocked bool

	budget int // DATA payload bytes allowed per round
	data   int // DATA payload bytes added this round
	retx   int // retransmitted DATA payload bytes added this round
	ctl    int // control payload bytes added this round (≤ ControlArena)
	bodies int // body bytes (DATA and padding) added this round
	used   int // arena bytes used this round
	n      int // frames

	frames [MaxBatchFrames]bframe
	arena  []byte
}

// NewBatch returns an empty batch whose DATA payload budget is budget bytes
// (Timing.BatchBudget). The writer keeps one per Conn for its whole life.
// A non-positive budget selects the default of 256 KiB.
func NewBatch(budget int) *Batch {
	if budget <= 0 {
		budget = defaultBatchBudget
	}
	return &Batch{budget: budget, arena: make([]byte, arenaSize)}
}

// Reset starts a new round at now: it releases every chunk reference the
// batch still holds (as ReleaseRefs), empties it, and clears the WakeAt
// request and the cap-blocked mark.
func (b *Batch) Reset(now time.Time) {
	b.ReleaseRefs()
	clear(b.frames[:b.n])
	b.n, b.data, b.retx, b.ctl, b.bodies, b.used = 0, 0, 0, 0, 0, 0
	b.now, b.wake, b.capBlocked = now, time.Time{}, false
}

// ReleaseRefs releases the chunk references taken by AddData. The writer
// calls it as soon as the physical write returned; it is idempotent within
// a round. A batch whose write is still inside an embedder call keeps its
// references (the abandoned-call rule, design §4.1). After it, Frame no
// longer reports the DATA bodies (their memory may be recycled).
func (b *Batch) ReleaseRefs() {
	for i := range b.frames[:b.n] {
		f := &b.frames[i]
		if f.hdr.Type != wire.TypeData {
			continue
		}
		if f.chunk != nil {
			f.chunk.Release()
			f.chunk = nil
		}
		f.body = nil
	}
}

// BatchFrame is a read-only view of one appended frame (tests and
// diagnostics; the writer encodes from the batch's own state).
type BatchFrame struct {
	Header  wire.Header // Type, Flags, Handle and Len (payload length, the DATA offset included); Fseq is 0 until the writer stamps it
	Off     uint64      // DATA: stream offset
	Body    []byte      // DATA: the bytes (alias Chunk.B)
	Chunk   *Buf        // DATA: the referenced send chunk
	Retx    bool        // DATA: retransmitted bytes
	Payload []byte      // control frames: the encoded payload (aliases the batch arena; valid until Reset)
}

// Frame returns frame i (0 ≤ i < Len()) in insertion order. A padded PING
// or PONG reports its fixed 20-byte part as Payload and its zero padding as
// Body.
func (b *Batch) Frame(i int) BatchFrame {
	if i < 0 || i >= b.n {
		panic("rendr/carrier: Batch.Frame index out of range")
	}
	f := &b.frames[i]
	if f.hdr.Type == wire.TypeData {
		return BatchFrame{Header: f.hdr, Off: f.off, Body: f.body, Chunk: f.chunk, Retx: f.retx}
	}
	start := int(f.head) + wire.HeaderLen
	end := start + int(f.ctl)
	return BatchFrame{Header: f.hdr, Body: f.body, Payload: b.arena[start:end:end]}
}

// WakeTime returns the earliest WakeAt request of this round (zero if none).
func (b *Batch) WakeTime() time.Time {
	return b.wake
}

// CapBlocked reports whether MarkCapBlocked was called in this round.
func (b *Batch) CapBlocked() bool {
	return b.capBlocked
}

// Now is the time passed to Reset for this round (the writer takes one
// time.Now per batch); Fill uses it for ACK-delay decisions.
func (b *Batch) Now() time.Time {
	return b.now
}

// Len returns the number of frames in the batch.
func (b *Batch) Len() int {
	return b.n
}

// Room returns the DATA payload bytes still allowed in this batch
// (Timing.BatchBudget minus DATA already added); control frames do not
// count against it.
func (b *Batch) Room() int {
	return b.budget - b.data
}

// Full reports that no further frame of any kind fits (frame count or
// control arena exhausted): the frame limit is reached, or the control
// arena and the DATA budget are both used up.
func (b *Batch) Full() bool {
	return b.n >= MaxBatchFrames || (b.ctl >= ControlArena && b.data >= b.budget)
}

// AddOpenAck appends an OPEN_ACK frame; false if the batch is full.
func (b *Batch) AddOpenAck(handle uint32, a *wire.OpenAck) bool {
	n := wire.OpenAckFixedLen
	if a.Status != wire.StatusOK {
		n += len(a.Msg)
	}
	if len(a.Msg) > wire.MaxMsg {
		panic("rendr/carrier: OPEN_ACK message beyond wire.MaxMsg")
	}
	p, ok := b.addSession(wire.TypeOpenAck, 0, handle, n)
	if ok {
		wire.PutOpenAck(p, a)
	}
	return ok
}

// AddJoinAck appends a JOIN_ACK frame; false if the batch is full.
func (b *Batch) AddJoinAck(handle uint32, a *wire.JoinAck) bool {
	p, ok := b.addSession(wire.TypeJoinAck, 0, handle, wire.JoinAckLen)
	if ok {
		wire.PutJoinAck(p, a)
	}
	return ok
}

// AddAck appends an ACK frame with header flags (FlagAckFinDelivered,
// FlagAckDone); false if the batch is full.
func (b *Batch) AddAck(handle uint32, flags uint8, a *wire.Ack) bool {
	if flags&^wire.AllowedFlags(wire.TypeAck) != 0 {
		panic("rendr/carrier: undefined ACK flags")
	}
	p, ok := b.addSession(wire.TypeAck, flags, handle, wire.AckLen)
	if ok {
		wire.PutAck(p, a)
	}
	return ok
}

// AddFin appends a FIN frame at stream offset off; false if the batch is full.
func (b *Batch) AddFin(handle uint32, off uint64) bool {
	p, ok := b.addSession(wire.TypeFin, 0, handle, wire.FinLen)
	if ok {
		wire.PutFin(p, off)
	}
	return ok
}

// AddRst appends an RST frame; false if the batch is full.
func (b *Batch) AddRst(handle uint32, r *wire.Rst) bool {
	if len(r.Msg) > wire.MaxMsg {
		panic("rendr/carrier: RST message beyond wire.MaxMsg")
	}
	p, ok := b.addSession(wire.TypeRst, 0, handle, wire.RstFixedLen+len(r.Msg))
	if ok {
		wire.PutRst(p, r)
	}
	return ok
}

// AddSched appends a SCHED frame carrying cause in its flags; false if the
// batch is full.
func (b *Batch) AddSched(handle uint32, cause wire.SchedCause, s *wire.Sched) bool {
	if uint8(cause)&^wire.SchedCauseMask != 0 {
		panic("rendr/carrier: SCHED cause outside wire.SchedCauseMask")
	}
	if s.N < 1 || s.N > wire.MaxSchedIDs {
		panic("rendr/carrier: SCHED carrier count outside 1..wire.MaxSchedIDs")
	}
	p, ok := b.addSession(wire.TypeSched, uint8(cause), handle, wire.SchedFixedLen+4*s.N)
	if ok {
		wire.PutSched(p, s)
	}
	return ok
}

// AddData appends one DATA frame for stream offset off whose bytes body
// alias chunk.B (never copied on an OwnedTCP; copied once into the
// coalescing scratch otherwise). It takes a reference on chunk that the
// writer releases after the physical write returned, so the chunk cannot be
// recycled while the write may still read it (L17, L43). retx marks
// retransmitted bytes (RetxBytes). It returns false, adding nothing, when
// len(body) > Room() or the batch is full; len(body) must be ≥ 1. A nil
// chunk (tests) takes no reference.
func (b *Batch) AddData(handle uint32, off uint64, body []byte, chunk *Buf, retx bool) bool {
	if len(body) == 0 || len(body) > wire.MaxFramePayload-wire.DataPrefixLen {
		panic("rendr/carrier: DATA body length outside 1..MaxFramePayload-8")
	}
	if handle == 0 {
		panic("rendr/carrier: session frame with handle 0")
	}
	if b.n >= MaxBatchFrames || len(body) > b.budget-b.data {
		return false
	}
	if chunk != nil {
		chunk.Ref()
	}
	f, p := b.reserve(wire.TypeData, 0, handle, wire.DataPrefixLen, len(body))
	wire.PutDataOffset(p, off)
	f.off, f.body, f.chunk, f.retx = off, body, chunk, retx
	b.data += len(body)
	b.bodies += len(body)
	if retx {
		b.retx += len(body)
	}
	return true
}

// MarkCapBlocked records that pullable data remained for this carrier
// because it reached its capacity cap: the writer counts the time until
// the next Fill that pulls data as backlog (§4.10) and requests a cap-hit
// PING if none was sent since the carrier's last DATA. While the last round
// was cap-blocked, a matched PONG that advances the PONG watermark wakes
// the writer, so release is clocked by the RTT, not by the PING timer
// (design §4.10, R13).
func (b *Batch) MarkCapBlocked() {
	b.capBlocked = true
}

// WakeAt asks the writer to run Fill again at t even if nothing wakes it
// (the earliest request of a round wins). A zero t is ignored.
func (b *Batch) WakeAt(t time.Time) {
	if !t.IsZero() && (b.wake.IsZero() || t.Before(b.wake)) {
		b.wake = t
	}
}

// addSession reserves a session control frame (non-zero handle) with an
// n-byte payload in the arena; ok is false when the frame count or the
// control arena is exhausted.
func (b *Batch) addSession(t wire.Type, flags uint8, handle uint32, n int) (p []byte, ok bool) {
	if handle == 0 {
		panic("rendr/carrier: session frame with handle 0")
	}
	return b.addControl(t, flags, handle, n)
}

// addControl reserves a control frame whose whole n-byte payload lives in
// the arena.
func (b *Batch) addControl(t wire.Type, flags uint8, handle uint32, n int) (p []byte, ok bool) {
	if b.n >= MaxBatchFrames || b.ctl+n > ControlArena {
		return nil, false
	}
	_, p = b.reserve(t, flags, handle, n, 0)
	b.ctl += n
	return p, true
}

// reserve appends a frame record and lays out its header, in-arena payload
// part (ctl bytes, returned for encoding) and trailer at the arena's end.
// The caller checked the frame count; the arena is sized so that it always
// has room (arenaSize).
func (b *Batch) reserve(t wire.Type, flags uint8, handle uint32, ctl, body int) (*bframe, []byte) {
	f := &b.frames[b.n]
	b.n++
	head := b.used
	b.used += wire.HeaderLen + ctl + wire.TrailerLen
	*f = bframe{
		hdr:  wire.Header{Type: t, Flags: flags, Len: uint32(ctl + body), Handle: handle},
		head: int32(head),
		ctl:  int32(ctl),
	}
	start := head + wire.HeaderLen
	return f, b.arena[start : start+ctl : start+ctl]
}

// The carrier writer's side of a batch (design §4.8): carrier control
// frames, sealing (fseq, headers, CRC32C trailers) and the two physical
// write shapes. These run on the writer goroutine only, in the order
// Reset → add → seal → appendBuffers or appendTo → write → ReleaseRefs
// (ReleaseRefs drops the DATA bodies, so a write shape built after it
// would lack them).

// addPing appends a PING (FlagPingBusy when busy) with p's id, timestamp,
// nonce and padding; false if the batch is full.
func (b *Batch) addPing(busy bool, p *wire.Ping) bool {
	var flags uint8
	if busy {
		flags = wire.FlagPingBusy
	}
	return b.addPingFrame(wire.TypePing, flags, p)
}

// addPong appends the PONG answering PING payload p (same id, timestamp,
// nonce and pad length; flags 0); false if the batch is full.
func (b *Batch) addPong(p *wire.Ping) bool {
	return b.addPingFrame(wire.TypePong, 0, p)
}

func (b *Batch) addPingFrame(t wire.Type, flags uint8, p *wire.Ping) bool {
	if p.Pad < 0 || p.Pad > wire.MaxPingPad {
		panic("rendr/carrier: PING pad outside 0..wire.MaxPingPad")
	}
	if b.n >= MaxBatchFrames || b.ctl+wire.PingFixedLen > ControlArena {
		return false
	}
	f, dst := b.reserve(t, flags, 0, wire.PingFixedLen, p.Pad)
	fixed := *p
	fixed.Pad = 0
	wire.PutPing(dst, &fixed)
	b.ctl += wire.PingFixedLen
	if p.Pad > 0 {
		f.body = zeroPad[:p.Pad]
		b.bodies += p.Pad
	}
	return true
}

// addClose appends CLOSE(reason); false if the batch is full.
func (b *Batch) addClose(r wire.CloseReason) bool {
	p, ok := b.addControl(wire.TypeClose, 0, 0, wire.ReasonLen)
	if ok {
		wire.PutReason(p, uint8(r))
	}
	return ok
}

// addGoAway appends GOAWAY(reason); false if the batch is full.
func (b *Batch) addGoAway(r wire.GoAwayReason) bool {
	p, ok := b.addControl(wire.TypeGoAway, 0, 0, wire.ReasonLen)
	if ok {
		wire.PutReason(p, uint8(r))
	}
	return ok
}

// seal stamps consecutive fseq values starting at fseq (wrapping) on the
// frames in insertion order, writes every header and every CRC32C trailer
// (chained over header, in-arena payload and body without copying), and
// returns the fseq that follows the last frame. It reads the referenced
// bodies and writes only the batch's own arena, so it runs outside every
// lock. A DATA body changed after seal no longer matches its trailer: the
// receiver kills the carrier instead of accepting altered bytes (L43).
func (b *Batch) seal(fseq uint32) uint32 {
	for i := range b.frames[:b.n] {
		f := &b.frames[i]
		f.hdr.Fseq = fseq
		fseq++
		h := int(f.head)
		wire.PutHeader(b.arena[h:], &f.hdr)
		end := h + wire.HeaderLen + int(f.ctl)
		crc := wire.CRC(b.arena[h:end])
		if len(f.body) > 0 {
			crc = wire.CRCUpdate(crc, f.body)
		}
		wire.PutTrailer(b.arena[end:], crc)
	}
	return fseq
}

// wireLen returns the bytes of the batch on the wire.
func (b *Batch) wireLen() int {
	return b.used + b.bodies
}

// dataBytes returns the DATA payload bytes of this round (bodies only, the
// offset prefixes excluded); retxBytes the retransmitted part of them.
func (b *Batch) dataBytes() int { return b.data }

func (b *Batch) retxBytes() int { return b.retx }

// appendBuffers appends the sealed batch to bufs as a vector of slices in
// wire order — arena runs and bodies alternately: arena part₁, body₁, arena
// part₂, … — for the zero-copy vectored write of an OwnedTCP (design §4.8).
// With a reused backing array of capacity 2·MaxBatchFrames+1 it allocates
// nothing.
func (b *Batch) appendBuffers(bufs net.Buffers) net.Buffers {
	seg := 0
	for i := range b.frames[:b.n] {
		f := &b.frames[i]
		if len(f.body) == 0 {
			continue
		}
		cut := int(f.head) + wire.HeaderLen + int(f.ctl)
		bufs = append(bufs, b.arena[seg:cut], f.body)
		seg = cut
	}
	if seg < b.used {
		bufs = append(bufs, b.arena[seg:b.used])
	}
	return bufs
}

// appendTo appends the sealed batch's wire bytes to dst: the single
// coalesced Write every conn other than an OwnedTCP gets (a TLS carrier
// emits one record per batch, and the embedder never sees retransmission
// memory, L43). With cap(dst) ≥ len(dst)+wireLen() it allocates nothing.
func (b *Batch) appendTo(dst []byte) []byte {
	seg := 0
	for i := range b.frames[:b.n] {
		f := &b.frames[i]
		if len(f.body) == 0 {
			continue
		}
		cut := int(f.head) + wire.HeaderLen + int(f.ctl)
		dst = append(dst, b.arena[seg:cut]...)
		dst = append(dst, f.body...)
		seg = cut
	}
	return append(dst, b.arena[seg:b.used]...)
}
