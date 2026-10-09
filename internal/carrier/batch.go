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
// payload, DATA's 8-byte offset or DGRAM's 8-byte seq) and trailer occupy
// arena[head : head+HeaderLen+ctl+TrailerLen] in that order; a frame with a
// body (DATA or DGRAM bytes, PING/PONG padding) goes on the wire as header ‖
// in-arena part ‖ body ‖ trailer, so the arena is split at the body. A REL
// frame (datagram mode) is a control frame whose in-arena payload is the
// whole REL payload: cseq · itype · iflags · ihandle · ipayload.
type bframe struct {
	hdr   wire.Header // Type, Flags, Len, Handle; Fseq once sealed (REL: the outer header)
	head  int32       // arena offset of the header
	ctl   int32       // in-arena payload bytes after the header
	off   uint64      // DATA: stream offset; DGRAM: session seq
	body  []byte      // DATA or DGRAM bytes (alias chunk.B) or zero padding (alias zeroPad)
	chunk *Buf        // DATA, DGRAM: the referenced chunk until ReleaseRefs
	retx  bool        // DATA: retransmitted bytes
	ref   bool        // DGRAM: this frame holds the batch's one reference on chunk
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
// exactly what was appended (design §16.2 WP4). On a datagram carrier the
// writer puts the batch in datagram mode for the round (SetDatagram,
// batch_dgram.go): reliable control frames are then reserved as REL frames
// and the sealed frames are packed into datagrams.
type Batch struct {
	now        time.Time
	wake       time.Time
	capBlocked bool

	budget  int // DATA payload bytes allowed per round
	data    int // DATA payload bytes added this round (DGRAM bytes too on a stream batch)
	retx    int // retransmitted DATA payload bytes added this round
	ctl     int // control payload bytes added this round (≤ ControlArena)
	bodies  int // body bytes (DATA, DGRAM and padding) added this round
	used    int // arena bytes used this round
	n       int // frames
	dgBytes int // DGRAM body bytes added this round (both modes)

	// The datagram mode of this round (batch_dgram.go; M2 design §A5.8):
	// set by SetDatagram, ended by Reset.
	dgram       bool
	frameBudget int                   // the carrier's send frame budget (DgramRoom)
	relRoom     int                   // new REL frames this round may reserve
	nrel        int                   // new REL frames reserved this round
	relIdx      [wire.RelWindow]uint8 // frame index of the k-th new REL
	relStamped  uint32                // bit k: relPayload stamped the k-th new REL's cseq
	relBlocked  bool                  // a reliable Add* found no REL room this round
	lastRef     *Buf                  // the chunk of the latest DGRAM reference taken this round

	// The payload quota of the current endpoint call (M3-D10; set by limit
	// before each endpoint call of a MUX writer round, cleared by Reset).
	quota   bool // a quota is in force
	ctlOnly bool // the quota is 0: control frames only
	qEnd    int  // payload() at which the quota ends
	taken   int  // payload() when the current call began (Taken)

	// The response hold of the current call (M3-D8): a passive view
	// admitted on a started trunk places nothing after its OK response
	// until the dialer's go frame. Set by the MUX writer around that view's
	// call; holdOn once the OK response for holdH was added.
	holdH  uint32
	holdOn bool

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
// batch still holds (as ReleaseRefs), empties it, clears the WakeAt
// request and the cap-blocked mark, and ends datagram mode.
func (b *Batch) Reset(now time.Time) {
	b.ReleaseRefs()
	clear(b.frames[:b.n])
	b.n, b.data, b.retx, b.ctl, b.bodies, b.used, b.dgBytes = 0, 0, 0, 0, 0, 0, 0
	b.now, b.wake, b.capBlocked = now, time.Time{}, false
	b.dgram, b.frameBudget, b.relRoom, b.nrel, b.relStamped, b.relBlocked = false, 0, 0, 0, 0, false
	b.quota, b.ctlOnly, b.qEnd, b.taken = false, false, 0, 0
	b.holdH, b.holdOn = 0, false
}

// ReleaseRefs releases the chunk references taken by AddData and AddDgram.
// The writer calls it as soon as the physical write returned (on a
// datagram carrier: after the last datagram of the batch); it is
// idempotent within a round. A batch whose write is still inside an
// embedder call keeps its references (the abandoned-call rule, design
// §4.1). After it, Frame no longer reports the DATA and DGRAM bodies (their
// memory may be recycled), and the write shapes would lack them.
func (b *Batch) ReleaseRefs() {
	for i := range b.frames[:b.n] {
		f := &b.frames[i]
		switch f.hdr.Type {
		case wire.TypeData:
			if f.chunk != nil {
				f.chunk.Release()
				f.chunk = nil
			}
			f.body = nil
		case wire.TypeDgram:
			if f.ref {
				f.chunk.Release()
				f.ref = false
			}
			f.chunk, f.body = nil, nil
		}
	}
	b.lastRef = nil
}

// BatchFrame is a read-only view of one appended frame (tests and
// diagnostics; the writer encodes from the batch's own state).
type BatchFrame struct {
	Header  wire.Header // Type, Flags, Handle and Len (payload length, the DATA offset or DGRAM seq included); Fseq is 0 until the writer stamps it
	Off     uint64      // DATA: stream offset
	Body    []byte      // DATA, DGRAM: the bytes (alias Chunk.B)
	Chunk   *Buf        // DATA: the referenced send chunk; DGRAM: the chunk passed to AddDgram
	Retx    bool        // DATA: retransmitted bytes
	Payload []byte      // control frames: the encoded payload (aliases the batch arena; valid until Reset)
	Seq     uint64      // DGRAM: the session seq (Body holds the datagram)
	Rel     bool        // a reliable control frame wrapped in REL on a datagram batch; Header is the inner header
}

// Frame returns frame i (0 ≤ i < Len()) in insertion order. A padded PING
// or PONG reports its fixed 20-byte part as Payload and its zero padding as
// Body. A REL frame (a reliable control frame of a datagram batch, or a
// retransmission) reports its inner frame — Header the inner type, flags,
// handle and payload length (Fseq: the outer frame's), Payload the inner
// payload — with Rel set, so Fill-level tests read a wrapped FIN exactly
// like a bare one.
func (b *Batch) Frame(i int) BatchFrame {
	if i < 0 || i >= b.n {
		panic("rendr/carrier: Batch.Frame index out of range")
	}
	f := &b.frames[i]
	switch f.hdr.Type {
	case wire.TypeData:
		return BatchFrame{Header: f.hdr, Off: f.off, Body: f.body, Chunk: f.chunk, Retx: f.retx}
	case wire.TypeDgram:
		return BatchFrame{Header: f.hdr, Seq: f.off, Body: f.body, Chunk: f.chunk}
	}
	start := int(f.head) + wire.HeaderLen
	end := start + int(f.ctl)
	p := b.arena[start:end:end]
	if f.hdr.Type == wire.TypeRel {
		h := relInner(p)
		h.Fseq = f.hdr.Fseq
		return BatchFrame{Header: h, Payload: p[wire.RelHeadLen:], Rel: true}
	}
	return BatchFrame{Header: f.hdr, Body: f.body, Payload: p}
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
// (Timing.BatchBudget minus DATA already added; on a stream batch DGRAM
// bytes count as DATA, M2-D26); control frames do not count against it.
// On a MUX trunk it is also bounded by the payload quota of the current
// endpoint call (M3-D10): 0 under a quota of 0 (ControlOnly).
func (b *Batch) Room() int {
	r := b.budget - b.data
	if b.quota {
		r = min(r, b.qEnd-b.payload())
	}
	return r
}

// payload returns the DATA and DGRAM payload bytes placed in this batch:
// DATA bytes (DGRAM bytes included) on a stream batch, DGRAM bytes on a
// datagram batch. The quota and Taken are measured in it.
func (b *Batch) payload() int {
	if b.dgram {
		return b.dgBytes
	}
	return b.data
}

// Full reports that no further frame of any kind fits (frame count or
// control arena exhausted). Every Add* refuses while Full is true, DATA
// and DGRAM included. Full false does not promise that a particular frame
// fits: AddData also needs len(body) ≤ Room(), AddDgram len(body) ≤
// DgramRoom(), a reliable frame of a datagram batch REL room, and a
// control frame needs room for its payload in the arena, so callers check
// every Add* result.
func (b *Batch) Full() bool {
	return b.n >= MaxBatchFrames || b.ctl >= ControlArena
}

// The reliable control frames — OPEN_ACK, JOIN_ACK, FIN, RST, SCHED, a
// reliable PACK (AddPack), CLOSE and GOAWAY — are REL frames on a datagram
// batch (M2-D7, plan:356): each of their Add* calls then also returns false
// when the round's REL room is used (RelRoom), so the frame stays due in
// the session (W5). On a stream batch they are ordinary frames.

// AddOpenAck appends an OPEN_ACK frame (REL on a datagram batch); false if
// the batch is full or no REL room is left.
func (b *Batch) AddOpenAck(handle uint32, a *wire.OpenAck) bool {
	n := wire.OpenAckFixedLen
	if a.Status != wire.StatusOK {
		n += len(a.Msg)
	}
	if len(a.Msg) > wire.MaxMsg {
		panic("rendr/carrier: OPEN_ACK message beyond wire.MaxMsg")
	}
	p, ok := b.addSessionRel(wire.TypeOpenAck, 0, handle, n)
	if ok {
		wire.PutOpenAck(p, a)
		b.heldBy(handle, a.Status)
	}
	return ok
}

// heldBy starts the response hold of the current call when its OK
// response for the held handle was added (M3-D8).
func (b *Batch) heldBy(handle uint32, st wire.AckStatus) {
	if handle == b.holdH && handle != 0 && st == wire.StatusOK {
		b.holdOn = true
	}
}

// heldOut reports a session frame of handle that the response hold keeps
// out of the batch.
func (b *Batch) heldOut(handle uint32) bool {
	return b.holdOn && handle == b.holdH
}

// AddJoinAck appends a JOIN_ACK frame (REL on a datagram batch); false if
// the batch is full or no REL room is left.
func (b *Batch) AddJoinAck(handle uint32, a *wire.JoinAck) bool {
	p, ok := b.addSessionRel(wire.TypeJoinAck, 0, handle, wire.JoinAckLen)
	if ok {
		wire.PutJoinAck(p, a)
		b.heldBy(handle, a.Status)
	}
	return ok
}

// AddAck appends an ACK frame with header flags (FlagAckFinDelivered,
// FlagAckDone); false if the batch is full. ACK belongs to stream sessions:
// it panics on a datagram batch (a packet session places PACK).
func (b *Batch) AddAck(handle uint32, flags uint8, a *wire.Ack) bool {
	if flags&^wire.AllowedFlags(wire.TypeAck) != 0 {
		panic("rendr/carrier: undefined ACK flags")
	}
	if b.dgram {
		panic("rendr/carrier: ACK on a datagram batch")
	}
	p, ok := b.addSession(wire.TypeAck, flags, handle, wire.AckLen)
	if ok {
		wire.PutAck(p, a)
	}
	return ok
}

// AddFin appends a FIN frame at stream offset off (a packet session: its
// final seq; REL on a datagram batch); false if the batch is full or no
// REL room is left.
func (b *Batch) AddFin(handle uint32, off uint64) bool {
	p, ok := b.addSessionRel(wire.TypeFin, 0, handle, wire.FinLen)
	if ok {
		wire.PutFin(p, off)
	}
	return ok
}

// AddRst appends an RST frame (REL on a datagram batch); false if the batch
// is full or no REL room is left.
func (b *Batch) AddRst(handle uint32, r *wire.Rst) bool {
	if len(r.Msg) > wire.MaxMsg {
		panic("rendr/carrier: RST message beyond wire.MaxMsg")
	}
	p, ok := b.addSessionRel(wire.TypeRst, 0, handle, wire.RstFixedLen+len(r.Msg))
	if ok {
		wire.PutRst(p, r)
	}
	return ok
}

// AddSched appends a SCHED frame carrying cause in its flags (REL on a
// datagram batch); false if the batch is full or no REL room is left.
func (b *Batch) AddSched(handle uint32, cause wire.SchedCause, s *wire.Sched) bool {
	if uint8(cause)&^wire.SchedCauseMask != 0 {
		panic("rendr/carrier: SCHED cause outside wire.SchedCauseMask")
	}
	if s.N < 1 || s.N > wire.MaxSchedIDs {
		panic("rendr/carrier: SCHED carrier count outside 1..wire.MaxSchedIDs")
	}
	p, ok := b.addSessionRel(wire.TypeSched, uint8(cause), handle, wire.SchedFixedLen+4*s.N)
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
// chunk (tests) takes no reference. DATA belongs to stream sessions: it
// panics on a datagram batch.
func (b *Batch) AddData(handle uint32, off uint64, body []byte, chunk *Buf, retx bool) bool {
	if len(body) == 0 || len(body) > wire.MaxFramePayload-wire.DataPrefixLen {
		panic("rendr/carrier: DATA body length outside 1..MaxFramePayload-8")
	}
	if handle == 0 {
		panic("rendr/carrier: session frame with handle 0")
	}
	if b.dgram {
		panic("rendr/carrier: DATA on a datagram batch")
	}
	if b.Full() || len(body) > b.Room() || b.ctlOnly || b.heldOut(handle) {
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

// Taken returns the DATA and DGRAM payload bytes earlier endpoint calls
// of this writer round placed in the batch (M3-D11): a view on a MUX trunk
// subtracts it from the shared capacity, Capacity() − Inflight() − Taken().
// Always 0 on a dedicated carrier, whose one endpoint fills the round.
func (b *Batch) Taken() int { return b.taken }

// ControlOnly reports that the current endpoint call runs under a payload
// quota of 0 — the MUX writer's control pass (M3-D10): the call places
// control frames only (AddData and AddDgram refuse, Room is 0), and by the
// Fill contract it changes no idleness and marks nothing cap-blocked
// (R1-1 rule 5; MarkCapBlocked is ignored meanwhile).
func (b *Batch) ControlOnly() bool { return b.ctlOnly }

// SetQuota sets the payload quota of the next endpoint call (limit). The
// MUX writer sets it around each view's Fill; package session tests call
// it to drive a Fill under a quota (TestFillQuotaZeroKeepsIdle).
func (b *Batch) SetQuota(q int) { b.limit(q) }

// limit sets the payload quota of the next endpoint call (M3-D10): Room
// then reports at most q more payload bytes and AddDgram refuses a body
// beyond it, and q == 0 lets the call place control frames only
// (ControlOnly). A negative q removes the quota. Either way the call's
// Taken is the payload placed so far. The MUX writer sets it around each
// view's Fill; a dedicated carrier never sets one.
//
// On a datagram batch DgramRoom keeps reporting the carrier's budget (the
// session reads a datagram above it as one the budget left behind, M2-D45),
// and the quota is enforced by AddDgram refusing, as on a full batch.
func (b *Batch) limit(q int) {
	b.taken = b.payload()
	if q < 0 {
		b.quota, b.ctlOnly = false, false
		return
	}
	b.quota, b.ctlOnly, b.qEnd = true, q == 0, b.taken+q
}

// MarkCapBlocked records that pullable data remained for this carrier
// because it reached its capacity cap: the writer counts the time until
// the next Fill that pulls data as backlog (§4.10) and requests a cap-hit
// PING if none was sent since the carrier's last DATA. While the last round
// was cap-blocked, a matched PONG that advances the PONG watermark wakes
// the writer, so release is clocked by the RTT, not by the PING timer
// (design §4.10, R13).
func (b *Batch) MarkCapBlocked() {
	if b.ctlOnly {
		return // a control pass decides nothing about capacity (R1-1 rule 5)
	}
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
	if b.heldOut(handle) {
		return nil, false
	}
	return b.addControl(t, flags, handle, n)
}

// addSessionRel is addSession for a reliable session frame: REL-wrapped on
// a datagram batch (addReliable).
func (b *Batch) addSessionRel(t wire.Type, flags uint8, handle uint32, n int) (p []byte, ok bool) {
	if handle == 0 {
		panic("rendr/carrier: session frame with handle 0")
	}
	if b.heldOut(handle) {
		return nil, false
	}
	return b.addReliable(t, flags, handle, n)
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
// would lack them). A datagram carrier's writer packs the sealed frames
// into datagrams instead (batch_dgram.go).

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

// pingFits reports whether a PING or PONG still fits: a frame slot and its
// fixed payload in the control arena (padding is a body, outside the arena).
func (b *Batch) pingFits() bool {
	return b.n < MaxBatchFrames && b.ctl+wire.PingFixedLen <= ControlArena
}

func (b *Batch) addPingFrame(t wire.Type, flags uint8, p *wire.Ping) bool {
	if p.Pad < 0 || p.Pad > wire.MaxPingPad {
		panic("rendr/carrier: PING pad outside 0..wire.MaxPingPad")
	}
	if !b.pingFits() {
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

// addClose appends CLOSE(reason) (REL on a datagram batch); false if the
// batch is full or no REL room is left.
func (b *Batch) addClose(r wire.CloseReason) bool {
	p, ok := b.addReliable(wire.TypeClose, 0, 0, wire.ReasonLen)
	if ok {
		wire.PutReason(p, uint8(r))
	}
	return ok
}

// addGoAway appends GOAWAY(reason) (REL on a datagram batch); false if the
// batch is full or no REL room is left.
func (b *Batch) addGoAway(r wire.GoAwayReason) bool {
	p, ok := b.addReliable(wire.TypeGoAway, 0, 0, wire.ReasonLen)
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
// lock. A DATA or DGRAM body changed after seal no longer matches its
// trailer: the receiver never accepts the altered bytes (L43; a stream
// carrier is killed, a datagram carrier drops the rest of the datagram,
// PA-1). On a datagram batch every frame — a REL around its stamped REL
// payload, a DGRAM over seq ‖ datagram — is an outer frame of its own,
// sealed the same way; every new REL must carry its cseq first
// (relPayload), else seal panics: an unstamped REL would leave with a cseq
// the sender never tracks.
func (b *Batch) seal(fseq uint32) uint32 {
	if b.relStamped != uint32(1)<<b.nrel-1 {
		panic("rendr/carrier: a new REL frame sealed before relPayload stamped its cseq")
	}
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
// offset prefixes excluded) — on a stream batch the DGRAM bytes too
// (M2-D26), on a datagram batch none of them; retxBytes the retransmitted
// part of them.
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

// The MUX writer's own frames (M3 design §A5.3, §A3.4): DETACH, the first
// frame of a view opened on a live trunk, a refusal answer of the refusal
// ring and a view's last frame (WriteAndClose). They run on the writer
// goroutine like the carrier control frames.

// addDetach appends DETACH(h, r) (carrier level; REL on a datagram batch);
// false if the batch is full or no REL room is left.
func (b *Batch) addDetach(h uint32, r wire.DetachReason) bool {
	p, ok := b.addReliable(wire.TypeDetach, 0, 0, wire.DetachLen)
	if ok {
		wire.PutDetach(p, &wire.Detach{Handle: h, Reason: r})
	}
	return ok
}

// addFirst appends the first frame (OPEN or JOIN, type t) of view h with
// payload p. On a stream batch the payload is referenced as a body (an OPEN
// may carry up to wire.MaxMetadata bytes of metadata, beyond the control
// arena; p must stay unchanged until the round's write returned); on a
// datagram batch it is a REL frame (openView bounds it by
// wire.RelMaxPayload). False if the batch is full or no REL room is left.
func (b *Batch) addFirst(t wire.Type, h uint32, p []byte) bool {
	if b.dgram {
		q, ok := b.addSessionRel(t, 0, h, len(p))
		if ok {
			copy(q, p)
		}
		return ok
	}
	if b.n >= MaxBatchFrames {
		return false
	}
	f, _ := b.reserve(t, 0, h, 0, len(p))
	if len(p) > 0 {
		f.body = p
		b.bodies += len(p)
	}
	return true
}

// addAnswer appends the refusal a for handle h: OPEN_ACK or JOIN_ACK with
// a's status (REL on a datagram batch); false if the batch is full or no
// REL room is left.
func (b *Batch) addAnswer(h uint32, a *Answer) bool {
	if a.Type == wire.TypeJoinAck {
		return b.AddJoinAck(h, &wire.JoinAck{Status: a.Status, RxNext: a.RxNext})
	}
	return b.AddOpenAck(h, &wire.OpenAck{Status: a.Status, Window: a.Window, Code: a.Code})
}

// addLast appends a view's last session frame (WriteAndClose): type t with
// flags and payload p for handle h, REL-wrapped on a datagram batch when t
// is a reliable type (every session control type but ACK and a PACK
// without flags). ok is false if the batch is full or no REL room is
// left; skip is true for a frame that cannot travel on this batch at all
// (ACK on a datagram batch, a carrier-level or data type), which is then
// dropped.
func (b *Batch) addLast(t wire.Type, flags uint8, h uint32, p []byte) (ok, skip bool) {
	switch t {
	case wire.TypeAck:
		if b.dgram {
			return false, true
		}
		q, ok := b.addSession(t, flags, h, len(p))
		if ok {
			copy(q, p)
		}
		return ok, false
	case wire.TypePack:
		var q []byte
		if b.dgram && flags != 0 {
			q, ok = b.addSessionRel(t, flags, h, len(p))
		} else {
			q, ok = b.addSession(t, flags, h, len(p))
		}
		if ok {
			copy(q, p)
		}
		return ok, false
	case wire.TypeOpenAck, wire.TypeJoinAck, wire.TypeFin, wire.TypeRst, wire.TypeSched:
		if len(p) > ControlArena || (b.dgram && wire.RelHeadLen+len(p) > wire.RelMaxPayload) {
			return false, true
		}
		q, ok := b.addSessionRel(t, flags, h, len(p))
		if ok {
			copy(q, p)
		}
		return ok, false
	}
	return false, true
}

// responseIn looks for the first OPEN_ACK or JOIN_ACK for handle h among
// frames [from, Len()) — on a datagram batch inside REL — and returns its
// type and status (the passive's first response of a view, M3-D7, M3-D8).
func (b *Batch) responseIn(from int, h uint32) (t wire.Type, st wire.AckStatus, ok bool) {
	for i := from; i < b.n; i++ {
		f := &b.frames[i]
		hdr := f.hdr
		start := int(f.head) + wire.HeaderLen
		p := b.arena[start : start+int(f.ctl)]
		if hdr.Type == wire.TypeRel {
			hdr = relInner(p)
			p = p[wire.RelHeadLen:]
		}
		if hdr.Handle != h || (hdr.Type != wire.TypeOpenAck && hdr.Type != wire.TypeJoinAck) || len(p) == 0 {
			continue
		}
		return hdr.Type, wire.AckStatus(p[0]), true
	}
	return 0, 0, false
}
