package wire

import "errors"

// This file declares the M2 additions of wire format v2 (plan §5; M2 design
// §A3): the packet-session frames DGRAM and PACK, the reliable control
// sublayer frames REL and RACK, the raw-UDP flow header and the datagram
// classification helpers. M2 wave 1 implements the codecs and extends Known,
// CarrierLevel, AllowedFlags, PayloadBounds and String to the four types in
// the same commit that moves the M1 tests pinning them as ErrType; until
// then ParseHeader keeps rejecting them.

// M2 frame types (M2-D6).
const (
	// TypeDgram carries one application datagram of a packet session:
	// seq u64 · bytes (session frame, handle SessionHandle). Never
	// retransmitted (plan D9).
	TypeDgram Type = 0x20
	// TypePack is the packet session's accounting frame: highestSeq u64 ·
	// received u64 · epochEcho u32, header flags FlagPackFinDelivered and
	// FlagPackDone (session frame). It carries the SCHED echo and the end
	// flags; it is never a liveness signal (M2-D39).
	TypePack Type = 0x21
	// TypeRel wraps one reliable control frame on a datagram carrier:
	// cseq u32 · itype u8 · iflags u8 · ihandle u32 · ipayload
	// (carrier-level, handle 0; M2-D7).
	TypeRel Type = 0x34
	// TypeRack acknowledges REL frames: cumAck u32 · sack u32
	// (carrier-level, handle 0; M2-D8).
	TypeRack Type = 0x35
	// TypeReservedR (0x52, 'R', the first PREFACE magic byte) is never
	// assigned: the rendr bytes of a datagram that start with "RND2" are a
	// PREFACE or PREFACE_ACK, never a frame.
	TypeReservedR Type = 0x52
)

// PACK header flags (M2-D9).
const (
	// FlagPackFinDelivered (PACK): the sender delivered the receiver's FIN
	// (its ReadFrom reached the EOF condition), as FlagAckFinDelivered.
	FlagPackFinDelivered uint8 = 1 << 0
	// FlagPackDone (PACK): the sender's DONE, as FlagAckDone: its FIN was
	// acknowledged and the receiver's FIN was delivered; its last session
	// frame.
	FlagPackDone uint8 = 1 << 1
)

// Sizes and limits of the M2 additions.
const (
	// DgramPrefixLen is the DGRAM payload prefix (the u64 seq).
	DgramPrefixLen = 8
	// DgramOverhead is what a DGRAM frame adds to its application payload:
	// header, seq and trailer (17 + 8). A datagram carrier whose frame
	// budget is B carries application datagrams of at most B − 25 bytes
	// (plan:331: 1152 → 1127).
	DgramOverhead = FrameOverhead + DgramPrefixLen
	// PackLen is the exact PACK payload size.
	PackLen = 20
	// RelHeadLen is the REL payload before the inner payload: cseq u32 ·
	// itype u8 · iflags u8 · ihandle u32.
	RelHeadLen = 10
	// RelMaxPayload bounds a REL payload after a carrier's handshake: the
	// largest wrapped frame is an OPEN_ACK with a 255-byte message (only the
	// dialer's first datagram may carry a larger REL, its OPEN).
	RelMaxPayload = RelHeadLen + OpenAckFixedLen + MaxMsg
	// RackLen is the exact RACK payload size.
	RackLen = 8
	// RelWindow is the most REL frames a carrier direction has outstanding;
	// a receiver holds at most RelWindow − 1 out of order (M2-D16, M2-D17).
	RelWindow = 8
	// FirstCseq is the first cseq of each direction of a datagram carrier
	// (testhooks may preset another, L14).
	FirstCseq uint32 = 1

	// FlowHeaderLen is the raw-UDP flow header in front of the rendr bytes
	// of every datagram of a carrier/udp flow: ver u8 · flow u64 (M2-D10).
	FlowHeaderLen = 9
	// FlowVersion is the only flow header version; the layout is frozen.
	FlowVersion = 2

	// MinPacketPayload and MaxPacketPayload bound a packet session's
	// MaxPayload (plan:287).
	MinPacketPayload = 512
	MaxPacketPayload = 65507
	// MinFrameBudget is the smallest frame budget (bytes of frames per
	// datagram) of a datagram carrier: a single-carrier session can then
	// carry MinPacketPayload (M2-D51).
	MinFrameBudget = MinPacketPayload + DgramOverhead
	// MaxDatagram is the largest UDP payload and the largest datagram any
	// datagram carrier passes to its transport.
	MaxDatagram = 65507
	// ControlFloor is the smallest frame budget that still carries every
	// control datagram of an established carrier (the largest is a REL
	// OPEN_ACK with a 255-byte message, 292 bytes): a carrier whose budget
	// shrinks below it is killed (M2-D25).
	ControlFloor = 300

	// FseqWindowBits is the anti-replay window of a datagram carrier
	// direction (plan:333).
	FseqWindowBits = 1024
	// DefaultSeqWindowBits is a packet session's receive dedup window (L39).
	DefaultSeqWindowBits = 16384
)

// Datagram transport errors shared by the core, the root package, the quic
// module (through the root) and rendrtest, which may import only this
// package.
var (
	// ErrDatagramTooLarge is matched (errors.Is) by DatagramTooLargeError:
	// a datagram transport refused one datagram because of its size. The
	// carrier lives and lowers its budget (M2-D25); it is never a carrier
	// death (L01, L37).
	ErrDatagramTooLarge = errors.New("rendr: datagram too large for the carrier")
	// ErrFlowHeader: a raw-UDP datagram without a valid flow header (fewer
	// than 9 bytes, another version, or flow ID 0). Dropped and counted,
	// never answered.
	ErrFlowHeader = errors.New("rendr/wire: bad flow header")
)

// DatagramTooLargeError is the error a datagram transport returns from a
// write it refused because of the datagram's size. Max is the largest
// datagram it can send now (0: unknown).
type DatagramTooLargeError struct {
	Max int
}

// Error implements error.
func (e *DatagramTooLargeError) Error() string {
	if e.Max > 0 {
		return "rendr: datagram too large for the carrier (max " + itoa(e.Max) + ")"
	}
	return "rendr: datagram too large for the carrier"
}

// Is reports target == ErrDatagramTooLarge.
func (e *DatagramTooLargeError) Is(target error) bool { return target == ErrDatagramTooLarge }

// itoa formats a non-negative int without fmt.
func itoa(v int) string {
	if v <= 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// PutDgramSeq writes the DGRAM prefix (seq) into dst[:DgramPrefixLen].
func PutDgramSeq(dst []byte, seq uint64) {
	panic("unimplemented: M2")
}

// ParseDgram decodes a DGRAM payload: seq and the datagram bytes (aliasing
// p; an empty datagram is legal). Fewer than DgramPrefixLen bytes is
// ErrShort.
func ParseDgram(p []byte) (seq uint64, data []byte, err error) {
	panic("unimplemented: M2")
}

// Pack is the PACK payload: highestSeq u64 · received u64 · epochEcho u32.
// Canonical: Received == 0 implies HighestSeq == 0 (ErrReserved).
type Pack struct {
	HighestSeq uint64 // the highest seq the sender accepted (0 while Received is 0)
	Received   uint64 // distinct datagrams the sender accepted
	EpochEcho  uint32 // passive: the SCHED epoch it applied; dialer: 0
}

// PutPack writes p into dst and returns PackLen.
func PutPack(dst []byte, p *Pack) int {
	panic("unimplemented: M2")
}

// ParsePack decodes a PACK payload (exactly PackLen bytes, canonical).
func ParsePack(p []byte) (Pack, error) {
	panic("unimplemented: M2")
}

// RelHead is the fixed part of a REL payload: the cseq and the compact
// inner header (no inner length, fseq or CRC: the outer frame's cover it).
type RelHead struct {
	Cseq   uint32 // per carrier direction, serial arithmetic (L14)
	Type   Type   // a Wrappable type
	Flags  uint8  // ⊆ AllowedFlags(Type)
	Handle uint32 // 0 for CLOSE and GOAWAY, SessionHandle otherwise
}

// PutRelHead writes h into dst[:RelHeadLen].
func PutRelHead(dst []byte, h *RelHead) {
	panic("unimplemented: M2")
}

// ParseRel decodes a REL payload: the head and the inner payload (aliasing
// p). Check order: length ≥ RelHeadLen (ErrShort); Wrappable(type)
// (ErrType: REL in REL is impossible); flags (ErrFlags); handle
// (ErrHandle); inner length within PayloadBounds(type) (ErrLength). The
// inner payload is decoded by its own parser at dispatch.
func ParseRel(p []byte) (h RelHead, inner []byte, err error) {
	panic("unimplemented: M2")
}

// Rack is the RACK payload: cumAck u32 · sack u32. CumAck is the highest
// cseq the receiver dispatched in order; sack bit i (bit 0 the least
// significant) reports cseq CumAck + 2 + i held out of order.
type Rack struct {
	CumAck uint32
	Sack   uint32
}

// PutRack writes r into dst and returns RackLen.
func PutRack(dst []byte, r *Rack) int {
	panic("unimplemented: M2")
}

// ParseRack decodes a RACK payload (exactly RackLen bytes).
func ParseRack(p []byte) (Rack, error) {
	panic("unimplemented: M2")
}

// Wrappable reports whether a REL may carry type t: OPEN, OPEN_ACK, JOIN,
// JOIN_ACK, FIN, RST, SCHED, CLOSE, GOAWAY (plan:356) and PACK (M2-D39).
func Wrappable(t Type) bool {
	panic("unimplemented: M2")
}

// PutFlowHeader writes the raw-UDP flow header (FlowVersion, flow) into
// dst[:FlowHeaderLen]. It panics if flow is 0.
func PutFlowHeader(dst []byte, flow uint64) {
	panic("unimplemented: M2")
}

// ParseFlowHeader splits a raw-UDP datagram into its flow ID and its rendr
// bytes (aliasing d). ErrFlowHeader for fewer than FlowHeaderLen bytes, a
// version other than FlowVersion, or flow 0.
func ParseFlowHeader(d []byte) (flow uint64, rest []byte, err error) {
	panic("unimplemented: M2")
}

// IsPreface reports whether the rendr bytes b of a datagram start with a
// PREFACE or PREFACE_ACK candidate: at least PrefaceLen bytes and the
// "RND2" magic. The full checks are ParsePreface and ParsePrefaceAck.
func IsPreface(b []byte) bool {
	return len(b) >= PrefaceLen && b[0] == Magic[0] && b[1] == Magic[1] && b[2] == Magic[2] && b[3] == Magic[3]
}

// PacketWindow returns the OPEN_ACK(OK) window field of a packet session:
// the accepted MaxPayload (pmtu) in the high 16 bits and the accepted frame
// budget of the answering carrier (cmtu; 0 on a stream carrier) in the low
// 16 bits (M2-D11). Stream sessions keep their receive window there.
func PacketWindow(pmtu, cmtu uint16) uint32 { return uint32(pmtu)<<16 | uint32(cmtu) }

// SplitPacketWindow is the inverse of PacketWindow.
func SplitPacketWindow(w uint32) (pmtu, cmtu uint16) { return uint16(w >> 16), uint16(w) }
