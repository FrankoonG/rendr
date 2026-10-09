package wire

import (
	"encoding/binary"
	"errors"
)

// This file holds the M2 additions of wire format v2 (plan §5; M2 design
// §A3): the packet-session frames DGRAM and PACK, the reliable control
// sublayer frames REL and RACK, the raw-UDP flow header and the datagram
// classification helpers. Known, CarrierLevel, AllowedFlags, PayloadBounds
// and String cover the four types, so ParseHeader checks them like every
// other core type (§A3.1). No M1 encoding changes (M2-D11).
//
// A datagram's bytes (§A3.4) are an optional raw-UDP flow header (only on
// raw-UDP flow carriers), then rendr bytes: an optional PREFACE or
// PREFACE_ACK (only in the handshake datagrams) followed by whole frames
// that fill the datagram exactly. The package has no datagram walker: the
// carrier reader walks a datagram with DecodeFrame and the payload parsers.

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

// PutDgramSeq writes the DGRAM prefix (seq) into dst[:DgramPrefixLen]. The
// datagram bytes follow it in the frame (the batch references them; they
// are never copied into its arena). It panics if dst is too small.
func PutDgramSeq(dst []byte, seq uint64) {
	_ = dst[DgramPrefixLen-1]
	binary.BigEndian.PutUint64(dst[:DgramPrefixLen], seq)
}

// ParseDgram decodes a DGRAM payload: seq and the datagram bytes (aliasing
// p; an empty datagram is legal). Fewer than DgramPrefixLen bytes is
// ErrShort. Every seq decodes: its limits (OffsetLimit, the peer's final
// seq) and the session's MaxPayload are the receiving session's checks
// (M2 design §A3.2). data's capacity ends at its length.
func ParseDgram(p []byte) (seq uint64, data []byte, err error) {
	if len(p) < DgramPrefixLen {
		return 0, nil, ErrShort
	}
	return binary.BigEndian.Uint64(p[:DgramPrefixLen]), p[DgramPrefixLen:len(p):len(p)], nil
}

// Pack is the PACK payload: highestSeq u64 · received u64 · epochEcho u32.
// Canonical: Received == 0 implies HighestSeq == 0 (ErrReserved).
type Pack struct {
	HighestSeq uint64 // the highest seq the sender accepted (0 while Received is 0)
	Received   uint64 // distinct datagrams the sender accepted
	EpochEcho  uint32 // passive: the SCHED epoch it applied; dialer: 0
}

// PutPack writes p into dst and returns PackLen. It writes the canonical
// HighestSeq 0 itself when Received is 0, whatever p holds, so a sender
// cannot emit a PACK its peer rejects (as PutOpenAck writes its canonical
// zero fields). It panics if dst is too small.
func PutPack(dst []byte, p *Pack) int {
	_ = dst[PackLen-1]
	hi := p.HighestSeq
	if p.Received == 0 {
		hi = 0
	}
	binary.BigEndian.PutUint64(dst[0:8], hi)
	binary.BigEndian.PutUint64(dst[8:16], p.Received)
	binary.BigEndian.PutUint32(dst[16:20], p.EpochEcho)
	return PackLen
}

// ParsePack decodes a PACK payload (exactly PackLen bytes, canonical).
// Received ≤ HighestSeq + 1 is not a codec rule (seqs start at the
// session's first seq): the receiving session checks a PACK against what
// it sent (M2 design §A3.2).
func ParsePack(p []byte) (Pack, error) {
	if err := exactTail(len(p), PackLen); err != nil {
		return Pack{}, err
	}
	pk := Pack{
		HighestSeq: binary.BigEndian.Uint64(p[0:8]),
		Received:   binary.BigEndian.Uint64(p[8:16]),
		EpochEcho:  binary.BigEndian.Uint32(p[16:20]),
	}
	if pk.Received == 0 && pk.HighestSeq != 0 {
		return Pack{}, ErrReserved
	}
	return pk, nil
}

// RelHead is the fixed part of a REL payload: the cseq and the compact
// inner header (no inner length, fseq or CRC: the outer frame's cover it).
type RelHead struct {
	Cseq   uint32 // per carrier direction, serial arithmetic (L14)
	Type   Type   // a Wrappable type
	Flags  uint8  // ⊆ AllowedFlags(Type)
	Handle uint32 // 0 for CLOSE, GOAWAY and DETACH; non-zero (the session's handle) otherwise
}

// PutRelHead writes h into dst[:RelHeadLen]; the inner payload follows it.
// The fields are written as given (no validation, so tests can build
// invalid frames; the writer wraps only Wrappable types). It panics if dst
// is too small.
func PutRelHead(dst []byte, h *RelHead) {
	_ = dst[RelHeadLen-1]
	binary.BigEndian.PutUint32(dst[0:4], h.Cseq)
	dst[4] = byte(h.Type)
	dst[5] = h.Flags
	binary.BigEndian.PutUint32(dst[6:10], h.Handle)
}

// ParseRel decodes a REL payload: the head and the inner payload (aliasing
// p). Check order: length ≥ RelHeadLen (ErrShort); Wrappable(type)
// (ErrType: REL in REL is impossible); flags (ErrFlags); handle (ErrHandle:
// ParseHeader's rule, 0 for CLOSE, GOAWAY and DETACH, non-zero for a
// session type); inner length within PayloadBounds(type) (ErrLength). The
// inner payload is decoded by its own parser at dispatch. Every cseq
// decodes (the receiver's window decides). inner's capacity ends at its
// length; an error returns the zero RelHead and a nil inner.
func ParseRel(p []byte) (h RelHead, inner []byte, err error) {
	if len(p) < RelHeadLen {
		return RelHead{}, nil, ErrShort
	}
	h = RelHead{
		Cseq:   binary.BigEndian.Uint32(p[0:4]),
		Type:   Type(p[4]),
		Flags:  p[5],
		Handle: binary.BigEndian.Uint32(p[6:10]),
	}
	if !Wrappable(h.Type) {
		return RelHead{}, nil, ErrType
	}
	if h.Flags&^AllowedFlags(h.Type) != 0 {
		return RelHead{}, nil, ErrFlags
	}
	if !handleOK(h.Type, h.Handle) {
		return RelHead{}, nil, ErrHandle
	}
	n := len(p) - RelHeadLen
	if lo, hi, _ := PayloadBounds(h.Type); n < lo || n > hi {
		return RelHead{}, nil, ErrLength
	}
	return h, p[RelHeadLen:len(p):len(p)], nil
}

// Rack is the RACK payload: cumAck u32 · sack u32. CumAck is the highest
// cseq the receiver dispatched in order; sack bit i (bit 0 the least
// significant) reports cseq CumAck + 2 + i held out of order. Only bits
// 0 … RelWindow − 2 exist (a receiver holds at most RelWindow − 1 frames);
// the others are reserved zero.
type Rack struct {
	CumAck uint32
	Sack   uint32
}

// rackSackMask covers the defined sack bits: cseq CumAck + 2 … CumAck +
// RelWindow (bits 0 … RelWindow − 2).
const rackSackMask uint32 = 1<<(RelWindow-1) - 1

// PutRack writes r into dst and returns RackLen. The fields are written as
// given (reserved sack bits included, as Open.Flags). It panics if dst is
// too small.
func PutRack(dst []byte, r *Rack) int {
	_ = dst[RackLen-1]
	binary.BigEndian.PutUint32(dst[0:4], r.CumAck)
	binary.BigEndian.PutUint32(dst[4:8], r.Sack)
	return RackLen
}

// ParseRack decodes a RACK payload: exactly RackLen bytes; sack bits
// outside rackSackMask must be 0 (ErrReserved). Every cumAck decodes
// (serial arithmetic, L14): whether it or a sack bit names a cseq not yet
// sent is the sender's check (M2 design §A3.3).
func ParseRack(p []byte) (Rack, error) {
	if err := exactTail(len(p), RackLen); err != nil {
		return Rack{}, err
	}
	r := Rack{CumAck: binary.BigEndian.Uint32(p[0:4]), Sack: binary.BigEndian.Uint32(p[4:8])}
	if r.Sack&^rackSackMask != 0 {
		return Rack{}, ErrReserved
	}
	return r, nil
}

// Wrappable reports whether a REL may carry type t: OPEN, OPEN_ACK, JOIN,
// JOIN_ACK, FIN, RST, SCHED, CLOSE, GOAWAY (plan:356), PACK (M2-D39) and
// DETACH (M3-D6). REL, RACK, DGRAM, DATA, ACK, PING, PONG, extensions and
// unknown types are not: REL inside REL is impossible by construction.
func Wrappable(t Type) bool {
	switch t {
	case TypeOpen, TypeOpenAck, TypeJoin, TypeJoinAck, TypeFin, TypeRst, TypeSched,
		TypeClose, TypeGoAway, TypePack, TypeDetach:
		return true
	}
	return false
}

// PutFlowHeader writes the raw-UDP flow header (FlowVersion, flow) into
// dst[:FlowHeaderLen]. It panics if flow is 0 or dst is too small.
func PutFlowHeader(dst []byte, flow uint64) {
	if flow == 0 {
		panic("rendr/wire: PutFlowHeader: flow ID 0")
	}
	_ = dst[FlowHeaderLen-1]
	dst[0] = FlowVersion
	binary.BigEndian.PutUint64(dst[1:FlowHeaderLen], flow)
}

// ParseFlowHeader splits a raw-UDP datagram into its flow ID and its rendr
// bytes (aliasing d). ErrFlowHeader for fewer than FlowHeaderLen bytes, a
// version other than FlowVersion, or flow 0. The flow ID is a
// demultiplexing key, not authentication (plan:361): it has no integrity
// check of its own. rest may be empty; its capacity ends at its length.
func ParseFlowHeader(d []byte) (flow uint64, rest []byte, err error) {
	if len(d) < FlowHeaderLen || d[0] != FlowVersion {
		return 0, nil, ErrFlowHeader
	}
	flow = binary.BigEndian.Uint64(d[1:FlowHeaderLen])
	if flow == 0 {
		return 0, nil, ErrFlowHeader
	}
	return flow, d[FlowHeaderLen:len(d):len(d)], nil
}

// IsPreface reports whether the rendr bytes b of a datagram start with a
// PREFACE or PREFACE_ACK candidate: at least PrefaceLen bytes and the
// "RND2" magic. The full checks are ParsePreface and ParsePrefaceAck. A
// frame never starts with the magic: its first byte is its type, and 0x52
// ('R') is never assigned (TypeReservedR).
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
