package wire

import (
	"encoding/binary"
	"hash/crc32"
	"slices"
)

// Table is the CRC32C (Castagnoli) table used for every preface and frame.
var Table = crc32.MakeTable(crc32.Castagnoli)

// Header is a decoded frame header.
type Header struct {
	Type   Type
	Flags  uint8
	Len    uint32 // payload length, ≤ MaxFramePayload
	Fseq   uint32 // per carrier, per direction; strict +1 (serial arithmetic) on stream carriers
	Handle uint32 // 0 for carrier-level frames, the session handle otherwise
}

// PutHeader writes h into b[:HeaderLen]. It panics if len(b) < HeaderLen or
// h.Len > MaxFramePayload (programming errors).
func PutHeader(b []byte, h *Header) {
	if h.Len > MaxFramePayload {
		panic("rendr/wire: PutHeader: payload length beyond MaxFramePayload")
	}
	_ = b[HeaderLen-1]
	b[0] = byte(h.Type)
	b[1] = h.Flags
	b[2], b[3], b[4] = byte(h.Len>>16), byte(h.Len>>8), byte(h.Len)
	binary.BigEndian.PutUint32(b[5:9], h.Fseq)
	binary.BigEndian.PutUint32(b[9:13], h.Handle)
}

// ParseHeader decodes b[:HeaderLen] and checks everything that can be
// checked before the payload is read or any buffer is sized: Len ≤
// MaxFramePayload (ErrLength), the type is a known M1 core type or an
// extension (ErrType), only AllowedFlags(type) are set (ErrFlags), the
// handle rule of Type.CarrierLevel (ErrHandle), and Len within
// PayloadBounds(type) (ErrLength). For an extension type only Len ≤
// MaxFramePayload applies: its flags and handle are opaque. The fseq is not
// checked (it is stateful; see SeqLess). Fewer than HeaderLen bytes are
// ErrShort; bytes after the header are ignored.
//
// The handle rule is stateless: 0 for a carrier-level type, non-zero for a
// session type. That a session frame carries its own carrier's session
// handle (SessionHandle in M1) and that the carrier accepts session frames
// at all (probe and sessionless carriers do not) are per-carrier rules
// (design §5.2 check 4) that the code reading the carrier applies after
// ParseHeader.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < HeaderLen {
		return Header{}, ErrShort
	}
	h := Header{
		Type:   Type(b[0]),
		Flags:  b[1],
		Len:    uint32(b[2])<<16 | uint32(b[3])<<8 | uint32(b[4]),
		Fseq:   binary.BigEndian.Uint32(b[5:9]),
		Handle: binary.BigEndian.Uint32(b[9:13]),
	}
	if h.Len > MaxFramePayload {
		return Header{}, ErrLength
	}
	if h.Type.Extension() {
		return h, nil
	}
	if !h.Type.Known() {
		return Header{}, ErrType
	}
	if h.Flags&^AllowedFlags(h.Type) != 0 {
		return Header{}, ErrFlags
	}
	if h.Type.CarrierLevel() != (h.Handle == 0) {
		return Header{}, ErrHandle
	}
	if lo, hi, _ := PayloadBounds(h.Type); int(h.Len) < lo || int(h.Len) > hi {
		return Header{}, ErrLength
	}
	return h, nil
}

// PayloadBounds returns the inclusive payload length bounds of t: OPEN
// 32..32+65535, OPEN_ACK 10..265, JOIN 25, JOIN_ACK 9, DATA 9..MaxFramePayload,
// ACK 16, FIN 8, RST 5..260, SCHED 9..69, PING/PONG 20..20+MaxPingPad, CLOSE 1,
// GOAWAY 1, extensions 0..MaxFramePayload. ok is false for unknown core types.
func PayloadBounds(t Type) (min, max int, ok bool) {
	if t.Extension() {
		return 0, MaxFramePayload, true
	}
	switch t {
	case TypeOpen:
		return OpenFixedLen, OpenFixedLen + MaxMetadata, true
	case TypeOpenAck:
		return OpenAckFixedLen, OpenAckFixedLen + MaxMsg, true
	case TypeJoin:
		return JoinLen, JoinLen, true
	case TypeJoinAck:
		return JoinAckLen, JoinAckLen, true
	case TypeData:
		return DataPrefixLen + 1, MaxFramePayload, true
	case TypeAck:
		return AckLen, AckLen, true
	case TypeFin:
		return FinLen, FinLen, true
	case TypeRst:
		return RstFixedLen, RstFixedLen + MaxMsg, true
	case TypeSched:
		return SchedFixedLen + 4, SchedFixedLen + 4*MaxSchedIDs, true
	case TypePing, TypePong:
		return PingFixedLen, PingFixedLen + MaxPingPad, true
	case TypeClose, TypeGoAway:
		return ReasonLen, ReasonLen, true
	}
	return 0, 0, false
}

// CRC returns the CRC32C of b.
func CRC(b []byte) uint32 { return crc32.Checksum(b, Table) }

// CRCUpdate continues a CRC32C over b (chaining over header, prefix and
// payload pieces without copying).
func CRCUpdate(crc uint32, b []byte) uint32 { return crc32.Update(crc, Table, b) }

// PutTrailer writes crc big-endian into b[:TrailerLen].
func PutTrailer(b []byte, crc uint32) {
	_ = b[3]
	b[0], b[1], b[2], b[3] = byte(crc>>24), byte(crc>>16), byte(crc>>8), byte(crc)
}

// Trailer reads the big-endian CRC from b[:TrailerLen].
func Trailer(b []byte) uint32 {
	_ = b[3]
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// AppendFrame appends one complete frame (header with Len = len(payload),
// payload, CRC32C trailer) to dst and returns the extended slice. It is used
// for handshake first frames and by tests; the carrier writer encodes
// batches without it. Header fields other than Len are written as given (no
// validation), so tests can build invalid frames; it panics if
// len(payload) > MaxFramePayload.
func AppendFrame(dst []byte, h Header, payload []byte) []byte {
	if len(payload) > MaxFramePayload {
		panic("rendr/wire: AppendFrame: payload beyond MaxFramePayload")
	}
	h.Len = uint32(len(payload))
	dst = slices.Grow(dst, FrameOverhead+len(payload))
	start := len(dst)
	dst = dst[:start+HeaderLen]
	PutHeader(dst[start:], &h)
	dst = append(dst, payload...)
	crc := CRC(dst[start:])
	dst = dst[:len(dst)+TrailerLen]
	PutTrailer(dst[len(dst)-TrailerLen:], crc)
	return dst
}

// Frame is one decoded frame; Payload aliases the decoder's input.
type Frame struct {
	Header
	Payload []byte
}

// DecodeFrame decodes the complete frame at the front of b: ParseHeader,
// payload, trailer and CRC (ErrCRC). It returns ErrShort when b does not yet
// hold the whole frame, and n, the number of bytes consumed, otherwise. It
// does not check the fseq. Extension frames decode successfully; callers
// skip them. A header error is reported as soon as the 13 header bytes are
// present, before anything sized by Len is looked at; on any error n is 0.
// Payload's capacity ends at the payload (appending to it cannot overwrite
// the trailer or the next frame).
func DecodeFrame(b []byte) (f Frame, n int, err error) {
	h, err := ParseHeader(b)
	if err != nil {
		return Frame{}, 0, err
	}
	end := HeaderLen + int(h.Len)
	if len(b)-TrailerLen < end {
		return Frame{}, 0, ErrShort
	}
	if CRC(b[:end]) != Trailer(b[end:]) {
		return Frame{}, 0, ErrCRC
	}
	return Frame{Header: h, Payload: b[HeaderLen:end:end]}, end + TrailerLen, nil
}

// SeqLess reports a < b in RFC 1982 serial-number arithmetic on uint32. It is
// used for fseq, SCHED epochs and PING ids, all of which wrap (L14).
func SeqLess(a, b uint32) bool { return a != b && int32(b-a) > 0 }
