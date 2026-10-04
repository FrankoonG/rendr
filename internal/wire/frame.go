package wire

import "hash/crc32"

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
	panic("unimplemented: M1b")
}

// ParseHeader decodes b[:HeaderLen] and checks everything that can be
// checked before the payload is read or any buffer is sized: Len ≤
// MaxFramePayload (ErrLength), the type is a known M1 core type or an
// extension (ErrType), only AllowedFlags(type) are set (ErrFlags), the
// handle rule of Type.CarrierLevel (ErrHandle), and Len within
// PayloadBounds(type) (ErrLength). For an extension type only Len ≤
// MaxFramePayload applies: its flags and handle are opaque. The fseq is not
// checked (it is stateful; see SeqLess).
func ParseHeader(b []byte) (Header, error) {
	panic("unimplemented: M1b")
}

// PayloadBounds returns the inclusive payload length bounds of t: OPEN
// 32..32+65535, OPEN_ACK 10..265, JOIN 25, JOIN_ACK 9, DATA 9..MaxFramePayload,
// ACK 16, FIN 8, RST 5..260, SCHED 9..69, PING/PONG 20..20+MaxPingPad, CLOSE 1,
// GOAWAY 1, extensions 0..MaxFramePayload. ok is false for unknown core types.
func PayloadBounds(t Type) (min, max int, ok bool) {
	panic("unimplemented: M1b")
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
// batches without it.
func AppendFrame(dst []byte, h Header, payload []byte) []byte {
	panic("unimplemented: M1b")
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
// skip them.
func DecodeFrame(b []byte) (f Frame, n int, err error) {
	panic("unimplemented: M1b")
}

// SeqLess reports a < b in RFC 1982 serial-number arithmetic on uint32. It is
// used for fseq, SCHED epochs and PING ids, all of which wrap (L14).
func SeqLess(a, b uint32) bool { return a != b && int32(b-a) > 0 }
