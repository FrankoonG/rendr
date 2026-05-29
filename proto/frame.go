package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Version is the current rendr wire-protocol version. CLAUDE.md
// hard rule #7: any wire change MUST bump this.
const Version uint8 = 2

// HeaderSize is the fixed wire size of the frame header.
const HeaderSize = 8

// MaxSeq is the largest sequence number representable in 48 bits.
const MaxSeq uint64 = (1 << 48) - 1

// FrameType is the T bit.
type FrameType uint8

const (
	FrameData FrameType = 0
	FrameCtrl FrameType = 1
)

// Header is the decoded form of the 8-byte wire header.
type Header struct {
	Version uint8     // 2 bits
	Type    FrameType // 1 bit
	Last    bool      // 1 bit, F
	Flags   uint16    // 12 bits
	Seq     uint64    // 48 bits
}

// ErrBadHeader is returned by Decode for malformed bytes.
var ErrBadHeader = errors.New("proto: malformed frame header")

// Encode writes h's 8-byte wire representation to buf. buf must be
// at least HeaderSize bytes long.
func (h Header) Encode(buf []byte) error {
	if len(buf) < HeaderSize {
		return fmt.Errorf("proto: encode buf too small: %d < %d", len(buf), HeaderSize)
	}
	if h.Version > 0x3 {
		return fmt.Errorf("proto: version out of range: %d", h.Version)
	}
	if h.Type > 1 {
		return fmt.Errorf("proto: type out of range: %d", h.Type)
	}
	if h.Flags > 0x0FFF {
		return fmt.Errorf("proto: flags out of range: 0x%x", h.Flags)
	}
	if h.Seq > MaxSeq {
		return fmt.Errorf("proto: seq out of range: %d", h.Seq)
	}

	// word0 layout (big-endian, 32 bits):
	//   [VER:2][T:1][F:1][FLAGS:12][SEQ_LOW16:16]
	var word0 uint32
	word0 |= uint32(h.Version&0x3) << 30
	word0 |= uint32(h.Type&0x1) << 29
	if h.Last {
		word0 |= 1 << 28
	}
	word0 |= (uint32(h.Flags) & 0x0FFF) << 16
	word0 |= uint32(h.Seq & 0xFFFF)
	binary.BigEndian.PutUint32(buf[0:4], word0)

	// word1: SEQ_HIGH32 (the upper 32 bits of the 48-bit SEQ)
	binary.BigEndian.PutUint32(buf[4:8], uint32(h.Seq>>16))
	return nil
}

// DecodeHeader parses the first 8 bytes of buf into a Header.
func DecodeHeader(buf []byte) (Header, error) {
	if len(buf) < HeaderSize {
		return Header{}, ErrBadHeader
	}
	word0 := binary.BigEndian.Uint32(buf[0:4])
	word1 := binary.BigEndian.Uint32(buf[4:8])

	h := Header{
		Version: uint8((word0 >> 30) & 0x3),
		Type:    FrameType((word0 >> 29) & 0x1),
		Last:    ((word0 >> 28) & 0x1) == 1,
		Flags:   uint16((word0 >> 16) & 0x0FFF),
		Seq:     (uint64(word1) << 16) | uint64(word0&0xFFFF),
	}
	return h, nil
}

// Frame is a Header with a payload of arbitrary length. The proto
// package does not impose a maximum payload; transport adapters may.
type Frame struct {
	Header  Header
	Payload []byte
}
