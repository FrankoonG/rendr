package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// UDPFlowVersion is the current wire-protocol version for the
// opaque-UDP flow header. CLAUDE.md hard rule #7: any wire change
// MUST bump this.
const UDPFlowVersion uint8 = 2

// UDPFlowHeaderSize is the fixed 12-byte preamble prepended to every
// payload datagram that rendr carries over opaque UDP.
const UDPFlowHeaderSize = 12

// UDPFlowIDSize is the on-wire length of a flow_id.
const UDPFlowIDSize = 7

// UDPFlowHeader is the decoded form of the 12-byte preamble.
//
//	+--------+----------------------------+----------------+
//	| VER(1) |        FLOW_ID(7)          | PAYLOAD_LEN(4) |
//	+--------+----------------------------+----------------+
//	|                  payload (var len)                    |
//	+-------------------------------------------------------+
//
// Unlike proto.Header (the stream-frame header used by TCP / QUIC
// reliable paths), this header carries no SEQ and no flags - opaque
// UDP delivers datagrams unordered and unacked, and the engine
// keys path-migration off the flow_id alone.
type UDPFlowHeader struct {
	Version     uint8
	FlowID      [UDPFlowIDSize]byte
	PayloadSize uint32
}

// ErrBadUDPFlow is returned by DecodeUDPFlow when the input is
// shorter than UDPFlowHeaderSize.
var ErrBadUDPFlow = errors.New("proto: short UDP-flow header")

// Encode writes h into the first 12 bytes of buf. buf must hold at
// least UDPFlowHeaderSize bytes.
func (h UDPFlowHeader) Encode(buf []byte) error {
	if len(buf) < UDPFlowHeaderSize {
		return fmt.Errorf("proto: encode buf too small for UDP-flow header: %d < %d", len(buf), UDPFlowHeaderSize)
	}
	buf[0] = h.Version
	copy(buf[1:8], h.FlowID[:])
	binary.BigEndian.PutUint32(buf[8:12], h.PayloadSize)
	return nil
}

// DecodeUDPFlow parses the first 12 bytes of buf.
func DecodeUDPFlow(buf []byte) (UDPFlowHeader, error) {
	var h UDPFlowHeader
	if len(buf) < UDPFlowHeaderSize {
		return h, ErrBadUDPFlow
	}
	h.Version = buf[0]
	copy(h.FlowID[:], buf[1:8])
	h.PayloadSize = binary.BigEndian.Uint32(buf[8:12])
	return h, nil
}

// UDPFlowFrame is a (header, payload) pair. It is a convenience type
// for transport adapters; on the wire the header is simply prepended
// to the payload bytes inside a single UDP datagram.
type UDPFlowFrame struct {
	Header  UDPFlowHeader
	Payload []byte
}

// Encode produces a single contiguous byte slice = header || payload,
// suitable for handing directly to net.PacketConn.WriteTo.
func (f UDPFlowFrame) Encode() ([]byte, error) {
	if uint64(len(f.Payload)) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("proto: UDP-flow payload exceeds uint32 length")
	}
	out := make([]byte, UDPFlowHeaderSize+len(f.Payload))
	header := f.Header
	header.PayloadSize = uint32(len(f.Payload))
	if err := header.Encode(out[:UDPFlowHeaderSize]); err != nil {
		return nil, err
	}
	copy(out[UDPFlowHeaderSize:], f.Payload)
	return out, nil
}

// DecodeUDPFlowFrame splits buf into header + payload. Payload is a
// sub-slice of buf; callers that retain it past the next read MUST
// copy it.
func DecodeUDPFlowFrame(buf []byte) (UDPFlowFrame, error) {
	h, err := DecodeUDPFlow(buf)
	if err != nil {
		return UDPFlowFrame{}, err
	}
	payload := buf[UDPFlowHeaderSize:]
	if uint64(h.PayloadSize) != uint64(len(payload)) {
		return UDPFlowFrame{}, fmt.Errorf("proto: UDP-flow payload length %d does not match datagram payload %d", h.PayloadSize, len(payload))
	}
	return UDPFlowFrame{Header: h, Payload: payload}, nil
}
