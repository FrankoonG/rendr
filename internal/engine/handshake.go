package engine

import (
	"errors"
	"fmt"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

// PerformClientHello sends HELLO on pc as the first frame and returns
// without waiting for a response. flowID is the engine's flow id.
func PerformClientHello(pc transport.PathConn, flowID [16]byte, caps uint32) error {
	payload := proto.HelloPayload{FlowID: flowID, Caps: caps}.Encode()
	return writeCtrl(pc, proto.CtrlHello, 0, payload, 0)
}

func PerformClientHelloWithPathName(pc transport.PathConn, flowID [16]byte, caps uint32, name string) error {
	payload := proto.HelloPayload{FlowID: flowID, Caps: caps}.EncodeWithPathName(name)
	return writeCtrl(pc, proto.CtrlHello, 0, payload, 0)
}

// PerformClientBridgeTag sends BRIDGE_TAG so the server attaches
// this new path to an existing bridge identified by bridgeID.
func PerformClientBridgeTag(pc transport.PathConn, bridgeID [16]byte) error {
	payload := proto.BridgeTagPayload{BridgeID: bridgeID}.Encode()
	return writeCtrl(pc, proto.CtrlBridgeTag, 0, payload, 0)
}

func PerformClientBridgeTagWithPathName(pc transport.PathConn, bridgeID [16]byte, name string) error {
	payload := proto.BridgeTagPayload{BridgeID: bridgeID}.EncodeWithPathName(name)
	return writeCtrl(pc, proto.CtrlBridgeTag, 0, payload, 0)
}

// PerformBye sends BYE on the active path. Best-effort: failures are
// reported as errors but the caller usually proceeds to Close.
func PerformBye(pc transport.PathConn, reason proto.ByeReason, seq uint64) error {
	payload := proto.ByePayload{Reason: reason}.Encode()
	return writeCtrl(pc, proto.CtrlBye, 0, payload, seq)
}

// ReadFirstFrame reads exactly one framed unit from pc and returns
// its header + payload. Used by the server side to inspect the
// initial control frame (HELLO or BRIDGE_TAG) before allocating an
// engine.
func ReadFirstFrame(pc transport.PathConn) (proto.Header, []byte, error) {
	buf := make([]byte, MaxPayload+proto.HeaderSize)
	n, err := pc.Read(buf)
	if err != nil {
		return proto.Header{}, nil, err
	}
	if n < proto.HeaderSize {
		return proto.Header{}, nil, errors.New("engine: short first frame")
	}
	hdr, err := proto.DecodeHeader(buf[:proto.HeaderSize])
	if err != nil {
		return proto.Header{}, nil, err
	}
	if hdr.Version != proto.Version {
		return hdr, nil, fmt.Errorf("engine: peer proto version %d != %d", hdr.Version, proto.Version)
	}
	payload := append([]byte(nil), buf[proto.HeaderSize:n]...)
	return hdr, payload, nil
}

// writeCtrl is a low-level helper that builds and sends a single
// control frame on pc using the supplied SEQ. It does NOT engage the
// engine's send mutex; callers using this during handshake have
// exclusive access to the brand-new PathConn.
func writeCtrl(pc transport.PathConn, code proto.CtrlCode, flagsExtra uint16, payload []byte, seq uint64) error {
	hdr := proto.Header{
		Version: proto.Version,
		Type:    proto.FrameCtrl,
		Flags:   proto.FlagsForCtrl(code) | (flagsExtra & 0x0F00),
		Seq:     seq,
	}
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := hdr.Encode(frame[:proto.HeaderSize]); err != nil {
		return err
	}
	copy(frame[proto.HeaderSize:], payload)
	_, err := pc.Write(frame)
	return err
}
