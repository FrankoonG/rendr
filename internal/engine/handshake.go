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

func PerformClientHelloAck(pc transport.PathConn, flowID [16]byte, instanceID proto.InstanceID, caps uint32, name string) (proto.HelloAckPayload, error) {
	payload := proto.HelloPayload{FlowID: flowID, InstanceID: instanceID, Caps: caps}.EncodeWithPathName(name)
	if err := writeCtrl(pc, proto.CtrlHello, 0, payload, 0); err != nil {
		return proto.HelloAckPayload{}, err
	}
	hdr, ackPayload, err := ReadFirstFrame(pc)
	if err != nil {
		return proto.HelloAckPayload{}, err
	}
	if hdr.Type != proto.FrameCtrl || proto.CtrlCodeFromFlags(hdr.Flags) != proto.CtrlHelloAck {
		return proto.HelloAckPayload{}, fmt.Errorf("engine: expected HELLO_ACK, got %s", proto.CtrlCodeFromFlags(hdr.Flags))
	}
	ack, err := proto.DecodeHelloAck(ackPayload)
	if err != nil {
		return proto.HelloAckPayload{}, err
	}
	if ack.FlowID != flowID {
		return proto.HelloAckPayload{}, fmt.Errorf("engine: HELLO_ACK flow mismatch")
	}
	return ack, nil
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

func PerformClientBridgeTagAck(pc transport.PathConn, bridgeID [16]byte, instanceID, expectedPeer proto.InstanceID, name string) (proto.BridgeAckPayload, error) {
	payload := proto.BridgeTagPayload{
		BridgeID:               bridgeID,
		InstanceID:             instanceID,
		ExpectedPeerInstanceID: expectedPeer,
	}.EncodeWithPathName(name)
	if err := writeCtrl(pc, proto.CtrlBridgeTag, 0, payload, 0); err != nil {
		return proto.BridgeAckPayload{}, err
	}
	hdr, ackPayload, err := ReadFirstFrame(pc)
	if err != nil {
		return proto.BridgeAckPayload{}, err
	}
	if hdr.Type != proto.FrameCtrl || proto.CtrlCodeFromFlags(hdr.Flags) != proto.CtrlBridgeAck {
		return proto.BridgeAckPayload{}, fmt.Errorf("engine: expected BRIDGE_ACK, got %s", proto.CtrlCodeFromFlags(hdr.Flags))
	}
	ack, err := proto.DecodeBridgeAck(ackPayload)
	if err != nil {
		return proto.BridgeAckPayload{}, err
	}
	if ack.BridgeID != bridgeID {
		return proto.BridgeAckPayload{}, fmt.Errorf("engine: BRIDGE_ACK flow mismatch")
	}
	if !ack.Code.OK() {
		if ack.Reason != "" {
			return ack, fmt.Errorf("engine: bridge rejected: %s: %s", ack.Code, ack.Reason)
		}
		return ack, fmt.Errorf("engine: bridge rejected: %s", ack.Code)
	}
	return ack, nil
}

func PerformHelloAck(pc transport.PathConn, flowID [16]byte, instanceID proto.InstanceID, caps uint32) error {
	payload := proto.HelloAckPayload{FlowID: flowID, InstanceID: instanceID, Caps: caps}.Encode()
	return writeCtrl(pc, proto.CtrlHelloAck, 0, payload, 0)
}

func PerformBridgeAck(pc transport.PathConn, bridgeID [16]byte, instanceID proto.InstanceID, code proto.AckCode, reason string) error {
	payload := proto.BridgeAckPayload{BridgeID: bridgeID, InstanceID: instanceID, Code: code, Reason: reason}.Encode()
	return writeCtrl(pc, proto.CtrlBridgeAck, 0, payload, 0)
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
