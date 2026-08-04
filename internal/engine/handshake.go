package engine

import (
	"errors"
	"fmt"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

func PerformClientHelloAck(pc transport.PathConn, e *Engine, instanceID proto.InstanceID, caps uint32, name string) (proto.HelloAckPayload, error) {
	flowID := e.FlowID()
	targetID, err := e.LocalPathTargetID(name)
	if err != nil {
		return proto.HelloAckPayload{}, err
	}
	payload, err := (proto.HelloPayload{
		Negotiation:     e.LocalNegotiation(),
		FlowID:          flowID,
		InstanceID:      instanceID,
		Caps:            caps,
		InitialTargetID: targetID,
		LocalTXManifest: e.LocalGraphManifest(),
	}).Encode()
	if err != nil {
		return proto.HelloAckPayload{}, err
	}
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
	local := e.localGraphBinding()
	if ack.AcceptedPeerBinding.Revision != local.revision || ack.AcceptedPeerBinding.Digest != local.digest {
		return proto.HelloAckPayload{}, fmt.Errorf("engine: HELLO_ACK did not accept local graph binding")
	}
	if err := e.AcceptPeerNegotiation(ack.Negotiation, ack.LocalTXManifest); err != nil {
		return proto.HelloAckPayload{}, err
	}
	return ack, nil
}

func PerformClientBridgeTagAck(pc transport.PathConn, e *Engine, name string) (proto.BridgeAckPayload, error) {
	targetID, err := e.LocalPathTargetID(name)
	if err != nil {
		return proto.BridgeAckPayload{}, err
	}
	tag := newBridgeTagPayload(e, targetID)
	payload := tag.Encode()
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
	if ack.BridgeID != e.FlowID() {
		return proto.BridgeAckPayload{}, fmt.Errorf("engine: BRIDGE_ACK flow mismatch")
	}
	if ack.InstanceID != e.PeerInstanceID() {
		return proto.BridgeAckPayload{}, fmt.Errorf("engine: BRIDGE_ACK instance mismatch")
	}
	if ack.SessionEpoch != tag.SessionEpoch || ack.GraphRevision != tag.GraphRevision ||
		ack.GraphDigest != tag.GraphDigest || ack.TargetID != tag.TargetID ||
		ack.AttachID != tag.AttachID || ack.Direction != tag.Direction {
		return proto.BridgeAckPayload{}, fmt.Errorf("engine: BRIDGE_ACK binding mismatch")
	}
	if !ack.Code.OK() {
		if ack.Reason != "" {
			return ack, fmt.Errorf("engine: bridge rejected: %s: %s", ack.Code, ack.Reason)
		}
		return ack, fmt.Errorf("engine: bridge rejected: %s", ack.Code)
	}
	if _, err := e.PeerPathName(ack.ResponderTargetID); err != nil {
		return ack, fmt.Errorf("engine: BRIDGE_ACK responder target: %w", err)
	}
	return ack, nil
}

func PerformHelloAck(pc transport.PathConn, e *Engine, instanceID proto.InstanceID, caps uint32, localTargetID proto.TargetID) error {
	peer := e.peerGraphBinding()
	payload, err := (proto.HelloAckPayload{
		Negotiation:         e.LocalNegotiation(),
		FlowID:              e.FlowID(),
		InstanceID:          instanceID,
		Caps:                caps,
		InitialTargetID:     localTargetID,
		AcceptedPeerBinding: proto.GraphBinding{Revision: peer.revision, Digest: peer.digest},
		LocalTXManifest:     e.LocalGraphManifest(),
	}).Encode()
	if err != nil {
		return err
	}
	return writeCtrl(pc, proto.CtrlHelloAck, 0, payload, 0)
}

func PerformBridgeAck(pc transport.PathConn, tag proto.BridgeTagPayload, instanceID proto.InstanceID, code proto.AckCode, reason string) error {
	return PerformBridgeAckForTarget(pc, tag, instanceID, tag.TargetID, code, reason)
}

// PerformBridgeAckForTarget acknowledges an attached full-duplex carrier and
// declares the independently selected responder-TX leaf. Rejection paths may
// use PerformBridgeAck because the responder identity is ignored unless OK.
func PerformBridgeAckForTarget(pc transport.PathConn, tag proto.BridgeTagPayload, instanceID proto.InstanceID, responderTargetID proto.TargetID, code proto.AckCode, reason string) error {
	payload := proto.BridgeAckPayload{
		BridgeID:          tag.BridgeID,
		AttachID:          tag.AttachID,
		InstanceID:        instanceID,
		SessionEpoch:      tag.SessionEpoch,
		Direction:         tag.Direction,
		GraphRevision:     tag.GraphRevision,
		GraphDigest:       tag.GraphDigest,
		TargetID:          tag.TargetID,
		ResponderTargetID: responderTargetID,
		Code:              code,
		Reason:            reason,
	}.Encode()
	return writeCtrl(pc, proto.CtrlBridgeAck, 0, payload, 0)
}

func newBridgeTagPayload(e *Engine, targetID proto.TargetID) proto.BridgeTagPayload {
	negotiation := e.LocalNegotiation()
	return proto.BridgeTagPayload{
		BridgeID:               e.FlowID(),
		AttachID:               NewClientFlowID(),
		InstanceID:             e.LocalInstanceID(),
		ExpectedPeerInstanceID: e.PeerInstanceID(),
		SessionEpoch:           negotiation.SessionEpoch,
		Direction:              senderDirection(e.side),
		GraphRevision:          negotiation.GraphRevision,
		GraphDigest:            negotiation.GraphDigest,
		TargetID:               targetID,
	}
}

// ValidateBridgeBinding verifies an attach request against immutable session
// identity before the caller allocates a path id or starts reader goroutines.
func (e *Engine) ValidateBridgeBinding(tag proto.BridgeTagPayload) error {
	if tag.BridgeID != e.flowID || tag.SessionEpoch != proto.SessionEpoch(e.flowID) {
		return fmt.Errorf("engine: bridge session epoch mismatch")
	}
	binding := e.peerGraphBinding()
	if tag.GraphRevision != binding.revision || tag.GraphDigest != binding.digest {
		return fmt.Errorf("engine: bridge graph binding mismatch")
	}
	if tag.InstanceID == (proto.InstanceID{}) || tag.InstanceID != e.PeerInstanceID() {
		return fmt.Errorf("engine: bridge sender instance mismatch")
	}
	if tag.ExpectedPeerInstanceID == (proto.InstanceID{}) || tag.ExpectedPeerInstanceID != e.LocalInstanceID() {
		return fmt.Errorf("engine: bridge receiver instance mismatch")
	}
	if tag.Direction != peerSenderDirection(e.side) {
		return fmt.Errorf("engine: bridge sender direction mismatch")
	}
	node, ok := binding.manifest.Node(tag.TargetID)
	if !ok || node.Kind != proto.GraphNodeKindPath {
		return fmt.Errorf("engine: bridge target is not a path in the peer graph")
	}
	e.attachMu.Lock()
	if _, duplicate := e.seenAttach[tag.AttachID]; duplicate {
		e.attachMu.Unlock()
		return ErrDuplicateAttach
	}
	e.seenAttach[tag.AttachID] = struct{}{}
	e.attachMu.Unlock()
	return nil
}

var ErrDuplicateAttach = errors.New("engine: duplicate bridge attach id")

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
