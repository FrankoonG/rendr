package rendr

import (
	"context"
	"errors"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

func canonicalFirstControlCode(hdr proto.Header) (proto.CtrlCode, bool) {
	if hdr.Version != proto.Version || hdr.Type != proto.FrameCtrl || hdr.Last || hdr.Seq != 0 {
		return 0, false
	}
	code := proto.CtrlCodeFromFlags(hdr.Flags)
	if hdr.Flags != proto.FlagsForCtrl(code) || (code != proto.CtrlHello && code != proto.CtrlBridgeTag) {
		return 0, false
	}
	return code, true
}

func decodeHelloForAdmission(pc transport.PathConn, payload []byte) (proto.HelloPayload, error) {
	hello, err := proto.DecodeHello(payload)
	rejectIncompatibleNegotiation(pc, err)
	return hello, err
}

func rejectIncompatibleNegotiation(pc transport.PathConn, err error) {
	if err != nil && errors.Is(err, proto.ErrNegotiationIncompatible) {
		_ = engine.PerformBye(pc, proto.ByeProtoVer, 0)
	}
}

func attachServerPath(e *engine.Engine, pc transport.PathConn, spec PathSpec, peerTargetID proto.TargetID) (uint32, proto.TargetID, error) {
	peerName, err := e.PeerPathName(peerTargetID)
	if err != nil {
		return 0, proto.TargetID{}, err
	}
	localTargetID, err := e.LocalPathTargetID(peerName)
	if err != nil {
		return 0, proto.TargetID{}, err
	}
	id, err := e.PreparePathBound(pc, spec, engine.PathBinding{
		LocalTXTargetID: localTargetID,
		PeerTXTargetID:  peerTargetID,
	})
	return id, localTargetID, err
}

func acknowledgeServerPath(ctx context.Context, e *engine.Engine, pathID uint32, pc transport.PathConn, tag proto.BridgeTagPayload, proposalWire []byte, instanceID proto.InstanceID, localTargetID proto.TargetID) error {
	if err := engine.PerformServerBridgeAdmission(ctx, pc, e, pathID, instanceID, localTargetID, tag, proposalWire); err != nil {
		e.AbortPathAttach(pathID, err)
		return err
	}
	return nil
}

func acknowledgeInitialServerPath(ctx context.Context, e *engine.Engine, pathID uint32, pc transport.PathConn, instanceID proto.InstanceID, caps uint32, localTargetID proto.TargetID, hello proto.HelloPayload, proposalWire []byte) error {
	if err := engine.PerformServerHelloAdmission(ctx, pc, e, pathID, instanceID, caps, localTargetID, hello.InitialTargetID, hello, proposalWire); err != nil {
		e.AbortPathAttach(pathID, err)
		return err
	}
	return nil
}

func eLocalCaps(e *engine.Engine) uint32 {
	var caps uint32
	if e.Packetized() {
		caps |= proto.CapsPacketMode
	}
	if e.PeerCaps()&proto.CapsL3Identity != 0 {
		caps |= proto.CapsL3Identity
	}
	return caps
}

func helloPathName(p proto.HelloPayload) string {
	node, _ := p.LocalTXManifest.Node(p.InitialTargetID)
	return node.Name
}

func bridgePathName(e *engine.Engine, p proto.BridgeTagPayload) string {
	name, _ := e.PeerPathName(p.TargetID)
	return name
}

func bridgeValidationAckCode(err error) proto.AckCode {
	if errors.Is(err, engine.ErrDuplicateAttach) {
		return proto.AckRejectDuplicate
	}
	return proto.AckRejectProtoState
}
