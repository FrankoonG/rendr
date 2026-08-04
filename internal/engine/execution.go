package engine

import "github.com/FrankoonG/rendr/proto"

func dispatchForExecutionKind(kind proto.ExecutionKind) (uint32, bool) {
	switch kind {
	case proto.ExecutionKindSelector:
		return dispatchSelector, true
	case proto.ExecutionKindBond:
		return dispatchBond, true
	case proto.ExecutionKindRace:
		return dispatchRace, true
	default:
		return 0, false
	}
}

func senderDirection(side Side) proto.SenderDirection {
	if side == SideClient {
		return proto.SenderDirectionClientToServer
	}
	return proto.SenderDirectionServerToClient
}

func peerSenderDirection(side Side) proto.SenderDirection {
	if side == SideClient {
		return proto.SenderDirectionServerToClient
	}
	return proto.SenderDirectionClientToServer
}
