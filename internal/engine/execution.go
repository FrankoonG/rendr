package engine

import "github.com/FrankoonG/rendr/proto"

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
