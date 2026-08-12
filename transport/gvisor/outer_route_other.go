//go:build !linux

package gvisor

import (
	"context"
	"net"
)

func platformObserveOuterUDPRoute(
	context.Context,
	*packetWire,
	outerUDPMode,
	*net.UDPAddr,
	*net.UDPAddr,
) (outerRoutePlatformEvidence, error) {
	return outerRoutePlatformEvidence{}, ErrOuterPacketUnsupported
}

func platformOuterUDPZonesEqual(_ *packetWire, left, right string) bool {
	return outerUDPZonesEqual(left, right)
}
