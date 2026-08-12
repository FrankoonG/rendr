//go:build !linux

package gvisor

import "net"

type outerSocketContext struct{}

// v1.0 production support is Linux-only. Keep socket policy behind this
// platform boundary so a future port can provide its own no-fragment proof.
func platformOuterPacketAvailable() error { return ErrOuterPacketUnsupported }

func platformConfigureOuterUDPPMTU(*net.UDPConn, outerUDPMode) error {
	return ErrOuterPacketUnsupported
}

func platformCaptureOuterSocketContext(net.PacketConn) (outerSocketContext, error) {
	return outerSocketContext{}, ErrOuterPacketUnsupported
}

func platformReleaseOuterSocketContext(*outerSocketContext) {}
