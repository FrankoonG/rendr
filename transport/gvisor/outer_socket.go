package gvisor

import (
	"errors"
	"fmt"
	"net"
	"runtime"
)

// ErrOuterPacketUnsupported reports that this platform cannot prove and
// enforce the outer UDP no-fragment contract. Process-local gVisor links do not
// depend on this capability.
var ErrOuterPacketUnsupported = errors.New("gvisor: outer UDP packet carrier is unsupported on this platform")

type outerUDPMode uint8

const (
	outerUDPIPv4 outerUDPMode = iota + 1
	outerUDPIPv6
	outerUDPDualStack
)

func (mode outerUDPMode) String() string {
	switch mode {
	case outerUDPIPv4:
		return "IPv4"
	case outerUDPIPv6:
		return "IPv6"
	case outerUDPDualStack:
		return "dual-stack"
	default:
		return "invalid"
	}
}

func (mode outerUDPMode) network() (string, error) {
	switch mode {
	case outerUDPIPv4:
		return "udp4", nil
	case outerUDPIPv6:
		return "udp6", nil
	case outerUDPDualStack:
		return "udp", nil
	default:
		return "", fmt.Errorf("gvisor: invalid outer UDP mode %d", mode)
	}
}

func outerUDPListenerMode(address *net.UDPAddr) (outerUDPMode, error) {
	if address == nil || len(address.IP) == 0 {
		return outerUDPDualStack, nil
	}
	if address.IP.To4() != nil {
		return outerUDPIPv4, nil
	}
	if address.IP.To16() != nil {
		return outerUDPIPv6, nil
	}
	return 0, fmt.Errorf("gvisor: invalid outer UDP listener address %v", address)
}

func outerUDPRemoteMode(address *net.UDPAddr) (outerUDPMode, error) {
	if address == nil || len(address.IP) == 0 || address.IP.IsUnspecified() {
		return 0, fmt.Errorf("gvisor: outer UDP peer must have a concrete IP: %v", address)
	}
	if address.IP.To4() != nil {
		return outerUDPIPv4, nil
	}
	if address.IP.To16() != nil {
		return outerUDPIPv6, nil
	}
	return 0, fmt.Errorf("gvisor: invalid outer UDP peer address %v", address)
}

type outerUDPPMTUConfigurer func(*net.UDPConn, outerUDPMode) error

// PacketAvailable reports whether real outer UDP packet carriers can enforce
// the platform PMTU contract. Available continues to describe process-local
// gVisor carrier availability.
func PacketAvailable() error { return platformOuterPacketAvailable() }

func listenOuterUDP(mode outerUDPMode, local *net.UDPAddr) (*net.UDPConn, error) {
	if err := PacketAvailable(); err != nil {
		return nil, err
	}
	return listenOuterUDPWithConfigurer(mode, local, platformConfigureOuterUDPPMTU)
}

func listenOuterUDPWire(mode outerUDPMode, local *net.UDPAddr, shared bool) (*packetWire, error) {
	// Keeping creation and namespace capture on one OS thread provides the
	// kernel-5 fallback when SO_NETNS_COOKIE is unavailable.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	conn, err := listenOuterUDP(mode, local)
	if err != nil {
		return nil, err
	}
	socket, socketErr := platformCaptureOuterSocketContext(conn)
	if socketErr != nil {
		_ = conn.Close()
		return nil, socketErr
	}
	wire := newPacketWireWithSocketContext(conn, shared, socket)
	wire.bindMode = mode
	wire.bindLocal = cloneOuterUDPAddress(local)
	wire.bindKnown = true
	return wire, nil
}

func (wire *packetWire) successorBindAddress(mode outerUDPMode, selected *net.UDPAddr) (*net.UDPAddr, error) {
	if wire == nil {
		return nil, net.ErrClosed
	}
	if !wire.bindKnown {
		fallback := cloneOuterUDPAddress(selected)
		if fallback != nil {
			fallback.Port = 0
		}
		return fallback, nil
	}
	if wire.bindMode != mode && wire.bindMode != outerUDPDualStack {
		return nil, fmt.Errorf("gvisor: successor family %s conflicts with captured bind family %s", mode, wire.bindMode)
	}
	local := cloneOuterUDPAddress(wire.bindLocal)
	if local != nil {
		local.Port = 0
	}
	return local, nil
}

func listenOuterUDPWithConfigurer(
	mode outerUDPMode,
	local *net.UDPAddr,
	configure outerUDPPMTUConfigurer,
) (*net.UDPConn, error) {
	network, err := mode.network()
	if err != nil {
		return nil, err
	}
	if err := validateOuterUDPLocal(mode, local); err != nil {
		return nil, err
	}
	if configure == nil {
		return nil, errors.New("gvisor: outer UDP PMTU configurer is unavailable")
	}
	conn, err := net.ListenUDP(network, local)
	if err != nil {
		return nil, err
	}
	if err := configure(conn, mode); err != nil {
		proofErr := fmt.Errorf("gvisor: prove %s outer UDP no-fragment PMTU policy: %w", mode, err)
		if closeErr := conn.Close(); closeErr != nil {
			return nil, errors.Join(proofErr, fmt.Errorf("gvisor: close rejected outer UDP socket: %w", closeErr))
		}
		return nil, proofErr
	}
	return conn, nil
}

func validateOuterUDPLocal(mode outerUDPMode, local *net.UDPAddr) error {
	if local == nil {
		return nil
	}
	switch mode {
	case outerUDPIPv4:
		if len(local.IP) == 0 || local.IP.To4() != nil {
			return nil
		}
	case outerUDPIPv6:
		if len(local.IP) == 0 || (local.IP.To4() == nil && local.IP.To16() != nil) {
			return nil
		}
	case outerUDPDualStack:
		if len(local.IP) == 0 {
			return nil
		}
	default:
		return fmt.Errorf("gvisor: invalid outer UDP mode %d", mode)
	}
	return fmt.Errorf("gvisor: %s outer UDP mode conflicts with local address %v", mode, local)
}
