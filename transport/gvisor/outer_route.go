package gvisor

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"
)

type outerNetNSIdentity struct {
	device      uint64
	inode       uint64
	cookie      uint64
	cookieKnown bool
}

func (identity outerNetNSIdentity) valid() bool {
	return identity.device != 0 && identity.inode != 0
}

type outerRoutePlatformEvidence struct {
	local            *net.UDPAddr
	outputInterface  uint32
	pathMTU          int
	pathMTUKnown     bool
	socketMark       uint32
	boundInterface   uint32
	connected        bool
	networkNamespace outerNetNSIdentity
}

type routeObservation struct {
	digest           [sha256.Size]byte
	family           outerUDPMode
	local            *net.UDPAddr
	remote           *net.UDPAddr
	outputInterface  uint32
	pathMTU          int
	pathMTUKnown     bool
	socketMark       uint32
	boundInterface   uint32
	connected        bool
	networkNamespace outerNetNSIdentity
}

func contextCause(ctx context.Context) error {
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	return ctx.Err()
}

func observeUDPRouteForWire(
	ctx context.Context,
	wire *packetWire,
	remote net.Addr,
) (routeObservation, error) {
	if wire == nil || wire.conn == nil {
		return routeObservation{}, errors.New("gvisor: outer UDP route observation has no active socket")
	}
	return observeUDPRouteForConnAndWire(ctx, wire.conn, wire, remote)
}

// observeUDPRouteForConn is retained for package tests and diagnostics. It
// still interrogates the supplied socket itself; it never dials a substitute.
func observeUDPRouteForConn(
	ctx context.Context,
	packetConn net.PacketConn,
	remote net.Addr,
) (routeObservation, error) {
	if packetConn == nil {
		return routeObservation{}, errors.New("gvisor: route observation has no socket")
	}
	wire := newPacketWire(packetConn, true)
	defer wire.releaseSocketContext()
	return observeUDPRouteForConnAndWire(ctx, packetConn, wire, remote)
}

func observeUDPRouteForConnAndWire(
	ctx context.Context,
	packetConn net.PacketConn,
	wire *packetWire,
	remote net.Addr,
) (routeObservation, error) {
	if remote == nil {
		return routeObservation{}, errors.New("gvisor: route observation has no peer")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	udpRemote, err := resolveOuterUDPAddress(remote)
	if err != nil {
		return routeObservation{}, err
	}
	mode, err := outerUDPRemoteMode(udpRemote)
	if err != nil {
		return routeObservation{}, err
	}
	if packetConn.LocalAddr() == nil {
		return routeObservation{}, errors.New("gvisor: outer UDP socket has no local tuple")
	}
	declaredLocal, err := resolveOuterUDPAddress(packetConn.LocalAddr())
	if err != nil {
		return routeObservation{}, fmt.Errorf("gvisor: parse outer UDP local address: %w", err)
	}
	platform, err := platformObserveOuterUDPRoute(ctx, wire, mode, declaredLocal, udpRemote)
	if err != nil {
		return routeObservation{}, err
	}
	return newRouteObservation(mode, platform.local, udpRemote, platform)
}

func newRouteObservation(
	family outerUDPMode,
	local *net.UDPAddr,
	remote *net.UDPAddr,
	platform outerRoutePlatformEvidence,
) (routeObservation, error) {
	if family != outerUDPIPv4 && family != outerUDPIPv6 {
		return routeObservation{}, fmt.Errorf("gvisor: invalid route family %d", family)
	}
	local = cloneOuterUDPAddress(local)
	remote = cloneOuterUDPAddress(remote)
	if local == nil || remote == nil || len(local.IP) == 0 || local.IP.IsUnspecified() || local.Port <= 0 ||
		len(remote.IP) == 0 || remote.IP.IsUnspecified() || remote.Port <= 0 || platform.outputInterface == 0 {
		return routeObservation{}, errors.New("gvisor: incomplete outer UDP route evidence")
	}
	if family == outerUDPIPv4 && (local.IP.To4() == nil || remote.IP.To4() == nil) {
		return routeObservation{}, errors.New("gvisor: IPv4 route evidence has a non-IPv4 address")
	}
	if family == outerUDPIPv6 && (local.IP.To4() != nil || local.IP.To16() == nil ||
		remote.IP.To4() != nil || remote.IP.To16() == nil) {
		return routeObservation{}, errors.New("gvisor: IPv6 route evidence has a non-IPv6 address")
	}
	pathMTUKnown := platform.pathMTUKnown || platform.pathMTU > 0
	if pathMTUKnown && platform.pathMTU <= 0 {
		return routeObservation{}, errors.New("gvisor: invalid known outer UDP path MTU")
	}
	if platform.boundInterface != 0 && platform.boundInterface != platform.outputInterface {
		return routeObservation{}, errors.New("gvisor: outer UDP route violates SO_BINDTODEVICE")
	}
	observation := routeObservation{
		family: family, local: local, remote: remote,
		outputInterface: platform.outputInterface, pathMTU: platform.pathMTU,
		pathMTUKnown: pathMTUKnown, socketMark: platform.socketMark,
		boundInterface: platform.boundInterface, connected: platform.connected,
		networkNamespace: platform.networkNamespace,
	}
	observation.digest = digestRouteObservation(observation)
	return observation, nil
}

func digestRouteObservation(observation routeObservation) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("GVR4"))
	flags := byte(0)
	if observation.pathMTUKnown {
		flags |= 1
	}
	if observation.connected {
		flags |= 2
	}
	if observation.networkNamespace.cookieKnown {
		flags |= 4
	}
	_, _ = hash.Write([]byte{byte(observation.family), flags})
	writeRouteUDPAddress(hash, observation.family, observation.local)
	writeRouteUDPAddress(hash, observation.family, observation.remote)
	var scalar [8]byte
	binary.BigEndian.PutUint32(scalar[:4], observation.outputInterface)
	binary.BigEndian.PutUint32(scalar[4:], uint32(observation.pathMTU))
	_, _ = hash.Write(scalar[:])
	binary.BigEndian.PutUint32(scalar[:4], observation.socketMark)
	binary.BigEndian.PutUint32(scalar[4:], observation.boundInterface)
	_, _ = hash.Write(scalar[:])
	binary.BigEndian.PutUint64(scalar[:], observation.networkNamespace.device)
	_, _ = hash.Write(scalar[:])
	binary.BigEndian.PutUint64(scalar[:], observation.networkNamespace.inode)
	_, _ = hash.Write(scalar[:])
	binary.BigEndian.PutUint64(scalar[:], observation.networkNamespace.cookie)
	_, _ = hash.Write(scalar[:])
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func writeRouteUDPAddress(hash interface{ Write([]byte) (int, error) }, family outerUDPMode, address *net.UDPAddr) {
	if address == nil {
		_, _ = hash.Write(make([]byte, 8))
		return
	}
	ip := address.IP.To16()
	if family == outerUDPIPv4 {
		ip = address.IP.To4()
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(ip)))
	_, _ = hash.Write(size[:])
	_, _ = hash.Write(ip)
	binary.BigEndian.PutUint32(size[:], uint32(address.Port))
	_, _ = hash.Write(size[:])
	binary.BigEndian.PutUint32(size[:], uint32(len(address.Zone)))
	_, _ = hash.Write(size[:])
	_, _ = hash.Write([]byte(address.Zone))
}

func (observation routeObservation) requiredPathMTU() int {
	switch observation.family {
	case outerUDPIPv4:
		return outerIPv4HeaderSize + outerUDPHeaderSize + outerMaxDatagramSize
	case outerUDPIPv6:
		return outerIPv6HeaderSize + outerUDPHeaderSize + outerMaxDatagramSize
	default:
		return 0
	}
}

// qualifiesMaximumData only rejects a route when the active socket supplied a
// factual MTU that is too small. Unknown MTU remains unknown and must be
// resolved by the bilateral maximum-DATA qualification exchange.
func (observation routeObservation) qualifiesMaximumData() bool {
	required := observation.requiredPathMTU()
	return required > 0 && observation.outputInterface != 0 && observation.local != nil && observation.remote != nil &&
		(!observation.pathMTUKnown || observation.pathMTU >= required)
}

func (observation routeObservation) maximumDataError() error {
	if observation.qualifiesMaximumData() {
		return nil
	}
	return newOuterMTUError(
		outerMaxDatagramSize,
		observation.pathMTU,
		observation.requiredPathMTU(),
		fmt.Errorf("active-socket route cannot carry protocol-v5 maximum DATA: %w", syscall.EMSGSIZE),
	)
}

func resolveOuterUDPAddress(address net.Addr) (*net.UDPAddr, error) {
	if address == nil {
		return nil, errors.New("gvisor: nil outer UDP address")
	}
	if udp, ok := address.(*net.UDPAddr); ok {
		return cloneOuterUDPAddress(udp), nil
	}
	resolved, err := net.ResolveUDPAddr("udp", address.String())
	if err != nil {
		return nil, fmt.Errorf("gvisor: resolve outer UDP address %q: %w", address.String(), err)
	}
	return resolved, nil
}

func cloneOuterUDPAddress(address *net.UDPAddr) *net.UDPAddr {
	if address == nil {
		return nil
	}
	return &net.UDPAddr{
		IP: append(net.IP(nil), address.IP...), Port: address.Port, Zone: address.Zone,
	}
}

func outerUDPZonesEqual(left, right string) bool {
	if left == right {
		return true
	}
	leftIndex, leftOK := outerUDPZoneIndex(left)
	rightIndex, rightOK := outerUDPZoneIndex(right)
	return leftOK && rightOK && leftIndex == rightIndex
}

func addrEqualOnWire(wire *packetWire, left, right net.Addr) bool {
	if left == nil || right == nil || left.Network() != right.Network() {
		return false
	}
	leftUDP, leftOK := left.(*net.UDPAddr)
	rightUDP, rightOK := right.(*net.UDPAddr)
	if leftOK && rightOK {
		return leftUDP.Port == rightUDP.Port && leftUDP.IP.Equal(rightUDP.IP) &&
			platformOuterUDPZonesEqual(wire, leftUDP.Zone, rightUDP.Zone)
	}
	return left.String() == right.String()
}

func outerUDPZoneIndex(zone string) (int, bool) {
	if zone == "" {
		return 0, true
	}
	if index, err := strconv.Atoi(zone); err == nil && index > 0 {
		if _, err := net.InterfaceByIndex(index); err == nil {
			return index, true
		}
		return 0, false
	}
	device, err := net.InterfaceByName(zone)
	if err != nil {
		return 0, false
	}
	return device.Index, true
}
