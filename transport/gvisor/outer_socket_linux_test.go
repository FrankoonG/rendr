//go:build linux

package gvisor

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"golang.org/x/sys/unix"
)

func TestLinuxOuterPacketAvailable(t *testing.T) {
	if err := PacketAvailable(); err != nil {
		t.Fatal(err)
	}
}

func TestOuterUDPPMTUReadbackIPv4IPv6AndDualStack(t *testing.T) {
	tests := []struct {
		name  string
		mode  outerUDPMode
		local *net.UDPAddr
		check func(*net.UDPConn) error
	}{
		{
			name: "ipv4", mode: outerUDPIPv4,
			local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
			check: func(conn *net.UDPConn) error {
				return requireOuterSocketOption(conn, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
			},
		},
		{
			name: "ipv6", mode: outerUDPIPv6,
			local: &net.UDPAddr{IP: net.IPv6loopback},
			check: func(conn *net.UDPConn) error {
				if err := requireOuterSocketOption(conn, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1); err != nil {
					return err
				}
				return requireOuterSocketOption(conn, unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO)
			},
		},
		{
			name: "dual-stack", mode: outerUDPDualStack, local: &net.UDPAddr{},
			check: func(conn *net.UDPConn) error {
				for _, option := range []struct {
					level, name, want int
				}{
					{unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 0},
					{unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO},
					{unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO},
				} {
					if err := requireOuterSocketOption(conn, option.level, option.name, option.want); err != nil {
						return err
					}
				}
				return nil
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn, err := listenOuterUDP(test.mode, test.local)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := test.check(conn); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLinuxOuterRouteEvidenceUsesExactSocketFlow(t *testing.T) {
	for _, test := range []struct {
		name   string
		mode   outerUDPMode
		local  *net.UDPAddr
		family outerUDPMode
	}{
		{name: "ipv4", mode: outerUDPIPv4, local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, family: outerUDPIPv4},
		{name: "ipv6", mode: outerUDPIPv6, local: &net.UDPAddr{IP: net.IPv6loopback}, family: outerUDPIPv6},
	} {
		t.Run(test.name, func(t *testing.T) {
			sender, err := listenOuterUDP(test.mode, test.local)
			if err != nil {
				t.Fatal(err)
			}
			defer sender.Close()
			receiver, err := listenOuterUDP(test.mode, test.local)
			if err != nil {
				t.Fatal(err)
			}
			defer receiver.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			observation, err := observeUDPRouteForConn(ctx, sender, receiver.LocalAddr())
			if err != nil {
				t.Fatal(err)
			}
			wantLocal := sender.LocalAddr().(*net.UDPAddr)
			wantRemote := receiver.LocalAddr().(*net.UDPAddr)
			if observation.family != test.family || observation.local.Port != wantLocal.Port ||
				!observation.local.IP.Equal(wantLocal.IP) || observation.remote.Port != wantRemote.Port ||
				!observation.remote.IP.Equal(wantRemote.IP) || observation.outputInterface == 0 ||
				!observation.networkNamespace.valid() || !observation.qualifiesMaximumData() {
				t.Fatalf("exact Linux route evidence=%+v local=%v remote=%v", observation, wantLocal, wantRemote)
			}
		})
	}
}

func TestLinuxOuterRouteEvidenceUsesActualConnectedSocketPMTU(t *testing.T) {
	receiver, err := listenOuterUDP(outerUDPIPv4, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	remote := receiver.LocalAddr().(*net.UDPAddr)
	connected, err := net.DialUDP("udp4", nil, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer connected.Close()
	if err := platformConfigureOuterUDPPMTU(connected, outerUDPIPv4); err != nil {
		t.Fatal(err)
	}
	wire := newPacketWire(connected, false)
	defer wire.releaseSocketContext()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	observation, err := observeUDPRouteForWire(ctx, wire, remote)
	if err != nil {
		t.Fatal(err)
	}
	local := connected.LocalAddr().(*net.UDPAddr)
	if !observation.connected || !observation.pathMTUKnown || observation.pathMTU <= 0 ||
		observation.local.Port != local.Port || !observation.local.IP.Equal(local.IP) ||
		observation.networkNamespace.cookieKnown && observation.networkNamespace.cookie == 0 {
		t.Fatalf("connected active-socket evidence=%+v local=%v", observation, local)
	}
}

func TestLinuxOuterRouteEvidenceUsesActiveSocketMarkAndBoundDevice(t *testing.T) {
	sender, err := listenOuterUDP(outerUDPIPv4, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	receiver, err := listenOuterUDP(outerUDPIPv4, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	loopback, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sender.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	const mark = 0x4a31
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		if optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark); optionErr == nil {
			optionErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, loopback.Name)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if optionErr != nil {
		if optionErr == unix.EPERM || optionErr == unix.EACCES {
			t.Skipf("socket mark/bound-device mutation requires privilege: %v", optionErr)
		}
		t.Fatal(optionErr)
	}
	wire := newPacketWire(sender, false)
	defer wire.releaseSocketContext()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	observation, err := observeUDPRouteForWire(ctx, wire, receiver.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	if observation.socketMark != mark || observation.boundInterface != uint32(loopback.Index) ||
		observation.outputInterface != uint32(loopback.Index) ||
		observation.local.Port != sender.LocalAddr().(*net.UDPAddr).Port {
		t.Fatalf("active socket mark/device evidence=%+v", observation)
	}
}

func TestLinuxOuterRouteEvidenceRejectsWrongCapturedNetNS(t *testing.T) {
	sender, err := listenOuterUDP(outerUDPIPv4, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	receiver, err := listenOuterUDP(outerUDPIPv4, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	wire := newPacketWire(sender, false)
	defer wire.releaseSocketContext()
	wire.socket.mu.Lock()
	wire.socket.identity.inode++
	wire.socket.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if observation, err := observeUDPRouteForWire(ctx, wire, receiver.LocalAddr()); err == nil {
		t.Fatalf("wrong network namespace identity produced evidence=%+v", observation)
	}

	t.Run("successor socket uses active socket namespace", func(t *testing.T) {
		testLinuxOuterSuccessorSocketUsesActiveSocketNetworkNamespace(t)
	})
}

func TestLinuxOuterRouteZonesAcceptNumericAndRejectConflict(t *testing.T) {
	loopback, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	numeric := strconv.Itoa(loopback.Index)
	index, err := resolveOuterRouteZones("lo", numeric)
	if err != nil || index != uint32(loopback.Index) {
		t.Fatalf("name/numeric zone=(%d,%v)", index, err)
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range interfaces {
		if candidate.Index == loopback.Index {
			continue
		}
		if _, err := resolveOuterRouteZones(numeric, strconv.Itoa(candidate.Index)); err == nil {
			t.Fatalf("conflicting numeric zones %d/%d accepted", loopback.Index, candidate.Index)
		}
		return
	}
	t.Skip("only one network interface is available")
}

func TestLinuxOuterZoneEqualityUsesCapturedSocketNetNS(t *testing.T) {
	loopback, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := listenOuterUDP(outerUDPIPv6, &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	wire := newPacketWire(conn, false)
	defer wire.releaseSocketContext()
	left := &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 43501, Zone: "lo"}
	right := &net.UDPAddr{
		IP: net.ParseIP("fe80::1"), Port: 43501, Zone: strconv.Itoa(loopback.Index),
	}
	if !addrEqualOnWire(wire, left, right) {
		t.Fatal("name/numeric zones in the captured socket namespace did not compare equal")
	}
	wire.socket.mu.Lock()
	wire.socket.identity.inode++
	wire.socket.mu.Unlock()
	if addrEqualOnWire(wire, left, right) {
		t.Fatal("zone comparison fell back to the caller namespace after captured identity mismatch")
	}

	t.Run("restore-failure-abandons-locked-thread", func(t *testing.T) {
		operationErr := errors.New("injected namespace operation failure")
		restoreErr := errors.New("injected namespace restore failure")
		locks, unlocks, abandons := 0, 0, 0
		err := runOuterNamespaceWorker(
			func() (bool, error) { return true, nil },
			func() error { return operationErr },
			func() error { return restoreErr },
			outerNamespaceThreadHooks{
				lock:    func() { locks++ },
				unlock:  func() { unlocks++ },
				abandon: func() { abandons++ },
			},
		)
		if !errors.Is(err, operationErr) || !errors.Is(err, restoreErr) {
			t.Fatalf("worker error=%v, want operation and restore failures", err)
		}
		if locks != 1 || unlocks != 0 || abandons != 1 {
			t.Fatalf("thread lifecycle locks=%d unlocks=%d abandons=%d", locks, unlocks, abandons)
		}
	})
}

func TestLinuxOuterRouteMetricsParserRejectsMalformedAndPreservesUnknown(t *testing.T) {
	if mtu, known, err := parseOuterRouteMTU(nil); err != nil || known || mtu != 0 {
		t.Fatalf("absent RTAX_MTU=(%d,%t,%v)", mtu, known, err)
	}
	var mtuValue [4]byte
	binary.NativeEndian.PutUint32(mtuValue[:], 1280)
	valid := outerNetlinkAttribute(unix.RTAX_MTU, mtuValue[:])
	if mtu, known, err := parseOuterRouteMTU(valid); err != nil || !known || mtu != 1280 {
		t.Fatalf("valid RTAX_MTU=(%d,%t,%v)", mtu, known, err)
	}
	malformed := map[string][]byte{
		"short-header": {1, 2, 3},
		"short-length": {3, 0, byte(unix.RTAX_MTU), 0},
		"long-length":  {12, 0, byte(unix.RTAX_MTU), 0, 0, 0, 5, 0},
		"short-mtu":    {7, 0, byte(unix.RTAX_MTU), 0, 0, 0, 5, 0},
	}
	for name, value := range malformed {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseOuterRouteMTU(value); err == nil {
				t.Fatal("malformed RTA_METRICS was accepted")
			}
		})
	}
	duplicate := append(append([]byte(nil), valid...), valid...)
	if _, _, err := parseOuterRouteMTU(duplicate); err == nil {
		t.Fatal("duplicate RTAX_MTU was accepted")
	}
}

func TestLinuxOuterRouteRequestAndResponseValidateSelectors(t *testing.T) {
	local := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 41000}
	remote := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 42000}
	request, err := outerUDPRouteRequest(outerUDPIPv4, local, remote, 0x10203, 7, 99)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := syscall.ParseNetlinkMessage(request)
	if err != nil || len(messages) != 1 {
		t.Fatalf("parse route request messages=%d err=%v", len(messages), err)
	}
	messages[0].Header.Type = unix.RTM_NEWROUTE
	attributes, err := syscall.ParseNetlinkRouteAttr(&messages[0])
	if err != nil {
		t.Fatal(err)
	}
	found := make(map[uint16][]byte)
	for _, attribute := range attributes {
		found[attribute.Attr.Type&0x3fff] = append([]byte(nil), attribute.Value...)
	}
	for _, selector := range []struct {
		typ  uint16
		size int
	}{
		{unix.RTA_MARK, 4}, {unix.RTA_OIF, 4}, {unix.RTA_SPORT, 2},
		{unix.RTA_DPORT, 2}, {unix.RTA_SRC, net.IPv4len}, {unix.RTA_DST, net.IPv4len},
	} {
		if len(found[selector.typ]) != selector.size {
			t.Fatalf("route selector %d size=%d want %d", selector.typ, len(found[selector.typ]), selector.size)
		}
	}
	if binary.NativeEndian.Uint32(found[unix.RTA_MARK]) != 0x10203 ||
		binary.NativeEndian.Uint32(found[unix.RTA_OIF]) != 7 ||
		binary.BigEndian.Uint16(found[unix.RTA_SPORT]) != 41000 ||
		binary.BigEndian.Uint16(found[unix.RTA_DPORT]) != 42000 ||
		!net.IP(found[unix.RTA_SRC]).Equal(local.IP) || !net.IP(found[unix.RTA_DST]).Equal(remote.IP) {
		t.Fatalf("route selectors=%v", found)
	}

	body := make([]byte, unix.SizeofRtMsg)
	body[0] = unix.AF_INET
	message := syscall.NetlinkMessage{Data: append(body, outerNetlinkAttribute(unix.RTA_OIF, []byte{7, 0, 0})...)}
	if _, err := parseOuterUDPRoute(message, outerUDPIPv4, 7); err == nil {
		t.Fatal("malformed OIF was accepted")
	}
	message = syscall.NetlinkMessage{Data: body}
	if _, err := parseOuterUDPRoute(message, outerUDPIPv4, 0); err == nil {
		t.Fatal("route response without OIF was accepted")
	}
}

func TestLinuxSuccessorReceiverRejectsKernelTruncatedDatagram(t *testing.T) {
	receiver, err := listenOuterUDP(outerUDPIPv4, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	sender, err := listenOuterUDP(outerUDPIPv4, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		receiver.Close()
		t.Fatal(err)
	}
	defer sender.Close()
	wire := newPacketWire(receiver, false)
	injected := make(chan []byte, 2)
	owner, err := newLinkOwner(
		linkID{1}, linkSecret{2}, leafmobility.RoleDialer, [4]byte{10, 64, 0, 8}, wire,
		sender.LocalAddr(), nil, func(packet []byte) { injected <- append([]byte(nil), packet...) },
	)
	if err != nil {
		wire.close()
		t.Fatal(err)
	}
	defer owner.close()
	owner.startReceiver(wire)

	truncatedPrefix, err := encodeOuterData(
		owner.id, 1, 1, inboundTestPacket(owner, packetMTU, 0xa1), owner.secret,
	)
	if err != nil {
		t.Fatal(err)
	}
	oversized := append(truncatedPrefix, 0xde, 0xad)
	validPacket := inboundTestPacket(owner, packetMTU, 0xb2)
	valid, err := encodeOuterData(owner.id, 1, 1, validPacket, owner.secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sender.WriteTo(oversized, receiver.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if _, err := sender.WriteTo(valid, receiver.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	select {
	case packet := <-injected:
		if !bytes.Equal(packet, validPacket) {
			t.Fatal("kernel-truncated oversized DATA prefix reached the successor endpoint")
		}
	case <-time.After(time.Second):
		t.Fatal("valid DATA after kernel truncation was not received")
	}
	select {
	case <-injected:
		t.Fatal("kernel-truncated and valid DATA were both injected")
	case <-time.After(30 * time.Millisecond):
	}
}

func requireOuterSocketOption(conn *net.UDPConn, level, option, want int) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var got int
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		got, optionErr = unix.GetsockoptInt(int(fd), level, option)
	}); err != nil {
		return err
	}
	if optionErr != nil {
		return optionErr
	}
	if got != want {
		return fmt.Errorf("socket option level=%d name=%d readback=%d want %d", level, option, got, want)
	}
	return nil
}
