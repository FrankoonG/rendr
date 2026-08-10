//go:build linux

package tun

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/platform"
	"github.com/FrankoonG/rendr/l3ingress"
	"github.com/FrankoonG/rendr/virtualif"
	"golang.org/x/sys/unix"
)

const (
	realTUNTestEnvironment = "RENDR_TUN_REAL_IO_TEST"
	realTUNTestNetNSID     = "RENDR_TUN_REAL_IO_NETNS_ID"
)

func TestPrivilegedTUNRealIPv4IPv6IO(t *testing.T) {
	requireRealTUNTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	features, err := platform.Detect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, feature := range []platform.FeatureID{
		platform.FeatureTUNOpen,
		platform.FeatureTUNSetIFF,
		platform.FeatureTUNSingleQueue,
	} {
		evidence, ok := features.Feature(feature)
		if !ok || evidence.State != platform.FeatureAvailable {
			t.Fatalf("feature %s=%+v present=%t", feature, evidence, ok)
		}
	}

	const mtu = 1280
	device, err := Open(Config{Enabled: true, Name: "rndrio%d", MTU: mtu, Queues: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	if device.QueueCount() != 1 || device.MTU() != mtu {
		t.Fatalf("device queues/mtu=%d/%d want 1/%d", device.QueueCount(), device.MTU(), mtu)
	}
	assertTUNOpenIsExclusive(t, device)
	if _, err := device.ReadContext(ctx, make([]byte, mtu-1)); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("undersized packet buffer error=%v want io.ErrShortBuffer", err)
	}
	if _, err := device.Write(make([]byte, mtu+1)); !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatalf("oversized raw packet error=%v want EMSGSIZE", err)
	}
	runIP(t, "link", "set", "dev", device.Name(), "up")
	ipv4Prefix := netip.MustParsePrefix("198.18.96.1/30")
	ipv6Prefix := netip.MustParsePrefix("fd00:72:1::1/126")
	runIP(t, "addr", "add", ipv4Prefix.String(), "dev", device.Name())
	assertTUNInterfaceState(t, device, mtu, ipv4Prefix)
	assertReadDoesNotSilentlyTruncate(t, device,
		netip.MustParseAddr("198.18.96.1"), netip.MustParseAddr("198.18.96.2"), 1400)
	runIP(t, "-6", "addr", "add", ipv6Prefix.String(), "dev", device.Name(), "nodad")
	assertTUNInterfaceState(t, device, mtu, ipv4Prefix, ipv6Prefix)

	for _, test := range []struct {
		name    string
		network string
		local   netip.Addr
		remote  netip.Addr
	}{
		{name: "ipv4", network: "udp4", local: netip.MustParseAddr("198.18.96.1"), remote: netip.MustParseAddr("198.18.96.2")},
		{name: "ipv6", network: "udp6", local: netip.MustParseAddr("fd00:72:1::1"), remote: netip.MustParseAddr("fd00:72:1::2")},
	} {
		t.Run(test.name, func(t *testing.T) {
			assertKernelToTUNUDP(t, device, test.network, test.local, test.remote, []byte("kernel-to-tun-"+test.name))
			assertTUNToKernelUDP(t, device, test.network, test.local, test.remote, []byte("tun-to-kernel-"+test.name))
			headerBytes := 28
			if test.local.Is6() {
				headerBytes = 48
			}
			boundary := bytes.Repeat([]byte{byte(device.MTU() % 251)}, device.MTU()-headerBytes)
			packet := assertKernelToTUNUDP(t, device, test.network, test.local, test.remote, boundary)
			if len(packet) != device.MTU() {
				t.Fatalf("MTU boundary packet=%d want=%d", len(packet), device.MTU())
			}
			assertKernelRejectsOversizeUDP(t, device, test.network, test.local, test.remote, len(boundary)+1)
		})
	}
}

func TestPrivilegedTUNMultiQueueDistributesRealPackets(t *testing.T) {
	requireRealTUNTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	features, err := platform.Detect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	evidence, ok := features.Feature(platform.FeatureTUNMultiQueue)
	if !ok || evidence.State != platform.FeatureAvailable {
		t.Fatalf("multiqueue feature=%+v present=%t", evidence, ok)
	}

	device, err := Open(Config{Enabled: true, Name: "rndrmq%d", MTU: 1400, Queues: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	if device.QueueCount() != 2 {
		t.Fatalf("queue count=%d want=2", device.QueueCount())
	}
	assertTUNOpenIsExclusive(t, device)
	runIP(t, "link", "set", "dev", device.Name(), "up")
	prefix := netip.MustParsePrefix("198.18.97.1/24")
	runIP(t, "addr", "add", prefix.String(), "dev", device.Name())
	assertTUNInterfaceState(t, device, 1400, prefix)

	const packets = 256
	local := netip.MustParseAddr("198.18.97.1")
	remote := netip.MustParseAddr("198.18.97.2")
	assertKernelToTUNUDP(t, device, "udp4", local, remote, []byte("aggregate-device-read"))
	assertPublicTUNWriteSequence(t, device, local, remote)
	assertEachTUNQueueToKernelUDP(t, device, local, remote)
	readCtx, stopReaders := context.WithCancel(ctx)
	observed := make(chan tunQueueObservation, packets*2)
	errorsCh := make(chan error, 2)
	var readers sync.WaitGroup
	for queue := 0; queue < device.QueueCount(); queue++ {
		readers.Add(1)
		go func(queue int) {
			defer readers.Done()
			readTUNQueuePackets(readCtx, device, queue, local, remote, observed, errorsCh)
		}(queue)
	}

	connections := make([]*net.UDPConn, packets)
	defer closeUDPConnections(connections)
	for sequence := 0; sequence < packets; sequence++ {
		conn, err := net.DialUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, 0)),
			net.UDPAddrFromAddrPort(netip.AddrPortFrom(remote, 49000)))
		if err != nil {
			stopReaders()
			readers.Wait()
			t.Fatal(err)
		}
		connections[sequence] = conn
		payload := make([]byte, 8)
		copy(payload, "RMQ1")
		binary.BigEndian.PutUint32(payload[4:], uint32(sequence))
		if _, err := conn.Write(payload); err != nil {
			stopReaders()
			readers.Wait()
			t.Fatal(err)
		}
	}

	seen := make(map[uint32]int, packets)
	counts := make([]int, device.QueueCount())
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for len(seen) < packets {
		select {
		case got := <-observed:
			if previous, duplicate := seen[got.sequence]; duplicate {
				stopReaders()
				readers.Wait()
				t.Fatalf("sequence %d observed on queues %d and %d", got.sequence, previous, got.queue)
			}
			seen[got.sequence] = got.queue
			counts[got.queue]++
		case err := <-errorsCh:
			stopReaders()
			readers.Wait()
			t.Fatal(err)
		case <-deadline.C:
			stopReaders()
			readers.Wait()
			t.Fatalf("multiqueue packets=%d/%d distribution=%v", len(seen), packets, counts)
		}
	}
	stopReaders()
	readers.Wait()
	if counts[0] == 0 || counts[1] == 0 {
		t.Fatalf("kernel did not distribute packets across both queues: %v", counts)
	}
	representatives := make([]*net.UDPConn, device.QueueCount())
	for sequence, queue := range seen {
		if representatives[queue] == nil {
			representatives[queue] = connections[sequence]
		}
	}
	assertPublicTUNReadAcrossQueues(t, device, representatives, local, remote)
}

func TestPrivilegedTUNDeviceLifecycleIsBounded(t *testing.T) {
	requireRealTUNTest(t)
	baselineFDs := countOpenFDs(t)
	baselineGoroutines := runtime.NumGoroutine()
	const cycles = 100
	for cycle := 0; cycle < cycles; cycle++ {
		queues := 1 + cycle%2
		device, err := Open(Config{Enabled: true, Name: "rndrl%d", MTU: 1400, Queues: queues})
		if err != nil {
			t.Fatalf("cycle %d open: %v", cycle, err)
		}
		name := device.Name()
		if cycle == 0 {
			pollEntered := observeNextPoll(device)
			readCtx, cancelRead := context.WithCancel(context.Background())
			readDone := make(chan error, 1)
			go func() {
				buffer := make([]byte, 1500)
				_, readErr := device.ReadContext(readCtx, buffer)
				readDone <- readErr
			}()
			select {
			case <-pollEntered:
			case <-time.After(time.Second):
				t.Fatal("ReadContext did not enter poll loop")
			}
			cancelRead()
			select {
			case err := <-readDone:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cycle %d canceled read error=%v want context.Canceled", cycle, err)
				}
			case <-time.After(time.Second):
				t.Fatal("ReadContext did not observe cancellation")
			}
			if _, err := net.InterfaceByName(name); err != nil {
				t.Fatalf("ReadContext cancellation destroyed live interface: %v", err)
			}
			if err := device.Close(); err != nil {
				t.Fatalf("cycle %d close: %v", cycle, err)
			}
		} else if cycle == 1 {
			pollEntered := observeNextPoll(device)
			readDone := make(chan error, 1)
			go func() {
				buffer := make([]byte, 1500)
				_, readErr := device.Read(buffer)
				readDone <- readErr
			}()
			select {
			case <-pollEntered:
			case <-time.After(time.Second):
				t.Fatal("Device.Read did not enter poll loop")
			}
			if err := device.Close(); err != nil {
				t.Fatalf("cycle %d close: %v", cycle, err)
			}
			select {
			case err := <-readDone:
				if !errors.Is(err, os.ErrClosed) {
					t.Fatalf("blocked read error=%v want os.ErrClosed", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Device.Close did not release blocked Read")
			}
		} else if err := device.Close(); err != nil {
			t.Fatalf("cycle %d close: %v", cycle, err)
		}
		if cycle < 2 {
			if _, err := device.ReadContext(context.Background(), make([]byte, 1)); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("cycle %d post-close read error=%v want os.ErrClosed", cycle, err)
			}
			if _, err := device.Write(make([]byte, device.MTU()+1)); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("cycle %d post-close write error=%v want os.ErrClosed", cycle, err)
			}
		}
		waitTUNInterfaceGone(t, name)
	}
	runtime.GC()
	if current := countOpenFDs(t); current > baselineFDs+2 {
		t.Fatalf("TUN fd slope baseline=%d current=%d", baselineFDs, current)
	}
	if current := runtime.NumGoroutine(); current > baselineGoroutines+2 {
		t.Fatalf("TUN goroutine slope baseline=%d current=%d", baselineGoroutines, current)
	}
}

type tunQueueObservation struct {
	queue    int
	sequence uint32
}

func requireRealTUNTest(t testing.TB) {
	t.Helper()
	if os.Getenv(realTUNTestEnvironment) != "1" {
		t.Skip("set RENDR_TUN_REAL_IO_TEST=1 to exercise real TUN packet I/O")
	}
	if os.Geteuid() != 0 {
		t.Fatal("real TUN packet I/O requires root in the test namespace")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Fatalf("ip command is mandatory: %v", err)
	}
	selfNS := networkNamespaceIdentity(t, "/proc/self/ns/net")
	initNS := networkNamespaceIdentity(t, "/proc/1/ns/net")
	if selfNS == initNS {
		t.Fatalf("real TUN packet I/O is not isolated: self netns %s equals init netns", selfNS)
	}
	expectedNS := os.Getenv(realTUNTestNetNSID)
	if expectedNS == "" || expectedNS != selfNS {
		t.Fatalf("network namespace identity=%q want harness-provided %q", selfNS, expectedNS)
	}
	t.Logf("isolated network namespace=%s (init=%s)", selfNS, initNS)
}

func assertTUNOpenIsExclusive(t testing.TB, device *Device) {
	t.Helper()
	attached, err := Open(Config{
		Enabled: true,
		Name:    device.Name(),
		MTU:     device.MTU() + 120,
		Queues:  device.QueueCount(),
	})
	if err == nil {
		_ = attached.Close()
		t.Fatal("Open attached to an existing TUN instead of failing create-exclusive")
	}
	var virtualError *virtualif.Error
	if !errors.As(err, &virtualError) || virtualError.Reason != virtualif.ReasonTUNUnavailable {
		t.Fatalf("exclusive create error=%T %v", err, err)
	}
	iface, lookupErr := net.InterfaceByName(device.Name())
	if lookupErr != nil || iface.MTU != device.MTU() {
		t.Fatalf("failed attach mutated live TUN: interface=%+v err=%v", iface, lookupErr)
	}
}

func assertKernelToTUNUDP(t testing.TB, device *Device, network string, local, remote netip.Addr, payload []byte) []byte {
	t.Helper()
	conn, err := net.DialUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, 0)),
		net.UDPAddrFromAddrPort(netip.AddrPortFrom(remote, 48000)))
	if err != nil {
		t.Fatal(err)
	}
	source := conn.LocalAddr().(*net.UDPAddr).AddrPort()
	if _, err := conn.Write(payload); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	packet, meta := readMatchingTUNPacket(t, device, 3*time.Second, func(meta l3ingress.PacketMeta, packet []byte) bool {
		return meta.Identity.Proto == l3ingress.ProtocolUDP && meta.Identity.SrcIP == local &&
			meta.Identity.DstIP == remote && meta.Identity.SrcPort == source.Port() && meta.Identity.DstPort == 48000
	})
	got, err := l3ingress.UDPPayload(packet, meta)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) || len(packet) > device.MTU() {
		t.Fatalf("kernel->TUN payload=%x want=%x packet=%d mtu=%d", got, payload, len(packet), device.MTU())
	}
	return packet
}

func assertKernelRejectsOversizeUDP(
	t testing.TB,
	device *Device,
	network string,
	local, remote netip.Addr,
	payloadBytes int,
) {
	t.Helper()
	conn, err := net.DialUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, 0)),
		net.UDPAddrFromAddrPort(netip.AddrPortFrom(remote, 48001)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		if local.Is4() {
			optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
			return
		}
		optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO)
	}); err != nil {
		t.Fatal(err)
	}
	if optionErr != nil {
		t.Fatal(optionErr)
	}
	n, err := conn.Write(make([]byte, payloadBytes))
	if !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatalf("oversize UDP write=%d payload=%d mtu=%d err=%v want EMSGSIZE", n, payloadBytes, device.MTU(), err)
	}
}

func assertTUNToKernelUDP(t testing.TB, device *Device, network string, local, remote netip.Addr, payload []byte) {
	t.Helper()
	listener, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := listener.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	destination := listener.LocalAddr().(*net.UDPAddr).AddrPort()
	packet, err := l3ingress.BuildUDPPacket(l3ingress.L3Identity{
		Proto: l3ingress.ProtocolUDP,
		SrcIP: remote, SrcPort: 48100,
		DstIP: local, DstPort: destination.Port(),
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	written, err := device.Write(packet)
	if err != nil || written != len(packet) {
		t.Fatalf("TUN->kernel write=%d/%d err=%v", written, len(packet), err)
	}
	buffer := make([]byte, 2048)
	n, source, err := listener.ReadFromUDPAddrPort(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if source.Addr() != remote || source.Port() != 48100 || !bytes.Equal(buffer[:n], payload) {
		t.Fatalf("TUN->kernel source=%s payload=%x want=%s:%d/%x", source, buffer[:n], remote, 48100, payload)
	}
}

func assertReadDoesNotSilentlyTruncate(
	t testing.TB,
	device *Device,
	local, remote netip.Addr,
	kernelMTU int,
) {
	t.Helper()
	runIP(t, "link", "set", "dev", device.Name(), "mtu", fmt.Sprint(kernelMTU))
	defer runIP(t, "link", "set", "dev", device.Name(), "mtu", fmt.Sprint(device.MTU()))

	payload := bytes.Repeat([]byte{0xa7}, kernelMTU-28)
	conn, err := net.DialUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, 0)),
		net.UDPAddrFromAddrPort(netip.AddrPortFrom(remote, 48002)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(payload); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	small := make([]byte, device.MTU())
	for {
		_, err := device.ReadContext(ctx, small)
		if errors.Is(err, io.ErrShortBuffer) {
			break
		}
		if err != nil {
			t.Fatalf("wait for oversized kernel packet: %v", err)
		}
	}
	large := make([]byte, MaxMTU)
	n, err := device.ReadContext(ctx, large)
	if err != nil {
		t.Fatalf("replay oversized kernel packet: %v", err)
	}
	if n != kernelMTU {
		t.Fatalf("replayed packet=%d want=%d", n, kernelMTU)
	}
	meta, err := l3ingress.ParsePacket(large[:n])
	if err != nil {
		t.Fatal(err)
	}
	got, err := l3ingress.UDPPayload(large[:n], meta)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Identity.SrcIP != local || meta.Identity.DstIP != remote || !bytes.Equal(got, payload) {
		t.Fatalf("replayed oversized packet identity=%s payload=%d want=%s->%s/%d", meta.Identity, len(got), local, remote, len(payload))
	}
}

func assertPublicTUNWriteSequence(t testing.TB, device *Device, local, remote netip.Addr) {
	t.Helper()
	listener, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	queueWrites := make([]int, device.QueueCount())
	originalWrite := device.write
	device.write = func(fd int, packet []byte) (int, error) {
		queue := -1
		for index, file := range device.files {
			if int(file.Fd()) == fd {
				queue = index
				break
			}
		}
		if queue < 0 {
			return 0, fmt.Errorf("public Write selected unknown TUN fd %d", fd)
		}
		queueWrites[queue]++
		return originalWrite(fd, packet)
	}
	defer func() { device.write = originalWrite }()
	destination := listener.LocalAddr().(*net.UDPAddr).AddrPort()
	const packets = 32
	for sequence := 0; sequence < packets; sequence++ {
		payload := make([]byte, 8)
		copy(payload, "RMW1")
		binary.BigEndian.PutUint32(payload[4:], uint32(sequence))
		packet, err := l3ingress.BuildUDPPacket(l3ingress.L3Identity{
			Proto: l3ingress.ProtocolUDP,
			SrcIP: remote, SrcPort: 48150,
			DstIP: local, DstPort: destination.Port(),
		}, payload)
		if err != nil {
			t.Fatal(err)
		}
		written, err := device.Write(packet)
		if err != nil || written != len(packet) {
			t.Fatalf("public write sequence=%d write=%d/%d err=%v", sequence, written, len(packet), err)
		}
	}
	if err := listener.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	for sequence := 0; sequence < packets; sequence++ {
		n, source, err := listener.ReadFromUDPAddrPort(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if n != 8 || string(buffer[:4]) != "RMW1" || binary.BigEndian.Uint32(buffer[4:8]) != uint32(sequence) ||
			source != netip.AddrPortFrom(remote, 48150) {
			t.Fatalf("public write recv sequence=%d source=%s payload=%x", sequence, source, buffer[:n])
		}
	}
	for queue, writes := range queueWrites {
		if writes == 0 {
			t.Fatalf("public Write did not exercise TUN queue %d: %v", queue, queueWrites)
		}
	}
}

func assertEachTUNQueueToKernelUDP(t testing.TB, device *Device, local, remote netip.Addr) {
	t.Helper()
	listener, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	destination := listener.LocalAddr().(*net.UDPAddr).AddrPort()
	for queue := 0; queue < device.QueueCount(); queue++ {
		payload := []byte(fmt.Sprintf("queue-%d-to-kernel", queue))
		sourcePort := uint16(48200 + queue)
		packet, err := l3ingress.BuildUDPPacket(l3ingress.L3Identity{
			Proto: l3ingress.ProtocolUDP,
			SrcIP: remote, SrcPort: sourcePort,
			DstIP: local, DstPort: destination.Port(),
		}, payload)
		if err != nil {
			t.Fatal(err)
		}
		written, err := device.writeQueue(queue, packet)
		if err != nil || written != len(packet) {
			t.Fatalf("queue %d TUN->kernel write=%d/%d err=%v", queue, written, len(packet), err)
		}
		if err := listener.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 2048)
		n, source, err := listener.ReadFromUDPAddrPort(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if source != netip.AddrPortFrom(remote, sourcePort) || !bytes.Equal(buffer[:n], payload) {
			t.Fatalf("queue %d source=%s payload=%x want=%s/%x", queue, source, buffer[:n], netip.AddrPortFrom(remote, sourcePort), payload)
		}
	}
}

func assertPublicTUNReadAcrossQueues(
	t testing.TB,
	device *Device,
	representatives []*net.UDPConn,
	local, remote netip.Addr,
) {
	t.Helper()
	for queue, conn := range representatives {
		if conn == nil {
			t.Fatalf("no kernel flow was observed on queue %d", queue)
		}
		payload := make([]byte, 8)
		copy(payload, "RMP1")
		binary.BigEndian.PutUint32(payload[4:], uint32(queue))
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("queue %d public-read stimulus: %v", queue, err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	seen := make(map[uint32]bool, len(representatives))
	buffer := make([]byte, MaxMTU)
	for len(seen) < len(representatives) {
		n, err := device.ReadContext(ctx, buffer)
		if err != nil {
			t.Fatalf("public ReadContext covered queues=%v: %v", seen, err)
		}
		meta, err := l3ingress.ParsePacket(buffer[:n])
		if err != nil || meta.Identity.Proto != l3ingress.ProtocolUDP ||
			meta.Identity.SrcIP != local || meta.Identity.DstIP != remote || meta.Identity.DstPort != 49000 {
			continue
		}
		payload, err := l3ingress.UDPPayload(buffer[:n], meta)
		if err != nil || len(payload) != 8 || string(payload[:4]) != "RMP1" {
			continue
		}
		queue := binary.BigEndian.Uint32(payload[4:])
		if int(queue) >= len(representatives) || seen[queue] {
			t.Fatalf("public ReadContext returned invalid/duplicate queue marker %d", queue)
		}
		seen[queue] = true
	}
}

func readMatchingTUNPacket(
	t testing.TB,
	device *Device,
	timeout time.Duration,
	match func(l3ingress.PacketMeta, []byte) bool,
) ([]byte, l3ingress.PacketMeta) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	buffer := make([]byte, 64<<10)
	for {
		n, err := device.ReadContext(ctx, buffer)
		if err != nil {
			t.Fatal(err)
		}
		packet := append([]byte(nil), buffer[:n]...)
		meta, err := l3ingress.ParsePacket(packet)
		if err == nil && match(meta, packet) {
			return packet, meta
		}
	}
}

func assertTUNInterfaceState(t testing.TB, device *Device, mtu int, prefixes ...netip.Prefix) {
	t.Helper()
	iface, err := net.InterfaceByName(device.Name())
	if err != nil {
		t.Fatal(err)
	}
	if iface.Index <= 0 || iface.MTU != mtu || iface.Flags&net.FlagUp == 0 {
		t.Fatalf("interface state index=%d mtu=%d flags=%s want positive/%d/up", iface.Index, iface.MTU, iface.Flags, mtu)
	}
	addresses, err := iface.Addrs()
	if err != nil {
		t.Fatal(err)
	}
	actual := make([]string, 0, len(addresses))
	for _, address := range addresses {
		actual = append(actual, address.String())
	}
	for _, prefix := range prefixes {
		if !slices.Contains(actual, prefix.String()) {
			t.Fatalf("interface %s addresses=%v missing %s", device.Name(), actual, prefix)
		}
		assertKernelRoute(t, device.Name(), prefix.Addr(), nextAddress(prefix.Addr()))
	}
	t.Logf("TUN device=%s ifindex=%d mtu=%d addresses=%v", device.Name(), iface.Index, iface.MTU, actual)
}

func assertKernelRoute(t testing.TB, deviceName string, local, remote netip.Addr) {
	t.Helper()
	args := []string{"-j"}
	if remote.Is6() {
		args = append(args, "-6")
	}
	args = append(args, "route", "get", remote.String())
	output, err := exec.Command("ip", args...).Output()
	if err != nil {
		t.Fatalf("ip %v: %v", args, err)
	}
	var routes []struct {
		Dev     string `json:"dev"`
		PrefSrc string `json:"prefsrc"`
	}
	if err := json.Unmarshal(output, &routes); err != nil {
		t.Fatalf("decode ip route JSON %q: %v", output, err)
	}
	if len(routes) != 1 || routes[0].Dev != deviceName || routes[0].PrefSrc != local.String() {
		t.Fatalf("route %s=%s want dev=%s prefsrc=%s", remote, strings.TrimSpace(string(output)), deviceName, local)
	}
}

func nextAddress(address netip.Addr) netip.Addr {
	return address.Next()
}

func networkNamespaceIdentity(t testing.TB, path string) string {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Dev == 0 || stat.Ino == 0 {
		t.Fatalf("%s has no network namespace inode", path)
	}
	return fmt.Sprintf("%d:%d", stat.Dev, stat.Ino)
}

func readTUNQueuePackets(
	ctx context.Context,
	device *Device,
	queue int,
	local, remote netip.Addr,
	observed chan<- tunQueueObservation,
	errorsCh chan<- error,
) {
	buffer := make([]byte, 2048)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, err := tryReadTUNQueue(device, queue, buffer)
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR) {
			time.Sleep(time.Millisecond)
			continue
		}
		if err != nil {
			select {
			case errorsCh <- fmt.Errorf("queue %d read: %w", queue, err):
			default:
			}
			return
		}
		packet := buffer[:n]
		meta, err := l3ingress.ParsePacket(packet)
		if err != nil || meta.Identity.Proto != l3ingress.ProtocolUDP || meta.Identity.SrcIP != local || meta.Identity.DstIP != remote {
			continue
		}
		payload, err := l3ingress.UDPPayload(packet, meta)
		if err != nil || len(payload) != 8 || string(payload[:4]) != "RMQ1" {
			continue
		}
		observation := tunQueueObservation{queue: queue, sequence: binary.BigEndian.Uint32(payload[4:])}
		select {
		case observed <- observation:
		case <-ctx.Done():
			return
		}
	}
}

func tryReadTUNQueue(device *Device, queue int, buffer []byte) (int, error) {
	device.mu.RLock()
	defer device.mu.RUnlock()
	if device.closed || queue < 0 || queue >= len(device.files) {
		return 0, os.ErrClosed
	}
	return unix.Read(int(device.files[queue].Fd()), buffer)
}

func closeUDPConnections(connections []*net.UDPConn) {
	for _, connection := range connections {
		if connection != nil {
			_ = connection.Close()
		}
	}
}

func observeNextPoll(device *Device) <-chan struct{} {
	entered := make(chan struct{})
	var once sync.Once
	device.beforePoll = func() {
		once.Do(func() { close(entered) })
	}
	return entered
}

func countOpenFDs(t testing.TB) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func waitTUNInterfaceGone(t testing.TB, name string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := net.InterfaceByName(name); err != nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("TUN interface %q remained after all queues closed", name)
}
