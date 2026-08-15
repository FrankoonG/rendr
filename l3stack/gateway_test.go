package l3stack

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
	"github.com/FrankoonG/rendr/l3session"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func TestGatewayTerminatesTCPAndPreservesIdentity(t *testing.T) {
	tests := []struct {
		name        string
		network     tcpip.NetworkProtocolNumber
		client      netip.Addr
		prefix      int
		destination netip.Addr
	}{
		{
			name: "ipv4", network: header.IPv4ProtocolNumber,
			client: netip.MustParseAddr("10.0.0.2"), prefix: 24,
			destination: netip.MustParseAddr("198.51.100.20"),
		},
		{
			name: "ipv6", network: header.IPv6ProtocolNumber,
			client: netip.MustParseAddr("2001:db8:1::2"), prefix: 64,
			destination: netip.MustParseAddr("2001:db8:2::20"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testGatewayTCPFlow(t, tt.network, tt.client, tt.prefix, tt.destination)
		})
	}
}

func testGatewayTCPFlow(
	t *testing.T,
	network tcpip.NetworkProtocolNumber,
	clientIP netip.Addr,
	prefix int,
	destinationIP netip.Addr,
) {
	t.Helper()
	serverRuntime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := serverRuntime.Listen(rendr.ListenConfig{
		AcceptL3Identity: true,
		Streams:          []rendr.StreamSource{{Name: "tcp", Carrier: rendr.CarrierTCP, Listener: rawListener}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	egressApp, egressPeer := newGatewayTCPConnPair(t)
	defer egressApp.Close()
	egress := &gatewayTestEgress{conn: egressPeer, identities: make(chan l3ingress.L3Identity, 1)}
	registry := l3ingress.NewEgressRegistry()
	if err := registry.Register("direct", egress); err != nil {
		t.Fatal(err)
	}
	peerDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := listener.AcceptStream(ctx)
		if err == nil {
			err = (&l3session.TCPPeerRelay{Conn: conn, Egresses: registry}).Run(ctx)
			_ = conn.Close()
		}
		peerDone <- err
	}()

	device := newGatewayTestDevice(1500)
	root := rendr.Selector("root", []rendr.Target{
		rendr.Path("tcp-a", rendr.PathSpec{Transport: "tcp", Address: listener.Addr().String()}),
		rendr.Path("tcp-b", rendr.PathSpec{Transport: "tcp", Address: listener.Addr().String()}),
	})
	gateway, err := New(Config{
		Device: device,
		Router: func(context.Context, l3ingress.FlowMeta) (l3ingress.FlowDecision, error) {
			return l3ingress.FlowDecision{Peer: "peer-a", Root: root, Egress: "direct"}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	gatewayDone := make(chan error, 1)
	go func() { gatewayDone <- gateway.Run(ctx) }()
	defer func() {
		cancel()
		_ = gateway.Close()
		_ = device.Close()
	}()

	clientStack, clientLink := newGatewayTestClientStack(t, network, clientIP, prefix)
	defer clientStack.Close()
	defer clientLink.Close()
	bridgeCtx, stopBridge := context.WithCancel(context.Background())
	defer stopBridge()
	bridgeGatewayTestPackets(bridgeCtx, clientLink, device, network)

	client, err := gonet.DialTCP(clientStack, tcpip.FullAddress{
		NIC: stackNICID, Addr: tcpipAddress(destinationIP), Port: 443,
	}, network)
	if err != nil {
		t.Fatalf("dial through gateway: %v", err)
	}
	defer client.Close()
	local := client.LocalAddr().(*net.TCPAddr).AddrPort()
	wantIdentity := l3ingress.L3Identity{
		Proto: l3ingress.ProtocolTCP,
		SrcIP: local.Addr(), SrcPort: local.Port(),
		DstIP: destinationIP, DstPort: 443,
	}
	admin := waitGatewayStreamControl(t, gateway, wantIdentity, 2)
	request := []byte("request-through-tun-stack")
	split := len(request) / 2
	if _, err := client.Write(request[:split]); err != nil {
		t.Fatal(err)
	}
	var next uint32
	var nextName string
	for _, path := range admin.Paths() {
		if path.ID != admin.ActivePath() {
			next = path.ID
			nextName = path.Spec.Opts["name"]
			break
		}
	}
	if next == 0 {
		t.Fatalf("no inactive TCP path: %+v", admin.Paths())
	}
	if err := admin.SelectTarget("root", nextName); err != nil {
		t.Fatalf("migrate TUN TCP flow: %v", err)
	}
	if _, err := client.Write(request[split:]); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	gotRequest, err := io.ReadAll(egressApp)
	if err != nil {
		t.Fatalf("egress read: %v", err)
	}
	if string(gotRequest) != string(request) {
		t.Fatalf("egress request = %q, want %q", gotRequest, request)
	}
	response := []byte("response-after-client-fin")
	if _, err := egressApp.Write(response); err != nil {
		t.Fatal(err)
	}
	_ = egressApp.Close()
	if err := client.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	gotResponse, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("client read response: %v", err)
	}
	if string(gotResponse) != string(response) {
		t.Fatalf("client response = %q, want %q", gotResponse, response)
	}

	var identity l3ingress.L3Identity
	select {
	case identity = <-egress.identities:
	case <-time.After(time.Second):
		t.Fatal("peer egress did not receive L3 identity")
	}
	if identity != wantIdentity {
		t.Fatalf("peer identity = %s, want %s", identity, wantIdentity)
	}
	if admin.MigrationCount() == 0 {
		t.Fatal("TUN TCP flow reported no committed path migration")
	}

	cancel()
	select {
	case err := <-gatewayDone:
		if err != nil {
			t.Fatalf("gateway Run: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("gateway did not stop")
	}
	select {
	case err := <-peerDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("peer relay: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("peer relay did not stop")
	}
}

func TestGatewayTCPFlowSurvivesActiveCarrierDeath(t *testing.T) {
	serverRuntime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	listenerA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenerB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = listenerA.Close()
		t.Fatal(err)
	}
	listener, err := serverRuntime.Listen(rendr.ListenConfig{
		AcceptL3Identity: true,
		Streams: []rendr.StreamSource{
			{Name: "fault-a", Carrier: rendr.CarrierTCP, Listener: listenerA},
			{Name: "fault-b", Carrier: rendr.CarrierTCP, Listener: listenerB},
		},
	})
	if err != nil {
		_ = listenerA.Close()
		_ = listenerB.Close()
		t.Fatal(err)
	}
	defer listener.Close()

	tracker := newGatewayStreamTracker()
	clientRuntime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"fault-a", "fault-b"} {
		if err := clientRuntime.RegisterStreamFactory(name, tracker.factory(name)); err != nil {
			t.Fatal(err)
		}
	}
	root := rendr.Selector("root", []rendr.Target{
		rendr.Path("a", rendr.PathSpec{Transport: "fault-a", Address: listenerA.Addr().String()}),
		rendr.Path("b", rendr.PathSpec{Transport: "fault-b", Address: listenerB.Addr().String()}),
	})

	egressApp, egressPeer := newGatewayTCPConnPair(t)
	defer egressApp.Close()
	egress := &gatewayTestEgress{conn: egressPeer, identities: make(chan l3ingress.L3Identity, 1)}
	registry := l3ingress.NewEgressRegistry()
	if err := registry.Register("direct", egress); err != nil {
		t.Fatal(err)
	}
	peerCtx, stopPeer := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopPeer()
	peerDone := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptStream(peerCtx)
		if err == nil {
			err = (&l3session.TCPPeerRelay{Conn: conn, Egresses: registry}).Run(peerCtx)
			_ = conn.Close()
		}
		peerDone <- err
	}()
	echoDone := make(chan error, 1)
	go func() {
		for _, exchange := range []struct{ request, response string }{
			{request: "before-death", response: "ack-before"},
			{request: "after-death", response: "ack-after"},
		} {
			buf := make([]byte, len(exchange.request))
			if _, err := io.ReadFull(egressApp, buf); err != nil {
				echoDone <- err
				return
			}
			if string(buf) != exchange.request {
				echoDone <- errors.New("unexpected TCP egress request")
				return
			}
			if _, err := egressApp.Write([]byte(exchange.response)); err != nil {
				echoDone <- err
				return
			}
		}
		echoDone <- nil
	}()

	device := newGatewayTestDevice(1500)
	gateway, err := New(Config{
		Device:  device,
		Starter: &l3session.Starter{Runtime: clientRuntime},
		Router: func(context.Context, l3ingress.FlowMeta) (l3ingress.FlowDecision, error) {
			return l3ingress.FlowDecision{Peer: "peer-a", Root: root, Egress: "direct"}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	gatewayDone := make(chan error, 1)
	go func() { gatewayDone <- gateway.Run(ctx) }()
	defer func() {
		cancel()
		stopPeer()
		_ = gateway.Close()
		_ = device.Close()
	}()

	clientStack, clientLink := newGatewayTestClientStack(
		t, header.IPv4ProtocolNumber, netip.MustParseAddr("10.0.0.2"), 24,
	)
	defer clientStack.Close()
	defer clientLink.Close()
	bridgeCtx, stopBridge := context.WithCancel(context.Background())
	defer stopBridge()
	bridgeGatewayTestPackets(bridgeCtx, clientLink, device, header.IPv4ProtocolNumber)
	destination := netip.MustParseAddr("198.51.100.20")
	client, err := gonet.DialTCP(clientStack, tcpip.FullAddress{
		NIC: stackNICID, Addr: tcpipAddress(destination), Port: 443,
	}, header.IPv4ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	local := client.LocalAddr().(*net.TCPAddr).AddrPort()
	id := l3ingress.L3Identity{
		Proto: l3ingress.ProtocolTCP, SrcIP: local.Addr(), SrcPort: local.Port(),
		DstIP: destination, DstPort: 443,
	}
	admin := waitGatewayStreamControl(t, gateway, id, 2)
	writeAndReadGatewayTCP(t, client, "before-death", "ack-before")

	oldActive := admin.ActivePath()
	activeTransport := ""
	for _, path := range admin.Paths() {
		if path.ID == oldActive {
			activeTransport = path.Spec.Transport
			break
		}
	}
	if activeTransport == "" || !tracker.closeOne(activeTransport) {
		t.Fatalf("could not close active transport %q: %+v", activeTransport, admin.Paths())
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && (admin.MigrationCount() == 0 || admin.ActivePath() == oldActive) {
		time.Sleep(time.Millisecond)
	}
	if admin.MigrationCount() == 0 || admin.ActivePath() == oldActive {
		t.Fatalf("active carrier death did not fail over: old=%d active=%d migrations=%d paths=%+v",
			oldActive, admin.ActivePath(), admin.MigrationCount(), admin.Paths())
	}
	writeAndReadGatewayTCP(t, client, "after-death", "ack-after")

	select {
	case got := <-egress.identities:
		if got != id {
			t.Fatalf("peer identity = %s, want %s", got, id)
		}
	case <-time.After(time.Second):
		t.Fatal("peer egress did not receive identity")
	}
	select {
	case err := <-echoDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("egress exchanges did not complete")
	}
	if got := admin.State(); got != "active" {
		t.Fatalf("flow state before clean shutdown = %q, want active", got)
	}

	cancel()
	stopPeer()
	select {
	case err := <-gatewayDone:
		if err != nil {
			t.Fatalf("gateway Run: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("gateway did not stop")
	}
	select {
	case err := <-peerDone:
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("peer relay: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("peer relay did not stop")
	}
}

type gatewayStreamControl interface {
	rendr.Conn
	rendr.MigrationController
	rendr.ConnectionObserver
}

func waitGatewayStreamControl(
	t *testing.T,
	gateway *Gateway,
	id l3ingress.L3Identity,
	wantPaths int,
) gatewayStreamControl {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if session, ok := gateway.manager.Session(id); ok && session.Conn != nil {
			if admin, ok := session.Conn.(gatewayStreamControl); ok && len(admin.Paths()) >= wantPaths {
				return admin
			}
		}
		time.Sleep(time.Millisecond)
	}
	if session, ok := gateway.manager.Session(id); ok && session.Conn != nil {
		t.Fatalf("TUN TCP flow has %d paths, want %d", len(session.Conn.Paths()), wantPaths)
	}
	t.Fatalf("TUN TCP flow %s did not start", id)
	return nil
}

func TestGatewayRelaysUDPPacketsAndPreservesIdentity(t *testing.T) {
	tests := []struct {
		name string
		id   l3ingress.L3Identity
	}{
		{
			name: "ipv4",
			id: l3ingress.L3Identity{
				Proto: l3ingress.ProtocolUDP, SrcIP: netip.MustParseAddr("10.0.0.2"), SrcPort: 53000,
				DstIP: netip.MustParseAddr("198.51.100.53"), DstPort: 53,
			},
		},
		{
			name: "ipv6",
			id: l3ingress.L3Identity{
				Proto: l3ingress.ProtocolUDP, SrcIP: netip.MustParseAddr("2001:db8:1::2"), SrcPort: 53001,
				DstIP: netip.MustParseAddr("2001:db8:2::53"), DstPort: 53,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testGatewayUDPFlow(t, tt.id)
		})
	}
}

func TestGatewayCloseBeforeRunDoesNotStrandLifecycle(t *testing.T) {
	gateway, device := newIdleGateway(t)
	if err := gateway.Close(); err != nil {
		t.Fatalf("initial Close: %v", err)
	}
	if err := gateway.Run(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Run after Close = %v, want net.ErrClosed", err)
	}
	done := make(chan error, 1)
	go func() { done <- gateway.Close() }()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("second Close = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("second Close blocked after Run returned")
	}
	_ = device.Close()
}

func TestGatewayConcurrentRunCloseDoesNotDeadlock(t *testing.T) {
	for attempt := 0; attempt < 32; attempt++ {
		gateway, device := newIdleGateway(t)
		runDone := make(chan error, 1)
		closeDone := make(chan error, 1)
		start := make(chan struct{})
		go func() {
			<-start
			runDone <- gateway.Run(context.Background())
		}()
		go func() {
			<-start
			closeDone <- gateway.Close()
		}()
		close(start)
		select {
		case <-runDone:
		case <-time.After(time.Second):
			t.Fatalf("attempt %d: Run blocked", attempt)
		}
		select {
		case <-closeDone:
		case <-time.After(time.Second):
			t.Fatalf("attempt %d: Close blocked", attempt)
		}
		_ = device.Close()
	}
}

func TestGatewayFlowFailureDoesNotStopExistingFlow(t *testing.T) {
	first := l3ingress.L3Identity{
		Proto: l3ingress.ProtocolUDP, SrcIP: netip.MustParseAddr("10.0.0.2"), SrcPort: 51000,
		DstIP: netip.MustParseAddr("198.51.100.53"), DstPort: 53,
	}
	second := first
	second.SrcPort++
	table := l3ingress.NewFlowTable(
		func(context.Context, l3ingress.FlowMeta) (l3ingress.FlowDecision, error) {
			return l3ingress.FlowDecision{Deny: true, DenyReason: "test"}, nil
		},
		l3ingress.FlowTableOptions{ActiveCapacity: 1, ClosedCapacity: 1},
	)
	flowErrors := make(chan error, 1)
	device := newGatewayTestDevice(1500)
	gateway, err := New(Config{
		Device: device, FlowTable: table,
		OnFlowError: func(_ l3ingress.L3Identity, err error) { flowErrors <- err },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- gateway.Run(ctx) }()
	defer func() {
		cancel()
		_ = gateway.Close()
		_ = device.Close()
	}()

	send := func(id l3ingress.L3Identity) {
		t.Helper()
		packet, err := l3ingress.BuildUDPPacket(id, []byte("probe"))
		if err != nil {
			t.Fatal(err)
		}
		select {
		case device.inbound <- packet:
		case <-time.After(time.Second):
			t.Fatal("device ingress blocked")
		}
	}
	send(first)
	waitGatewayFlowPackets(t, table, first, 1)
	send(second)
	select {
	case err := <-flowErrors:
		if !errors.Is(err, l3ingress.ErrFlowTableFull) {
			t.Fatalf("flow error = %v, want ErrFlowTableFull", err)
		}
	case <-time.After(time.Second):
		t.Fatal("capacity failure was not reported")
	}
	send(first)
	waitGatewayFlowPackets(t, table, first, 2)
	select {
	case err := <-done:
		t.Fatalf("flow-local capacity failure stopped Gateway.Run: %v", err)
	default:
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Gateway.Run after cancel: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Gateway.Run did not stop after cancel")
	}
}

func TestGatewayIgnoresNonFlowControlProtocols(t *testing.T) {
	routerCalls := 0
	flowErrors := make(chan error, 1)
	device := newGatewayTestDevice(1500)
	gateway, err := New(Config{
		Device: device,
		Router: func(context.Context, l3ingress.FlowMeta) (l3ingress.FlowDecision, error) {
			routerCalls++
			return l3ingress.FlowDecision{Deny: true}, nil
		},
		OnFlowError: func(_ l3ingress.L3Identity, err error) { flowErrors <- err },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()

	for _, protocol := range []l3ingress.Protocol{l3ingress.ProtocolICMP, l3ingress.ProtocolICMPv6} {
		event := l3ingress.PacketEvent{
			Packet: []byte{0x01},
			Meta: l3ingress.PacketMeta{Identity: l3ingress.L3Identity{
				Proto: protocol,
				SrcIP: netip.MustParseAddr("2001:db8::1"),
				DstIP: netip.MustParseAddr("2001:db8::2"),
			}},
		}
		if err := gateway.HandlePacket(context.Background(), event); err != nil {
			t.Fatalf("HandlePacket(%s): %v", protocol, err)
		}
	}
	if routerCalls != 0 {
		t.Fatalf("router calls=%d want 0", routerCalls)
	}
	if snapshots := gateway.table.Snapshots(); len(snapshots) != 0 {
		t.Fatalf("control traffic allocated flows: %+v", snapshots)
	}
	select {
	case err := <-flowErrors:
		t.Fatalf("control traffic reported a flow error: %v", err)
	default:
	}
}

func TestGatewayOutboundWriteFailureCancelsIngressPump(t *testing.T) {
	writeErr := errors.New("test TUN write failed")
	device := newGatewayTestDevice(1500)
	device.writeErr = writeErr
	gateway, err := New(Config{
		Device: device,
		Router: func(context.Context, l3ingress.FlowMeta) (l3ingress.FlowDecision, error) {
			return l3ingress.FlowDecision{Deny: true}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- gateway.Run(context.Background()) }()
	deadline := time.Now().Add(time.Second)
	for {
		gateway.runMu.Lock()
		started := gateway.runCtx != nil
		gateway.runMu.Unlock()
		if started {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Gateway.Run did not start")
		}
		time.Sleep(time.Millisecond)
	}

	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte{4, 0, 0, 0})})
	var packets stack.PacketBufferList
	packets.PushBack(packet)
	if n, tcpErr := gateway.link.WritePackets(packets); tcpErr != nil || n != 1 {
		t.Fatalf("queue outbound packet n=%d err=%v", n, tcpErr)
	}
	select {
	case err := <-done:
		if !errors.Is(err, writeErr) {
			t.Fatalf("Gateway.Run error = %v, want %v", err, writeErr)
		}
	case <-time.After(time.Second):
		t.Fatal("outbound write failure did not stop Gateway.Run")
	}
	_ = device.Close()
}

func TestGatewayCancellationInterruptsBlockedOutboundWrite(t *testing.T) {
	device := &blockingGatewayWriteDevice{
		gatewayTestDevice: newGatewayTestDevice(1500),
		started:           make(chan struct{}),
	}
	gateway, err := New(Config{
		Device: device,
		Router: func(context.Context, l3ingress.FlowMeta) (l3ingress.FlowDecision, error) {
			return l3ingress.FlowDecision{Deny: true}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- gateway.Run(ctx) }()
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte{4, 0, 0, 0})})
	var packets stack.PacketBufferList
	packets.PushBack(packet)
	if n, tcpErr := gateway.link.WritePackets(packets); tcpErr != nil || n != 1 {
		t.Fatalf("queue outbound packet n=%d err=%v", n, tcpErr)
	}
	select {
	case <-device.started:
	case <-time.After(time.Second):
		t.Fatal("outbound WriteContext did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Gateway.Run after cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Gateway.Run remained blocked in outbound device write")
	}
	if err := gateway.Close(); err != nil {
		t.Fatal(err)
	}
	_ = device.Close()
}

func waitGatewayFlowPackets(
	t *testing.T,
	table *l3ingress.FlowTable,
	id l3ingress.L3Identity,
	want uint64,
) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if snapshot, ok := table.Snapshot(id); ok && snapshot.Packets >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	snapshot, ok := table.Snapshot(id)
	t.Fatalf("flow packets = %d ok=%v, want >=%d", snapshot.Packets, ok, want)
}

func newIdleGateway(t *testing.T) (*Gateway, *gatewayTestDevice) {
	t.Helper()
	device := newGatewayTestDevice(1500)
	gateway, err := New(Config{
		Device: device,
		Router: func(context.Context, l3ingress.FlowMeta) (l3ingress.FlowDecision, error) {
			return l3ingress.FlowDecision{Deny: true}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return gateway, device
}

func testGatewayUDPFlow(t *testing.T, id l3ingress.L3Identity) {
	t.Helper()
	serverRuntime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	rawPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := serverRuntime.Listen(rendr.ListenConfig{
		AcceptL3Identity: true,
		Packets:          []rendr.PacketSource{{Name: "udpflow", Carrier: rendr.CarrierUDP, Conn: rawPacketConn}},
	})
	if err != nil {
		_ = rawPacketConn.Close()
		t.Fatal(err)
	}
	defer listener.Close()

	echo, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	echoDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 256)
		var err error
		for index := 0; index < 3 && err == nil; index++ {
			var n int
			var peer net.Addr
			n, peer, err = echo.ReadFrom(buf)
			if err == nil {
				_, err = echo.WriteTo(append([]byte("reply:"), buf[:n]...), peer)
			}
		}
		echoDone <- err
	}()

	egress := &gatewayTestUDPEgress{
		remote:     echo.LocalAddr().(*net.UDPAddr).AddrPort(),
		identities: make(chan l3ingress.L3Identity, 1),
	}
	registry := l3ingress.NewEgressRegistry()
	if err := registry.Register("direct", egress); err != nil {
		t.Fatal(err)
	}
	peerCtx, stopPeer := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopPeer()
	peerDone := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptPacket(peerCtx)
		if err == nil {
			err = (&l3session.UDPPeerRelay{PacketConn: conn, Egresses: registry}).Run(peerCtx)
			_ = conn.Close()
		}
		peerDone <- err
	}()

	device := newGatewayTestDevice(1500)
	root := rendr.Selector("root", []rendr.Target{
		rendr.Path("udp-a", rendr.PathSpec{Transport: "udpflow", Address: listener.Addr().String()}),
		rendr.Path("udp-b", rendr.PathSpec{Transport: "udpflow", Address: listener.Addr().String()}),
	})
	gateway, err := New(Config{
		Device: device,
		Router: func(context.Context, l3ingress.FlowMeta) (l3ingress.FlowDecision, error) {
			return l3ingress.FlowDecision{Peer: "peer-a", Root: root, Egress: "direct"}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	gatewayDone := make(chan error, 1)
	go func() { gatewayDone <- gateway.Run(ctx) }()
	defer func() {
		cancel()
		_ = gateway.Close()
		_ = device.Close()
	}()

	first := []byte("query-through-tun")
	sendGatewayUDPPacket(t, device, id, first)
	readGatewayUDPReply(t, device, id, append([]byte("reply:"), first...))

	admin := waitGatewayPacketControl(t, gateway, id, 2)
	var next uint32
	var nextName string
	for _, path := range admin.Paths() {
		if path.ID != admin.ActivePath() {
			next = path.ID
			nextName = path.Spec.Opts["name"]
			break
		}
	}
	if next == 0 {
		t.Fatalf("no inactive UDP path: %+v", admin.Paths())
	}
	if err := admin.SelectTarget("root", nextName); err != nil {
		t.Fatalf("migrate TUN UDP flow: %v", err)
	}
	second := []byte("query-after-migration")
	sendGatewayUDPPacket(t, device, id, second)
	readGatewayUDPReply(t, device, id, append([]byte("reply:"), second...))
	sendGatewayUDPPacket(t, device, id, nil)
	readGatewayUDPReply(t, device, id, []byte("reply:"))
	if admin.MigrationCount() == 0 {
		t.Fatal("TUN UDP flow reported no committed path migration")
	}
	select {
	case got := <-egress.identities:
		if got != id {
			t.Fatalf("peer identity = %s, want %s", got, id)
		}
	case <-time.After(time.Second):
		t.Fatal("peer UDP egress did not receive L3 identity")
	}
	select {
	case err := <-echoDone:
		if err != nil {
			t.Fatalf("UDP egress echo: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("UDP egress did not receive request")
	}
	reaped := gateway.ReapIdle(time.Now().Add(time.Hour))
	if len(reaped) != 1 || reaped[0].Ref == (l3ingress.FlowRef{}) || reaped[0].Ref.Identity != id {
		t.Fatalf("idle reap = %+v, want current UDP flow", reaped)
	}
	if _, ok := gateway.manager.Session(id); ok {
		t.Fatal("idle-reaped UDP session remained in manager")
	}
	if closed, ok := gateway.table.ClosedSnapshot(id); !ok || closed.Ref != reaped[0].Ref || closed.CloseReason != l3ingress.FlowCloseIdle {
		t.Fatalf("closed idle snapshot = %+v ok=%v", closed, ok)
	}

	cancel()
	stopPeer()
	select {
	case err := <-gatewayDone:
		if err != nil {
			t.Fatalf("gateway Run: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("gateway did not stop")
	}
	select {
	case err := <-peerDone:
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("UDP peer relay: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("UDP peer relay did not stop")
	}
}

type gatewayPacketControl interface {
	rendr.PacketConn
	rendr.MigrationController
	rendr.ConnectionObserver
}

func waitGatewayPacketControl(
	t *testing.T,
	gateway *Gateway,
	id l3ingress.L3Identity,
	wantPaths int,
) gatewayPacketControl {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if session, ok := gateway.manager.Session(id); ok && session.PacketConn != nil {
			if admin, ok := session.PacketConn.(gatewayPacketControl); ok && len(admin.Paths()) >= wantPaths {
				return admin
			}
		}
		time.Sleep(time.Millisecond)
	}
	if session, ok := gateway.manager.Session(id); ok && session.PacketConn != nil {
		t.Fatalf("TUN UDP flow has %d paths, want %d", len(session.PacketConn.Paths()), wantPaths)
	}
	t.Fatalf("TUN UDP flow %s did not start", id)
	return nil
}

func sendGatewayUDPPacket(
	t *testing.T,
	device *gatewayTestDevice,
	id l3ingress.L3Identity,
	payload []byte,
) {
	t.Helper()
	packet, err := l3ingress.BuildUDPPacket(id, payload)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case device.inbound <- packet:
	case <-time.After(time.Second):
		t.Fatal("gateway did not accept UDP packet")
	}
}

func readGatewayUDPReply(
	t *testing.T,
	device *gatewayTestDevice,
	id l3ingress.L3Identity,
	wantPayload []byte,
) {
	t.Helper()
	var reply []byte
	select {
	case reply = <-device.outbound:
	case <-time.After(3 * time.Second):
		t.Fatal("gateway did not return UDP reply")
	}
	meta, err := l3ingress.ParsePacket(reply)
	if err != nil {
		t.Fatalf("parse UDP reply: %v", err)
	}
	if meta.Identity != id.Reverse() {
		t.Fatalf("reply identity = %s, want %s", meta.Identity, id.Reverse())
	}
	gotPayload, err := l3ingress.UDPPayload(reply, meta)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotPayload) != string(wantPayload) {
		t.Fatalf("reply payload = %q, want %q", gotPayload, wantPayload)
	}
}

func writeAndReadGatewayTCP(t *testing.T, conn net.Conn, request, response string) {
	t.Helper()
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatalf("write %q: %v", request, err)
	}
	buf := make([]byte, len(response))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read response for %q: %v", request, err)
	}
	if string(buf) != response {
		t.Fatalf("response for %q = %q, want %q", request, buf, response)
	}
}

type gatewayTestDevice struct {
	mtu       int
	inbound   chan []byte
	outbound  chan []byte
	closed    chan struct{}
	closeOnce sync.Once
	writeErr  error
}

func newGatewayTestDevice(mtu int) *gatewayTestDevice {
	return &gatewayTestDevice{
		mtu: mtu, inbound: make(chan []byte, 256), outbound: make(chan []byte, 256),
		closed: make(chan struct{}),
	}
}

func (d *gatewayTestDevice) Read(p []byte) (int, error) {
	return d.ReadContext(context.Background(), p)
}

func (d *gatewayTestDevice) ReadContext(ctx context.Context, p []byte) (int, error) {
	select {
	case packet := <-d.inbound:
		if len(packet) > len(p) {
			return 0, io.ErrShortBuffer
		}
		return copy(p, packet), nil
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-d.closed:
		return 0, net.ErrClosed
	}
}

func (d *gatewayTestDevice) Write(packet []byte) (int, error) {
	return d.WriteContext(context.Background(), packet)
}

func (d *gatewayTestDevice) WriteContext(ctx context.Context, packet []byte) (int, error) {
	if d.writeErr != nil {
		return 0, d.writeErr
	}
	copyPacket := append([]byte(nil), packet...)
	select {
	case d.outbound <- copyPacket:
		return len(packet), nil
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-d.closed:
		return 0, net.ErrClosed
	}
}

type blockingGatewayWriteDevice struct {
	*gatewayTestDevice
	started chan struct{}
	once    sync.Once
}

func (d *blockingGatewayWriteDevice) Write([]byte) (int, error) {
	return 0, errors.New("l3stack test: uncancellable Write called")
}

func (d *blockingGatewayWriteDevice) WriteContext(ctx context.Context, _ []byte) (int, error) {
	d.once.Do(func() { close(d.started) })
	<-ctx.Done()
	return 0, ctx.Err()
}

func (d *gatewayTestDevice) Close() error {
	d.closeOnce.Do(func() { close(d.closed) })
	return nil
}
func (*gatewayTestDevice) Name() string { return "test-tun" }
func (d *gatewayTestDevice) MTU() int   { return d.mtu }

type gatewayTestEgress struct {
	mu         sync.Mutex
	conn       l3ingress.TCPConn
	identities chan l3ingress.L3Identity
}

type gatewayStreamTracker struct {
	mu    sync.Mutex
	conns map[string][]*gatewayTrackedConn
}

type gatewayTrackedConn struct {
	net.Conn
	closeOnce sync.Once
	closeErr  error
}

func newGatewayStreamTracker() *gatewayStreamTracker {
	return &gatewayStreamTracker{conns: make(map[string][]*gatewayTrackedConn)}
}

func (t *gatewayStreamTracker) factory(name string) rendr.StreamFactory {
	return rendr.StreamFactory{
		Carrier: rendr.CarrierTCP,
		Dial: func(ctx context.Context, address string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
			if err != nil {
				return nil, err
			}
			tracked := &gatewayTrackedConn{Conn: conn}
			t.mu.Lock()
			t.conns[name] = append(t.conns[name], tracked)
			t.mu.Unlock()
			return tracked, nil
		},
	}
}

func (t *gatewayStreamTracker) closeOne(name string) bool {
	t.mu.Lock()
	conns := t.conns[name]
	t.mu.Unlock()
	if len(conns) == 0 {
		return false
	}
	return conns[0].Close() == nil
}

func (c *gatewayTrackedConn) Close() error {
	c.closeOnce.Do(func() { c.closeErr = c.Conn.Close() })
	return c.closeErr
}

type gatewayTestUDPEgress struct {
	remote     netip.AddrPort
	identities chan l3ingress.L3Identity
}

func (*gatewayTestUDPEgress) DialTCP(context.Context, l3ingress.L3Identity) (l3ingress.TCPConn, error) {
	return nil, errors.New("unexpected TCP egress")
}

func (e *gatewayTestUDPEgress) DialUDP(_ context.Context, id l3ingress.L3Identity) (net.PacketConn, netip.AddrPort, error) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	e.identities <- id
	return conn, e.remote, nil
}

func (e *gatewayTestEgress) DialTCP(_ context.Context, id l3ingress.L3Identity) (l3ingress.TCPConn, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.conn == nil {
		return nil, errors.New("gateway test egress already consumed")
	}
	conn := e.conn
	e.conn = nil
	e.identities <- id
	return conn, nil
}

func (*gatewayTestEgress) DialUDP(context.Context, l3ingress.L3Identity) (net.PacketConn, netip.AddrPort, error) {
	return nil, netip.AddrPort{}, errors.New("unexpected UDP egress")
}

func newGatewayTestClientStack(
	t *testing.T,
	network tcpip.NetworkProtocolNumber,
	clientIP netip.Addr,
	prefix int,
) (*stack.Stack, *channel.Endpoint) {
	t.Helper()
	link := channel.New(256, 1500, "")
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{gtcp.NewProtocol},
	})
	if err := s.CreateNIC(stackNICID, link); err != nil {
		t.Fatalf("create client NIC: %s", err)
	}
	if err := s.AddProtocolAddress(stackNICID, tcpip.ProtocolAddress{
		Protocol:          network,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpipAddress(clientIP), PrefixLen: prefix},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("add client address: %s", err)
	}
	destination := header.IPv4EmptySubnet
	if network == header.IPv6ProtocolNumber {
		destination = header.IPv6EmptySubnet
	}
	s.SetRouteTable([]tcpip.Route{{Destination: destination, NIC: stackNICID}})
	return s, link
}

func bridgeGatewayTestPackets(
	ctx context.Context,
	client *channel.Endpoint,
	device *gatewayTestDevice,
	network tcpip.NetworkProtocolNumber,
) {
	go func() {
		for {
			packet := client.ReadContext(ctx)
			if packet == nil {
				return
			}
			view := packet.ToView()
			wire := append([]byte(nil), view.AsSlice()...)
			view.Release()
			packet.DecRef()
			select {
			case device.inbound <- wire:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		for {
			select {
			case wire := <-device.outbound:
				packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(wire)})
				client.InjectInbound(network, packet)
				packet.DecRef()
			case <-ctx.Done():
				return
			}
		}
	}()
}

func tcpipAddress(address netip.Addr) tcpip.Address {
	if address.Is4() {
		return tcpip.AddrFrom4(address.As4())
	}
	return tcpip.AddrFrom16(address.As16())
}

func newGatewayTCPConnPair(t *testing.T) (l3ingress.TCPConn, l3ingress.TCPConn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	var server net.Conn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		_ = client.Close()
		_ = listener.Close()
		t.Fatal(err)
	case <-time.After(time.Second):
		_ = client.Close()
		_ = listener.Close()
		t.Fatal("timed out accepting gateway TCP pair")
	}
	_ = listener.Close()
	clientTCP, clientOK := client.(l3ingress.TCPConn)
	serverTCP, serverOK := server.(l3ingress.TCPConn)
	if !clientOK || !serverOK {
		_ = client.Close()
		_ = server.Close()
		t.Fatalf("gateway loopback TCP pair lacks CloseWrite: %T/%T", client, server)
	}
	return clientTCP, serverTCP
}
