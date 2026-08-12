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
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestGatewayRejectsLocalTCPHandshakeUntilPeerEgressIsReady(t *testing.T) {
	serverRuntime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := serverRuntime.Listen(rendr.ListenConfig{
		AcceptL3Identity: true,
		Streams: []rendr.StreamSource{{
			Name: "tcp", Carrier: rendr.CarrierTCP, Listener: raw,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	peerDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := listener.AcceptStream(ctx)
		if err == nil {
			// The registry is factual but intentionally has no requested egress.
			err = (&l3session.TCPPeerRelay{
				Conn: conn, Egresses: l3ingress.NewEgressRegistry(),
			}).Run(ctx)
			_ = conn.Close()
		}
		peerDone <- err
	}()

	device := newGatewayTestDevice(1500)
	flowErrors := make(chan struct {
		id  l3ingress.L3Identity
		err error
	}, 1)
	root := rendr.Selector("root", []rendr.Target{
		rendr.Path("tcp", rendr.PathSpec{Transport: "tcp", Address: listener.Addr().String()}),
	})
	gateway, err := New(Config{
		Device: device,
		Router: func(context.Context, l3ingress.FlowMeta) (l3ingress.FlowDecision, error) {
			return l3ingress.FlowDecision{Peer: "peer", Root: root, Egress: "missing"}, nil
		},
		OnFlowError: func(id l3ingress.L3Identity, err error) {
			flowErrors <- struct {
				id  l3ingress.L3Identity
				err error
			}{id: id, err: err}
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

	clientStack, clientLink := newGatewayTestClientStack(
		t, header.IPv4ProtocolNumber, netip.MustParseAddr("10.0.0.2"), 24,
	)
	defer clientStack.Close()
	defer clientLink.Close()
	bridgeCtx, stopBridge := context.WithCancel(context.Background())
	defer stopBridge()
	bridgeGatewayTestPackets(bridgeCtx, clientLink, device, header.IPv4ProtocolNumber)

	destination := netip.MustParseAddr("198.51.100.20")
	dialDone := make(chan error, 1)
	go func() {
		conn, err := gonet.DialTCP(clientStack, tcpip.FullAddress{
			NIC: stackNICID, Addr: tcpipAddress(destination), Port: 443,
		}, header.IPv4ProtocolNumber)
		if conn != nil {
			_ = conn.Close()
			dialDone <- errors.New("local TCP handshake unexpectedly succeeded")
			return
		}
		dialDone <- err
	}()
	select {
	case err := <-dialDone:
		if err == nil {
			t.Fatal("local TCP handshake succeeded without a peer egress")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("local TCP handshake did not fail after peer rejection")
	}

	var failed struct {
		id  l3ingress.L3Identity
		err error
	}
	select {
	case failed = <-flowErrors:
	case <-time.After(time.Second):
		t.Fatal("gateway did not report peer readiness rejection")
	}
	var rejection *l3session.TCPPeerRejectError
	if !errors.As(failed.err, &rejection) || rejection.Reason != l3session.ReasonTCPPeerEgressUnavailable {
		t.Fatalf("flow error=%v, want peer_egress_unavailable", failed.err)
	}
	if _, ok := gateway.manager.Session(failed.id); ok {
		t.Fatal("peer-rejected TCP flow retained a rendr session")
	}
	gateway.pendingMu.Lock()
	pending := len(gateway.pending)
	gateway.pendingMu.Unlock()
	if pending != 0 {
		t.Fatalf("peer-rejected TCP flow retained %d pending SYN entries", pending)
	}
	if snapshot, ok := gateway.table.Snapshot(failed.id); ok {
		t.Fatalf("peer-rejected TCP flow remained active: %+v", snapshot)
	}

	select {
	case err := <-peerDone:
		if reason, ok := l3ingress.EgressErrorReasonOf(err); !ok || reason != l3ingress.ReasonEgressNotFound {
			t.Fatalf("peer error=%v, want egress_not_found", err)
		}
	case <-time.After(time.Second):
		t.Fatal("peer relay did not terminate after egress rejection")
	}

	cancel()
	select {
	case err := <-gatewayDone:
		if err != nil {
			t.Fatalf("gateway Run: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("gateway did not stop after readiness rejection")
	}
}

func TestGatewayTCPPeerReadinessTimeoutReleasesForwarderSlot(t *testing.T) {
	serverRuntime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := serverRuntime.Listen(rendr.ListenConfig{
		AcceptL3Identity: true,
		Streams:          []rendr.StreamSource{{Name: "tcp", Carrier: rendr.CarrierTCP, Listener: raw}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	egressApp, egressPeer := newGatewayTCPConnPair(t)
	defer egressApp.Close()
	eg := &gatewayTestEgress{conn: egressPeer, identities: make(chan l3ingress.L3Identity, 1)}
	registry := l3ingress.NewEgressRegistry()
	if err := registry.Register("direct", eg); err != nil {
		t.Fatal(err)
	}
	peerCtx, stopPeer := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopPeer()
	firstAccepted := make(chan struct{})
	releaseFirst := make(chan struct{})
	peerDone := make(chan error, 1)
	go func() {
		first, acceptErr := listener.AcceptStream(peerCtx)
		if acceptErr != nil {
			peerDone <- acceptErr
			return
		}
		close(firstAccepted)
		select {
		case <-releaseFirst:
		case <-peerCtx.Done():
			_ = first.Close()
			peerDone <- peerCtx.Err()
			return
		}
		_ = first.Close()
		second, acceptErr := listener.AcceptStream(peerCtx)
		if acceptErr == nil {
			acceptErr = (&l3session.TCPPeerRelay{Conn: second, Egresses: registry}).Run(peerCtx)
			_ = second.Close()
		}
		peerDone <- acceptErr
	}()

	device := newGatewayTestDevice(1500)
	root := rendr.Selector("root", []rendr.Target{
		rendr.Path("tcp", rendr.PathSpec{Transport: "tcp", Address: listener.Addr().String()}),
	})
	flowErrors := make(chan struct {
		id  l3ingress.L3Identity
		err error
	}, 4)
	gateway, err := New(Config{
		Device: device, TCPMaxInFlight: 1, TCPPeerReadyTimeout: 50 * time.Millisecond,
		Router: func(context.Context, l3ingress.FlowMeta) (l3ingress.FlowDecision, error) {
			return l3ingress.FlowDecision{Peer: "peer", Root: root, Egress: "direct"}, nil
		},
		OnFlowError: func(id l3ingress.L3Identity, err error) {
			flowErrors <- struct {
				id  l3ingress.L3Identity
				err error
			}{id: id, err: err}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, stopGateway := context.WithCancel(context.Background())
	gatewayDone := make(chan error, 1)
	go func() { gatewayDone <- gateway.Run(runCtx) }()
	defer func() {
		stopGateway()
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
	firstDial := make(chan error, 1)
	go func() {
		conn, dialErr := gonet.DialTCP(clientStack, tcpip.FullAddress{
			NIC: stackNICID, Addr: tcpipAddress(destination), Port: 443,
		}, header.IPv4ProtocolNumber)
		if conn != nil {
			_ = conn.Close()
		}
		firstDial <- dialErr
	}()
	select {
	case <-firstAccepted:
	case <-time.After(time.Second):
		t.Fatal("peer did not accept readiness-stalled stream")
	}
	select {
	case dialErr := <-firstDial:
		if dialErr == nil {
			t.Fatal("readiness-stalled local handshake unexpectedly succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("peer readiness timeout did not reject local handshake")
	}
	var timedOut struct {
		id  l3ingress.L3Identity
		err error
	}
	select {
	case timedOut = <-flowErrors:
		if !errors.Is(timedOut.err, context.DeadlineExceeded) {
			t.Fatalf("readiness flow error=%v, want context deadline exceeded", timedOut.err)
		}
	case <-time.After(time.Second):
		t.Fatal("gateway did not report readiness timeout")
	}
	waitGatewayTCPAdmissionCleanup(t, gateway, timedOut.id)
	close(releaseFirst)

	second, err := gonet.DialTCP(clientStack, tcpip.FullAddress{
		NIC: stackNICID, Addr: tcpipAddress(destination), Port: 444,
	}, header.IPv4ProtocolNumber)
	if err != nil {
		t.Fatalf("second flow did not reuse released forwarder slot: %v", err)
	}
	defer second.Close()
	echoDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 4)
		if _, readErr := io.ReadFull(egressApp, buf); readErr != nil {
			echoDone <- readErr
			return
		}
		_, writeErr := egressApp.Write([]byte("pong"))
		echoDone <- writeErr
	}()
	if _, err := second.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(second, response); err != nil || string(response) != "pong" {
		t.Fatalf("second flow response=%q err=%v", response, err)
	}
	if err := <-echoDone; err != nil {
		t.Fatal(err)
	}

	stopGateway()
	stopPeer()
	select {
	case err := <-gatewayDone:
		if err != nil {
			t.Fatalf("gateway Run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("gateway did not stop after readiness timeout recovery")
	}
	select {
	case err := <-peerDone:
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("peer relay: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("peer relay did not stop")
	}
}

func waitGatewayTCPAdmissionCleanup(t *testing.T, gateway *Gateway, id l3ingress.L3Identity) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		gateway.pendingMu.Lock()
		pending, admissions := len(gateway.pending), len(gateway.admissions)
		gateway.pendingMu.Unlock()
		_, session := gateway.manager.Session(id)
		_, active := gateway.table.Snapshot(id)
		if pending == 0 && admissions == 0 && !session && !active {
			return
		}
		time.Sleep(time.Millisecond)
	}
	gateway.pendingMu.Lock()
	pending, admissions := len(gateway.pending), len(gateway.admissions)
	gateway.pendingMu.Unlock()
	_, session := gateway.manager.Session(id)
	_, active := gateway.table.Snapshot(id)
	t.Fatalf("readiness cleanup pending=%d admissions=%d session=%v active=%v", pending, admissions, session, active)
}

func TestGatewayShutdownWaitsForForwarderCallbackEnteredBeforeStop(t *testing.T) {
	serverRuntime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := serverRuntime.Listen(rendr.ListenConfig{
		AcceptL3Identity: true,
		Streams:          []rendr.StreamSource{{Name: "tcp", Carrier: rendr.CarrierTCP, Listener: raw}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peerAccepted := make(chan rendr.Conn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if conn, acceptErr := listener.AcceptStream(ctx); acceptErr == nil {
			peerAccepted <- conn
		}
	}()

	device := newGatewayTestDevice(1500)
	root := rendr.Selector("root", []rendr.Target{
		rendr.Path("tcp", rendr.PathSpec{Transport: "tcp", Address: listener.Addr().String()}),
	})
	gateway, err := New(Config{
		Device: device,
		Router: func(context.Context, l3ingress.FlowMeta) (l3ingress.FlowDecision, error) {
			return l3ingress.FlowDecision{Peer: "peer", Root: root, Egress: "direct"}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	callbackEntered := make(chan struct{})
	releaseCallback := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseCallback) }) }
	defer release()
	gateway.manager.OnStart = func(context.Context, *l3session.Session) error {
		close(callbackEntered)
		<-releaseCallback
		return nil
	}
	runCtx, stopGateway := context.WithCancel(context.Background())
	defer stopGateway()
	gatewayDone := make(chan error, 1)
	go func() { gatewayDone <- gateway.Run(runCtx) }()
	defer func() {
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
	dialDone := make(chan error, 1)
	go func() {
		conn, dialErr := gonet.DialTCP(clientStack, tcpip.FullAddress{
			NIC: stackNICID, Addr: tcpipAddress(netip.MustParseAddr("198.51.100.20")), Port: 443,
		}, header.IPv4ProtocolNumber)
		if conn != nil {
			_ = conn.Close()
		}
		dialDone <- dialErr
	}()
	select {
	case <-callbackEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("TCP forwarder callback did not enter session readiness")
	}
	stopGateway()
	select {
	case err := <-gatewayDone:
		t.Fatalf("Gateway.Run returned before entered callback drained: %v", err)
	case <-time.After(75 * time.Millisecond):
	}
	release()
	select {
	case err := <-gatewayDone:
		if err != nil {
			t.Fatalf("Gateway.Run after callback release: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Gateway.Run did not finish after entered callback drained")
	}
	clientStack.Close()
	clientLink.Close()
	select {
	case dialErr := <-dialDone:
		if dialErr == nil {
			t.Fatal("shutdown-interrupted TCP dial unexpectedly succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not release local TCP dial")
	}
	select {
	case conn := <-peerAccepted:
		_ = conn.Close()
	case <-time.After(time.Second):
		t.Fatal("peer did not accept session before callback barrier")
	}
}

func TestGatewayReapIdleRemovesUnacceptedPendingSYN(t *testing.T) {
	gateway := newPendingSYNTestGateway(t)
	defer gateway.Close()
	id := l3ingress.L3Identity{
		Proto: l3ingress.ProtocolTCP,
		SrcIP: netip.MustParseAddr("10.0.0.2"), SrcPort: 41000,
		DstIP: netip.MustParseAddr("198.51.100.20"), DstPort: 443,
	}
	// The IP version is valid enough to enter the stack, but the absent TCP
	// header makes gVisor reject it without invoking the forwarder. This leaves
	// the routed SYN pending until the embedding policy reaps the idle flow.
	packet := make([]byte, 20)
	packet[0] = 0x45
	event := l3ingress.PacketEvent{
		Packet: packet,
		Meta: l3ingress.PacketMeta{
			Identity: id, TCPFlags: l3ingress.TCPFlagSYN,
		},
		Flow: l3ingress.FlowMeta{L3Identity: id, Direction: l3ingress.DirectionIngress},
	}
	if err := gateway.HandlePacket(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	gateway.pendingMu.Lock()
	pendingBefore := len(gateway.pending)
	gateway.pendingMu.Unlock()
	if pendingBefore != 1 {
		t.Fatalf("pending SYN entries=%d, want 1", pendingBefore)
	}
	reaped := gateway.ReapIdle(time.Now().Add(time.Second))
	if len(reaped) != 1 || reaped[0].Ref.Identity != id {
		t.Fatalf("reaped=%+v, want one TCP flow", reaped)
	}
	gateway.pendingMu.Lock()
	pendingAfter := len(gateway.pending)
	gateway.pendingMu.Unlock()
	if pendingAfter != 0 {
		t.Fatalf("idle reap retained %d pending SYN entries", pendingAfter)
	}
}

func TestGatewayStaleReapCannotDeleteReplacementPendingSYN(t *testing.T) {
	gateway := newPendingSYNTestGateway(t)
	defer gateway.Close()
	id := l3ingress.L3Identity{
		Proto: l3ingress.ProtocolTCP,
		SrcIP: netip.MustParseAddr("10.0.0.2"), SrcPort: 42000,
		DstIP: netip.MustParseAddr("198.51.100.20"), DstPort: 443,
	}
	flow := l3ingress.FlowMeta{L3Identity: id, Direction: l3ingress.DirectionIngress}
	decision, _, first, err := gateway.table.Resolve(context.Background(), flow, 40)
	if err != nil {
		t.Fatal(err)
	}
	firstEvent := l3ingress.PacketEvent{
		Meta: l3ingress.PacketMeta{Identity: id, TCPFlags: l3ingress.TCPFlagSYN},
		Flow: first.Flow, Ref: first.Ref, Decision: decision, Decided: true,
	}
	gateway.pendingMu.Lock()
	gateway.pending[first.Ref] = firstEvent
	gateway.pendingMu.Unlock()
	closed, ok := gateway.table.CloseRef(first.Ref, l3ingress.FlowCloseManual)
	if !ok {
		t.Fatal("first flow did not close")
	}
	decision, _, second, err := gateway.table.Resolve(context.Background(), flow, 40)
	if err != nil {
		t.Fatal(err)
	}
	if second.Ref == first.Ref {
		t.Fatal("tuple reuse did not allocate a new flow generation")
	}
	secondEvent := l3ingress.PacketEvent{
		Meta: l3ingress.PacketMeta{Identity: id, TCPFlags: l3ingress.TCPFlagSYN},
		Flow: second.Flow, Ref: second.Ref, Decision: decision, Decided: true,
	}
	gateway.pendingMu.Lock()
	gateway.pending[second.Ref] = secondEvent
	gateway.pendingMu.Unlock()

	// A relay callback that already claimed the old SYN may finish after tuple
	// reuse. Its exact ref must not close the replacement flow.
	gateway.finishTCPFlow(context.Background(), firstEvent, errors.New("stale relay failure"))
	if current, ok := gateway.table.Snapshot(id); !ok || current.Ref != second.Ref {
		t.Fatalf("stale relay completion replaced current flow: current=%+v ok=%v want=%+v", current.Ref, ok, second.Ref)
	}
	gateway.closeReapedSession(closed)
	gateway.pendingMu.Lock()
	got, exists := gateway.pending[second.Ref]
	gateway.pendingMu.Unlock()
	if !exists || got.Ref != second.Ref {
		t.Fatalf("stale reap removed replacement pending SYN: exists=%v got=%+v want=%+v", exists, got.Ref, second.Ref)
	}
}

func TestGatewayTCPRelayCloseReasonDistinguishesFINFromFailure(t *testing.T) {
	tests := []struct {
		name   string
		port   uint16
		err    error
		reason l3ingress.FlowCloseReason
	}{
		{name: "orderly-fin", port: 43000, reason: l3ingress.FlowCloseTCPFIN},
		{name: "relay-failure", port: 43001, err: errors.New("injected relay reset"), reason: l3ingress.FlowCloseTCPRST},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gateway := newPendingSYNTestGateway(t)
			defer gateway.Close()
			id := l3ingress.L3Identity{
				Proto: l3ingress.ProtocolTCP,
				SrcIP: netip.MustParseAddr("10.0.0.2"), SrcPort: tt.port,
				DstIP: netip.MustParseAddr("198.51.100.20"), DstPort: 443,
			}
			flow := l3ingress.FlowMeta{L3Identity: id, Direction: l3ingress.DirectionIngress}
			decision, _, snapshot, err := gateway.table.Resolve(context.Background(), flow, 40)
			if err != nil {
				t.Fatal(err)
			}
			event := l3ingress.PacketEvent{
				Meta: l3ingress.PacketMeta{Identity: id}, Flow: snapshot.Flow,
				Ref: snapshot.Ref, Decision: decision, Decided: true,
			}
			gateway.finishTCPFlow(context.Background(), event, tt.err)
			closed, ok := gateway.table.ClosedSnapshot(id)
			if !ok || closed.Ref != snapshot.Ref || closed.CloseReason != tt.reason {
				t.Fatalf("closed=%+v ok=%v, want ref=%+v reason=%q", closed, ok, snapshot.Ref, tt.reason)
			}
		})
	}
}

func newPendingSYNTestGateway(t *testing.T) *Gateway {
	t.Helper()
	root := rendr.Selector("root", []rendr.Target{
		rendr.Path("tcp", rendr.PathSpec{Transport: "tcp", Address: "127.0.0.1:1"}),
	})
	gateway, err := New(Config{
		Device: newGatewayTestDevice(1500),
		Router: func(context.Context, l3ingress.FlowMeta) (l3ingress.FlowDecision, error) {
			return l3ingress.FlowDecision{Peer: "peer", Root: root, Egress: "direct"}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return gateway
}
