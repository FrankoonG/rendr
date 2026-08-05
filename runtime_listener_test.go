package rendr

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport/tcp"
)

func TestRuntimeListenerCrossSourceBridgeAndCloseIsolation(t *testing.T) {
	first, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	second, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = first.Close()
		t.Fatal(err)
	}
	serverRuntime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := serverRuntime.Listen(ListenConfig{Streams: []StreamSource{
		{Name: "ingress-a", Carrier: CarrierTCP, Listener: first},
		{Name: "ingress-b", Carrier: CarrierTCP, Listener: second},
	}})
	if err != nil {
		_ = first.Close()
		_ = second.Close()
		t.Fatal(err)
	}
	defer listener.Close()

	clientRuntime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	registerTCPFactory := func(name string) {
		t.Helper()
		err := clientRuntime.RegisterStreamFactory(name, StreamFactory{
			Carrier: CarrierTCP,
			Dial: func(ctx context.Context, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", address)
			},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	registerTCPFactory("carrier-a")
	registerTCPFactory("carrier-b")
	client, err := clientRuntime.Dial(context.Background(), SessionConfig{Root: Selector("root", []Target{
		Path("a", PathSpec{Transport: "carrier-a", Address: first.Addr().String()}),
		Path("b", PathSpec{Transport: "carrier-b", Address: second.Addr().String()}),
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server, err := listener.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	assertAcceptedControlSurface(t, server)

	if !waitForRuntimePathCount(client, server, 2, 5*time.Second) {
		t.Fatalf("cross-source bridge did not attach: client=%v server=%v", client.Paths(), server.Paths())
	}
	if got := client.Status().Peer.InstanceID; got != serverRuntime.instanceID {
		t.Fatalf("peer instance=%x want shared Runtime instance=%x", got, serverRuntime.instanceID)
	}
	if got := serverRuntime.bridges.Len(); got != 1 {
		t.Fatalf("active Runtime flow count=%d want 1", got)
	}

	assertStreamRoundTrip(t, client, server, []byte("before-listener-close"))
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	assertStreamRoundTrip(t, server, client, []byte("accepted-session-survives"))
}

func TestRuntimeListenerSourceFailureIsIsolated(t *testing.T) {
	failed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	healthy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = failed.Close()
		t.Fatal(err)
	}
	serverRuntime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := serverRuntime.Listen(ListenConfig{Streams: []StreamSource{
		{Name: "failed", Carrier: CarrierTCP, Listener: failed},
		{Name: "healthy", Carrier: CarrierTCP, Listener: healthy},
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := failed.Close(); err != nil {
		t.Fatal(err)
	}

	clientRuntime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := clientRuntime.RegisterStreamFactory("healthy", StreamFactory{
		Carrier: CarrierTCP,
		Dial: func(ctx context.Context, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", address)
		},
	}); err != nil {
		t.Fatal(err)
	}
	client, err := clientRuntime.Dial(context.Background(), SessionConfig{Root: Path("healthy", PathSpec{
		Transport: "healthy",
		Address:   healthy.Addr().String(),
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server, err := listener.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("healthy source was terminated by sibling failure: %v", err)
	}
	defer server.Close()
	assertStreamRoundTrip(t, client, server, []byte("source-isolation"))
}

func TestRuntimeListenerPacketSessionSurvivesListenerClose(t *testing.T) {
	serverSocket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverRuntime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := serverRuntime.Listen(ListenConfig{Packets: []PacketSource{{
		Name:    "packet-ingress",
		Carrier: CarrierUDP,
		Conn:    serverSocket,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	clientRuntime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := clientRuntime.RegisterPacketFactory("packet", PacketFactory{
		Carrier: CarrierUDP,
		Dial: func(context.Context, string) (net.PacketConn, error) {
			return net.ListenPacket("udp", "127.0.0.1:0")
		},
	}); err != nil {
		t.Fatal(err)
	}
	client, err := clientRuntime.DialPacket(context.Background(), SessionConfig{Root: Path("packet", PathSpec{
		Transport: "packet",
		Address:   serverSocket.LocalAddr().String(),
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server, err := listener.AcceptPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	assertAcceptedControlSurface(t, server)
	assertPacketRoundTrip(t, client, server, []byte("packet-before-close"))
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	assertPacketRoundTrip(t, server, client, []byte("packet-after-close"))
}

func TestRuntimeListenerCrossStreamPacketSourceBridge(t *testing.T) {
	streamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	packetSocket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		_ = streamListener.Close()
		t.Fatal(err)
	}
	serverRuntime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := serverRuntime.Listen(ListenConfig{
		Streams: []StreamSource{{Name: "stream-ingress", Carrier: CarrierTCP, Listener: streamListener}},
		Packets: []PacketSource{{Name: "packet-ingress", Carrier: CarrierUDP, Conn: packetSocket}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	clientRuntime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := clientRuntime.RegisterStreamFactory("stream", StreamFactory{
		Carrier: CarrierTCP,
		Dial: func(ctx context.Context, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", address)
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := clientRuntime.RegisterPacketFactory("packet", PacketFactory{
		Carrier: CarrierUDP,
		Dial: func(context.Context, string) (net.PacketConn, error) {
			return net.ListenPacket("udp", "127.0.0.1:0")
		},
	}); err != nil {
		t.Fatal(err)
	}
	client, err := clientRuntime.Dial(context.Background(), SessionConfig{Root: Selector("root", []Target{
		Path("stream", PathSpec{Transport: "stream", Address: streamListener.Addr().String()}),
		Path("packet", PathSpec{Transport: "packet", Address: packetSocket.LocalAddr().String()}),
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server, err := listener.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if !waitForRuntimePathCount(client, server, 2, 5*time.Second) {
		t.Fatalf("heterogeneous bridge did not attach: client=%v server=%v", client.Paths(), server.Paths())
	}
	assertStatusCarrier(t, client.Status(), "stream", CarrierTCP)
	assertStatusCarrier(t, client.Status(), "packet", CarrierUDP)
	assertStatusCarrier(t, server.Status(), "stream", CarrierTCP)
	assertStatusCarrier(t, server.Status(), "packet", CarrierUDP)

	clientPacketID := runtimeListenerPathID(t, client.Paths(), "packet")
	if err := client.(*engineBackedConn).Migrate(clientPacketID); err != nil {
		t.Fatal(err)
	}
	assertStreamRoundTrip(t, client, server, []byte("stream-over-packet-leaf"))
	clientPacket := runtimeListenerPathInfo(t, client.Paths(), clientPacketID)
	if clientPacket.DataWrites == 0 {
		t.Fatalf("packet-backed leaf carried no DATA: %+v", clientPacket)
	}

	serverPacketID := runtimeListenerPathID(t, server.Paths(), "packet")
	if err := server.(MigrationController).Migrate(serverPacketID); err != nil {
		t.Fatal(err)
	}
	assertStreamRoundTrip(t, server, client, []byte("reverse-over-packet-leaf"))
}

func TestRuntimeListenerCloseUnblocksSlowFirstFrame(t *testing.T) {
	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := runtime.Listen(ListenConfig{Streams: []StreamSource{{
		Name:     "slow",
		Carrier:  CarrierTCP,
		Listener: rawListener,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Dial("tcp", rawListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	deadline := time.Now().Add(2 * time.Second)
	for runtimeListenerInflight(listener) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if runtimeListenerInflight(listener) == 0 {
		t.Fatal("slow first-frame connection never entered handshake admission")
	}
	started := time.Now()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	for runtimeListenerInflight(listener) != 0 && time.Since(started) < time.Second {
		time.Sleep(time.Millisecond)
	}
	if got := runtimeListenerInflight(listener); got != 0 {
		t.Fatalf("in-flight handshakes after close=%d", got)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("listener close took too long to reclaim slow first frame: %s", elapsed)
	}
}

func TestRuntimeListenerCloseJoinsHandshakeWorker(t *testing.T) {
	source := newRuntimePipeListener()
	runtime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := runtime.Listen(ListenConfig{Streams: []StreamSource{{
		Name: "gated", Carrier: CarrierUnknown, Listener: source,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	conn := newGatedFirstFrameConn()
	if err := source.inject(conn); err != nil {
		t.Fatal(err)
	}
	select {
	case <-conn.readStarted:
	case <-time.After(time.Second):
		t.Fatal("handshake worker did not enter first-frame read")
	}
	closed := make(chan error, 1)
	go func() { closed <- listener.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("listener Close returned before handshake worker exited: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	conn.releaseRead()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("listener Close did not join released handshake worker")
	}
	if got := runtimeListenerInflight(listener); got != 0 {
		t.Fatalf("in-flight paths after joined close=%d", got)
	}
}

func TestRuntimeListenerLastSourceFailureCompletesSelfShutdown(t *testing.T) {
	runtime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	sourceErr := errors.New("terminal source failure")
	listener, err := runtime.Listen(ListenConfig{Streams: []StreamSource{{
		Name: "terminal", Carrier: CarrierUnknown, Listener: &terminalErrorListener{err: sourceErr},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-listener.closed:
	case <-time.After(time.Second):
		t.Fatal("last-source failure did not start listener shutdown")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		runtime.listenMu.Lock()
		released := runtime.listener == nil
		runtime.listenMu.Unlock()
		if released {
			break
		}
		time.Sleep(time.Millisecond)
	}
	runtime.listenMu.Lock()
	released := runtime.listener == nil
	runtime.listenMu.Unlock()
	if !released {
		t.Fatal("last-source worker waited on itself during shutdown")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := listener.AcceptStream(ctx); !errors.Is(err, sourceErr) {
		t.Fatalf("accept error=%v, want terminal source error", err)
	}
	replacementSource := newRuntimePipeListener()
	replacement, err := runtime.Listen(ListenConfig{Streams: []StreamSource{{
		Name: "replacement", Carrier: CarrierUnknown, Listener: replacementSource,
	}}})
	if err != nil {
		t.Fatalf("runtime did not accept replacement listener after self-shutdown: %v", err)
	}
	if err := replacement.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeListenerCloseForceClosesUnacceptedSession(t *testing.T) {
	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverRuntime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := serverRuntime.Listen(ListenConfig{Streams: []StreamSource{{
		Name:     "stream",
		Carrier:  CarrierTCP,
		Listener: rawListener,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	clientRuntime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := clientRuntime.RegisterStreamFactory("stream", StreamFactory{
		Carrier: CarrierTCP,
		Dial: func(ctx context.Context, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", address)
		},
	}); err != nil {
		t.Fatal(err)
	}
	client, err := clientRuntime.Dial(context.Background(), SessionConfig{Root: Path("stream", PathSpec{
		Transport: "stream",
		Address:   rawListener.Addr().String(),
	})})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.(*engineBackedConn).e.Close() })

	deadline := time.Now().Add(2 * time.Second)
	for len(listener.streamAccept) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(listener.streamAccept) != 1 {
		t.Fatal("completed session was not queued before listener close")
	}
	serverEngine, ok := serverRuntime.bridges.Lookup(client.FlowID())
	if !ok || serverEngine == nil {
		t.Fatal("queued session engine was not active before listener close")
	}

	closed := make(chan error, 1)
	go func() { closed <- listener.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("listener close waited on graceful teardown of an unaccepted session")
	}
	if got := len(listener.streamAccept); got != 0 {
		t.Fatalf("queued sessions after close=%d", got)
	}
	deadline = time.Now().Add(time.Second)
	for serverRuntime.bridges.Len() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := serverRuntime.bridges.Len(); got != 0 {
		t.Fatalf("bridge entries after force-closing unaccepted session=%d", got)
	}
	select {
	case <-serverEngine.Closed():
	case <-time.After(time.Second):
		t.Fatal("unaccepted server engine did not quiesce after listener close")
	}
}

func TestRuntimeListenerBridgeCannotObserveFailedHelloReservation(t *testing.T) {
	source := newRuntimePipeListener()
	serverRuntime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := serverRuntime.Listen(ListenConfig{Streams: []StreamSource{{
		Name:     "pipe",
		Carrier:  CarrierUnknown,
		Listener: source,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	flowID := engine.NewClientFlowID()
	clientEngine := engine.New(engine.SideClient, flowID, engine.Limits{})
	defer clientEngine.Close()
	graph, err := compileTargetGraph(Path("path", PathSpec{Transport: "pipe", Address: "peer"}))
	if err != nil {
		t.Fatal(err)
	}
	if err := clientEngine.ConfigureLocalGraph(1, graph.manifest); err != nil {
		t.Fatal(err)
	}
	clientID := engine.NewInstanceID()
	clientEngine.SetLocalInstanceID(clientID)
	targetID, err := clientEngine.LocalPathTargetID("path")
	if err != nil {
		t.Fatal(err)
	}
	helloPayload, err := (proto.HelloPayload{
		Negotiation:     clientEngine.LocalNegotiation(),
		FlowID:          flowID,
		InstanceID:      clientID,
		InitialTargetID: targetID,
		LocalTXManifest: clientEngine.LocalGraphManifest(),
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}

	clientHello, serverHello := net.Pipe()
	defer clientHello.Close()
	if err := source.inject(serverHello); err != nil {
		t.Fatal(err)
	}
	helloPath := tcp.Wrap(clientHello)
	writeRuntimeTestControl(t, helloPath, proto.CtrlHello, helloPayload)
	deadline := time.Now().Add(2 * time.Second)
	for serverRuntime.bridges.Len() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := serverRuntime.bridges.Len(); got != 1 {
		t.Fatalf("HELLO reservation count=%d want 1", got)
	}
	if active := serverRuntime.bridges.Snapshot(); len(active) != 0 {
		t.Fatalf("reserved HELLO was prematurely published: %x", active)
	}

	clientBridge, serverBridge := net.Pipe()
	defer clientBridge.Close()
	if err := source.inject(serverBridge); err != nil {
		t.Fatal(err)
	}
	bridgePath := tcp.Wrap(clientBridge)
	negotiation := clientEngine.LocalNegotiation()
	tag := proto.BridgeTagPayload{
		BridgeID:               flowID,
		AttachID:               engine.NewClientFlowID(),
		InstanceID:             clientID,
		ExpectedPeerInstanceID: serverRuntime.instanceID,
		SessionEpoch:           negotiation.SessionEpoch,
		Direction:              proto.SenderDirectionClientToServer,
		GraphRevision:          negotiation.GraphRevision,
		GraphDigest:            negotiation.GraphDigest,
		TargetID:               targetID,
	}
	writeRuntimeTestControl(t, bridgePath, proto.CtrlBridgeTag, tag.Encode())

	// The server is blocked writing HELLO_ACK to the first net.Pipe. Closing
	// that peer forces HELLO rollback; the waiting BRIDGE must observe abort,
	// never the half-constructed Engine.
	if err := clientHello.Close(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, tcp.MaxFrameSize)
	n, err := bridgePath.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	header, err := proto.DecodeHeader(buf[:proto.HeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	if header.Type != proto.FrameCtrl || proto.CtrlCodeFromFlags(header.Flags) != proto.CtrlBridgeAck {
		t.Fatalf("first bridge response=%v/%v", header.Type, proto.CtrlCodeFromFlags(header.Flags))
	}
	ack, err := proto.DecodeBridgeAck(buf[proto.HeaderSize:n])
	if err != nil {
		t.Fatal(err)
	}
	if ack.Code != proto.AckRejectUnknown {
		t.Fatalf("bridge ack=%s want %s", ack.Code, proto.AckRejectUnknown)
	}
	deadline = time.Now().Add(time.Second)
	for serverRuntime.bridges.Len() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := serverRuntime.bridges.Len(); got != 0 {
		t.Fatalf("bridge reservation leaked after HELLO rollback: %d", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := listener.AcceptStream(ctx); err == nil {
		t.Fatal("failed HELLO produced an application session")
	}
}

func TestRuntimeListenerAcceptCloseOwnershipLinearization(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		rawListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		serverRuntime, err := NewRuntime(RuntimeConfig{})
		if err != nil {
			t.Fatal(err)
		}
		listener, err := serverRuntime.Listen(ListenConfig{Streams: []StreamSource{{
			Name:     "stream",
			Carrier:  CarrierTCP,
			Listener: rawListener,
		}}})
		if err != nil {
			t.Fatal(err)
		}
		clientRuntime, err := NewRuntime(RuntimeConfig{})
		if err != nil {
			t.Fatal(err)
		}
		if err := clientRuntime.RegisterStreamFactory("stream", StreamFactory{
			Carrier: CarrierTCP,
			Dial: func(ctx context.Context, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", address)
			},
		}); err != nil {
			t.Fatal(err)
		}
		client, err := clientRuntime.Dial(context.Background(), SessionConfig{Root: Path("stream", PathSpec{
			Transport: "stream",
			Address:   rawListener.Addr().String(),
		})})
		if err != nil {
			t.Fatal(err)
		}

		type acceptResult struct {
			conn Conn
			err  error
		}
		start := make(chan struct{})
		accepted := make(chan acceptResult, 1)
		closed := make(chan error, 1)
		go func() {
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := listener.AcceptStream(ctx)
			accepted <- acceptResult{conn: conn, err: err}
		}()
		go func() {
			<-start
			closed <- listener.Close()
		}()
		close(start)
		result := <-accepted
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
		if result.err == nil {
			assertStreamRoundTrip(t, client, result.conn, []byte("accepted-before-close"))
			_ = result.conn.Close()
		} else if result.conn != nil {
			t.Fatalf("iteration %d returned conn with error %v", iteration, result.err)
		}
		// This test owns the unpublished side directly. A listener-close win
		// intentionally leaves no peer route, so graceful Close would spend its
		// full bounded timeout on every iteration and obscure the ownership race.
		_ = client.(*engineBackedConn).e.Close()
		deadline := time.Now().Add(time.Second)
		for serverRuntime.bridges.Len() != 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if got := serverRuntime.bridges.Len(); got != 0 {
			t.Fatalf("iteration %d leaked %d bridge entries", iteration, got)
		}
		if got := len(listener.streamSlots); got != 0 {
			t.Fatalf("iteration %d leaked %d accept slots", iteration, got)
		}
	}
}

func TestRuntimeAllowsOnlyOneActiveIngressDomain(t *testing.T) {
	runtime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	firstRaw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	first, err := runtime.Listen(ListenConfig{Streams: []StreamSource{{Name: "first", Listener: firstRaw}}})
	if err != nil {
		t.Fatal(err)
	}
	secondRaw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Listen(ListenConfig{Streams: []StreamSource{{Name: "second", Listener: secondRaw}}}); err == nil {
		_ = secondRaw.Close()
		t.Fatal("Runtime accepted a second active ingress domain")
	}
	_ = secondRaw.Close()
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	replacementRaw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := runtime.Listen(ListenConfig{Streams: []StreamSource{{Name: "replacement", Listener: replacementRaw}}})
	if err != nil {
		_ = replacementRaw.Close()
		t.Fatalf("Runtime did not release closed ingress domain: %v", err)
	}
	_ = replacement.Close()
}

func TestRuntimeListenerHelloRetryAfterLostAckIsIdempotent(t *testing.T) {
	firstRaw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	first := &dropFirstHelloAckListener{Listener: firstRaw}
	second, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = firstRaw.Close()
		t.Fatal(err)
	}
	serverRuntime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := serverRuntime.Listen(ListenConfig{Streams: []StreamSource{
		{Name: "first", Carrier: CarrierTCP, Listener: first},
		{Name: "second", Carrier: CarrierTCP, Listener: second},
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	clientRuntime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"first", "second"} {
		if err := clientRuntime.RegisterStreamFactory(name, StreamFactory{
			Carrier: CarrierTCP,
			Dial: func(ctx context.Context, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", address)
			},
		}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := clientRuntime.Dial(ctx, SessionConfig{Root: Selector("root", []Target{
		Path("first", PathSpec{Transport: "first", Address: firstRaw.Addr().String()}),
		Path("second", PathSpec{Transport: "second", Address: second.Addr().String()}),
	})})
	if err != nil {
		t.Fatalf("HELLO retry did not recover lost ACK: %v", err)
	}
	defer client.Close()
	server, err := listener.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if !waitForRuntimePathCount(client, server, 2, 5*time.Second) {
		t.Fatalf("retry session paths client=%v server=%v", client.Paths(), server.Paths())
	}
	assertStreamRoundTrip(t, client, server, []byte("hello-retry"))
	if got := serverRuntime.bridges.Len(); got != 1 {
		t.Fatalf("HELLO retry produced %d active flows, want 1", got)
	}
	secondAcceptCtx, secondCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer secondCancel()
	if duplicate, err := listener.AcceptStream(secondAcceptCtx); err == nil {
		_ = duplicate.Close()
		t.Fatal("HELLO retry produced a duplicate application session")
	}
}

func TestRuntimeListenerRejectsNoncanonicalHelloBeforeReservation(t *testing.T) {
	source := newRuntimePipeListener()
	runtime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := runtime.Listen(ListenConfig{Streams: []StreamSource{{Name: "pipe", Listener: source}}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cases := []struct {
		name         string
		mutateHeader func(*proto.Header)
		zeroInstance bool
	}{
		{name: "last flag", mutateHeader: func(header *proto.Header) { header.Last = true }},
		{name: "nonzero sequence", mutateHeader: func(header *proto.Header) { header.Seq = 1 }},
		{name: "unused control flags", mutateHeader: func(header *proto.Header) { header.Flags |= 0x0100 }},
		{name: "zero peer instance", zeroInstance: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			flowID := engine.NewClientFlowID()
			clientEngine := engine.New(engine.SideClient, flowID, engine.Limits{}.Clamp())
			defer clientEngine.Close()
			graph, err := compileTargetGraph(Path("path", PathSpec{Transport: "pipe", Address: "peer"}))
			if err != nil {
				t.Fatal(err)
			}
			if err := clientEngine.ConfigureLocalGraph(1, graph.manifest); err != nil {
				t.Fatal(err)
			}
			instanceID := engine.NewInstanceID()
			targetID, err := clientEngine.LocalPathTargetID("path")
			if err != nil {
				t.Fatal(err)
			}
			payload, err := (proto.HelloPayload{
				Negotiation:     clientEngine.LocalNegotiation(),
				FlowID:          flowID,
				InstanceID:      instanceID,
				InitialTargetID: targetID,
				LocalTXManifest: clientEngine.LocalGraphManifest(),
			}).Encode()
			if err != nil {
				t.Fatal(err)
			}
			if testCase.zeroInstance {
				clear(payload[96:112])
			}
			clientRaw, serverRaw := net.Pipe()
			defer clientRaw.Close()
			if err := source.inject(serverRaw); err != nil {
				t.Fatal(err)
			}
			header := proto.Header{Version: proto.Version, Type: proto.FrameCtrl, Flags: proto.FlagsForCtrl(proto.CtrlHello)}
			if testCase.mutateHeader != nil {
				testCase.mutateHeader(&header)
			}
			writeRuntimeTestHeader(t, tcp.Wrap(clientRaw), header, payload)
			_ = clientRaw.SetReadDeadline(time.Now().Add(time.Second))
			var one [1]byte
			if _, err := clientRaw.Read(one[:]); err == nil {
				t.Fatal("malformed HELLO received a response instead of rejection")
			}
			deadline := time.Now().Add(time.Second)
			for runtimeListenerInflight(listener) != 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if got := runtime.bridges.Len(); got != 0 {
				t.Fatalf("malformed HELLO reserved %d flows", got)
			}
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if conn, err := listener.AcceptStream(ctx); err == nil {
		_ = conn.Close()
		t.Fatal("malformed HELLO produced an application session")
	}
}

func waitForRuntimePathCount(client, server Conn, want int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if len(client.Paths()) == want && len(server.Paths()) == want {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return len(client.Paths()) == want && len(server.Paths()) == want
}

func assertStreamRoundTrip(t *testing.T, writer net.Conn, reader net.Conn, payload []byte) {
	t.Helper()
	if err := writer.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := reader.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload=%q want %q", got, payload)
	}
}

func assertPacketRoundTrip(t *testing.T, writer, reader PacketConn, payload []byte) {
	t.Helper()
	if err := writer.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := reader.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.WriteTo(payload, nil); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	n, _, err := reader.ReadFrom(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(got[:n]) != string(payload) {
		t.Fatalf("packet payload=%q want %q", got[:n], payload)
	}
}

func runtimeListenerPathID(t *testing.T, paths []PathInfo, name string) uint32 {
	t.Helper()
	for _, path := range paths {
		if pathSpecName(path.Spec) == name {
			return path.ID
		}
	}
	t.Fatalf("path %q not found in %v", name, paths)
	return 0
}

func runtimeListenerPathInfo(t *testing.T, paths []PathInfo, id uint32) PathInfo {
	t.Helper()
	for _, path := range paths {
		if path.ID == id {
			return path
		}
	}
	t.Fatalf("path id %d not found in %v", id, paths)
	return PathInfo{}
}

func assertAcceptedControlSurface(t *testing.T, session any) {
	t.Helper()
	if _, ok := session.(MigrationController); !ok {
		t.Fatalf("accepted session %T lacks MigrationController", session)
	}
	if _, ok := session.(ConnectionObserver); !ok {
		t.Fatalf("accepted session %T lacks ConnectionObserver", session)
	}
	if _, ok := session.(PathController); ok {
		t.Fatalf("accepted session %T exposes unsupported PathController", session)
	}
}

func assertStatusCarrier(t *testing.T, status Status, name string, want CarrierFamily) {
	t.Helper()
	for _, path := range status.Paths {
		if path.Name == name {
			if path.Carrier != want {
				t.Fatalf("status path %q carrier=%d want %d: %+v", name, path.Carrier, want, status.Paths)
			}
			return
		}
	}
	t.Fatalf("status path %q missing: %+v", name, status.Paths)
}

func runtimeListenerInflight(listener *SessionListener) int {
	listener.inflightMu.Lock()
	defer listener.inflightMu.Unlock()
	return len(listener.inflight)
}

func writeRuntimeTestControl(t *testing.T, path *tcp.PathConn, code proto.CtrlCode, payload []byte) {
	t.Helper()
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := (proto.Header{
		Version: proto.Version,
		Type:    proto.FrameCtrl,
		Flags:   proto.FlagsForCtrl(code),
	}).Encode(frame[:proto.HeaderSize]); err != nil {
		t.Fatal(err)
	}
	copy(frame[proto.HeaderSize:], payload)
	if _, err := path.Write(frame); err != nil {
		t.Fatal(err)
	}
}

func writeRuntimeTestHeader(t *testing.T, path *tcp.PathConn, header proto.Header, payload []byte) {
	t.Helper()
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := header.Encode(frame[:proto.HeaderSize]); err != nil {
		t.Fatal(err)
	}
	copy(frame[proto.HeaderSize:], payload)
	if _, err := path.Write(frame); err != nil {
		t.Fatal(err)
	}
}

type runtimePipeListener struct {
	accept chan net.Conn
	closed chan struct{}
	once   sync.Once
}

type gatedFirstFrameConn struct {
	readStarted chan struct{}
	release     chan struct{}
	closed      chan struct{}
	readOnce    sync.Once
	releaseOnce sync.Once
	closeOnce   sync.Once
}

type terminalErrorListener struct{ err error }

func (l *terminalErrorListener) Accept() (net.Conn, error) { return nil, l.err }
func (l *terminalErrorListener) Close() error              { return nil }
func (l *terminalErrorListener) Addr() net.Addr            { return stringAddr("terminal-error") }

func newGatedFirstFrameConn() *gatedFirstFrameConn {
	return &gatedFirstFrameConn{
		readStarted: make(chan struct{}),
		release:     make(chan struct{}),
		closed:      make(chan struct{}),
	}
}

func (c *gatedFirstFrameConn) Read([]byte) (int, error) {
	c.readOnce.Do(func() { close(c.readStarted) })
	<-c.release
	return 0, net.ErrClosed
}

func (c *gatedFirstFrameConn) Write(payload []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
		return len(payload), nil
	}
}

func (c *gatedFirstFrameConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *gatedFirstFrameConn) LocalAddr() net.Addr              { return stringAddr("gated-local") }
func (c *gatedFirstFrameConn) RemoteAddr() net.Addr             { return stringAddr("gated-remote") }
func (c *gatedFirstFrameConn) SetDeadline(time.Time) error      { return nil }
func (c *gatedFirstFrameConn) SetReadDeadline(time.Time) error  { return nil }
func (c *gatedFirstFrameConn) SetWriteDeadline(time.Time) error { return nil }
func (c *gatedFirstFrameConn) releaseRead()                     { c.releaseOnce.Do(func() { close(c.release) }) }

func newRuntimePipeListener() *runtimePipeListener {
	return &runtimePipeListener{
		accept: make(chan net.Conn),
		closed: make(chan struct{}),
	}
}

func (l *runtimePipeListener) inject(conn net.Conn) error {
	select {
	case l.accept <- conn:
		return nil
	case <-l.closed:
		return net.ErrClosed
	}
}

func (l *runtimePipeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.accept:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *runtimePipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *runtimePipeListener) Addr() net.Addr { return stringAddr("runtime-pipe") }

type dropFirstHelloAckListener struct {
	net.Listener
	once sync.Once
}

func (l *dropFirstHelloAckListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	wrapped := false
	l.once.Do(func() { wrapped = true })
	if !wrapped {
		return conn, nil
	}
	return &dropFirstFramedWriteConn{Conn: conn}, nil
}

type dropFirstFramedWriteConn struct {
	net.Conn
	writes atomic.Int32
}

func (c *dropFirstFramedWriteConn) Write(payload []byte) (int, error) {
	write := c.writes.Add(1)
	if write <= 2 {
		if write == 2 {
			_ = c.Conn.Close()
		}
		return len(payload), nil
	}
	return c.Conn.Write(payload)
}
