package rendr

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/transport/tcp"
)

func TestRuntimeAutomaticallyRedialsDeadGenericLeaf(t *testing.T) {
	listener, err := ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := listener.Accept(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	runtime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int32
	if err := runtime.RegisterStreamFactory("recover-stream", StreamFactory{
		Carrier: CarrierTCP,
		Dial: func(ctx context.Context, address string) (net.Conn, error) {
			attempt := attempts.Add(1)
			if attempt == 2 || attempt == 3 {
				return nil, &net.DNSError{Err: "injected recovery dial failure", IsTemporary: true}
			}
			var dialer net.Dialer
			return dialer.DialContext(ctx, "tcp", address)
		},
	}); err != nil {
		t.Fatal(err)
	}
	spec := PathSpec{Transport: "recover-stream", Address: listener.Addr().String(), Opts: map[string]string{"name": "b"}}
	clientConn, err := runtime.Dial(context.Background(), SessionConfig{Root: Selector("root", []Target{Path("b", spec)})})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	var serverConn Conn
	select {
	case serverConn = <-accepted:
	case err := <-acceptErr:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("accept timed out")
	}
	defer serverConn.Close()

	client := clientConn.(*engineBackedConn)
	server := serverConn.(*engineBackedConn)
	deadID := client.Paths()[0].ID
	if err := client.e.ForceKillPathForTest(deadID); err != nil {
		t.Fatal(err)
	}
	replacement, serverReplacement := waitForStreamReplacement(t, client, server, deadID, 5*time.Second)
	if attempts.Load() < 4 {
		t.Fatalf("recovery did not retry injected dial failures: attempts=%d", attempts.Load())
	}
	assertBidirectionalStreamPayload(t, client, server, "first-replacement")
	assertPathCarriedData(t, client.Paths(), replacement)
	assertPathCarriedData(t, server.Paths(), serverReplacement)
	if err := client.e.ForceKillPathForTest(replacement); err != nil {
		t.Fatal(err)
	}
	second, secondServer := waitForStreamReplacement(t, client, server, replacement, 5*time.Second)
	if attempts.Load() < 5 {
		t.Fatalf("immediate second death did not redial again: attempts=%d", attempts.Load())
	}
	assertBidirectionalStreamPayload(t, client, server, "second-replacement")
	assertPathCarriedData(t, client.Paths(), second)
	assertPathCarriedData(t, server.Paths(), secondServer)
	waitForMigrationCounts(t, client.MigrationCount, server.MigrationCount, 2)
}

func TestRecoveryGenerationReconcilesStartupAndInFlightDeath(t *testing.T) {
	e := engine.New(engine.SideClient, engine.NewClientFlowID(), engine.Limits{}.Clamp())
	defer e.Close()
	spec := PathSpec{Transport: "generation-test", Address: "peer", Opts: map[string]string{"name": "leaf"}}
	var attempts atomic.Int32
	var peersMu sync.Mutex
	var peers []net.Conn
	defer func() {
		peersMu.Lock()
		defer peersMu.Unlock()
		for _, peer := range peers {
			_ = peer.Close()
		}
	}()
	add := func(context.Context, PathSpec) (uint32, error) {
		attempt := attempts.Add(1)
		local, peer := net.Pipe()
		peersMu.Lock()
		peers = append(peers, peer)
		peersMu.Unlock()
		id, err := e.AttachPath(tcp.Wrap(local), spec)
		if err != nil {
			_ = local.Close()
			return 0, err
		}
		if attempt == 1 {
			if err := e.ForceKillPathForTest(id); err != nil {
				return 0, err
			}
		}
		return id, nil
	}
	supervisor := newPathRecoverySupervisor(e, nil, add, []PathSpec{spec}, nil, RetryPolicy{})
	if supervisor == nil {
		t.Fatal("recovery supervisor was not created")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if attempts.Load() >= 2 && len(e.Paths()) == 1 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("generation reconciliation lost replacement death: attempts=%d paths=%v", attempts.Load(), e.Paths())
}

func TestCleanRemovalCancelsInFlightRecoveryWithoutResurrection(t *testing.T) {
	e := engine.New(engine.SideClient, engine.NewClientFlowID(), engine.Limits{}.Clamp())
	defer e.Close()
	attachPipe := func(spec PathSpec) (uint32, net.Conn) {
		t.Helper()
		local, peer := net.Pipe()
		id, err := e.AttachPath(tcp.Wrap(local), spec)
		if err != nil {
			_ = local.Close()
			_ = peer.Close()
			t.Fatal(err)
		}
		return id, peer
	}
	leaf := PathSpec{Transport: "cancel-test", Address: "peer", Opts: map[string]string{"name": "leaf"}}
	guard := PathSpec{Transport: "cancel-test", Address: "guard", Opts: map[string]string{"name": "guard"}}
	leafID, leafPeer := attachPipe(leaf)
	defer leafPeer.Close()
	_, guardPeer := attachPipe(guard)
	defer guardPeer.Close()

	started := make(chan struct{})
	canceled := make(chan struct{})
	var startedOnce sync.Once
	var canceledOnce sync.Once
	var attempts atomic.Int32
	add := func(ctx context.Context, _ PathSpec) (uint32, error) {
		attempts.Add(1)
		startedOnce.Do(func() { close(started) })
		<-ctx.Done()
		canceledOnce.Do(func() { close(canceled) })
		return 0, ctx.Err()
	}
	if supervisor := newPathRecoverySupervisor(e, nil, add, []PathSpec{leaf}, nil, RetryPolicy{}); supervisor == nil {
		t.Fatal("recovery supervisor was not created")
	}
	if err := e.ForceKillPathForTest(leafID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("recovery attempt did not start")
	}

	manualID, manualPeer := attachPipe(leaf)
	defer manualPeer.Close()
	if err := e.RemovePath(manualID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("clean removal did not cancel in-flight recovery")
	}
	time.Sleep(3 * recoveryInitialBackoff)
	if got := attempts.Load(); got != 1 {
		t.Fatalf("cleanly removed leaf was redialed %d times", got)
	}
	for _, path := range e.Paths() {
		if pathSpecName(path.Spec) == "leaf" {
			t.Fatalf("cleanly removed leaf was resurrected: %v", e.Paths())
		}
	}
}

func TestCleanPathRemovalDoesNotTriggerAutomaticRedial(t *testing.T) {
	listener, err := ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan Conn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, acceptErr := listener.Accept(ctx)
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	runtime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int32
	if err := runtime.RegisterStreamFactory("clean-stream", StreamFactory{
		Carrier: CarrierTCP,
		Dial: func(ctx context.Context, address string) (net.Conn, error) {
			attempts.Add(1)
			var dialer net.Dialer
			return dialer.DialContext(ctx, "tcp", address)
		},
	}); err != nil {
		t.Fatal(err)
	}
	spec := func(name string) PathSpec {
		return PathSpec{Transport: "clean-stream", Address: listener.Addr().String(), Opts: map[string]string{"name": name}}
	}
	conn, err := runtime.Dial(context.Background(), SessionConfig{Root: Selector("root", []Target{
		Path("a", spec("a")), Path("b", spec("b")),
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	server := <-accepted
	defer server.Close()
	if !waitForNPaths(t, conn, server, "clean-stream", listener.Addr().String(), 2, 5*time.Second) {
		t.Fatal("initial paths did not attach")
	}
	client := conn.(*engineBackedConn)
	var removeID uint32
	for _, path := range client.Paths() {
		if !path.Active {
			removeID = path.ID
			break
		}
	}
	if removeID == 0 {
		t.Fatal("no removable secondary path")
	}
	if err := client.RemovePath(removeID); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	if got := attempts.Load(); got != 2 {
		t.Fatalf("clean removal triggered redial: attempts=%d", got)
	}
	if got := len(client.Paths()); got != 1 {
		t.Fatalf("cleanly removed path reappeared: %v", client.Paths())
	}
}

func TestRuntimeAutomaticallyRedialsDeadGenericPacketLeaf(t *testing.T) {
	listener, err := ListenUDPFlowPacket("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan PacketConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := listener.AcceptPacket(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	runtime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int32
	if err := runtime.RegisterPacketFactory("recover-packet", PacketFactory{
		Carrier: CarrierUDP,
		Dial: func(context.Context, string) (net.PacketConn, error) {
			attempt := attempts.Add(1)
			if attempt == 2 || attempt == 3 {
				return nil, &net.DNSError{Err: "injected packet recovery dial failure", IsTemporary: true}
			}
			return net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		},
	}); err != nil {
		t.Fatal(err)
	}
	spec := PathSpec{Transport: "recover-packet", Address: listener.Addr().String(), Opts: map[string]string{"name": "b"}}
	clientConn, err := runtime.DialPacket(context.Background(), SessionConfig{Root: Selector("root", []Target{Path("b", spec)})})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	var serverConn PacketConn
	select {
	case serverConn = <-accepted:
	case err := <-acceptErr:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("packet accept timed out")
	}
	defer serverConn.Close()

	client := clientConn.(*enginePacketConn)
	server := serverConn.(*enginePacketConn)
	deadID := client.Paths()[0].ID
	if err := client.e.ForceKillPathForTest(deadID); err != nil {
		t.Fatal(err)
	}
	replacement, serverReplacement := waitForPacketReplacement(t, client, server, deadID, 5*time.Second)
	if attempts.Load() < 4 {
		t.Fatalf("packet recovery did not retry dial failures: attempts=%d", attempts.Load())
	}
	assertBidirectionalPacketPayload(t, client, server, "first-packet-replacement")
	assertPathCarriedData(t, client.Paths(), replacement)
	assertPathCarriedData(t, server.Paths(), serverReplacement)
	if err := client.e.ForceKillPathForTest(replacement); err != nil {
		t.Fatal(err)
	}
	second, secondServer := waitForPacketReplacement(t, client, server, replacement, 5*time.Second)
	if attempts.Load() < 5 {
		t.Fatalf("packet immediate second death did not redial: attempts=%d", attempts.Load())
	}
	assertBidirectionalPacketPayload(t, client, server, "second-packet-replacement")
	assertPathCarriedData(t, client.Paths(), second)
	assertPathCarriedData(t, server.Paths(), secondServer)
	waitForMigrationCounts(t, client.MigrationCount, server.MigrationCount, 2)
	if status := client.Status(); status.Protocol != SessionProtocolFramedPacketV3 {
		t.Fatalf("packet protocol=%q", status.Protocol)
	}
}

func waitForStreamReplacement(t *testing.T, client, server *engineBackedConn, oldID uint32, timeout time.Duration) (uint32, uint32) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		clientPaths := client.Paths()
		serverPaths := server.Paths()
		if len(clientPaths) == 1 && clientPaths[0].ID != oldID && len(serverPaths) == 1 {
			return clientPaths[0].ID, serverPaths[0].ID
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("stream replacement did not commit: old=%d client=%v server=%v", oldID, client.Paths(), server.Paths())
	return 0, 0
}

func waitForPacketReplacement(t *testing.T, client, server *enginePacketConn, oldID uint32, timeout time.Duration) (uint32, uint32) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		clientPaths := client.Paths()
		serverPaths := server.Paths()
		if len(clientPaths) == 1 && clientPaths[0].ID != oldID && len(serverPaths) == 1 {
			return clientPaths[0].ID, serverPaths[0].ID
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("packet replacement did not commit: old=%d client=%v server=%v", oldID, client.Paths(), server.Paths())
	return 0, 0
}

func assertBidirectionalStreamPayload(t *testing.T, client, server net.Conn, label string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	_ = client.SetDeadline(deadline)
	_ = server.SetDeadline(deadline)
	defer client.SetDeadline(time.Time{})
	defer server.SetDeadline(time.Time{})
	clientPayload := []byte(label + "-client")
	if _, err := client.Write(clientPayload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(clientPayload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(clientPayload) {
		t.Fatalf("client payload=%q want %q", got, clientPayload)
	}
	serverPayload := []byte(label + "-server")
	if _, err := server.Write(serverPayload); err != nil {
		t.Fatal(err)
	}
	got = make([]byte, len(serverPayload))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(serverPayload) {
		t.Fatalf("server payload=%q want %q", got, serverPayload)
	}
}

func assertBidirectionalPacketPayload(t *testing.T, client, server net.PacketConn, label string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	_ = client.SetDeadline(deadline)
	_ = server.SetDeadline(deadline)
	defer client.SetDeadline(time.Time{})
	defer server.SetDeadline(time.Time{})
	clientPayload := []byte(label + "-client")
	if _, err := client.WriteTo(clientPayload, nil); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(clientPayload))
	n, _, err := server.ReadFrom(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(got[:n]) != string(clientPayload) {
		t.Fatalf("client packet=%q want %q", got[:n], clientPayload)
	}
	serverPayload := []byte(label + "-server")
	if _, err := server.WriteTo(serverPayload, nil); err != nil {
		t.Fatal(err)
	}
	got = make([]byte, len(serverPayload))
	n, _, err = client.ReadFrom(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(got[:n]) != string(serverPayload) {
		t.Fatalf("server packet=%q want %q", got[:n], serverPayload)
	}
}

func assertPathCarriedData(t *testing.T, paths []PathInfo, id uint32) {
	t.Helper()
	for _, path := range paths {
		if path.ID == id {
			if path.DataWrites == 0 {
				t.Fatalf("replacement path %d carried no DATA: %v", id, paths)
			}
			return
		}
	}
	t.Fatalf("replacement path %d disappeared: %v", id, paths)
}

func waitForMigrationCounts(t *testing.T, client, server func() uint64, want uint64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if client() == want && server() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("migration counts client/server=%d/%d, want %d/%d", client(), server(), want, want)
}
