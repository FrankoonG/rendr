package quic

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	qg "github.com/FrankoonG/quic-go"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/transport"
)

type pathAcceptResult struct {
	path transport.PathConn
	err  error
}

func TestPathListenerSessionKinds(t *testing.T) {
	if got := new(Listener).SessionKind(); got != transport.PathSessionAny {
		t.Fatalf("stream SessionKind = %v, want %v", got, transport.PathSessionAny)
	}
	if got := new(DatagramListener).SessionKind(); got != transport.PathSessionPacket {
		t.Fatalf("DATAGRAM SessionKind = %v, want %v", got, transport.PathSessionPacket)
	}
}

func TestListenerAcceptPathDelegatesToStreamAccept(t *testing.T) {
	serverTLS, clientTLS, err := devTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := Listen("127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan pathAcceptResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		path, err := listener.AcceptPath(ctx)
		accepted <- pathAcceptResult{path: path, err: err}
	}()

	client, err := (&Transport{ClientTLS: clientTLS}).DialPath(context.Background(), transport.PathSpec{
		Address: listener.Addr().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	want := []byte("stream path listener")
	if _, err := client.Write(want); err != nil {
		t.Fatal(err)
	}
	result := awaitPathAccept(t, accepted)
	t.Cleanup(func() { _ = result.path.Close() })
	assertQUICListenerClaim(t, result.path, leafmobility.SessionAny)

	got := make([]byte, len(want))
	n, err := result.path.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:n], want) {
		t.Fatalf("accepted payload = %q, want %q", got[:n], want)
	}
}

func TestDatagramListenerAcceptPathDelegatesToDatagramAccept(t *testing.T) {
	serverTLS, clientTLS, err := devTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := ListenDatagram("127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan pathAcceptResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		path, err := listener.AcceptPath(ctx)
		accepted <- pathAcceptResult{path: path, err: err}
	}()

	client, err := (&Transport{ClientTLS: clientTLS}).DialPath(context.Background(), transport.PathSpec{
		Address: listener.Addr().String(),
		Opts:    map[string]string{"mode": "datagram"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	want := []byte("datagram path listener")
	if _, err := client.Write(want); err != nil {
		t.Fatal(err)
	}
	result := awaitPathAccept(t, accepted)
	t.Cleanup(func() { _ = result.path.Close() })
	assertQUICListenerClaim(t, result.path, leafmobility.SessionPacket)

	got := make([]byte, len(want))
	n, err := result.path.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:n], want) {
		t.Fatalf("accepted payload = %q, want %q", got[:n], want)
	}
	if _, ok := result.path.(transport.OwnedFrameReader); !ok {
		t.Fatal("DATAGRAM AcceptPath returned a stream path")
	}
}

func TestOwnedQUICPathsExposeSocketAccelerationEvidence(t *testing.T) {
	serverTLS, clientTLS, err := devTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := Listen("127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan pathAcceptResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		path, err := listener.AcceptPath(ctx)
		accepted <- pathAcceptResult{path: path, err: err}
	}()
	client, err := (&Transport{ClientTLS: clientTLS}).DialPath(context.Background(), transport.PathSpec{
		Address: listener.Addr().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if _, err := client.Write([]byte("acceleration status")); err != nil {
		t.Fatal(err)
	}
	server := awaitPathAccept(t, accepted).path
	t.Cleanup(func() { _ = server.Close() })
	assertPathRead(t, server, []byte("acceleration status"))

	for name, value := range map[string]any{
		"client":   client,
		"server":   server,
		"listener": listener,
	} {
		observer, ok := value.(transport.DatagramAccelerationObserver)
		if !ok {
			t.Fatalf("%s %T does not expose acceleration status", name, value)
		}
		status := observer.DatagramAccelerationStatus()
		if status.Mode == transport.DatagramAccelerationUnknown || status.Cause == "" || status.ProbeGeneration == 0 || status.ProbedAt.IsZero() {
			t.Fatalf("%s status=%+v", name, status)
		}
	}
}

func TestDialPathCloseReleasesOwnedUDPSocket(t *testing.T) {
	serverTLS, clientTLS, err := devTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := Listen("127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan pathAcceptResult, 1)
	go func() {
		path, err := listener.AcceptPath(context.Background())
		accepted <- pathAcceptResult{path: path, err: err}
	}()
	client, err := (&Transport{ClientTLS: clientTLS}).DialPath(context.Background(), transport.PathSpec{Address: listener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("admit")); err != nil {
		t.Fatal(err)
	}
	server := awaitPathAccept(t, accepted).path
	defer server.Close()
	assertPathRead(t, server, []byte("admit"))
	local, err := net.ResolveUDPAddr("udp", client.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		rebound, bindErr := net.ListenUDP("udp", local)
		if bindErr == nil {
			_ = rebound.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("client UDP socket %s was not released: %v", local, bindErr)
		}
		time.Sleep(time.Millisecond)
	}
}

func assertQUICListenerClaim(t *testing.T, path transport.PathConn, session leafmobility.Session) {
	t.Helper()
	provider, ok := path.(leafmobility.Provider)
	if !ok || provider.LeafMobilityClaim() == nil {
		t.Fatal("adapter listener path has no sealed ownership claim")
	}
	facts := provider.LeafMobilityClaim().Snapshot()
	if facts.Kind != leafmobility.KindQUIC || facts.Role != leafmobility.RoleAcceptor ||
		facts.Scope != leafmobility.ScopeEndpoint || facts.Session != session ||
		facts.Operations != leafmobility.OperationQUICCIDRebind || facts.Generation == 0 {
		t.Fatalf("adapter listener QUIC facts=%+v", facts)
	}
}

func TestStreamListenerClosePreservesAcceptedPath(t *testing.T) {
	serverTLS, clientTLS, err := devTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := Listen("127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan pathAcceptResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		path, err := listener.AcceptPath(ctx)
		accepted <- pathAcceptResult{path: path, err: err}
	}()

	client, err := (&Transport{ClientTLS: clientTLS}).DialPath(context.Background(), transport.PathSpec{
		Address: listener.Addr().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if _, err := client.Write([]byte("admit stream path")); err != nil {
		t.Fatal(err)
	}
	server := awaitPathAccept(t, accepted).path
	t.Cleanup(func() { _ = server.Close() })
	assertPathRead(t, server, []byte("admit stream path"))

	if err := listener.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	assertTransportRetained(t, listener)
	assertAdmissionClosed(t, listener)
	assertPathTransfer(t, client, server, []byte("stream survives listener close"))
	assertPathTransfer(t, server, client, []byte("stream reply survives listener close"))

	if err := server.Close(); err != nil {
		t.Fatalf("accepted path Close: %v", err)
	}
	awaitTransportRelease(t, listener)
	if err := server.Close(); err != nil {
		t.Fatalf("second accepted path Close: %v", err)
	}
}

func TestDatagramListenerClosePreservesAcceptedPath(t *testing.T) {
	serverTLS, clientTLS, err := devTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := ListenDatagram("127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan pathAcceptResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		path, err := listener.AcceptPath(ctx)
		accepted <- pathAcceptResult{path: path, err: err}
	}()

	client, err := (&Transport{ClientTLS: clientTLS}).DialPath(context.Background(), transport.PathSpec{
		Address: listener.Addr().String(),
		Opts:    map[string]string{"mode": "datagram"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server := awaitPathAccept(t, accepted).path
	t.Cleanup(func() { _ = server.Close() })

	if err := listener.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	assertTransportRetained(t, listener.listener)
	assertAdmissionClosed(t, listener)
	assertPathTransfer(t, client, server, []byte("datagram survives listener close"))
	assertPathTransfer(t, server, client, []byte("datagram reply survives listener close"))

	if err := client.Close(); err != nil {
		t.Fatalf("client path Close: %v", err)
	}
	awaitTransportRelease(t, listener.listener)
	if err := server.Close(); err != nil {
		t.Fatalf("accepted path Close after terminal death: %v", err)
	}
}

func TestDatagramListenerCloseUnblocksAccept(t *testing.T) {
	serverTLS, _, err := devTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := ListenDatagram("127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	if listener.Addr() == nil {
		t.Fatal("Addr returned nil")
	}
	if _, exposesStreamAccept := any(listener).(interface {
		Accept(context.Context) (*PathConn, error)
	}); exposesStreamAccept {
		t.Fatal("DatagramListener unexpectedly exposes stream Accept")
	}

	accepted := make(chan pathAcceptResult, 1)
	go func() {
		path, err := listener.AcceptPath(context.Background())
		accepted <- pathAcceptResult{path: path, err: err}
	}()
	if err := listener.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case result := <-accepted:
		if result.path != nil {
			t.Fatalf("AcceptPath returned %T after listener close", result.path)
		}
		if result.err == nil {
			t.Fatal("AcceptPath returned nil error after listener close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not unblock AcceptPath")
	}
}

func TestStreamListenerRepeatedAcceptTimeoutsDoNotDelayClose(t *testing.T) {
	serverTLS, _, err := devTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := Listen("127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}

	for iteration := 0; iteration < 200; iteration++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		path, acceptErr := listener.AcceptPath(ctx)
		cancel()
		if path != nil {
			_ = path.Close()
			t.Fatalf("iteration %d returned an unexpected path", iteration)
		}
		if !errors.Is(acceptErr, context.DeadlineExceeded) {
			t.Fatalf("iteration %d error = %v, want context deadline", iteration, acceptErr)
		}
	}

	closed := make(chan error, 1)
	go func() { closed <- listener.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close exceeded the Runtime listener callback budget after repeated AcceptPath timeouts")
	}
	awaitTransportRelease(t, listener)
	listener.ownershipMu.Lock()
	retained := listener.retained
	listener.ownershipMu.Unlock()
	if retained != 0 {
		t.Fatalf("listener retained %d timed-out AcceptPath leases", retained)
	}
}

func TestStreamListenerPartialConnectionTimeoutDoesNotPoisonAccept(t *testing.T) {
	serverTLS, clientTLS, err := devTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := Listen("127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	idle, err := qg.DialAddr(context.Background(), listener.Addr().String(), clientTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = idle.CloseWithError(0, "test complete") })

	acceptCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	path, err := listener.AcceptPath(acceptCtx)
	cancel()
	if path != nil {
		_ = path.Close()
		t.Fatal("idle QUIC connection unexpectedly produced a stream path")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("AcceptPath error = %v, want context deadline", err)
	}

	accepted := make(chan pathAcceptResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		path, err := listener.AcceptPath(ctx)
		accepted <- pathAcceptResult{path: path, err: err}
	}()
	client, err := (&Transport{ClientTLS: clientTLS}).DialPath(context.Background(), transport.PathSpec{
		Address: listener.Addr().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if _, err := client.Write([]byte("after partial timeout")); err != nil {
		t.Fatal(err)
	}
	result := awaitPathAccept(t, accepted)
	t.Cleanup(func() { _ = result.path.Close() })
}

func awaitPathAccept(t *testing.T, accepted <-chan pathAcceptResult) pathAcceptResult {
	t.Helper()
	select {
	case result := <-accepted:
		if result.err != nil {
			t.Fatalf("AcceptPath: %v", result.err)
		}
		if result.path == nil {
			t.Fatal("AcceptPath returned a nil path")
		}
		return result
	case <-time.After(10 * time.Second):
		t.Fatal("AcceptPath timed out")
		return pathAcceptResult{}
	}
}

func assertPathTransfer(t *testing.T, writer, reader transport.PathConn, payload []byte) {
	t.Helper()
	if _, err := writer.Write(payload); err != nil {
		t.Fatalf("Write(%q): %v", payload, err)
	}
	assertPathRead(t, reader, payload)
}

func assertPathRead(t *testing.T, reader transport.PathConn, want []byte) {
	t.Helper()
	got := make([]byte, len(want))
	n, err := reader.Read(got)
	if err != nil {
		t.Fatalf("Read(%q): %v", want, err)
	}
	if !bytes.Equal(got[:n], want) {
		t.Fatalf("Read = %q, want %q", got[:n], want)
	}
}

func assertAdmissionClosed(t *testing.T, listener transport.PathListener) {
	t.Helper()
	path, err := listener.AcceptPath(context.Background())
	if path != nil {
		_ = path.Close()
		t.Fatalf("AcceptPath after Close returned %T", path)
	}
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("AcceptPath after Close error = %v, want net.ErrClosed", err)
	}
}

func assertTransportRetained(t *testing.T, listener *Listener) {
	t.Helper()
	select {
	case <-listener.transportDone:
		t.Fatal("listener transport closed while an accepted path was active")
	default:
	}
}

func awaitTransportRelease(t *testing.T, listener *Listener) {
	t.Helper()
	select {
	case <-listener.transportDone:
	case <-time.After(5 * time.Second):
		t.Fatal("listener transport was not released after its accepted paths ended")
	}
	if listener.tr != nil {
		t.Fatal("listener retained its closed transport")
	}
	rebound, err := net.ListenPacket("udp", listener.Addr().String())
	if err != nil {
		t.Fatalf("listener UDP address was not released: %v", err)
	}
	_ = rebound.Close()
}
