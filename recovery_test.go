package rendr

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
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
			if attempt == 3 || attempt == 4 {
				return nil, &net.DNSError{Err: "injected recovery dial failure", IsTemporary: true}
			}
			var dialer net.Dialer
			return dialer.DialContext(ctx, "tcp", address)
		},
	}); err != nil {
		t.Fatal(err)
	}
	spec := func(name string) PathSpec {
		return PathSpec{Transport: "recover-stream", Address: listener.Addr().String(), Opts: map[string]string{"name": name}}
	}
	clientConn, err := runtime.Dial(context.Background(), SessionConfig{Root: Selector("root", []Target{
		Path("a", spec("a")),
		Path("b", spec("b")),
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	var server Conn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("accept timed out")
	}
	defer server.Close()
	if !waitForNPaths(t, clientConn, server, "recover-stream", listener.Addr().String(), 2, 5*time.Second) {
		t.Fatalf("initial paths client=%v server=%v", clientConn.Paths(), server.Paths())
	}

	client := clientConn.(*engineBackedConn)
	var deadID uint32
	for _, path := range client.Paths() {
		if pathSpecName(path.Spec) == "b" {
			deadID = path.ID
			break
		}
	}
	if deadID == 0 {
		t.Fatal("leaf b was not attached")
	}
	if err := client.e.ForceKillPathForTest(deadID); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	var replacement uint32
	for time.Now().Before(deadline) {
		for _, path := range client.Paths() {
			if pathSpecName(path.Spec) == "b" && path.ID != deadID {
				replacement = path.ID
				break
			}
		}
		if replacement != 0 && len(client.Paths()) == 2 && len(server.Paths()) == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if replacement == 0 {
		t.Fatalf("leaf b was not automatically restored; attempts=%d client=%v server=%v", attempts.Load(), client.Paths(), server.Paths())
	}
	if attempts.Load() < 5 {
		t.Fatalf("recovery did not retry injected dial failures: attempts=%d", attempts.Load())
	}

	payload := []byte("automatic-redial")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload=%q want %q", got, payload)
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
			if attempt == 3 || attempt == 4 {
				return nil, &net.DNSError{Err: "injected packet recovery dial failure", IsTemporary: true}
			}
			return net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		},
	}); err != nil {
		t.Fatal(err)
	}
	spec := func(name string) PathSpec {
		return PathSpec{Transport: "recover-packet", Address: listener.Addr().String(), Opts: map[string]string{"name": name}}
	}
	clientConn, err := runtime.DialPacket(context.Background(), SessionConfig{Root: Selector("root", []Target{
		Path("a", spec("a")),
		Path("b", spec("b")),
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	var server PacketConn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("packet accept timed out")
	}
	defer server.Close()
	waitPacketPaths := func(want int, deadline time.Time) bool {
		for time.Now().Before(deadline) {
			if len(clientConn.Paths()) == want && len(server.Paths()) == want {
				return true
			}
			time.Sleep(10 * time.Millisecond)
		}
		return false
	}
	if !waitPacketPaths(2, time.Now().Add(5*time.Second)) {
		t.Fatalf("initial packet paths client=%v server=%v", clientConn.Paths(), server.Paths())
	}

	client := clientConn.(*enginePacketConn)
	var deadID uint32
	for _, path := range client.Paths() {
		if pathSpecName(path.Spec) == "b" {
			deadID = path.ID
			break
		}
	}
	if deadID == 0 {
		t.Fatal("packet leaf b was not attached")
	}
	if err := client.e.ForceKillPathForTest(deadID); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	var replacement uint32
	for time.Now().Before(deadline) {
		for _, path := range client.Paths() {
			if pathSpecName(path.Spec) == "b" && path.ID != deadID {
				replacement = path.ID
				break
			}
		}
		if replacement != 0 && len(client.Paths()) == 2 && len(server.Paths()) == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if replacement == 0 || attempts.Load() < 5 {
		t.Fatalf("packet leaf was not restored after retries: replacement=%d attempts=%d client=%v server=%v", replacement, attempts.Load(), client.Paths(), server.Paths())
	}

	payload := []byte("automatic-packet-redial")
	if _, err := client.WriteTo(payload, nil); err != nil {
		t.Fatal(err)
	}
	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	n, _, err := server.ReadFrom(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(got[:n]) != string(payload) {
		t.Fatalf("packet payload=%q want %q", got[:n], payload)
	}
	if status := client.Status(); status.Protocol != SessionProtocolFramedPacketV3 {
		t.Fatalf("packet protocol=%q", status.Protocol)
	}
}
