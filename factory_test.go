package rendr

import (
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/transport"
)

// TestM9X5StreamPathFactoryRoundTrip drives an internal session dialer through
// an AddStreamPathFactory-registered transport: no global registry
// involvement, no tcp/udpflow code path. The factory hands rendr a
// net.Conn produced by net.Pipe()-style plumbing into a real rendr
// listener on the loopback. Asserts:
//   - Dial succeeds via factory-supplied connection
//   - subsequent Write/Read round-trips through rendr framing
//   - the factory was invoked exactly once (single path)
//   - flow_id symmetry (C1) still holds because the underlying
//     listener is a real Runtime-owned session listener
func TestM9X5StreamPathFactoryRoundTrip(t *testing.T) {
	ln, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan Conn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		accepted <- c
	}()

	var dials atomic.Int32
	factory := func(ctx context.Context, addr string) (net.Conn, error) {
		dials.Add(1)
		return net.Dial("tcp", addr)
	}

	d := &sessionDialer{Root: selectorRoot(

		[]PathSpec{{Transport: "factory-tcp", Address: ln.Addr().String()}})}

	if err := d.AddStreamPathFactory("factory-tcp", factory); err != nil {
		t.Fatal(err)
	}

	client, err := d.Dial(context.Background())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	want := []byte("hello via path-factory")
	if _, err := client.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("payload: got %q want %q", got, want)
	}
	if dials.Load() != 1 {
		t.Fatalf("factory invoked %d times, want 1", dials.Load())
	}
	streamMobility := client.Status().Paths[0].Mobility
	if streamMobility.ID != MobilityRedialAttach || streamMobility.Reason != MobilityReasonEndpointNotOwned || streamMobility.EndpointGeneration != 0 {
		t.Fatalf("generic StreamFactory mobility=%+v", streamMobility)
	}

	if cli, ok := client.(Conn); ok {
		if srv, ok := server.(Conn); ok {
			if cli.FlowID() != srv.FlowID() {
				t.Fatalf("flow_id mismatch through factory wrap")
			}
		}
	}
}

// TestM9X5StreamFactoryFallback keeps its historical test ID while verifying
// the v1 Runtime boundary: unknown IDs fail closed and immutable built-ins are
// available without a process-global registry.
func TestM9X5StreamFactoryFallback(t *testing.T) {
	// Part 1: unknown transport name returns an error and does NOT
	// touch any listener. Use a closed listener to source an address
	// for shape; never dial against it.
	probe, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	probeAddr := probe.Addr().String()
	probe.Close()
	d := &sessionDialer{Root: selectorRoot([]PathSpec{{Transport: "no-such-transport", Address: probeAddr}})}
	if _, err := d.Dial(context.Background()); err == nil {
		t.Fatal("expected dial error for unknown transport")
	}

	// Part 2: "tcp" is an immutable built-in framed factory. Wait for the accept-side
	// HELLO to fully complete before closing the listener to avoid
	// racing with listener.handleHello on teardown.
	ln, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan Conn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		accepted <- c
	}()

	d2 := &sessionDialer{Root: selectorRoot([]PathSpec{{Transport: "tcp", Address: ln.Addr().String()}})}
	c, err := d2.Dial(context.Background())
	if err != nil {
		t.Fatalf("Dial via built-in tcp: %v", err)
	}
	srv := <-accepted
	c.Close()
	srv.Close()
}

// TestM9X5AddStreamFactoryValidation covers the API guard rails:
// empty name, nil factory, duplicate registration, name conflict
// across stream/packet maps.
func TestM9X5AddStreamFactoryValidation(t *testing.T) {
	d := &sessionDialer{}
	if err := d.AddStreamPathFactory("", func(context.Context, string) (net.Conn, error) { return nil, nil }); err == nil {
		t.Fatal("empty name should error")
	}
	if err := d.AddStreamPathFactory("ok", nil); err == nil {
		t.Fatal("nil factory should error")
	}

	noop := func(context.Context, string) (net.Conn, error) { return nil, errors.New("noop") }
	if err := d.AddStreamPathFactory("dup", noop); err != nil {
		t.Fatal(err)
	}
	if err := d.AddStreamPathFactory("dup", noop); err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Fatalf("duplicate stream factory: %v", err)
	}
}

// TestM9X5PacketPathFactoryRoundTrip drives a packet-mode session dialer
// entirely through an AddPacketPathFactory-registered source. The
// factory returns a *net.UDPConn produced by net.ListenUDP (which
// satisfies net.PacketConn). rendr's udpflow.WrapFromSpec then
// resolves spec.Address as the peer for WriteTo and generates a
// random flow_id. Asserts:
//   - DialPacket succeeds via factory-supplied PacketConn
//   - WriteTo / ReadFrom round-trip with rendr packet-mode framing
//   - factory is invoked exactly once (single path)
//   - flow_id symmetry between client and server
func TestM9X5PacketPathFactoryRoundTrip(t *testing.T) {
	ln, err := listenRuntimeUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan PacketConn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := ln.AcceptPacket(ctx)
		if err != nil {
			return
		}
		accepted <- c
	}()

	var dials atomic.Int32
	factory := func(ctx context.Context, addr string) (net.PacketConn, error) {
		dials.Add(1)
		return net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	}

	d := &sessionDialer{Root: selectorRoot(

		[]PathSpec{{Transport: "factory-udp", Address: ln.Addr().String()}})}

	if err := d.AddPacketPathFactory("factory-udp", factory); err != nil {
		t.Fatal(err)
	}

	client, err := d.DialPacket(context.Background())
	if err != nil {
		t.Fatalf("DialPacket: %v", err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	want := []byte("packet-factory round trip")
	if _, err := client.WriteTo(want, nil); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _, err := server.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != string(want) {
		t.Fatalf("payload: got %q want %q", buf[:n], want)
	}
	if dials.Load() != 1 {
		t.Fatalf("factory invoked %d times, want 1", dials.Load())
	}
	if client.(PacketConn).FlowID() != server.(PacketConn).FlowID() {
		t.Fatalf("flow_id mismatch through packet factory wrap")
	}
	packetMobility := client.Status().Paths[0].Mobility
	if packetMobility.ID != MobilityRedialAttach || packetMobility.Reason != MobilityReasonEndpointNotOwned || packetMobility.EndpointGeneration != 0 {
		t.Fatalf("generic PacketFactory mobility=%+v", packetMobility)
	}
}

// TestM9X5AddPacketFactoryValidation: API guard rails for packet
// factories — empty name, nil factory, duplicate registration,
// shadow conflict with stream factory of the same name.
func TestM9X5AddPacketFactoryValidation(t *testing.T) {
	d := &sessionDialer{}
	dummy := func(context.Context, string) (net.PacketConn, error) { return nil, nil }
	if err := d.AddPacketPathFactory("", dummy); err == nil {
		t.Fatal("empty name should error")
	}
	if err := d.AddPacketPathFactory("ok", nil); err == nil {
		t.Fatal("nil factory should error")
	}
	if err := d.AddPacketPathFactory("p", dummy); err != nil {
		t.Fatal(err)
	}
	if err := d.AddPacketPathFactory("p", dummy); err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Fatalf("duplicate packet factory: %v", err)
	}
	// Cross-map shadow conflict: registering stream factory with same name.
	streamFn := func(context.Context, string) (net.Conn, error) { return nil, nil }
	if err := d.AddStreamPathFactory("p", streamFn); err == nil || !strings.Contains(err.Error(), "packet factory") {
		t.Fatalf("expected stream-shadow-packet error, got %v", err)
	}
}

func TestStreamFactoryResolverAddPathUsesSessionSnapshot(t *testing.T) {
	ln, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := startFactoryStreamAccept(ln)

	const transportName = "snapshot-stream"
	var originalCalls, mutatedCalls, lateCalls atomic.Int32
	original := func(ctx context.Context, addr string) (net.Conn, error) {
		originalCalls.Add(1)
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	d := &sessionDialer{Root: selectorRoot([]PathSpec{
		{Transport: transportName, Address: ln.Addr().String()},
		{Transport: transportName, Address: ln.Addr().String()},
	})}
	if err := d.AddStreamPathFactory(transportName, original); err != nil {
		t.Fatal(err)
	}
	client, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := awaitFactoryAccept(t, accepted)
	defer server.Close()
	waitFactoryPathCount(t, client, server, 2)
	admin := client.(testConnectionControl)
	removeID := inactiveFactoryPathID(t, client.Paths())
	if err := admin.RemovePath(removeID); err != nil {
		t.Fatalf("RemovePath before snapshot AddPath: %v", err)
	}
	waitFactoryClientPathCount(t, client, 1)

	// Replace the original session dialer's map after Dial. The live session must not
	// share this map or consult it again.
	d.streamFactories = map[string]streamPathFactory{
		transportName: func(context.Context, string) (net.Conn, error) {
			mutatedCalls.Add(1)
			return nil, errors.New("mutated stream factory must not run")
		},
	}
	if err := d.AddStreamPathFactory("late-stream", func(context.Context, string) (net.Conn, error) {
		lateCalls.Add(1)
		return nil, errors.New("late stream factory must not run")
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := admin.AddPath(PathSpec{Transport: transportName, Address: ln.Addr().String()}); err != nil {
		t.Fatalf("AddPath through captured stream factory: %v", err)
	}
	waitFactoryPathCount(t, client, server, 2)
	if got := originalCalls.Load(); got != 3 {
		t.Fatalf("original stream factory calls=%d, want 3", got)
	}
	if got := mutatedCalls.Load(); got != 0 {
		t.Fatalf("mutated stream factory calls=%d, want 0", got)
	}

	_, err = admin.AddPath(PathSpec{Transport: "late-stream", Address: ln.Addr().String()})
	if err == nil || !strings.Contains(err.Error(), "path is not present in the frozen session graph") {
		t.Fatalf("late stream factory error=%v, want frozen graph rejection", err)
	}
	if got := lateCalls.Load(); got != 0 {
		t.Fatalf("late stream factory calls=%d, want 0", got)
	}
	assertFactoryStreamRoundTrip(t, client, server, "stream snapshot recovery")
}

func TestPacketFactoryResolverAddPathUsesSessionSnapshot(t *testing.T) {
	ln, err := listenRuntimeUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := startFactoryPacketAccept(ln)

	const transportName = "snapshot-packet"
	var originalCalls, mutatedCalls, lateCalls atomic.Int32
	original := func(context.Context, string) (net.PacketConn, error) {
		originalCalls.Add(1)
		return net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	}
	d := &sessionDialer{Root: selectorRoot([]PathSpec{
		{Transport: transportName, Address: ln.Addr().String()},
		{Transport: transportName, Address: ln.Addr().String()},
	})}
	if err := d.AddPacketPathFactory(transportName, original); err != nil {
		t.Fatal(err)
	}
	client, err := d.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := awaitFactoryAccept(t, accepted)
	defer server.Close()
	waitFactoryPathCount(t, client, server, 2)
	admin := client.(testPacketConnectionControl)
	removeID := inactiveFactoryPathID(t, client.Paths())
	if err := admin.RemovePath(removeID); err != nil {
		t.Fatalf("RemovePath before snapshot AddPath: %v", err)
	}
	waitFactoryClientPathCount(t, client, 1)

	d.packetFactories = map[string]packetPathFactory{
		transportName: func(context.Context, string) (net.PacketConn, error) {
			mutatedCalls.Add(1)
			return nil, errors.New("mutated packet factory must not run")
		},
	}
	if err := d.AddPacketPathFactory("late-packet", func(context.Context, string) (net.PacketConn, error) {
		lateCalls.Add(1)
		return nil, errors.New("late packet factory must not run")
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := admin.AddPath(PathSpec{Transport: transportName, Address: ln.Addr().String()}); err != nil {
		t.Fatalf("AddPath through captured packet factory: %v", err)
	}
	waitFactoryPathCount(t, client, server, 2)
	if got := originalCalls.Load(); got != 3 {
		t.Fatalf("original packet factory calls=%d, want 3", got)
	}
	if got := mutatedCalls.Load(); got != 0 {
		t.Fatalf("mutated packet factory calls=%d, want 0", got)
	}

	_, err = admin.AddPath(PathSpec{Transport: "late-packet", Address: ln.Addr().String()})
	if err == nil || !strings.Contains(err.Error(), "path is not present in the frozen session graph") {
		t.Fatalf("late packet factory error=%v, want frozen graph rejection", err)
	}
	if got := lateCalls.Load(); got != 0 {
		t.Fatalf("late packet factory calls=%d, want 0", got)
	}
	assertFactoryPacketRoundTrip(t, client, server, "packet snapshot recovery")
}

func TestStreamFactoryResolverRetryUsesSessionSnapshot(t *testing.T) {
	ln, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := startFactoryStreamAccept(ln)

	const transportName = "retry-stream"
	var originalCalls, mutatedCalls atomic.Int32
	original := func(ctx context.Context, addr string) (net.Conn, error) {
		call := originalCalls.Add(1)
		if call == 2 {
			return nil, errors.New("injected initial extra-path failure")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	d := &sessionDialer{
		Root: selectorRoot([]PathSpec{
			{Transport: transportName, Address: ln.Addr().String()},
			{Transport: transportName, Address: ln.Addr().String()},
		}),
		Retry: retryPolicy{MinBackoff: 100 * time.Millisecond, MaxBackoff: 100 * time.Millisecond},
	}
	if err := d.AddStreamPathFactory(transportName, original); err != nil {
		t.Fatal(err)
	}
	client, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := awaitFactoryAccept(t, accepted)
	defer server.Close()

	d.streamFactories = map[string]streamPathFactory{
		transportName: func(context.Context, string) (net.Conn, error) {
			mutatedCalls.Add(1)
			return nil, errors.New("mutated retry stream factory must not run")
		},
	}
	waitFactoryPathCount(t, client, server, 2)
	if got := originalCalls.Load(); got < 3 {
		t.Fatalf("original retry stream factory calls=%d, want at least 3", got)
	}
	if got := mutatedCalls.Load(); got != 0 {
		t.Fatalf("mutated retry stream factory calls=%d, want 0", got)
	}
	assertFactoryStreamRoundTrip(t, client, server, "stream snapshot retry")
}

func TestPacketFactoryResolverRetryUsesSessionSnapshot(t *testing.T) {
	ln, err := listenRuntimeUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := startFactoryPacketAccept(ln)

	const transportName = "retry-packet"
	var originalCalls, mutatedCalls atomic.Int32
	original := func(context.Context, string) (net.PacketConn, error) {
		call := originalCalls.Add(1)
		if call == 2 {
			return nil, errors.New("injected initial packet extra-path failure")
		}
		return net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	}
	d := &sessionDialer{
		Root: selectorRoot([]PathSpec{
			{Transport: transportName, Address: ln.Addr().String()},
			{Transport: transportName, Address: ln.Addr().String()},
		}),
		Retry: retryPolicy{MinBackoff: 100 * time.Millisecond, MaxBackoff: 100 * time.Millisecond},
	}
	if err := d.AddPacketPathFactory(transportName, original); err != nil {
		t.Fatal(err)
	}
	client, err := d.DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := awaitFactoryAccept(t, accepted)
	defer server.Close()

	d.packetFactories = map[string]packetPathFactory{
		transportName: func(context.Context, string) (net.PacketConn, error) {
			mutatedCalls.Add(1)
			return nil, errors.New("mutated retry packet factory must not run")
		},
	}
	waitFactoryPathCount(t, client, server, 2)
	if got := originalCalls.Load(); got < 3 {
		t.Fatalf("original retry packet factory calls=%d, want at least 3", got)
	}
	if got := mutatedCalls.Load(); got != 0 {
		t.Fatalf("mutated retry packet factory calls=%d, want 0", got)
	}
	assertFactoryPacketRoundTrip(t, client, server, "packet snapshot retry")
}

type factoryAcceptResult[T any] struct {
	conn T
	err  error
}

func startFactoryStreamAccept(ln *runtimeListenerFixture) <-chan factoryAcceptResult[Conn] {
	result := make(chan factoryAcceptResult[Conn], 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := ln.Accept(ctx)
		result <- factoryAcceptResult[Conn]{conn: conn, err: err}
	}()
	return result
}

func startFactoryPacketAccept(ln *runtimeListenerFixture) <-chan factoryAcceptResult[PacketConn] {
	result := make(chan factoryAcceptResult[PacketConn], 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := ln.AcceptPacket(ctx)
		result <- factoryAcceptResult[PacketConn]{conn: conn, err: err}
	}()
	return result
}

func awaitFactoryAccept[T any](t *testing.T, result <-chan factoryAcceptResult[T]) T {
	t.Helper()
	select {
	case accepted := <-result:
		if accepted.err != nil {
			t.Fatalf("accept: %v", accepted.err)
		}
		return accepted.conn
	case <-time.After(6 * time.Second):
		t.Fatal("accept timed out")
		var zero T
		return zero
	}
}

type factoryPathSnapshot interface {
	Paths() []PathInfo
}

func waitFactoryPathCount(t *testing.T, client, server factoryPathSnapshot, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(client.Paths()) >= want && len(server.Paths()) >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("paths did not reach %d: client=%d server=%d", want, len(client.Paths()), len(server.Paths()))
}

func waitFactoryClientPathCount(t *testing.T, client factoryPathSnapshot, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(client.Paths()) == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("client paths did not reach %d: got %d", want, len(client.Paths()))
}

func inactiveFactoryPathID(t *testing.T, paths []PathInfo) uint32 {
	t.Helper()
	for _, path := range paths {
		if !path.Active {
			return path.ID
		}
	}
	t.Fatal("factory snapshot test has no inactive path")
	return 0
}

func assertFactoryStreamRoundTrip(t *testing.T, client, server Conn, payload string) {
	t.Helper()
	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := server.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != payload {
		t.Fatalf("stream payload=%q, want %q", got, payload)
	}
}

func assertFactoryPacketRoundTrip(t *testing.T, client, server PacketConn, payload string) {
	t.Helper()
	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := server.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.WriteTo([]byte(payload), nil); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload)+32)
	n, _, err := server.ReadFrom(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(got[:n]) != payload {
		t.Fatalf("packet payload=%q, want %q", got[:n], payload)
	}
}

const factoryBoundaryFailureCount = 1000

func TestPathFactoryResolverStreamTrustBoundaryHighCount(t *testing.T) {
	const factoryID = "hostile-stream"
	panicValue := &factoryBoundaryPanicValue{}
	factoryErr := errors.New("stream factory conflict")
	var calls atomic.Int64
	var conflictedClosed atomic.Int64
	var healthy *factoryBoundaryStreamConn
	resolver := &pathFactoryResolver{stream: map[string]streamPathFactory{
		factoryID: func(context.Context, string) (net.Conn, error) {
			switch call := calls.Add(1); {
			case call <= factoryBoundaryFailureCount:
				panic(panicValue)
			case call <= 2*factoryBoundaryFailureCount:
				return nil, nil
			case call <= 3*factoryBoundaryFailureCount:
				var typedNil *factoryBoundaryStreamConn
				return typedNil, nil
			case call <= 4*factoryBoundaryFailureCount:
				return &factoryBoundaryStreamConn{closeHook: func() { conflictedClosed.Add(1) }}, factoryErr
			default:
				healthy = &factoryBoundaryStreamConn{}
				return healthy, nil
			}
		},
	}}
	spec := PathSpec{Transport: factoryID, Address: "unused"}

	// The first call has the initial-dial shape; the rest exercise the same
	// immutable resolver entry point used by recovery retries.
	for range factoryBoundaryFailureCount {
		path, err := resolver.dialPath(context.Background(), spec)
		if path != nil {
			t.Fatalf("panic call returned path %T", path)
		}
		assertFactoryBoundaryError(t, err, factoryID, FactoryKindStream, FactoryReasonPanic, panicValue)
	}
	for range factoryBoundaryFailureCount {
		path, err := resolver.dialPath(context.Background(), spec)
		if path != nil {
			t.Fatalf("nil call returned path %T", path)
		}
		assertFactoryBoundaryError(t, err, factoryID, FactoryKindStream, FactoryReasonNilResult, nil)
	}
	for range factoryBoundaryFailureCount {
		path, err := resolver.dialPath(context.Background(), spec)
		if path != nil {
			t.Fatalf("typed-nil call returned path %T", path)
		}
		assertFactoryBoundaryError(t, err, factoryID, FactoryKindStream, FactoryReasonNilResult, nil)
	}
	for range factoryBoundaryFailureCount {
		path, err := resolver.dialPath(context.Background(), spec)
		if path != nil {
			t.Fatalf("conflicting call returned path %T", path)
		}
		if !errors.Is(err, factoryErr) {
			t.Fatalf("conflicting call error=%v, want %v", err, factoryErr)
		}
	}
	if got := conflictedClosed.Load(); got != factoryBoundaryFailureCount {
		t.Fatalf("conflicting stream results closed=%d, want %d", got, factoryBoundaryFailureCount)
	}

	path, err := resolver.dialPath(context.Background(), spec)
	if err != nil {
		t.Fatalf("healthy call after failures: %v", err)
	}
	if path == nil || healthy == nil {
		t.Fatalf("healthy call returned path=%T conn=%v", path, healthy)
	}
	if err := path.Close(); err != nil {
		t.Fatalf("close healthy path: %v", err)
	}
	if !healthy.closed.Load() {
		t.Fatal("healthy stream connection was not owned by returned path")
	}
	if got, want := calls.Load(), int64(4*factoryBoundaryFailureCount+1); got != want {
		t.Fatalf("factory calls=%d, want %d", got, want)
	}
}

func TestPathFactoryResolverPacketTrustBoundaryHighCount(t *testing.T) {
	const factoryID = "hostile-packet"
	panicValue := &factoryBoundaryPanicValue{}
	factoryErr := errors.New("packet factory conflict")
	var calls atomic.Int64
	var conflictedClosed atomic.Int64
	var healthy *factoryBoundaryPacketConn
	resolver := &pathFactoryResolver{packet: map[string]packetPathFactory{
		factoryID: func(context.Context, string) (net.PacketConn, error) {
			switch call := calls.Add(1); {
			case call <= factoryBoundaryFailureCount:
				panic(panicValue)
			case call <= 2*factoryBoundaryFailureCount:
				return nil, nil
			case call <= 3*factoryBoundaryFailureCount:
				var typedNil *factoryBoundaryPacketConn
				return typedNil, nil
			case call <= 4*factoryBoundaryFailureCount:
				return &factoryBoundaryPacketConn{closeHook: func() { conflictedClosed.Add(1) }}, factoryErr
			default:
				healthy = &factoryBoundaryPacketConn{}
				return healthy, nil
			}
		},
	}}
	spec := PathSpec{Transport: factoryID, Address: "127.0.0.1:1"}

	for range factoryBoundaryFailureCount {
		path, err := resolver.dialPath(context.Background(), spec)
		if path != nil {
			t.Fatalf("panic call returned path %T", path)
		}
		assertFactoryBoundaryError(t, err, factoryID, FactoryKindPacket, FactoryReasonPanic, panicValue)
	}
	for range factoryBoundaryFailureCount {
		path, err := resolver.dialPath(context.Background(), spec)
		if path != nil {
			t.Fatalf("nil call returned path %T", path)
		}
		assertFactoryBoundaryError(t, err, factoryID, FactoryKindPacket, FactoryReasonNilResult, nil)
	}
	for range factoryBoundaryFailureCount {
		path, err := resolver.dialPath(context.Background(), spec)
		if path != nil {
			t.Fatalf("typed-nil call returned path %T", path)
		}
		assertFactoryBoundaryError(t, err, factoryID, FactoryKindPacket, FactoryReasonNilResult, nil)
	}
	for range factoryBoundaryFailureCount {
		path, err := resolver.dialPath(context.Background(), spec)
		if path != nil {
			t.Fatalf("conflicting call returned path %T", path)
		}
		if !errors.Is(err, factoryErr) {
			t.Fatalf("conflicting call error=%v, want %v", err, factoryErr)
		}
	}
	if got := conflictedClosed.Load(); got != factoryBoundaryFailureCount {
		t.Fatalf("conflicting packet results closed=%d, want %d", got, factoryBoundaryFailureCount)
	}

	path, err := resolver.dialPath(context.Background(), spec)
	if err != nil {
		t.Fatalf("healthy call after failures: %v", err)
	}
	if path == nil || healthy == nil {
		t.Fatalf("healthy call returned path=%T conn=%v", path, healthy)
	}
	if err := path.Close(); err != nil {
		t.Fatalf("close healthy path: %v", err)
	}
	if !healthy.closed.Load() {
		t.Fatal("healthy packet connection was not owned by returned path")
	}
	if got, want := calls.Load(), int64(4*factoryBoundaryFailureCount+1); got != want {
		t.Fatalf("factory calls=%d, want %d", got, want)
	}
}

func TestPathFactoryResolverFramedTrustBoundaryHighCount(t *testing.T) {
	const factoryID = "hostile-framed"
	panicValue := &factoryBoundaryPanicValue{}
	factoryErr := errors.New("framed factory conflict")
	var calls atomic.Int64
	var conflictedClosed atomic.Int64
	var healthy *factoryBoundaryPathConn
	factory := &factoryBoundaryFramedFactory{dial: func(context.Context, PathSpec) (transport.PathConn, error) {
		switch call := calls.Add(1); {
		case call <= factoryBoundaryFailureCount:
			panic(panicValue)
		case call <= 2*factoryBoundaryFailureCount:
			return nil, nil
		case call <= 3*factoryBoundaryFailureCount:
			var typedNil *factoryBoundaryPathConn
			return typedNil, nil
		case call <= 4*factoryBoundaryFailureCount:
			return &factoryBoundaryPathConn{closeHook: func() { conflictedClosed.Add(1) }}, factoryErr
		default:
			healthy = &factoryBoundaryPathConn{}
			return healthy, nil
		}
	}}
	resolver := &pathFactoryResolver{framed: map[string]transport.PathFactory{factoryID: factory}}
	spec := PathSpec{Transport: factoryID, Address: "unused"}

	for range factoryBoundaryFailureCount {
		path, err := resolver.dialPath(context.Background(), spec)
		if path != nil {
			t.Fatalf("panic call returned path %T", path)
		}
		assertFactoryBoundaryError(t, err, factoryID, FactoryKindFramed, FactoryReasonPanic, panicValue)
	}
	for range factoryBoundaryFailureCount {
		path, err := resolver.dialPath(context.Background(), spec)
		if path != nil {
			t.Fatalf("nil call returned path %T", path)
		}
		assertFactoryBoundaryError(t, err, factoryID, FactoryKindFramed, FactoryReasonNilResult, nil)
	}
	for range factoryBoundaryFailureCount {
		path, err := resolver.dialPath(context.Background(), spec)
		if path != nil {
			t.Fatalf("typed-nil call returned path %T", path)
		}
		assertFactoryBoundaryError(t, err, factoryID, FactoryKindFramed, FactoryReasonNilResult, nil)
	}
	for range factoryBoundaryFailureCount {
		path, err := resolver.dialPath(context.Background(), spec)
		if path != nil {
			t.Fatalf("conflicting call returned path %T", path)
		}
		if !errors.Is(err, factoryErr) {
			t.Fatalf("conflicting call error=%v, want %v", err, factoryErr)
		}
	}
	if got := conflictedClosed.Load(); got != factoryBoundaryFailureCount {
		t.Fatalf("conflicting framed results closed=%d, want %d", got, factoryBoundaryFailureCount)
	}

	path, err := resolver.dialPath(context.Background(), spec)
	if err != nil {
		t.Fatalf("healthy call after failures: %v", err)
	}
	if path != healthy || healthy == nil {
		t.Fatalf("healthy call returned path=%T want %T", path, healthy)
	}
	if err := path.Close(); err != nil {
		t.Fatalf("close healthy path: %v", err)
	}
	if !healthy.closed.Load() {
		t.Fatal("healthy framed connection was not closed")
	}
	if got, want := calls.Load(), int64(4*factoryBoundaryFailureCount+1); got != want {
		t.Fatalf("factory calls=%d, want %d", got, want)
	}
}

func TestPathFactoryResolverPreservesFactoryContextCancellation(t *testing.T) {
	const factoryID = "cancel-stream"
	spec := PathSpec{Transport: factoryID, Address: "unused"}

	t.Run("already canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var calls atomic.Int32
		resolver := &pathFactoryResolver{stream: map[string]streamPathFactory{
			factoryID: func(context.Context, string) (net.Conn, error) {
				calls.Add(1)
				panic("must not be invoked")
			},
		}}
		if _, err := resolver.dialPath(ctx, spec); !errors.Is(err, context.Canceled) {
			t.Fatalf("dial error=%v, want context cancellation", err)
		}
		if calls.Load() != 0 {
			t.Fatalf("canceled dial invoked factory %d times", calls.Load())
		}
	})

	t.Run("canceled during panic", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		panicValue := &factoryBoundaryPanicValue{}
		resolver := &pathFactoryResolver{stream: map[string]streamPathFactory{
			factoryID: func(context.Context, string) (net.Conn, error) {
				cancel()
				panic(panicValue)
			},
		}}
		_, err := resolver.dialPath(ctx, spec)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("dial error=%v, want context cancellation", err)
		}
		assertFactoryBoundaryError(t, err, factoryID, FactoryKindStream, FactoryReasonPanic, panicValue)
	})

	t.Run("canceled during nil result", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		resolver := &pathFactoryResolver{stream: map[string]streamPathFactory{
			factoryID: func(context.Context, string) (net.Conn, error) {
				cancel()
				return nil, nil
			},
		}}
		_, err := resolver.dialPath(ctx, spec)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("dial error=%v, want context cancellation", err)
		}
		assertFactoryBoundaryError(t, err, factoryID, FactoryKindStream, FactoryReasonNilResult, nil)
	})

	t.Run("canceled during successful result", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		late := &factoryBoundaryStreamConn{}
		resolver := &pathFactoryResolver{stream: map[string]streamPathFactory{
			factoryID: func(context.Context, string) (net.Conn, error) {
				cancel()
				return late, nil
			},
		}}
		path, err := resolver.dialPath(ctx, spec)
		if path != nil {
			t.Fatalf("canceled dial returned a late path %T", path)
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("dial error=%v, want context cancellation", err)
		}
		if !late.closed.Load() {
			t.Fatal("late successful factory result was not closed")
		}
	})

	t.Run("cleanup panic remains typed", func(t *testing.T) {
		factoryErr := errors.New("factory returned conflicting error")
		panicValue := &factoryBoundaryPanicValue{}
		resolver := &pathFactoryResolver{stream: map[string]streamPathFactory{
			factoryID: func(context.Context, string) (net.Conn, error) {
				return &factoryBoundaryStreamConn{closeHook: func() { panic(panicValue) }}, factoryErr
			},
		}}
		path, err := resolver.dialPath(context.Background(), spec)
		if path != nil {
			t.Fatalf("conflicting factory returned path %T", path)
		}
		if !errors.Is(err, factoryErr) {
			t.Fatalf("cleanup error=%v, want original %v", err, factoryErr)
		}
		assertFactoryBoundaryError(t, err, factoryID, FactoryKindStream, FactoryReasonCleanup, panicValue)
	})

	t.Run("cleanup Goexit remains typed", func(t *testing.T) {
		factoryErr := errors.New("factory returned conflicting error")
		resolver := &pathFactoryResolver{stream: map[string]streamPathFactory{
			factoryID: func(context.Context, string) (net.Conn, error) {
				return &factoryBoundaryStreamConn{closeHook: runtime.Goexit}, factoryErr
			},
		}}
		path, err := resolver.dialPath(context.Background(), spec)
		if path != nil {
			t.Fatalf("conflicting factory returned path %T", path)
		}
		if !errors.Is(err, factoryErr) {
			t.Fatalf("cleanup error=%v, want original %v", err, factoryErr)
		}
		assertFactoryBoundaryError(t, err, factoryID, FactoryKindStream, FactoryReasonCleanup, nil)
	})

	t.Run("factory cancellation error", func(t *testing.T) {
		resolver := &pathFactoryResolver{stream: map[string]streamPathFactory{
			factoryID: func(context.Context, string) (net.Conn, error) {
				return nil, context.Canceled
			},
		}}
		if _, err := resolver.dialPath(context.Background(), spec); err != context.Canceled {
			t.Fatalf("dial error=%v, want unchanged context.Canceled", err)
		}
	})
}

func TestPathFactoryResolverContainsGoexit(t *testing.T) {
	const factoryID = "goexit-stream"
	var calls atomic.Int32
	var healthy *factoryBoundaryStreamConn
	resolver := &pathFactoryResolver{stream: map[string]streamPathFactory{
		factoryID: func(context.Context, string) (net.Conn, error) {
			if calls.Add(1) == 1 {
				runtime.Goexit()
				return nil, errors.New("runtime.Goexit returned")
			}
			healthy = &factoryBoundaryStreamConn{}
			return healthy, nil
		},
	}}
	spec := PathSpec{Transport: factoryID, Address: "unused"}
	path, err := resolver.dialPath(context.Background(), spec)
	if path != nil {
		t.Fatalf("runtime.Goexit returned path %T", path)
	}
	assertFactoryBoundaryError(t, err, factoryID, FactoryKindStream, FactoryReasonAbnormal, nil)

	path, err = resolver.dialPath(context.Background(), spec)
	if err != nil {
		t.Fatalf("healthy call after Goexit: %v", err)
	}
	if path == nil || healthy == nil {
		t.Fatalf("healthy call returned path=%T conn=%v", path, healthy)
	}
	if err := path.Close(); err != nil {
		t.Fatalf("close healthy path: %v", err)
	}
}

func TestPathFactoryResolverDoesNotRecoverBuiltinPanic(t *testing.T) {
	panicValue := &factoryBoundaryPanicValue{}
	resolver := &pathFactoryResolver{framed: map[string]transport.PathFactory{
		"tcp": &factoryBoundaryFramedFactory{dial: func(context.Context, PathSpec) (transport.PathConn, error) {
			panic(panicValue)
		}},
	}}
	defer func() {
		if recovered := recover(); recovered != panicValue {
			t.Fatalf("builtin panic recovered=%T, want original %T", recovered, panicValue)
		}
	}()
	_, _ = resolver.dialPath(context.Background(), PathSpec{Transport: "tcp", Address: "unused"})
	t.Fatal("built-in factory panic was converted to an error")
}

func assertFactoryBoundaryError(
	t *testing.T,
	err error,
	factoryID string,
	kind FactoryKind,
	reason FactoryErrorReason,
	panicValue any,
) {
	t.Helper()
	if err == nil {
		t.Fatal("factory call returned nil error")
	}
	var factoryErr *FactoryError
	if !errors.As(err, &factoryErr) {
		t.Fatalf("factory error type=%T, want *FactoryError: %v", err, err)
	}
	if factoryErr.FactoryID != factoryID || factoryErr.Kind != kind || factoryErr.Reason != reason {
		t.Fatalf("factory error=%+v, want id=%q kind=%q reason=%q", factoryErr, factoryID, kind, reason)
	}
	wantPanicType := ""
	if panicValue != nil {
		wantPanicType = reflect.TypeOf(panicValue).String()
	}
	if factoryErr.PanicType != wantPanicType {
		t.Fatalf("panic type=%q, want %q", factoryErr.PanicType, wantPanicType)
	}
	_ = err.Error()
}

type factoryBoundaryPanicValue struct{}

func (*factoryBoundaryPanicValue) Error() string {
	panic("factory panic payload must not be formatted")
}

type factoryBoundaryAddr string

func (a factoryBoundaryAddr) Network() string { return "factory-boundary" }
func (a factoryBoundaryAddr) String() string  { return string(a) }

type factoryBoundaryStreamConn struct {
	closed    atomic.Bool
	closeHook func()
}

func (*factoryBoundaryStreamConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *factoryBoundaryStreamConn) Write(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return len(p), nil
}
func (c *factoryBoundaryStreamConn) Close() error {
	if c.closed.CompareAndSwap(false, true) && c.closeHook != nil {
		c.closeHook()
	}
	return nil
}
func (*factoryBoundaryStreamConn) LocalAddr() net.Addr              { return factoryBoundaryAddr("local") }
func (*factoryBoundaryStreamConn) RemoteAddr() net.Addr             { return factoryBoundaryAddr("remote") }
func (*factoryBoundaryStreamConn) SetDeadline(time.Time) error      { return nil }
func (*factoryBoundaryStreamConn) SetReadDeadline(time.Time) error  { return nil }
func (*factoryBoundaryStreamConn) SetWriteDeadline(time.Time) error { return nil }

type factoryBoundaryPacketConn struct {
	closed    atomic.Bool
	closeHook func()
}

func (*factoryBoundaryPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, io.EOF
}
func (c *factoryBoundaryPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return len(p), nil
}
func (c *factoryBoundaryPacketConn) Close() error {
	if c.closed.CompareAndSwap(false, true) && c.closeHook != nil {
		c.closeHook()
	}
	return nil
}
func (*factoryBoundaryPacketConn) LocalAddr() net.Addr              { return factoryBoundaryAddr("local") }
func (*factoryBoundaryPacketConn) SetDeadline(time.Time) error      { return nil }
func (*factoryBoundaryPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*factoryBoundaryPacketConn) SetWriteDeadline(time.Time) error { return nil }

type factoryBoundaryFramedFactory struct {
	dial func(context.Context, PathSpec) (transport.PathConn, error)
}

func (f *factoryBoundaryFramedFactory) DialPath(ctx context.Context, spec transport.PathSpec) (transport.PathConn, error) {
	return f.dial(ctx, spec)
}
func (*factoryBoundaryFramedFactory) Probe(context.Context, transport.PathSpec) (transport.PathQuality, error) {
	return transport.PathQuality{}, nil
}

type factoryBoundaryPathConn struct {
	closed    atomic.Bool
	closeHook func()
}

func (*factoryBoundaryPathConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *factoryBoundaryPathConn) Write(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return len(p), nil
}
func (c *factoryBoundaryPathConn) Close() error {
	if c.closed.CompareAndSwap(false, true) && c.closeHook != nil {
		c.closeHook()
	}
	return nil
}
func (*factoryBoundaryPathConn) Quality() transport.PathQuality            { return transport.PathQuality{} }
func (*factoryBoundaryPathConn) OnDeath(func(transport.DeathCause, error)) {}
func (*factoryBoundaryPathConn) LocalAddr() string                         { return "local" }
func (*factoryBoundaryPathConn) RemoteAddr() string                        { return "remote" }
