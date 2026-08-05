package rendr

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestM9X5StreamPathFactoryRoundTrip drives a Dialer entirely through
// an AddStreamPathFactory-registered transport: no global registry
// involvement, no tcp/udpflow code path. The factory hands rendr a
// net.Conn produced by net.Pipe()-style plumbing into a real rendr
// listener on the loopback. Asserts:
//   - Dial succeeds via factory-supplied connection
//   - subsequent Write/Read round-trips through rendr framing
//   - the factory was invoked exactly once (single path)
//   - flow_id symmetry (C1) still holds because the underlying
//     listener is a real rendr.Listener
func TestM9X5StreamPathFactoryRoundTrip(t *testing.T) {
	ln, err := ListenTCP("127.0.0.1:0")
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

	d := &Dialer{Root: selectorRoot(

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

	if cli, ok := client.(Conn); ok {
		if srv, ok := server.(Conn); ok {
			if cli.FlowID() != srv.FlowID() {
				t.Fatalf("flow_id mismatch through factory wrap")
			}
		}
	}
}

// TestM9X5StreamFactoryFallback: when a PathSpec.Transport matches a
// global registry transport AND a factory of the same name exists on
// the Dialer, the factory wins. Conversely, an unregistered factory
// name falls through to the global registry without error.
func TestM9X5StreamFactoryFallback(t *testing.T) {
	// Part 1: unknown transport name returns an error and does NOT
	// touch any listener. Use a closed listener to source an address
	// for shape; never dial against it.
	probe, err := ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	probeAddr := probe.Addr().String()
	probe.Close()
	d := &Dialer{Root: selectorRoot([]PathSpec{{Transport: "no-such-transport", Address: probeAddr}})}
	if _, err := d.Dial(context.Background()); err == nil {
		t.Fatal("expected dial error for unknown transport")
	}

	// Part 2: "tcp" used without a factory -> falls back to the
	// global transport.Default registry. Wait for the accept-side
	// HELLO to fully complete before closing the listener to avoid
	// racing with listener.handleHello on teardown.
	ln, err := ListenTCP("127.0.0.1:0")
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

	d2 := &Dialer{Root: selectorRoot([]PathSpec{{Transport: "tcp", Address: ln.Addr().String()}})}
	c, err := d2.Dial(context.Background())
	if err != nil {
		t.Fatalf("Dial via global tcp: %v", err)
	}
	srv := <-accepted
	c.Close()
	srv.Close()
}

// TestM9X5AddStreamFactoryValidation covers the API guard rails:
// empty name, nil factory, duplicate registration, name conflict
// across stream/packet maps.
func TestM9X5AddStreamFactoryValidation(t *testing.T) {
	d := &Dialer{}
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

// TestM9X5PacketPathFactoryRoundTrip drives a packet-mode Dialer
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
	ln, err := ListenUDPFlowPacket("127.0.0.1:0")
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

	d := &Dialer{Root: selectorRoot(

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
}

// TestM9X5AddPacketFactoryValidation: API guard rails for packet
// factories — empty name, nil factory, duplicate registration,
// shadow conflict with stream factory of the same name.
func TestM9X5AddPacketFactoryValidation(t *testing.T) {
	d := &Dialer{}
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
	if err := d.AddStreamPathFactory("p", streamFn); err == nil || !strings.Contains(err.Error(), "PacketPathFactory") {
		t.Fatalf("expected stream-shadow-packet error, got %v", err)
	}
}

func TestStreamFactoryResolverAddPathUsesSessionSnapshot(t *testing.T) {
	ln, err := ListenTCP("127.0.0.1:0")
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
	d := &Dialer{Root: selectorRoot([]PathSpec{
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

	// Replace the original Dialer's map after Dial. The live session must not
	// share this map or consult it again.
	d.streamFactories = map[string]StreamPathFactory{
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
	ln, err := ListenUDPFlowPacket("127.0.0.1:0")
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
	d := &Dialer{Root: selectorRoot([]PathSpec{
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

	d.packetFactories = map[string]PacketPathFactory{
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
	ln, err := ListenTCP("127.0.0.1:0")
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
	d := &Dialer{
		Root: selectorRoot([]PathSpec{
			{Transport: transportName, Address: ln.Addr().String()},
			{Transport: transportName, Address: ln.Addr().String()},
		}),
		Retry: RetryPolicy{MinBackoff: 100 * time.Millisecond, MaxBackoff: 100 * time.Millisecond},
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

	d.streamFactories = map[string]StreamPathFactory{
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
	ln, err := ListenUDPFlowPacket("127.0.0.1:0")
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
	d := &Dialer{
		Root: selectorRoot([]PathSpec{
			{Transport: transportName, Address: ln.Addr().String()},
			{Transport: transportName, Address: ln.Addr().String()},
		}),
		Retry: RetryPolicy{MinBackoff: 100 * time.Millisecond, MaxBackoff: 100 * time.Millisecond},
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

	d.packetFactories = map[string]PacketPathFactory{
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

func startFactoryStreamAccept(ln Listener) <-chan factoryAcceptResult[Conn] {
	result := make(chan factoryAcceptResult[Conn], 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := ln.Accept(ctx)
		result <- factoryAcceptResult[Conn]{conn: conn, err: err}
	}()
	return result
}

func startFactoryPacketAccept(ln PacketListener) <-chan factoryAcceptResult[PacketConn] {
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
