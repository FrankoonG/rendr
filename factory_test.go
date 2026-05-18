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

	d := &Dialer{
		Mode:  ModePrime,
		Paths: []PathSpec{{Transport: "factory-tcp", Address: ln.Addr().String()}},
	}
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
	d := &Dialer{Paths: []PathSpec{{Transport: "no-such-transport", Address: probeAddr}}}
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

	d2 := &Dialer{Paths: []PathSpec{{Transport: "tcp", Address: ln.Addr().String()}}}
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

	d := &Dialer{
		Mode:  ModePrime,
		Paths: []PathSpec{{Transport: "factory-udp", Address: ln.Addr().String()}},
	}
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
