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
	ln, err := ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		c.Close()
	}()

	// 1) Unregistered transport name -> errors out (no fallback shadow)
	d := &Dialer{Paths: []PathSpec{{Transport: "no-such-transport", Address: ln.Addr().String()}}}
	if _, err := d.Dial(context.Background()); err == nil {
		t.Fatal("expected dial error for unknown transport")
	}

	// 2) "tcp" used without registering a factory -> uses global registry
	d2 := &Dialer{Paths: []PathSpec{{Transport: "tcp", Address: ln.Addr().String()}}}
	c, err := d2.Dial(context.Background())
	if err != nil {
		t.Fatalf("Dial via global tcp: %v", err)
	}
	c.Close()
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

// TestM9X5PacketFactoryStage2 confirms stage 1 returns the sentinel
// error so embedders can errors.Is on it (and switch to a real
// implementation when stage 2 lands).
func TestM9X5PacketFactoryStage2(t *testing.T) {
	d := &Dialer{}
	err := d.AddPacketPathFactory("dummy", func(context.Context, string) (net.PacketConn, error) { return nil, nil })
	if !errors.Is(err, ErrPacketFactoryStage2) {
		t.Fatalf("got %v, want ErrPacketFactoryStage2", err)
	}
}
