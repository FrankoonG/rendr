package l3ingress

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestTCPFlowRelayDispatchesIdentityAndBridgesStream(t *testing.T) {
	id := tcpFlowRelayIdentity()
	egress := &tcpRelayEgress{}
	reg := NewEgressRegistry()
	if err := reg.Register("direct", egress); err != nil {
		t.Fatal(err)
	}

	app, endpoint := net.Pipe()
	defer app.Close()
	relay := &TCPFlowRelay{Egresses: reg}
	errCh := make(chan error, 1)
	go func() { errCh <- relay.Serve(context.Background(), tcpFlowRelayEvent(id), endpoint) }()

	egressSide := egress.waitConn(t)
	defer egressSide.Close()
	if got := egress.lastID(); got != id {
		t.Fatalf("egress id=%+v want %+v", got, id)
	}
	go func() {
		buf := make([]byte, 5)
		if _, err := io.ReadFull(egressSide, buf); err != nil {
			t.Errorf("egress read: %v", err)
			return
		}
		if string(buf) != "hello" {
			t.Errorf("egress read %q want hello", buf)
			return
		}
		if _, err := egressSide.Write([]byte("world")); err != nil {
			t.Errorf("egress write: %v", err)
		}
	}()

	if _, err := app.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(app, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "world" {
		t.Fatalf("app read %q want world", got)
	}
	app.Close()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for relay shutdown")
	}
}

func TestTCPFlowRelayCloseFlowAllowsReopen(t *testing.T) {
	id := tcpFlowRelayIdentity()
	egress := &tcpRelayEgress{}
	reg := NewEgressRegistry()
	if err := reg.Register("direct", egress); err != nil {
		t.Fatal(err)
	}
	relay := &TCPFlowRelay{Egresses: reg}

	app, endpoint := net.Pipe()
	errCh := make(chan error, 1)
	go func() { errCh <- relay.Serve(context.Background(), tcpFlowRelayEvent(id), endpoint) }()
	egressSide := egress.waitConn(t)
	closeActiveFlow(t, relay, id)
	_ = app.Close()
	_ = egressSide.Close()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first relay shutdown")
	}

	app2, endpoint2 := net.Pipe()
	defer app2.Close()
	errCh = make(chan error, 1)
	go func() { errCh <- relay.Serve(context.Background(), tcpFlowRelayEvent(id), endpoint2) }()
	egressSide2 := egress.waitConn(t)
	defer egressSide2.Close()
	if egress.count() != 2 {
		t.Fatalf("egress dial count=%d want 2", egress.count())
	}
	_ = relay.Close()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for second relay shutdown")
	}
}

func closeActiveFlow(t *testing.T, relay *TCPFlowRelay, id L3Identity) {
	t.Helper()
	deadline := time.After(time.Second)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		if relay.CloseFlow(id) {
			return
		}
		select {
		case <-deadline:
			t.Fatal("CloseFlow returned false for active flow")
		case <-tick.C:
		}
	}
}

func tcpFlowRelayIdentity() L3Identity {
	return L3Identity{
		Proto:   ProtocolTCP,
		SrcIP:   netip.MustParseAddr("10.0.0.2"),
		SrcPort: 40000,
		DstIP:   netip.MustParseAddr("198.51.100.20"),
		DstPort: 443,
	}
}

func tcpFlowRelayEvent(id L3Identity) PacketEvent {
	return PacketEvent{
		Meta: PacketMeta{Identity: id},
		Flow: FlowMeta{L3Identity: id, Direction: DirectionEgress},
		Decision: FlowDecision{
			Egress: "direct",
		},
		Decided: true,
	}
}

type tcpRelayEgress struct {
	mu    sync.Mutex
	id    L3Identity
	conns chan net.Conn
	n     int
}

func (e *tcpRelayEgress) DialTCP(_ context.Context, id L3Identity) (net.Conn, error) {
	local, remote := net.Pipe()
	e.mu.Lock()
	if e.conns == nil {
		e.conns = make(chan net.Conn, 4)
	}
	e.id = id
	e.n++
	conns := e.conns
	e.mu.Unlock()
	conns <- remote
	return local, nil
}

func (e *tcpRelayEgress) DialUDP(context.Context, L3Identity) (net.PacketConn, netip.AddrPort, error) {
	return nil, netip.AddrPort{}, errors.New("tcp-only egress")
}

func (e *tcpRelayEgress) waitConn(t *testing.T) net.Conn {
	t.Helper()
	e.mu.Lock()
	if e.conns == nil {
		e.conns = make(chan net.Conn, 4)
	}
	conns := e.conns
	e.mu.Unlock()
	select {
	case c := <-conns:
		return c
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for egress conn")
		return nil
	}
}

func (e *tcpRelayEgress) lastID() L3Identity {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.id
}

func (e *tcpRelayEgress) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.n
}
