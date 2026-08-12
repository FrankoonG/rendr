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

	app, endpoint, err := newTestTCPConnPair()
	if err != nil {
		t.Fatal(err)
	}
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
		buf, err := io.ReadAll(egressSide)
		if err != nil {
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
		if err := egressSide.CloseWrite(); err != nil {
			t.Errorf("egress CloseWrite: %v", err)
		}
	}()

	if _, err := app.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := app.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(app, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "world" {
		t.Fatalf("app read %q want world", got)
	}
	if _, err := app.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("app read after response=%v, want EOF", err)
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

	app, endpoint, err := newTestTCPConnPair()
	if err != nil {
		t.Fatal(err)
	}
	errCh1 := make(chan error, 1)
	go func() { errCh1 <- relay.Serve(context.Background(), tcpFlowRelayEvent(id), endpoint) }()
	egressSide := egress.waitConn(t)
	closeActiveFlow(t, relay, id)
	_ = app.Close()
	_ = egressSide.Close()
	select {
	case err := <-errCh1:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first relay shutdown")
	}

	app2, endpoint2, err := newTestTCPConnPair()
	if err != nil {
		t.Fatal(err)
	}
	defer app2.Close()
	errCh2 := make(chan error, 1)
	go func() { errCh2 <- relay.Serve(context.Background(), tcpFlowRelayEvent(id), endpoint2) }()
	egressSide2 := egress.waitConn(t)
	defer egressSide2.Close()
	if egress.count() != 2 {
		t.Fatalf("egress dial count=%d want 2", egress.count())
	}
	payload := []byte("reopened")
	writeErr := make(chan error, 1)
	go func() {
		_, err := app2.Write(payload)
		writeErr <- err
	}()
	if err := egressSide2.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(egressSide2, got); err != nil {
		t.Fatalf("reopened relay read: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("reopened relay read %q want %q", got, payload)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("reopened relay write: %v", err)
	}
	_ = relay.Close()
	select {
	case err := <-errCh2:
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
	conns chan TCPConn
	n     int
}

func (e *tcpRelayEgress) DialTCP(_ context.Context, id L3Identity) (TCPConn, error) {
	local, remote, err := newTestTCPConnPair()
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	if e.conns == nil {
		e.conns = make(chan TCPConn, 4)
	}
	e.id = id
	e.n++
	conns := e.conns
	e.mu.Unlock()
	conns <- remote
	return local, nil
}

func newTestTCPConnPair() (TCPConn, TCPConn, error) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, nil, err
	}
	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		_ = listener.Close()
		return nil, nil, err
	}
	select {
	case server := <-accepted:
		_ = listener.Close()
		return client, server, nil
	case err := <-acceptErr:
		_ = client.Close()
		_ = listener.Close()
		return nil, nil, err
	case <-time.After(time.Second):
		_ = client.Close()
		_ = listener.Close()
		return nil, nil, errors.New("timed out accepting test TCP connection")
	}
}

func (e *tcpRelayEgress) DialUDP(context.Context, L3Identity) (net.PacketConn, netip.AddrPort, error) {
	return nil, netip.AddrPort{}, errors.New("tcp-only egress")
}

func (e *tcpRelayEgress) waitConn(t *testing.T) TCPConn {
	t.Helper()
	e.mu.Lock()
	if e.conns == nil {
		e.conns = make(chan TCPConn, 4)
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
