package l3session

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
)

func TestUDPPeerRelayDispatchesIdentityAndBridgesReplies(t *testing.T) {
	ln, err := rendr.ListenUDPFlowPacket("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accepted := make(chan rendr.PacketConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		pc, err := ln.AcceptPacket(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- pc
	}()
	client, err := (&rendr.Dialer{
		Root:               rendr.Path("udp", rendr.PathSpec{Transport: "udpflow", Address: ln.Addr().String()}),
		PreserveL3Identity: true,
	}).DialPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var server rendr.PacketConn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()

	egressConn := newPeerTestPacketConn()
	egress := &peerTestEgress{conn: egressConn}
	registry := l3ingress.NewEgressRegistry()
	if err := registry.Register("vpn", egress); err != nil {
		t.Fatal(err)
	}
	peerErr := make(chan error, 1)
	go func() {
		peerErr <- (&UDPPeerRelay{PacketConn: server, Egresses: registry}).Run(ctx)
	}()

	id := l3ingress.L3Identity{
		Proto:   l3ingress.ProtocolUDP,
		SrcIP:   netip.MustParseAddr("192.0.2.10"),
		SrcPort: 42000,
		DstIP:   netip.MustParseAddr("198.51.100.20"),
		DstPort: 53,
	}
	request, err := appendUDPEnvelope(nil, id, "vpn", []byte("query"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.WriteTo(request, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-egressConn.writes:
		if string(got) != "query" {
			t.Fatalf("egress payload=%q want query", got)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if got := egress.identity(); got != id {
		t.Fatalf("egress identity=%s want %s", got, id)
	}

	egressConn.reads <- []byte("answer")
	buf := make([]byte, 32)
	n, _, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "answer" {
		t.Fatalf("reply=%q want answer", buf[:n])
	}
	_ = egressConn.Close()
	select {
	case err := <-peerErr:
		if err != nil {
			t.Fatalf("peer relay: %v", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestUDPPeerRelayRejectsMetadataChange(t *testing.T) {
	firstID := l3ingress.L3Identity{
		Proto: l3ingress.ProtocolUDP,
		SrcIP: netip.MustParseAddr("192.0.2.1"), DstIP: netip.MustParseAddr("198.51.100.1"),
		SrcPort: 1000, DstPort: 2000,
	}
	secondID := firstID
	secondID.SrcPort++
	first, _ := appendUDPEnvelope(nil, firstID, "vpn", []byte("one"))
	second, _ := appendUDPEnvelope(nil, secondID, "vpn", []byte("two"))
	packetConn := newScriptedRendrPacketConn(first, second)
	egressConn := newPeerTestPacketConn()
	registry := l3ingress.NewEgressRegistry()
	if err := registry.Register("vpn", &peerTestEgress{conn: egressConn}); err != nil {
		t.Fatal(err)
	}
	err := (&UDPPeerRelay{PacketConn: packetConn, Egresses: registry}).Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "identity or egress changed") {
		t.Fatalf("err=%v want metadata-change rejection", err)
	}
}

type peerTestEgress struct {
	mu   sync.Mutex
	id   l3ingress.L3Identity
	conn *peerTestPacketConn
}

func (e *peerTestEgress) DialTCP(context.Context, l3ingress.L3Identity) (net.Conn, error) {
	return nil, errors.New("UDP test egress")
}

func (e *peerTestEgress) DialUDP(_ context.Context, id l3ingress.L3Identity) (net.PacketConn, netip.AddrPort, error) {
	e.mu.Lock()
	e.id = id
	e.mu.Unlock()
	return e.conn, netip.MustParseAddrPort("198.51.100.20:53"), nil
}

func (e *peerTestEgress) identity() l3ingress.L3Identity {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.id
}

type peerTestPacketConn struct {
	reads     chan []byte
	writes    chan []byte
	done      chan struct{}
	deadline  chan struct{}
	closeOnce sync.Once
	deadOnce  sync.Once
}

func newPeerTestPacketConn() *peerTestPacketConn {
	return &peerTestPacketConn{
		reads:    make(chan []byte, 4),
		writes:   make(chan []byte, 4),
		done:     make(chan struct{}),
		deadline: make(chan struct{}),
	}
}

func (c *peerTestPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case payload := <-c.reads:
		return copy(p, payload), rendrPeerAddr, nil
	case <-c.done:
		return 0, nil, io.EOF
	case <-c.deadline:
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (c *peerTestPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case c.writes <- append([]byte(nil), p...):
		return len(p), nil
	case <-c.done:
		return 0, net.ErrClosed
	}
}

func (c *peerTestPacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.done) })
	return nil
}
func (c *peerTestPacketConn) LocalAddr() net.Addr { return rendrPeerAddr }
func (c *peerTestPacketConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}
func (c *peerTestPacketConn) SetReadDeadline(t time.Time) error {
	if !t.IsZero() && !t.After(time.Now()) {
		c.deadOnce.Do(func() { close(c.deadline) })
	}
	return nil
}
func (c *peerTestPacketConn) SetWriteDeadline(time.Time) error { return nil }

type scriptedRendrPacketConn struct {
	*peerTestPacketConn
	packets chan []byte
}

func newScriptedRendrPacketConn(packets ...[]byte) *scriptedRendrPacketConn {
	c := &scriptedRendrPacketConn{
		peerTestPacketConn: newPeerTestPacketConn(),
		packets:            make(chan []byte, len(packets)),
	}
	for _, packet := range packets {
		c.packets <- packet
	}
	return c
}

func (c *scriptedRendrPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case packet := <-c.packets:
		return copy(p, packet), rendrPeerAddr, nil
	default:
		return 0, nil, io.EOF
	}
}
func (c *scriptedRendrPacketConn) Paths() []rendr.PathInfo { return nil }
func (c *scriptedRendrPacketConn) FlowID() [16]byte        { return [16]byte{1} }
func (c *scriptedRendrPacketConn) Status() rendr.Status    { return rendr.Status{} }
