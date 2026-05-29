package l3ingress

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestUDPFlowRelayDispatchesPayloadAndWritesReply(t *testing.T) {
	id := L3Identity{
		Proto:   ProtocolUDP,
		SrcIP:   netip.MustParseAddr("10.0.0.2"),
		SrcPort: 40000,
		DstIP:   netip.MustParseAddr("198.51.100.53"),
		DstPort: 53,
	}
	packet := mustBuildUDPPacket(t, id, []byte("query"))
	meta, err := ParsePacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	pc := newScriptedPacketConn([]byte("answer"))
	egress := &udpRelayEgress{
		pc:     pc,
		remote: netip.MustParseAddrPort("198.51.100.53:53"),
	}
	reg := NewEgressRegistry()
	if err := reg.Register("dns-egress", egress); err != nil {
		t.Fatal(err)
	}
	dev := &writeCaptureDevice{writes: make(chan []byte, 1)}
	relay := &UDPFlowRelay{Device: dev, Egresses: reg}
	defer relay.Close()

	err = relay.HandlePacket(context.Background(), PacketEvent{
		Packet: packet,
		Meta:   meta,
		Flow:   FlowMeta{L3Identity: id, Direction: DirectionIngress},
		Decision: FlowDecision{
			Egress: "dns-egress",
		},
		Decided: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if egress.id != id {
		t.Fatalf("egress id=%+v want %+v", egress.id, id)
	}
	wrote, writeAddr := pc.writeSnapshot()
	if string(wrote) != "query" {
		t.Fatalf("egress wrote=%q", wrote)
	}
	if writeAddr.String() != "198.51.100.53:53" {
		t.Fatalf("egress write addr=%v", writeAddr)
	}

	select {
	case reply := <-dev.writes:
		replyMeta, err := ParsePacket(reply)
		if err != nil {
			t.Fatal(err)
		}
		if replyMeta.Identity != id.Reverse() {
			t.Fatalf("reply identity=%+v want %+v", replyMeta.Identity, id.Reverse())
		}
		payload, err := UDPPayload(reply, replyMeta)
		if err != nil {
			t.Fatal(err)
		}
		if string(payload) != "answer" {
			t.Fatalf("reply payload=%q", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for reply packet")
	}
}

func TestUDPFlowRelayRequiresDecision(t *testing.T) {
	id := L3Identity{
		Proto:   ProtocolUDP,
		SrcIP:   netip.MustParseAddr("10.0.0.2"),
		SrcPort: 40000,
		DstIP:   netip.MustParseAddr("198.51.100.53"),
		DstPort: 53,
	}
	packet := mustBuildUDPPacket(t, id, []byte("query"))
	meta, err := ParsePacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	relay := &UDPFlowRelay{Device: &writeCaptureDevice{}}
	if err := relay.HandlePacket(context.Background(), PacketEvent{Packet: packet, Meta: meta}); err == nil {
		t.Fatal("missing decision accepted")
	}
}

func TestUDPFlowRelayCloseFlowAllowsReopen(t *testing.T) {
	id := L3Identity{
		Proto:   ProtocolUDP,
		SrcIP:   netip.MustParseAddr("10.0.0.2"),
		SrcPort: 40000,
		DstIP:   netip.MustParseAddr("198.51.100.53"),
		DstPort: 53,
	}
	packet := mustBuildUDPPacket(t, id, []byte("query"))
	meta, err := ParsePacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	egress := &countingUDPEgress{remote: netip.MustParseAddrPort("198.51.100.53:53")}
	reg := NewEgressRegistry()
	if err := reg.Register("dns-egress", egress); err != nil {
		t.Fatal(err)
	}
	relay := &UDPFlowRelay{Device: &writeCaptureDevice{}, Egresses: reg}
	defer relay.Close()
	ev := PacketEvent{
		Packet:   packet,
		Meta:     meta,
		Flow:     FlowMeta{L3Identity: id, Direction: DirectionIngress},
		Decision: FlowDecision{Egress: "dns-egress"},
		Decided:  true,
	}
	if err := relay.HandlePacket(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if egress.dials != 1 {
		t.Fatalf("dials=%d want 1", egress.dials)
	}
	if !relay.CloseFlow(id) {
		t.Fatal("CloseFlow returned false")
	}
	if !egress.lastClosed() {
		t.Fatal("packet conn was not closed")
	}
	if err := relay.HandlePacket(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if egress.dials != 2 {
		t.Fatalf("dials=%d want 2 after reopen", egress.dials)
	}
}

type udpRelayEgress struct {
	id     L3Identity
	pc     net.PacketConn
	remote netip.AddrPort
}

func (e *udpRelayEgress) DialTCP(context.Context, L3Identity) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (e *udpRelayEgress) DialUDP(_ context.Context, id L3Identity) (net.PacketConn, netip.AddrPort, error) {
	e.id = id
	return e.pc, e.remote, nil
}

type scriptedPacketConn struct {
	mu        sync.Mutex
	wrote     []byte
	writeAddr net.Addr
	reply     []byte
	replied   bool
	closed    bool
}

func newScriptedPacketConn(reply []byte) *scriptedPacketConn {
	return &scriptedPacketConn{reply: reply}
}

func (c *scriptedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.replied {
		return 0, nil, io.EOF
	}
	c.replied = true
	return copy(p, c.reply), &net.UDPAddr{IP: net.ParseIP("198.51.100.53"), Port: 53}, nil
}

func (c *scriptedPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wrote = append([]byte(nil), p...)
	c.writeAddr = addr
	return len(p), nil
}

func (c *scriptedPacketConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}
func (c *scriptedPacketConn) writeSnapshot() ([]byte, net.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.wrote...), c.writeAddr
}
func (c *scriptedPacketConn) LocalAddr() net.Addr              { return fakeAddr("scripted") }
func (c *scriptedPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedPacketConn) SetWriteDeadline(time.Time) error { return nil }

type writeCaptureDevice struct {
	writes chan []byte
}

func (d *writeCaptureDevice) Read([]byte) (int, error) { return 0, io.EOF }
func (d *writeCaptureDevice) Write(p []byte) (int, error) {
	if d.writes != nil {
		d.writes <- append([]byte(nil), p...)
	}
	return len(p), nil
}
func (d *writeCaptureDevice) Close() error { return nil }
func (d *writeCaptureDevice) Name() string { return "capture0" }
func (d *writeCaptureDevice) MTU() int     { return 1500 }

type countingUDPEgress struct {
	dials  int
	remote netip.AddrPort
	last   *idlePacketConn
}

func (e *countingUDPEgress) DialTCP(context.Context, L3Identity) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (e *countingUDPEgress) DialUDP(context.Context, L3Identity) (net.PacketConn, netip.AddrPort, error) {
	e.dials++
	e.last = newIdlePacketConn()
	return e.last, e.remote, nil
}

func (e *countingUDPEgress) lastClosed() bool {
	if e.last == nil {
		return false
	}
	e.last.mu.Lock()
	defer e.last.mu.Unlock()
	return e.last.closed
}

type idlePacketConn struct {
	mu       sync.Mutex
	closed   bool
	closedCh chan struct{}
}

func newIdlePacketConn() *idlePacketConn {
	return &idlePacketConn{closedCh: make(chan struct{})}
}

func (c *idlePacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	<-c.closedCh
	return 0, nil, io.EOF
}

func (c *idlePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (c *idlePacketConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.closedCh)
	}
	return nil
}
func (c *idlePacketConn) LocalAddr() net.Addr              { return fakeAddr("idle") }
func (c *idlePacketConn) SetDeadline(time.Time) error      { return nil }
func (c *idlePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *idlePacketConn) SetWriteDeadline(time.Time) error { return nil }
