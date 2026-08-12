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

func TestUDPFlowRelayRejectsPacketsAfterClose(t *testing.T) {
	id := L3Identity{
		Proto: ProtocolUDP, SrcIP: netip.MustParseAddr("10.0.0.2"), SrcPort: 40000,
		DstIP: netip.MustParseAddr("198.51.100.53"), DstPort: 53,
	}
	packet := mustBuildUDPPacket(t, id, []byte("query"))
	meta, err := ParsePacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	egress := &countingUDPEgress{remote: netip.MustParseAddrPort("198.51.100.53:53")}
	registry := NewEgressRegistry()
	if err := registry.Register("dns-egress", egress); err != nil {
		t.Fatal(err)
	}
	relay := &UDPFlowRelay{Device: &writeCaptureDevice{}, Egresses: registry}
	if err := relay.Close(); err != nil {
		t.Fatal(err)
	}
	err = relay.HandlePacket(context.Background(), PacketEvent{
		Packet: packet, Meta: meta, Flow: FlowMeta{L3Identity: id, Direction: DirectionIngress},
		Decision: FlowDecision{Egress: "dns-egress"}, Decided: true,
	})
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("HandlePacket after Close error=%v, want %v", err, net.ErrClosed)
	}
	if egress.dials != 0 {
		t.Fatalf("HandlePacket after Close dialed egress %d times", egress.dials)
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

func TestUDPFlowRelayDropsRepliesFromUnexpectedSource(t *testing.T) {
	id := L3Identity{
		Proto: ProtocolUDP, SrcIP: netip.MustParseAddr("10.0.0.2"), SrcPort: 40000,
		DstIP: netip.MustParseAddr("198.51.100.53"), DstPort: 53,
	}
	packet := mustBuildUDPPacket(t, id, []byte("query"))
	meta, err := ParsePacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	pc := &sourceScriptPacketConn{reads: []sourceScriptRead{
		{payload: []byte("injected"), source: netip.MustParseAddrPort("203.0.113.9:53")},
		{payload: []byte("answer"), source: netip.MustParseAddrPort("198.51.100.53:53")},
	}}
	reg := NewEgressRegistry()
	if err := reg.Register("dns-egress", &udpRelayEgress{
		pc: pc, remote: netip.MustParseAddrPort("198.51.100.53:53"),
	}); err != nil {
		t.Fatal(err)
	}
	device := &writeCaptureDevice{writes: make(chan []byte, 2)}
	relay := &UDPFlowRelay{Device: device, Egresses: reg}
	defer relay.Close()
	if err := relay.HandlePacket(context.Background(), PacketEvent{
		Packet: packet, Meta: meta, Flow: FlowMeta{L3Identity: id, Direction: DirectionIngress},
		Decision: FlowDecision{Egress: "dns-egress"}, Decided: true,
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case reply := <-device.writes:
		replyMeta, err := ParsePacket(reply)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := UDPPayload(reply, replyMeta)
		if err != nil {
			t.Fatal(err)
		}
		if string(payload) != "answer" {
			t.Fatalf("forwarded payload=%q want trusted answer", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("trusted reply was not forwarded")
	}
	select {
	case reply := <-device.writes:
		t.Fatalf("unexpected-source reply was relabeled and forwarded: %x", reply)
	default:
	}
}

func TestUDPFlowRelayContextCancellationClosesIdleSession(t *testing.T) {
	id := L3Identity{
		Proto: ProtocolUDP, SrcIP: netip.MustParseAddr("10.0.0.2"), SrcPort: 40000,
		DstIP: netip.MustParseAddr("198.51.100.53"), DstPort: 53,
	}
	packet := mustBuildUDPPacket(t, id, []byte("query"))
	meta, err := ParsePacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	egress := &countingUDPEgress{remote: netip.MustParseAddrPort("198.51.100.53:53")}
	registry := NewEgressRegistry()
	if err := registry.Register("dns-egress", egress); err != nil {
		t.Fatal(err)
	}
	relay := &UDPFlowRelay{Device: &writeCaptureDevice{}, Egresses: registry}
	ctx, cancel := context.WithCancel(context.Background())
	if err := relay.HandlePacket(ctx, PacketEvent{
		Packet: packet, Meta: meta, Flow: FlowMeta{L3Identity: id, Direction: DirectionIngress},
		Decision: FlowDecision{Egress: "dns-egress"}, Decided: true,
	}); err != nil {
		t.Fatal(err)
	}
	cancel()
	deadline := time.Now().Add(time.Second)
	for {
		relay.mu.Lock()
		_, present := relay.sessions[id]
		relay.mu.Unlock()
		if !present && egress.lastClosed() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("canceled idle session present=%v socket_closed=%v", present, egress.lastClosed())
		}
		time.Sleep(time.Millisecond)
	}
	if err := relay.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestUDPFlowRelayContextCancellationUnblocksDeviceWrite(t *testing.T) {
	id := L3Identity{
		Proto: ProtocolUDP, SrcIP: netip.MustParseAddr("10.0.0.2"), SrcPort: 40001,
		DstIP: netip.MustParseAddr("198.51.100.53"), DstPort: 53,
	}
	packet := mustBuildUDPPacket(t, id, []byte("query"))
	meta, err := ParsePacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	pc := newScriptedPacketConn([]byte("answer"))
	registry := NewEgressRegistry()
	if err := registry.Register("dns-egress", &udpRelayEgress{
		pc: pc, remote: netip.MustParseAddrPort("198.51.100.53:53"),
	}); err != nil {
		t.Fatal(err)
	}
	device := newBlockingUDPWriteDevice()
	relay := &UDPFlowRelay{Device: device, Egresses: registry}
	ctx, cancel := context.WithCancel(context.Background())
	if err := relay.HandlePacket(ctx, PacketEvent{
		Packet: packet, Meta: meta, Flow: FlowMeta{L3Identity: id, Direction: DirectionIngress},
		Decision: FlowDecision{Egress: "dns-egress"}, Decided: true,
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-device.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("reply loop never entered device WriteContext")
	}
	cancel()
	deadline := time.Now().Add(time.Second)
	for {
		relay.mu.Lock()
		_, present := relay.sessions[id]
		relay.mu.Unlock()
		pc.mu.Lock()
		closed := pc.closed
		pc.mu.Unlock()
		if !present && closed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("canceled blocked write retained session/socket: present=%v closed=%v", present, closed)
		}
		time.Sleep(time.Millisecond)
	}
	if err := relay.Close(); err != nil {
		t.Fatal(err)
	}
}

type udpRelayEgress struct {
	id     L3Identity
	pc     net.PacketConn
	remote netip.AddrPort
}

func (e *udpRelayEgress) DialTCP(context.Context, L3Identity) (TCPConn, error) {
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

type sourceScriptRead struct {
	payload []byte
	source  netip.AddrPort
}

type sourceScriptPacketConn struct {
	mu     sync.Mutex
	reads  []sourceScriptRead
	closed bool
}

func (c *sourceScriptPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || len(c.reads) == 0 {
		return 0, nil, io.EOF
	}
	next := c.reads[0]
	c.reads = c.reads[1:]
	return copy(p, next.payload), net.UDPAddrFromAddrPort(next.source), nil
}

func (c *sourceScriptPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (c *sourceScriptPacketConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}
func (*sourceScriptPacketConn) LocalAddr() net.Addr              { return fakeAddr("source-script") }
func (*sourceScriptPacketConn) SetDeadline(time.Time) error      { return nil }
func (*sourceScriptPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*sourceScriptPacketConn) SetWriteDeadline(time.Time) error { return nil }

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
func (d *writeCaptureDevice) WriteContext(ctx context.Context, p []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return d.Write(p)
}
func (d *writeCaptureDevice) Close() error { return nil }
func (d *writeCaptureDevice) Name() string { return "capture0" }
func (d *writeCaptureDevice) MTU() int     { return 1500 }

type blockingUDPWriteDevice struct {
	writeStarted chan struct{}
	startOnce    sync.Once
}

func newBlockingUDPWriteDevice() *blockingUDPWriteDevice {
	return &blockingUDPWriteDevice{writeStarted: make(chan struct{})}
}

func (*blockingUDPWriteDevice) Read([]byte) (int, error) { return 0, io.EOF }
func (*blockingUDPWriteDevice) Write([]byte) (int, error) {
	panic("UDP relay bypassed WriteContext")
}
func (d *blockingUDPWriteDevice) WriteContext(ctx context.Context, _ []byte) (int, error) {
	d.startOnce.Do(func() { close(d.writeStarted) })
	<-ctx.Done()
	return 0, ctx.Err()
}
func (*blockingUDPWriteDevice) Close() error { return nil }
func (*blockingUDPWriteDevice) Name() string { return "blocking0" }
func (*blockingUDPWriteDevice) MTU() int     { return 1500 }

type countingUDPEgress struct {
	dials  int
	remote netip.AddrPort
	last   *idlePacketConn
}

func (e *countingUDPEgress) DialTCP(context.Context, L3Identity) (TCPConn, error) {
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
