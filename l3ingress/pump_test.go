package l3ingress

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"
)

func TestPumpRoutesParsedPackets(t *testing.T) {
	packet := ipv4Packet(6, [4]byte{10, 0, 0, 1}, [4]byte{198, 51, 100, 9}, 1234, 443)
	dev := &fakeDevice{packets: [][]byte{packet}}
	fixed := time.Unix(100, 200)
	var routed FlowMeta
	var got PacketEvent
	p := &Pump{
		Device: dev,
		Now:    func() time.Time { return fixed },
		Router: func(_ context.Context, flow FlowMeta) (FlowDecision, error) {
			routed = flow
			return FlowDecision{Peer: "peer-a", Egress: "direct"}, nil
		},
		Handler: PacketHandlerFunc(func(_ context.Context, ev PacketEvent) error {
			got = ev
			return io.EOF
		}),
	}
	err := p.Run(context.Background())
	if !errors.Is(err, io.EOF) {
		t.Fatalf("Run err=%v want io.EOF", err)
	}
	wantID := L3Identity{
		Proto:   ProtocolTCP,
		SrcIP:   netip.MustParseAddr("10.0.0.1"),
		SrcPort: 1234,
		DstIP:   netip.MustParseAddr("198.51.100.9"),
		DstPort: 443,
	}
	if routed.L3Identity != wantID {
		t.Fatalf("router identity=%+v want %+v", routed.L3Identity, wantID)
	}
	if !routed.CreatedAt.Equal(fixed) || routed.Direction != DirectionIngress {
		t.Fatalf("router flow meta=%+v", routed)
	}
	if got.Flow.L3Identity != wantID || !got.Decided || got.Decision.Peer != "peer-a" || got.Decision.Egress != "direct" {
		t.Fatalf("event=%+v", got)
	}
	if len(got.Packet) == 0 || &got.Packet[0] == &packet[0] {
		t.Fatal("event packet was not copied")
	}
}

func TestPumpSkipsParseErrors(t *testing.T) {
	good := ipv4Packet(17, [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, 5353, 53000)
	dev := &fakeDevice{packets: [][]byte{{0x45, 0}, good}}
	var parseErrs int
	var handled int
	p := &Pump{
		Device: dev,
		OnParseError: func(packet []byte, err error) {
			parseErrs++
			if len(packet) != 2 {
				t.Fatalf("bad parse packet copy len=%d", len(packet))
			}
		},
		Handler: PacketHandlerFunc(func(context.Context, PacketEvent) error {
			handled++
			return nil
		}),
	}
	if err := p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if parseErrs != 1 || handled != 1 {
		t.Fatalf("parseErrs=%d handled=%d want 1/1", parseErrs, handled)
	}
}

func TestPumpCachesRouterDecisionPerFlow(t *testing.T) {
	packet := ipv4Packet(6, [4]byte{10, 0, 0, 1}, [4]byte{198, 51, 100, 9}, 1234, 443)
	dev := &fakeDevice{packets: [][]byte{packet, packet}}
	fixed := time.Unix(100, 0)
	var routerCalls int
	var handled []PacketEvent
	p := &Pump{
		Device: dev,
		Now:    func() time.Time { return fixed },
		Router: func(_ context.Context, flow FlowMeta) (FlowDecision, error) {
			routerCalls++
			return FlowDecision{Peer: "peer-a"}, nil
		},
		Handler: PacketHandlerFunc(func(_ context.Context, ev PacketEvent) error {
			handled = append(handled, ev)
			return nil
		}),
	}
	if err := p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if routerCalls != 1 {
		t.Fatalf("routerCalls=%d want 1", routerCalls)
	}
	if len(handled) != 2 {
		t.Fatalf("handled=%d want 2", len(handled))
	}
	if !handled[0].Flow.CreatedAt.Equal(fixed) || !handled[1].Flow.CreatedAt.Equal(fixed) {
		t.Fatalf("flow CreatedAt not stable: %+v %+v", handled[0].Flow, handled[1].Flow)
	}
	if !handled[0].Decided || !handled[1].Decided || handled[1].Decision.Peer != "peer-a" {
		t.Fatalf("events not decided from cache: %+v", handled)
	}
}

func TestPumpUsesProvidedFlowTable(t *testing.T) {
	packet := ipv4Packet(17, [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, 5353, 53000)
	id := L3Identity{
		Proto:   ProtocolUDP,
		SrcIP:   netip.MustParseAddr("192.0.2.1"),
		SrcPort: 5353,
		DstIP:   netip.MustParseAddr("192.0.2.2"),
		DstPort: 53000,
	}
	table := NewFlowTable(func(context.Context, FlowMeta) (FlowDecision, error) {
		return FlowDecision{Peer: "peer-b", Egress: "vpn"}, nil
	}, FlowTableOptions{})
	p := &Pump{
		Device:    &fakeDevice{packets: [][]byte{packet}},
		FlowTable: table,
		Router: func(context.Context, FlowMeta) (FlowDecision, error) {
			t.Fatal("Pump Router should not run when FlowTable is provided")
			return FlowDecision{}, nil
		},
		Handler: PacketHandlerFunc(func(_ context.Context, ev PacketEvent) error {
			if ev.Decision.Peer != "peer-b" || ev.Decision.Egress != "vpn" {
				t.Fatalf("event decision=%+v", ev.Decision)
			}
			return nil
		}),
	}
	if err := p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	snapshot, ok := table.Snapshot(id)
	if !ok {
		t.Fatal("flow not tracked")
	}
	if snapshot.Packets != 1 || snapshot.Bytes != uint64(len(packet)) {
		t.Fatalf("snapshot stats=%+v", snapshot)
	}
}

func TestPumpClosesFlowTableOnTCPReset(t *testing.T) {
	packet := ipv4Packet(6, [4]byte{10, 0, 0, 1}, [4]byte{198, 51, 100, 9}, 1234, 443)
	reset := append([]byte(nil), packet...)
	reset[33] = TCPFlagRST
	id := L3Identity{
		Proto:   ProtocolTCP,
		SrcIP:   netip.MustParseAddr("10.0.0.1"),
		SrcPort: 1234,
		DstIP:   netip.MustParseAddr("198.51.100.9"),
		DstPort: 443,
	}
	table := NewFlowTable(func(context.Context, FlowMeta) (FlowDecision, error) {
		return FlowDecision{Peer: "peer-a"}, nil
	}, FlowTableOptions{})
	var handled int
	p := &Pump{
		Device:    &fakeDevice{packets: [][]byte{packet, reset}},
		FlowTable: table,
		Handler: PacketHandlerFunc(func(_ context.Context, ev PacketEvent) error {
			handled++
			return nil
		}),
	}
	if err := p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if handled != 2 {
		t.Fatalf("handled=%d want 2", handled)
	}
	if _, ok := table.Snapshot(id); ok {
		t.Fatal("reset flow still active")
	}
	closed, ok := table.ClosedSnapshot(id)
	if !ok {
		t.Fatal("reset flow not closed")
	}
	if closed.CloseReason != FlowCloseTCPRST || closed.Packets != 2 {
		t.Fatalf("closed snapshot=%+v", closed)
	}
}

func TestPumpSkipsDeniedFlow(t *testing.T) {
	packet := ipv4Packet(17, [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, 5353, 53000)
	id := L3Identity{
		Proto:   ProtocolUDP,
		SrcIP:   netip.MustParseAddr("192.0.2.1"),
		SrcPort: 5353,
		DstIP:   netip.MustParseAddr("192.0.2.2"),
		DstPort: 53000,
	}
	table := NewFlowTable(func(context.Context, FlowMeta) (FlowDecision, error) {
		return FlowDecision{Deny: true, DenyReason: "cidr_blocked"}, nil
	}, FlowTableOptions{})
	var handled int
	p := &Pump{
		Device:    &fakeDevice{packets: [][]byte{packet, packet}},
		FlowTable: table,
		Handler: PacketHandlerFunc(func(context.Context, PacketEvent) error {
			handled++
			return nil
		}),
	}
	if err := p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if handled != 0 {
		t.Fatalf("handled=%d want 0", handled)
	}
	snapshot, ok := table.Snapshot(id)
	if !ok {
		t.Fatal("denied flow was not tracked")
	}
	if !snapshot.Decision.Deny || snapshot.Decision.DenyReason != "cidr_blocked" {
		t.Fatalf("snapshot decision=%+v", snapshot.Decision)
	}
	if snapshot.Packets != 2 {
		t.Fatalf("snapshot packets=%d want 2", snapshot.Packets)
	}
}

func TestPumpRequiresDeviceAndHandler(t *testing.T) {
	if err := (&Pump{}).Run(context.Background()); err == nil {
		t.Fatal("nil device accepted")
	}
	if err := (&Pump{Device: &fakeDevice{}}).Run(context.Background()); err == nil {
		t.Fatal("nil handler accepted")
	}
}

func TestPumpCancelsContextReaderWithoutClosingDevice(t *testing.T) {
	device := &contextDevice{started: make(chan struct{})}
	pump := &Pump{
		Device: device,
		Handler: PacketHandlerFunc(func(context.Context, PacketEvent) error {
			t.Fatal("handler ran without a packet")
			return nil
		}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- pump.Run(ctx) }()
	select {
	case <-device.started:
	case <-time.After(time.Second):
		t.Fatal("Pump did not use ContextReader")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run error=%v want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Pump did not stop after context cancellation")
	}
	if device.closed {
		t.Fatal("Pump closed device while canceling ContextReader")
	}
}

func TestPumpRetriesRetainedPacketAfterShortBuffer(t *testing.T) {
	packet, err := BuildUDPPacket(L3Identity{
		Proto: ProtocolUDP,
		SrcIP: netip.MustParseAddr("192.0.2.1"), SrcPort: 1234,
		DstIP: netip.MustParseAddr("192.0.2.2"), DstPort: 4321,
	}, bytes.Repeat([]byte{0xa5}, 1800))
	if err != nil {
		t.Fatal(err)
	}
	device := &retainedPacketDevice{packet: packet, mtu: 1280}
	pump := &Pump{
		Device: device,
		Handler: PacketHandlerFunc(func(_ context.Context, event PacketEvent) error {
			if !bytes.Equal(event.Packet, packet) {
				t.Fatalf("packet changed across short-buffer retry: got=%d want=%d", len(event.Packet), len(packet))
			}
			return io.EOF
		}),
	}
	if err := pump.Run(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("Run error=%v want handler io.EOF", err)
	}
	if len(device.readSizes) != 2 || device.readSizes[0] != device.mtu || device.readSizes[1] != defaultReadBufferSize {
		t.Fatalf("read buffer sizes=%v want [%d %d]", device.readSizes, device.mtu, defaultReadBufferSize)
	}
}

type fakeDevice struct {
	packets [][]byte
	mtu     int
	closed  bool
}

type contextDevice struct {
	fakeDevice
	started chan struct{}
}

type retainedPacketDevice struct {
	packet    []byte
	mtu       int
	delivered bool
	readSizes []int
}

func (d *retainedPacketDevice) Read(p []byte) (int, error) {
	return d.ReadContext(context.Background(), p)
}

func (d *retainedPacketDevice) ReadContext(ctx context.Context, p []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	d.readSizes = append(d.readSizes, len(p))
	if d.delivered {
		return 0, io.EOF
	}
	if len(p) < len(d.packet) {
		return 0, io.ErrShortBuffer
	}
	d.delivered = true
	return copy(p, d.packet), nil
}

func (*retainedPacketDevice) Write(p []byte) (int, error) { return len(p), nil }
func (*retainedPacketDevice) Close() error                { return nil }
func (*retainedPacketDevice) Name() string                { return "retained0" }
func (d *retainedPacketDevice) MTU() int                  { return d.mtu }

func (d *contextDevice) ReadContext(ctx context.Context, _ []byte) (int, error) {
	close(d.started)
	<-ctx.Done()
	return 0, ctx.Err()
}

func (d *fakeDevice) Read(p []byte) (int, error) {
	if len(d.packets) == 0 {
		return 0, io.EOF
	}
	next := d.packets[0]
	d.packets = d.packets[1:]
	return copy(p, next), nil
}

func (d *fakeDevice) ReadContext(ctx context.Context, p []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return d.Read(p)
}

func (d *fakeDevice) Write(p []byte) (int, error) { return len(p), nil }
func (d *fakeDevice) Close() error {
	d.closed = true
	return nil
}
func (d *fakeDevice) Name() string { return "fake0" }
func (d *fakeDevice) MTU() int {
	if d.mtu != 0 {
		return d.mtu
	}
	return 1500
}
