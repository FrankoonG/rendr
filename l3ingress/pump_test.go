package l3ingress

import (
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

func TestPumpRequiresDeviceAndHandler(t *testing.T) {
	if err := (&Pump{}).Run(context.Background()); err == nil {
		t.Fatal("nil device accepted")
	}
	if err := (&Pump{Device: &fakeDevice{}}).Run(context.Background()); err == nil {
		t.Fatal("nil handler accepted")
	}
}

type fakeDevice struct {
	packets [][]byte
	mtu     int
	closed  bool
}

func (d *fakeDevice) Read(p []byte) (int, error) {
	if len(d.packets) == 0 {
		return 0, io.EOF
	}
	next := d.packets[0]
	d.packets = d.packets[1:]
	return copy(p, next), nil
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
