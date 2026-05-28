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
