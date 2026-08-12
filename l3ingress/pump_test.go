package l3ingress

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
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
			return nil
		}),
	}
	err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("Run err=%v", err)
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

func TestPumpRealHandlerFailureDoesNotStopSharedIngress(t *testing.T) {
	icmp := ipv4Packet(1, [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, 0, 0)
	id := L3Identity{
		Proto: ProtocolUDP, SrcIP: netip.MustParseAddr("192.0.2.1"), SrcPort: 40000,
		DstIP: netip.MustParseAddr("192.0.2.53"), DstPort: 53,
	}
	udp := mustBuildUDPPacket(t, id, []byte("query-after-failure"))
	pc := newScriptedPacketConn(nil)
	registry := NewEgressRegistry()
	if err := registry.Register("dns", &udpRelayEgress{
		pc: pc, remote: netip.MustParseAddrPort("192.0.2.53:53"),
	}); err != nil {
		t.Fatal(err)
	}
	relay := &UDPFlowRelay{Device: &writeCaptureDevice{}, Egresses: registry}
	defer relay.Close()
	failures := make(chan PacketFailure, 1)
	pump := &Pump{
		Device: &fakeDevice{packets: [][]byte{icmp, udp}},
		Router: func(context.Context, FlowMeta) (FlowDecision, error) {
			return FlowDecision{Egress: "dns"}, nil
		},
		Handler: relay,
		OnPacketFailure: func(failure PacketFailure) {
			failures <- failure
		},
	}
	if err := pump.Run(context.Background()); err != nil {
		t.Fatalf("Run stopped on flow-local failure: %v", err)
	}

	select {
	case failure := <-failures:
		if failure.Stage != PacketFailureHandle {
			t.Fatalf("failure stage=%q want %q", failure.Stage, PacketFailureHandle)
		}
		if failure.Event.Meta.Identity.Proto != ProtocolICMP || failure.Err == nil {
			t.Fatalf("failure evidence=%+v", failure)
		}
	case <-time.After(time.Second):
		t.Fatal("handler failure was not observable")
	}
	wrote, _ := pc.writeSnapshot()
	if string(wrote) != "query-after-failure" {
		t.Fatalf("subsequent UDP payload=%q", wrote)
	}
	status := pump.Status()
	if status.PacketFailures != 1 || !status.HasLastFailure || status.LastFailure.Err == nil {
		t.Fatalf("status=%+v", status)
	}
	if status.LastFailure.Event.Meta.Identity.Proto != ProtocolICMP {
		t.Fatalf("last failure protocol=%v want ICMP", status.LastFailure.Event.Meta.Identity.Proto)
	}
}

func TestPumpRealDialFailureDoesNotStopSharedIngress(t *testing.T) {
	failedID := L3Identity{
		Proto: ProtocolUDP, SrcIP: netip.MustParseAddr("192.0.2.1"), SrcPort: 40000,
		DstIP: netip.MustParseAddr("192.0.2.53"), DstPort: 53,
	}
	validID := failedID
	validID.SrcPort++
	failedPacket := mustBuildUDPPacket(t, failedID, []byte("missing-egress"))
	validPacket := mustBuildUDPPacket(t, validID, []byte("query-after-dial-failure"))
	pc := newScriptedPacketConn(nil)
	registry := NewEgressRegistry()
	if err := registry.Register("dns", &udpRelayEgress{
		pc: pc, remote: netip.MustParseAddrPort("192.0.2.53:53"),
	}); err != nil {
		t.Fatal(err)
	}
	relay := &UDPFlowRelay{Device: &writeCaptureDevice{}, Egresses: registry}
	defer relay.Close()
	pump := &Pump{
		Device: &fakeDevice{packets: [][]byte{failedPacket, validPacket}},
		Router: func(_ context.Context, flow FlowMeta) (FlowDecision, error) {
			if flow.L3Identity == failedID {
				return FlowDecision{Egress: "missing"}, nil
			}
			return FlowDecision{Egress: "dns"}, nil
		},
		Handler: relay,
	}
	if err := pump.Run(context.Background()); err != nil {
		t.Fatalf("Run stopped on dial failure: %v", err)
	}
	wrote, _ := pc.writeSnapshot()
	if string(wrote) != "query-after-dial-failure" {
		t.Fatalf("subsequent UDP payload=%q", wrote)
	}
	status := pump.Status()
	reason, ok := EgressErrorReasonOf(status.LastFailure.Err)
	if status.PacketFailures != 1 || status.LastFailure.Stage != PacketFailureHandle ||
		!ok || reason != ReasonEgressNotFound {
		t.Fatalf("status=%+v reason=%q ok=%v", status, reason, ok)
	}
}

func TestPumpFlowCapacityFailureIsPacketLocal(t *testing.T) {
	first := ipv4Packet(17, [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, 10001, 53)
	overCapacity := ipv4Packet(17, [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, 10002, 53)
	table := NewFlowTable(nil, FlowTableOptions{ActiveCapacity: 1})
	var handled int
	pump := &Pump{
		Device:    &fakeDevice{packets: [][]byte{first, overCapacity, first}},
		FlowTable: table,
		Handler: PacketHandlerFunc(func(context.Context, PacketEvent) error {
			handled++
			return nil
		}),
	}
	if err := pump.Run(context.Background()); err != nil {
		t.Fatalf("Run stopped on flow table capacity: %v", err)
	}
	if handled != 2 {
		t.Fatalf("handled=%d want 2", handled)
	}
	status := pump.Status()
	if status.PacketFailures != 1 || status.LastFailure.Stage != PacketFailureResolve ||
		!errors.Is(status.LastFailure.Err, ErrFlowTableFull) {
		t.Fatalf("status=%+v", status)
	}
}

func TestPumpFailureObserverIsResourceBoundedWhenBlocked(t *testing.T) {
	const failureCount = 2048
	packet := ipv4Packet(17, [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, 10001, 53)
	packets := make([][]byte, failureCount)
	for i := range packets {
		packets[i] = packet
	}
	wantErr := errors.New("flow unavailable")
	observerEntered := make(chan struct{})
	releaseObserver := make(chan struct{})
	observerDone := make(chan struct{})
	var observerCalls atomic.Int32
	pump := &Pump{
		Device: &fakeDevice{packets: packets},
		Handler: PacketHandlerFunc(func(context.Context, PacketEvent) error {
			return wantErr
		}),
		OnPacketFailure: func(PacketFailure) {
			observerCalls.Add(1)
			close(observerEntered)
			<-releaseObserver
			close(observerDone)
		},
	}
	if err := pump.Run(context.Background()); err != nil {
		t.Fatalf("Run blocked on failure observer: %v", err)
	}
	select {
	case <-observerEntered:
	case <-time.After(time.Second):
		t.Fatal("failure observer never ran")
	}
	status := pump.Status()
	if status.PacketFailures != failureCount {
		t.Fatalf("packet failures=%d want %d", status.PacketFailures, failureCount)
	}
	if status.ObserverDrops != failureCount-1 {
		t.Fatalf("observer drops=%d want %d", status.ObserverDrops, failureCount-1)
	}
	if observerCalls.Load() != 1 {
		t.Fatalf("observer calls=%d want 1", observerCalls.Load())
	}
	if !errors.Is(status.LastFailure.Err, wantErr) {
		t.Fatalf("last failure=%v want %v", status.LastFailure.Err, wantErr)
	}
	close(releaseObserver)
	select {
	case <-observerDone:
	case <-time.After(time.Second):
		t.Fatal("failure observer did not exit after release")
	}
}

func TestPumpFailureObserverPanicCannotKillPump(t *testing.T) {
	packet := ipv4Packet(17, [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, 10001, 53)
	wantErr := errors.New("first packet rejected")
	observerDone := make(chan struct{})
	var handled atomic.Int32
	pump := &Pump{
		Device: &fakeDevice{packets: [][]byte{packet, packet}},
		Handler: PacketHandlerFunc(func(context.Context, PacketEvent) error {
			if handled.Add(1) == 1 {
				return wantErr
			}
			return nil
		}),
	}
	pump.OnPacketFailure = func(failure PacketFailure) {
		defer close(observerDone)
		_ = pump.Status()
		failure.Event.Packet[0] = 0
		panic("hostile observer")
	}
	if err := pump.Run(context.Background()); err != nil {
		t.Fatalf("Run stopped after observer panic: %v", err)
	}
	if handled.Load() != 2 {
		t.Fatalf("handled=%d want 2", handled.Load())
	}
	select {
	case <-observerDone:
	case <-time.After(time.Second):
		t.Fatal("failure observer never ran")
	}
	deadline := time.Now().Add(time.Second)
	for {
		status := pump.Status()
		if status.ObserverPanics == 1 {
			if got := status.LastFailure.Event.Packet[0] >> 4; got != 4 {
				t.Fatalf("observer mutated retained evidence IP version=%d", got)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("observer panic was not recorded: %+v", status)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestPumpContextCancellationWinsOverHandlerFailure(t *testing.T) {
	packet := ipv4Packet(17, [4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, 10001, 53)
	ctx, cancel := context.WithCancel(context.Background())
	pump := &Pump{
		Device: &fakeDevice{packets: [][]byte{packet, packet}},
		Handler: PacketHandlerFunc(func(context.Context, PacketEvent) error {
			cancel()
			return errors.New("flow failed while canceling")
		}),
	}
	if err := pump.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error=%v want context.Canceled", err)
	}
	if status := pump.Status(); status.PacketFailures != 0 {
		t.Fatalf("cancellation recorded as packet failure: %+v", status)
	}
}

func TestPumpDeviceReadFailureIsTerminal(t *testing.T) {
	wantErr := errors.New("device read failed")
	pump := &Pump{
		Device: &fakeDevice{terminalErr: wantErr},
		Handler: PacketHandlerFunc(func(context.Context, PacketEvent) error {
			t.Fatal("handler ran without a packet")
			return nil
		}),
	}
	if err := pump.Run(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("Run error=%v want %v", err, wantErr)
	}
}

func TestPumpExplicitDeviceCloseIsTerminal(t *testing.T) {
	device := newCloseBlockingDevice()
	pump := &Pump{
		Device: device,
		Handler: PacketHandlerFunc(func(context.Context, PacketEvent) error {
			t.Fatal("handler ran without a packet")
			return nil
		}),
	}
	done := make(chan error, 1)
	go func() { done <- pump.Run(context.Background()) }()
	select {
	case <-device.started:
	case <-time.After(time.Second):
		t.Fatal("Pump never entered device read")
	}
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Run error=%v want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Pump did not stop after explicit device close")
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
			return nil
		}),
	}
	if err := pump.Run(context.Background()); err != nil {
		t.Fatalf("Run error=%v", err)
	}
	if len(device.readSizes) != 3 || device.readSizes[0] != device.mtu ||
		device.readSizes[1] != defaultReadBufferSize || device.readSizes[2] != defaultReadBufferSize {
		t.Fatalf("read buffer sizes=%v want [%d %d %d]", device.readSizes, device.mtu,
			defaultReadBufferSize, defaultReadBufferSize)
	}
}

type fakeDevice struct {
	packets     [][]byte
	mtu         int
	closed      bool
	terminalErr error
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

type closeBlockingDevice struct {
	started   chan struct{}
	closed    chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
}

func newCloseBlockingDevice() *closeBlockingDevice {
	return &closeBlockingDevice{started: make(chan struct{}), closed: make(chan struct{})}
}

func (d *closeBlockingDevice) Read([]byte) (int, error) {
	return d.ReadContext(context.Background(), nil)
}

func (d *closeBlockingDevice) ReadContext(ctx context.Context, _ []byte) (int, error) {
	d.startOnce.Do(func() { close(d.started) })
	select {
	case <-d.closed:
		return 0, net.ErrClosed
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (*closeBlockingDevice) Write(p []byte) (int, error) { return len(p), nil }
func (d *closeBlockingDevice) Close() error {
	d.closeOnce.Do(func() { close(d.closed) })
	return nil
}
func (*closeBlockingDevice) Name() string { return "close-blocking0" }
func (*closeBlockingDevice) MTU() int     { return 1500 }

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
		if d.terminalErr != nil {
			return 0, d.terminalErr
		}
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
