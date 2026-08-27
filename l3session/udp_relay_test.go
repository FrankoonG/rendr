package l3session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
)

func TestUDPRelayForwardsPayloadThroughRendrPacketSession(t *testing.T) {
	ln := newTestPacketSessionListener(t, "udpflow")
	defer ln.Close()

	accepted := make(chan rendr.PacketConn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pc, err := ln.AcceptPacket(ctx)
		if err != nil {
			t.Errorf("accept packet: %v", err)
			return
		}
		accepted <- pc
	}()

	id := l3ingress.L3Identity{
		Proto:   l3ingress.ProtocolUDP,
		SrcIP:   netip.MustParseAddr("10.0.0.2"),
		SrcPort: 40000,
		DstIP:   netip.MustParseAddr("198.51.100.53"),
		DstPort: 53,
	}
	packet, err := l3ingress.BuildUDPPacket(id, []byte("query"))
	if err != nil {
		t.Fatal(err)
	}
	meta, err := l3ingress.ParsePacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	root := rendr.Path("udp-a", rendr.PathSpec{Transport: "udpflow", Address: ln.Addr().String()})
	dev := &packetCaptureDevice{writes: make(chan []byte, 1)}
	relay := &UDPRelay{Device: dev}
	defer relay.Close()

	if err := relay.HandlePacket(context.Background(), l3ingress.PacketEvent{
		Packet: packet,
		Meta:   meta,
		Flow:   l3ingress.FlowMeta{L3Identity: id, Direction: l3ingress.DirectionIngress},
		Decision: l3ingress.FlowDecision{
			Peer:   "peer-a",
			Root:   root,
			Egress: "direct",
		},
		Decided: true,
	}); err != nil {
		t.Fatal(err)
	}

	server := <-accepted
	defer server.Close()
	buf := make([]byte, 256)
	n, addr, err := server.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := decodeUDPEnvelope(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Identity != id || envelope.Egress != "direct" || string(envelope.Payload) != "query" {
		t.Fatalf("server envelope=%+v want id=%s egress=direct payload=query", envelope, id)
	}
	if _, err := server.WriteTo([]byte("answer"), addr); err != nil {
		t.Fatal(err)
	}

	select {
	case reply := <-dev.writes:
		replyMeta, err := l3ingress.ParsePacket(reply)
		if err != nil {
			t.Fatal(err)
		}
		if replyMeta.Identity != id.Reverse() {
			t.Fatalf("reply identity=%+v want %+v", replyMeta.Identity, id.Reverse())
		}
		payload, err := l3ingress.UDPPayload(reply, replyMeta)
		if err != nil {
			t.Fatal(err)
		}
		if string(payload) != "answer" {
			t.Fatalf("reply payload=%q want answer", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for relay reply")
	}

	if sess, ok := relay.manager().Session(id); !ok || sess.PacketConn() == nil {
		t.Fatalf("missing packet session: ok=%v sess=%+v", ok, sess)
	}
	if !relay.CloseFlow(id) {
		t.Fatal("CloseFlow returned false")
	}
	if _, ok := relay.manager().Session(id); ok {
		t.Fatal("session remained cached after CloseFlow")
	}
}

func TestUDPRelayPreservesFlowAcrossPacketMigration(t *testing.T) {
	ln := newTestPacketSessionListener(t, "udpflow")
	defer ln.Close()

	accepted := make(chan rendr.PacketConn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pc, err := ln.AcceptPacket(ctx)
		if err != nil {
			t.Errorf("accept packet: %v", err)
			return
		}
		accepted <- pc
	}()

	id := l3ingress.L3Identity{
		Proto:   l3ingress.ProtocolUDP,
		SrcIP:   netip.MustParseAddr("10.0.0.2"),
		SrcPort: 40000,
		DstIP:   netip.MustParseAddr("198.51.100.53"),
		DstPort: 53,
	}
	root := rendr.Selector("root", []rendr.Target{
		rendr.Path("udp-a", rendr.PathSpec{Transport: "udpflow", Address: ln.Addr().String()}),
		rendr.Path("udp-b", rendr.PathSpec{Transport: "udpflow", Address: ln.Addr().String()}),
	})
	dev := &packetCaptureDevice{writes: make(chan []byte, 2)}
	relay := &UDPRelay{Device: dev}
	defer relay.Close()

	send := func(payload string) {
		t.Helper()
		packet, err := l3ingress.BuildUDPPacket(id, []byte(payload))
		if err != nil {
			t.Fatal(err)
		}
		meta, err := l3ingress.ParsePacket(packet)
		if err != nil {
			t.Fatal(err)
		}
		if err := relay.HandlePacket(context.Background(), l3ingress.PacketEvent{
			Packet: packet,
			Meta:   meta,
			Flow:   l3ingress.FlowMeta{L3Identity: id, Direction: l3ingress.DirectionIngress},
			Decision: l3ingress.FlowDecision{
				Peer:   "peer-a",
				Root:   root,
				Egress: "direct",
			},
			Decided: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	readReply := func(want string) {
		t.Helper()
		select {
		case reply := <-dev.writes:
			replyMeta, err := l3ingress.ParsePacket(reply)
			if err != nil {
				t.Fatal(err)
			}
			if replyMeta.Identity != id.Reverse() {
				t.Fatalf("reply identity=%+v want %+v", replyMeta.Identity, id.Reverse())
			}
			got, err := l3ingress.UDPPayload(reply, replyMeta)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != want {
				t.Fatalf("reply payload=%q want %q", got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for %q", want)
		}
	}

	send("one")
	server := <-accepted
	defer server.Close()
	echoPacket(t, server, id, "one", "ack-one")
	readReply("ack-one")

	sess, ok := relay.manager().Session(id)
	if !ok || sess.PacketConn() == nil {
		t.Fatalf("missing packet session: ok=%v sess=%+v", ok, sess)
	}
	admin := sess.PacketConn().(packetControl)
	_ = waitForSessionPathAttached(t, admin, "udp-b", 3*time.Second)
	if err := admin.SelectTarget("root", "udp-b"); err != nil {
		t.Fatal(err)
	}

	send("two")
	echoPacket(t, server, id, "two", "ack-two")
	readReply("ack-two")
	if admin.FlowID() != server.FlowID() {
		t.Fatalf("flow id changed across migration: client=%x server=%x", admin.FlowID(), server.FlowID())
	}
}

func TestUDPRelayContextCancellationStopsIdleReplyLoop(t *testing.T) {
	ln := newTestPacketSessionListener(t, "udpflow")
	defer ln.Close()
	accepted := make(chan rendr.PacketConn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pc, err := ln.AcceptPacket(ctx)
		if err == nil {
			accepted <- pc
		}
	}()

	id := l3ingress.L3Identity{
		Proto: l3ingress.ProtocolUDP, SrcIP: netip.MustParseAddr("10.0.0.2"), SrcPort: 40003,
		DstIP: netip.MustParseAddr("198.51.100.53"), DstPort: 53,
	}
	packet, err := l3ingress.BuildUDPPacket(id, []byte("query"))
	if err != nil {
		t.Fatal(err)
	}
	meta, err := l3ingress.ParsePacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	relay := &UDPRelay{Device: &packetCaptureDevice{}}
	defer relay.Close()
	ctx, cancel := context.WithCancel(context.Background())
	if err := relay.HandlePacket(ctx, l3ingress.PacketEvent{
		Packet: packet, Meta: meta,
		Flow: l3ingress.FlowMeta{L3Identity: id, Direction: l3ingress.DirectionIngress},
		Decision: l3ingress.FlowDecision{
			Peer: "peer-a", Egress: "direct",
			Root: rendr.Path("udp", rendr.PathSpec{Transport: "udpflow", Address: ln.Addr().String()}),
		},
		Decided: true,
	}); err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	defer server.Close()
	cancel()

	deadline := time.Now().Add(time.Second)
	for {
		_, managerPresent := relay.manager().Session(id)
		relay.mu.Lock()
		_, replyPresent := relay.sessions[id]
		_, packetPresent := relay.packets[id]
		relay.mu.Unlock()
		if !managerPresent && !replyPresent && !packetPresent {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("canceled flow remained manager/reply/packet=%v/%v/%v", managerPresent, replyPresent, packetPresent)
		}
		time.Sleep(time.Millisecond)
	}
	if err := relay.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestUDPRelayRejectsPacketsAfterClose(t *testing.T) {
	relay := &UDPRelay{Device: &packetCaptureDevice{}}
	if err := relay.Close(); err != nil {
		t.Fatal(err)
	}
	id := l3ingress.L3Identity{
		Proto: l3ingress.ProtocolUDP, SrcIP: netip.MustParseAddr("10.0.0.2"), SrcPort: 40005,
		DstIP: netip.MustParseAddr("198.51.100.53"), DstPort: 53,
	}
	packet, err := l3ingress.BuildUDPPacket(id, []byte("query"))
	if err != nil {
		t.Fatal(err)
	}
	meta, err := l3ingress.ParsePacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	err = relay.HandlePacket(context.Background(), l3ingress.PacketEvent{Packet: packet, Meta: meta})
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("HandlePacket after Close error=%v, want %v", err, net.ErrClosed)
	}
}

func TestUDPRelayCloseFlowUnblocksDeviceWrite(t *testing.T) {
	ln := newTestPacketSessionListener(t, "udpflow")
	defer ln.Close()
	accepted := make(chan rendr.PacketConn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pc, err := ln.AcceptPacket(ctx)
		if err == nil {
			accepted <- pc
		}
	}()

	id := l3ingress.L3Identity{
		Proto: l3ingress.ProtocolUDP, SrcIP: netip.MustParseAddr("10.0.0.2"), SrcPort: 40004,
		DstIP: netip.MustParseAddr("198.51.100.53"), DstPort: 53,
	}
	packet, err := l3ingress.BuildUDPPacket(id, []byte("query"))
	if err != nil {
		t.Fatal(err)
	}
	meta, err := l3ingress.ParsePacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	device := newBlockingPacketWriteDevice()
	relay := &UDPRelay{Device: device}
	defer relay.Close()
	if err := relay.HandlePacket(context.Background(), l3ingress.PacketEvent{
		Packet: packet, Meta: meta,
		Flow: l3ingress.FlowMeta{L3Identity: id, Direction: l3ingress.DirectionIngress},
		Decision: l3ingress.FlowDecision{
			Peer: "peer-a", Egress: "direct",
			Root: rendr.Path("udp", rendr.PathSpec{Transport: "udpflow", Address: ln.Addr().String()}),
		},
		Decided: true,
	}); err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	defer server.Close()
	echoPacket(t, server, id, "query", "answer")
	select {
	case <-device.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("reply loop never entered device WriteContext")
	}
	closed := make(chan bool, 1)
	go func() { closed <- relay.CloseFlow(id) }()
	select {
	case ok := <-closed:
		if !ok {
			t.Fatal("CloseFlow returned false")
		}
	case <-time.After(time.Second):
		t.Fatal("CloseFlow remained blocked behind the virtual-interface write")
	}
	if _, ok := relay.manager().Session(id); ok {
		t.Fatal("manager retained session after blocked-write cancellation")
	}
	relay.mu.Lock()
	_, replyPresent := relay.sessions[id]
	_, packetPresent := relay.packets[id]
	relay.mu.Unlock()
	if replyPresent || packetPresent {
		t.Fatalf("relay retained reply/packet state after CloseFlow=%v/%v", replyPresent, packetPresent)
	}
}

func TestUDPReplyLoopTeardownCannotForgetReplacementGeneration(t *testing.T) {
	id := l3ingress.L3Identity{
		Proto: l3ingress.ProtocolUDP, SrcIP: netip.MustParseAddr("10.0.0.2"), SrcPort: 40001,
		DstIP: netip.MustParseAddr("198.51.100.53"), DstPort: 53,
	}
	oldConn := &fakeConn{}
	newConn := &fakeConn{}
	oldSession := &Session{
		request: l3ingress.SessionRequest{Identity: id, Ref: l3ingress.FlowRef{Identity: id, Generation: 1}},
		conn:    oldConn,
	}
	newSession := &Session{
		request: l3ingress.SessionRequest{Identity: id, Ref: l3ingress.FlowRef{Identity: id, Generation: 2}},
		conn:    newConn,
	}
	manager := &Manager{sessions: map[l3ingress.L3Identity]*Session{id: newSession}}
	relay := &UDPRelay{
		Manager: manager,
		sessions: map[l3ingress.L3Identity]packetReplyLoop{
			id: {session: newSession, cancel: func() {}},
		},
		packets: map[l3ingress.L3Identity]*Session{id: newSession},
	}
	relay.fast.Store(&packetSessionCache{id: id, sess: newSession})

	relay.forgetSession(id, oldSession)
	if current, ok := manager.Session(id); !ok || current != newSession {
		t.Fatalf("stale reply loop removed replacement: current=%p ok=%v", current, ok)
	}
	if relay.packetSession(id, newSession.Request().Ref) != newSession {
		t.Fatal("stale reply loop removed replacement packet cache")
	}
	if cached := relay.fast.Load(); cached == nil || cached.sess != newSession {
		t.Fatal("stale reply loop cleared replacement fast cache")
	}
	if oldConn.closed.Load() != 1 || newConn.closed.Load() != 0 {
		t.Fatalf("close counts old/new=%d/%d", oldConn.closed.Load(), newConn.closed.Load())
	}
}

func TestUDPRelayRetiresCachedPredecessorBeforeTupleReuse(t *testing.T) {
	id := l3ingress.L3Identity{
		Proto: l3ingress.ProtocolUDP, SrcIP: netip.MustParseAddr("10.0.0.3"), SrcPort: 40002,
		DstIP: netip.MustParseAddr("198.51.100.54"), DstPort: 53,
	}
	oldRef := l3ingress.FlowRef{Identity: id, Generation: 1}
	newRef := l3ingress.FlowRef{Identity: id, Generation: 2}
	oldConn := &fakeConn{}
	oldSession := &Session{
		request: l3ingress.SessionRequest{Identity: id, Ref: oldRef, Egress: "old-egress"},
		conn:    oldConn,
	}
	canceled := make(chan struct{})
	manager := &Manager{sessions: map[l3ingress.L3Identity]*Session{id: oldSession}}
	relay := &UDPRelay{
		Manager: manager,
		sessions: map[l3ingress.L3Identity]packetReplyLoop{
			id: {session: oldSession, cancel: func() { close(canceled) }},
		},
		packets: map[l3ingress.L3Identity]*Session{id: oldSession},
	}
	relay.fast.Store(&packetSessionCache{id: id, sess: oldSession})

	if got := relay.packetSession(id, newRef); got != nil {
		t.Fatal("new generation reused predecessor packet session")
	}
	relay.retireStalePacketSession(id, newRef)
	select {
	case <-canceled:
	default:
		t.Fatal("predecessor reply loop was not canceled")
	}
	if _, ok := manager.Session(id); ok || oldConn.closed.Load() != 1 {
		t.Fatalf("predecessor remained in manager: present=%v closes=%d", ok, oldConn.closed.Load())
	}
	if relay.packetSession(id, newRef) != nil || relay.fast.Load() != nil {
		t.Fatal("predecessor cache survived generation retirement")
	}
}

func TestUDPRelaySmallBufferCannotConsumeLargeReply(t *testing.T) {
	id := l3ingress.L3Identity{
		Proto: l3ingress.ProtocolUDP,
		SrcIP: netip.MustParseAddr("2001:db8::50"), SrcPort: 53000,
		DstIP: netip.MustParseAddr("2001:db8::53"), DstPort: 53,
	}
	payload := bytes.Repeat([]byte{0x6d}, maxUDPPeerPayloadSize)
	packetConn := &udpIdleTestPacketConn{payload: payload}
	sess := &Session{
		request:    l3ingress.SessionRequest{Identity: id, Ref: l3ingress.FlowRef{Identity: id, Generation: 1}},
		packetConn: packetConn,
	}
	manager := &Manager{sessions: map[l3ingress.L3Identity]*Session{id: sess}}
	device := &packetCaptureDevice{writes: make(chan []byte, 1)}
	relay := &UDPRelay{
		Device: device, Manager: manager, BufferSize: 128,
		packets: map[l3ingress.L3Identity]*Session{id: sess},
	}
	relay.readReplies(context.Background(), id, sess)
	select {
	case packet := <-device.writes:
		meta, err := l3ingress.ParsePacket(packet)
		if err != nil {
			t.Fatal(err)
		}
		got, err := l3ingress.UDPPayload(packet, meta)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("reply payload length=%d want %d", len(got), len(payload))
		}
	default:
		t.Fatal("large reply was consumed without delivery")
	}
}

func echoPacket(t *testing.T, pc rendr.PacketConn, id l3ingress.L3Identity, want, reply string) {
	t.Helper()
	buf := make([]byte, 256)
	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := decodeUDPEnvelope(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Identity != id || envelope.Egress != "direct" || string(envelope.Payload) != want {
		t.Fatalf("server envelope=%+v want id=%s egress=direct payload=%q", envelope, id, want)
	}
	if _, err := pc.WriteTo([]byte(reply), addr); err != nil {
		t.Fatal(err)
	}
}

type packetCaptureDevice struct {
	writes chan []byte
}

func (d *packetCaptureDevice) Read([]byte) (int, error) { return 0, io.EOF }
func (d *packetCaptureDevice) Write(p []byte) (int, error) {
	if d.writes != nil {
		d.writes <- append([]byte(nil), p...)
	}
	return len(p), nil
}
func (d *packetCaptureDevice) WriteContext(ctx context.Context, p []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return d.Write(p)
}
func (d *packetCaptureDevice) Close() error { return nil }
func (d *packetCaptureDevice) Name() string { return "packet-capture0" }
func (d *packetCaptureDevice) MTU() int     { return 1500 }

type blockingPacketWriteDevice struct {
	writeStarted chan struct{}
	startOnce    sync.Once
}

func newBlockingPacketWriteDevice() *blockingPacketWriteDevice {
	return &blockingPacketWriteDevice{writeStarted: make(chan struct{})}
}

func (*blockingPacketWriteDevice) Read([]byte) (int, error) { return 0, io.EOF }
func (*blockingPacketWriteDevice) Write([]byte) (int, error) {
	panic("UDP relay bypassed WriteContext")
}
func (d *blockingPacketWriteDevice) WriteContext(ctx context.Context, _ []byte) (int, error) {
	d.startOnce.Do(func() { close(d.writeStarted) })
	<-ctx.Done()
	return 0, ctx.Err()
}
func (*blockingPacketWriteDevice) Close() error { return nil }
func (*blockingPacketWriteDevice) Name() string { return "blocking-packet0" }
func (*blockingPacketWriteDevice) MTU() int     { return 1500 }
