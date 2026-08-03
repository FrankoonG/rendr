package l3session

import (
	"context"
	"io"
	"net/netip"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
)

func TestUDPRelayForwardsPayloadThroughRendrPacketSession(t *testing.T) {
	ln, err := rendr.ListenUDPFlowPacket("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
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

	if sess, ok := relay.manager().Session(id); !ok || sess.PacketConn == nil {
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
	ln, err := rendr.ListenUDPFlowPacket("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
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
	if !ok || sess.PacketConn == nil {
		t.Fatalf("missing packet session: ok=%v sess=%+v", ok, sess)
	}
	admin := sess.PacketConn.(rendr.AdminPacketConn)
	var pathB uint32
	for _, p := range admin.Paths() {
		if p.Spec.Opts["name"] == "udp-b" {
			pathB = p.ID
			break
		}
	}
	if pathB == 0 {
		t.Fatalf("path udp-b not attached: %+v", admin.Paths())
	}
	if err := admin.Migrate(pathB); err != nil {
		t.Fatal(err)
	}

	send("two")
	echoPacket(t, server, id, "two", "ack-two")
	readReply("ack-two")
	if admin.FlowID() != server.FlowID() {
		t.Fatalf("flow id changed across migration: client=%x server=%x", admin.FlowID(), server.FlowID())
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
func (d *packetCaptureDevice) Close() error { return nil }
func (d *packetCaptureDevice) Name() string { return "packet-capture0" }
func (d *packetCaptureDevice) MTU() int     { return 1500 }
