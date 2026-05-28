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
	buf := make([]byte, 32)
	n, addr, err := server.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "query" {
		t.Fatalf("server read %q want query", buf[:n])
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
