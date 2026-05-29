package l3session

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
	"github.com/FrankoonG/rendr/proto"
)

func TestStarterStreamSessionPreservesL3Capability(t *testing.T) {
	ln, err := rendr.ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan rendr.Conn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := ln.Accept(ctx)
		if err != nil {
			t.Errorf("accept stream: %v", err)
			return
		}
		accepted <- c
	}()

	req := l3ingress.SessionRequest{
		Kind:               l3ingress.SessionKindStream,
		Identity:           testIdentity(l3ingress.ProtocolTCP),
		Peer:               "peer-a",
		Root:               rendr.Path("tcp-a", rendr.PathSpec{Transport: "tcp", Address: ln.Addr().String()}),
		Egress:             "direct",
		PreserveL3Identity: true,
	}
	sess, err := Starter{}.Start(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if sess.Conn == nil || sess.PacketConn != nil {
		t.Fatalf("session shape conn=%T packet=%T", sess.Conn, sess.PacketConn)
	}

	server := <-accepted
	defer server.Close()
	assertPeerL3Cap(t, server.(rendr.AdminConn).Stats().PeerCaps, false)

	go func() {
		buf := make([]byte, 5)
		if _, err := io.ReadFull(server, buf); err != nil {
			t.Errorf("server read: %v", err)
			return
		}
		if string(buf) != "hello" {
			t.Errorf("server read %q", buf)
			return
		}
		if _, err := server.Write([]byte("world")); err != nil {
			t.Errorf("server write: %v", err)
		}
	}()
	if _, err := sess.Conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(sess.Conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "world" {
		t.Fatalf("client read %q want world", got)
	}
}

func TestStarterPacketSessionPreservesL3Capability(t *testing.T) {
	ln, err := rendr.ListenUDPFlowPacket("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan rendr.PacketConn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := ln.AcceptPacket(ctx)
		if err != nil {
			t.Errorf("accept packet: %v", err)
			return
		}
		accepted <- c
	}()

	req := l3ingress.SessionRequest{
		Kind:               l3ingress.SessionKindPacket,
		Identity:           testIdentity(l3ingress.ProtocolUDP),
		Peer:               "peer-a",
		Root:               rendr.Path("udp-a", rendr.PathSpec{Transport: "udpflow", Address: ln.Addr().String()}),
		Egress:             "direct",
		PreserveL3Identity: true,
	}
	sess, err := Starter{}.Start(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if sess.Conn != nil || sess.PacketConn == nil {
		t.Fatalf("session shape conn=%T packet=%T", sess.Conn, sess.PacketConn)
	}

	server := <-accepted
	defer server.Close()
	assertPeerL3Cap(t, server.(rendr.AdminPacketConn).Stats().PeerCaps, true)

	go func() {
		buf := make([]byte, 32)
		n, addr, err := server.ReadFrom(buf)
		if err != nil {
			t.Errorf("server readfrom: %v", err)
			return
		}
		if string(buf[:n]) != "ping" {
			t.Errorf("server read %q", buf[:n])
			return
		}
		if _, err := server.WriteTo([]byte("pong"), addr); err != nil {
			t.Errorf("server writeto: %v", err)
		}
	}()
	if _, err := sess.PacketConn.WriteTo([]byte("ping"), dummyAddr("peer")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, _, err := sess.PacketConn.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "pong" {
		t.Fatalf("client read %q want pong", buf[:n])
	}
}

func TestStarterRejectsUnsupportedRequest(t *testing.T) {
	_, err := Starter{}.Start(context.Background(), l3ingress.SessionRequest{
		Kind:               l3ingress.SessionKindStream,
		Identity:           testIdentity(l3ingress.ProtocolTCP),
		Peer:               "peer-a",
		Root:               "not-a-target",
		Egress:             "direct",
		PreserveL3Identity: true,
	})
	assertReason(t, err, ReasonUnsupportedRoot)

	_, err = Starter{}.Start(context.Background(), l3ingress.SessionRequest{
		Kind:               l3ingress.SessionKind("raw"),
		Identity:           testIdentity(l3ingress.ProtocolTCP),
		Peer:               "peer-a",
		Root:               rendr.Path("tcp-a", rendr.PathSpec{Transport: "tcp", Address: "127.0.0.1:1"}),
		Egress:             "direct",
		PreserveL3Identity: true,
	})
	assertReason(t, err, ReasonUnsupportedKind)
}

func testIdentity(protoNum l3ingress.Protocol) l3ingress.L3Identity {
	return l3ingress.L3Identity{
		Proto:   protoNum,
		SrcIP:   netip.MustParseAddr("192.0.2.10"),
		SrcPort: 12345,
		DstIP:   netip.MustParseAddr("198.51.100.20"),
		DstPort: 443,
	}
}

func assertPeerL3Cap(t *testing.T, caps uint32, packet bool) {
	t.Helper()
	if caps&proto.CapsL3Identity == 0 {
		t.Fatalf("PeerCaps=0x%08x missing CapsL3Identity", caps)
	}
	if packet && caps&proto.CapsPacketMode == 0 {
		t.Fatalf("PeerCaps=0x%08x missing CapsPacketMode", caps)
	}
	if !packet && caps&proto.CapsPacketMode != 0 {
		t.Fatalf("PeerCaps=0x%08x unexpectedly has CapsPacketMode", caps)
	}
}

func assertReason(t *testing.T, err error, reason ErrorReason) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("err=%v, want *Error", err)
	}
	if e.Reason != reason {
		t.Fatalf("reason=%q want %q", e.Reason, reason)
	}
}

type dummyAddr string

func (d dummyAddr) Network() string { return "dummy" }
func (d dummyAddr) String() string  { return string(d) }

var _ net.Addr = dummyAddr("")
