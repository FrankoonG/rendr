package l3session

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
)

func TestTCPRelayBridgesEndpointThroughRendrStreamSession(t *testing.T) {
	ln, err := rendr.ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := acceptStream(t, ln)
	id := tcpRelayIdentity()
	ev := tcpRelayEvent(id, rendr.Path("tcp-a", rendr.PathSpec{Transport: "tcp", Address: ln.Addr().String()}))
	app, endpoint := net.Pipe()
	defer app.Close()

	relay := &TCPRelay{}
	errCh := make(chan error, 1)
	go func() { errCh <- relay.Serve(context.Background(), ev, endpoint) }()

	server := <-accepted
	defer server.Close()
	go func() {
		buf := make([]byte, 5)
		if _, err := io.ReadFull(server, buf); err != nil {
			t.Errorf("server read: %v", err)
			return
		}
		if string(buf) != "hello" {
			t.Errorf("server read %q want hello", buf)
			return
		}
		if _, err := server.Write([]byte("world")); err != nil {
			t.Errorf("server write: %v", err)
		}
	}()

	if _, err := app.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(app, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "world" {
		t.Fatalf("app read %q want world", got)
	}
	app.Close()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for relay shutdown")
	}
}

func TestTCPRelayPreservesFlowAcrossStreamMigration(t *testing.T) {
	ln, err := rendr.ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := acceptStream(t, ln)
	id := tcpRelayIdentity()
	root := rendr.Selector("root", []rendr.Target{
		rendr.Path("tcp-a", rendr.PathSpec{Transport: "tcp", Address: ln.Addr().String()}),
		rendr.Path("tcp-b", rendr.PathSpec{Transport: "tcp", Address: ln.Addr().String()}),
	})
	app, endpoint := net.Pipe()
	defer app.Close()

	relay := &TCPRelay{}
	errCh := make(chan error, 1)
	go func() { errCh <- relay.Serve(context.Background(), tcpRelayEvent(id, root), endpoint) }()

	server := <-accepted
	defer server.Close()
	oneDone := startEchoStream(t, server, "one", "ack-one")
	writeAndReadStream(t, app, "one", "ack-one")
	waitEcho(t, oneDone, "one")

	sess, ok := relay.manager().Session(id)
	if !ok || sess.Conn == nil {
		t.Fatalf("missing stream session: ok=%v sess=%+v", ok, sess)
	}
	admin := sess.Conn.(rendr.AdminConn)
	var pathB uint32
	for _, p := range admin.Paths() {
		if p.Spec.Opts["name"] == "tcp-b" {
			pathB = p.ID
			break
		}
	}
	if pathB == 0 {
		t.Fatalf("path tcp-b not attached: %+v", admin.Paths())
	}
	if err := admin.Migrate(pathB); err != nil {
		t.Fatal(err)
	}
	twoDone := startEchoStream(t, server, "two", "ack-two")
	writeAndReadStream(t, app, "two", "ack-two")
	waitEcho(t, twoDone, "two")
	if admin.FlowID() != server.FlowID() {
		t.Fatalf("flow id changed across migration: client=%x server=%x", admin.FlowID(), server.FlowID())
	}

	app.Close()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for relay shutdown")
	}
}

func acceptStream(t *testing.T, ln rendr.Listener) <-chan rendr.Conn {
	t.Helper()
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
	return accepted
}

func tcpRelayIdentity() l3ingress.L3Identity {
	return l3ingress.L3Identity{
		Proto:   l3ingress.ProtocolTCP,
		SrcIP:   netip.MustParseAddr("10.0.0.2"),
		SrcPort: 40000,
		DstIP:   netip.MustParseAddr("198.51.100.20"),
		DstPort: 443,
	}
}

func tcpRelayEvent(id l3ingress.L3Identity, root rendr.Target) l3ingress.PacketEvent {
	return l3ingress.PacketEvent{
		Meta: l3ingress.PacketMeta{Identity: id},
		Flow: l3ingress.FlowMeta{L3Identity: id, Direction: l3ingress.DirectionIngress},
		Decision: l3ingress.FlowDecision{
			Peer:   "peer-a",
			Root:   root,
			Egress: "direct",
		},
		Decided: true,
	}
}

func startEchoStream(t *testing.T, c rendr.Conn, want, reply string) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, len(want))
		if _, err := io.ReadFull(c, buf); err != nil {
			done <- err
			return
		}
		if string(buf) != want {
			done <- fmt.Errorf("server read %q want %q", buf, want)
			return
		}
		_, err := c.Write([]byte(reply))
		done <- err
	}()
	return done
}

func waitEcho(t *testing.T, done <-chan error, label string) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for server echo %q", label)
	}
}

func writeAndReadStream(t *testing.T, c net.Conn, send, want string) {
	t.Helper()
	if _, err := c.Write([]byte(send)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("app read %q want %q", got, want)
	}
}
