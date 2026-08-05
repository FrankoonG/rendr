package udprelay

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/FrankoonG/rendr"
)

func TestRelayRoundTripOverMigratedPacketConn(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	echo, echoAddr := startUDPEcho(t)
	defer echo.Close()

	ln, err := rendr.ListenUDPFlowPacket("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan rendr.PacketConn, 1)
	go func() {
		pc, err := ln.AcceptPacket(ctx)
		if err != nil {
			t.Errorf("accept packet: %v", err)
			return
		}
		accepted <- pc
	}()

	client, err := (&rendr.Dialer{
		Root: packetSelector(ln.Addr().String()),
	}).DialPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}

	var server rendr.PacketConn
	select {
	case server = <-accepted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	waitPacketPaths(t, client, server, 2)

	serverRelay, err := Start(ctx, Config{
		PacketConn: server,
		LocalAddr:  "127.0.0.1:0",
		TargetAddr: echoAddr.String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer serverRelay.Close()

	clientRelay, err := Start(ctx, Config{
		PacketConn: client,
		LocalAddr:  "127.0.0.1:0",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientRelay.Close()

	app, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()

	sendAndExpect(t, app, clientRelay.LocalAddr(), []byte("before-migration"))

	admin := client.(packetControl)
	cur := admin.ActivePath()
	var next uint32
	for _, p := range admin.Paths() {
		if p.ID != cur {
			next = p.ID
			break
		}
	}
	if next == 0 {
		t.Fatal("no alternate packet path")
	}
	if err := admin.Migrate(next); err != nil {
		t.Fatalf("migrate packet path: %v", err)
	}

	sendAndExpect(t, app, clientRelay.LocalAddr(), []byte("after-migration"))
	if got := admin.MigrationCount(); got == 0 {
		t.Fatal("expected at least one packet path migration")
	}
}

func TestDialAndServeRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	echo, echoAddr := startUDPEcho(t)
	defer echo.Close()

	ln, err := rendr.ListenUDPFlowPacket("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverReady := make(chan *Relay, 1)
	go func() {
		r, err := Serve(ctx, ServeConfig{
			Listener:   ln,
			LocalAddr:  "127.0.0.1:0",
			TargetAddr: echoAddr.String(),
		})
		if err != nil {
			t.Errorf("serve relay: %v", err)
			return
		}
		serverReady <- r
	}()

	clientRelay, err := Dial(ctx, DialConfig{
		Dialer: &rendr.Dialer{
			Root: packetSelector(ln.Addr().String()),
		},
		LocalAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientRelay.Close()

	var serverRelay *Relay
	select {
	case serverRelay = <-serverReady:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer serverRelay.Close()

	waitPacketPaths(t, clientRelay.PacketConn(), serverRelay.PacketConn(), 2)

	app, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()

	sendAndExpect(t, app, clientRelay.LocalAddr(), []byte("dial-serve-before"))
	admin := clientRelay.PacketConn().(packetControl)
	migrateToAlternate(t, admin)
	sendAndExpect(t, app, clientRelay.LocalAddr(), []byte("dial-serve-after"))
}

func TestServerAcceptsMultipleClients(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	echo, echoAddr := startUDPEcho(t)
	defer echo.Close()

	ln, err := rendr.ListenUDPFlowPacket("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	server, err := Listen(ctx, ServeConfig{
		Listener:   ln,
		LocalAddr:  "127.0.0.1:0",
		TargetAddr: echoAddr.String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	for i := 0; i < 2; i++ {
		clientRelay, err := Dial(ctx, DialConfig{
			Dialer: &rendr.Dialer{
				Root: packetSelector(ln.Addr().String()),
			},
			LocalAddr: "127.0.0.1:0",
		})
		if err != nil {
			t.Fatal(err)
		}
		defer clientRelay.Close()
		waitServerRelays(t, server, i+1)

		app, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		sendAndExpect(t, app, clientRelay.LocalAddr(), []byte(fmt.Sprintf("server-client-%d-before", i)))
		admin := clientRelay.PacketConn().(packetControl)
		migrateToAlternate(t, admin)
		sendAndExpect(t, app, clientRelay.LocalAddr(), []byte(fmt.Sprintf("server-client-%d-after", i)))
		_ = app.Close()
	}
}

func packetSelector(addr string) rendr.Target {
	return rendr.Selector("root", []rendr.Target{
		rendr.Path("udp-a", rendr.PathSpec{Transport: "udpflow", Address: addr}),
		rendr.Path("udp-b", rendr.PathSpec{Transport: "udpflow", Address: addr}),
	})
}

func startUDPEcho(t *testing.T) (net.PacketConn, net.Addr) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	return pc, pc.LocalAddr()
}

func waitPacketPaths(t *testing.T, client, server rendr.PacketConn, want int) {
	t.Helper()
	ca := client.(packetControl)
	sa := server.(packetControl)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(ca.Paths()) >= want && len(sa.Paths()) >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("paths did not attach: client=%d server=%d want=%d", len(ca.Paths()), len(sa.Paths()), want)
}

func waitServerRelays(t *testing.T, server *Server, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if server.Relays() >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server relays=%d want >=%d", server.Relays(), want)
}

func migrateToAlternate(t *testing.T, admin packetControl) {
	t.Helper()
	cur := admin.ActivePath()
	var next uint32
	for _, p := range admin.Paths() {
		if p.ID != cur {
			next = p.ID
			break
		}
	}
	if next == 0 {
		t.Fatal("no alternate packet path")
	}
	if err := admin.Migrate(next); err != nil {
		t.Fatalf("migrate packet path: %v", err)
	}
}

func sendAndExpect(t *testing.T, app net.PacketConn, relayAddr net.Addr, payload []byte) {
	t.Helper()
	if _, err := app.WriteTo(payload, relayAddr); err != nil {
		t.Fatalf("app write %q: %v", payload, err)
	}
	if err := app.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload)+16)
	n, _, err := app.ReadFrom(buf)
	if err != nil {
		t.Fatalf("app read %q: %v", payload, err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("echo mismatch for %q: got %q", payload, fmt.Sprintf("%s", buf[:n]))
	}
}
