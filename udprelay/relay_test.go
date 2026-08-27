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

func TestDialRequiresRuntime(t *testing.T) {
	_, err := Dial(context.Background(), DialConfig{})
	if err == nil || err.Error() != "udprelay: Runtime is required" {
		t.Fatalf("Dial error = %v, want Runtime is required", err)
	}
}

func TestRelayRoundTripOverMigratedPacketConn(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	echo, echoAddr := startUDPEcho(t)
	defer echo.Close()

	ln := newPacketSessionListener(t, "udpflow")
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

	runtime := newRuntime(t)
	client, err := runtime.DialPacket(ctx, rendr.SessionConfig{
		Root: packetSelector(ln.Addr().String()),
	})
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
	var nextName string
	for _, p := range admin.Paths() {
		if p.ID != cur {
			next = p.ID
			nextName = p.Spec.Opts["name"]
			break
		}
	}
	if next == 0 {
		t.Fatal("no alternate packet path")
	}
	if err := admin.SelectTarget("root", nextName); err != nil {
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

	ln := newPacketSessionListener(t, "udpflow")
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
		Runtime: newRuntime(t),
		Session: rendr.SessionConfig{
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

	ln := newPacketSessionListener(t, "udpflow")

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
			Runtime: newRuntime(t),
			Session: rendr.SessionConfig{
				Root: packetSelector(ln.Addr().String()),
			},
			LocalAddr: "127.0.0.1:0",
		})
		if err != nil {
			t.Fatal(err)
		}
		defer clientRelay.Close()
		waitServerRelays(t, server, i+1)
		waitPacketPathNames(t, clientRelay.PacketConn(), []string{"udp-a", "udp-b"}, 3*time.Second)

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

func newRuntime(t *testing.T) *rendr.Runtime {
	t.Helper()
	runtime, err := rendr.NewRuntime(rendr.RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func newPacketSessionListener(t *testing.T, sourceName string) *rendr.SessionListener {
	t.Helper()
	runtime := newRuntime(t)
	rawPacketConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := runtime.Listen(rendr.ListenConfig{Packets: []rendr.PacketSource{{
		Name:            sourceName,
		Carrier:         rendr.CarrierUDP,
		Conn:            rawPacketConn,
		MaxDatagramSize: 1400,
	}}})
	if err != nil {
		_ = rawPacketConn.Close()
		t.Fatal(err)
	}
	return listener
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
	serverObserver, ok := server.(rendr.ConnectionObserver)
	if !ok {
		t.Fatal("accepted packet session does not expose ConnectionObserver")
	}
	if _, ok := server.(rendr.PathController); ok {
		t.Fatal("accepted packet session unexpectedly exposes PathController")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(client.Paths()) >= want && len(serverObserver.Stats().Paths) >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("paths did not attach: client=%d server=%d want=%d client_status=%+v server_status=%+v",
		len(client.Paths()), len(serverObserver.Stats().Paths), want, client.Status(), server.Status())
}

func waitPacketPathNames(t *testing.T, conn rendr.PacketConn, names []string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		status := conn.Status()
		attached := make(map[string]bool, len(status.Paths))
		for _, path := range status.Paths {
			if path.State == rendr.PathAttached && path.ID != 0 {
				attached[path.Name] = true
			}
		}
		complete := true
		for _, name := range names {
			if !attached[name] {
				complete = false
				break
			}
		}
		if complete {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("packet paths %v did not attach: status=%+v", names, conn.Status())
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
	var nextName string
	for _, p := range admin.Paths() {
		if p.ID != cur {
			next = p.ID
			nextName = p.Spec.Opts["name"]
			break
		}
	}
	if next == 0 {
		t.Fatal("no alternate packet path")
	}
	if err := admin.SelectTarget("root", nextName); err != nil {
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
