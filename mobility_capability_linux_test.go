//go:build linux && amd64 && !rendr_experimental_tcprepair

package rendr

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
	transporttcp "github.com/FrankoonG/rendr/transport/tcp"
)

func TestRuntimeOwnedTCPProvidersDoNotAdvertiseTCPRepairBeforeQualification(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ownedListener, err := transporttcp.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverRuntime, err := NewRuntimeContext(ctx, RuntimeConfig{})
	if err != nil {
		_ = ownedListener.Close()
		t.Fatal(err)
	}
	listener, err := serverRuntime.Listen(ListenConfig{Framed: []FramedSource{{
		Name:     "tcp",
		Carrier:  CarrierTCP,
		Listener: ownedListener,
	}}})
	if err != nil {
		_ = ownedListener.Close()
		t.Fatal(err)
	}
	defer listener.Close()

	clientRuntime, err := NewRuntimeContext(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	client, err := clientRuntime.Dial(ctx, SessionConfig{Root: Selector("root", []Target{
		Path("unreachable", PathSpec{Transport: "tcp", Address: "127.0.0.1:0"}),
		Path("owned", PathSpec{Transport: "tcp", Address: ownedListener.Addr().String()}),
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	clientConn, ok := client.(*engineBackedConn)
	if !ok {
		t.Fatalf("dialed connection type = %T, want *engineBackedConn", client)
	}
	if provider, ok := clientConn.resolver.framed["tcp"].(*transporttcp.Transport); !ok || provider == nil {
		t.Fatalf("built-in tcp provider = %T, want *tcp.Transport", clientConn.resolver.framed["tcp"])
	}
	serverConn, ok := server.(*acceptedStreamConn)
	if !ok {
		t.Fatalf("accepted connection type = %T, want *acceptedStreamConn", server)
	}
	assertRuntimeMobilityEnvelope(t, "stream client", clientConn.e, 0)
	assertRuntimeMobilityEnvelope(t, "stream server", serverConn.engine, 0)
	assertRuntimePeerMobilityFrozen(t, clientConn.e, serverConn.engine)

	paths := client.Paths()
	if len(paths) != 1 || pathSpecName(paths[0].Spec) != "owned" {
		t.Fatalf("attached paths after primary fallback = %v, want only owned", paths)
	}
	assertStreamRoundTrip(t, client, server, []byte("owned-tcp-repair"))
	assertStreamRoundTrip(t, server, client, []byte("owned-tcp-repair-reply"))
}

func TestRuntimeDialPacketOverBuiltInTCPFiltersTCPRepair(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rawListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverRuntime, err := NewRuntimeContext(ctx, RuntimeConfig{})
	if err != nil {
		_ = rawListener.Close()
		t.Fatal(err)
	}
	listener, err := serverRuntime.Listen(ListenConfig{Streams: []StreamSource{{
		Name:     "tcp",
		Carrier:  CarrierTCP,
		Listener: rawListener,
	}}})
	if err != nil {
		_ = rawListener.Close()
		t.Fatal(err)
	}
	defer listener.Close()

	clientRuntime, err := NewRuntimeContext(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	client, err := clientRuntime.DialPacket(ctx, SessionConfig{Root: Path("packet", PathSpec{
		Transport: "tcp",
		Address:   rawListener.Addr().String(),
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.AcceptPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	clientConn, ok := client.(*enginePacketConn)
	if !ok {
		t.Fatalf("dialed packet connection type = %T, want *enginePacketConn", client)
	}
	if provider, ok := clientConn.resolver.framed["tcp"].(*transporttcp.Transport); !ok || provider == nil {
		t.Fatalf("built-in tcp provider = %T, want *tcp.Transport", clientConn.resolver.framed["tcp"])
	}
	serverConn, ok := server.(*acceptedPacketConn)
	if !ok {
		t.Fatalf("accepted packet connection type = %T, want *acceptedPacketConn", server)
	}
	assertRuntimeMobilityEnvelope(t, "packet client", clientConn.e, 0)
	assertRuntimeMobilityEnvelope(t, "packet server", serverConn.engine, 0)
	assertRuntimePeerMobilityFrozen(t, clientConn.e, serverConn.engine)

	assertPacketRoundTrip(t, client, server, []byte("packet-over-tcp"))
	assertPacketRoundTrip(t, server, client, []byte("packet-over-tcp-reply"))
}

func assertRuntimeMobilityEnvelope(t *testing.T, side string, e *engine.Engine, want proto.LeafMobilitySet) {
	t.Helper()
	negotiation := e.LocalNegotiation()
	if negotiation.MobilitySupported != want || negotiation.MobilityRequired != 0 {
		t.Fatalf("%s mobility envelope = (0x%x,0x%x), want (0x%x,0)",
			side, negotiation.MobilitySupported, negotiation.MobilityRequired, want)
	}
}

func assertRuntimePeerMobilityFrozen(t *testing.T, client, server *engine.Engine) {
	t.Helper()
	if err := client.ValidatePeerNegotiation(server.LocalNegotiation(), server.LocalGraphManifest()); err != nil {
		t.Fatalf("client frozen peer negotiation: %v", err)
	}
	if err := server.ValidatePeerNegotiation(client.LocalNegotiation(), client.LocalGraphManifest()); err != nil {
		t.Fatalf("server frozen peer negotiation: %v", err)
	}
}
