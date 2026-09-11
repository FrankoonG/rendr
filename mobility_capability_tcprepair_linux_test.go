//go:build linux && amd64

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

func TestRuntimeOwnedTCPProvidersAdvertiseTCPRepair(t *testing.T) {
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
		Name: "tcp", Carrier: CarrierTCP, Listener: ownedListener,
	}}})
	if err != nil {
		_ = ownedListener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	clientRuntime, err := NewRuntimeContext(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	client, err := clientRuntime.Dial(ctx, SessionConfig{Root: Path("owned", PathSpec{
		Transport: "tcp", Address: ownedListener.Addr().String(),
	})})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server, err := listener.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	clientConn := client.(*engineBackedConn)
	serverConn := server.(*acceptedStreamConn)
	assertDefaultRuntimeMobilityEnvelope(t, "stream client", clientConn.e, proto.LeafMobilityTCPRepair)
	assertDefaultRuntimeMobilityEnvelope(t, "stream server", serverConn.engine, proto.LeafMobilityTCPRepair)
	assertDefaultRuntimePeerMobilityFrozen(t, clientConn.e, serverConn.engine)
	assertDefaultTCPRepairIdleStatus(t, "stream client", client.Status())
	assertDefaultTCPRepairIdleStatus(t, "stream server", server.Status())
	assertStreamRoundTrip(t, client, server, []byte("owned-tcp-repair"))
	assertStreamRoundTrip(t, server, client, []byte("owned-tcp-repair-reply"))
}

func TestRuntimeOwnedTCPRequiresBilateralProvider(t *testing.T) {
	for _, test := range []struct {
		name         string
		ownedDialer  bool
		ownedIngress bool
	}{
		{name: "owned dialer generic ingress", ownedDialer: true},
		{name: "generic dialer owned ingress", ownedIngress: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			serverRuntime, err := NewRuntimeContext(ctx, RuntimeConfig{})
			if err != nil {
				t.Fatal(err)
			}
			clientRuntime, err := NewRuntimeContext(ctx, RuntimeConfig{})
			if err != nil {
				t.Fatal(err)
			}

			var address string
			var listener *SessionListener
			if test.ownedIngress {
				owned, listenErr := transporttcp.Listen("tcp4", "127.0.0.1:0")
				if listenErr != nil {
					t.Fatal(listenErr)
				}
				address = owned.Addr().String()
				listener, err = serverRuntime.Listen(ListenConfig{Framed: []FramedSource{{
					Name: "ingress", Carrier: CarrierTCP, Listener: owned,
				}}})
				if err != nil {
					_ = owned.Close()
					t.Fatal(err)
				}
			} else {
				generic, listenErr := net.Listen("tcp4", "127.0.0.1:0")
				if listenErr != nil {
					t.Fatal(listenErr)
				}
				address = generic.Addr().String()
				listener, err = serverRuntime.Listen(ListenConfig{Streams: []StreamSource{{
					Name: "ingress", Carrier: CarrierTCP, Listener: generic,
				}}})
				if err != nil {
					_ = generic.Close()
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { _ = listener.Close() })

			transportID := "tcp"
			if !test.ownedDialer {
				transportID = "generic"
				if err := clientRuntime.RegisterStreamFactory(transportID, StreamFactory{
					Carrier: CarrierTCP,
					Dial: func(ctx context.Context, address string) (net.Conn, error) {
						return (&net.Dialer{}).DialContext(ctx, "tcp4", address)
					},
				}); err != nil {
					t.Fatal(err)
				}
			}
			client, err := clientRuntime.Dial(ctx, SessionConfig{Root: Path("path", PathSpec{
				Transport: transportID, Address: address,
			})})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			server, err := listener.AcceptStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = server.Close() })

			clientConn := client.(*engineBackedConn)
			serverConn := server.(*acceptedStreamConn)
			wantClient := proto.LeafMobilitySet(0)
			if test.ownedDialer {
				wantClient = proto.LeafMobilityTCPRepair
			}
			wantServer := proto.LeafMobilitySet(0)
			if test.ownedIngress {
				wantServer = proto.LeafMobilityTCPRepair
			}
			assertDefaultRuntimeMobilityEnvelope(t, "stream client", clientConn.e, wantClient)
			assertDefaultRuntimeMobilityEnvelope(t, "stream server", serverConn.engine, wantServer)
			assertDefaultRuntimePeerMobilityFrozen(t, clientConn.e, serverConn.engine)
			assertDefaultRedialBaselineStatus(t, "stream client", client.Status())
			assertDefaultRedialBaselineStatus(t, "stream server", server.Status())
			assertStreamRoundTrip(t, client, server, []byte("asymmetric-provider"))
			assertStreamRoundTrip(t, server, client, []byte("asymmetric-provider-reply"))
		})
	}
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
		Name: "tcp", Carrier: CarrierTCP, Listener: rawListener,
	}}})
	if err != nil {
		_ = rawListener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	clientRuntime, err := NewRuntimeContext(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	client, err := clientRuntime.DialPacket(ctx, SessionConfig{Root: Path("packet", PathSpec{
		Transport: "tcp", Address: rawListener.Addr().String(),
	})})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server, err := listener.AcceptPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	clientConn := client.(*enginePacketConn)
	serverConn := server.(*acceptedPacketConn)
	assertDefaultRuntimeMobilityEnvelope(t, "packet client", clientConn.e, 0)
	assertDefaultRuntimeMobilityEnvelope(t, "packet server", serverConn.engine, 0)
	assertDefaultRuntimePeerMobilityFrozen(t, clientConn.e, serverConn.engine)
	assertPacketRoundTrip(t, client, server, []byte("packet-over-tcp"))
	assertPacketRoundTrip(t, server, client, []byte("packet-over-tcp-reply"))
}

func assertDefaultRuntimeMobilityEnvelope(t *testing.T, side string, e *engine.Engine, want proto.LeafMobilitySet) {
	t.Helper()
	negotiation := e.LocalNegotiation()
	if negotiation.MobilitySupported != want || negotiation.MobilityRequired != 0 {
		t.Fatalf("%s mobility envelope = (0x%x,0x%x), want (0x%x,0)",
			side, negotiation.MobilitySupported, negotiation.MobilityRequired, want)
	}
}

func assertDefaultRuntimePeerMobilityFrozen(t *testing.T, client, server *engine.Engine) {
	t.Helper()
	if err := client.ValidatePeerNegotiation(server.LocalNegotiation(), server.LocalGraphManifest()); err != nil {
		t.Fatalf("client frozen peer negotiation: %v", err)
	}
	if err := server.ValidatePeerNegotiation(client.LocalNegotiation(), client.LocalGraphManifest()); err != nil {
		t.Fatalf("server frozen peer negotiation: %v", err)
	}
}

func assertDefaultTCPRepairIdleStatus(t *testing.T, side string, status Status) {
	t.Helper()
	if len(status.Paths) != 1 {
		t.Fatalf("%s paths=%v, want one owned TCP path", side, status.Paths)
	}
	mobility := status.Paths[0].Mobility
	if mobility.ID != MobilityRedialAttach || mobility.Negotiated != MobilityTCPRepairSamePeerTuple ||
		mobility.State != MobilityStateBaseline ||
		mobility.Reason != MobilityReasonAwaitingFactualChange || mobility.Fallback != MobilityRedialAttach ||
		mobility.EndpointGeneration == 0 || mobility.UpdatedAt.IsZero() {
		t.Fatalf("%s idle mobility=%+v", side, mobility)
	}
}

func assertDefaultRedialBaselineStatus(t *testing.T, side string, status Status) {
	t.Helper()
	if len(status.Paths) != 1 {
		t.Fatalf("%s paths=%v, want one path", side, status.Paths)
	}
	mobility := status.Paths[0].Mobility
	if mobility.ID != MobilityRedialAttach || mobility.Negotiated != "" || mobility.State != MobilityStateBaseline ||
		mobility.Reason == MobilityReasonAwaitingFactualChange || mobility.Fallback != "" {
		t.Fatalf("%s asymmetric mobility=%+v", side, mobility)
	}
}
