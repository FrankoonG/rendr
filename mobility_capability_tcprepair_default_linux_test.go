//go:build linux && amd64 && !rendr_experimental_tcprepair

package rendr

import (
	"context"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
	transporttcp "github.com/FrankoonG/rendr/transport/tcp"
)

func TestRuntimeOwnedTCPDefaultsToRedialAttachWithoutExperimentalDriver(t *testing.T) {
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

	clientEngine := client.(*engineBackedConn).e
	serverEngine := server.(*acceptedStreamConn).engine
	assertNoSpecializedMobility(t, "stream client", clientEngine)
	assertNoSpecializedMobility(t, "stream server", serverEngine)
	if err := clientEngine.ValidatePeerNegotiation(serverEngine.LocalNegotiation(), serverEngine.LocalGraphManifest()); err != nil {
		t.Fatalf("client peer negotiation: %v", err)
	}
	if err := serverEngine.ValidatePeerNegotiation(clientEngine.LocalNegotiation(), clientEngine.LocalGraphManifest()); err != nil {
		t.Fatalf("server peer negotiation: %v", err)
	}
	assertDefaultRedialOnlyStatus(t, "stream client", client.Status())
	assertDefaultRedialOnlyStatus(t, "stream server", server.Status())
	assertStreamRoundTrip(t, client, server, []byte("owned-tcp-redial-baseline"))
	assertStreamRoundTrip(t, server, client, []byte("owned-tcp-redial-baseline-reply"))
}

func assertNoSpecializedMobility(t *testing.T, side string, e *engine.Engine) {
	t.Helper()
	negotiation := e.LocalNegotiation()
	if negotiation.MobilitySupported != proto.LeafMobilitySet(0) || negotiation.MobilityRequired != 0 {
		t.Fatalf("%s mobility envelope = (0x%x,0x%x), want (0,0)",
			side, negotiation.MobilitySupported, negotiation.MobilityRequired)
	}
}

func assertDefaultRedialOnlyStatus(t *testing.T, side string, status Status) {
	t.Helper()
	if len(status.Paths) != 1 {
		t.Fatalf("%s paths=%v, want one owned TCP path", side, status.Paths)
	}
	mobility := status.Paths[0].Mobility
	if mobility.ID != MobilityRedialAttach || mobility.Negotiated != "" ||
		mobility.State != MobilityStateBaseline || mobility.Fallback != "" ||
		mobility.EndpointGeneration == 0 || mobility.UpdatedAt.IsZero() {
		t.Fatalf("%s baseline mobility=%+v", side, mobility)
	}
}
