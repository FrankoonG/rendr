package rendr

import (
	"context"
	"net"
	"testing"
)

func TestGenericCarrierFactsNeverGrantOwnedMobility(t *testing.T) {
	resolver := &pathFactoryResolver{
		stream: map[string]StreamPathFactory{
			"tcp-family": func(context.Context, string) (net.Conn, error) { return nil, net.ErrClosed },
			"udp-family": func(context.Context, string) (net.Conn, error) { return nil, net.ErrClosed },
		},
		carrier: map[string]CarrierFamily{
			"tcp-family": CarrierTCP,
			"udp-family": CarrierUDP,
		},
	}
	for _, factory := range []string{"tcp-family", "udp-family"} {
		status := planLeafMobility(PathSpec{Transport: factory}, resolver)
		if status.ID != MobilityRedialAttach {
			t.Fatalf("factory=%s mobility=%q, want %q", factory, status.ID, MobilityRedialAttach)
		}
		if status.Reason == "" || status.PlannedAt.IsZero() {
			t.Fatalf("factory=%s incomplete mobility evidence: %+v", factory, status)
		}
	}
}

func TestUnknownBuiltInPathFailsConservativelyToRedialAttach(t *testing.T) {
	status := planLeafMobility(PathSpec{Transport: "implementation-name-must-not-matter"}, nil)
	if status.ID != MobilityRedialAttach || status.Reason == "" {
		t.Fatalf("status=%+v", status)
	}
}
