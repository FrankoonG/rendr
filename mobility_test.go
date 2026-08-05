package rendr

import (
	"context"
	"net"
	"testing"
)

func TestGenericCarrierFactsNeverGrantOwnedMobility(t *testing.T) {
	resolver := &pathFactoryResolver{
		stream: map[string]streamPathFactory{
			"tcp-family": func(context.Context, string) (net.Conn, error) { return nil, net.ErrClosed },
			"udp-family": func(context.Context, string) (net.Conn, error) { return nil, net.ErrClosed },
			"tcprepair":  func(context.Context, string) (net.Conn, error) { return nil, net.ErrClosed },
			"gvisor":     func(context.Context, string) (net.Conn, error) { return nil, net.ErrClosed },
		},
		carrier: map[string]CarrierFamily{
			"tcp-family": CarrierTCP,
			"udp-family": CarrierUDP,
			"tcprepair":  CarrierTCP,
			"gvisor":     CarrierUnknown,
		},
	}
	for _, factory := range []string{"tcp-family", "udp-family", "tcprepair", "gvisor"} {
		status := planLeafMobility(resolver.carrierFamily(factory))
		if status.ID != MobilityRedialAttach {
			t.Fatalf("factory=%s mobility=%q, want %q", factory, status.ID, MobilityRedialAttach)
		}
		if status.Reason == "" || status.PlannedAt.IsZero() {
			t.Fatalf("factory=%s incomplete mobility evidence: %+v", factory, status)
		}
	}
}

func TestUnknownBuiltInPathFailsConservativelyToRedialAttach(t *testing.T) {
	for _, name := range []string{"implementation-name-must-not-matter", "tcprepair", "gvisor"} {
		status := planLeafMobility(CarrierUnknown)
		if status.ID != MobilityRedialAttach || status.Reason == "" {
			t.Fatalf("transport=%q status=%+v", name, status)
		}
	}
}
