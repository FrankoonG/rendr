package rendr

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/transport"
	basetcp "github.com/FrankoonG/rendr/transport/tcp"
)

type mobilityClaimTestPath struct {
	transport.PathConn
	claim *leafmobility.Claim
}

func (p *mobilityClaimTestPath) LeafMobilityClaim() *leafmobility.Claim { return p.claim }

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

func TestOwnedClaimCannotBypassPeerAgreement(t *testing.T) {
	tests := []struct {
		name      string
		kind      leafmobility.Kind
		operation leafmobility.Operation
	}{
		{name: "tcp", kind: leafmobility.KindRawTCP, operation: leafmobility.OperationTCPRepair},
		{name: "udp-flow", kind: leafmobility.KindUDPFlow, operation: leafmobility.OperationUDPFlowRebind},
		{name: "quic", kind: leafmobility.KindQUIC, operation: leafmobility.OperationQUICCIDRebind},
		{name: "gvisor", kind: leafmobility.KindGVisor, operation: leafmobility.OperationGVisorLinkRebind},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status := planLeafMobility(CarrierUnknown, leafmobility.Facts{
				Kind:       test.kind,
				Role:       leafmobility.RoleDialer,
				Scope:      leafmobility.ScopeEndpoint,
				Session:    leafmobility.SessionAny,
				Operations: test.operation,
				Generation: 7,
			})
			if status.ID != MobilityRedialAttach || status.Reason != MobilityReasonPeerAgreementNotNegotiated {
				t.Fatalf("status=%+v, want conservative redial/attach", status)
			}
			if status.EndpointGeneration != 7 {
				t.Fatalf("endpoint generation=%d want=7", status.EndpointGeneration)
			}
		})
	}
}

func TestLeafMobilityPlanTimestampComesFromPlanningBoundary(t *testing.T) {
	plannedAt := time.Unix(123, 456)
	status := planLeafMobilityAt(plannedAt, leafmobility.Facts{
		Kind:       leafmobility.KindRawTCP,
		Role:       leafmobility.RoleDialer,
		Scope:      leafmobility.ScopeEndpoint,
		Session:    leafmobility.SessionStream,
		Generation: 1,
	})
	if status.PlannedAt != plannedAt {
		t.Fatalf("planned at=%v want=%v", status.PlannedAt, plannedAt)
	}
}

func TestRetiredEndpointCannotContributeOwnershipEvidence(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	claim := leafmobility.MustNewClaim(leafmobility.Facts{
		Kind:       leafmobility.KindRawTCP,
		Role:       leafmobility.RoleDialer,
		Scope:      leafmobility.ScopeEndpoint,
		Session:    leafmobility.SessionStream,
		Operations: leafmobility.OperationTCPRepair,
		Generation: leafmobility.NextGeneration(),
	})
	claim.RetireUnbound()
	status := planPathConnMobility(CarrierTCP, &mobilityClaimTestPath{PathConn: basetcp.Wrap(left), claim: claim})
	if status.ID != MobilityRedialAttach || status.Reason != MobilityReasonEndpointRetired || status.EndpointGeneration != 0 {
		t.Fatalf("retired endpoint status=%+v", status)
	}
}
