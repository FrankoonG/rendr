package rendr

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
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
		if status.Reason == "" || status.State != MobilityStateBaseline ||
			!status.ObservedAt.IsZero() || !status.UpdatedAt.IsZero() || !status.ExpiresAt.IsZero() {
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

func TestLeafMobilityBaselineDoesNotFabricateEventTiming(t *testing.T) {
	status := planLeafMobility(CarrierUnknown, leafmobility.Facts{
		Kind:       leafmobility.KindRawTCP,
		Role:       leafmobility.RoleDialer,
		Scope:      leafmobility.ScopeEndpoint,
		Session:    leafmobility.SessionStream,
		Generation: 1,
	})
	if !status.ObservedAt.IsZero() || !status.UpdatedAt.IsZero() || !status.ExpiresAt.IsZero() || status.EvidenceGeneration != 0 {
		t.Fatalf("baseline fabricated event evidence: %+v", status)
	}
}

func TestLeafMobilityInitiatorProjectionIsGenerationBound(t *testing.T) {
	ref := engine.PathRef{ID: 7, Owner: 9}
	now := time.Unix(123, 456)
	deadline := now.Add(90 * time.Second)
	facts := leafmobility.Facts{
		Kind:       leafmobility.KindRawTCP,
		Role:       leafmobility.RoleDialer,
		Scope:      leafmobility.ScopeEndpoint,
		Session:    leafmobility.SessionStream,
		Operations: leafmobility.OperationTCPRepair,
		Generation: 11,
	}
	base := engine.LeafMobilityInitiatorSnapshot{
		Ref: ref, EvidenceGeneration: 3, SourceEndpointGeneration: facts.Generation,
		EvidenceReason: leafmobility.RefreshReasonRouteSourceChanged,
		ObservedAt:     now, UpdatedAt: now.Add(time.Millisecond), Deadline: deadline,
		Operation: leafmobility.OperationTCPRepair, Fallback: leafmobility.FallbackRedialAttach,
		TransactionID: leafmobility.TransactionID{0x41, 0x42},
	}
	tests := []struct {
		name       string
		phase      engine.LeafMobilityInitiatorPhase
		operation  leafmobility.Operation
		resultGen  uint64
		wantState  MobilityState
		wantID     MobilityID
		wantReason MobilityReason
	}{
		{name: "pending", phase: engine.LeafMobilityInitiatorPending, operation: 0, wantState: MobilityStatePending, wantID: MobilityRedialAttach, wantReason: MobilityReasonRouteSourceChanged},
		{name: "deferred before plan", phase: engine.LeafMobilityInitiatorDeferred, operation: 0, wantState: MobilityStateDeferred, wantID: MobilityRedialAttach, wantReason: MobilityReasonRouteSourceChanged},
		{name: "planning", phase: engine.LeafMobilityInitiatorPlanning, operation: 0, wantState: MobilityStatePlanning, wantID: MobilityRedialAttach, wantReason: MobilityReasonRouteSourceChanged},
		{name: "deferred after plan", phase: engine.LeafMobilityInitiatorDeferred, operation: leafmobility.OperationTCPRepair, wantState: MobilityStateDeferred, wantID: MobilityTCPRepairSamePeerTuple, wantReason: MobilityReasonRouteSourceChanged},
		{name: "negotiating", phase: engine.LeafMobilityInitiatorNegotiating, operation: leafmobility.OperationTCPRepair, wantState: MobilityStateNegotiating, wantID: MobilityTCPRepairSamePeerTuple, wantReason: MobilityReasonRouteSourceChanged},
		{name: "executing", phase: engine.LeafMobilityInitiatorExecuting, operation: leafmobility.OperationTCPRepair, wantState: MobilityStateExecuting, wantID: MobilityTCPRepairSamePeerTuple, wantReason: MobilityReasonRouteSourceChanged},
		{name: "committed", phase: engine.LeafMobilityInitiatorCommitted, operation: leafmobility.OperationTCPRepair, resultGen: facts.Generation, wantState: MobilityStateCommitted, wantID: MobilityTCPRepairSamePeerTuple, wantReason: MobilityReasonRouteSourceChanged},
		{name: "rolled back", phase: engine.LeafMobilityInitiatorRolledBack, operation: leafmobility.OperationTCPRepair, resultGen: facts.Generation, wantState: MobilityStateRolledBack, wantID: MobilityTCPRepairSamePeerTuple, wantReason: MobilityReasonExecutionRolledBack},
		{name: "rejected", phase: engine.LeafMobilityInitiatorRejected, operation: leafmobility.OperationTCPRepair, wantState: MobilityStateRejected, wantID: MobilityTCPRepairSamePeerTuple, wantReason: MobilityReasonPeerRejected},
		{name: "expired", phase: engine.LeafMobilityInitiatorExpired, operation: leafmobility.OperationTCPRepair, wantState: MobilityStateExpired, wantID: MobilityTCPRepairSamePeerTuple, wantReason: MobilityReasonEventBudgetExpired},
		{name: "fail closed", phase: engine.LeafMobilityInitiatorFailClosed, operation: leafmobility.OperationTCPRepair, resultGen: facts.Generation, wantState: MobilityStateFailClosed, wantID: MobilityTCPRepairSamePeerTuple, wantReason: MobilityReasonDestructiveOutcomeUntrusted},
		{name: "safe failure", phase: engine.LeafMobilityInitiatorFailed, operation: leafmobility.OperationTCPRepair, wantState: MobilityStateBaseline, wantID: MobilityTCPRepairSamePeerTuple, wantReason: MobilityReasonAttemptFailedSafely},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation := base
			observation.Phase = test.phase
			observation.Operation = test.operation
			observation.ResultEndpointGeneration = test.resultGen
			if test.resultGen != 0 {
				observation.SourceEndpointGeneration = facts.Generation - 1
			}
			got := projectLeafMobility(engine.LeafMobilitySnapshot{Ref: ref, Facts: facts, Initiator: observation})
			if got.State != test.wantState || got.ID != test.wantID || got.Reason != test.wantReason ||
				got.TransactionID != [16]byte(base.TransactionID) ||
				got.EndpointGeneration != facts.Generation || got.EvidenceGeneration != base.EvidenceGeneration ||
				got.ObservedAt != now || got.UpdatedAt != base.UpdatedAt || got.ExpiresAt != deadline {
				t.Fatalf("projection=%+v", got)
			}
			if got.Fallback != MobilityRedialAttach {
				t.Fatalf("fallback=%q want=%q", got.Fallback, MobilityRedialAttach)
			}
			if got.Negotiated != MobilityTCPRepairSamePeerTuple {
				t.Fatalf("negotiated=%q want=%q", got.Negotiated, MobilityTCPRepairSamePeerTuple)
			}
		})
	}

	t.Run("unavailable source", func(t *testing.T) {
		observation := base
		observation.Phase = engine.LeafMobilityInitiatorDeferred
		observation.EvidenceReason = leafmobility.RefreshReasonRouteSourceUnavailable
		got := projectLeafMobility(engine.LeafMobilitySnapshot{Ref: ref, Facts: facts, Initiator: observation})
		if got.State != MobilityStateDeferred || got.Reason != MobilityReasonRouteSourceUnavailable || got.ExpiresAt != deadline {
			t.Fatalf("unavailable projection=%+v", got)
		}
	})

	for _, test := range []struct {
		name string
		in   leafmobility.RefreshReason
		want MobilityReason
	}{
		{name: "link unresponsive", in: leafmobility.RefreshReasonLinkUnresponsive, want: MobilityReasonLinkUnresponsive},
		{name: "local read", in: leafmobility.RefreshReasonLocalReadFailure, want: MobilityReasonLocalReadFailure},
		{name: "local write", in: leafmobility.RefreshReasonLocalWriteFailure, want: MobilityReasonLocalWriteFailure},
		{name: "outer MTU", in: leafmobility.RefreshReasonOuterMTUFailure, want: MobilityReasonOuterMTUFailure},
		{name: "replay stalled", in: leafmobility.RefreshReasonReplayStalled, want: MobilityReasonReplayStalled},
		{name: "replay failure", in: leafmobility.RefreshReasonReplayFailure, want: MobilityReasonReplayFailure},
		{name: "liveness probe", in: leafmobility.RefreshReasonLivenessProbeFailure, want: MobilityReasonLivenessProbeFailure},
	} {
		t.Run(test.name, func(t *testing.T) {
			observation := base
			observation.Phase = engine.LeafMobilityInitiatorExecuting
			observation.EvidenceReason = test.in
			got := projectLeafMobility(engine.LeafMobilitySnapshot{Ref: ref, Facts: facts, Initiator: observation})
			if got.State != MobilityStateExecuting || got.Reason != test.want || got.ExpiresAt != deadline {
				t.Fatalf("typed fault projection=%+v", got)
			}
		})
	}

	t.Run("restored physical baseline", func(t *testing.T) {
		observation := base
		observation.Phase = engine.LeafMobilityInitiatorBaseline
		observation.EvidenceReason = leafmobility.RefreshReasonRouteSourceRestored
		observation.Deadline = time.Time{}
		got := projectLeafMobility(engine.LeafMobilitySnapshot{Ref: ref, Facts: facts, Initiator: observation})
		if got.State != MobilityStateBaseline || got.Reason != MobilityReasonRouteSourceRestored || !got.ExpiresAt.IsZero() {
			t.Fatalf("restored projection=%+v", got)
		}
	})

	for _, mutate := range []struct {
		name  string
		phase engine.LeafMobilityInitiatorPhase
		fn    func(*engine.LeafMobilitySnapshot)
	}{
		{name: "stale owner", phase: engine.LeafMobilityInitiatorCommitted, fn: func(s *engine.LeafMobilitySnapshot) { s.Initiator.Ref.Owner++ }},
		{name: "stale source generation", phase: engine.LeafMobilityInitiatorExecuting, fn: func(s *engine.LeafMobilitySnapshot) { s.Initiator.SourceEndpointGeneration-- }},
		{name: "stale committed result", phase: engine.LeafMobilityInitiatorCommitted, fn: func(s *engine.LeafMobilitySnapshot) { s.Initiator.ResultEndpointGeneration-- }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			observation := base
			observation.Phase = mutate.phase
			observation.ResultEndpointGeneration = facts.Generation
			snapshot := engine.LeafMobilitySnapshot{Ref: ref, Facts: facts, Initiator: observation}
			mutate.fn(&snapshot)
			got := projectLeafMobility(snapshot)
			if got.State != MobilityStateBaseline || got.ID != MobilityRedialAttach || got.Negotiated != "" || got.EvidenceGeneration != 0 {
				t.Fatalf("stale evidence was published: %+v", got)
			}
		})
	}
}

func TestLeafMobilitySubscriptionProjection(t *testing.T) {
	ref := engine.PathRef{ID: 3, Owner: 5}
	facts := leafmobility.Facts{
		Kind: leafmobility.KindRawTCP, Role: leafmobility.RoleDialer, Scope: leafmobility.ScopeEndpoint,
		Session: leafmobility.SessionStream, Operations: leafmobility.OperationTCPRepair, Generation: 17,
	}
	for _, test := range []struct {
		phase      engine.LeafMobilityInitiatorPhase
		wantState  MobilityState
		wantReason MobilityReason
	}{
		{phase: engine.LeafMobilityInitiatorIdle, wantState: MobilityStateBaseline, wantReason: MobilityReasonAwaitingFactualChange},
		{phase: engine.LeafMobilityInitiatorSubscriptionUnavailable, wantState: MobilityStateSubscriptionUnavailable, wantReason: MobilityReasonRefreshSubscriptionUnavailable},
	} {
		updated := time.Unix(456, 0)
		got := projectLeafMobility(engine.LeafMobilitySnapshot{
			Ref: ref, Facts: facts,
			Initiator: engine.LeafMobilityInitiatorSnapshot{
				Ref: ref, SourceEndpointGeneration: facts.Generation, Phase: test.phase, UpdatedAt: updated,
			},
		})
		if got.State != test.wantState || got.Reason != test.wantReason || got.ID != MobilityRedialAttach ||
			got.Negotiated != MobilityTCPRepairSamePeerTuple || got.Fallback != MobilityRedialAttach ||
			got.EndpointGeneration != facts.Generation || got.UpdatedAt != updated || got.EvidenceGeneration != 0 {
			t.Fatalf("phase=%d status=%+v", test.phase, got)
		}
	}
}

func TestLeafMobilityIdleProjectionRequiresNegotiatedInitiator(t *testing.T) {
	ref := engine.PathRef{ID: 7, Owner: 9}
	facts := leafmobility.Facts{
		Kind: leafmobility.KindRawTCP, Role: leafmobility.RoleDialer, Scope: leafmobility.ScopeEndpoint,
		Session: leafmobility.SessionStream, Operations: leafmobility.OperationTCPRepair, Generation: 23,
	}
	got := projectLeafMobility(engine.LeafMobilitySnapshot{Ref: ref, Facts: facts})
	if got.ID != MobilityRedialAttach || got.Negotiated != "" || got.Fallback != "" || got.State != MobilityStateBaseline ||
		got.Reason != MobilityReasonPeerAgreementNotNegotiated {
		t.Fatalf("unnegotiated ownership projected as specialized mobility: %+v", got)
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
		Generation: leafmobility.NextGeneration(),
	})
	claim.RetireUnbound()
	status := planPathConnMobility(CarrierTCP, &mobilityClaimTestPath{PathConn: basetcp.Wrap(left), claim: claim})
	if status.ID != MobilityRedialAttach || status.Reason != MobilityReasonEndpointRetired || status.EndpointGeneration != 0 {
		t.Fatalf("retired endpoint status=%+v", status)
	}
}
