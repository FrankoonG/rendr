package rendr

import (
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/transport"
)

type SessionProtocol string

const (
	SessionProtocolFramedStreamV3 SessionProtocol = "framed_stream_v3"
	SessionProtocolFramedPacketV3 SessionProtocol = "framed_packet_v3"
)

type MobilityID string

const (
	MobilityRedialAttach           MobilityID = "redial_attach"
	MobilityTCPRepairSamePeerTuple MobilityID = "tcp_repair_same_peer_tuple"
	MobilityQUICCIDRebind          MobilityID = "quic_cid_rebind"
	MobilityUDPFlowRebind          MobilityID = "udp_flow_rebind"
	MobilityGVisorPacketLinkRebind MobilityID = "gvisor_packet_link_rebind"
)

type MobilityReason string

const (
	MobilityReasonEndpointNotOwned               MobilityReason = "endpoint_not_owned"
	MobilityReasonEndpointRetired                MobilityReason = "endpoint_retired"
	MobilityReasonOwnedOperationNotQualified     MobilityReason = "owned_operation_not_qualified"
	MobilityReasonPeerAgreementNotNegotiated     MobilityReason = "peer_agreement_not_negotiated"
	MobilityReasonAwaitingFactualChange          MobilityReason = "awaiting_factual_change"
	MobilityReasonRefreshSubscriptionUnavailable MobilityReason = "refresh_subscription_unavailable"
	MobilityReasonRouteSourceChanged             MobilityReason = "route_source_changed"
	MobilityReasonRouteSourceUnavailable         MobilityReason = "route_source_unavailable"
	MobilityReasonRouteSourceRestored            MobilityReason = "route_source_restored"
	MobilityReasonAttemptFailedSafely            MobilityReason = "attempt_failed_safely"
	MobilityReasonPeerRejected                   MobilityReason = "peer_rejected"
	MobilityReasonEventBudgetExpired             MobilityReason = "event_budget_expired"
	MobilityReasonExecutionRolledBack            MobilityReason = "execution_rolled_back"
	MobilityReasonDestructiveOutcomeUntrusted    MobilityReason = "destructive_outcome_untrusted"
)

type MobilityState string

const (
	MobilityStateBaseline                MobilityState = "baseline"
	MobilityStateSubscriptionUnavailable MobilityState = "subscription_unavailable"
	MobilityStatePending                 MobilityState = "pending"
	MobilityStateDeferred                MobilityState = "deferred"
	MobilityStatePlanning                MobilityState = "planning"
	MobilityStateNegotiating             MobilityState = "negotiating"
	MobilityStateExecuting               MobilityState = "executing"
	MobilityStateCommitted               MobilityState = "committed"
	MobilityStateRolledBack              MobilityState = "rolled_back"
	MobilityStateRejected                MobilityState = "rejected"
	MobilityStateExpired                 MobilityState = "expired"
	MobilityStateFailClosed              MobilityState = "fail_closed"
)

type MobilityStatus struct {
	ID                 MobilityID
	State              MobilityState
	Reason             MobilityReason
	Fallback           MobilityID
	EndpointGeneration uint64
	EvidenceGeneration uint64
	ObservedAt         time.Time
	UpdatedAt          time.Time
	ExpiresAt          time.Time
}

func planLeafMobility(_ CarrierFamily, owned ...leafmobility.Facts) MobilityStatus {
	planned := MobilityStatus{
		ID:     MobilityRedialAttach,
		State:  MobilityStateBaseline,
		Reason: MobilityReasonEndpointNotOwned,
	}
	if len(owned) == 0 {
		return planned
	}
	facts := owned[0]
	planned.EndpointGeneration = facts.Generation
	planned.Reason = MobilityReasonOwnedOperationNotQualified

	var operation leafmobility.Operation
	switch facts.Kind {
	case leafmobility.KindRawTCP:
		operation = leafmobility.OperationTCPRepair
	case leafmobility.KindUDPFlow:
		operation = leafmobility.OperationUDPFlowRebind
	case leafmobility.KindQUIC:
		operation = leafmobility.OperationQUICCIDRebind
	case leafmobility.KindGVisor:
		operation = leafmobility.OperationGVisorLinkRebind
	}
	if operation != 0 && facts.Operations.Has(operation) {
		// Ownership facts alone cannot prove that this engine and its peer
		// negotiated the operation. A coherent topology snapshot may replace
		// this baseline with the engine-owned initiator observation.
		planned.Reason = MobilityReasonPeerAgreementNotNegotiated
	}
	return planned
}

func projectLeafMobility(snapshot engine.LeafMobilitySnapshot) MobilityStatus {
	baseline := planLeafMobility(CarrierUnknown, snapshot.Facts)
	observation := snapshot.Initiator
	if observation.Ref != snapshot.Ref {
		return baseline
	}

	sourceCurrent := observation.SourceEndpointGeneration != 0 &&
		observation.SourceEndpointGeneration == snapshot.Facts.Generation
	resultCurrent := observation.ResultEndpointGeneration != 0 &&
		observation.ResultEndpointGeneration == snapshot.Facts.Generation
	if observation.Phase == engine.LeafMobilityInitiatorIdle {
		if !sourceCurrent {
			return baseline
		}
		baseline.Reason = MobilityReasonAwaitingFactualChange
		baseline.UpdatedAt = observation.UpdatedAt
		return baseline
	}
	if observation.Phase == engine.LeafMobilityInitiatorSubscriptionUnavailable {
		if !sourceCurrent {
			return baseline
		}
		baseline.State = MobilityStateSubscriptionUnavailable
		baseline.Reason = MobilityReasonRefreshSubscriptionUnavailable
		baseline.UpdatedAt = observation.UpdatedAt
		return baseline
	}
	if observation.Phase == engine.LeafMobilityInitiatorSuperseded {
		return baseline
	}
	if observation.EvidenceGeneration == 0 || observation.ObservedAt.IsZero() || observation.UpdatedAt.IsZero() {
		return baseline
	}

	terminalResult := observation.Phase == engine.LeafMobilityInitiatorCommitted ||
		observation.Phase == engine.LeafMobilityInitiatorRolledBack ||
		observation.Phase == engine.LeafMobilityInitiatorFailClosed
	if (terminalResult && !resultCurrent) || (!terminalResult && !sourceCurrent) {
		return baseline
	}

	projected := MobilityStatus{
		ID:                 MobilityRedialAttach,
		State:              MobilityStateBaseline,
		Reason:             MobilityReasonRouteSourceChanged,
		EndpointGeneration: snapshot.Facts.Generation,
		EvidenceGeneration: observation.EvidenceGeneration,
		ObservedAt:         observation.ObservedAt,
		UpdatedAt:          observation.UpdatedAt,
		ExpiresAt:          observation.Deadline,
	}
	switch observation.EvidenceReason {
	case leafmobility.RefreshReasonRouteSourceUnavailable:
		projected.Reason = MobilityReasonRouteSourceUnavailable
	case leafmobility.RefreshReasonRouteSourceRestored:
		projected.Reason = MobilityReasonRouteSourceRestored
	}
	if operation := mobilityIDForOperation(observation.Operation); operation != "" {
		projected.ID = operation
	}
	if observation.Fallback == leafmobility.FallbackRedialAttach {
		projected.Fallback = MobilityRedialAttach
	}

	switch observation.Phase {
	case engine.LeafMobilityInitiatorPending:
		projected.State = MobilityStatePending
	case engine.LeafMobilityInitiatorDeferred:
		projected.State = MobilityStateDeferred
	case engine.LeafMobilityInitiatorPlanning:
		projected.State = MobilityStatePlanning
	case engine.LeafMobilityInitiatorBaseline:
		projected.State = MobilityStateBaseline
	case engine.LeafMobilityInitiatorNegotiating:
		projected.State = MobilityStateNegotiating
	case engine.LeafMobilityInitiatorExecuting:
		projected.State = MobilityStateExecuting
	case engine.LeafMobilityInitiatorCommitted:
		projected.State = MobilityStateCommitted
	case engine.LeafMobilityInitiatorRolledBack:
		projected.State = MobilityStateRolledBack
		projected.Reason = MobilityReasonExecutionRolledBack
	case engine.LeafMobilityInitiatorRejected:
		projected.State = MobilityStateRejected
		projected.Reason = MobilityReasonPeerRejected
	case engine.LeafMobilityInitiatorExpired:
		projected.State = MobilityStateExpired
		projected.Reason = MobilityReasonEventBudgetExpired
	case engine.LeafMobilityInitiatorFailClosed:
		projected.State = MobilityStateFailClosed
		projected.Reason = MobilityReasonDestructiveOutcomeUntrusted
	case engine.LeafMobilityInitiatorFailed:
		projected.State = MobilityStateBaseline
		projected.Reason = MobilityReasonAttemptFailedSafely
	default:
		return baseline
	}
	return projected
}

func mobilityIDForOperation(operation leafmobility.Operation) MobilityID {
	switch operation {
	case leafmobility.OperationTCPRepair:
		return MobilityTCPRepairSamePeerTuple
	case leafmobility.OperationQUICCIDRebind:
		return MobilityQUICCIDRebind
	case leafmobility.OperationUDPFlowRebind:
		return MobilityUDPFlowRebind
	case leafmobility.OperationGVisorLinkRebind:
		return MobilityGVisorPacketLinkRebind
	default:
		return ""
	}
}

func planPathConnMobility(carrier CarrierFamily, path transport.PathConn) MobilityStatus {
	if provider, ok := path.(leafmobility.Provider); ok {
		if claim := provider.LeafMobilityClaim(); claim != nil {
			if claim.Retired() {
				planned := planLeafMobility(carrier)
				planned.Reason = MobilityReasonEndpointRetired
				return planned
			}
			return planLeafMobility(carrier, claim.Snapshot())
		}
	}
	return planLeafMobility(carrier)
}
