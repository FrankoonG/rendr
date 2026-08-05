package rendr

import (
	"time"

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
	MobilityReasonEndpointNotOwned           MobilityReason = "endpoint_not_owned"
	MobilityReasonEndpointRetired            MobilityReason = "endpoint_retired"
	MobilityReasonOwnedOperationNotQualified MobilityReason = "owned_operation_not_qualified"
	MobilityReasonPeerAgreementNotNegotiated MobilityReason = "peer_agreement_not_negotiated"
)

type MobilityStatus struct {
	ID                 MobilityID
	Reason             MobilityReason
	Fallback           MobilityID
	EndpointGeneration uint64
	PlannedAt          time.Time
}

func planLeafMobility(_ CarrierFamily, owned ...leafmobility.Facts) MobilityStatus {
	return planLeafMobilityAt(time.Now(), owned...)
}

func planLeafMobilityAt(plannedAt time.Time, owned ...leafmobility.Facts) MobilityStatus {
	planned := MobilityStatus{
		ID:        MobilityRedialAttach,
		Reason:    MobilityReasonEndpointNotOwned,
		PlannedAt: plannedAt,
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
		// The current wire epoch has no leaf-mobility transaction envelope.
		// Ownership and a driver operation are necessary but cannot authorize
		// unilateral mutation of a live peer connection.
		planned.Reason = MobilityReasonPeerAgreementNotNegotiated
	}
	return planned
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
