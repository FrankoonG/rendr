package rendr

import "time"

type SessionProtocol string

const (
	SessionProtocolFramedStreamV3 SessionProtocol = "framed_stream_v3"
	SessionProtocolFramedPacketV3 SessionProtocol = "framed_packet_v3"
)

type MobilityID string

const (
	MobilityRedialAttach MobilityID = "redial_attach"
)

type MobilityStatus struct {
	ID        MobilityID
	Reason    string
	Fallback  MobilityID
	PlannedAt time.Time
}

func planLeafMobility(spec PathSpec, resolver *pathFactoryResolver) MobilityStatus {
	planned := MobilityStatus{ID: MobilityRedialAttach, PlannedAt: time.Now()}
	if resolver == nil || !resolver.hasFactory(spec.Transport) {
		planned.Reason = "no owned mobility endpoint; use framed redial/attach"
		return planned
	}
	switch resolver.carrierFamily(spec.Transport) {
	case CarrierTCP:
		planned.Reason = "generic TCP-family factory does not grant TCB ownership"
	case CarrierUDP:
		planned.Reason = "generic UDP-family factory does not grant CID or flow ownership"
	default:
		planned.Reason = "generic factory carrier is unknown"
	}
	return planned
}
