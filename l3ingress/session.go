package l3ingress

import "fmt"

// SessionKind is the rendr-facing shape required for one classified
// L3 flow.
type SessionKind string

const (
	SessionKindStream SessionKind = "stream"
	SessionKindPacket SessionKind = "packet"
)

// SessionErrorReason is a machine-readable per-flow session planning
// failure.
type SessionErrorReason string

const (
	ReasonSessionUndecided           SessionErrorReason = "flow_undecided"
	ReasonSessionDenied              SessionErrorReason = "flow_denied"
	ReasonSessionUnsupportedProtocol SessionErrorReason = "unsupported_protocol"
	ReasonSessionMissingPeer         SessionErrorReason = "missing_peer"
	ReasonSessionMissingRoot         SessionErrorReason = "missing_root"
	ReasonSessionMissingEgress       SessionErrorReason = "missing_egress"
	ReasonSessionIdentityMismatch    SessionErrorReason = "identity_mismatch"
)

// SessionError keeps ingress-to-rendr planning failures inspectable.
type SessionError struct {
	Reason SessionErrorReason
	Detail string
}

func (e *SessionError) Error() string {
	if e.Detail == "" {
		return "l3ingress: " + string(e.Reason)
	}
	return "l3ingress: " + string(e.Reason) + ": " + e.Detail
}

// SessionRequest is the stable handoff between l3ingress and the
// future TCP/UDP flow adapters that create rendr Conn/PacketConn
// sessions. Root is intentionally opaque here; the adapter layer
// that imports top-level rendr owns the concrete target type check.
type SessionRequest struct {
	Kind               SessionKind
	Identity           L3Identity
	Peer               string
	Root               any
	Egress             string
	Labels             map[string]string
	PreserveL3Identity bool
}

// BuildSessionRequest converts a parsed packet event plus cached router
// decision into the normalized request a TUN flow adapter needs before
// it creates a rendr stream or packet session.
func BuildSessionRequest(ev PacketEvent) (SessionRequest, error) {
	if !ev.Decided {
		return SessionRequest{}, sessionErr(ReasonSessionUndecided, "")
	}
	if ev.Decision.Deny {
		return SessionRequest{}, sessionErr(ReasonSessionDenied, ev.Decision.DenyReason)
	}
	id := ev.Meta.Identity
	if id == (L3Identity{}) {
		id = ev.Flow.L3Identity
	}
	if ev.Flow.L3Identity != (L3Identity{}) && id != ev.Flow.L3Identity {
		return SessionRequest{}, sessionErr(ReasonSessionIdentityMismatch,
			fmt.Sprintf("packet=%s flow=%s", id.String(), ev.Flow.L3Identity.String()))
	}
	var kind SessionKind
	switch id.Proto {
	case ProtocolTCP:
		kind = SessionKindStream
	case ProtocolUDP:
		kind = SessionKindPacket
	default:
		return SessionRequest{}, sessionErr(ReasonSessionUnsupportedProtocol, id.Proto.String())
	}
	if ev.Decision.Peer == "" {
		return SessionRequest{}, sessionErr(ReasonSessionMissingPeer, "")
	}
	if ev.Decision.Root == nil {
		return SessionRequest{}, sessionErr(ReasonSessionMissingRoot, "")
	}
	if ev.Decision.Egress == "" {
		return SessionRequest{}, sessionErr(ReasonSessionMissingEgress, "")
	}
	return SessionRequest{
		Kind:               kind,
		Identity:           id,
		Peer:               ev.Decision.Peer,
		Root:               ev.Decision.Root,
		Egress:             ev.Decision.Egress,
		Labels:             cloneStringMap(ev.Decision.Labels),
		PreserveL3Identity: true,
	}, nil
}

func sessionErr(reason SessionErrorReason, detail string) error {
	return &SessionError{Reason: reason, Detail: detail}
}
