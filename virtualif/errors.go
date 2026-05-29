package virtualif

// ErrorReason is stable enough for regression tests and embedders to
// branch on without scraping localized error strings.
type ErrorReason string

const (
	ReasonTUNUnavailable            ErrorReason = "tun_unavailable"
	ReasonTUNPermissionDenied       ErrorReason = "tun_permission_denied"
	ReasonPeerL3IdentityUnsupported ErrorReason = "peer_l3_identity_unsupported"
	ReasonPeerEgressUnsupported     ErrorReason = "peer_egress_unsupported"
	ReasonInvalidMTU                ErrorReason = "invalid_mtu"
)

// Error is returned by virtual-interface capability probes and setup.
type Error struct {
	Op     string
	Reason ErrorReason
	Err    error
}

func (e *Error) Error() string {
	msg := string(e.Reason)
	if e.Op != "" {
		msg = e.Op + ": " + msg
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *Error) Unwrap() error { return e.Err }
