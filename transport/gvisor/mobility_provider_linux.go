//go:build linux && amd64

package gvisor

import "github.com/FrankoonG/rendr/internal/leafmobility"

var (
	_ leafmobility.ImplementationProvider = (*Transport)(nil)
	_ leafmobility.ImplementationProvider = (*Listener)(nil)
)

// LeafMobilityImplementation reports implementation presence only. Each
// packet-carried endpoint must still prove sealed ownership, current route
// eligibility, and peer agreement before the driver can execute.
func (transport *Transport) LeafMobilityImplementation() leafmobility.ImplementationEvidence {
	return gvisorLinkImplementationEvidence(transport)
}

// LeafMobilityImplementation reports implementation presence only. Accepted
// packet-carried endpoints receive independent claims and factual preflight.
func (listener *Listener) LeafMobilityImplementation() leafmobility.ImplementationEvidence {
	return gvisorLinkImplementationEvidence(listener)
}

func gvisorLinkImplementationEvidence(owner leafmobility.ImplementationProvider) leafmobility.ImplementationEvidence {
	return leafmobility.MustNewImplementationEvidence(owner, &linkDriver{})
}
