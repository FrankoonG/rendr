//go:build rendr_experimental_gvisor

package gvisor

import "github.com/FrankoonG/rendr/internal/leafmobility"

var (
	_ leafmobility.ImplementationProvider = (*Transport)(nil)
	_ leafmobility.ImplementationProvider = (*Listener)(nil)
)

func (transport *Transport) LeafMobilityImplementation() leafmobility.ImplementationEvidence {
	return gvisorLinkImplementationEvidence(transport)
}

func (listener *Listener) LeafMobilityImplementation() leafmobility.ImplementationEvidence {
	return gvisorLinkImplementationEvidence(listener)
}

func gvisorLinkImplementationEvidence(owner leafmobility.ImplementationProvider) leafmobility.ImplementationEvidence {
	return leafmobility.MustNewImplementationEvidence(owner, &linkDriver{})
}
