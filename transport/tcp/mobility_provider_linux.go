//go:build linux && amd64 && rendr_experimental_tcprepair

package tcp

import "github.com/FrankoonG/rendr/internal/leafmobility"

var (
	_ leafmobility.ImplementationProvider = (*Transport)(nil)
	_ leafmobility.ImplementationProvider = (*Listener)(nil)
)

// LeafMobilityImplementation reports implementation presence only. The marker
// deliberately has no endpoint; each produced owned claim receives its own
// driver and must still pass fresh endpoint eligibility.
func (transport *Transport) LeafMobilityImplementation() leafmobility.ImplementationEvidence {
	return tcpRepairImplementationEvidence(transport)
}

// LeafMobilityImplementation reports implementation presence only. Accepted
// endpoints receive independent drivers and factual eligibility checks.
func (listener *Listener) LeafMobilityImplementation() leafmobility.ImplementationEvidence {
	return tcpRepairImplementationEvidence(listener)
}

func tcpRepairImplementationEvidence(owner leafmobility.ImplementationProvider) leafmobility.ImplementationEvidence {
	return leafmobility.MustNewImplementationEvidence(owner, &tcpRepairDriver{})
}
