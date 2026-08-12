package quic

import "github.com/FrankoonG/rendr/internal/leafmobility"

var (
	_ leafmobility.ImplementationProvider = (*Transport)(nil)
	_ leafmobility.ImplementationProvider = (*Listener)(nil)
	_ leafmobility.ImplementationProvider = (*DatagramListener)(nil)
)

// LeafMobilityImplementation reports production implementation presence.
// Per-connection ownership and current AddPath eligibility are still proved by
// each returned PathConn's sealed claim and fresh driver preflight.
func (transport *Transport) LeafMobilityImplementation() leafmobility.ImplementationEvidence {
	return quicCIDImplementationEvidence(transport)
}

func (listener *Listener) LeafMobilityImplementation() leafmobility.ImplementationEvidence {
	return quicCIDImplementationEvidence(listener)
}

func (listener *DatagramListener) LeafMobilityImplementation() leafmobility.ImplementationEvidence {
	return quicCIDImplementationEvidence(listener)
}

func quicCIDImplementationEvidence(owner leafmobility.ImplementationProvider) leafmobility.ImplementationEvidence {
	return leafmobility.MustNewImplementationEvidence(owner, &cidDriver{})
}
