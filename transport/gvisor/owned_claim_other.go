//go:build !linux || !amd64

package gvisor

import (
	"net"

	"github.com/FrankoonG/rendr/internal/leafmobility"
)

func newPacketLinkClaim(owner *linkOwner, role leafmobility.Role) (*leafmobility.Claim, error) {
	if owner == nil || owner.LeafMobilityIncarnation() == 0 {
		return nil, net.ErrClosed
	}
	return leafmobility.NewClaim(leafmobility.Facts{
		Kind: leafmobility.KindGVisor, Role: role, Scope: leafmobility.ScopeEndpoint,
		Session: leafmobility.SessionAny, Generation: leafmobility.NextGeneration(),
	})
}
