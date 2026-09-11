//go:build linux && amd64

package tcp

import "github.com/FrankoonG/rendr/internal/leafmobility"

func newOwnedClaim(endpoint *endpointOwner, role leafmobility.Role) *leafmobility.Claim {
	driver := newTCPRepairDriver(endpoint)
	return leafmobility.MustNewDrivenClaimWithIncarnation(leafmobility.Facts{
		Kind: leafmobility.KindRawTCP, Role: role, Session: leafmobility.SessionAny,
		Generation: leafmobility.NextGeneration(),
	}, driver, leafmobility.MustNewResource(leafmobility.ScopeEndpoint), endpoint)
}
