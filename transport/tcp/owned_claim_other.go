//go:build !linux || !amd64

package tcp

import "github.com/FrankoonG/rendr/internal/leafmobility"

func newOwnedClaim(_ *endpointOwner, role leafmobility.Role) *leafmobility.Claim {
	return leafmobility.MustNewClaim(leafmobility.Facts{
		Kind: leafmobility.KindRawTCP, Role: role, Scope: leafmobility.ScopeEndpoint,
		Session: leafmobility.SessionAny, Generation: leafmobility.NextGeneration(),
	})
}
