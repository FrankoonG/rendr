//go:build rendr_experimental_gvisor

package gvisor

import "github.com/FrankoonG/rendr/internal/leafmobility"

func newPacketLinkClaim(owner *linkOwner, role leafmobility.Role) (*leafmobility.Claim, error) {
	driver := newLinkDriver(owner)
	claim, err := leafmobility.NewDrivenClaimWithIncarnation(leafmobility.Facts{
		Kind: leafmobility.KindGVisor, Role: role,
		Session: leafmobility.SessionAny, Generation: leafmobility.NextGeneration(),
	}, driver, leafmobility.MustNewResource(leafmobility.ScopeEndpoint), owner)
	if err != nil {
		return nil, err
	}
	if err := owner.attachClaim(claim); err != nil {
		return nil, err
	}
	return claim, nil
}
