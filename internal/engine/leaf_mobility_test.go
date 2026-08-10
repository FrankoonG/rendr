package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/transport"
)

type claimedMemoryPath struct {
	transport.PathConn
	claim *leafmobility.Claim
}

func (p *claimedMemoryPath) LeafMobilityClaim() *leafmobility.Claim { return p.claim }

func (p *claimedMemoryPath) SubscribeLeafMobilityRefresh(ctx context.Context, fn func(leafmobility.RefreshEvidence)) (func(), error) {
	if source, ok := p.PathConn.(leafmobility.RefreshSource); ok {
		return source.SubscribeLeafMobilityRefresh(ctx, fn)
	}
	return func() {}, nil
}

func TestOwnedLeafClaimBindsToOnePhysicalGeneration(t *testing.T) {
	e, binding := admissionTestEngine(t)
	t.Cleanup(func() { _ = e.Close() })

	claim := leafmobility.MustNewClaim(leafmobility.Facts{
		Kind:       leafmobility.KindRawTCP,
		Role:       leafmobility.RoleDialer,
		Scope:      leafmobility.ScopeEndpoint,
		Session:    leafmobility.SessionStream,
		Generation: 1,
	})
	path, peer := newMemoryPathPair()
	defer peer.Close()
	id, err := e.AttachPathBound(&claimedMemoryPath{PathConn: path, claim: claim}, transport.PathSpec{Transport: "memory"}, binding)
	if err != nil {
		t.Fatal(err)
	}

	snapshot := e.TopologySnapshot()
	if len(snapshot.LeafMobility) != 1 {
		t.Fatalf("leaf mobility snapshots=%d want=1", len(snapshot.LeafMobility))
	}
	got := snapshot.LeafMobility[0]
	if got.Ref.ID != id || got.Ref.Owner == 0 || got.Facts.Kind != leafmobility.KindRawTCP {
		t.Fatalf("leaf mobility snapshot=%+v", got)
	}
	bound, ok := claim.Binding()
	if !ok || bound.PathID != id || bound.Owner != got.Ref.Owner || bound.FlowID != e.FlowID() ||
		bound.LocalTargetID != [16]byte(binding.LocalTXTargetID) || bound.PeerTargetID != [16]byte(binding.PeerTXTargetID) {
		t.Fatalf("claim binding=%+v ok=%v", bound, ok)
	}

	second, secondPeer := newMemoryPathPair()
	defer secondPeer.Close()
	_, err = e.AttachPathBound(&claimedMemoryPath{PathConn: second, claim: claim}, transport.PathSpec{Transport: "memory"}, binding)
	if !errors.Is(err, leafmobility.ErrAlreadyBound) {
		t.Fatalf("reused claim error=%v want=%v", err, leafmobility.ErrAlreadyBound)
	}
	_ = e.Close()
	if !claim.Retired() {
		t.Fatal("engine close did not retire bound ownership claim")
	}
}

func TestOwnedLeafClaimRetiresOnAdmissionAbort(t *testing.T) {
	e, binding := admissionTestEngine(t)
	defer e.Close()
	claim := leafmobility.MustNewClaim(leafmobility.Facts{
		Kind:       leafmobility.KindUDPFlow,
		Role:       leafmobility.RoleDialer,
		Scope:      leafmobility.ScopeEndpoint,
		Session:    leafmobility.SessionPacket,
		Generation: leafmobility.NextGeneration(),
	})
	path, peer := newMemoryPathPair()
	defer peer.Close()
	id, err := e.PreparePathBound(&claimedMemoryPath{PathConn: path, claim: claim}, transport.PathSpec{Transport: "memory"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	e.AbortPathAttach(id, errors.New("injected admission abort"))
	if !claim.Retired() {
		t.Fatal("admission abort did not retire bound ownership claim")
	}
}
