//go:build rendr_experimental_gvisor

package gvisor

import (
	"context"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
)

func TestGVisorRefreshContextCancellationClearsSubscriberAndAllowsResubscribe(t *testing.T) {
	listener := mustPacketListener(t)
	client, server := dialAndAccept(t, listener)
	defer client.Close()
	defer server.Close()

	path := client.(*retainedPathConn)
	claim := path.LeafMobilityClaim()
	binding := leafmobility.Binding{
		FlowID: [16]byte{91, 1}, LocalTargetID: [16]byte{91, 2}, PeerTargetID: [16]byte{91, 3},
		PathID: 91, Owner: 191,
	}
	issuer := leafmobility.NewAuthorityIssuer()
	if err := issuer.BindClaim(claim, binding); err != nil {
		t.Fatal(err)
	}
	defer claim.Retire(binding)

	ctx, cancelContext := context.WithCancel(context.Background())
	returnedCancel, err := path.SubscribeLeafMobilityRefresh(ctx, func(leafmobility.RefreshEvidence) {})
	if err != nil {
		t.Fatal(err)
	}
	path.link.refreshMu.Lock()
	monitorDone := path.link.refreshDone
	dispatchDone := path.link.refreshDispatchDone
	path.link.refreshMu.Unlock()

	// Context ownership is part of RefreshSource's contract. The adapter must
	// clear its subscriber even if the caller has not invoked returnedCancel.
	cancelContext()
	waitRefreshLoopDone(t, "monitor", monitorDone)
	waitRefreshLoopDone(t, "dispatcher", dispatchDone)
	path.link.refreshMu.Lock()
	callback := path.link.refreshFn
	events := path.link.refreshEvents
	cancel := path.link.refreshCancel
	path.link.refreshMu.Unlock()
	if callback != nil || events != nil || cancel != nil {
		t.Fatalf("canceled refresh subscription remained installed: callback=%t events=%t cancel=%t",
			callback != nil, events != nil, cancel != nil)
	}

	// The returned cancel remains idempotent after context cancellation, and a
	// new engine generation can install its own exact subscription.
	returnedCancel()
	secondCancel, err := path.SubscribeLeafMobilityRefresh(
		context.Background(), func(leafmobility.RefreshEvidence) {},
	)
	if err != nil {
		t.Fatalf("resubscribe after context cancellation: %v", err)
	}
	path.link.refreshMu.Lock()
	secondMonitorDone := path.link.refreshDone
	secondDispatchDone := path.link.refreshDispatchDone
	path.link.refreshMu.Unlock()
	secondCancel()
	waitRefreshLoopDone(t, "second monitor", secondMonitorDone)
	waitRefreshLoopDone(t, "second dispatcher", secondDispatchDone)

	if path.link.publishWireFailure() {
		t.Fatal("canceled refresh subscriber accepted a later wire failure")
	}
}

func waitRefreshLoopDone(t testing.TB, name string, done <-chan struct{}) {
	t.Helper()
	if done == nil {
		t.Fatalf("%s has no completion signal", name)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("%s did not stop after refresh cancellation", name)
	}
}
