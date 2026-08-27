//go:build linux && amd64 && rendr_experimental_gvisor

package gvisor

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
)

func TestGVisorLivenessElectionGivesDialerOneTickPriority(t *testing.T) {
	dialer := (&linkOwner{role: leafmobility.RoleDialer}).livenessFailureThreshold()
	acceptor := (&linkOwner{role: leafmobility.RoleAcceptor}).livenessFailureThreshold()
	if dialer != outerLivenessFailure || acceptor != outerLivenessFailure+outerLivenessTick {
		t.Fatalf("liveness election thresholds dialer=%v acceptor=%v", dialer, acceptor)
	}
}

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

	if path.link.publishWireFailure(leafmobility.RefreshReasonLocalWriteFailure) {
		t.Fatal("canceled refresh subscriber accepted a later wire failure")
	}
}

func TestGVisorWireFaultEvidencePreservesFirstTypedCause(t *testing.T) {
	for _, reason := range []leafmobility.RefreshReason{
		leafmobility.RefreshReasonLinkUnresponsive,
		leafmobility.RefreshReasonLocalReadFailure,
		leafmobility.RefreshReasonLocalWriteFailure,
		leafmobility.RefreshReasonOuterMTUFailure,
		leafmobility.RefreshReasonReplayStalled,
		leafmobility.RefreshReasonReplayFailure,
		leafmobility.RefreshReasonLivenessProbeFailure,
	} {
		t.Run("reason-"+strconv.Itoa(int(reason)), func(t *testing.T) {
			listener := mustPacketListener(t)
			client, server := dialAndAccept(t, listener)
			t.Cleanup(func() {
				if err := client.Close(); err != nil {
					t.Errorf("close typed-fault client: %v", err)
				}
				if err := server.Close(); err != nil {
					t.Errorf("close typed-fault server: %v", err)
				}
			})
			path := client.(*retainedPathConn)
			claim := path.LeafMobilityClaim()
			binding := leafmobility.Binding{
				FlowID: [16]byte{92, byte(reason)}, LocalTargetID: [16]byte{92, 2}, PeerTargetID: [16]byte{92, 3},
				PathID: uint32(92 + reason), Owner: uint64(192 + reason),
			}
			issuer := leafmobility.NewAuthorityIssuer()
			if err := issuer.BindClaim(claim, binding); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = claim.Retire(binding) })
			events := make(chan leafmobility.RefreshEvidence, 1)
			cancel, err := path.SubscribeLeafMobilityRefresh(context.Background(), func(evidence leafmobility.RefreshEvidence) {
				events <- evidence
			})
			if err != nil {
				t.Fatal(err)
			}
			defer cancel()
			path.link.mu.Lock()
			path.link.routeBaseline = [32]byte{0xff}
			path.link.mu.Unlock()
			if !path.link.publishWireFailure(reason) {
				t.Fatalf("typed wire fault %d was not published", reason)
			}
			path.link.publishWireFailure(leafmobility.RefreshReasonLinkUnresponsive)
			select {
			case evidence := <-events:
				snapshot, validateErr := evidence.ValidateFor(claim, 0)
				if validateErr != nil {
					t.Fatal(validateErr)
				}
				if snapshot.Reason != reason {
					t.Fatalf("wire fault reason=%d want first cause=%d", snapshot.Reason, reason)
				}
			case <-time.After(time.Second):
				t.Fatalf("typed wire fault %d produced no evidence", reason)
			}
		})
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
