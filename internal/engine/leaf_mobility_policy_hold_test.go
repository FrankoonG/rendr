package engine

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

func TestLeafMobilityRefreshCallbackHoldsSelectorBeforePlanning(t *testing.T) {
	var source *initiatorRefreshPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			source = &initiatorRefreshPath{PathConn: path}
			return source
		}, nil, nil, nil,
	)
	fixture.clientDriver.entered = make(chan struct{})
	fixture.clientDriver.release = make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(fixture.clientDriver.release) }) }
	t.Cleanup(release)

	fixture.client.pathsMu.RLock()
	subject := fixture.client.paths[fixture.clientRef.ID]
	fixture.client.pathsMu.RUnlock()
	if subject == nil {
		t.Fatal("missing subject path slot")
	}
	emitter, err := leafmobility.NewRefreshEmitter(fixture.clientClaim)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
	if err != nil {
		t.Fatal(err)
	}
	if source == nil || !source.publish(evidence) {
		t.Fatal("refresh source was not subscribed")
	}
	if holds := subject.mobilityPolicyHolds.Load(); holds == 0 {
		t.Fatal("refresh callback returned before publishing its policy hold")
	}
	if err := fixture.client.selectLocalTarget(
		fixture.ids["root"], fixture.ids["c"], "probe-wire-timeout", policySelectionProbeFailure,
	); !errors.Is(err, errPolicySelectionLeafMobilityHeld) {
		t.Fatalf("selection before mobility planning=%v, want %v", err, errPolicySelectionLeafMobilityHeld)
	}
	assertSelectorTarget(t, fixture.client, fixture.ids["root"], fixture.ids["a"])

	select {
	case <-fixture.clientDriver.entered:
	case <-time.After(time.Second):
		t.Fatal("automatic mobility did not reach blocked preflight")
	}
	release()
	eventuallyEngine(t, 3*time.Second, func() bool {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		return ok && status.Phase == LeafMobilityInitiatorCommitted
	})
	eventuallyEngine(t, time.Second, func() bool { return subject.mobilityPolicyHolds.Load() == 0 })
	if err := fixture.client.selectLocalTarget(
		fixture.ids["root"], fixture.ids["c"], "probe-wire-timeout", policySelectionProbeFailure,
	); err != nil {
		t.Fatalf("selection after automatic mobility completion remained held: %v", err)
	}
}

func TestLeafMobilityRefreshPendingReplacementBalancesPolicyHolds(t *testing.T) {
	var source *initiatorRefreshPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			source = &initiatorRefreshPath{PathConn: path}
			return source
		}, nil, nil, nil,
	)
	fixture.clientDriver.entered = make(chan struct{})
	fixture.clientDriver.release = make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(fixture.clientDriver.release) }) }
	t.Cleanup(release)
	fixture.client.pathsMu.RLock()
	subject := fixture.client.paths[fixture.clientRef.ID]
	fixture.client.pathsMu.RUnlock()
	if subject == nil || source == nil {
		t.Fatal("missing refresh subject")
	}
	emitter, err := leafmobility.NewRefreshEmitter(fixture.clientClaim)
	if err != nil {
		t.Fatal(err)
	}
	first, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
	if err != nil || !source.publish(first) {
		t.Fatalf("publish first refresh: published=%t err=%v", err == nil, err)
	}
	select {
	case <-fixture.clientDriver.entered:
	case <-time.After(time.Second):
		t.Fatal("first refresh did not reach blocked preflight")
	}
	for iteration := 0; iteration < 20; iteration++ {
		next, observeErr := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
		if observeErr != nil || !source.publish(next) {
			t.Fatalf("publish replacement %d: published=%t err=%v", iteration, observeErr == nil, observeErr)
		}
		if holds := subject.mobilityPolicyHolds.Load(); holds < 1 || holds > 2 {
			t.Fatalf("replacement %d retained %d policy holds, want 1..2", iteration, holds)
		}
	}
	release()
	eventuallyEngine(t, 3*time.Second, func() bool { return subject.mobilityPolicyHolds.Load() == 0 })
}

func TestLeafMobilityInitiatorNegotiationHoldsSelectedPolicyBranch(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xf1)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.client.selectLocalTarget(
		fixture.ids["root"], fixture.ids["c"], "probe-wire-timeout", policySelectionProbeFailure,
	); !errors.Is(err, errPolicySelectionLeafMobilityHeld) {
		t.Fatalf("selection during initiator fence=%v, want %v", err, errPolicySelectionLeafMobilityHeld)
	}
	assertSelectorTarget(t, fixture.client, fixture.ids["root"], fixture.ids["a"])
	if err := authority.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := fixture.client.selectLocalTarget(
		fixture.ids["root"], fixture.ids["c"], "probe-wire-timeout", policySelectionProbeFailure,
	); err != nil {
		t.Fatalf("selection after rollback remained held: %v", err)
	}
}

func TestLeafMobilityResponderPreparedHoldsSelectedPolicyBranch(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xf2)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.server.selectLocalTarget(
		fixture.ids["root"], fixture.ids["c"], "probe-wire-timeout", policySelectionProbeFailure,
	); !errors.Is(err, errPolicySelectionLeafMobilityHeld) {
		t.Fatalf("selection during responder PREPARED=%v, want %v", err, errPolicySelectionLeafMobilityHeld)
	}
	assertSelectorTarget(t, fixture.server, fixture.ids["root"], fixture.ids["a"])
	if err := authority.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := fixture.server.selectLocalTarget(
		fixture.ids["root"], fixture.ids["c"], "probe-wire-timeout", policySelectionProbeFailure,
	); err != nil {
		t.Fatalf("selection after responder release remained held: %v", err)
	}
}

func TestLeafMobilityHoldProtectsNestedSelectedSubtreeOnly(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "aggregate", "fallback"),
		runtimeNode(proto.GraphNodeKindBond, "aggregate", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
		runtimeNode(proto.GraphNodeKindPath, "fallback"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	var heldSlot *pathSlot
	for _, name := range []string{"a", "b", "fallback"} {
		path, peer := newMemoryPathPair()
		t.Cleanup(func() { _ = peer.Close() })
		id, err := e.AttachPathBound(path, transport.PathSpec{Transport: "memory"}, PathBinding{
			LocalTXTargetID: ids[name], PeerTXTargetID: ids[name],
		})
		if err != nil {
			t.Fatal(err)
		}
		if name == "a" {
			e.pathsMu.RLock()
			heldSlot = e.paths[id]
			e.pathsMu.RUnlock()
		}
	}
	if err := e.InitializePolicySelection(ids["root"], ids["aggregate"], "initial"); err != nil {
		t.Fatal(err)
	}
	hold := e.acquireLeafMobilityPolicyHold(heldSlot)
	if hold == nil {
		t.Fatal("failed to acquire nested leaf mobility policy hold")
	}
	if err := e.SelectLocalTarget(ids["root"], ids["fallback"], "quality"); !errors.Is(err, errPolicySelectionLeafMobilityHeld) {
		t.Fatalf("nested branch selection=%v, want %v", err, errPolicySelectionLeafMobilityHeld)
	}
	hold.Release()
	if err := e.SelectLocalTarget(ids["root"], ids["fallback"], "quality"); err != nil {
		t.Fatalf("nested branch selection after release: %v", err)
	}
}

func assertSelectorTarget(t *testing.T, e *Engine, selectorID, want proto.TargetID) {
	t.Helper()
	e.policyStateMu.Lock()
	got := e.policySelections[selectorID]
	e.policyStateMu.Unlock()
	if got != want {
		t.Fatalf("selector target=%x want %x", got, want)
	}
}
