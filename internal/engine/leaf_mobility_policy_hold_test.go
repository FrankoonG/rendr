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
	testTypedLeafMobilityFaultReasonsRequirePolicyHold(t)
}

func TestLinkUnresponsiveRefreshHoldsSelectorBeforePlanning(t *testing.T) {
	tests := []struct {
		name   string
		reason leafmobility.RefreshReason
	}{
		{"link-unresponsive", leafmobility.RefreshReasonLinkUnresponsive},
		{"local-read-failure", leafmobility.RefreshReasonLocalReadFailure},
		{"local-write-failure", leafmobility.RefreshReasonLocalWriteFailure},
		{"replay-stalled", leafmobility.RefreshReasonReplayStalled},
		{"replay-failure", leafmobility.RefreshReasonReplayFailure},
		{"liveness-probe-failure", leafmobility.RefreshReasonLivenessProbeFailure},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testFaultRefreshAllowsFactualSelectorFailover(t, test.reason)
		})
	}
}

func testFaultRefreshAllowsFactualSelectorFailover(t *testing.T, reason leafmobility.RefreshReason) {
	var source *initiatorRefreshPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			source = &initiatorRefreshPath{PathConn: path}
			return source
		}, nil, nil, nil,
	)
	fixture.clientDriver.retryableFailures.Store(100)

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
	evidence, err := emitter.Observe(reason)
	if err != nil {
		t.Fatal(err)
	}
	if source == nil || !source.publish(evidence) {
		t.Fatal("fault refresh source was not subscribed")
	}
	if holds := subject.mobilityPolicyHolds.Load(); holds == 0 {
		t.Fatal("fault refresh callback returned without a selector policy hold")
	}
	eventuallyEngine(t, time.Second, func() bool {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		return ok && status.Phase == LeafMobilityInitiatorDeferred
	})
	if err := fixture.client.SelectLocalTarget(
		fixture.ids["root"], fixture.ids["c"], "ordinary-policy-move",
	); !errors.Is(err, errPolicySelectionLeafMobilityHeld) {
		t.Fatalf("ordinary selection during fault planning=%v, want %v", err, errPolicySelectionLeafMobilityHeld)
	}

	started := time.Now()
	if err := fixture.client.selectLocalTarget(
		fixture.ids["root"], fixture.ids["c"], "probe-wire-timeout", policySelectionProbeFailure,
	); err != nil {
		t.Fatalf("factual failover during fault planning: %v", err)
	}
	if elapsed := time.Since(started); elapsed >= 200*time.Millisecond {
		t.Fatalf("factual failover took %v, want <200ms", elapsed)
	}
	assertSelectorTarget(t, fixture.client, fixture.ids["root"], fixture.ids["c"])
	if active := fixture.client.ActivePath(); active != fixture.clientControlRef.ID {
		t.Fatalf("active path after factual failover=%d, want healthy C path %d", active, fixture.clientControlRef.ID)
	}
	assertLeafMobilityDataFlow(t, fixture, "fault-failover-to-c")
	if err := fixture.client.RetirePath(fixture.clientRef, errors.New("stop retryable fault planner")); err != nil {
		t.Fatal(err)
	}
}

func testTypedLeafMobilityFaultReasonsRequirePolicyHold(t *testing.T) {
	for _, reason := range []leafmobility.RefreshReason{
		leafmobility.RefreshReasonRouteSourceChanged,
		leafmobility.RefreshReasonLinkUnresponsive,
		leafmobility.RefreshReasonLocalReadFailure,
		leafmobility.RefreshReasonLocalWriteFailure,
		leafmobility.RefreshReasonOuterMTUFailure,
		leafmobility.RefreshReasonReplayStalled,
		leafmobility.RefreshReasonReplayFailure,
		leafmobility.RefreshReasonLivenessProbeFailure,
	} {
		if !leafMobilityRefreshRequiresPolicyHold(reason) {
			t.Fatalf("fault reason %d does not retain selector policy", reason)
		}
	}
	for _, reason := range []leafmobility.RefreshReason{
		leafmobility.RefreshReasonLinkUnresponsive,
		leafmobility.RefreshReasonLocalReadFailure,
		leafmobility.RefreshReasonLocalWriteFailure,
		leafmobility.RefreshReasonReplayStalled,
		leafmobility.RefreshReasonReplayFailure,
		leafmobility.RefreshReasonLivenessProbeFailure,
	} {
		if !leafMobilityRefreshIsLeafFault(reason) {
			t.Fatalf("actual leaf fault reason %d cannot bypass its planner hold", reason)
		}
	}
	for _, reason := range []leafmobility.RefreshReason{
		leafmobility.RefreshReasonRouteSourceChanged,
		leafmobility.RefreshReasonOuterMTUFailure,
	} {
		if leafMobilityRefreshIsLeafFault(reason) {
			t.Fatalf("non-fault transaction reason %d can bypass its policy hold", reason)
		}
	}
	for _, reason := range []leafmobility.RefreshReason{
		leafmobility.RefreshReasonInvalid,
		leafmobility.RefreshReasonRouteSourceUnavailable,
		leafmobility.RefreshReasonRouteSourceRestored,
	} {
		if leafMobilityRefreshRequiresPolicyHold(reason) {
			t.Fatalf("non-executable reason %d retained selector policy", reason)
		}
	}
}

func TestLeafMobilityRefreshCallbackDoesNotWaitForPolicyOwner(t *testing.T) {
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
	var releaseDriver sync.Once
	t.Cleanup(func() { releaseDriver.Do(func() { close(fixture.clientDriver.release) }) })

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
	evidence, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
	if err != nil {
		t.Fatal(err)
	}

	fixture.client.policyOwnerMu.Lock()
	ownerLocked := true
	t.Cleanup(func() {
		if ownerLocked {
			fixture.client.policyOwnerMu.Unlock()
		}
	})
	published := make(chan bool, 1)
	go func() { published <- source.publish(evidence) }()
	select {
	case ok := <-published:
		if !ok {
			t.Fatal("refresh source was not subscribed")
		}
	case <-time.After(time.Second):
		t.Fatal("refresh callback blocked behind policyOwnerMu")
	}
	if holds := subject.mobilityPolicyHolds.Load(); holds == 0 {
		t.Fatal("nonblocking callback returned without publishing a provisional hold")
	}
	fixture.client.policyOwnerMu.Unlock()
	ownerLocked = false
	releaseDriver.Do(func() { close(fixture.clientDriver.release) })
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

func TestLeafMobilityInactiveRefreshPromotesHoldAtPolicyActivation(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	base, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = peer.Close() })
	driverBase := &enginePlanDriver{
		operation: leafmobility.OperationTCPRepair,
		evidence:  leafmobility.EvidenceDigest{0xe2},
		entered:   make(chan struct{}),
		release:   make(chan struct{}),
	}
	var releaseDriver sync.Once
	t.Cleanup(func() { releaseDriver.Do(func() { close(driverBase.release) }) })
	driver := newAuthorityTestExecutionDriver(driverBase, newAuthorityTestIncarnationReporter())
	claim := leafmobility.MustNewDrivenClaimWithIncarnation(leafmobility.Facts{
		Kind: leafmobility.KindRawTCP, Role: leafmobility.RoleDialer,
		Session: leafmobility.SessionStream, Generation: leafmobility.NextGeneration(),
	}, driver, leafmobility.MustNewResource(leafmobility.ScopeEndpoint), driver.reporter)
	source := &initiatorRefreshPath{PathConn: base, claim: claim}
	id, err := fixture.client.AttachPathBound(
		&claimedMemoryPath{PathConn: source, claim: claim},
		transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "inactive-refresh"}},
		PathBinding{LocalTXTargetID: fixture.ids["b"], PeerTXTargetID: fixture.ids["b"]},
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.client.pathsMu.RLock()
	slot := fixture.client.paths[id]
	fixture.client.pathsMu.RUnlock()
	if slot == nil {
		t.Fatal("missing inactive refresh slot")
	}
	emitter, err := leafmobility.NewRefreshEmitter(claim)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
	if err != nil {
		t.Fatal(err)
	}
	if !source.publish(evidence) {
		t.Fatal("inactive refresh source was not subscribed")
	}
	select {
	case <-driverBase.entered:
	case <-time.After(time.Second):
		t.Fatal("inactive refresh did not reach blocked preflight")
	}
	if holds := slot.mobilityPolicyHolds.Load(); holds != 0 {
		t.Fatalf("inactive refresh held policy before activation: %d", holds)
	}
	if err := fixture.client.SelectLocalTarget(fixture.ids["root"], fixture.ids["b"], "activate-refresh"); err != nil {
		t.Fatal(err)
	}
	if holds := slot.mobilityPolicyHolds.Load(); holds == 0 {
		t.Fatal("policy activation did not promote inactive refresh hold")
	}
	if err := fixture.client.SelectLocalTarget(fixture.ids["root"], fixture.ids["c"], "move-away"); !errors.Is(err, errPolicySelectionLeafMobilityHeld) {
		t.Fatalf("selection after refresh activation=%v, want %v", err, errPolicySelectionLeafMobilityHeld)
	}
	releaseDriver.Do(func() { close(driverBase.release) })
}

func TestLeafMobilityRefreshPublishedAfterPolicyActivationPromotesHold(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	base, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = peer.Close() })
	driverBase := &enginePlanDriver{
		operation: leafmobility.OperationTCPRepair,
		evidence:  leafmobility.EvidenceDigest{0xe3},
		entered:   make(chan struct{}),
		release:   make(chan struct{}),
	}
	var releaseDriver sync.Once
	t.Cleanup(func() { releaseDriver.Do(func() { close(driverBase.release) }) })
	driver := newAuthorityTestExecutionDriver(driverBase, newAuthorityTestIncarnationReporter())
	claim := leafmobility.MustNewDrivenClaimWithIncarnation(leafmobility.Facts{
		Kind: leafmobility.KindRawTCP, Role: leafmobility.RoleDialer,
		Session: leafmobility.SessionStream, Generation: leafmobility.NextGeneration(),
	}, driver, leafmobility.MustNewResource(leafmobility.ScopeEndpoint), driver.reporter)
	source := &initiatorRefreshPath{PathConn: base, claim: claim}
	id, err := fixture.client.AttachPathBound(
		&claimedMemoryPath{PathConn: source, claim: claim},
		transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "late-refresh"}},
		PathBinding{LocalTXTargetID: fixture.ids["b"], PeerTXTargetID: fixture.ids["b"]},
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.client.pathsMu.RLock()
	slot := fixture.client.paths[id]
	fixture.client.pathsMu.RUnlock()
	if slot == nil {
		t.Fatal("missing late refresh slot")
	}

	emitter, err := leafmobility.NewRefreshEmitter(claim)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
	if err != nil {
		t.Fatal(err)
	}
	reachedPublish := make(chan struct{})
	releasePublish := make(chan struct{})
	var releasePublishOnce sync.Once
	t.Cleanup(func() { releasePublishOnce.Do(func() { close(releasePublish) }) })
	fixture.client.leafRefreshBeforePublish = func() {
		close(reachedPublish)
		<-releasePublish
	}
	published := make(chan bool, 1)
	go func() { published <- source.publish(evidence) }()
	select {
	case <-reachedPublish:
	case <-time.After(time.Second):
		t.Fatal("refresh callback did not reach the pre-publication boundary")
	}
	if holds := slot.mobilityPolicyHolds.Load(); holds != 0 {
		t.Fatalf("inactive unpublished refresh held policy: %d", holds)
	}
	if err := fixture.client.SelectLocalTarget(fixture.ids["root"], fixture.ids["b"], "activate-before-publish"); err != nil {
		t.Fatal(err)
	}
	releasePublishOnce.Do(func() { close(releasePublish) })
	if !<-published {
		t.Fatal("late refresh source was not subscribed")
	}
	fixture.client.leafRefreshBeforePublish = nil
	select {
	case <-driverBase.entered:
	case <-time.After(time.Second):
		t.Fatal("late refresh did not reach blocked preflight")
	}
	if holds := slot.mobilityPolicyHolds.Load(); holds == 0 {
		t.Fatal("late refresh publication did not hold the newly effective leaf")
	}
	if err := fixture.client.SelectLocalTarget(fixture.ids["root"], fixture.ids["c"], "move-away"); !errors.Is(err, errPolicySelectionLeafMobilityHeld) {
		t.Fatalf("selection after late refresh=%v, want %v", err, errPolicySelectionLeafMobilityHeld)
	}
	releaseDriver.Do(func() { close(driverBase.release) })
}

func TestLeafMobilityPendingRefreshPromotesHoldAtActivation(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	base, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = peer.Close() })
	driverBase := &enginePlanDriver{
		operation: leafmobility.OperationTCPRepair,
		evidence:  leafmobility.EvidenceDigest{0xe1},
		entered:   make(chan struct{}),
		release:   make(chan struct{}),
	}
	var releaseDriver sync.Once
	t.Cleanup(func() { releaseDriver.Do(func() { close(driverBase.release) }) })
	driver := newAuthorityTestExecutionDriver(driverBase, newAuthorityTestIncarnationReporter())
	claim := leafmobility.MustNewDrivenClaimWithIncarnation(leafmobility.Facts{
		Kind: leafmobility.KindRawTCP, Role: leafmobility.RoleDialer,
		Session: leafmobility.SessionStream, Generation: leafmobility.NextGeneration(),
	}, driver, leafmobility.MustNewResource(leafmobility.ScopeEndpoint), driver.reporter)
	source := &initiatorRefreshPath{PathConn: base, claim: claim}
	replacementID, err := fixture.client.PreparePathBound(
		&claimedMemoryPath{PathConn: source, claim: claim},
		transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "selected-refresh-replacement"}},
		fixture.binding,
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.client.pathsMu.RLock()
	replacement := fixture.client.pendingPaths[replacementID]
	fixture.client.pathsMu.RUnlock()
	if replacement == nil {
		t.Fatal("missing pending replacement slot")
	}
	emitter, err := leafmobility.NewRefreshEmitter(claim)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
	if err != nil {
		t.Fatal(err)
	}
	if !source.publish(evidence) {
		t.Fatal("pending refresh source was not subscribed")
	}
	if err := fixture.client.StagePathAttach(replacementID); err != nil {
		t.Fatal(err)
	}

	observedHold := make(chan int32, 1)
	releaseActivation := make(chan struct{})
	var releaseActivationOnce sync.Once
	t.Cleanup(func() { releaseActivationOnce.Do(func() { close(releaseActivation) }) })
	fixture.client.activationAfterInitialSelection = func() {
		observedHold <- replacement.mobilityPolicyHolds.Load()
		<-releaseActivation
	}
	activated := make(chan error, 1)
	go func() {
		activated <- fixture.client.activateStagedPathContext(context.Background(), replacementID, true, true)
	}()
	var holds int32
	select {
	case holds = <-observedHold:
	case <-time.After(time.Second):
		t.Fatal("replacement activation did not reach publication hook")
	}
	releaseActivationOnce.Do(func() { close(releaseActivation) })
	if err := <-activated; err != nil {
		t.Fatal(err)
	}
	fixture.client.activationAfterInitialSelection = nil
	if holds == 0 {
		t.Fatal("pending refresh hold was not promoted with physical activation")
	}
	select {
	case <-driverBase.entered:
	case <-time.After(time.Second):
		t.Fatal("activated refresh did not reach blocked preflight")
	}
	if err := fixture.client.SelectLocalTarget(fixture.ids["root"], fixture.ids["c"], "quality"); !errors.Is(err, errPolicySelectionLeafMobilityHeld) {
		t.Fatalf("selection during promoted refresh=%v, want %v", err, errPolicySelectionLeafMobilityHeld)
	}
	releaseDriver.Do(func() { close(driverBase.release) })
}

func TestLeafMobilityRecoveredDesiredRefreshHoldsBeforeFirstData(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	runtime := fixture.client.localExecutionRuntime()
	if err := runtime.selectChild(fixture.ids["root"], fixture.ids["b"]); err != nil {
		t.Fatal(err)
	}
	if leaves, _, err := runtime.activeLeafTargets(runtimeAttached(fixture.ids, "a", "c")); err != nil {
		t.Fatal(err)
	} else if len(leaves) != 1 || leaves[0] != fixture.ids["a"] {
		t.Fatalf("desired-b fallback leaves=%x want a", leaves)
	}

	base, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = peer.Close() })
	driverBase := &enginePlanDriver{
		operation: leafmobility.OperationTCPRepair,
		evidence:  leafmobility.EvidenceDigest{0xe4},
		entered:   make(chan struct{}),
		release:   make(chan struct{}),
	}
	var releaseDriver sync.Once
	t.Cleanup(func() { releaseDriver.Do(func() { close(driverBase.release) }) })
	driver := newAuthorityTestExecutionDriver(driverBase, newAuthorityTestIncarnationReporter())
	claim := leafmobility.MustNewDrivenClaimWithIncarnation(leafmobility.Facts{
		Kind: leafmobility.KindRawTCP, Role: leafmobility.RoleDialer,
		Session: leafmobility.SessionStream, Generation: leafmobility.NextGeneration(),
	}, driver, leafmobility.MustNewResource(leafmobility.ScopeEndpoint), driver.reporter)
	source := &initiatorRefreshPath{PathConn: base, claim: claim}
	binding := PathBinding{LocalTXTargetID: fixture.ids["b"], PeerTXTargetID: fixture.ids["b"]}
	recoveredID, err := fixture.client.PreparePathBound(
		&claimedMemoryPath{PathConn: source, claim: claim},
		transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "recovered-desired-refresh"}},
		binding,
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.client.pathsMu.RLock()
	recovered := fixture.client.pendingPaths[recoveredID]
	fixture.client.pathsMu.RUnlock()
	if recovered == nil {
		t.Fatal("missing recovered desired slot")
	}
	emitter, err := leafmobility.NewRefreshEmitter(claim)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
	if err != nil {
		t.Fatal(err)
	}
	if !source.publish(evidence) {
		t.Fatal("recovered desired refresh source was not subscribed")
	}
	if holds := recovered.mobilityPolicyHolds.Load(); holds != 0 {
		t.Fatalf("pending recovered desired path held policy before activation: %d", holds)
	}
	if err := fixture.client.StagePathAttach(recoveredID); err != nil {
		t.Fatal(err)
	}

	observedHold := make(chan int32, 1)
	releaseActivation := make(chan struct{})
	var releaseActivationOnce sync.Once
	t.Cleanup(func() { releaseActivationOnce.Do(func() { close(releaseActivation) }) })
	fixture.client.activationAfterInitialSelection = func() {
		observedHold <- recovered.mobilityPolicyHolds.Load()
		<-releaseActivation
	}
	activated := make(chan error, 1)
	go func() {
		activated <- fixture.client.activateStagedPathContext(context.Background(), recoveredID, true, true)
	}()
	var holds int32
	select {
	case holds = <-observedHold:
	case <-time.After(time.Second):
		t.Fatal("recovered desired activation did not reach publication hook")
	}
	if holds == 0 {
		t.Fatal("recovered desired refresh was not held before first DATA")
	}
	releaseActivationOnce.Do(func() { close(releaseActivation) })
	if err := <-activated; err != nil {
		t.Fatal(err)
	}
	fixture.client.activationAfterInitialSelection = nil
	select {
	case <-driverBase.entered:
	case <-time.After(time.Second):
		t.Fatal("recovered desired refresh did not reach blocked preflight")
	}
	if err := fixture.client.SelectLocalTarget(fixture.ids["root"], fixture.ids["c"], "move-away"); !errors.Is(err, errPolicySelectionLeafMobilityHeld) {
		t.Fatalf("selection during recovered desired refresh=%v, want %v", err, errPolicySelectionLeafMobilityHeld)
	}
	releaseDriver.Do(func() { close(driverBase.release) })
}

func TestLeafMobilityCloseDrainsOrphanedRefreshEnqueue(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	slot := &pathSlot{id: 41, owner: 73}
	hold := holdLeafMobilityPolicy(slot)
	ref := PathRef{ID: slot.id, Owner: slot.owner}
	e.leafRefreshMu.Lock()
	e.leafRefreshPending[ref] = leafMobilityRefreshEvent{ref: ref, policyHold: hold}
	e.leafRefreshMu.Unlock()

	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	e.leafRefreshMu.Lock()
	pending := len(e.leafRefreshPending)
	e.leafRefreshMu.Unlock()
	if pending != 0 || slot.mobilityPolicyHolds.Load() != 0 {
		t.Fatalf("closed refresh queue retained pending=%d holds=%d", pending, slot.mobilityPolicyHolds.Load())
	}
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

func TestLeafMobilityHoldProtectsEffectiveFallbackInsteadOfDesiredLeaf(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b", "c"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
		runtimeNode(proto.GraphNodeKindPath, "c"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	var fallback *pathSlot
	for _, name := range []string{"a", "c"} {
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
			fallback = e.paths[id]
			e.pathsMu.RUnlock()
		}
	}
	runtime := e.localExecutionRuntime()
	if err := runtime.selectChild(ids["root"], ids["b"]); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runtime.activeLeafTargets(runtimeAttached(ids, "a", "c")); err != nil {
		t.Fatal(err)
	}
	hold := e.acquireLeafMobilityPolicyHold(fallback)
	if hold == nil {
		t.Fatal("failed to hold effective fallback")
	}
	defer hold.Release()
	if err := e.SelectLocalTarget(ids["root"], ids["c"], "quality"); !errors.Is(err, errPolicySelectionLeafMobilityHeld) {
		t.Fatalf("selection away from effective fallback=%v, want %v", err, errPolicySelectionLeafMobilityHeld)
	}
}

func TestLeafMobilityPolicySwitchProjectsNestedPhysicalPathRefs(t *testing.T) {
	root := proto.GraphNode{
		ID:       proto.DeriveTargetID(proto.GraphNodeKindSelector, "root"),
		Kind:     proto.GraphNodeKindSelector,
		Name:     "root",
		Children: []proto.TargetID{proto.DeriveTargetID(proto.GraphNodeKindBond, "aggregate"), proto.DeriveTargetID(proto.GraphNodeKindPath, "fallback")},
	}
	aggregate := proto.GraphNode{
		ID:       proto.DeriveTargetID(proto.GraphNodeKindBond, "aggregate"),
		Kind:     proto.GraphNodeKindBond,
		Name:     "aggregate",
		Children: []proto.TargetID{proto.DeriveTargetID(proto.GraphNodeKindSelector, "choice"), proto.DeriveTargetID(proto.GraphNodeKindRace, "redundant")},
	}
	choice := proto.GraphNode{
		ID:       proto.DeriveTargetID(proto.GraphNodeKindSelector, "choice"),
		Kind:     proto.GraphNodeKindSelector,
		Name:     "choice",
		Children: []proto.TargetID{proto.DeriveTargetID(proto.GraphNodeKindPath, "a"), proto.DeriveTargetID(proto.GraphNodeKindPath, "b")},
	}
	redundant := proto.GraphNode{
		ID:       proto.DeriveTargetID(proto.GraphNodeKindRace, "redundant"),
		Kind:     proto.GraphNodeKindRace,
		Name:     "redundant",
		Children: []proto.TargetID{proto.DeriveTargetID(proto.GraphNodeKindPath, "c"), proto.DeriveTargetID(proto.GraphNodeKindPath, "d")},
	}
	manifest, ids := runtimeGraph(t,
		root,
		aggregate,
		choice,
		redundant,
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
		runtimeNode(proto.GraphNodeKindPath, "c"),
		runtimeNode(proto.GraphNodeKindPath, "d"),
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
	refs := make(map[string]PathRef)
	for _, name := range []string{"a", "c", "d", "fallback"} {
		path, peer := newMemoryPathPair()
		t.Cleanup(func() { _ = peer.Close() })
		id, err := e.AttachPathBound(path, transport.PathSpec{Transport: "memory"}, PathBinding{
			LocalTXTargetID: ids[name], PeerTXTargetID: ids[name],
		})
		if err != nil {
			t.Fatal(err)
		}
		ref, ok := e.PathRef(id)
		if !ok {
			t.Fatalf("missing physical ref for %s", name)
		}
		refs[name] = ref
	}
	runtime := e.localExecutionRuntime()
	if err := runtime.selectChild(ids["root"], ids["aggregate"]); err != nil {
		t.Fatal(err)
	}
	if err := runtime.selectChild(ids["choice"], ids["b"]); err != nil {
		t.Fatal(err)
	}
	e.pathsMu.Lock()
	projected := e.policySwitchPhysicalPathRefsLocked(runtime, ids["root"], ids["fallback"])
	e.pathsMu.Unlock()
	for _, name := range []string{"a", "c", "d", "fallback"} {
		if !projected[refs[name]] {
			t.Fatalf("physical projection omitted %s ref %+v: %v", name, refs[name], projected)
		}
	}
	if len(projected) != 4 {
		t.Fatalf("physical projection=%v want exactly four effective refs", projected)
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
