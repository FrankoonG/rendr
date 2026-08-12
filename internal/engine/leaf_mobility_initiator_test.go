package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/transport"
)

type initiatorRefreshPath struct {
	transport.PathConn

	mu              sync.Mutex
	callback        func(leafmobility.RefreshEvidence)
	cancelCount     atomic.Int32
	claim           *leafmobility.Claim
	emitOnSubscribe bool
}

type blockingRefreshPath struct {
	transport.PathConn
	entered chan struct{}
	once    sync.Once
}

type noRefreshClaimedPath struct {
	transport.PathConn
	claim *leafmobility.Claim
}

func (p *noRefreshClaimedPath) LeafMobilityClaim() *leafmobility.Claim { return p.claim }

func (p *blockingRefreshPath) SubscribeLeafMobilityRefresh(ctx context.Context, _ func(leafmobility.RefreshEvidence)) (func(), error) {
	p.once.Do(func() { close(p.entered) })
	<-ctx.Done()
	return nil, context.Cause(ctx)
}

func (p *initiatorRefreshPath) setLeafMobilityTestClaim(claim *leafmobility.Claim) { p.claim = claim }

func (p *initiatorRefreshPath) SubscribeLeafMobilityRefresh(_ context.Context, fn func(leafmobility.RefreshEvidence)) (func(), error) {
	if fn == nil {
		return nil, errors.New("nil refresh callback")
	}
	p.mu.Lock()
	p.callback = fn
	p.mu.Unlock()
	if p.emitOnSubscribe {
		emitter, err := leafmobility.NewRefreshEmitter(p.claim)
		if err != nil {
			return nil, err
		}
		evidence, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
		if err != nil {
			return nil, err
		}
		fn(evidence)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			p.mu.Lock()
			p.callback = nil
			p.mu.Unlock()
			p.cancelCount.Add(1)
		})
	}, nil
}

func (p *initiatorRefreshPath) publish(evidence leafmobility.RefreshEvidence) bool {
	p.mu.Lock()
	callback := p.callback
	p.mu.Unlock()
	if callback == nil {
		return false
	}
	callback(evidence)
	return true
}

func TestLeafMobilityInitiatorExecutesFreshFactualEvent(t *testing.T) {
	var source *initiatorRefreshPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			source = &initiatorRefreshPath{PathConn: path}
			return source
		}, nil, nil, nil,
	)
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
	eventuallyEngine(t, 3*time.Second, func() bool {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		return ok && status.Phase == LeafMobilityInitiatorCommitted
	})
	status, _ := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
	if status.Operation != leafmobility.OperationTCPRepair || status.TransactionID == (leafmobility.TransactionID{}) ||
		status.EvidenceGeneration == 0 || status.SourceEndpointGeneration == 0 || status.ResultEndpointGeneration == 0 || status.Error != "" {
		t.Fatalf("initiator status=%+v", status)
	}
	if fixture.clientDriver.prepareCalls.Load() != 1 || fixture.clientDriver.cutoverCalls.Load() != 1 ||
		fixture.clientDriver.commitCalls.Load() != 1 || fixture.clientDriver.activateCalls.Load() != 1 {
		t.Fatalf("driver calls prepare/stage/publish/activate=%d/%d/%d/%d",
			fixture.clientDriver.prepareCalls.Load(), fixture.clientDriver.cutoverCalls.Load(),
			fixture.clientDriver.commitCalls.Load(), fixture.clientDriver.activateCalls.Load())
	}
	topology := fixture.client.TopologySnapshot()
	var observed *LeafMobilitySnapshot
	for index := range topology.LeafMobility {
		if topology.LeafMobility[index].Ref == fixture.clientRef {
			observed = &topology.LeafMobility[index]
			break
		}
	}
	if observed == nil || observed.Initiator.Phase != LeafMobilityInitiatorCommitted ||
		observed.Initiator.ResultEndpointGeneration != observed.Facts.Generation {
		t.Fatalf("coherent topology mobility=%+v", observed)
	}
	assertLeafMobilityDataFlow(t, fixture, "after-automatic-commit")
}

func TestLeafMobilityCommitHookObservesCommittedTransaction(t *testing.T) {
	var source *initiatorRefreshPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			source = &initiatorRefreshPath{PathConn: path}
			return source
		}, nil, nil, nil,
	)
	type observation struct {
		oldID, newID uint32
		cause        string
		status       LeafMobilityInitiatorSnapshot
		present      bool
	}
	observed := make(chan observation, 2)
	cancel := fixture.client.OnMigrate(func(oldID, newID uint32, cause string) {
		status, present := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		observed <- observation{oldID: oldID, newID: newID, cause: cause, status: status, present: present}
	})
	defer cancel()
	emitter, err := leafmobility.NewRefreshEmitter(fixture.clientClaim)
	if err != nil {
		t.Fatal(err)
	}
	flowID := fixture.client.FlowID()
	var previousTransaction leafmobility.TransactionID
	var previousEndpointGeneration uint64
	for migration := 1; migration <= 2; migration++ {
		evidence, observeErr := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
		if observeErr != nil {
			t.Fatal(observeErr)
		}
		if source == nil || !source.publish(evidence) {
			t.Fatal("refresh source was not subscribed")
		}
		select {
		case got := <-observed:
			if got.oldID != fixture.clientRef.ID || got.newID != fixture.clientRef.ID ||
				got.cause != "leaf-mobility" || !got.present ||
				got.status.Phase != LeafMobilityInitiatorCommitted ||
				got.status.TransactionID == (leafmobility.TransactionID{}) ||
				got.status.ResultEndpointGeneration == 0 ||
				got.status.ResultEndpointGeneration == got.status.SourceEndpointGeneration {
				t.Fatalf("migration %d callback observation=%+v", migration, got)
			}
			if previousTransaction != (leafmobility.TransactionID{}) && got.status.TransactionID == previousTransaction {
				t.Fatalf("migration %d reused transaction %x", migration, got.status.TransactionID)
			}
			if previousEndpointGeneration != 0 && got.status.SourceEndpointGeneration != previousEndpointGeneration {
				t.Fatalf("migration %d source generation=%d want prior result=%d",
					migration, got.status.SourceEndpointGeneration, previousEndpointGeneration)
			}
			previousTransaction = got.status.TransactionID
			previousEndpointGeneration = got.status.ResultEndpointGeneration
		case <-time.After(3 * time.Second):
			t.Fatalf("committed leaf mobility hook %d did not fire", migration)
		}
		if fixture.client.FlowID() != flowID {
			t.Fatalf("migration %d changed flow identity", migration)
		}
		if ref, ok := fixture.client.PathRef(fixture.clientRef.ID); !ok || ref != fixture.clientRef {
			t.Fatalf("migration %d changed logical path reference: got=%+v ok=%t want=%+v",
				migration, ref, ok, fixture.clientRef)
		}
		if got := fixture.client.MigrationCount(); got != uint64(migration) {
			t.Fatalf("migration %d count=%d", migration, got)
		}
		assertLeafMobilityDataFlow(t, fixture, fmt.Sprintf("between-observed-commits-%d", migration))
	}
}

func TestLeafMobilityInitiatorPreservesSynchronousSubscriptionEventUntilActivation(t *testing.T) {
	var source *initiatorRefreshPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			source = &initiatorRefreshPath{PathConn: path, emitOnSubscribe: true}
			return source
		}, nil, nil, nil,
	)
	if source == nil {
		t.Fatal("missing synchronous refresh source")
	}
	eventuallyEngine(t, 3*time.Second, func() bool {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		return ok && status.Phase == LeafMobilityInitiatorCommitted
	})
	if calls := fixture.clientDriver.calls.Load(); calls != 1 {
		t.Fatalf("synchronous subscription event preflights=%d want=1", calls)
	}
}

func TestLeafMobilityRefreshStartupCannotBlockEngineClose(t *testing.T) {
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{}, nil, nil, nil, nil,
	)
	base, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = peer.Close() })
	driverBase := &enginePlanDriver{operation: leafmobility.OperationTCPRepair, evidence: leafmobility.EvidenceDigest{0xd2}}
	driver := newAuthorityTestExecutionDriver(driverBase, newAuthorityTestIncarnationReporter())
	claim := leafmobility.MustNewDrivenClaimWithIncarnation(leafmobility.Facts{
		Kind: leafmobility.KindRawTCP, Role: leafmobility.RoleDialer,
		Session: leafmobility.SessionStream, Generation: leafmobility.NextGeneration(),
	}, driver, leafmobility.MustNewResource(leafmobility.ScopeEndpoint), driver.reporter)
	blocked := &blockingRefreshPath{PathConn: base, entered: make(chan struct{})}
	prepared := make(chan error, 1)
	go func() {
		_, err := fixture.client.PreparePathBound(
			&claimedMemoryPath{PathConn: blocked, claim: claim},
			transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "blocked-monitor"}},
			PathBinding{LocalTXTargetID: fixture.ids["b"], PeerTXTargetID: fixture.ids["b"]},
		)
		prepared <- err
	}()
	select {
	case <-blocked.entered:
	case <-time.After(time.Second):
		t.Fatal("refresh startup did not block as stimulated")
	}
	closed := make(chan error, 1)
	go func() { closed <- fixture.client.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("refresh startup blocked Engine.Close")
	}
	select {
	case <-prepared:
	case <-time.After(time.Second):
		t.Fatal("refresh startup did not observe engine cancellation")
	}
}

func TestLeafMobilityRefreshSubscriptionUnavailableIsObservable(t *testing.T) {
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{}, nil, nil, nil, nil,
	)
	base, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = peer.Close() })
	driverBase := &enginePlanDriver{operation: leafmobility.OperationTCPRepair, evidence: leafmobility.EvidenceDigest{0xd3}}
	driver := newAuthorityTestExecutionDriver(driverBase, newAuthorityTestIncarnationReporter())
	claim := leafmobility.MustNewDrivenClaimWithIncarnation(leafmobility.Facts{
		Kind: leafmobility.KindRawTCP, Role: leafmobility.RoleDialer,
		Session: leafmobility.SessionStream, Generation: leafmobility.NextGeneration(),
	}, driver, leafmobility.MustNewResource(leafmobility.ScopeEndpoint), driver.reporter)
	id, err := fixture.client.AttachPathBound(
		&noRefreshClaimedPath{PathConn: base, claim: claim},
		transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "no-refresh"}},
		PathBinding{LocalTXTargetID: fixture.ids["b"], PeerTXTargetID: fixture.ids["b"]},
	)
	if err != nil {
		t.Fatal(err)
	}
	ref, ok := fixture.client.PathRef(id)
	if !ok {
		t.Fatal("no-refresh leaf has no physical reference")
	}
	status, ok := fixture.client.LeafMobilityInitiatorStatus(ref)
	if !ok || status.Phase != LeafMobilityInitiatorSubscriptionUnavailable ||
		status.SourceEndpointGeneration != claim.Snapshot().Generation || status.EvidenceGeneration != 0 {
		t.Fatalf("subscription status=%+v ok=%t", status, ok)
	}
	topology := fixture.client.TopologySnapshot()
	for _, mobility := range topology.LeafMobility {
		if mobility.Ref == ref {
			if mobility.Initiator.Phase != LeafMobilityInitiatorSubscriptionUnavailable ||
				mobility.Initiator.SourceEndpointGeneration != mobility.Facts.Generation {
				t.Fatalf("topology subscription status=%+v", mobility)
			}
			return
		}
	}
	t.Fatal("topology omitted no-refresh owned leaf")
}

func TestLeafMobilityInitiatorCoalescesOldIncarnationStorm(t *testing.T) {
	var source *initiatorRefreshPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			source = &initiatorRefreshPath{PathConn: path}
			return source
		}, nil, nil, nil,
	)
	fixture.clientDriver.release = make(chan struct{})
	emitter, err := leafmobility.NewRefreshEmitter(fixture.clientClaim)
	if err != nil {
		t.Fatal(err)
	}
	for iteration := 0; iteration < 100; iteration++ {
		evidence, observeErr := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
		if observeErr != nil {
			t.Fatal(observeErr)
		}
		if !source.publish(evidence) {
			t.Fatal("refresh source was not subscribed")
		}
	}
	eventuallyEngine(t, time.Second, func() bool { return fixture.clientDriver.calls.Load() == 1 })
	close(fixture.clientDriver.release)
	eventuallyEngine(t, 3*time.Second, func() bool {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		return ok && (status.Phase == LeafMobilityInitiatorCommitted || status.Phase == LeafMobilityInitiatorSuperseded)
	})
	// Every queued event described incarnation 1. The first commit advances the
	// incarnation, so the coalesced remainder must be discarded as stale.
	time.Sleep(50 * time.Millisecond)
	if calls := fixture.clientDriver.calls.Load(); calls != 1 {
		t.Fatalf("old-incarnation storm ran %d preflights, want 1", calls)
	}
	assertLeafMobilityDataFlow(t, fixture, "reset-zombie-between-automatic-migrations")

	newEvidence, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
	if err != nil {
		t.Fatal(err)
	}
	if !source.publish(newEvidence) {
		t.Fatal("refresh source was not subscribed after commit")
	}
	eventuallyEngine(t, 3*time.Second, func() bool { return fixture.clientDriver.calls.Load() == 2 })
	eventuallyEngine(t, 3*time.Second, func() bool {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		return ok && status.Phase == LeafMobilityInitiatorCommitted && status.EvidenceGeneration > 0
	})
}

func TestLeafMobilityInitiatorRetirementCancelsAndForgets(t *testing.T) {
	var source *initiatorRefreshPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			source = &initiatorRefreshPath{PathConn: path}
			return source
		}, nil, nil, nil,
	)
	emitter, err := leafmobility.NewRefreshEmitter(fixture.clientClaim)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
	if err != nil {
		t.Fatal(err)
	}
	if !source.publish(evidence) {
		t.Fatal("refresh source was not subscribed")
	}
	if err := fixture.client.RetirePath(fixture.clientRef, errors.New("test retirement")); err != nil {
		t.Fatal(err)
	}
	eventuallyEngine(t, time.Second, func() bool { return source.cancelCount.Load() == 1 })
	if _, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef); ok {
		t.Fatal("retired path retained initiator status")
	}
	if source.publish(evidence) {
		t.Fatal("retired source retained callback")
	}
	if calls := fixture.clientDriver.calls.Load(); calls > 1 {
		t.Fatalf("retirement allowed %d preflights", calls)
	}
}

func TestLeafMobilityInitiatorBilateralSimultaneousEventConverges(t *testing.T) {
	var clientSource, serverSource *initiatorRefreshPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			clientSource = &initiatorRefreshPath{PathConn: path}
			return clientSource
		},
		func(path *memoryPathConn) transport.PathConn {
			serverSource = &initiatorRefreshPath{PathConn: path}
			return serverSource
		}, nil, nil,
	)
	clientEmitter, err := leafmobility.NewRefreshEmitter(fixture.clientClaim)
	if err != nil {
		t.Fatal(err)
	}
	serverEmitter, err := leafmobility.NewRefreshEmitter(fixture.serverClaim)
	if err != nil {
		t.Fatal(err)
	}
	clientEvidence, err := clientEmitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
	if err != nil {
		t.Fatal(err)
	}
	serverEvidence, err := serverEmitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var published atomic.Int32
	var group sync.WaitGroup
	for _, publish := range []func() bool{
		func() bool { return clientSource.publish(clientEvidence) },
		func() bool { return serverSource.publish(serverEvidence) },
	} {
		group.Add(1)
		go func(publish func() bool) {
			defer group.Done()
			<-start
			if publish() {
				published.Add(1)
			}
		}(publish)
	}
	close(start)
	group.Wait()
	if published.Load() != 2 {
		t.Fatalf("published callbacks=%d want=2", published.Load())
	}
	eventuallyEngine(t, 3*time.Second, func() bool {
		client, clientOK := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		server, serverOK := fixture.server.LeafMobilityInitiatorStatus(fixture.serverRef)
		return clientOK && serverOK && leafInitiatorTerminal(client.Phase) && leafInitiatorTerminal(server.Phase)
	})
	assertLeafMobilityDataFlow(t, fixture, "after-bilateral-refresh")
	if fixture.clientResource.Snapshot().Poisoned || fixture.serverResource.Snapshot().Poisoned {
		t.Fatalf("simultaneous refresh poisoned resources client=%+v server=%+v",
			fixture.clientResource.Snapshot(), fixture.serverResource.Snapshot())
	}
	if clientCalls, serverCalls := fixture.clientDriver.calls.Load(), fixture.serverDriver.calls.Load(); clientCalls > 8 || serverCalls > 8 {
		t.Fatalf("simultaneous peer-busy preflights client/server=%d/%d want <=8", clientCalls, serverCalls)
	}
}

func TestLeafMobilityInitiatorBusyGateRetainsEventAndReplans(t *testing.T) {
	var source *initiatorRefreshPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			source = &initiatorRefreshPath{PathConn: path}
			return source
		}, nil, nil, nil,
	)
	manualPlan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xe1)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, manualPlan)
	if err != nil {
		t.Fatal(err)
	}
	baselinePreflights := fixture.clientDriver.calls.Load()
	emitter, err := leafmobility.NewRefreshEmitter(fixture.clientClaim)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
	if err != nil {
		t.Fatal(err)
	}
	if !source.publish(evidence) {
		t.Fatal("refresh source was not subscribed")
	}
	eventuallyEngine(t, time.Second, func() bool {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		return ok && status.Phase == LeafMobilityInitiatorDeferred
	})
	if got := fixture.clientDriver.calls.Load(); got != baselinePreflights+1 {
		t.Fatalf("busy event preflights=%d want=%d before gate release", got, baselinePreflights+1)
	}
	if err := authority.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	eventuallyEngine(t, 3*time.Second, func() bool {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		return ok && status.Phase == LeafMobilityInitiatorCommitted
	})
	if got := fixture.clientDriver.calls.Load(); got != baselinePreflights+2 {
		t.Fatalf("retained event preflights=%d want=%d", got, baselinePreflights+2)
	}
}

func TestLeafMobilityUnavailableSourceKeepsOriginalEventBudget(t *testing.T) {
	var source *initiatorRefreshPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			source = &initiatorRefreshPath{PathConn: path}
			return source
		}, nil, nil, nil,
	)
	fixture.client.limits.MigrationBudget = 60 * time.Millisecond
	state := leafmobility.NewRefreshSourceState()
	if _, err := state.Update([32]byte{0x61}); err != nil {
		t.Fatal(err)
	}
	emitter, err := leafmobility.NewRefreshEmitterWithSourceState(fixture.clientClaim, state)
	if err != nil {
		t.Fatal(err)
	}
	unavailable, changed, err := state.MarkUnavailable()
	if err != nil || !changed {
		t.Fatalf("mark unavailable changed=%t err=%v", changed, err)
	}
	lost, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceUnavailable, unavailable)
	if err != nil {
		t.Fatal(err)
	}
	if !source.publish(lost) {
		t.Fatal("unavailable refresh was not published")
	}
	eventuallyEngine(t, time.Second, func() bool {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		return ok && status.Phase == LeafMobilityInitiatorExpired
	})
	first, _ := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
	if first.EvidenceReason != leafmobility.RefreshReasonRouteSourceUnavailable || first.Deadline.IsZero() {
		t.Fatalf("unavailable status=%+v", first)
	}

	replacement, err := state.Update([32]byte{0x62})
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged, replacement)
	if err != nil {
		t.Fatal(err)
	}
	recoveredSnapshot, err := recovered.ValidateFor(fixture.clientClaim, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !source.publish(recovered) {
		t.Fatal("replacement refresh was not published")
	}
	eventuallyEngine(t, time.Second, func() bool {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		return ok && status.Phase == LeafMobilityInitiatorExpired &&
			status.EvidenceGeneration == recoveredSnapshot.Generation
	})
	second, _ := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
	if second.Deadline != first.Deadline || !second.ObservedAt.After(first.ObservedAt) {
		t.Fatalf("recovered status=%+v original=%+v", second, first)
	}
	if calls := fixture.clientDriver.calls.Load(); calls != 0 {
		t.Fatalf("expired unavailable event ran %d preflights", calls)
	}

	restored, err := state.Update([32]byte{0x61})
	if err != nil {
		t.Fatal(err)
	}
	restoredEvidence, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceRestored, restored)
	if err != nil {
		t.Fatal(err)
	}
	if !source.publish(restoredEvidence) {
		t.Fatal("late baseline restoration was not published")
	}
	eventuallyEngine(t, time.Second, func() bool {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		return ok && status.Phase == LeafMobilityInitiatorBaseline && status.Deadline.IsZero()
	})
	fixture.client.leafRefreshMu.Lock()
	_, retainedBudget := fixture.client.leafRefreshBudget[fixture.clientRef]
	fixture.client.leafRefreshMu.Unlock()
	if retainedBudget {
		t.Fatal("late baseline restoration retained the expired episode budget")
	}

	nextSource, err := state.Update([32]byte{0x63})
	if err != nil {
		t.Fatal(err)
	}
	next, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged, nextSource)
	if err != nil {
		t.Fatal(err)
	}
	if !source.publish(next) {
		t.Fatal("new post-restoration episode was not published")
	}
	eventuallyEngine(t, 3*time.Second, func() bool {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		return ok && status.Phase == LeafMobilityInitiatorCommitted
	})
	third, _ := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
	if !third.Deadline.After(first.Deadline) || fixture.clientDriver.calls.Load() != 1 {
		t.Fatalf("new episode status=%+v preflights=%d", third, fixture.clientDriver.calls.Load())
	}
}

func TestLeafMobilitySourceRestorationResetsCompletedEpisode(t *testing.T) {
	var source *initiatorRefreshPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			source = &initiatorRefreshPath{PathConn: path}
			return source
		}, nil, nil, nil,
	)
	fixture.client.limits.MigrationBudget = 500 * time.Millisecond
	state := leafmobility.NewRefreshSourceState()
	if _, err := state.Update([32]byte{0x71}); err != nil {
		t.Fatal(err)
	}
	emitter, err := leafmobility.NewRefreshEmitterWithSourceState(fixture.clientClaim, state)
	if err != nil {
		t.Fatal(err)
	}
	unavailable, _, err := state.MarkUnavailable()
	if err != nil {
		t.Fatal(err)
	}
	lost, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceUnavailable, unavailable)
	if err != nil {
		t.Fatal(err)
	}
	if !source.publish(lost) {
		t.Fatal("unavailable refresh was not published")
	}
	eventuallyEngine(t, time.Second, func() bool {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		return ok && status.Phase == LeafMobilityInitiatorDeferred
	})

	restored, err := state.Update([32]byte{0x71})
	if err != nil {
		t.Fatal(err)
	}
	restoredEvidence, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceRestored, restored)
	if err != nil {
		t.Fatal(err)
	}
	if !source.publish(restoredEvidence) {
		t.Fatal("restored refresh was not published")
	}
	eventuallyEngine(t, time.Second, func() bool {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		return ok && status.Phase == LeafMobilityInitiatorBaseline && status.Deadline.IsZero()
	})
	if calls := fixture.clientDriver.calls.Load(); calls != 0 {
		t.Fatalf("baseline restoration ran %d preflights", calls)
	}

	replacement, err := state.Update([32]byte{0x72})
	if err != nil {
		t.Fatal(err)
	}
	next, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged, replacement)
	if err != nil {
		t.Fatal(err)
	}
	if !source.publish(next) {
		t.Fatal("new episode refresh was not published")
	}
	eventuallyEngine(t, 3*time.Second, func() bool {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		return ok && status.Phase == LeafMobilityInitiatorCommitted
	})
	if calls := fixture.clientDriver.calls.Load(); calls != 1 {
		t.Fatalf("new episode preflights=%d want=1", calls)
	}
}

func TestLeafMobilityInitiatorRetriesFactualPreflightWithoutNewEvidence(t *testing.T) {
	var source *initiatorRefreshPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			source = &initiatorRefreshPath{PathConn: path}
			return source
		}, nil, nil, nil,
	)
	fixture.clientDriver.retryableFailures.Store(1)
	emitter, err := leafmobility.NewRefreshEmitter(fixture.clientClaim)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
	if err != nil {
		t.Fatal(err)
	}
	if !source.publish(evidence) {
		t.Fatal("refresh source was not subscribed")
	}
	eventuallyEngine(t, 3*time.Second, func() bool {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		return ok && status.Phase == LeafMobilityInitiatorCommitted
	})
	if calls := fixture.clientDriver.calls.Load(); calls != 2 {
		t.Fatalf("retryable preflight calls=%d want=2", calls)
	}
}

func TestLeafMobilityInitiatorRetryablePreflightBacksOff(t *testing.T) {
	var source *initiatorRefreshPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			source = &initiatorRefreshPath{PathConn: path}
			return source
		}, nil, nil, nil,
	)
	fixture.clientDriver.retryableFailures.Store(100)
	emitter, err := leafmobility.NewRefreshEmitter(fixture.clientClaim)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
	if err != nil {
		t.Fatal(err)
	}
	if !source.publish(evidence) {
		t.Fatal("refresh source was not subscribed")
	}
	eventuallyEngine(t, time.Second, func() bool {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		return ok && status.Phase == LeafMobilityInitiatorDeferred
	})
	time.Sleep(95 * time.Millisecond)
	if calls := fixture.clientDriver.calls.Load(); calls < 3 || calls > 4 {
		t.Fatalf("backoff preflight calls=%d want [3,4]", calls)
	}
	if err := fixture.client.RetirePath(fixture.clientRef, errors.New("stop retry test")); err != nil {
		t.Fatal(err)
	}
}

func TestLeafMobilityInitiatorDefersUntilIndependentControlRouteAppears(t *testing.T) {
	var source *initiatorRefreshPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			source = &initiatorRefreshPath{PathConn: path}
			return source
		}, nil, nil, nil,
	)
	if err := fixture.client.RetirePath(fixture.clientControlRef, errors.New("remove automatic control route")); err != nil {
		t.Fatal(err)
	}
	if _, ok := fixture.server.PathRef(fixture.serverControlRef.ID); ok {
		if err := fixture.server.RetirePath(fixture.serverControlRef, errors.New("remove peer automatic control route")); err != nil {
			t.Fatal(err)
		}
	}
	eventuallyEngine(t, time.Second, func() bool {
		_, clientOK := fixture.client.PathRef(fixture.clientControlRef.ID)
		_, serverOK := fixture.server.PathRef(fixture.serverControlRef.ID)
		return !clientOK && !serverOK
	})
	emitter, err := leafmobility.NewRefreshEmitter(fixture.clientClaim)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
	if err != nil {
		t.Fatal(err)
	}
	if !source.publish(evidence) {
		t.Fatal("refresh source was not subscribed")
	}
	eventuallyEngine(t, time.Second, func() bool {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		return ok && status.Phase == LeafMobilityInitiatorDeferred
	})
	if calls := fixture.clientDriver.calls.Load(); calls != 0 {
		t.Fatalf("missing control route still ran %d preflights", calls)
	}
	attachLeafMobilityFixtureOrdinaryPath(t, fixture, "b")
	eventuallyEngine(t, 3*time.Second, func() bool {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		return ok && status.Phase == LeafMobilityInitiatorCommitted
	})
	if calls := fixture.clientDriver.calls.Load(); calls != 1 {
		t.Fatalf("control-route recovery ran %d preflights, want 1", calls)
	}
}

func TestLeafMobilityInitiatorRetiringDeferredLeafCancelsWorker(t *testing.T) {
	var source *initiatorRefreshPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			source = &initiatorRefreshPath{PathConn: path}
			return source
		}, nil, nil, nil,
	)
	if err := fixture.client.RetirePath(fixture.clientControlRef, errors.New("remove control route")); err != nil {
		t.Fatal(err)
	}
	eventuallyEngine(t, time.Second, func() bool {
		_, ok := fixture.client.PathRef(fixture.clientControlRef.ID)
		return !ok
	})
	emitter, err := leafmobility.NewRefreshEmitter(fixture.clientClaim)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
	if err != nil {
		t.Fatal(err)
	}
	if !source.publish(evidence) {
		t.Fatal("refresh source was not subscribed")
	}
	fixture.client.pathsMu.RLock()
	subject := fixture.client.paths[fixture.clientRef.ID]
	fixture.client.pathsMu.RUnlock()
	if subject == nil || subject.mobilityPolicyHolds.Load() == 0 {
		t.Fatal("deferred factual refresh did not hold its selected policy leaf")
	}
	eventuallyEngine(t, time.Second, func() bool {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		return ok && status.Phase == LeafMobilityInitiatorDeferred
	})
	if err := fixture.client.RetirePath(fixture.clientRef, errors.New("retire deferred subject")); err != nil {
		t.Fatal(err)
	}
	eventuallyEngine(t, time.Second, func() bool {
		fixture.client.leafRefreshMu.Lock()
		_, running := fixture.client.leafRefreshRunning[fixture.clientRef]
		_, cancel := fixture.client.leafRefreshCancel[fixture.clientRef]
		fixture.client.leafRefreshMu.Unlock()
		return !running && !cancel && subject.mobilityPolicyHolds.Load() == 0
	})
}

func TestLeafMobilityInitiatorDeferredLeafDoesNotStarveAnotherLeaf(t *testing.T) {
	var activeSource *initiatorRefreshPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			activeSource = &initiatorRefreshPath{PathConn: path}
			return activeSource
		}, nil, nil, nil,
	)

	pendingBase, pendingPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = pendingPeer.Close() })
	pendingDriverBase := &enginePlanDriver{operation: leafmobility.OperationTCPRepair, evidence: leafmobility.EvidenceDigest{0xd1}}
	pendingDriver := newAuthorityTestExecutionDriver(pendingDriverBase, newAuthorityTestIncarnationReporter())
	pendingClaim := leafmobility.MustNewDrivenClaimWithIncarnation(leafmobility.Facts{
		Kind: leafmobility.KindRawTCP, Role: leafmobility.RoleDialer,
		Session: leafmobility.SessionStream, Generation: leafmobility.NextGeneration(),
	}, pendingDriver, leafmobility.MustNewResource(leafmobility.ScopeEndpoint), pendingDriver.reporter)
	pendingSource := &initiatorRefreshPath{PathConn: pendingBase, claim: pendingClaim}
	pendingID, err := fixture.client.PreparePathBound(
		&claimedMemoryPath{PathConn: pendingSource, claim: pendingClaim},
		transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "pending-refresh"}},
		PathBinding{LocalTXTargetID: fixture.ids["b"], PeerTXTargetID: fixture.ids["b"]},
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.client.pathsMu.RLock()
	pendingSlot := fixture.client.pendingPaths[pendingID]
	var pendingRef PathRef
	if pendingSlot != nil {
		pendingRef = PathRef{ID: pendingSlot.id, Owner: pendingSlot.owner}
	}
	fixture.client.pathsMu.RUnlock()
	if pendingRef == (PathRef{}) {
		t.Fatal("prepared refresh leaf has no physical reference")
	}
	pendingEmitter, err := leafmobility.NewRefreshEmitter(pendingClaim)
	if err != nil {
		t.Fatal(err)
	}
	pendingEvidence, err := pendingEmitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
	if err != nil {
		t.Fatal(err)
	}
	if !pendingSource.publish(pendingEvidence) {
		t.Fatal("prepared refresh leaf was not subscribed")
	}
	eventuallyEngine(t, time.Second, func() bool {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(pendingRef)
		return ok && status.Phase == LeafMobilityInitiatorDeferred
	})

	activeEmitter, err := leafmobility.NewRefreshEmitter(fixture.clientClaim)
	if err != nil {
		t.Fatal(err)
	}
	activeEvidence, err := activeEmitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
	if err != nil {
		t.Fatal(err)
	}
	if !activeSource.publish(activeEvidence) {
		t.Fatal("active refresh leaf was not subscribed")
	}
	eventuallyEngine(t, 3*time.Second, func() bool {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		return ok && status.Phase == LeafMobilityInitiatorCommitted
	})
	if calls := fixture.clientDriver.calls.Load(); calls != 1 {
		t.Fatalf("active leaf preflights=%d want=1", calls)
	}
}

func TestLeafMobilityInitiatorSlowPreflightDoesNotHoldGlobalAuthority(t *testing.T) {
	var slowSource *initiatorRefreshPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			slowSource = &initiatorRefreshPath{PathConn: path}
			return slowSource
		}, nil, nil, nil,
	)
	fixture.clientDriver.entered = make(chan struct{})
	fixture.clientDriver.release = make(chan struct{})
	var releaseSlow sync.Once
	release := func() { releaseSlow.Do(func() { close(fixture.clientDriver.release) }) }
	t.Cleanup(release)

	slowEmitter, err := leafmobility.NewRefreshEmitter(fixture.clientClaim)
	if err != nil {
		t.Fatal(err)
	}
	slowEvidence, err := slowEmitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
	if err != nil {
		t.Fatal(err)
	}
	if !slowSource.publish(slowEvidence) {
		t.Fatal("slow refresh source was not subscribed")
	}
	select {
	case <-fixture.clientDriver.entered:
	case <-time.After(time.Second):
		t.Fatal("slow preflight did not block as stimulated")
	}

	fastClientBase, fastServerBase := newMemoryPathPair()
	fastClientDriverBase := &enginePlanDriver{operation: leafmobility.OperationTCPRepair, evidence: leafmobility.EvidenceDigest{0xe4}}
	fastServerDriverBase := &enginePlanDriver{operation: leafmobility.OperationTCPRepair, evidence: leafmobility.EvidenceDigest{0xe5}}
	fastClientDriver := newAuthorityTestExecutionDriver(fastClientDriverBase, newAuthorityTestIncarnationReporter())
	fastServerDriver := newAuthorityTestExecutionDriver(fastServerDriverBase, newAuthorityTestIncarnationReporter())
	fastClientClaim := leafmobility.MustNewDrivenClaimWithIncarnation(leafmobility.Facts{
		Kind: leafmobility.KindRawTCP, Role: leafmobility.RoleDialer,
		Session: leafmobility.SessionStream, Generation: leafmobility.NextGeneration(),
	}, fastClientDriver, leafmobility.MustNewResource(leafmobility.ScopeEndpoint), fastClientDriver.reporter)
	fastServerClaim := leafmobility.MustNewDrivenClaimWithIncarnation(leafmobility.Facts{
		Kind: leafmobility.KindRawTCP, Role: leafmobility.RoleAcceptor,
		Session: leafmobility.SessionStream, Generation: leafmobility.NextGeneration(),
	}, fastServerDriver, leafmobility.MustNewResource(leafmobility.ScopeEndpoint), fastServerDriver.reporter)
	fastSource := &initiatorRefreshPath{PathConn: fastClientBase, claim: fastClientClaim}
	binding := PathBinding{LocalTXTargetID: fixture.ids["b"], PeerTXTargetID: fixture.ids["b"]}
	fastID, err := fixture.client.AttachPathBound(
		&claimedMemoryPath{PathConn: fastSource, claim: fastClientClaim},
		transport.PathSpec{Transport: "memory"}, binding,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.server.AttachPathBound(
		&claimedMemoryPath{PathConn: fastServerBase, claim: fastServerClaim},
		transport.PathSpec{Transport: "memory"}, binding,
	); err != nil {
		t.Fatal(err)
	}
	fastRef, ok := fixture.client.PathRef(fastID)
	if !ok {
		t.Fatal("fast leaf has no physical reference")
	}
	fastEmitter, err := leafmobility.NewRefreshEmitter(fastClientClaim)
	if err != nil {
		t.Fatal(err)
	}
	fastEvidence, err := fastEmitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
	if err != nil {
		t.Fatal(err)
	}
	if !fastSource.publish(fastEvidence) {
		t.Fatal("fast refresh source was not subscribed")
	}
	eventuallyEngine(t, 3*time.Second, func() bool {
		status, present := fixture.client.LeafMobilityInitiatorStatus(fastRef)
		return present && status.Phase == LeafMobilityInitiatorCommitted
	})
	if calls := fastClientDriverBase.calls.Load(); calls != 1 {
		t.Fatalf("fast leaf preflights=%d want=1", calls)
	}
	if calls := fixture.clientDriver.calls.Load(); calls != 1 {
		t.Fatalf("blocked leaf preflights=%d want=1", calls)
	}
	assertLeafMobilityDataFlow(t, fixture, "between-independent-leaf-migrations")

	release()
	eventuallyEngine(t, 3*time.Second, func() bool {
		status, present := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		return present && status.Phase == LeafMobilityInitiatorCommitted
	})
}

func TestLeafMobilityInitiatorBudgetStartsAtObservation(t *testing.T) {
	var source *initiatorRefreshPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			source = &initiatorRefreshPath{PathConn: path}
			return source
		}, nil, nil, nil,
	)
	manualPlan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xe2)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, manualPlan)
	if err != nil {
		t.Fatal(err)
	}
	baselinePreflights := fixture.clientDriver.calls.Load()
	fixture.client.limits.MigrationBudget = 75 * time.Millisecond
	emitter, err := leafmobility.NewRefreshEmitter(fixture.clientClaim)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
	if err != nil {
		t.Fatal(err)
	}
	if !source.publish(evidence) {
		t.Fatal("refresh source was not subscribed")
	}
	eventuallyEngine(t, time.Second, func() bool {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		return ok && status.Phase == LeafMobilityInitiatorExpired
	})
	status, _ := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
	if elapsed := status.UpdatedAt.Sub(status.ObservedAt); elapsed < 50*time.Millisecond || elapsed > 250*time.Millisecond {
		t.Fatalf("event budget elapsed=%s status=%+v", elapsed, status)
	}
	if got := fixture.clientDriver.calls.Load(); got != baselinePreflights+1 {
		t.Fatalf("expired queued event preflights=%d want=%d", got, baselinePreflights+1)
	}
	if err := authority.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestLeafMobilityInitiatorCommitsParticipateInZombieProtection(t *testing.T) {
	var source *initiatorRefreshPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			source = &initiatorRefreshPath{PathConn: path}
			return source
		}, nil, nil, nil,
	)
	emitter, err := leafmobility.NewRefreshEmitter(fixture.clientClaim)
	if err != nil {
		t.Fatal(err)
	}
	for migration := 1; migration <= 2; migration++ {
		evidence, observeErr := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
		if observeErr != nil {
			t.Fatal(observeErr)
		}
		if !source.publish(evidence) {
			t.Fatal("refresh source was not subscribed")
		}
		if migration == 1 {
			eventuallyEngine(t, 3*time.Second, func() bool {
				status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
				return ok && status.Phase == LeafMobilityInitiatorCommitted
			})
		}
	}
	select {
	case <-fixture.client.Closed():
	case <-time.After(3 * time.Second):
		t.Fatal("two payload-free automatic migrations did not trip zombie protection")
	}
	if !errors.Is(fixture.client.CloseErr(), ErrZombie) {
		t.Fatalf("close error=%v want=%v", fixture.client.CloseErr(), ErrZombie)
	}
	if got := fixture.client.MigrationCount(); got != 2 {
		t.Fatalf("automatic migration count=%d want=2", got)
	}
}

func leafInitiatorTerminal(phase LeafMobilityInitiatorPhase) bool {
	switch phase {
	case LeafMobilityInitiatorBaseline, LeafMobilityInitiatorCommitted,
		LeafMobilityInitiatorRolledBack, LeafMobilityInitiatorRejected, LeafMobilityInitiatorFailed,
		LeafMobilityInitiatorSuperseded, LeafMobilityInitiatorExpired, LeafMobilityInitiatorFailClosed,
		LeafMobilityInitiatorSubscriptionUnavailable:
		return true
	default:
		return false
	}
}

func assertLeafMobilityDataFlow(t testing.TB, fixture leafMobilityEngineFixture, payload string) {
	t.Helper()
	if _, err := fixture.client.SendData([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := make(chan struct {
		payload string
		err     error
	}, 1)
	go func() {
		buffer := make([]byte, 128)
		n, err := fixture.server.Recv(buffer)
		result <- struct {
			payload string
			err     error
		}{payload: string(buffer[:n]), err: err}
	}()
	select {
	case got := <-result:
		if got.err != nil || got.payload != payload {
			t.Fatalf("payload=%q err=%v want=%q", got.payload, got.err, payload)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
