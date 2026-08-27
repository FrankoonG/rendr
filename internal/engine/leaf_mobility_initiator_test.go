package engine

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
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

type failingRefreshCommitPath struct {
	*initiatorRefreshPath
	err   error
	calls atomic.Int32
}

func (p *failingRefreshCommitPath) CommitLeafMobilityRefresh(leafmobility.RefreshEvidence) error {
	p.calls.Add(1)
	return p.err
}

type blockingRefreshCommitPath struct {
	*initiatorRefreshPath
	entered      chan struct{}
	release      chan struct{}
	closeEntered chan struct{}
	enteredOnce  sync.Once
	closeOnce    sync.Once
	calls        atomic.Int32
	closeCalls   atomic.Int32
}

func (p *blockingRefreshCommitPath) CommitLeafMobilityRefresh(leafmobility.RefreshEvidence) error {
	p.calls.Add(1)
	p.enteredOnce.Do(func() { close(p.entered) })
	<-p.release
	return nil
}

func (p *blockingRefreshCommitPath) Close() error {
	p.closeCalls.Add(1)
	if p.closeEntered != nil {
		p.closeOnce.Do(func() { close(p.closeEntered) })
	}
	if p.initiatorRefreshPath == nil || p.PathConn == nil {
		return nil
	}
	return p.PathConn.Close()
}

type goexitRefreshCommitPath struct {
	*initiatorRefreshPath
	calls atomic.Int32
}

func (p *goexitRefreshCommitPath) CommitLeafMobilityRefresh(leafmobility.RefreshEvidence) error {
	p.calls.Add(1)
	runtime.Goexit()
	return nil
}

type panickingRefreshCommitPath struct {
	*initiatorRefreshPath
	panicValue any
	calls      atomic.Int32
}

func (p *panickingRefreshCommitPath) CommitLeafMobilityRefresh(leafmobility.RefreshEvidence) error {
	p.calls.Add(1)
	panic(p.panicValue)
}

type blockingRefreshPath struct {
	transport.PathConn
	entered chan struct{}
	once    sync.Once
}

type blockBeforePreparedRefreshPath struct {
	transport.PathConn
	reached chan struct{}
	release chan struct{}
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

func (p *blockBeforePreparedRefreshPath) Write(frame []byte) (int, error) {
	if leafMobilityAckPhase(frame) == proto.LeafMobilityPeerPlanAckPhasePrepared {
		p.once.Do(func() { close(p.reached) })
		<-p.release
	}
	return p.PathConn.Write(frame)
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

func TestLeafMobilitySourceBindingMustPrecedeDestructiveExecution(t *testing.T) {
	event := leafMobilityRefreshEvent{
		ref:      PathRef{ID: 7, Owner: 11},
		snapshot: leafmobility.RefreshSnapshot{EndpointGeneration: 13},
	}
	valid := MigrationPathBinding{
		PathID: 7, PathOwner: 11, PathGeneration: 17, RouteGeneration: 19,
		EndpointGeneration: 13, LocalTargetID: [16]byte{1}, PeerTargetID: [16]byte{2},
	}
	if !validLeafMobilitySourceBinding(event, valid) {
		t.Fatalf("valid pre-execution source binding was rejected: %+v", valid)
	}
	tests := []struct {
		name   string
		mutate func(*MigrationPathBinding)
	}{
		{name: "missing", mutate: func(binding *MigrationPathBinding) { *binding = MigrationPathBinding{} }},
		{name: "wrong path", mutate: func(binding *MigrationPathBinding) { binding.PathID++ }},
		{name: "wrong owner", mutate: func(binding *MigrationPathBinding) { binding.PathOwner++ }},
		{name: "missing path generation", mutate: func(binding *MigrationPathBinding) { binding.PathGeneration = 0 }},
		{name: "missing route generation", mutate: func(binding *MigrationPathBinding) { binding.RouteGeneration = 0 }},
		{name: "stale endpoint generation", mutate: func(binding *MigrationPathBinding) { binding.EndpointGeneration-- }},
		{name: "missing local target", mutate: func(binding *MigrationPathBinding) { binding.LocalTargetID = [16]byte{} }},
		{name: "missing peer target", mutate: func(binding *MigrationPathBinding) { binding.PeerTargetID = [16]byte{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			binding := valid
			test.mutate(&binding)
			if validLeafMobilitySourceBinding(event, binding) {
				t.Fatalf("invalid pre-execution source binding was accepted: %+v", binding)
			}
		})
	}
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
	testLeafMobilityInitiatorPreservesTypedRefreshReason(t)
}

func TestLeafMobilitySuccessfulPeerCommitInvalidatesResponderProbeEvidence(t *testing.T) {
	var source *initiatorRefreshPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			source = &initiatorRefreshPath{PathConn: path}
			return source
		}, nil, nil, nil,
	)

	fixture.server.pathsMu.RLock()
	serverSlot := fixture.server.paths[fixture.serverRef.ID]
	fixture.server.pathsMu.RUnlock()
	if serverSlot == nil {
		t.Fatal("missing responder subject slot")
	}
	peerEpochBefore := serverSlot.peerMobilityEpoch.Load()
	topologyEpochBefore := fixture.server.pathTopologyEpoch.Load()
	endpointGenerationBefore := serverSlot.probeEndpointGen.Load()
	routeGenerationBefore := serverSlot.routeGeneration.Load()
	migrationCountBefore := fixture.server.MigrationCount()
	dispatchIdentity := pathDispatchIdentity{
		generation:     serverSlot.nextDispatchGeneration(),
		pathGeneration: pathProbeGenerationForSlot(serverSlot),
	}
	serverSlot.markDispatchStalled(dispatchIdentity)
	dispatchGeneration := dispatchIdentity.generation
	generation := pathProbeGenerationForSlot(serverSlot)
	serverSlot.probeEvidence.Store(&pathProbeEvidence{
		generation: generation, fenceEpoch: serverSlot.txFenceEpoch.Load(), fenceTracked: true,
		firstIssued: time.Now(), lastIssued: time.Now(), lastLifecycle: pathProbeDataStarved, issued: 1,
	})
	const probeID = uint64(0x5151)
	fixture.server.probeMu.Lock()
	fixture.server.probeOutstanding[probeID] = pathProbeObservation{
		queuedAt: time.Now(), generation: generation, slot: serverSlot,
		fenceEpoch: serverSlot.txFenceEpoch.Load(), lifecycle: pathProbeDataStarved,
		dataStallGeneration: dispatchGeneration, dataBlockedAt: time.Now().Add(-time.Second),
	}
	fixture.server.probeMu.Unlock()
	if status := fixture.server.pathProbeStatuses(time.Now())[serverSlot]; status.failure != pathProbeFailureDataStarved {
		t.Fatalf("precondition responder probe status=%+v", status)
	}

	emitter, err := leafmobility.NewRefreshEmitter(fixture.clientClaim)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := emitter.Observe(leafmobility.RefreshReasonLinkUnresponsive)
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
	eventuallyEngine(t, time.Second, func() bool {
		fixture.server.probeMu.Lock()
		_, outstanding := fixture.server.probeOutstanding[probeID]
		fixture.server.probeMu.Unlock()
		return !outstanding && serverSlot.probeEvidence.Load() == nil &&
			serverSlot.peerMobilityEpoch.Load() == peerEpochBefore+1
	})
	if got := fixture.server.pathTopologyEpoch.Load(); got == 0 || got == topologyEpochBefore {
		t.Fatalf("peer commit topology epoch=%d, before=%d", got, topologyEpochBefore)
	}
	if got := serverSlot.probeEndpointGen.Load(); got != endpointGenerationBefore {
		t.Fatalf("peer commit changed local endpoint generation=%d, want %d", got, endpointGenerationBefore)
	}
	if got := serverSlot.routeGeneration.Load(); got != routeGenerationBefore {
		t.Fatalf("peer commit changed local route generation=%d, want %d", got, routeGenerationBefore)
	}
	if got := fixture.server.MigrationCount(); got != migrationCountBefore {
		t.Fatalf("peer commit changed local migration count=%d, want %d", got, migrationCountBefore)
	}
	if stall, ok := serverSlot.currentDispatchStall(); !ok || stall != dispatchIdentity {
		t.Fatalf("peer commit changed physical dispatch custody got=%+v present=%t want=%+v",
			stall, ok, dispatchIdentity)
	}
	if status := fixture.server.pathProbeStatuses(time.Now())[serverSlot]; status.failure != pathProbeFailureNone {
		t.Fatalf("peer commit retained responder probe failure=%+v", status)
	}

	// Model a probe writer that captured its generation before COMPLETE but
	// published evidence after the first invalidation pass. The peer epoch must
	// keep that delayed evidence permanently non-authoritative.
	const delayedProbeID = probeID + 1
	serverSlot.probeEvidence.Store(&pathProbeEvidence{
		generation: generation, fenceEpoch: serverSlot.txFenceEpoch.Load(), fenceTracked: true,
		firstIssued: time.Now(), lastIssued: time.Now(), lastLifecycle: pathProbeDataStarved, issued: 1,
	})
	fixture.server.probeMu.Lock()
	fixture.server.probeOutstanding[delayedProbeID] = pathProbeObservation{
		queuedAt: time.Now(), generation: generation, slot: serverSlot,
		fenceEpoch: serverSlot.txFenceEpoch.Load(), lifecycle: pathProbeDataStarved,
		dataStallGeneration: dispatchGeneration, dataBlockedAt: time.Now().Add(-time.Second),
	}
	fixture.server.probeMu.Unlock()
	if status := fixture.server.pathProbeStatuses(time.Now())[serverSlot]; status.failure != pathProbeFailureNone {
		t.Fatalf("delayed predecessor probe regained selector authority=%+v", status)
	}
	if _, current := serverSlot.probeSnapshot(); current {
		t.Fatal("delayed predecessor probe evidence remained current after peer epoch advance")
	}
}

func TestLeafMobilityInitiatorAbortsAuthorityWhenEvidenceChangesDuringNegotiation(t *testing.T) {
	var source *initiatorRefreshPath
	blocker := &blockBeforePreparedRefreshPath{reached: make(chan struct{}), release: make(chan struct{})}
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			source = &initiatorRefreshPath{PathConn: path}
			return source
		}, nil, nil,
		func(path *memoryPathConn) transport.PathConn {
			blocker.PathConn = path
			return blocker
		},
	)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(blocker.release) }) }
	t.Cleanup(release)

	state := leafmobility.NewRefreshSourceState()
	initial, err := state.Update([32]byte{0x91})
	if err != nil {
		t.Fatal(err)
	}
	emitter, err := leafmobility.NewRefreshEmitterWithSourceState(fixture.clientClaim, state)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged, initial)
	if err != nil {
		t.Fatal(err)
	}
	if source == nil || !source.publish(evidence) {
		t.Fatal("refresh source was not subscribed")
	}
	select {
	case <-blocker.reached:
	case <-time.After(time.Second):
		t.Fatal("automatic negotiation did not reach PREPARED publication")
	}
	if _, err := state.Update([32]byte{0x92}); err != nil {
		t.Fatal(err)
	}
	release()

	eventuallyEngine(t, 3*time.Second, func() bool {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		return ok && status.Phase == LeafMobilityInitiatorSuperseded
	})
	if fixture.clientDriver.prepareCalls.Load() != 0 || fixture.clientDriver.cutoverCalls.Load() != 0 ||
		fixture.clientDriver.commitCalls.Load() != 0 || fixture.clientDriver.activateCalls.Load() != 0 {
		t.Fatalf("stale authority reached driver prepare/stage/publish/activate=%d/%d/%d/%d",
			fixture.clientDriver.prepareCalls.Load(), fixture.clientDriver.cutoverCalls.Load(),
			fixture.clientDriver.commitCalls.Load(), fixture.clientDriver.activateCalls.Load())
	}
	if fixture.client.MigrationCount() != 0 {
		t.Fatalf("stale authority recorded %d migrations", fixture.client.MigrationCount())
	}
	assertLeafMobilityDataFlow(t, fixture, "after-stale-automatic-authority-abort")
}

func testLeafMobilityInitiatorPreservesTypedRefreshReason(t *testing.T) {
	for _, reason := range []leafmobility.RefreshReason{
		leafmobility.RefreshReasonLinkUnresponsive,
		leafmobility.RefreshReasonLocalReadFailure,
		leafmobility.RefreshReasonLocalWriteFailure,
		leafmobility.RefreshReasonOuterMTUFailure,
		leafmobility.RefreshReasonReplayStalled,
		leafmobility.RefreshReasonReplayFailure,
		leafmobility.RefreshReasonLivenessProbeFailure,
	} {
		t.Run(fmt.Sprintf("reason-%d", reason), func(t *testing.T) {
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
			evidence, err := emitter.Observe(reason)
			if err != nil {
				t.Fatal(err)
			}
			if source == nil || !source.publish(evidence) {
				t.Fatal("typed refresh source was not subscribed")
			}
			eventuallyEngine(t, 3*time.Second, func() bool {
				status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
				return ok && status.EvidenceGeneration != 0 && status.EvidenceReason == reason
			})
			status, _ := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
			if status.EvidenceReason != reason {
				t.Fatalf("engine reason=%d want=%d status=%+v", status.EvidenceReason, reason, status)
			}
		})
	}
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
		event MigrationEvent
	}
	observed := make(chan observation, 2)
	subscription := fixture.client.OnMigrationEvent(func(event MigrationEvent) {
		observed <- observation{event: event}
	})
	defer subscription.Cancel()
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
			eventuallyEngine(t, 3*time.Second, func() bool {
				status, present := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
				return present && status.Phase == LeafMobilityInitiatorCommitted
			})
			status, present := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
			if got.event.OldPathID != fixture.clientRef.ID || got.event.NewPathID != fixture.clientRef.ID ||
				got.event.Cause != "leaf-mobility" || !present ||
				status.TransactionID == (leafmobility.TransactionID{}) ||
				status.ResultEndpointGeneration == 0 ||
				status.ResultEndpointGeneration == status.SourceEndpointGeneration ||
				got.event.Evidence.Kind != MigrationEvidenceLeafMobility ||
				got.event.Evidence.TransactionID != [16]byte(status.TransactionID) ||
				got.event.Evidence.RefreshEvidenceGeneration != status.EvidenceGeneration ||
				got.event.Evidence.SourceEndpointGeneration != status.SourceEndpointGeneration ||
				got.event.Evidence.ResultEndpointGeneration != status.ResultEndpointGeneration ||
				got.event.Evidence.Source.PathID != fixture.clientRef.ID ||
				got.event.Evidence.Result.PathID != fixture.clientRef.ID ||
				got.event.Evidence.Source.PathOwner != fixture.clientRef.Owner ||
				got.event.Evidence.Result.PathOwner != fixture.clientRef.Owner ||
				got.event.Evidence.Source.EndpointGeneration != status.SourceEndpointGeneration ||
				got.event.Evidence.Result.EndpointGeneration != status.ResultEndpointGeneration ||
				got.event.Evidence.Source.HealthRevision == 0 ||
				got.event.Evidence.Result.HealthRevision <= got.event.Evidence.Source.HealthRevision ||
				got.event.Evidence.Source.PathGeneration == 0 || got.event.Evidence.Result.PathGeneration == 0 ||
				got.event.Evidence.Source.LocalTargetID == ([16]byte{}) || got.event.Evidence.Result.LocalTargetID == ([16]byte{}) ||
				got.event.Evidence.Leaf.RefreshReason != "route_source_changed" ||
				got.event.Evidence.Leaf.RefreshObservedAt.IsZero() ||
				got.event.Evidence.Leaf.RefreshSourceGeneration == 0 ||
				!got.event.Evidence.Leaf.RefreshSourceUsable || got.event.Evidence.Leaf.RefreshIncarnation == 0 ||
				got.event.Evidence.Selector != (MigrationSelectorBinding{}) ||
				got.event.Evidence.TopologyEpoch == 0 || len(got.event.Evidence.ProbeGenerations) != 0 ||
				got.event.Ordinal != uint64(migration) {
				t.Fatalf("migration %d callback observation=%+v status=%+v", migration, got, status)
			}
			if previousTransaction != (leafmobility.TransactionID{}) && status.TransactionID == previousTransaction {
				t.Fatalf("migration %d reused transaction %x", migration, status.TransactionID)
			}
			if previousEndpointGeneration != 0 && status.SourceEndpointGeneration != previousEndpointGeneration {
				t.Fatalf("migration %d source generation=%d want prior result=%d",
					migration, status.SourceEndpointGeneration, previousEndpointGeneration)
			}
			previousTransaction = status.TransactionID
			previousEndpointGeneration = status.ResultEndpointGeneration
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

func TestLeafMobilityCommittedEventPrecedesBlockingRefreshBaseline(t *testing.T) {
	var source *blockingRefreshCommitPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			source = &blockingRefreshCommitPath{
				initiatorRefreshPath: &initiatorRefreshPath{PathConn: path},
				entered:              make(chan struct{}),
				release:              make(chan struct{}),
			}
			return source
		}, nil, nil, nil,
	)
	t.Cleanup(func() {
		select {
		case <-source.release:
		default:
			close(source.release)
		}
	})
	events := make(chan MigrationEvent, 1)
	subscription := fixture.client.OnMigrationEvent(func(event MigrationEvent) { events <- event })
	defer subscription.Cancel()
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
	select {
	case <-source.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("refresh baseline callback did not block")
	}
	event := receiveMigrationEvent(t, events)
	if event.Evidence.Kind != MigrationEvidenceLeafMobility || fixture.client.MigrationCount() != 1 {
		t.Fatalf("event/count before baseline release=%+v/%d", event, fixture.client.MigrationCount())
	}
	close(source.release)
	eventuallyEngine(t, 3*time.Second, func() bool {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		return ok && status.Phase == LeafMobilityInitiatorCommitted && status.Error == ""
	})
}

func TestLeafMobilityRefreshBaselineDeadlineReleasesWorkerAndSerializesNextCommit(t *testing.T) {
	limits := Limits{MigrationBudget: 350 * time.Millisecond}
	var source *blockingRefreshCommitPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappersAndLimits(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			source = &blockingRefreshCommitPath{
				initiatorRefreshPath: &initiatorRefreshPath{PathConn: path},
				entered:              make(chan struct{}),
				release:              make(chan struct{}),
			}
			return source
		}, nil, nil, nil, limits, limits,
	)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(source.release) }) }
	t.Cleanup(release)

	events := make(chan MigrationEvent, 2)
	subscription := fixture.client.OnMigrationEvent(func(event MigrationEvent) { events <- event })
	defer subscription.Cancel()
	emitter, err := leafmobility.NewRefreshEmitter(fixture.clientClaim)
	if err != nil {
		t.Fatal(err)
	}
	firstEvidence, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
	if err != nil {
		t.Fatal(err)
	}
	firstSnapshot, err := firstEvidence.ValidateFor(fixture.clientClaim, 0)
	if err != nil {
		t.Fatal(err)
	}
	if source == nil || !source.publish(firstEvidence) {
		t.Fatal("refresh source was not subscribed")
	}
	select {
	case <-source.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("refresh baseline callback did not enter")
	}
	_ = receiveMigrationEvent(t, events)
	eventuallyEngine(t, 2*time.Second, func() bool {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		return ok && status.Phase == LeafMobilityInitiatorCommitted &&
			status.EvidenceGeneration == firstSnapshot.Generation &&
			strings.Contains(status.Error, leafMobilityRefreshCommitOp) &&
			strings.Contains(status.Error, "deadline")
	})
	fixture.client.pathsMu.RLock()
	subject := fixture.client.paths[fixture.clientRef.ID]
	fixture.client.pathsMu.RUnlock()
	fixture.client.leafRefreshMu.Lock()
	_, running := fixture.client.leafRefreshRunning[fixture.clientRef]
	_, workerCancel := fixture.client.leafRefreshCancel[fixture.clientRef]
	fixture.client.leafRefreshMu.Unlock()
	var policyHolds int32
	if subject != nil {
		policyHolds = subject.mobilityPolicyHolds.Load()
	}
	if running || workerCancel || subject == nil || policyHolds != 0 {
		t.Fatalf("timed-out committer retained running/cancel/subject/holds=%t/%t/%t/%d",
			running, workerCancel, subject != nil, policyHolds)
	}
	assertLeafMobilityDataFlow(t, fixture, "after-blocked-refresh-baseline-timeout")

	secondEvidence, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
	if err != nil {
		t.Fatal(err)
	}
	secondSnapshot, err := secondEvidence.ValidateFor(fixture.clientClaim, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !source.publish(secondEvidence) {
		t.Fatal("refresh source unsubscribed after callback timeout")
	}
	eventuallyEngine(t, time.Second, func() bool {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		return ok && status.EvidenceGeneration == secondSnapshot.Generation &&
			status.Phase == LeafMobilityInitiatorDeferred && source.calls.Load() == 1
	})
	if got := fixture.client.MigrationCount(); got != 1 {
		t.Fatalf("new transaction crossed orphaned baseline callback: migrations=%d", got)
	}

	release()
	_ = receiveMigrationEvent(t, events)
	committed := false
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		if ok && status.Phase == LeafMobilityInitiatorCommitted &&
			status.EvidenceGeneration == secondSnapshot.Generation && status.Error == "" {
			committed = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !committed {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		fixture.client.leafRefreshMu.Lock()
		_, pending := fixture.client.leafRefreshPending[fixture.clientRef]
		_, running := fixture.client.leafRefreshRunning[fixture.clientRef]
		fixture.client.leafRefreshMu.Unlock()
		t.Fatalf("second baseline did not commit: status=%+v present=%t pending/running=%t/%t migrations/calls=%d/%d",
			status, ok, pending, running, fixture.client.MigrationCount(), source.calls.Load())
	}
	if got := fixture.client.MigrationCount(); got != 2 || source.calls.Load() != 2 {
		t.Fatalf("serialized callback migrations/calls=%d/%d want 2/2", got, source.calls.Load())
	}
}

func TestLeafMobilityRefreshTerminalStatusWaitsForWorkerOwnershipRelease(t *testing.T) {
	limits := Limits{MigrationBudget: 350 * time.Millisecond}
	var source *blockingRefreshCommitPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappersAndLimits(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			source = &blockingRefreshCommitPath{
				initiatorRefreshPath: &initiatorRefreshPath{PathConn: path},
				entered:              make(chan struct{}),
				release:              make(chan struct{}),
			}
			return source
		}, nil, nil, nil, limits, limits,
	)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(source.release) }) }
	t.Cleanup(release)

	terminalStatusEntered := make(chan struct{})
	releaseTerminalStatus := make(chan struct{})
	var releaseStatusOnce sync.Once
	unblockStatus := func() { releaseStatusOnce.Do(func() { close(releaseTerminalStatus) }) }
	t.Cleanup(unblockStatus)
	var armTerminalStatus atomic.Bool
	fixture.client.leafRefreshStatusBeforeWrite = func() {
		if armTerminalStatus.CompareAndSwap(true, false) {
			close(terminalStatusEntered)
			<-releaseTerminalStatus
		}
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
	select {
	case <-source.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("refresh baseline callback did not enter")
	}
	armTerminalStatus.Store(true)
	select {
	case <-terminalStatusEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("terminal refresh status did not reach its publication boundary")
	}

	fixture.client.pathsMu.RLock()
	subject := fixture.client.paths[fixture.clientRef.ID]
	fixture.client.pathsMu.RUnlock()
	fixture.client.leafRefreshMu.Lock()
	_, running := fixture.client.leafRefreshRunning[fixture.clientRef]
	_, workerCancel := fixture.client.leafRefreshCancel[fixture.clientRef]
	fixture.client.leafRefreshMu.Unlock()
	var policyHolds int32
	if subject != nil {
		policyHolds = subject.mobilityPolicyHolds.Load()
	}
	if running || workerCancel || subject == nil || policyHolds != 0 {
		t.Fatalf("terminal publication retained running/cancel/subject/holds=%t/%t/%t/%d",
			running, workerCancel, subject != nil, policyHolds)
	}

	unblockStatus()
	eventuallyEngine(t, time.Second, func() bool {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		return ok && status.Phase == LeafMobilityInitiatorCommitted &&
			strings.Contains(status.Error, leafMobilityRefreshCommitOp) &&
			strings.Contains(status.Error, "deadline")
	})
}

func TestLeafMobilityRefreshBaselineGoexitIsTerminalAndReleasesOwnership(t *testing.T) {
	var source *goexitRefreshCommitPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			source = &goexitRefreshCommitPath{
				initiatorRefreshPath: &initiatorRefreshPath{PathConn: path},
			}
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
		return ok && status.Phase == LeafMobilityInitiatorCommitted &&
			strings.Contains(status.Error, leafMobilityRefreshCommitOp) &&
			strings.Contains(status.Error, "runtime.Goexit")
	})
	fixture.client.pathsMu.RLock()
	subject := fixture.client.paths[fixture.clientRef.ID]
	fixture.client.pathsMu.RUnlock()
	fixture.client.leafRefreshMu.Lock()
	_, running := fixture.client.leafRefreshRunning[fixture.clientRef]
	_, workerCancel := fixture.client.leafRefreshCancel[fixture.clientRef]
	fixture.client.leafRefreshMu.Unlock()
	var policyHolds int32
	if subject != nil {
		policyHolds = subject.mobilityPolicyHolds.Load()
	}
	if running || workerCancel || subject == nil || policyHolds != 0 || source.calls.Load() != 1 {
		t.Fatalf("Goexit committer retained running/cancel/subject/holds/calls=%t/%t/%t/%d/%d",
			running, workerCancel, subject != nil, policyHolds, source.calls.Load())
	}
}

func TestLeafMobilityRefreshBaselinePanicKeepsOneFactualCommit(t *testing.T) {
	panicErr := errors.New("injected refresh baseline panic")
	var source *panickingRefreshCommitPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			source = &panickingRefreshCommitPath{
				initiatorRefreshPath: &initiatorRefreshPath{PathConn: path},
				panicValue:           panicErr,
			}
			return source
		}, nil, nil, nil,
	)
	events := make(chan MigrationEvent, 2)
	subscription := fixture.client.OnMigrationEvent(func(event MigrationEvent) { events <- event })
	defer subscription.Cancel()
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
	event := receiveMigrationEvent(t, events)
	eventuallyEngine(t, 3*time.Second, func() bool {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		return ok && status.Phase == LeafMobilityInitiatorCommitted &&
			strings.Contains(status.Error, fmt.Sprintf("%T", panicErr))
	})
	status, _ := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
	if strings.Contains(status.Error, panicErr.Error()) {
		t.Fatalf("panic diagnostic exposed untrusted payload: %q", status.Error)
	}
	if fixture.client.MigrationCount() != 1 || source.calls.Load() != 1 ||
		event.Evidence.Kind != MigrationEvidenceLeafMobility {
		t.Fatalf("panic commit count/calls/event=%d/%d/%+v", fixture.client.MigrationCount(), source.calls.Load(), event)
	}
	if !source.publish(evidence) {
		t.Fatal("refresh source unsubscribed after contained panic")
	}
	time.Sleep(50 * time.Millisecond)
	if fixture.client.MigrationCount() != 1 || source.calls.Load() != 1 {
		t.Fatalf("replayed evidence duplicated panic commit count/calls=%d/%d",
			fixture.client.MigrationCount(), source.calls.Load())
	}
	select {
	case duplicate := <-events:
		t.Fatalf("replayed evidence emitted duplicate event: %+v", duplicate)
	default:
	}
}

func TestLeafMobilityRefreshBaselineFailureKeepsOneFactualCommit(t *testing.T) {
	baselineErr := errors.New("injected refresh baseline failure")
	var source *failingRefreshCommitPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			source = &failingRefreshCommitPath{
				initiatorRefreshPath: &initiatorRefreshPath{PathConn: path},
				err:                  baselineErr,
			}
			return source
		}, nil, nil, nil,
	)
	events := make(chan MigrationEvent, 2)
	subscription := fixture.client.OnMigrationEvent(func(event MigrationEvent) { events <- event })
	defer subscription.Cancel()
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
	event := receiveMigrationEvent(t, events)
	eventuallyEngine(t, 3*time.Second, func() bool {
		status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
		return ok && status.Phase == LeafMobilityInitiatorCommitted && strings.Contains(status.Error, baselineErr.Error())
	})
	status, _ := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
	if fixture.client.MigrationCount() != 1 || source.calls.Load() != 1 ||
		event.Evidence.Kind != MigrationEvidenceLeafMobility ||
		event.Evidence.TransactionID != [16]byte(status.TransactionID) ||
		event.Evidence.RefreshEvidenceGeneration != status.EvidenceGeneration ||
		event.Evidence.SourceEndpointGeneration != status.SourceEndpointGeneration ||
		event.Evidence.ResultEndpointGeneration != status.ResultEndpointGeneration {
		t.Fatalf("baseline failure count/calls/event/status=%d/%d/%+v/%+v",
			fixture.client.MigrationCount(), source.calls.Load(), event, status)
	}
	if !source.publish(evidence) {
		t.Fatal("refresh source unsubscribed after committed baseline failure")
	}
	time.Sleep(50 * time.Millisecond)
	if fixture.client.MigrationCount() != 1 || source.calls.Load() != 1 {
		t.Fatalf("replayed evidence duplicated commit count/calls=%d/%d",
			fixture.client.MigrationCount(), source.calls.Load())
	}
	select {
	case duplicate := <-events:
		t.Fatalf("replayed evidence emitted duplicate event: %+v", duplicate)
	default:
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

	t.Run("status publication cannot outlive its exact generation", func(t *testing.T) {
		var raceSource *initiatorRefreshPath
		raceFixture := newLeafMobilityEngineFixtureWithAllWrappers(
			t, leafmobility.Resource{}, leafmobility.Resource{},
			func(path *memoryPathConn) transport.PathConn {
				raceSource = &initiatorRefreshPath{PathConn: path}
				return raceSource
			}, nil, nil, nil,
		)
		if raceSource == nil {
			t.Fatal("missing refresh source")
		}
		entered := make(chan struct{})
		release := make(chan struct{})
		var releaseOnce sync.Once
		unblock := func() { releaseOnce.Do(func() { close(release) }) }
		t.Cleanup(unblock)
		var block atomic.Bool
		block.Store(true)
		raceFixture.client.leafRefreshStatusBeforeWrite = func() {
			if block.CompareAndSwap(true, false) {
				close(entered)
				<-release
			}
		}
		recorded := make(chan struct{})
		go func() {
			raceFixture.client.recordLeafMobilityInitiator(LeafMobilityInitiatorSnapshot{
				Ref: raceFixture.clientRef, EvidenceGeneration: ^uint64(0),
				Phase: LeafMobilityInitiatorFailed, UpdatedAt: time.Now(),
			})
			close(recorded)
		}()
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("status publication did not reach the generation/write boundary")
		}
		retired := make(chan error, 1)
		go func() {
			retired <- raceFixture.client.RetirePath(
				raceFixture.clientRef, errors.New("retire during status publication"),
			)
		}()
		var retireErr error
		premature := false
		select {
		case retireErr = <-retired:
			premature = true
		case <-time.After(20 * time.Millisecond):
		}
		unblock()
		select {
		case <-recorded:
		case <-time.After(time.Second):
			t.Fatal("status publication did not finish")
		}
		if !premature {
			select {
			case retireErr = <-retired:
			case <-time.After(time.Second):
				t.Fatal("retirement did not follow status publication")
			}
		}
		if retireErr != nil {
			t.Fatal(retireErr)
		}
		if premature {
			t.Fatal("path retirement crossed an in-flight exact-generation status publication")
		}
		if _, ok := raceFixture.client.LeafMobilityInitiatorStatus(raceFixture.clientRef); ok {
			t.Fatal("retired generation was recreated by a stale status publication")
		}
	})
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
