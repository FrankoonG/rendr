package engine

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

func TestSelectorCommitRejectsSameGenerationRecoveredWireTimeout(t *testing.T) {
	e, ids, aID, aSlot := newHealthRevisionSelectorFixture(t)
	now := time.Now()
	seedPathProbeSuccess(e, aSlot, now.Add(-5*time.Second), 10*time.Millisecond)
	seedPathProbeWireTimeout(e, aSlot, now.Add(-time.Second))
	aSlot.advanceHealthEvidenceRevision()

	view, ok := e.selectorEvidenceSnapshot()
	if !ok {
		t.Fatal("wire-timeout selector evidence snapshot was unavailable")
	}
	observation := view.observations[ids["a"]]
	if observation.probeFailure != pathProbeFailureWireTimeout || observation.probeLiveness != qualityStateStale {
		t.Fatalf("wire-timeout observation=%+v", observation)
	}
	commit := view.commitEvidence()
	generation := pathProbeGenerationForSlot(aSlot)
	e.probeMu.Lock()
	evidence := aSlot.probeEvidence.Load()
	if evidence == nil {
		e.probeMu.Unlock()
		t.Fatal("wire-timeout evidence disappeared before recovery")
	}
	recoveredAt := now.Add(time.Millisecond)
	recovered := pathProbeObservation{
		slot: aSlot, generation: generation, fenceEpoch: evidence.fenceEpoch,
		writeStartedAt: recoveredAt.Add(-time.Millisecond), writeCommittedAt: recoveredAt,
		wireProgressTracked: evidence.migrationTracked, wireMigrationEpoch: evidence.migrationEpoch,
	}
	recoveredOK := false
	aSlot.mutateHealthEvidence(func() {
		recoveredOK = e.recordPathProbeSuccessLocked(recovered, recoveredAt.Add(time.Millisecond))
	})
	if !recoveredOK {
		e.probeMu.Unlock()
		t.Fatal("same-generation probe recovery was rejected")
	}
	e.probeMu.Unlock()

	assertStaleHealthEvidenceCannotCommit(
		t, e, ids, aID, commit, "probe-wire-timeout", policySelectionProbeFailure,
	)
}

func TestSelectorCommitRejectsSameGenerationClearedDataStarvation(t *testing.T) {
	e, ids, aID, aSlot := newHealthRevisionSelectorFixture(t)
	generation := pathProbeGenerationForSlot(aSlot)
	identity := pathDispatchIdentity{generation: aSlot.nextDispatchGeneration(), pathGeneration: generation}
	aSlot.markDispatchStalled(identity)

	now := time.Now()
	const probeID = 0x5a17
	e.probeMu.Lock()
	aSlot.mutateHealthEvidence(func() {
		e.probeOutstanding[probeID] = pathProbeObservation{
			queuedAt: now.Add(-time.Second), generation: generation, slot: aSlot,
			fenceEpoch: aSlot.txFenceEpoch.Load(), lifecycle: pathProbeDataStarved,
			dataStallGeneration: identity.generation, dataBlockedAt: now.Add(-time.Second),
		}
	})
	e.probeMu.Unlock()

	view, ok := e.selectorEvidenceSnapshot()
	if !ok {
		t.Fatal("data-starvation selector evidence snapshot was unavailable")
	}
	observation := view.observations[ids["a"]]
	if observation.probeFailure != pathProbeFailureDataStarved || observation.probeLifecycle != pathProbeDataStarved {
		t.Fatalf("data-starvation observation=%+v", observation)
	}
	commit := view.commitEvidence()
	aSlot.completeDispatch(identity)
	if aSlot.dispatchStalled.Load() {
		t.Fatal("same-generation dispatch stall did not clear")
	}
	if pathProbeGenerationForSlot(aSlot) != generation {
		t.Fatal("test recovery changed the path generation")
	}

	assertStaleHealthEvidenceCannotCommit(
		t, e, ids, aID, commit, "probe-starved-data", policySelectionProbeStarvedData,
	)
}

func TestHealthEvidenceRevisionIgnoresNoOpPollingAndPredecessorCustody(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: time.Second}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	slot := &pathSlot{id: 91, owner: 92}
	generation := pathProbeGenerationForSlot(slot)
	initial, _, _ := slot.healthEvidenceSnapshot()
	if initial == 0 {
		t.Fatal("initial health evidence revision is zero")
	}

	e.probeMu.Lock()
	e.probeOutstanding[1] = pathProbeObservation{
		queuedAt: time.Now(), generation: generation, slot: slot, lifecycle: pathProbeQueued,
	}
	e.refreshPathProbeBlockStatesLocked(time.Now())
	e.refreshPathProbeBlockStatesLocked(time.Now().Add(time.Second))
	e.probeMu.Unlock()
	afterPolling, _, _ := slot.healthEvidenceSnapshot()
	if afterPolling != initial {
		t.Fatalf("no-op polling advanced health revision: before=%d after=%d", initial, afterPolling)
	}

	predecessor := pathDispatchIdentity{generation: 1, pathGeneration: generation}
	slot.routeGeneration.Add(1)
	slot.markDispatchStalled(predecessor)
	afterPredecessor, _, stalled := slot.healthEvidenceSnapshot()
	if !stalled {
		t.Fatal("predecessor custody stall was not retained")
	}
	if afterPredecessor != initial {
		t.Fatalf("predecessor custody advanced successor health revision: before=%d after=%d", initial, afterPredecessor)
	}
	slot.completeDispatch(predecessor)
	if afterClear, _, stalled := slot.healthEvidenceSnapshot(); stalled || afterClear != initial {
		t.Fatalf("predecessor custody clear changed health state: revision=%d stalled=%t", afterClear, stalled)
	}
}

func TestHealthEvidenceRevisionOverflowFailsFast(t *testing.T) {
	slot := &pathSlot{healthEvidenceRevision: ^uint64(0)}
	defer func() {
		if recover() == nil {
			t.Fatal("health evidence revision overflow did not panic")
		}
	}()
	slot.advanceHealthEvidenceRevision()
}

func TestSelectorCommitGateSerializesWireRecoveryAfterValidation(t *testing.T) {
	e, ids, _, aSlot := newHealthRevisionSelectorFixture(t)
	now := time.Now()
	seedPathProbeSuccess(e, aSlot, now.Add(-5*time.Second), 10*time.Millisecond)
	seedPathProbeWireTimeout(e, aSlot, now.Add(-time.Second))
	aSlot.advanceHealthEvidenceRevision()
	view, ok := e.selectorEvidenceSnapshot()
	if !ok || view.observations[ids["a"]].probeFailure != pathProbeFailureWireTimeout {
		t.Fatalf("wire-timeout snapshot unavailable or not failed: ok=%t observation=%+v", ok, view.observations[ids["a"]])
	}

	attempted := make(chan struct{})
	recovered := make(chan struct{})
	hookErrors := make(chan error, 2)
	var attemptedOnce sync.Once
	var routePublished atomic.Bool
	aSlot.healthEvidenceBeforeGate = func() { attemptedOnce.Do(func() { close(attempted) }) }
	e.policyCommitAfterPublish = func() { routePublished.Store(true) }
	e.selectorHealthAfterValidation = func() {
		go func() {
			e.probeMu.Lock()
			evidence := aSlot.probeEvidence.Load()
			generation := pathProbeGenerationForSlot(aSlot)
			observation := pathProbeObservation{
				slot: aSlot, generation: generation, fenceEpoch: evidence.fenceEpoch,
				writeStartedAt: now, writeCommittedAt: now.Add(time.Millisecond),
				wireProgressTracked: evidence.migrationTracked, wireMigrationEpoch: evidence.migrationEpoch,
			}
			aSlot.mutateHealthEvidence(func() {
				if !routePublished.Load() {
					hookErrors <- errors.New("wire recovery crossed commit gate before route publication")
				}
				if !e.recordPathProbeSuccessLocked(observation, now.Add(2*time.Millisecond)) {
					hookErrors <- errors.New("serialized wire recovery was rejected")
				}
			})
			e.probeMu.Unlock()
			close(recovered)
		}()
		select {
		case <-attempted:
		case <-time.After(time.Second):
			hookErrors <- errors.New("wire recovery did not reach the commit gate")
		}
		select {
		case <-recovered:
			hookErrors <- errors.New("wire recovery was not blocked after selector validation")
		default:
		}
	}

	err := e.commitRecursiveSelection(
		"probe-wire-timeout", e.localExecutionRuntime(), ids["root"], ids["b"],
		policySelectionProbeFailure, 0, view.commitEvidence(), nil, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-recovered:
	case <-time.After(time.Second):
		t.Fatal("wire recovery remained blocked after selector commit")
	}
	close(hookErrors)
	for err := range hookErrors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if e.MigrationCount() != 1 || !routePublished.Load() {
		t.Fatalf("serialized selector commit count/published=%d/%t want 1/true", e.MigrationCount(), routePublished.Load())
	}
}

func TestSelectorCommitGateSerializesStallClearAfterValidation(t *testing.T) {
	e, ids, _, aSlot, identity, commit := newDataStarvationCommitFixture(t)
	attempted := make(chan struct{})
	cleared := make(chan struct{})
	hookErrors := make(chan error, 2)
	var attemptedOnce sync.Once
	var routePublished atomic.Bool
	aSlot.healthEvidenceBeforeGate = func() { attemptedOnce.Do(func() { close(attempted) }) }
	e.policyCommitAfterPublish = func() { routePublished.Store(true) }
	e.selectorHealthAfterValidation = func() {
		go func() {
			aSlot.completeDispatch(identity)
			if !routePublished.Load() {
				hookErrors <- errors.New("stall clear crossed commit gate before route publication")
			}
			close(cleared)
		}()
		select {
		case <-attempted:
		case <-time.After(time.Second):
			hookErrors <- errors.New("stall clear did not reach the commit gate")
		}
		select {
		case <-cleared:
			hookErrors <- errors.New("stall clear was not blocked after selector validation")
		default:
		}
	}

	if err := e.commitRecursiveSelection(
		"probe-starved-data", e.localExecutionRuntime(), ids["root"], ids["b"],
		policySelectionProbeStarvedData, 0, commit, nil, false,
	); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cleared:
	case <-time.After(time.Second):
		t.Fatal("stall clear remained blocked after selector commit")
	}
	close(hookErrors)
	for err := range hookErrors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if aSlot.dispatchStalled.Load() || e.MigrationCount() != 1 || !routePublished.Load() {
		t.Fatalf("serialized stall clear stalled/count/published=%t/%d/%t", aSlot.dispatchStalled.Load(), e.MigrationCount(), routePublished.Load())
	}
}

func TestSelectorCommitGateRejectsStallClearedBeforeValidation(t *testing.T) {
	e, ids, aID, aSlot, identity, commit := newDataStarvationCommitFixture(t)
	var hookOnce sync.Once
	e.selectorHealthBeforeCommitGate = func() {
		hookOnce.Do(func() { aSlot.completeDispatch(identity) })
	}
	assertStaleHealthEvidenceCannotCommit(
		t, e, ids, aID, commit, "probe-starved-data", policySelectionProbeStarvedData,
	)
}

func TestSelectorCommitRejectsEvidenceExpiredAtRoutePublication(t *testing.T) {
	e, ids, activeBefore, _ := newHealthRevisionSelectorFixture(t)
	start := time.Unix(1_000, 0)
	validUntil := start.Add(time.Second)
	var clock atomic.Int64
	clock.Store(start.UnixNano())
	installEngineNowForTest(t, func() time.Time { return time.Unix(0, clock.Load()) })

	commit := selectorEvidenceCommit{
		topologyEpoch: e.currentPathTopologyEpoch(),
		capturedAt:    start,
		validUntil:    validUntil,
	}
	e.selectorHealthAfterValidation = func() {
		clock.Store(validUntil.UnixNano())
	}
	t.Cleanup(func() { e.selectorHealthAfterValidation = nil })

	err := e.commitRecursiveSelection(
		"quality", e.localExecutionRuntime(), ids["root"], ids["b"],
		policySelectionQuality, 0, commit, nil, false,
	)
	if !errors.Is(err, ErrSelectorDecisionUnavailable) {
		t.Fatalf("selector commit at ValidUntil error=%v, want %v", err, ErrSelectorDecisionUnavailable)
	}
	if e.ActivePath() != activeBefore || e.MigrationCount() != 0 {
		t.Fatalf("expired route publication changed active/count=%d/%d want %d/0", e.ActivePath(), e.MigrationCount(), activeBefore)
	}
}

func TestSelectorMigrationTimestampIsRoutePublicationLinearization(t *testing.T) {
	e, ids, activeBefore, _ := newHealthRevisionSelectorFixture(t)
	start := time.Unix(2_000, 0)
	validUntil := start.Add(time.Second)
	var clock atomic.Int64
	clock.Store(start.UnixNano())
	installEngineNowForTest(t, func() time.Time { return time.Unix(0, clock.Load()) })

	events := make(chan MigrationEvent, 1)
	subscription := e.OnMigrationEvent(func(event MigrationEvent) { events <- event })
	defer subscription.Cancel()
	e.policyCommitAfterPublish = func() {
		clock.Store(validUntil.Add(time.Second).UnixNano())
	}
	t.Cleanup(func() { e.policyCommitAfterPublish = nil })
	commit := selectorEvidenceCommit{
		topologyEpoch: e.currentPathTopologyEpoch(),
		capturedAt:    start,
		validUntil:    validUntil,
	}

	if err := e.commitRecursiveSelection(
		"quality", e.localExecutionRuntime(), ids["root"], ids["b"],
		policySelectionQuality, 0, commit, nil, false,
	); err != nil {
		t.Fatal(err)
	}
	event := receiveMigrationEvent(t, events)
	if event.OldPathID != activeBefore || event.NewPathID == activeBefore ||
		!event.CommittedAt.Equal(start) || !event.CommittedAt.Before(event.Evidence.Selector.ValidUntil) ||
		!event.Evidence.Selector.ValidUntil.Equal(validUntil) {
		t.Fatalf("selector event did not retain route publication time: %+v", event)
	}
}

func newDataStarvationCommitFixture(
	t *testing.T,
) (*Engine, map[string]proto.TargetID, uint32, *pathSlot, pathDispatchIdentity, selectorEvidenceCommit) {
	t.Helper()
	e, ids, aID, aSlot := newHealthRevisionSelectorFixture(t)
	generation := pathProbeGenerationForSlot(aSlot)
	identity := pathDispatchIdentity{generation: aSlot.nextDispatchGeneration(), pathGeneration: generation}
	aSlot.markDispatchStalled(identity)
	now := time.Now()
	e.probeMu.Lock()
	aSlot.mutateHealthEvidence(func() {
		e.probeOutstanding[0x6a18] = pathProbeObservation{
			queuedAt: now.Add(-time.Second), generation: generation, slot: aSlot,
			fenceEpoch: aSlot.txFenceEpoch.Load(), lifecycle: pathProbeDataStarved,
			dataStallGeneration: identity.generation, dataBlockedAt: now.Add(-time.Second),
		}
	})
	e.probeMu.Unlock()
	view, ok := e.selectorEvidenceSnapshot()
	if !ok {
		t.Fatal("data-starvation selector evidence snapshot was unavailable")
	}
	observation := view.observations[ids["a"]]
	if observation.probeFailure != pathProbeFailureDataStarved {
		t.Fatalf("data-starvation observation=%+v", observation)
	}
	if len(view.generations) == 0 {
		t.Fatal("data-starvation snapshot has no physical generation binding")
	}
	return e, ids, aID, aSlot, identity, view.commitEvidence()
}

func newHealthRevisionSelectorFixture(
	t *testing.T,
) (*Engine, map[string]proto.TargetID, uint32, *pathSlot) {
	t.Helper()
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{
		ProbeInterval: time.Millisecond,
	}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	a, aPeer := newMemoryPathPair()
	b, bPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = aPeer.Close(); _ = bPeer.Close() })
	aID := attachFixturePath(t, e, a, transport.PathSpec{Transport: "memory", Address: "health-a"}, ids["a"])
	attachFixturePath(t, e, b, transport.PathSpec{Transport: "memory", Address: "health-b"}, ids["b"])
	e.pathsMu.RLock()
	aSlot := e.paths[aID]
	e.pathsMu.RUnlock()
	if aSlot == nil || e.ActivePath() != aID {
		t.Fatalf("initial health fixture active/slot=%d/%p want %d/non-nil", e.ActivePath(), aSlot, aID)
	}
	seedPathProbeSuccess(e, aSlot, time.Now(), 10*time.Millisecond)
	return e, ids, aID, aSlot
}

func assertStaleHealthEvidenceCannotCommit(
	t *testing.T,
	e *Engine,
	ids map[string]proto.TargetID,
	wantActive uint32,
	commit selectorEvidenceCommit,
	cause string,
	origin policySelectionOrigin,
) {
	t.Helper()
	events := make(chan struct{}, 1)
	cancel := e.OnMigrate(func(_, _ uint32, _ string) { events <- struct{}{} })
	defer cancel()
	e.zombieMu.Lock()
	zombieBefore := e.zombieLeft
	e.zombieMu.Unlock()
	err := e.commitRecursiveSelection(
		cause, e.localExecutionRuntime(), ids["root"], ids["b"], origin, 0, commit, nil, false,
	)
	if !errors.Is(err, errStaleSelectorEvidence) {
		t.Fatalf("stale health evidence commit error=%v want %v", err, errStaleSelectorEvidence)
	}
	if e.ActivePath() != wantActive || e.MigrationCount() != 0 {
		t.Fatalf("stale health evidence changed active/migrations=%d/%d want %d/0", e.ActivePath(), e.MigrationCount(), wantActive)
	}
	e.zombieMu.Lock()
	zombieAfter := e.zombieLeft
	e.zombieMu.Unlock()
	if zombieAfter != zombieBefore {
		t.Fatalf("stale health evidence charged zombie budget: before=%d after=%d", zombieBefore, zombieAfter)
	}
	select {
	case <-events:
		t.Fatal("stale health evidence emitted a migration event")
	case <-time.After(10 * time.Millisecond):
	}
}
