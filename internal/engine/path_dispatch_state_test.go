package engine

import (
	"sync"
	"testing"

	"github.com/FrankoonG/rendr/proto"
)

func TestFlatSelectorDispatchCacheInvalidatesEveryRoutingAuthority(t *testing.T) {
	e, runtime, ids, aSlot, bSlot := newFlatSelectorDispatchCacheFixture(t)

	got, epoch := e.flatSelectorDispatchSlot(runtime, false)
	if got != aSlot || epoch == 0 {
		t.Fatalf("initial flat selector slot/epoch=%p/%d want %p/nonzero", got, epoch, aSlot)
	}
	initialCache := runtime.flatSelectorCache[0].Load()
	if initialCache == nil || initialCache.slot != aSlot {
		t.Fatalf("initial flat selector cache=%+v", initialCache)
	}
	mismatch := false
	allocations := testing.AllocsPerRun(1000, func() {
		cached, cachedEpoch := e.flatSelectorDispatchSlot(runtime, false)
		if cached != aSlot || cachedEpoch != epoch {
			mismatch = true
		}
	})
	if mismatch {
		t.Fatal("flat selector cache hit changed its physical authority")
	}
	if allocations != 0 {
		t.Fatalf("flat selector cache hit allocations/run=%.2f want 0", allocations)
	}
	if runtime.flatSelectorCache[0].Load() != initialCache {
		t.Fatal("stable flat selector route rebuilt its cache")
	}
	healthEpoch := e.healthEvidenceEpoch.Load()
	eligible := map[proto.TargetID]bool{ids["a"]: true, ids["b"]: true}
	present := map[proto.TargetID]bool{ids["a"]: true, ids["b"]: true}
	latest := map[proto.TargetID]*pathSlot{ids["a"]: aSlot, ids["b"]: bSlot}
	if batch := runtime.resolveFlatSelectorDispatchSlot(
		eligible, present, latest, epoch, healthEpoch, true,
	); batch != aSlot {
		t.Fatalf("initial batch cache slot=%p want %p", batch, aSlot)
	}
	if batchCache := runtime.flatSelectorCache[1].Load(); batchCache == nil || batchCache.slot != aSlot {
		t.Fatalf("initial batch cache=%+v", batchCache)
	}

	identity := pathDispatchIdentity{
		generation:     aSlot.nextDispatchGeneration(),
		pathGeneration: pathProbeGenerationForSlot(aSlot),
	}
	aSlot.markDispatchStalled(identity)
	if stalled, _ := e.flatSelectorDispatchSlot(runtime, false); stalled != nil {
		t.Fatalf("factual writer stall reused cached slot %p", stalled)
	}
	aSlot.completeDispatch(identity)
	if recovered, _ := e.flatSelectorDispatchSlot(runtime, false); recovered != aSlot {
		t.Fatalf("cleared writer stall slot=%p want %p", recovered, aSlot)
	}

	if err := runtime.selectChild(ids["root"], ids["b"]); err != nil {
		t.Fatal(err)
	}
	if runtime.flatSelectorCache[0].Load() != nil || runtime.flatSelectorCache[1].Load() != nil {
		t.Fatal("selector mutation did not clear both flat route cache variants")
	}
	if selected, _ := e.flatSelectorDispatchSlot(runtime, false); selected != bSlot {
		t.Fatalf("post-selector-mutation slot=%p want %p", selected, bSlot)
	}
	selectedCache := runtime.flatSelectorCache[0].Load()

	newHealthEpoch := e.healthEvidenceEpoch.Add(1)
	if cached, ok := runtime.cachedFlatSelectorDispatchSlot(epoch, newHealthEpoch, false); ok || cached != nil {
		t.Fatalf("health-epoch change reused cached slot %p", cached)
	}
	if selected, selectedEpoch := e.flatSelectorDispatchSlot(runtime, false); selected != bSlot || selectedEpoch != epoch {
		t.Fatalf("post-health-change slot/epoch=%p/%d want %p/%d", selected, selectedEpoch, bSlot, epoch)
	}
	healthCache := runtime.flatSelectorCache[0].Load()
	if healthCache == nil || healthCache == selectedCache || healthCache.healthEpoch != newHealthEpoch {
		t.Fatalf("health epoch did not rebuild the flat route cache: %+v", healthCache)
	}

	e.pathsMu.Lock()
	newEpoch := e.advancePathTopologyEpochLocked()
	e.pathsMu.Unlock()
	selected, selectedEpoch := e.flatSelectorDispatchSlot(runtime, false)
	if selected != bSlot || selectedEpoch != newEpoch {
		t.Fatalf("post-topology slot/epoch=%p/%d want %p/%d", selected, selectedEpoch, bSlot, newEpoch)
	}
	if refreshed := runtime.flatSelectorCache[0].Load(); refreshed == nil || refreshed == healthCache {
		t.Fatal("topology epoch did not rebuild the flat route cache")
	}
}

func newFlatSelectorDispatchCacheFixture(
	t *testing.T,
) (*Engine, *executionRuntime, map[string]proto.TargetID, *pathSlot, *pathSlot) {
	t.Helper()
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{})
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	a, aPeer := newMemoryPathPair()
	b, bPeer := newMemoryPathPair()
	aSlot := &pathSlot{
		id: 1, gen: 1, owner: 1, conn: a, localTXTargetID: ids["a"],
		healthEvidenceRevision: 1, healthEvidenceEpochSrc: &e.healthEvidenceEpoch,
		healthEvidenceCommitMu: &e.healthEvidenceCommitMu,
	}
	bSlot := &pathSlot{
		id: 2, gen: 1, owner: 2, conn: b, localTXTargetID: ids["b"],
		healthEvidenceRevision: 1, healthEvidenceEpochSrc: &e.healthEvidenceEpoch,
		healthEvidenceCommitMu: &e.healthEvidenceCommitMu,
	}
	aSlot.probeEndpointGen.Store(1)
	bSlot.probeEndpointGen.Store(1)
	e.pathsMu.Lock()
	e.paths[aSlot.id] = aSlot
	e.paths[bSlot.id] = bSlot
	e.advancePathTopologyEpochLocked()
	e.pathsMu.Unlock()
	runtime := e.localExecutionRuntime()
	if err := runtime.selectChild(ids["root"], ids["a"]); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		e.pathsMu.Lock()
		delete(e.paths, aSlot.id)
		delete(e.paths, bSlot.id)
		e.pathsMu.Unlock()
		_ = a.Close()
		_ = aPeer.Close()
		_ = b.Close()
		_ = bPeer.Close()
		_ = e.Close()
	})
	return e, runtime, ids, aSlot, bSlot
}

func TestApplicationDispatchWaiterCompletionAndAbandonmentAreSingleOwner(t *testing.T) {
	for iteration := 0; iteration < 1000; iteration++ {
		waiter := acquireApplicationDispatchWaiter()
		start := make(chan struct{})
		completed := make(chan struct{})
		go func() {
			<-start
			completeApplicationDispatchWaiter(waiter, pathDispatchResult{})
			close(completed)
		}()
		close(start)
		abandonApplicationDispatchWaiter(waiter)
		<-completed
	}

	waiter := acquireApplicationDispatchWaiter()
	completeApplicationDispatchWaiter(waiter, pathDispatchResult{})
	<-waiter.done
	releaseApplicationDispatchWaiter(waiter)
}

func TestDispatchStallGenerationClearsForEitherCompletionOrder(t *testing.T) {
	for iteration := 0; iteration < 1000; iteration++ {
		slot := &pathSlot{}
		identity := pathDispatchIdentity{generation: 1, pathGeneration: pathProbeGenerationForSlot(slot)}
		start := make(chan struct{})
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			slot.markDispatchStalled(identity)
		}()
		go func() {
			defer wait.Done()
			<-start
			slot.completeDispatch(identity)
		}()
		close(start)
		wait.Wait()
		if slot.dispatchStalled.Load() {
			t.Fatalf("iteration %d retained completed stalled generation", iteration)
		}
	}
}

func TestCutoverHandoffStallDoesNotMutateHealthEvidence(t *testing.T) {
	e := &Engine{}
	e.healthEvidenceEpoch.Store(1)
	slot := &pathSlot{
		healthEvidenceRevision: 1,
		healthEvidenceEpochSrc: &e.healthEvidenceEpoch,
		healthEvidenceCommitMu: &e.healthEvidenceCommitMu,
	}
	identity := pathDispatchIdentity{
		generation: 1, pathGeneration: pathProbeGenerationForSlot(slot),
	}

	slot.markDispatchCutoverHandoff(identity)
	if !slot.dispatchStalled.Load() || !slot.cutoverDispatchStalled() {
		t.Fatal("cutover handoff did not fence the in-flight dispatch")
	}
	if revision, _, factual := slot.healthEvidenceSnapshot(); revision != 1 || factual {
		t.Fatalf("cutover handoff became health evidence: revision=%d factual=%t", revision, factual)
	}
	if epoch := e.healthEvidenceEpoch.Load(); epoch != 1 {
		t.Fatalf("cutover handoff advanced health epoch to %d", epoch)
	}

	slot.completeDispatch(identity)
	if slot.dispatchStalled.Load() || slot.cutoverDispatchStalled() {
		t.Fatal("cutover handoff fence survived matching completion")
	}
	if revision, _, factual := slot.healthEvidenceSnapshot(); revision != 1 || factual {
		t.Fatalf("cutover completion mutated health evidence: revision=%d factual=%t", revision, factual)
	}
	if epoch := e.healthEvidenceEpoch.Load(); epoch != 1 {
		t.Fatalf("cutover completion advanced health epoch to %d", epoch)
	}
}

func TestFactualStallUpgradesCutoverHandoffEvidence(t *testing.T) {
	e := &Engine{}
	e.healthEvidenceEpoch.Store(1)
	slot := &pathSlot{
		healthEvidenceRevision: 1,
		healthEvidenceEpochSrc: &e.healthEvidenceEpoch,
		healthEvidenceCommitMu: &e.healthEvidenceCommitMu,
	}
	identity := pathDispatchIdentity{
		generation: 1, pathGeneration: pathProbeGenerationForSlot(slot),
	}

	slot.markDispatchCutoverHandoff(identity)
	slot.markDispatchStalled(identity)
	if slot.cutoverDispatchStalled() {
		t.Fatal("factual stall remained classified as cutover-only")
	}
	if got, factual := slot.currentDispatchStall(); !factual || got != identity {
		t.Fatalf("factual upgrade=%+v present=%t want %+v", got, factual, identity)
	}
	if revision := slot.healthEvidenceRevision; revision != 2 {
		t.Fatalf("factual upgrade revision=%d want 2", revision)
	}
	if epoch := e.healthEvidenceEpoch.Load(); epoch != 2 {
		t.Fatalf("factual upgrade epoch=%d want 2", epoch)
	}

	slot.completeDispatch(identity)
	if revision := slot.healthEvidenceRevision; revision != 3 {
		t.Fatalf("factual completion revision=%d want 3", revision)
	}
	if epoch := e.healthEvidenceEpoch.Load(); epoch != 3 {
		t.Fatalf("factual completion epoch=%d want 3", epoch)
	}
}

func TestOlderDispatchCompletionCannotClearNewerStall(t *testing.T) {
	slot := &pathSlot{}
	pathGeneration := pathProbeGenerationForSlot(slot)
	older := pathDispatchIdentity{generation: 1, pathGeneration: pathGeneration}
	newer := pathDispatchIdentity{generation: 2, pathGeneration: pathGeneration}
	slot.completeDispatch(older)
	slot.markDispatchStalled(newer)
	slot.completeDispatch(older)
	if got, ok := slot.currentDispatchStall(); !ok || got != newer {
		t.Fatal("older completion cleared newer stalled generation")
	}
	slot.completeDispatch(newer)
	if slot.dispatchStalled.Load() {
		t.Fatal("matching completion did not clear stalled generation")
	}
}

func TestOlderLateDispatchMarkCannotOverwriteNewerStall(t *testing.T) {
	slot := &pathSlot{}
	predecessor := pathProbeGenerationForSlot(slot)
	older := pathDispatchIdentity{generation: 1, pathGeneration: predecessor}
	slot.peerMobilityEpoch.Add(1)
	newer := pathDispatchIdentity{generation: 2, pathGeneration: pathProbeGenerationForSlot(slot)}

	slot.markDispatchStalled(newer)
	slot.markDispatchStalled(older)
	if got, ok := slot.currentDispatchStall(); !ok || got != newer {
		t.Fatalf("late older mark replaced newer stall: got=%+v present=%t want=%+v", got, ok, newer)
	}

	slot.completeDispatch(older)
	if got, ok := slot.currentDispatchStall(); !ok || got != newer {
		t.Fatalf("older completion changed newer stall: got=%+v present=%t want=%+v", got, ok, newer)
	}
}

func TestConcurrentDispatchMarksPublishNewestGeneration(t *testing.T) {
	for iteration := 0; iteration < 1000; iteration++ {
		slot := &pathSlot{}
		predecessor := pathProbeGenerationForSlot(slot)
		older := pathDispatchIdentity{generation: 1, pathGeneration: predecessor}
		slot.peerMobilityEpoch.Add(1)
		newer := pathDispatchIdentity{generation: 2, pathGeneration: pathProbeGenerationForSlot(slot)}

		start := make(chan struct{})
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			slot.markDispatchStalled(older)
		}()
		go func() {
			defer wait.Done()
			<-start
			slot.markDispatchStalled(newer)
		}()
		close(start)
		wait.Wait()

		if got, ok := slot.currentDispatchStall(); !ok || got != newer {
			t.Fatalf("iteration %d newest stall got=%+v present=%t want=%+v", iteration, got, ok, newer)
		}
	}
}

func TestDispatchCompletionFrontierCannotRegress(t *testing.T) {
	slot := &pathSlot{}
	pathGeneration := pathProbeGenerationForSlot(slot)
	first := pathDispatchIdentity{generation: 1, pathGeneration: pathGeneration}
	second := pathDispatchIdentity{generation: 2, pathGeneration: pathGeneration}
	slot.completeDispatch(second)
	slot.completeDispatch(first)
	if got := slot.dispatchDoneGen.Load(); got != 2 {
		t.Fatalf("completion frontier=%d want 2", got)
	}
	slot.markDispatchStalled(second)
	if slot.dispatchStalled.Load() {
		t.Fatal("already-completed generation remained stalled after out-of-order completion")
	}
}

func TestDispatchGenerationWrapPanics(t *testing.T) {
	slot := &pathSlot{}
	slot.dispatchNextGen.Store(^uint64(0))
	for attempt := 0; attempt < 2; attempt++ {
		func() {
			defer func() {
				if recovered := recover(); recovered == nil {
					t.Fatalf("dispatch generation exhaustion attempt %d did not panic", attempt)
				}
			}()
			_ = slot.nextDispatchGeneration()
		}()
	}
	if got := slot.dispatchNextGen.Load(); got != ^uint64(0) {
		t.Fatalf("exhausted dispatch generation wrapped to %d", got)
	}
}
