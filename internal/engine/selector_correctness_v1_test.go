package engine

import (
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

func TestInactiveNestedSelectorDoesNotAccrueQualityDwell(t *testing.T) {
	now := time.Unix(1_800, 0)
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "inner"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindSelector, "inner", "b", "c"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
		runtimeNode(proto.GraphNodeKindPath, "c"),
	)
	runtime := mustExecutionRuntime(t, manifest)
	attached := runtimeAttached(ids, "a", "b", "c")
	if err := runtime.commitSelectorChildOrigin(
		ids["root"], ids["a"], attached, policySelectionExternal, nil,
	); err != nil {
		t.Fatal(err)
	}
	if err := runtime.commitSelectorChildOrigin(
		ids["inner"], ids["b"], attached, policySelectionExternal, nil,
	); err != nil {
		t.Fatal(err)
	}
	observations := map[proto.TargetID]pathEvidenceObservation{
		ids["a"]: selectorObservation(ids["a"], now, time.Millisecond, 0, 1),
		ids["b"]: selectorObservation(ids["b"], now, 20*time.Millisecond, 0, 1),
		ids["c"]: selectorObservation(ids["c"], now, 2*time.Millisecond, 0, 1),
	}
	policy := selectorEvidencePolicy{
		latencyBandRatio: 0.25, latencyBandFloor: time.Millisecond, minimumConfidence: 1,
	}

	if decisions := runtime.selectorDecisions(
		proto.SenderDirectionClientToServer, observations, now, policy, 0, 0,
	); len(decisions) != 0 {
		t.Fatalf("candidate observation produced immediate decisions: %+v", decisions)
	}
	if decisions := runtime.selectorDecisions(
		proto.SenderDirectionClientToServer, observations, now.Add(time.Millisecond), policy, 0, 0,
	); len(decisions) != 0 {
		t.Fatalf("inactive nested quality produced an applicable decision: %+v", decisions)
	}

	runtime.mu.Lock()
	state := *runtime.selectors[ids["inner"]]
	runtime.mu.Unlock()
	if state.qualityCandidate != (proto.TargetID{}) || state.desired != ids["b"] || state.effective != ids["b"] {
		t.Fatalf("inactive nested state=%+v, want no candidate with b still selected", state)
	}
}

func TestInactiveSelectorActivationStartsCoherentDwell(t *testing.T) {
	base := time.Unix(1_850, 0)
	const dwell = 10 * time.Millisecond
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "inner"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindSelector, "inner", "b", "c"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
		runtimeNode(proto.GraphNodeKindPath, "c"),
	)
	exec := mustExecutionRuntime(t, manifest)
	attached := runtimeAttached(ids, "a", "b", "c")
	if err := exec.commitSelectorChildOrigin(ids["root"], ids["a"], attached, policySelectionExternal, nil); err != nil {
		t.Fatal(err)
	}
	if err := exec.commitSelectorChildOrigin(ids["inner"], ids["b"], attached, policySelectionExternal, nil); err != nil {
		t.Fatal(err)
	}
	observations := map[proto.TargetID]pathEvidenceObservation{
		ids["a"]: selectorObservation(ids["a"], base, time.Millisecond, 0, 1),
		ids["b"]: selectorObservation(ids["b"], base, 20*time.Millisecond, 0, 1),
		ids["c"]: selectorObservation(ids["c"], base, 2*time.Millisecond, 0, 1),
	}
	policy := selectorEvidencePolicy{
		latencyBandRatio: 0.25, latencyBandFloor: time.Millisecond, minimumConfidence: 1,
	}

	if decisions := exec.selectorDecisionFor(
		ids["inner"], proto.SenderDirectionClientToServer, observations, attached,
		base, policy, dwell, 0,
	); len(decisions) != 0 {
		t.Fatalf("inactive selector produced decisions: %+v", decisions)
	}
	if err := exec.commitSelectorChildOrigin(ids["root"], ids["inner"], attached, policySelectionExternal, nil); err != nil {
		t.Fatal(err)
	}
	assertSelectorAggregateLatency(t, exec, ids["inner"], observations, base, 20*time.Millisecond)

	activatedAt := base.Add(time.Second)
	if decisions := exec.selectorDecisionFor(
		ids["inner"], proto.SenderDirectionClientToServer, observations, attached,
		activatedAt, policy, dwell, 0,
	); len(decisions) != 0 {
		t.Fatalf("activation immediately consumed inactive dwell: %+v", decisions)
	}
	if decisions := exec.selectorDecisionFor(
		ids["inner"], proto.SenderDirectionClientToServer, observations, attached,
		activatedAt.Add(dwell-time.Nanosecond), policy, dwell, 0,
	); len(decisions) != 0 {
		t.Fatalf("selector moved before active dwell elapsed: %+v", decisions)
	}
	decisions := exec.selectorDecisionFor(
		ids["inner"], proto.SenderDirectionClientToServer, observations, attached,
		activatedAt.Add(dwell), policy, dwell, 0,
	)
	if len(decisions) != 1 || decisions[0].targetID != ids["c"] {
		t.Fatalf("active dwell decisions=%+v, want one inner->c", decisions)
	}
	if err := exec.commitSelectorChildOriginAtState(
		ids["inner"], ids["c"], attached, decisions[0].origin, decisions[0].selectorState, nil,
	); err != nil {
		t.Fatal(err)
	}
	exec.noteSelectorDecision(decisions[0], activatedAt.Add(dwell))
	assertSelectorAggregateLatency(t, exec, ids["inner"], observations, activatedAt.Add(dwell), 2*time.Millisecond)
	if again := exec.selectorDecisionFor(
		ids["inner"], proto.SenderDirectionClientToServer, observations, attached,
		activatedAt.Add(2*dwell), policy, dwell, 0,
	); len(again) != 0 {
		t.Fatalf("committed selector emitted a second cutover: %+v", again)
	}
}

func TestSameTickParentDecisionInvalidatesChildBeforeCutover(t *testing.T) {
	inner := policyTxUnitNode(proto.GraphNodeKindSelector, "same-tick-inner")
	b := policyTxUnitNode(proto.GraphNodeKindPath, "same-tick-b")
	c := policyTxUnitNode(proto.GraphNodeKindPath, "same-tick-c")
	inner.Children = []proto.TargetID{b.ID, c.ID}
	a := policyTxUnitNode(proto.GraphNodeKindPath, "same-tick-a")
	root := policyTxUnitNode(proto.GraphNodeKindSelector, "same-tick-root", inner.ID, a.ID)
	manifest := proto.GraphManifest{RootID: root.ID, Nodes: []proto.GraphNode{root, inner, a, b, c}}
	e, _, paths, _ := newPolicyTxUnitEngineWithOptions(
		t, Limits{ProbeInterval: time.Hour}.Clamp(), true, manifest, root.ID,
		b.Name, c.Name, a.Name,
	)
	exec := e.localExecutionRuntime()
	base := time.Now()
	observations := map[proto.TargetID]pathEvidenceObservation{
		a.ID: selectorObservation(a.ID, base, time.Millisecond, 0, 1),
		b.ID: selectorObservation(b.ID, base, 20*time.Millisecond, 0, 1),
		c.ID: selectorObservation(c.ID, base, 2*time.Millisecond, 0, 1),
	}
	policy := selectorEvidencePolicy{
		latencyBandRatio: 0.25, latencyBandFloor: time.Millisecond, minimumConfidence: 1,
	}
	_ = exec.selectorDecisions(proto.SenderDirectionServerToClient, observations, base, policy, 0, 0)
	decisions := exec.selectorDecisions(
		proto.SenderDirectionServerToClient, observations, base.Add(time.Nanosecond), policy, 0, 0,
	)
	if len(decisions) != 2 || decisions[0].selectorID != root.ID || decisions[1].selectorID != inner.ID {
		t.Fatalf("same-tick decisions=%+v, want parent then child", decisions)
	}
	view, ok := e.selectorEvidenceSnapshot()
	if !ok {
		t.Fatal("same-tick commit evidence unavailable")
	}
	for i := range decisions {
		decisions[i].topologyEpoch = view.topologyEpoch
		decisions[i].evidence = view.commitEvidenceForSelector(
			exec.plan, decisions[i].selectorID, decisions[i].selectorState,
		)
	}
	e.selectorCutoverMu.Lock()
	before := e.selectorCutoverGeneration
	e.selectorCutoverMu.Unlock()
	(&selector{}).applyRecursiveDecisions(e, exec, decisions, view.capturedAt)
	e.selectorCutoverMu.Lock()
	after, pending := e.selectorCutoverGeneration, e.selectorCutoverPending
	e.selectorCutoverMu.Unlock()
	if after != before+1 || pending {
		t.Fatalf("cutover generation/pending=%d/%t want %d/false", after, pending, before+1)
	}
	rootDesired, rootEffective, _, _ := exec.selectorSelection(root.ID)
	innerDesired, innerEffective, _, _ := exec.selectorSelection(inner.ID)
	if rootDesired != a.ID || rootEffective != a.ID || innerDesired != b.ID || innerEffective != b.ID {
		t.Fatalf(
			"selection root=%x/%x inner=%x/%x, want a/a and unchanged b/b",
			rootDesired, rootEffective, innerDesired, innerEffective,
		)
	}
	if e.ActivePath() != paths[a.Name] || e.MigrationCount() != 1 {
		t.Fatalf("active/count=%d/%d want a=%d/count=1", e.ActivePath(), e.MigrationCount(), paths[a.Name])
	}
}

func TestUnrelatedHealthUpdatesCannotStarveSelectorCommit(t *testing.T) {
	a := policyTxUnitNode(proto.GraphNodeKindPath, "dependency-a")
	b := policyTxUnitNode(proto.GraphNodeKindPath, "dependency-b")
	selected := policyTxUnitNode(proto.GraphNodeKindSelector, "dependency-selector", a.ID, b.ID)
	unrelated := policyTxUnitNode(proto.GraphNodeKindPath, "dependency-unrelated")
	root := policyTxUnitNode(proto.GraphNodeKindBond, "dependency-root", selected.ID, unrelated.ID)
	manifest := proto.GraphManifest{RootID: root.ID, Nodes: []proto.GraphNode{root, selected, a, b, unrelated}}
	e, _, _, handles := newPolicyTxUnitEngineWithOptions(
		t, Limits{ProbeInterval: time.Hour}.Clamp(), true, manifest, selected.ID,
		a.Name, b.Name, unrelated.Name,
	)
	now := time.Now()
	setSelectorRankingQuality(handles, a.Name, 20*time.Millisecond, now)
	setSelectorRankingQuality(handles, b.Name, 2*time.Millisecond, now)
	unrelatedSlot := selectorPathSlots(t, e, unrelated.ID)[0]
	stop := make(chan struct{})
	done := make(chan struct{})
	started := make(chan struct{})
	var once sync.Once
	e.peakTransferDecisionBeforeCommit = func() {
		go func() {
			defer close(done)
			for {
				unrelatedSlot.advanceHealthEvidenceRevision()
				once.Do(func() { close(started) })
				select {
				case <-stop:
					return
				default:
					runtime.Gosched()
				}
			}
		}()
		<-started
	}
	start := time.Now()
	target, err := e.SelectBestLocalPeakTransferNormalTarget(selected.ID, "dependency-scoped")
	close(stop)
	<-done
	e.peakTransferDecisionBeforeCommit = nil
	if err != nil || target != b.ID {
		t.Fatalf("selection=(%x,%v), want b under unrelated updates", target, err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("dependency-scoped selector commit took %v", elapsed)
	}
}

func TestRelevantHealthUpdateRejectsBeforeSelectorCutover(t *testing.T) {
	e, selectorNode, normalA, normalB, _, _, paths, handles := selectorRankingInversionFixture(t, "relevant-stale")
	now := time.Now()
	setSelectorRankingQuality(handles, normalA.Name, 20*time.Millisecond, now)
	setSelectorRankingQuality(handles, normalB.Name, 2*time.Millisecond, now)
	relevant := selectorPathSlots(t, e, normalA.ID)[0]
	e.peakTransferDecisionBeforeCommit = func() { relevant.advanceHealthEvidenceRevision() }
	e.selectorCutoverMu.Lock()
	before := e.selectorCutoverGeneration
	e.selectorCutoverMu.Unlock()
	target, err := e.SelectBestLocalPeakTransferNormalTarget(selectorNode.ID, "relevant-stale")
	e.selectorCutoverMu.Lock()
	after, pending := e.selectorCutoverGeneration, e.selectorCutoverPending
	e.selectorCutoverMu.Unlock()
	if target != (proto.TargetID{}) || !errors.Is(err, ErrSelectorDecisionUnavailable) {
		t.Fatalf("selection=(%x,%v), want stale decision", target, err)
	}
	if after != before || pending || e.ActivePath() != paths[normalA.Name] {
		t.Fatalf(
			"stale decision cutover/pending/active=%d/%t/%d want %d/false/%d",
			after, pending, e.ActivePath(), before, paths[normalA.Name],
		)
	}
}

func TestQualityDecisionWaitsOutsidePathAndHealthLocks(t *testing.T) {
	e, selectorNode, normalA, normalB, _, _, paths, handles := selectorRankingInversionFixture(
		t, "cutover-reservation",
	)
	now := time.Now()
	setSelectorRankingQuality(handles, normalA.Name, 20*time.Millisecond, now)
	setSelectorRankingQuality(handles, normalB.Name, 2*time.Millisecond, now)
	relevant := selectorPathSlots(t, e, normalA.ID)[0]

	first := e.beginSelectorCutover()
	firstPending := true
	t.Cleanup(func() {
		e.selectorCutoverBeforeWait = nil
		if firstPending {
			e.finishSelectorCutover(first)
		}
	})
	waiting := make(chan struct{})
	var waitingOnce sync.Once
	e.selectorCutoverBeforeWait = func(generation uint64) {
		if generation == first {
			waitingOnce.Do(func() { close(waiting) })
		}
	}
	type selectionResult struct {
		target proto.TargetID
		err    error
	}
	result := make(chan selectionResult, 1)
	go func() {
		target, err := e.SelectBestLocalPeakTransferNormalTarget(
			selectorNode.ID, "cutover-reservation",
		)
		result <- selectionResult{target: target, err: err}
	}()
	select {
	case <-waiting:
	case <-time.After(time.Second):
		t.Fatal("quality decision did not wait for the occupied cutover")
	}

	assertLockAvailable := func(name string, lock, unlock func()) {
		t.Helper()
		acquired := make(chan struct{})
		go func() {
			lock()
			close(acquired)
			unlock()
		}()
		select {
		case <-acquired:
		case <-time.After(time.Second):
			// Release the owner before failing so a broken implementation does
			// not strand the package test process behind the demonstrated cycle.
			e.finishSelectorCutover(first)
			firstPending = false
			select {
			case <-result:
			case <-time.After(time.Second):
			}
			t.Fatalf("waiting quality decision pinned %s", name)
		}
	}
	assertLockAvailable("pathsMu", e.pathsMu.Lock, e.pathsMu.Unlock)
	assertLockAvailable(
		"healthEvidenceCommitMu",
		e.healthEvidenceCommitMu.Lock,
		e.healthEvidenceCommitMu.Unlock,
	)

	// A relevant mutation while the quality decision waits must invalidate its
	// old evidence. On wake it revalidates before reserving another generation.
	relevant.advanceHealthEvidenceRevision()
	e.finishSelectorCutover(first)
	firstPending = false
	select {
	case got := <-result:
		if got.target != (proto.TargetID{}) || !errors.Is(got.err, ErrSelectorDecisionUnavailable) {
			t.Fatalf("selection after wake=(%x,%v), want stale decision", got.target, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("quality decision remained blocked after the first cutover completed")
	}
	e.selectorCutoverMu.Lock()
	generation, pending := e.selectorCutoverGeneration, e.selectorCutoverPending
	e.selectorCutoverMu.Unlock()
	if generation != first || pending {
		t.Fatalf("cutover generation/pending=%d/%t want %d/false", generation, pending, first)
	}
	if e.ActivePath() != paths[normalA.Name] || e.MigrationCount() != 0 {
		t.Fatalf(
			"stale retry changed active/count=%d/%d want %d/0",
			e.ActivePath(), e.MigrationCount(), paths[normalA.Name],
		)
	}
}

func assertSelectorAggregateLatency(
	t *testing.T,
	exec *executionRuntime,
	targetID proto.TargetID,
	observations map[proto.TargetID]pathEvidenceObservation,
	now time.Time,
	want time.Duration,
) {
	t.Helper()
	exec.mu.Lock()
	evidence := exec.aggregateTargetEvidenceLocked(
		targetID, proto.SenderDirectionClientToServer, observations,
		make(map[proto.TargetID]schedulingEvidence), now,
	)
	exec.mu.Unlock()
	if evidence.latency.latest != want {
		t.Fatalf("selector aggregate latency=%v want %v", evidence.latency.latest, want)
	}
}

func TestPathStabilityDoesNotFabricateProgressFromLiveness(t *testing.T) {
	now := time.Unix(1_900, 0)
	observation := selectorObservation(
		proto.DeriveTargetID(proto.GraphNodeKindPath, "idle"), now, time.Millisecond, 0, 1,
	)
	observation.dataProgress = 0
	evidence := evidenceFromPathObservation(proto.SenderDirectionClientToServer, observation, now)
	if evidence.stability.progress != 0 || evidence.stability.progressKnown {
		t.Fatalf("idle live path stability=%+v, want unknown zero progress", evidence.stability)
	}

	observation.dataProgress = 7
	evidence = evidenceFromPathObservation(proto.SenderDirectionClientToServer, observation, now)
	if evidence.stability.progress != 7 || !evidence.stability.progressKnown {
		t.Fatalf("observed path stability=%+v, want known progress 7", evidence.stability)
	}
}

func TestBestPeakTransferSelectionRejectsRankingInversion(t *testing.T) {
	e, selector, normalA, _, peakA, peakB, paths, handles := selectorRankingInversionFixture(t, "peak-rerank")
	now := time.Now()
	setSelectorRankingQuality(handles, normalA.Name, time.Millisecond, now)
	setSelectorRankingQuality(handles, peakA.Name, 10*time.Millisecond, now)
	setSelectorRankingQuality(handles, peakB.Name, 20*time.Millisecond, now)
	slots := selectorPathSlots(t, e, peakA.ID, peakB.ID)
	e.peakTransferDecisionBeforeCommit = func() {
		changedAt := time.Now()
		setSelectorRankingQuality(handles, peakA.Name, 100*time.Millisecond, changedAt)
		setSelectorRankingQuality(handles, peakB.Name, 2*time.Millisecond, changedAt)
		_ = observePathQualities(slots, selectorQualityObservationBudget)
	}

	selected, err := e.SelectBestLocalPeakTransferTarget(selector.ID, nil, "peak-rerank")
	if selected != (proto.TargetID{}) || !errors.Is(err, ErrSelectorDecisionUnavailable) {
		t.Fatalf("selection=(%x,%v), want zero/%v", selected, err, ErrSelectorDecisionUnavailable)
	}
	if e.ActivePath() != paths[normalA.Name] {
		t.Fatalf("ranking inversion changed active=%d want normal A=%d", e.ActivePath(), paths[normalA.Name])
	}
	e.peakTransferDecisionBeforeCommit = nil
	selected, err = e.SelectBestLocalPeakTransferTarget(selector.ID, nil, "peak-rerank-retry")
	if err != nil || selected != peakB.ID || e.ActivePath() != paths[peakB.Name] {
		t.Fatalf(
			"retry selection=(%x,%v) active=%d, want peak B %x/%d",
			selected, err, e.ActivePath(), peakB.ID, paths[peakB.Name],
		)
	}
}

func TestBestNormalTransferSelectionRejectsRankingInversion(t *testing.T) {
	e, selector, normalA, normalB, _, _, paths, handles := selectorRankingInversionFixture(t, "normal-rerank")
	now := time.Now()
	setSelectorRankingQuality(handles, normalA.Name, 10*time.Millisecond, now)
	setSelectorRankingQuality(handles, normalB.Name, 20*time.Millisecond, now)
	slots := selectorPathSlots(t, e, normalA.ID, normalB.ID)
	e.peakTransferDecisionBeforeCommit = func() {
		changedAt := time.Now()
		setSelectorRankingQuality(handles, normalA.Name, 100*time.Millisecond, changedAt)
		setSelectorRankingQuality(handles, normalB.Name, 2*time.Millisecond, changedAt)
		_ = observePathQualities(slots, selectorQualityObservationBudget)
	}

	selected, err := e.SelectBestLocalPeakTransferNormalTarget(selector.ID, "normal-rerank")
	if selected != (proto.TargetID{}) || !errors.Is(err, ErrSelectorDecisionUnavailable) {
		t.Fatalf("selection=(%x,%v), want zero/%v", selected, err, ErrSelectorDecisionUnavailable)
	}
	if e.ActivePath() != paths[normalA.Name] {
		t.Fatalf("ranking inversion changed active=%d want normal A=%d", e.ActivePath(), paths[normalA.Name])
	}
	e.peakTransferDecisionBeforeCommit = nil
	selected, err = e.SelectBestLocalPeakTransferNormalTarget(selector.ID, "normal-rerank-retry")
	if err != nil || selected != normalB.ID || e.ActivePath() != paths[normalB.Name] {
		t.Fatalf(
			"retry selection=(%x,%v) active=%d, want normal B %x/%d",
			selected, err, e.ActivePath(), normalB.ID, paths[normalB.Name],
		)
	}
}

func TestBestTransferSelectionRejectsQualityChangeAtPublication(t *testing.T) {
	for _, peak := range []bool{false, true} {
		name := "normal"
		if peak {
			name = "peak"
		}
		t.Run(name, func(t *testing.T) {
			e, selector, normalA, normalB, peakA, peakB, paths, handles := selectorRankingInversionFixture(t, "publication-"+name)
			now := time.Now()
			first, second := normalA, normalB
			if peak {
				first, second = peakA, peakB
			}
			setSelectorRankingQuality(handles, normalA.Name, time.Millisecond, now)
			setSelectorRankingQuality(handles, first.Name, 10*time.Millisecond, now)
			setSelectorRankingQuality(handles, second.Name, 20*time.Millisecond, now)

			slots := selectorPathSlots(t, e, first.ID, second.ID)
			var once sync.Once
			e.selectorHealthBeforeCommitGate = func() {
				once.Do(func() {
					changedAt := time.Now()
					setSelectorRankingQuality(handles, first.Name, 100*time.Millisecond, changedAt)
					setSelectorRankingQuality(handles, second.Name, 2*time.Millisecond, changedAt)
					_ = observePathQualities(slots, selectorQualityObservationBudget)
				})
			}
			t.Cleanup(func() { e.selectorHealthBeforeCommitGate = nil })

			var selected proto.TargetID
			var err error
			if peak {
				selected, err = e.SelectBestLocalPeakTransferTarget(selector.ID, nil, "publication-peak")
			} else {
				selected, err = e.SelectBestLocalPeakTransferNormalTarget(selector.ID, "publication-normal")
			}
			if selected != (proto.TargetID{}) || !errors.Is(err, ErrSelectorDecisionUnavailable) {
				t.Fatalf("selection=(%x,%v), want zero/%v", selected, err, ErrSelectorDecisionUnavailable)
			}
			if e.ActivePath() != paths[normalA.Name] {
				t.Fatalf("stale quality changed active path=%d want normal A=%d", e.ActivePath(), paths[normalA.Name])
			}
		})
	}
}

func selectorRankingInversionFixture(
	t *testing.T,
	prefix string,
) (*Engine, proto.GraphNode, proto.GraphNode, proto.GraphNode, proto.GraphNode, proto.GraphNode, map[string]uint32, map[string]*policyTxUnitPath) {
	t.Helper()
	normalA := policyTxUnitNode(proto.GraphNodeKindPath, prefix+"-normal-a")
	normalB := policyTxUnitNode(proto.GraphNodeKindPath, prefix+"-normal-b")
	peakA := policyTxUnitNode(proto.GraphNodeKindPath, prefix+"-peak-a")
	peakB := policyTxUnitNode(proto.GraphNodeKindPath, prefix+"-peak-b")
	selector := policyTxUnitNode(
		proto.GraphNodeKindSelector, prefix+"-selector", normalA.ID, normalB.ID, peakA.ID, peakB.ID,
	)
	selector.PeakCandidates = []proto.TargetID{peakA.ID, peakB.ID}
	manifest := proto.GraphManifest{
		RootID: selector.ID,
		Nodes:  []proto.GraphNode{selector, normalA, normalB, peakA, peakB},
	}
	e, _, paths, handles := newPolicyTxUnitEngineWithOptions(
		t, Limits{ProbeInterval: time.Hour}.Clamp(), true, manifest, selector.ID,
		normalA.Name, normalB.Name, peakA.Name, peakB.Name,
	)
	return e, selector, normalA, normalB, peakA, peakB, paths, handles
}

func setSelectorRankingQuality(
	handles map[string]*policyTxUnitPath,
	name string,
	rtt time.Duration,
	at time.Time,
) {
	handles[name].SetQuality(transport.PathQuality{RTT: rtt, LossPP: 1, At: at})
}

func selectorPathSlots(t *testing.T, e *Engine, targetIDs ...proto.TargetID) []*pathSlot {
	t.Helper()
	wanted := make(map[proto.TargetID]bool, len(targetIDs))
	for _, targetID := range targetIDs {
		wanted[targetID] = true
	}
	e.pathsMu.RLock()
	slots := make([]*pathSlot, 0, len(targetIDs))
	for _, slot := range e.paths {
		if wanted[slot.localTXTargetID] {
			slots = append(slots, slot)
		}
	}
	e.pathsMu.RUnlock()
	if len(slots) != len(targetIDs) {
		t.Fatalf("selector slots=%d want %d", len(slots), len(targetIDs))
	}
	return slots
}
