package engine

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type selectorReentrantQualityPath struct {
	*memoryPathConn
	onQuality func()
}

func (p *selectorReentrantQualityPath) Quality() transport.PathQuality {
	if p.onQuality != nil {
		p.onQuality()
	}
	return p.memoryPathConn.Quality()
}

func TestRecursiveSelectorDecisionPriorityMatrix(t *testing.T) {
	now := time.Unix(100, 0)
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	tests := []struct {
		name string
		a    pathEvidenceObservation
		b    pathEvidenceObservation
		want proto.TargetID
	}{
		{
			name: "latency excludes stability and speed outside band",
			a:    selectorObservation(ids["a"], now, 100*time.Millisecond, 0, 100),
			b:    selectorObservation(ids["b"], now, 10*time.Millisecond, 50, 1),
			want: ids["b"],
		},
		{
			name: "stability wins inside latency band",
			a:    selectorObservation(ids["a"], now, 10*time.Millisecond, 50, 100),
			b:    selectorObservation(ids["b"], now, 11*time.Millisecond, 0, 1),
			want: ids["b"],
		},
		{
			name: "speed breaks latency and stability tie",
			a:    selectorObservation(ids["a"], now, 10*time.Millisecond, 0, 1),
			b:    selectorObservation(ids["b"], now, 11*time.Millisecond, 0, 10),
			want: ids["b"],
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime := mustExecutionRuntime(t, manifest)
			if err := runtime.selectChild(ids["root"], ids["a"]); err != nil {
				t.Fatal(err)
			}
			observations := map[proto.TargetID]pathEvidenceObservation{ids["a"]: test.a, ids["b"]: test.b}
			policy := selectorEvidencePolicy{latencyBandRatio: 0.25, latencyBandFloor: time.Millisecond, minimumConfidence: 1}
			_ = runtime.selectorDecisions(proto.SenderDirectionClientToServer, observations, now, policy, 0, 0)
			decisions := runtime.selectorDecisions(proto.SenderDirectionClientToServer, observations, now, policy, 0, 0)
			if len(decisions) != 1 || decisions[0].selectorID != ids["root"] || decisions[0].targetID != test.want {
				t.Fatalf("decisions=%+v want root->%x", decisions, test.want)
			}
		})
	}
}

func TestSelectorGoodputCandidateSurvivesDefaultDwellTickJitter(t *testing.T) {
	base := time.Unix(150, 0)
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	runtime := mustExecutionRuntime(t, manifest)
	if err := runtime.selectChild(ids["root"], ids["a"]); err != nil {
		t.Fatal(err)
	}
	observations := map[proto.TargetID]pathEvidenceObservation{
		ids["a"]: selectorObservation(ids["a"], base, 10*time.Millisecond, 0, 1),
		ids["b"]: selectorObservation(ids["b"], base, 11*time.Millisecond, 0, 10),
	}
	policy := selectorEvidencePolicy{latencyBandRatio: 0.25, latencyBandFloor: time.Millisecond, minimumConfidence: 1}
	dwell := DefaultLimits().SelectorDwell
	if decisions := runtime.selectorDecisions(
		proto.SenderDirectionClientToServer, observations, base, policy, dwell, 0,
	); len(decisions) != 0 {
		t.Fatalf("candidate-start decisions=%+v", decisions)
	}
	for targetID, observation := range observations {
		observation.goodput.state = qualityStateStale
		observation.quality.At = base.Add(dwell + 200*time.Millisecond)
		observations[targetID] = observation
	}
	decisions := runtime.selectorDecisions(
		proto.SenderDirectionClientToServer, observations, base.Add(dwell+200*time.Millisecond), policy, dwell, 0,
	)
	if len(decisions) != 1 || decisions[0].targetID != ids["b"] || decisions[0].origin != policySelectionQuality {
		t.Fatalf("default-dwell decision=%+v, want b after bounded held speed evidence", decisions)
	}
}

func TestSelectorGoodputHoldCannotStartStaleOrOutliveBound(t *testing.T) {
	base := time.Unix(175, 0)
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	policy := selectorEvidencePolicy{latencyBandRatio: 0.25, latencyBandFloor: time.Millisecond, minimumConfidence: 1}
	dwell := DefaultLimits().SelectorDwell
	newRuntime := func(t *testing.T) *executionRuntime {
		t.Helper()
		runtime := mustExecutionRuntime(t, manifest)
		if err := runtime.selectChild(ids["root"], ids["a"]); err != nil {
			t.Fatal(err)
		}
		return runtime
	}
	observations := map[proto.TargetID]pathEvidenceObservation{
		ids["a"]: selectorObservation(ids["a"], base, 10*time.Millisecond, 0, 1),
		ids["b"]: selectorObservation(ids["b"], base, 11*time.Millisecond, 0, 10),
	}

	t.Run("stale cannot start", func(t *testing.T) {
		for targetID, observation := range observations {
			observation.goodput.state = qualityStateStale
			observations[targetID] = observation
		}
		runtime := newRuntime(t)
		if decisions := runtime.selectorDecisions(
			proto.SenderDirectionClientToServer, observations, base, policy, dwell, 0,
		); len(decisions) != 0 {
			t.Fatalf("stale evidence started decision=%+v", decisions)
		}
		if state := runtime.selectors[ids["root"]]; state == nil || state.qualityCandidate != (proto.TargetID{}) {
			t.Fatalf("stale evidence retained quality candidate=%+v", state)
		}
	})

	t.Run("hold expires", func(t *testing.T) {
		fresh := map[proto.TargetID]pathEvidenceObservation{
			ids["a"]: selectorObservation(ids["a"], base, 10*time.Millisecond, 0, 1),
			ids["b"]: selectorObservation(ids["b"], base, 11*time.Millisecond, 0, 10),
		}
		runtime := newRuntime(t)
		_ = runtime.selectorDecisions(proto.SenderDirectionClientToServer, fresh, base, policy, dwell, 0)
		for targetID, observation := range fresh {
			observation.goodput.state = qualityStateStale
			observation.quality.At = base.Add(selectorGoodputHoldDuration(dwell) + time.Nanosecond)
			fresh[targetID] = observation
		}
		if decisions := runtime.selectorDecisions(
			proto.SenderDirectionClientToServer, fresh,
			base.Add(selectorGoodputHoldDuration(dwell)+time.Nanosecond), policy, dwell, 0,
		); len(decisions) != 0 {
			t.Fatalf("expired hold produced decision=%+v", decisions)
		}
		if state := runtime.selectors[ids["root"]]; state == nil || state.qualityCandidate != (proto.TargetID{}) {
			t.Fatalf("expired hold retained quality candidate=%+v", state)
		}
	})
}

func TestRecursiveSelectorUnknownAndStaleCannotEvictFreshCurrent(t *testing.T) {
	now := time.Unix(200, 0)
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	for _, test := range []struct {
		name string
		b    pathEvidenceObservation
	}{
		{name: "unknown", b: pathEvidenceObservation{targetID: ids["b"], live: true}},
		{name: "stale", b: selectorObservation(ids["b"], now.Add(-selectorEvidenceFreshFor-time.Second), time.Millisecond, 0, 100)},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := mustExecutionRuntime(t, manifest)
			if err := runtime.selectChild(ids["root"], ids["a"]); err != nil {
				t.Fatal(err)
			}
			observations := map[proto.TargetID]pathEvidenceObservation{
				ids["a"]: selectorObservation(ids["a"], now, 10*time.Millisecond, 0, 1),
				ids["b"]: test.b,
			}
			policy := selectorEvidencePolicy{latencyBandRatio: 0.25, latencyBandFloor: time.Millisecond, minimumConfidence: 1}
			for i := 0; i < 3; i++ {
				if decisions := runtime.selectorDecisions(proto.SenderDirectionClientToServer, observations, now, policy, 0, 0); len(decisions) != 0 {
					t.Fatalf("untrusted challenger produced decision %+v", decisions)
				}
			}
		})
	}
}

func TestPeakSelectionHoldsAcrossQualityDwellButNotPathDeath(t *testing.T) {
	now := time.Unix(225, 0)
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "normal", "peak"),
		runtimeNode(proto.GraphNodeKindPath, "normal"),
		runtimeNode(proto.GraphNodeKindPath, "peak"),
	)
	root, _ := manifest.Node(ids["root"])
	root.PeakCandidates = []proto.TargetID{ids["peak"]}
	for i := range manifest.Nodes {
		if manifest.Nodes[i].ID == root.ID {
			manifest.Nodes[i] = root
		}
	}
	runtime := mustExecutionRuntime(t, manifest)
	if err := runtime.commitSelectorChildOrigin(ids["root"], ids["peak"], map[proto.TargetID]bool{
		ids["normal"]: true,
		ids["peak"]:   true,
	}, policySelectionPeakPromote, nil); err != nil {
		t.Fatal(err)
	}
	policy := selectorEvidencePolicy{latencyBandRatio: 0.05, latencyBandFloor: time.Millisecond, minimumConfidence: 1}
	observations := map[proto.TargetID]pathEvidenceObservation{
		ids["normal"]: selectorObservation(ids["normal"], now, time.Millisecond, 0, 100),
		ids["peak"]:   selectorObservation(ids["peak"], now, 100*time.Millisecond, 0, 1),
	}
	for _, at := range []time.Time{now, now.Add(time.Second), now.Add(10 * time.Second)} {
		if decisions := runtime.selectorDecisions(proto.SenderDirectionClientToServer, observations, at, policy, 100*time.Millisecond, 100*time.Millisecond); len(decisions) != 0 {
			t.Fatalf("healthy peak was evicted at %s: %+v", at.Sub(now), decisions)
		}
	}
	delete(observations, ids["peak"])
	decisions := runtime.selectorDecisions(proto.SenderDirectionClientToServer, observations, now.Add(11*time.Second), policy, time.Hour, time.Hour)
	if len(decisions) != 1 || decisions[0].targetID != ids["normal"] || decisions[0].origin != policySelectionPathDeath {
		t.Fatalf("dead peak decisions=%+v want immediate normal path death", decisions)
	}
}

func TestRankSelectorClassReturnsBestNormalAndUsesActiveNestedSelector(t *testing.T) {
	now := time.Unix(240, 0)
	ids := map[string]proto.TargetID{
		"root":   proto.DeriveTargetID(proto.GraphNodeKindSelector, "root"),
		"a":      proto.DeriveTargetID(proto.GraphNodeKindPath, "a"),
		"nested": proto.DeriveTargetID(proto.GraphNodeKindSelector, "nested"),
		"bad":    proto.DeriveTargetID(proto.GraphNodeKindPath, "bad"),
		"good":   proto.DeriveTargetID(proto.GraphNodeKindPath, "good"),
		"peak":   proto.DeriveTargetID(proto.GraphNodeKindPath, "peak"),
	}
	manifest := proto.GraphManifest{
		RootID: ids["root"],
		Nodes: []proto.GraphNode{
			{ID: ids["root"], Kind: proto.GraphNodeKindSelector, Name: "root", Children: []proto.TargetID{ids["a"], ids["nested"], ids["peak"]}, PeakCandidates: []proto.TargetID{ids["peak"]}},
			{ID: ids["a"], Kind: proto.GraphNodeKindPath, Name: "a"},
			{ID: ids["nested"], Kind: proto.GraphNodeKindSelector, Name: "nested", Children: []proto.TargetID{ids["bad"], ids["good"]}},
			{ID: ids["bad"], Kind: proto.GraphNodeKindPath, Name: "bad"},
			{ID: ids["good"], Kind: proto.GraphNodeKindPath, Name: "good"},
			{ID: ids["peak"], Kind: proto.GraphNodeKindPath, Name: "peak"},
		},
	}
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	runtime := mustExecutionRuntime(t, manifest)
	if err := runtime.selectChild(ids["root"], ids["peak"]); err != nil {
		t.Fatal(err)
	}
	if err := runtime.selectChild(ids["nested"], ids["bad"]); err != nil {
		t.Fatal(err)
	}
	observations := map[proto.TargetID]pathEvidenceObservation{
		ids["a"]:    selectorObservation(ids["a"], now, 50*time.Millisecond, 0, 1),
		ids["bad"]:  selectorObservation(ids["bad"], now, 200*time.Millisecond, 500, 1),
		ids["good"]: selectorObservation(ids["good"], now, time.Millisecond, 0, 100),
		ids["peak"]: selectorObservation(ids["peak"], now, 10*time.Millisecond, 0, 10),
	}
	policy := selectorEvidencePolicy{latencyBandRatio: 0.05, latencyBandFloor: time.Millisecond, minimumConfidence: 1}
	ranked := runtime.rankSelectorClassTargets(ids["root"], false, proto.SenderDirectionClientToServer, observations, now, policy)
	if len(ranked) != 2 || ranked[0] != ids["a"] || ranked[1] != ids["nested"] {
		t.Fatalf("normal ranking=%x want a then active-bad nested", ranked)
	}
	if err := runtime.selectChild(ids["nested"], ids["good"]); err != nil {
		t.Fatal(err)
	}
	ranked = runtime.rankSelectorClassTargets(ids["root"], false, proto.SenderDirectionClientToServer, observations, now, policy)
	if len(ranked) != 2 || ranked[0] != ids["nested"] || ranked[1] != ids["a"] {
		t.Fatalf("normal ranking after nested selection=%x want nested then a", ranked)
	}
}

func TestRankPeakTransferTargetsAppliesAdmissionInOneRanking(t *testing.T) {
	now := time.Unix(245, 0)
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "normal", "lossy", "jittery", "healthy"),
		runtimeNode(proto.GraphNodeKindPath, "normal"),
		runtimeNode(proto.GraphNodeKindPath, "lossy"),
		runtimeNode(proto.GraphNodeKindPath, "jittery"),
		runtimeNode(proto.GraphNodeKindPath, "healthy"),
	)
	root, _ := manifest.Node(ids["root"])
	root.PeakCandidates = []proto.TargetID{ids["lossy"], ids["jittery"], ids["healthy"]}
	for i := range manifest.Nodes {
		if manifest.Nodes[i].ID == root.ID {
			manifest.Nodes[i] = root
		}
	}
	runtime := mustExecutionRuntime(t, manifest)
	observations := map[proto.TargetID]pathEvidenceObservation{
		ids["normal"]:  selectorObservation(ids["normal"], now, time.Millisecond, 0, 1),
		ids["lossy"]:   selectorObservation(ids["lossy"], now, 2*time.Millisecond, peakTransferMaximumLossPP+1, 100),
		ids["jittery"]: selectorObservation(ids["jittery"], now, 3*time.Millisecond, 0, 90),
		ids["healthy"]: selectorObservation(ids["healthy"], now, 4*time.Millisecond, peakTransferMaximumLossPP, 80),
	}
	jittery := observations[ids["jittery"]]
	jittery.quality.Jitter = peakTransferMaximumJitter + time.Nanosecond
	observations[ids["jittery"]] = jittery
	policy := selectorEvidencePolicy{
		latencyBandRatio: 0.05, latencyBandFloor: time.Millisecond, minimumConfidence: 1,
	}

	ranked := runtime.rankPeakTransferTargets(
		ids["root"], proto.SenderDirectionClientToServer, observations, now, policy,
	)
	if len(ranked) != 1 || ranked[0] != ids["healthy"] {
		t.Fatalf("peak-transfer ranking=%x want only healthy=%x", ranked, ids["healthy"])
	}
}

func TestPeakTransferSuppressionIsAppliedBeforeLatencyBandRanking(t *testing.T) {
	now := time.Unix(246, 0)
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "normal", "suppressed", "stable-slow", "stable-fast"),
		runtimeNode(proto.GraphNodeKindPath, "normal"),
		runtimeNode(proto.GraphNodeKindPath, "suppressed"),
		runtimeNode(proto.GraphNodeKindPath, "stable-slow"),
		runtimeNode(proto.GraphNodeKindPath, "stable-fast"),
	)
	root, _ := manifest.Node(ids["root"])
	root.PeakCandidates = []proto.TargetID{ids["suppressed"], ids["stable-slow"], ids["stable-fast"]}
	for i := range manifest.Nodes {
		if manifest.Nodes[i].ID == root.ID {
			manifest.Nodes[i] = root
		}
	}
	runtime := mustExecutionRuntime(t, manifest)
	observations := map[proto.TargetID]pathEvidenceObservation{
		ids["normal"]:      selectorObservation(ids["normal"], now, time.Millisecond, 0, 1),
		ids["suppressed"]:  selectorObservation(ids["suppressed"], now, time.Millisecond, 0, 1),
		ids["stable-slow"]: selectorObservation(ids["stable-slow"], now, 10*time.Millisecond, 10, 1),
		ids["stable-fast"]: selectorObservation(ids["stable-fast"], now, 11*time.Millisecond, 0, 100),
	}
	policy := selectorEvidencePolicy{
		latencyBandRatio: 0.25, latencyBandFloor: time.Millisecond, minimumConfidence: 1,
	}
	withoutSuppression := runtime.rankPeakTransferTargets(
		ids["root"], proto.SenderDirectionClientToServer, observations, now, policy,
	)
	if len(withoutSuppression) != 3 || withoutSuppression[0] != ids["suppressed"] ||
		withoutSuppression[1] != ids["stable-slow"] {
		t.Fatalf("baseline ranking=%x want suppressed then latency-nearest", withoutSuppression)
	}
	withSuppression := runtime.rankSelectorClassTargetsWithAdmission(
		ids["root"], true, proto.SenderDirectionClientToServer, observations, now, policy, true,
		map[proto.TargetID]struct{}{ids["suppressed"]: {}},
	)
	if len(withSuppression) != 2 || withSuppression[0] != ids["stable-fast"] ||
		withSuppression[1] != ids["stable-slow"] {
		t.Fatalf("suppressed ranking=%x want stable-fast then stable-slow", withSuppression)
	}
}

func TestSelectorEvidenceSnapshotReleasesTopologyLockAndRejectsMixedProbeGeneration(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "path"),
		runtimeNode(proto.GraphNodeKindPath, "path"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	base, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = peer.Close() })
	now := time.Now()
	base.quality = transport.PathQuality{RTT: 50 * time.Millisecond, At: now}
	path := &selectorReentrantQualityPath{memoryPathConn: base}
	pathID := attachFixturePath(
		t, e, path, transport.PathSpec{Transport: "memory", Address: "selector-reentrant-quality"}, ids["path"],
	)
	e.pathsMu.RLock()
	slot := e.paths[pathID]
	e.pathsMu.RUnlock()
	seedPathProbeSuccess(e, slot, now, time.Millisecond)

	var once sync.Once
	path.onQuality = func() {
		once.Do(func() {
			e.pathsMu.Lock()
			slot.probeEndpointGen.Store(slot.probeEndpointGen.Load() + 1)
			e.advancePathTopologyEpochLocked()
			e.pathsMu.Unlock()
		})
	}
	type snapshotResult struct {
		view selectorEvidenceView
		ok   bool
	}
	result := make(chan snapshotResult, 1)
	go func() {
		view, ok := e.selectorEvidenceSnapshot()
		result <- snapshotResult{view: view, ok: ok}
	}()
	select {
	case got := <-result:
		if !got.ok {
			t.Fatal("coherent retry did not produce selector evidence")
		}
		observation := got.view.observations[ids["path"]]
		if observation.quality.RTT != 50*time.Millisecond || observation.probeLiveness != qualityStateUnknown {
			t.Fatalf("mixed predecessor probe evidence survived retry: %+v", observation)
		}
		if got.view.topologyEpoch != e.currentPathTopologyEpoch() {
			t.Fatalf("snapshot epoch=%d current=%d", got.view.topologyEpoch, e.currentPathTopologyEpoch())
		}
	case <-time.After(time.Second):
		t.Fatal("PathConn.Quality ran while selector held the topology lock")
	}
}

func TestRecursiveSelectorMissingCurrentIsFactualPathDeath(t *testing.T) {
	now := time.Unix(250, 0)
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	runtime := mustExecutionRuntime(t, manifest)
	if err := runtime.selectChild(ids["root"], ids["a"]); err != nil {
		t.Fatal(err)
	}
	decisions := runtime.selectorDecisions(
		proto.SenderDirectionClientToServer,
		map[proto.TargetID]pathEvidenceObservation{
			ids["b"]: selectorObservation(ids["b"], now, 20*time.Millisecond, 0, 1),
		},
		now,
		selectorEvidencePolicy{latencyBandRatio: 0.25, latencyBandFloor: time.Millisecond, minimumConfidence: 1},
		time.Hour,
		time.Hour,
	)
	if len(decisions) != 1 || decisions[0].selectorID != ids["root"] ||
		decisions[0].targetID != ids["b"] || decisions[0].cause != "death" ||
		decisions[0].origin != policySelectionPathDeath || !decisions[0].origin.requiresSelectorCutover() ||
		!decisions[0].origin.isFactualFailure() || decisions[0].origin.chargesZombieBudget() {
		t.Fatalf("decisions=%+v want factual root->b path death", decisions)
	}
}

func TestRecursiveSelectorPathDeathCommitsProjectedFallback(t *testing.T) {
	now := time.Unix(275, 0)
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b", "c"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
		runtimeNode(proto.GraphNodeKindPath, "c"),
	)
	runtime := mustExecutionRuntime(t, manifest)
	if err := runtime.selectChild(ids["root"], ids["a"]); err != nil {
		t.Fatal(err)
	}
	leaves, _, err := runtime.activeLeafTargets(map[proto.TargetID]bool{
		ids["b"]: true,
		ids["c"]: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(leaves) != 1 || leaves[0] != ids["b"] {
		t.Fatalf("physical fallback=%x want manifest-order b=%x", leaves, ids["b"])
	}

	decisions := runtime.selectorDecisions(
		proto.SenderDirectionClientToServer,
		map[proto.TargetID]pathEvidenceObservation{
			ids["b"]: selectorObservation(ids["b"], now, 100*time.Millisecond, 0, 1),
			ids["c"]: selectorObservation(ids["c"], now, time.Millisecond, 0, 100),
		},
		now,
		selectorEvidencePolicy{latencyBandRatio: 0.25, latencyBandFloor: time.Millisecond, minimumConfidence: 1},
		time.Hour,
		time.Hour,
	)
	if len(decisions) != 1 || decisions[0].selectorID != ids["root"] ||
		decisions[0].targetID != ids["b"] || decisions[0].origin != policySelectionPathDeath {
		t.Fatalf("decisions=%+v want projected fallback root->b path death", decisions)
	}
}

func TestStaleSelectorObservationCannotOverwriteDeathProjection(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b", "c"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
		runtimeNode(proto.GraphNodeKindPath, "c"),
	)
	limits := Limits{
		ProbeInterval:       time.Hour,
		SelectorDwell:       time.Hour,
		SelectorCooldown:    time.Hour,
		ZombieMaxMigrations: 2,
		ZombieCooldown:      time.Hour,
	}.Clamp()
	e := New(SideClient, NewClientFlowID(), limits)
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}

	sampleAt := time.Now()
	qualities := map[string]time.Duration{
		"a": 100 * time.Millisecond,
		"b": time.Millisecond,
		"c": 10 * time.Millisecond,
	}
	captures := make(map[string]*captureDispatchPath, 3)
	pathIDs := make(map[string]uint32, 3)
	for _, name := range []string{"a", "b", "c"} {
		path, peer := newMemoryPathPair()
		t.Cleanup(func() { _ = peer.Close() })
		path.quality = transport.PathQuality{RTT: qualities[name], At: sampleAt}
		capture := &captureDispatchPath{PathConn: path}
		captures[name] = capture
		pathIDs[name] = attachFixturePath(
			t, e, capture, transport.PathSpec{Transport: "memory", Address: name}, ids[name],
		)
	}
	if err := e.SelectExplicitTarget(ids["root"], ids["c"], "explicit"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.SendData([]byte("unacknowledged-before-death")); err != nil {
		t.Fatal(err)
	}
	cSequences := captures["c"].dataSequences()
	if len(cSequences) != 1 {
		t.Fatalf("initial DATA sequences on c=%v want one frame", cSequences)
	}
	publishedSeq := cSequences[0]
	staleObservations := e.selectorEvidenceObservations()
	if !staleObservations[ids["c"]].live {
		t.Fatal("pre-death selector snapshot did not contain live c")
	}

	runtime := e.localExecutionRuntime()
	e.pathsMu.Lock()
	departure := e.detachPathLocked(
		e.paths[pathIDs["c"]], runtime, transport.CauseTransportError, errors.New("injected selected path death"), false,
	)
	e.pathsMu.Unlock()
	var finishOnce sync.Once
	finishDeparture := func() { finishOnce.Do(func() { e.finishPathDeparture(departure) }) }
	defer finishDeparture()

	desired, effective, ok := runtime.selectedChild(ids["root"])
	if !ok || desired != ids["c"] || effective != ids["a"] || e.ActivePath() != pathIDs["a"] {
		t.Fatalf(
			"post-death projection active/desired/effective=%d/%x/%x ok=%t want a/c/a",
			e.ActivePath(), desired, effective, ok,
		)
	}
	if got := e.MigrationCount(); got != 2 {
		t.Fatalf("migration count after explicit+physical death=%d want 2", got)
	}

	decisions := runtime.selectorDecisions(
		proto.SenderDirectionClientToServer,
		staleObservations,
		time.Now(),
		e.selectorEvidencePolicy(),
		time.Hour,
		time.Hour,
	)
	if len(decisions) != 0 {
		t.Fatalf("pre-death snapshot produced an immediate decision: %+v", decisions)
	}
	desired, effective, ok = runtime.selectedChild(ids["root"])
	if !ok || desired != ids["c"] || effective != ids["a"] {
		t.Fatalf("stale snapshot changed desired/effective=%x/%x ok=%t want c/a", desired, effective, ok)
	}

	migrations := make(chan struct {
		oldID, newID uint32
		cause        string
	}, 2)
	cancel := e.OnMigrate(func(oldID, newID uint32, cause string) {
		migrations <- struct {
			oldID, newID uint32
			cause        string
		}{oldID: oldID, newID: newID, cause: cause}
	})
	defer cancel()
	decisionCommitted := make(chan struct{})
	var decisionOnce sync.Once
	e.selectorDecisionAfterCommit = func() {
		decisionOnce.Do(func() { close(decisionCommitted) })
	}
	finishDeparture()
	select {
	case <-decisionCommitted:
	case <-time.After(time.Second):
		t.Fatal("post-death selector transaction did not commit")
	}

	desired, effective, ok = runtime.selectedChild(ids["root"])
	if !ok || desired != ids["a"] || effective != ids["a"] || e.ActivePath() != pathIDs["a"] {
		t.Fatalf(
			"aligned fallback active/desired/effective=%d/%x/%x ok=%t want a/a/a",
			e.ActivePath(), desired, effective, ok,
		)
	}
	if got := e.MigrationCount(); got != 2 {
		t.Fatalf("stale snapshot caused a second death migration: count=%d want 2", got)
	}
	e.zombieMu.Lock()
	zombieLeft := e.zombieLeft
	e.zombieMu.Unlock()
	if zombieLeft != limits.ZombieMaxMigrations-1 || errors.Is(e.CloseErr(), ErrZombie) {
		t.Fatalf("single death zombie state left/error=%d/%v", zombieLeft, e.CloseErr())
	}

	deadline := time.Now().Add(time.Second)
	for {
		aSequences := captures["a"].dataSequences()
		if len(aSequences) > 0 && aSequences[0] == publishedSeq {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("fallback replay DATA sequences on a=%v want first %d", aSequences, publishedSeq)
		}
		time.Sleep(time.Millisecond)
	}
	if bSequences := captures["b"].dataSequences(); len(bSequences) != 0 {
		t.Fatalf("quality sibling received death replay after stale snapshot: %v", bSequences)
	}
	select {
	case event := <-migrations:
		if event.oldID != pathIDs["c"] || event.newID != pathIDs["a"] || event.cause != "death" {
			t.Fatalf("physical death migration=%+v want c->a", event)
		}
	default:
		t.Fatal("physical death migration hook did not fire")
	}
	select {
	case event := <-migrations:
		t.Fatalf("one path death published a second migration: %+v", event)
	default:
	}
}

func TestEnginePathDeathKeepsPhysicalAndSelectorFallbackAligned(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b", "c"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
		runtimeNode(proto.GraphNodeKindPath, "c"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: time.Hour}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	paths := make(map[string]*lifecycleHealthyPath, 3)
	pathIDs := make(map[string]uint32, 3)
	for _, name := range []string{"a", "b", "c"} {
		path := newLifecycleHealthyPath()
		paths[name] = path
		pathIDs[name] = attachFixturePath(t, e, path, transport.PathSpec{Transport: "memory", Address: name}, ids[name])
	}
	if err := e.SelectExplicitTarget(ids["root"], ids["c"], "explicit"); err != nil {
		t.Fatal(err)
	}
	if e.ActivePath() != pathIDs["c"] {
		t.Fatalf("explicit active=%d want c=%d", e.ActivePath(), pathIDs["c"])
	}

	migrations := make(chan struct {
		oldID, newID uint32
		cause        string
	}, 4)
	cancel := e.OnMigrate(func(oldID, newID uint32, cause string) {
		migrations <- struct {
			oldID, newID uint32
			cause        string
		}{oldID: oldID, newID: newID, cause: cause}
	})
	defer cancel()
	paths["c"].die(transport.CauseTransportError, errors.New("selected path failed"))
	select {
	case event := <-migrations:
		if event.oldID != pathIDs["c"] || event.newID != pathIDs["a"] || event.cause != "death" {
			t.Fatalf("death migration=%+v want c->a", event)
		}
	case <-time.After(time.Second):
		t.Fatal("path death did not publish migration")
	}
	var desired, effective proto.TargetID
	var ok bool
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		select {
		case event := <-migrations:
			t.Fatalf("one path death published a second migration: %+v", event)
		default:
		}
		desired, effective, ok = e.localExecutionRuntime().selectedChild(ids["root"])
		if ok && desired == ids["a"] && effective == ids["a"] {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !ok || desired != ids["a"] || effective != ids["a"] || e.ActivePath() != pathIDs["a"] {
		t.Fatalf("aligned fallback active/desired/effective=%d/%x/%x ok=%t", e.ActivePath(), desired, effective, ok)
	}
	select {
	case event := <-migrations:
		t.Fatalf("aligned selector transaction published a second migration: %+v", event)
	default:
	}
	if got := e.MigrationCount(); got != 2 {
		t.Fatalf("explicit+death migration count=%d want 2", got)
	}
}

func TestRecursiveSelectorFreshSiblingImmediatelyReplacesStaleCurrent(t *testing.T) {
	now := time.Unix(300, 0)
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	runtime := mustExecutionRuntime(t, manifest)
	if err := runtime.selectChild(ids["root"], ids["a"]); err != nil {
		t.Fatal(err)
	}
	runtime.mu.Lock()
	runtime.selectors[ids["root"]].lastQualityMove = now
	runtime.mu.Unlock()

	stale := selectorObservation(ids["a"], now.Add(-time.Second), 10*time.Millisecond, 0, 1)
	stale.freshFor = 500 * time.Millisecond
	stale.probeLiveness = qualityStateStale
	stale.probeLifecycle = pathProbeWireTimeout
	stale.probeFailure = pathProbeFailureWireTimeout
	fresh := selectorObservation(ids["b"], now, 20*time.Millisecond, 0, 1)
	fresh.freshFor = 500 * time.Millisecond
	decisions := runtime.selectorDecisions(
		proto.SenderDirectionClientToServer,
		map[proto.TargetID]pathEvidenceObservation{ids["a"]: stale, ids["b"]: fresh},
		now,
		selectorEvidencePolicy{latencyBandRatio: 0.25, latencyBandFloor: time.Millisecond, minimumConfidence: 1},
		time.Hour,
		time.Hour,
	)
	if len(decisions) != 1 || decisions[0].selectorID != ids["root"] ||
		decisions[0].targetID != ids["b"] || decisions[0].cause != "probe-wire-timeout" {
		t.Fatalf("decisions=%+v want immediate root->b probe-wire-timeout", decisions)
	}
}

func TestRecursiveSelectorProbeFailureCauseMatrixHighCount(t *testing.T) {
	now := time.Unix(350, 0)
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	tests := []struct {
		name      string
		lifecycle pathProbeLifecycle
		failure   pathProbeFailure
		liveness  qualityState
		cause     string
		origin    policySelectionOrigin
	}{
		{
			name: "committed wire timeout", lifecycle: pathProbeWireTimeout,
			failure: pathProbeFailureWireTimeout, liveness: qualityStateStale,
			cause: "probe-wire-timeout", origin: policySelectionProbeFailure,
		},
		{
			name: "queued behind DATA", lifecycle: pathProbeDataStarved,
			failure: pathProbeFailureDataStarved, liveness: qualityStateUnknown,
			cause: "probe-starved-data", origin: policySelectionProbeStarvedData,
		},
		{
			name: "probe physical Write stalled", lifecycle: pathProbeWriteStalled,
			failure: pathProbeFailureWriteStalled, liveness: qualityStateUnknown,
			cause: "probe-write-stalled", origin: policySelectionWriteStalled,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime := mustExecutionRuntime(t, manifest)
			if err := runtime.selectChild(ids["root"], ids["a"]); err != nil {
				t.Fatal(err)
			}
			current := selectorObservation(ids["a"], now, time.Millisecond, 0, 100)
			current.probeLifecycle = test.lifecycle
			current.probeFailure = test.failure
			current.probeLiveness = test.liveness
			if test.liveness == qualityStateStale {
				current.quality.At = now.Add(-time.Second)
				current.freshFor = 500 * time.Millisecond
			}
			challenger := selectorObservation(ids["b"], now, 20*time.Millisecond, 0, 1)
			observations := map[proto.TargetID]pathEvidenceObservation{
				ids["a"]: current,
				ids["b"]: challenger,
			}
			for iteration := 0; iteration < 512; iteration++ {
				decisions := runtime.selectorDecisions(
					proto.SenderDirectionClientToServer, observations, now,
					selectorEvidencePolicy{latencyBandRatio: 0.25, latencyBandFloor: time.Millisecond, minimumConfidence: 1},
					time.Hour, time.Hour,
				)
				if len(decisions) != 1 || decisions[0].targetID != ids["b"] ||
					decisions[0].cause != test.cause || decisions[0].origin != test.origin {
					t.Fatalf("iteration %d decisions=%+v want cause/origin %q/%d", iteration, decisions, test.cause, test.origin)
				}
			}
		})
	}
}

func TestRecursiveSelectorQueuedProbeCannotMasqueradeAsWireTimeout(t *testing.T) {
	now := time.Unix(375, 0)
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	runtime := mustExecutionRuntime(t, manifest)
	if err := runtime.selectChild(ids["root"], ids["a"]); err != nil {
		t.Fatal(err)
	}
	queued := selectorObservation(ids["a"], now.Add(-time.Hour), time.Millisecond, 0, 100)
	queued.freshFor = minimumSelectorProbeFreshFor
	queued.probeLifecycle = pathProbeQueued
	queued.probeLiveness = qualityStateUnknown
	queued.probeFailure = pathProbeFailureNone
	fresh := selectorObservation(ids["b"], now, 20*time.Millisecond, 0, 1)
	observations := map[proto.TargetID]pathEvidenceObservation{ids["a"]: queued, ids["b"]: fresh}
	for iteration := 0; iteration < 512; iteration++ {
		decisions := runtime.selectorDecisions(
			proto.SenderDirectionClientToServer, observations, now,
			selectorEvidencePolicy{latencyBandRatio: 0.25, latencyBandFloor: time.Millisecond, minimumConfidence: 1},
			time.Hour, time.Hour,
		)
		if len(decisions) != 0 {
			t.Fatalf("iteration %d queued probe produced immediate decision %+v", iteration, decisions)
		}
	}
}

func TestFirstAttachedLeafInitializesSelectorPreferenceWithoutDispatchFallback(t *testing.T) {
	now := time.Now()
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: 10 * time.Millisecond}.Clamp())
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
	aID, err := e.AttachPath(a, transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "a"}})
	if err != nil {
		t.Fatal(err)
	}
	bID, err := e.AttachPath(b, transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "b"}})
	if err != nil {
		t.Fatal(err)
	}
	runtime := e.localExecutionRuntime()
	desired, effective, ok := runtime.selectedChild(ids["root"])
	if !ok || desired != ids["a"] || effective != ids["a"] {
		t.Fatalf("initial selector desired/effective=%x/%x ok=%t want a/a", desired, effective, ok)
	}
	e.policyStateMu.Lock()
	generation, policyTarget := e.policyGeneration, e.policySelections[ids["root"]]
	e.policyStateMu.Unlock()
	if generation != 0 || policyTarget != ids["a"] {
		t.Fatalf("initial policy generation/target=%d/%x want 0/%x", generation, policyTarget, ids["a"])
	}
	if ticket, err := runtime.buildTicketObservedPresence(
		map[proto.TargetID]bool{ids["b"]: true},
		map[proto.TargetID]bool{ids["a"]: true, ids["b"]: true},
		nil, nil, false, 1, 0,
	); !errors.Is(err, errNoExecutionRoute) || len(ticket.routes) != 0 {
		t.Fatalf("temporary fallback routes=%+v err=%v want no route", ticket.routes, err)
	}
	desired, effective, _ = runtime.selectedChild(ids["root"])
	if desired != ids["a"] || effective != (proto.TargetID{}) {
		t.Fatalf("unavailable desired/effective=%x/%x want a/zero", desired, effective)
	}
	e.pathsMu.RLock()
	aSlot, bSlot := e.paths[aID], e.paths[bID]
	e.pathsMu.RUnlock()
	seedPathProbeSuccess(e, aSlot, now.Add(-time.Second), 10*time.Millisecond)
	seedPathProbeWireTimeout(e, aSlot, now.Add(-time.Nanosecond))
	seedPathProbeSuccess(e, bSlot, now, 20*time.Millisecond)
	decisions := runtime.selectorDecisions(
		proto.SenderDirectionClientToServer,
		e.selectorEvidenceObservations(),
		now,
		selectorEvidencePolicy{latencyBandRatio: 0.25, latencyBandFloor: time.Millisecond, minimumConfidence: 1},
		time.Hour,
		time.Hour,
	)
	if len(decisions) != 1 || decisions[0].targetID != ids["b"] || decisions[0].cause != "probe-wire-timeout" {
		t.Fatalf("fallback masked committed stale target: decisions=%+v", decisions)
	}
}

func TestFirstAttachedLeafInitializesEveryNestedSelectorPolicy(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "inner", "c"),
		runtimeNode(proto.GraphNodeKindSelector, "inner", "a", "b"),
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
	path, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = peer.Close() })
	if _, err := e.AttachPathBound(path, transport.PathSpec{Transport: "memory"}, PathBinding{
		LocalTXTargetID: ids["a"], PeerTXTargetID: ids["a"],
	}); err != nil {
		t.Fatal(err)
	}
	runtime := e.localExecutionRuntime()
	for selectorName, targetName := range map[string]string{"root": "inner", "inner": "a"} {
		desired, effective, ok := runtime.selectedChild(ids[selectorName])
		if !ok || desired != ids[targetName] || effective != ids[targetName] {
			t.Fatalf("%s desired/effective=%x/%x ok=%t want %s", selectorName, desired, effective, ok, targetName)
		}
		e.policyStateMu.Lock()
		policyTarget := e.policySelections[ids[selectorName]]
		e.policyStateMu.Unlock()
		if policyTarget != ids[targetName] {
			t.Fatalf("%s policy target=%x want %x", selectorName, policyTarget, ids[targetName])
		}
	}
	if e.policyGeneration != 0 {
		t.Fatalf("nested initial policy generation=%d want 0", e.policyGeneration)
	}
}

func TestConcurrentFirstPathActivationLinearizesInitialSelectorPolicy(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	prepare := func(name string) uint32 {
		t.Helper()
		path, peer := newMemoryPathPair()
		t.Cleanup(func() { _ = peer.Close() })
		id, err := e.PreparePathBound(path, transport.PathSpec{Transport: "memory"}, PathBinding{
			LocalTXTargetID: ids[name], PeerTXTargetID: ids[name],
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := e.StagePathAttach(id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	aID, bID := prepare("a"), prepare("b")

	type selectionSnapshot struct {
		active     uint32
		desired    proto.TargetID
		effective  proto.TargetID
		policy     proto.TargetID
		generation uint64
	}
	entered := make(chan selectionSnapshot, 1)
	release := make(chan struct{})
	var hookOnce sync.Once
	e.activationAfterInitialSelection = func() {
		hookOnce.Do(func() {
			desired, effective, _ := e.localExecutionRuntime().selectedChild(ids["root"])
			e.policyStateMu.Lock()
			snapshot := selectionSnapshot{
				active: e.activeID, desired: desired, effective: effective,
				policy: e.policySelections[ids["root"]], generation: e.policyGeneration,
			}
			e.policyStateMu.Unlock()
			entered <- snapshot
			<-release
		})
	}
	aDone := make(chan error, 1)
	go func() { aDone <- e.ActivateStagedPath(aID, false) }()
	var snapshot selectionSnapshot
	select {
	case snapshot = <-entered:
	case <-time.After(time.Second):
		t.Fatal("first activation did not reach initial-selection boundary")
	}
	if snapshot.active != aID || snapshot.desired != ids["a"] || snapshot.effective != ids["a"] ||
		snapshot.policy != ids["a"] || snapshot.generation != 0 {
		t.Fatalf("first publication snapshot=%+v want active/desired/effective/policy A at generation zero", snapshot)
	}
	bDone := make(chan error, 1)
	go func() { bDone <- e.ActivateStagedPath(bID, false) }()
	select {
	case err := <-bDone:
		t.Fatalf("second activation crossed first publication boundary: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	if err := <-aDone; err != nil {
		t.Fatal(err)
	}
	if err := <-bDone; err != nil {
		t.Fatal(err)
	}
	desired, effective, ok := e.localExecutionRuntime().selectedChild(ids["root"])
	if !ok || desired != ids["a"] || effective != ids["a"] || e.ActivePath() != aID {
		t.Fatalf("final active/desired/effective=%d/%x/%x ok=%t want A", e.ActivePath(), desired, effective, ok)
	}
	e.policyStateMu.Lock()
	generation, policyTarget := e.policyGeneration, e.policySelections[ids["root"]]
	e.policyStateMu.Unlock()
	if generation != 0 || policyTarget != ids["a"] {
		t.Fatalf("final initial policy generation/target=%d/%x want 0/%x", generation, policyTarget, ids["a"])
	}
}

func TestRecursiveSelectorStaleCurrentReplaysUnackedHistory(t *testing.T) {
	now := time.Now()
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	limits := Limits{
		SelectorHysteresis:   0.25,
		SelectorLatencyFloor: time.Millisecond,
		SelectorDwell:        time.Hour,
		SelectorCooldown:     time.Hour,
		ProbeInterval:        time.Second,
	}.Clamp()
	client := New(SideClient, NewClientFlowID(), limits)
	t.Cleanup(func() { _ = client.Close() })
	if err := client.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := client.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}

	a, aPeer := newMemoryPathPair()
	b, bPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = aPeer.Close() })
	t.Cleanup(func() { _ = bPeer.Close() })
	a.quality = transport.PathQuality{RTT: 10 * time.Millisecond, At: now.Add(-time.Second)}
	b.quality = transport.PathQuality{RTT: 20 * time.Millisecond, At: now}
	aCapture := &captureDispatchPath{PathConn: a}
	bCapture := &captureDispatchPath{PathConn: b}
	aID, err := client.AttachPath(aCapture, transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "a"}})
	if err != nil {
		t.Fatal(err)
	}
	bID, err := client.AttachPath(bCapture, transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if client.ActivePath() != aID {
		t.Fatalf("initial active=%d want a=%d", client.ActivePath(), aID)
	}
	client.pathsMu.RLock()
	aSlot := client.paths[aID]
	bSlot := client.paths[bID]
	client.pathsMu.RUnlock()
	seedPathProbeSuccess(client, aSlot, now.Add(-4*time.Second), 10*time.Millisecond)
	seedPathProbeWireTimeout(client, aSlot, now.Add(-time.Second))
	seedPathProbeSuccess(client, bSlot, now, 20*time.Millisecond)
	if _, err := client.SendData([]byte("unacked-before-blackhole")); err != nil {
		t.Fatal(err)
	}
	if got := aCapture.dataSequences(); len(got) != 1 || got[0] != 0 {
		t.Fatalf("initial sequences on a=%v want [0]", got)
	}

	migrated := make(chan string, 1)
	cancel := client.OnMigrate(func(_, _ uint32, cause string) { migrated <- cause })
	defer cancel()
	client.StartSelector(time.Millisecond)
	deadline := time.Now().Add(time.Second)
	for client.ActivePath() != bID && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if client.ActivePath() != bID {
		t.Fatalf("stale current did not switch to b: active=%d want=%d", client.ActivePath(), bID)
	}
	for len(bCapture.dataSequences()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := bCapture.dataSequences(); len(got) != 1 || got[0] != 0 {
		t.Fatalf("unacked history replay on b=%v want [0]", got)
	}
	select {
	case cause := <-migrated:
		if cause != "probe-wire-timeout" {
			t.Fatalf("migration cause=%q want probe-wire-timeout", cause)
		}
	case <-time.After(time.Second):
		t.Fatal("stale-current migration hook did not fire")
	}
}

func TestProbeFailureReplayStopsAtSwitchPublicationFrontier(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	client := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = client.Close() })
	if err := client.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := client.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	a, aPeer := newMemoryPathPair()
	b, bPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = aPeer.Close(); _ = bPeer.Close() })
	aCapture := &captureDispatchPath{PathConn: a}
	bCapture := &captureDispatchPath{PathConn: b}
	if _, err := client.AttachPath(aCapture, transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "a"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AttachPath(bCapture, transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "b"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.SendData([]byte("published-before-switch")); err != nil {
		t.Fatal(err)
	}

	replayEntered := make(chan struct{})
	replayRelease := make(chan struct{})
	var enteredOnce sync.Once
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(replayRelease) }) })
	client.boundedReplayBeforeSnapshot = func() {
		enteredOnce.Do(func() { close(replayEntered) })
		<-replayRelease
	}
	selectionResult := make(chan error, 1)
	go func() {
		selectionResult <- client.selectLocalTarget(ids["root"], ids["b"], "probe-wire-timeout", policySelectionProbeFailure)
	}()
	select {
	case <-replayEntered:
	case <-time.After(time.Second):
		t.Fatal("bounded replay did not reach its snapshot boundary")
	}
	nextWriteResult := make(chan error, 1)
	go func() {
		_, err := client.SendData([]byte("published-after-switch"))
		nextWriteResult <- err
	}()
	select {
	case err := <-selectionResult:
		t.Fatalf("selection returned before its frozen replay completed: %v", err)
	case err := <-nextWriteResult:
		t.Fatalf("post-switch DATA overtook frozen replay: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(replayRelease) })
	select {
	case err := <-selectionResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("selection did not finish after replay release")
	}
	select {
	case err := <-nextWriteResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("post-switch DATA did not finish after replay release")
	}
	deadline := time.Now().Add(time.Second)
	for len(bCapture.dataSequences()) < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	sequences := bCapture.dataSequences()
	if len(sequences) != 2 || sequences[0] != 0 || sequences[1] != 1 {
		t.Fatalf("successor DATA sequence=%v want [0 1]", sequences)
	}
}

func TestRecursiveSelectorSchedulerChangesActualDataRoute(t *testing.T) {
	now := time.Now()
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	limits := Limits{
		SelectorHysteresis:   0.25,
		SelectorLatencyFloor: time.Millisecond,
		SelectorDwell:        10 * time.Millisecond,
		SelectorCooldown:     10 * time.Millisecond,
	}.Clamp()
	client := New(SideClient, NewClientFlowID(), limits)
	t.Cleanup(func() { _ = client.Close() })
	if err := client.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := client.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}

	a, aPeer := newMemoryPathPair()
	b, bPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = aPeer.Close() })
	t.Cleanup(func() { _ = bPeer.Close() })
	a.quality = transport.PathQuality{RTT: 100 * time.Millisecond, At: now}
	b.quality = transport.PathQuality{RTT: 10 * time.Millisecond, At: now}
	aCapture := &captureDispatchPath{PathConn: a}
	bCapture := &captureDispatchPath{PathConn: b}
	aID, err := client.AttachPath(aCapture, transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "a"}})
	if err != nil {
		t.Fatal(err)
	}
	bID, err := client.AttachPath(bCapture, transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if client.ActivePath() != aID {
		t.Fatalf("initial active path=%d want=%d", client.ActivePath(), aID)
	}
	client.StartSelector(2 * time.Millisecond)
	deadline := time.Now().Add(time.Second)
	for client.ActivePath() != bID && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if client.ActivePath() != bID {
		t.Fatalf("selector did not activate lower-latency path: active=%d want=%d", client.ActivePath(), bID)
	}
	if _, err := client.SendData([]byte("selected")); err != nil {
		t.Fatal(err)
	}
	if got := len(aCapture.dataSequences()); got != 0 {
		t.Fatalf("old selector path received %d DATA frames", got)
	}
	if got := len(bCapture.dataSequences()); got != 1 {
		t.Fatalf("selected path received %d DATA frames, want 1", got)
	}
}

func TestRecursiveSelectorChoosesImmediateBondAggregate(t *testing.T) {
	now := time.Now()
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "aggregate"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindBond, "aggregate", "b", "c"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
		runtimeNode(proto.GraphNodeKindPath, "c"),
	)
	limits := Limits{SelectorHysteresis: 0.25, SelectorLatencyFloor: time.Millisecond, SelectorDwell: 5 * time.Millisecond, SelectorCooldown: 5 * time.Millisecond}.Clamp()
	client := New(SideClient, NewClientFlowID(), limits)
	t.Cleanup(func() { _ = client.Close() })
	if err := client.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := client.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	client.SetPacketMode()
	captures := make(map[string]*captureDispatchPath, 3)
	qualities := map[string]time.Duration{"a": 50 * time.Millisecond, "b": 10 * time.Millisecond, "c": 12 * time.Millisecond}
	for _, name := range []string{"a", "b", "c"} {
		path, peer := newMemoryPathPair()
		t.Cleanup(func() { _ = peer.Close() })
		path.quality = transport.PathQuality{RTT: qualities[name], At: now}
		capture := &captureDispatchPath{PathConn: path}
		captures[name] = capture
		if _, err := client.AttachPath(capture, transport.PathSpec{Transport: "memory", Weight: 1, Opts: map[string]string{"name": name}}); err != nil {
			t.Fatal(err)
		}
	}
	client.StartSelector(time.Millisecond)
	deadline := time.Now().Add(time.Second)
	for {
		desired, _, ok := client.localExecutionRuntime().selectedChild(ids["root"])
		if ok && desired == ids["aggregate"] {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("root selector did not choose bond aggregate; desired=%x", desired)
		}
		time.Sleep(time.Millisecond)
	}
	for i := 0; i < 4; i++ {
		if err := client.SendPacket([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	waitForCapturedFrames(t, captures, map[string]uint64{"a": 0, "b": 2, "c": 2})
}

func selectorObservation(id proto.TargetID, at time.Time, rtt time.Duration, loss uint16, goodput uint16) pathEvidenceObservation {
	return pathEvidenceObservation{
		targetID:      id,
		quality:       transport.PathQuality{RTT: rtt, At: at, LossPP: loss},
		loss:          loss,
		lossAt:        at,
		lossKnown:     true,
		probeLiveness: qualityStateFresh,
		goodput: speedEstimate{
			state: qualityStateFresh, bytesPerSecond: uint64(goodput),
			confidence: evidenceConfidenceFull, source: speedSourceDelivered,
			sampleTime: at, sampleCount: 1,
		},
		live: true,
	}
}

func TestRecursiveSelectorCompositeStaysHardFreshWithOneFreshLeaf(t *testing.T) {
	now := time.Unix(400, 0)
	for _, kind := range []proto.GraphNodeKind{proto.GraphNodeKindBond, proto.GraphNodeKindRace} {
		t.Run(kind.String(), func(t *testing.T) {
			groupName := "aggregate"
			if kind == proto.GraphNodeKindRace {
				groupName = "redundant"
			}
			manifest, ids := runtimeGraph(t,
				runtimeNode(proto.GraphNodeKindSelector, "root", groupName, "sibling"),
				runtimeNode(kind, groupName, "stale", "fresh"),
				runtimeNode(proto.GraphNodeKindPath, "stale"),
				runtimeNode(proto.GraphNodeKindPath, "fresh"),
				runtimeNode(proto.GraphNodeKindPath, "sibling"),
			)
			runtime := mustExecutionRuntime(t, manifest)
			if err := runtime.selectChild(ids["root"], ids[groupName]); err != nil {
				t.Fatal(err)
			}
			stale := selectorObservation(ids["stale"], now.Add(-time.Second), 100*time.Millisecond, 0, 1)
			stale.freshFor = 500 * time.Millisecond
			stale.probeLiveness = qualityStateStale
			fresh := selectorObservation(ids["fresh"], now, 100*time.Millisecond, 0, 1)
			sibling := selectorObservation(ids["sibling"], now, time.Millisecond, 0, 1)
			observations := map[proto.TargetID]pathEvidenceObservation{
				ids["stale"]: stale, ids["fresh"]: fresh, ids["sibling"]: sibling,
			}
			policy := selectorEvidencePolicy{
				latencyBandRatio: 0.25, latencyBandFloor: time.Millisecond, minimumConfidence: 1,
			}
			for i := 0; i < 2; i++ {
				decisions := runtime.selectorDecisions(
					proto.SenderDirectionClientToServer, observations, now.Add(time.Duration(i)), policy, time.Hour, time.Hour,
				)
				if len(decisions) != 0 {
					t.Fatalf("one stale %s leaf caused parent blackhole switch: %+v", kind, decisions)
				}
			}
		})
	}
}

func TestProbeFailureSelectionsParticipateInZombieProtection(t *testing.T) {
	newEngine := func(t *testing.T) (*Engine, map[string]proto.TargetID) {
		t.Helper()
		manifest, ids := runtimeGraph(t,
			runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
			runtimeNode(proto.GraphNodeKindPath, "a"),
			runtimeNode(proto.GraphNodeKindPath, "b"),
		)
		e := New(SideClient, NewClientFlowID(), Limits{ZombieMaxMigrations: 2, ZombieCooldown: time.Hour}.Clamp())
		t.Cleanup(func() { _ = e.Close() })
		if err := e.ConfigureLocalGraph(1, manifest); err != nil {
			t.Fatal(err)
		}
		if err := e.ConfigurePeerGraph(1, manifest); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"a", "b"} {
			path, peer := newMemoryPathPair()
			t.Cleanup(func() { _ = peer.Close() })
			if _, err := e.AttachPath(path, transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": name}}); err != nil {
				t.Fatal(err)
			}
		}
		return e, ids
	}

	t.Run("two unproductive probe moves trip", func(t *testing.T) {
		e, ids := newEngine(t)
		if err := e.selectLocalTarget(ids["root"], ids["b"], "probe-wire-timeout", policySelectionProbeFailure); err != nil {
			t.Fatal(err)
		}
		if err := e.selectLocalTarget(ids["root"], ids["a"], "probe-wire-timeout", policySelectionProbeFailure); err != nil {
			t.Fatal(err)
		}
		if !errors.Is(e.CloseErr(), ErrZombie) {
			t.Fatalf("close error=%v want %v", e.CloseErr(), ErrZombie)
		}
	})

	t.Run("payload resets probe move budget", func(t *testing.T) {
		e, ids := newEngine(t)
		if err := e.selectLocalTarget(ids["root"], ids["b"], "probe-wire-timeout", policySelectionProbeFailure); err != nil {
			t.Fatal(err)
		}
		e.markPayload()
		if err := e.selectLocalTarget(ids["root"], ids["a"], "probe-wire-timeout", policySelectionProbeFailure); err != nil {
			t.Fatal(err)
		}
		if errors.Is(e.CloseErr(), ErrZombie) {
			t.Fatal("payload did not reset probe-migration zombie budget")
		}
	})

	for _, cause := range []string{"probe-wire-timeout", "probe-starved-data", "probe-write-stalled"} {
		t.Run("external "+cause+" cannot authorize replay semantics", func(t *testing.T) {
			e, ids := newEngine(t)
			if err := e.SelectLocalTarget(ids["root"], ids["b"], cause); err != nil {
				t.Fatal(err)
			}
			if err := e.SelectLocalTarget(ids["root"], ids["a"], cause); err != nil {
				t.Fatal(err)
			}
			if errors.Is(e.CloseErr(), ErrZombie) {
				t.Fatal("untrusted cause string acquired factual-failure authority")
			}
		})
	}
}

func seedPathProbeSuccess(e *Engine, slot *pathSlot, at time.Time, rtt time.Duration) {
	generation := pathProbeGenerationForSlot(slot)
	e.probeMu.Lock()
	slot.probeEvidence.Store(&pathProbeEvidence{
		generation: generation, firstIssued: at, lastIssued: at, lastSuccess: at,
		lastLifecycle: pathProbeWriteCommitted, lastTransition: at,
		quality: transport.PathQuality{RTT: rtt, At: at}, issued: 1, succeeded: 1,
	})
	e.probeMu.Unlock()
}

func seedPathProbeWireTimeout(e *Engine, slot *pathSlot, at time.Time) {
	e.probeMu.Lock()
	evidence := slot.probeEvidence.Load()
	if evidence != nil && evidence.generation == pathProbeGenerationForSlot(slot) {
		next := *evidence
		next.lastWireTimeout = at
		next.lastLifecycle = pathProbeWireTimeout
		next.lastTransition = at
		next.timedOut++
		slot.probeEvidence.Store(&next)
	}
	e.probeMu.Unlock()
}
