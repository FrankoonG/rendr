package engine

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type blockingSelectorQualityPath struct {
	transport.PathConn
	calls atomic.Uint64
}

func (p *blockingSelectorQualityPath) Quality() transport.PathQuality {
	p.calls.Add(1)
	select {}
}

type cancellableSelectorQualityPath struct {
	transport.PathConn
	entered    chan struct{}
	exited     chan struct{}
	enterOnce  sync.Once
	exitOnce   sync.Once
	legacyCall atomic.Uint64
}

func (p *cancellableSelectorQualityPath) Quality() transport.PathQuality {
	p.legacyCall.Add(1)
	return transport.PathQuality{}
}

func (p *cancellableSelectorQualityPath) QualityContext(ctx context.Context) (transport.PathQuality, error) {
	p.enterOnce.Do(func() { close(p.entered) })
	<-ctx.Done()
	p.exitOnce.Do(func() { close(p.exited) })
	return transport.PathQuality{}, ctx.Err()
}

func policyEvidencePeakFixture(
	t *testing.T,
	prefix string,
) (*Engine, *policyTxUnitAckRecorder, proto.GraphNode, proto.GraphNode, proto.GraphNode, map[string]uint32, map[string]*policyTxUnitPath) {
	t.Helper()
	normal := policyTxUnitNode(proto.GraphNodeKindPath, prefix+"-normal")
	peak := policyTxUnitNode(proto.GraphNodeKindPath, prefix+"-peak")
	selector := policyTxUnitNode(proto.GraphNodeKindSelector, prefix+"-selector", normal.ID, peak.ID)
	selector.PeakCandidates = []proto.TargetID{peak.ID}
	manifest := proto.GraphManifest{RootID: selector.ID, Nodes: []proto.GraphNode{selector, normal, peak}}
	e, recorder, paths, handles := newPolicyTxUnitEngine(t, manifest, selector.ID, normal.Name, peak.Name)
	now := nowFn()
	handles[normal.Name].SetQuality(transport.PathQuality{RTT: time.Millisecond, LossPP: 1, At: now})
	handles[peak.Name].SetQuality(transport.PathQuality{RTT: 10 * time.Millisecond, LossPP: 1, At: now})
	return e, recorder, selector, normal, peak, paths, handles
}

func waitPolicyHandler(t *testing.T, done <-chan error, description string) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("%s did not finish", description)
		return nil
	}
}

func TestPolicyCommitQualityReentryRunsOutsidePolicyLocks(t *testing.T) {
	e, recorder, selector, normal, _, _, handles := policyEvidencePeakFixture(t, "quality-reentry")
	prepare := policyTxUnitClassPrepare(e, 0xb1, 0, selector.ID, true)
	prepared := policyTxUnitRequireAck(t, recorder, func() error { return e.handlePolicyPrepare(prepare) })

	reentered := make(chan error, 1)
	var once sync.Once
	handles["quality-reentry-peak"].SetQualityHook(func() {
		once.Do(func() {
			reentered <- e.SelectLocalTarget(selector.ID, normal.ID, "quality-reentry")
		})
	})
	commit := policyTxUnitCommit(t, prepare, prepared.ack.Generation, prepared.ack.ReservationID)
	done := make(chan error, 1)
	go func() { done <- e.handlePolicyCommit(commit) }()
	if err := waitPolicyHandler(t, reentered, "Quality policy reentry"); err != nil {
		t.Fatalf("Quality policy reentry: %v", err)
	}
	if err := waitPolicyHandler(t, done, "policy COMMIT after Quality reentry"); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyCommitAdmissionReentryRunsOutsidePolicyLocks(t *testing.T) {
	fixture := newPolicyTxUnitFixture(t)
	prepare := policyTxUnitPrepare(fixture.engine, 0xb2, 0, fixture.selectorID, fixture.targetB)
	prepared := policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyPrepare(prepare)
	})
	reentered := make(chan error, 1)
	var once sync.Once
	fixture.engine.SetPeerPolicyAdmission(func(_, _ proto.TargetID, _ string) error {
		once.Do(func() {
			reentered <- fixture.engine.SelectLocalTarget(
				fixture.selectorID, fixture.targetA, "admission-reentry",
			)
		})
		return nil
	})
	t.Cleanup(func() { fixture.engine.SetPeerPolicyAdmission(nil) })

	commit := policyTxUnitCommit(t, prepare, prepared.ack.Generation, prepared.ack.ReservationID)
	done := make(chan error, 1)
	go func() { done <- fixture.engine.handlePolicyCommit(commit) }()
	if err := waitPolicyHandler(t, reentered, "admission policy reentry"); err != nil {
		t.Fatalf("admission policy reentry: %v", err)
	}
	if err := waitPolicyHandler(t, done, "policy COMMIT after admission reentry"); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyCommitRechecksExpiryAfterExternalValidation(t *testing.T) {
	fixture := newPolicyTxUnitFixture(t)
	prepare := policyTxUnitPrepare(fixture.engine, 0xb3, 0, fixture.selectorID, fixture.targetB)
	prepared := policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyPrepare(prepare)
	})
	fixture.engine.SetPeerPolicyAdmission(func(_, _ proto.TargetID, _ string) error {
		fixture.engine.policyStateMu.Lock()
		if pending := fixture.engine.policyIncoming; pending != nil {
			pending.expires = time.Now().Add(-time.Second)
		}
		fixture.engine.policyStateMu.Unlock()
		return nil
	})
	t.Cleanup(func() { fixture.engine.SetPeerPolicyAdmission(nil) })

	commit := policyTxUnitCommit(t, prepare, prepared.ack.Generation, prepared.ack.ReservationID)
	final := policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyCommit(commit)
	})
	if final.ack.Code == proto.PolicyAckCodeAccept {
		t.Fatalf("expired policy COMMIT was accepted: %+v", final.ack)
	}
	generation, selection, pending, _ := policyTxUnitState(fixture.engine, fixture.selectorID)
	if generation != 0 || selection != fixture.targetA || pending {
		t.Fatalf("expired COMMIT changed owner: generation=%d selection=%x pending=%t", generation, selection, pending)
	}
}

func TestPeakDecisionRejectsCapturedEvidenceThatExpiresBeforeCommit(t *testing.T) {
	var clock atomic.Int64
	start := time.Unix(1_000, 0)
	clock.Store(start.UnixNano())
	previousNow := nowFn
	nowFn = func() time.Time { return time.Unix(0, clock.Load()) }
	t.Cleanup(func() { nowFn = previousNow })
	e, _, selector, normal, _, paths, _ := policyEvidencePeakFixture(t, "captured-at")

	e.pathsMu.RLock()
	for _, slot := range e.paths {
		if setter, ok := slot.conn.(interface{ SetQuality(transport.PathQuality) }); ok {
			setter.SetQuality(transport.PathQuality{RTT: time.Millisecond, LossPP: 1, At: start})
		}
	}
	e.pathsMu.RUnlock()
	e.peakTransferDecisionBeforeCommit = func() {
		clock.Store(start.Add(selectorEvidenceFreshFor + time.Second).UnixNano())
	}

	selected, err := e.SelectBestLocalPeakTransferTarget(selector.ID, nil, "captured-at-expired")
	if !errors.Is(err, ErrSelectorDecisionUnavailable) || selected != (proto.TargetID{}) {
		t.Fatalf("expired evidence selection=(%x,%v), want zero/%v", selected, err, ErrSelectorDecisionUnavailable)
	}
	if e.ActivePath() != paths[normal.Name] {
		t.Fatalf("expired evidence changed active path=%d want normal=%d", e.ActivePath(), paths[normal.Name])
	}
}

func TestPolicyCommitRechecksEvidenceFreshnessAtPublication(t *testing.T) {
	var clock atomic.Int64
	start := time.Now()
	clock.Store(start.UnixNano())
	previousNow := nowFn
	nowFn = func() time.Time { return time.Unix(0, clock.Load()) }
	t.Cleanup(func() { nowFn = previousNow })
	e, recorder, selector, normal, peak, _, _ := policyEvidencePeakFixture(t, "final-evidence")

	prepare := policyTxUnitPrepare(e, 0xb5, 0, selector.ID, peak.ID)
	prepared := policyTxUnitRequireAck(t, recorder, func() error { return e.handlePolicyPrepare(prepare) })
	execution := e.localExecutionRuntime()
	if execution == nil {
		t.Fatal("execution runtime is unavailable")
	}
	runtimeHeld := make(chan struct{})
	e.policyCommitBeforeOwnerLock = func() {
		execution.mu.Lock()
		close(runtimeHeld)
	}
	t.Cleanup(func() { e.policyCommitBeforeOwnerLock = nil })

	commit := policyTxUnitCommit(t, prepare, prepared.ack.Generation, prepared.ack.ReservationID)
	done := make(chan error, 1)
	go func() { done <- e.handlePolicyCommit(commit) }()
	select {
	case <-runtimeHeld:
	case <-time.After(time.Second):
		t.Fatal("COMMIT did not reach the post-validation hook")
	}

	deadline := time.Now().Add(time.Second)
	for {
		pathsHeld := !e.pathsMu.TryLock()
		if !pathsHeld {
			e.pathsMu.Unlock()
		}
		if pathsHeld {
			break
		}
		if time.Now().After(deadline) {
			execution.mu.Unlock()
			t.Fatal("COMMIT did not reach the final publication window")
		}
		time.Sleep(time.Millisecond)
	}
	clock.Store(start.Add(selectorEvidenceCommitLease + time.Second).UnixNano())
	execution.mu.Unlock()

	final := policyTxUnitRequireAck(t, recorder, func() error {
		return waitPolicyHandler(t, done, "policy COMMIT after evidence expiry")
	})
	if final.ack.Code == proto.PolicyAckCodeAccept {
		t.Fatalf("COMMIT accepted evidence that expired before publication: %+v", final.ack)
	}
	generation, selection, pending, _ := policyTxUnitState(e, selector.ID)
	if generation != 0 || selection != normal.ID || pending {
		t.Fatalf("expired evidence changed owner: generation=%d selection=%x pending=%t", generation, selection, pending)
	}
}

func TestInactiveExactChildPrepareFreezesTopologyWithoutCutover(t *testing.T) {
	pathA := policyTxUnitNode(proto.GraphNodeKindPath, "prepare-freeze-a")
	pathB := policyTxUnitNode(proto.GraphNodeKindPath, "prepare-freeze-b")
	pathC := policyTxUnitNode(proto.GraphNodeKindPath, "prepare-freeze-c")
	inner := policyTxUnitNode(proto.GraphNodeKindSelector, "prepare-freeze-inner", pathB.ID, pathC.ID)
	root := policyTxUnitNode(proto.GraphNodeKindSelector, "prepare-freeze-root", pathA.ID, inner.ID)
	manifest := proto.GraphManifest{
		RootID: root.ID,
		Nodes:  []proto.GraphNode{root, inner, pathA, pathB, pathC},
	}
	e, recorder, _, _ := newPolicyTxUnitEngine(
		t, manifest, root.ID, pathA.Name, pathB.Name, pathC.Name,
	)
	prepare := policyTxUnitPrepare(e, 0xb6, 0, inner.ID, pathC.ID)
	policyTxUnitRequireAck(t, recorder, func() error { return e.handlePolicyPrepare(prepare) })
	e.policyStateMu.Lock()
	pending := e.policyIncoming
	e.policyStateMu.Unlock()
	if pending == nil {
		t.Fatal("accepted PREPARE did not install a reservation")
	}
	if pending.decisionRequiresCutover {
		t.Fatal("inactive exact-child reservation incorrectly owns a cutover")
	}
	if !pending.decisionEvidence.bound() ||
		pending.decisionEvidence.topologyEpoch != e.currentPathTopologyEpoch() {
		t.Fatalf(
			"inactive exact-child evidence=%+v current topology=%d",
			pending.decisionEvidence, e.currentPathTopologyEpoch(),
		)
	}
}

func TestPeakTransferDoesNotRenewStaleTransportLossWithRTTProbe(t *testing.T) {
	e, _, selector, _, peak, _, handles := policyEvidencePeakFixture(t, "loss-source")
	now := time.Now()
	handles[peak.Name].SetQuality(transport.PathQuality{
		RTT: 10 * time.Millisecond, LossPP: 500, At: now.Add(-time.Hour),
	})
	e.pathsMu.RLock()
	var peakSlot *pathSlot
	for _, slot := range e.paths {
		if slot.localTXTargetID == peak.ID {
			peakSlot = slot
			break
		}
	}
	e.pathsMu.RUnlock()
	if peakSlot == nil {
		t.Fatal("peak slot is unavailable")
	}
	seedPathProbeSuccess(e, peakSlot, now, 10*time.Millisecond)

	ranked, err := e.RankLocalPeakTransferTargets(selector.ID)
	if err != nil || len(ranked) != 1 || ranked[0] != peak.ID {
		t.Fatalf("fresh probe-owned loss did not supersede stale transport loss: ranked=%x err=%v", ranked, err)
	}
}

func TestPeakTransferFailsClosedWhenTimingHasNoLossSample(t *testing.T) {
	e, _, selector, _, peak, _, handles := policyEvidencePeakFixture(t, "unknown-loss")
	handles[peak.Name].SetQuality(transport.PathQuality{})
	now := time.Now()
	e.pathsMu.RLock()
	var peakSlot *pathSlot
	for _, slot := range e.paths {
		if slot.localTXTargetID == peak.ID {
			peakSlot = slot
			break
		}
	}
	e.pathsMu.RUnlock()
	if peakSlot == nil {
		t.Fatal("peak slot is unavailable")
	}
	peakSlot.probeEvidence.Store(&pathProbeEvidence{
		generation:  pathProbeGenerationForSlot(peakSlot),
		lastSuccess: now,
		quality:     transport.PathQuality{RTT: time.Millisecond, At: now},
	})

	if ranked, err := e.RankLocalPeakTransferTargets(selector.ID); err == nil || len(ranked) != 0 {
		t.Fatalf("unknown loss was admitted: ranked=%x err=%v", ranked, err)
	}
}

func TestExplicitPeakCommitRejectsEndpointGenerationChangedByAdmission(t *testing.T) {
	e, recorder, selector, _, peak, paths, _ := policyEvidencePeakFixture(t, "explicit-generation")
	prepare := policyTxUnitPrepare(e, 0xb4, 0, selector.ID, peak.ID)
	prepared := policyTxUnitRequireAck(t, recorder, func() error { return e.handlePolicyPrepare(prepare) })
	e.SetPeerPolicyAdmission(func(_, _ proto.TargetID, _ string) error {
		e.pathsMu.Lock()
		slot := e.paths[paths[peak.Name]]
		slot.probeEndpointGen.Add(1)
		e.advancePathTopologyEpochLocked()
		e.pathsMu.Unlock()
		return nil
	})
	t.Cleanup(func() { e.SetPeerPolicyAdmission(nil) })

	commit := policyTxUnitCommit(t, prepare, prepared.ack.Generation, prepared.ack.ReservationID)
	final := policyTxUnitRequireAck(t, recorder, func() error { return e.handlePolicyCommit(commit) })
	if final.ack.Code == proto.PolicyAckCodeAccept {
		t.Fatalf("explicit peak COMMIT crossed endpoint generation: %+v", final.ack)
	}
}

func TestBlockedQualityCannotPreventEngineQuiescence(t *testing.T) {
	base, peer := newMemoryPathPair()
	path := &blockingSelectorQualityPath{PathConn: base}
	e, slot := newSelectorQualityEngine(t, path)
	if _, ok := e.selectorEvidenceSnapshot(); !ok {
		t.Fatal("legacy-quality evidence snapshot was incoherent")
	}
	slot.qualityObserverMu.Lock()
	observerStarted := slot.qualityObserverStarted
	slot.qualityObserverMu.Unlock()
	if observerStarted {
		t.Fatal("legacy Quality-only path started a quality observer")
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	_ = peer.Close()
	if calls := path.calls.Load(); calls != 0 {
		t.Fatalf("legacy blocking Quality calls=%d want zero", calls)
	}
}

func TestLegacyQualityOnlyRepeatedTeardownHasZeroGoroutineSlope(t *testing.T) {
	const sessionsPerBatch = 64
	runBatch := func() {
		for i := 0; i < sessionsPerBatch; i++ {
			base, peer := newMemoryPathPair()
			path := &blockingSelectorQualityPath{PathConn: base}
			e, slot := newSelectorQualityEngine(t, path)
			if _, ok := e.selectorEvidenceSnapshot(); !ok {
				t.Fatalf("session %d evidence snapshot was incoherent", i)
			}
			slot.qualityObserverMu.Lock()
			observerStarted := slot.qualityObserverStarted
			slot.qualityObserverMu.Unlock()
			if observerStarted {
				t.Fatalf("session %d started a legacy quality observer", i)
			}
			if err := e.Close(); err != nil {
				t.Fatalf("session %d Close: %v", i, err)
			}
			_ = peer.Close()
			if calls := path.calls.Load(); calls != 0 {
				t.Fatalf("session %d legacy Quality calls=%d want zero", i, calls)
			}
		}
	}

	baseline := settledGoroutineCount()
	runBatch()
	first := settledGoroutineCount()
	runBatch()
	second := settledGoroutineCount()
	if first > baseline+2 || second > first+2 {
		t.Fatalf(
			"legacy teardown goroutines baseline/first/second=%d/%d/%d",
			baseline, first, second,
		)
	}
}

func TestContextQualityObserverIsCanceledAndReapedByClose(t *testing.T) {
	base, peer := newMemoryPathPair()
	path := &cancellableSelectorQualityPath{
		PathConn: base,
		entered:  make(chan struct{}),
		exited:   make(chan struct{}),
	}
	e, _ := newSelectorQualityEngine(t, path)
	_, _ = e.selectorEvidenceSnapshot()
	select {
	case <-path.entered:
	case <-time.After(time.Second):
		_ = e.Close()
		_ = peer.Close()
		t.Fatal("QualityContext was not called")
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-path.exited:
	case <-time.After(time.Second):
		_ = peer.Close()
		t.Fatal("Close did not cancel and reap QualityContext")
	}
	_ = peer.Close()
	if calls := path.legacyCall.Load(); calls != 0 {
		t.Fatalf("legacy Quality was called %d times", calls)
	}
}

func TestPublicPathQualityProjectsFreshCurrentGenerationProbe(t *testing.T) {
	base, peer := newMemoryPathPair()
	path := &blockingSelectorQualityPath{PathConn: base}
	e, slot := newSelectorQualityEngine(t, path)
	now := time.Now()
	slot.probeEvidence.Store(&pathProbeEvidence{
		generation:     pathProbeGenerationForSlot(slot),
		firstIssued:    now,
		lastIssued:     now,
		lastSuccess:    now,
		lastLifecycle:  pathProbeWriteCommitted,
		lastTransition: now,
		quality:        transport.PathQuality{RTT: 7 * time.Millisecond, Jitter: time.Millisecond, At: now},
		issued:         1,
		succeeded:      1,
	})

	paths := e.Paths()
	if len(paths) != 1 || paths[0].Quality.RTT != 7*time.Millisecond ||
		paths[0].Quality.Jitter != time.Millisecond || !paths[0].Quality.At.Equal(now) {
		t.Fatalf("Paths quality=%+v, want fresh engine probe", paths)
	}
	topology := e.TopologySnapshot()
	if len(topology.Paths) != 1 || topology.Paths[0].Quality != paths[0].Quality {
		t.Fatalf("TopologySnapshot quality=%+v, want Paths projection %+v", topology.Paths, paths[0].Quality)
	}
	if calls := path.calls.Load(); calls != 0 {
		t.Fatalf("public projection called legacy Quality %d times", calls)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	_ = peer.Close()
}

func TestPublicPathQualityRejectsStaleOrReplacedProbe(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*pathSlot, time.Time)
	}{
		{
			name: "stale",
			mutate: func(slot *pathSlot, now time.Time) {
				stale := now.Add(-time.Hour)
				slot.probeEvidence.Store(&pathProbeEvidence{
					generation: pathProbeGenerationForSlot(slot), lastSuccess: stale,
					quality: transport.PathQuality{RTT: time.Millisecond, At: stale},
				})
			},
		},
		{
			name: "replaced-generation",
			mutate: func(slot *pathSlot, now time.Time) {
				slot.probeEvidence.Store(&pathProbeEvidence{
					generation: pathProbeGenerationForSlot(slot), lastSuccess: now,
					quality: transport.PathQuality{RTT: time.Millisecond, At: now},
				})
				slot.probeEndpointGen.Add(1)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			base, peer := newMemoryPathPair()
			path := &blockingSelectorQualityPath{PathConn: base}
			e, slot := newSelectorQualityEngine(t, path)
			test.mutate(slot, time.Now())
			paths := e.Paths()
			if len(paths) != 1 || paths[0].Quality != (transport.PathQuality{}) {
				t.Fatalf("invalid probe leaked into Paths: %+v", paths)
			}
			if calls := path.calls.Load(); calls != 0 {
				t.Fatalf("public projection called legacy Quality %d times", calls)
			}
			if err := e.Close(); err != nil {
				t.Fatal(err)
			}
			_ = peer.Close()
		})
	}
}

func newSelectorQualityEngine(t *testing.T, path transport.PathConn) (*Engine, *pathSlot) {
	t.Helper()
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "blocked-quality-root", "blocked-quality-path"),
		runtimeNode(proto.GraphNodeKindPath, "blocked-quality-path"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: time.Second}.Clamp())
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	pathID := attachFixturePath(
		t, e, path,
		transport.PathSpec{Transport: "memory", Address: "blocked-quality"},
		ids["blocked-quality-path"],
	)
	e.pathsMu.RLock()
	slot := e.paths[pathID]
	e.pathsMu.RUnlock()
	if slot == nil {
		t.Fatal("attached quality path is unavailable")
	}
	return e, slot
}

func settledGoroutineCount() int {
	minimum := int(^uint(0) >> 1)
	for i := 0; i < 5; i++ {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
		if count := runtime.NumGoroutine(); count < minimum {
			minimum = count
		}
	}
	return minimum
}

func promptTestQualityContext(
	ctx context.Context,
	quality func() transport.PathQuality,
) (transport.PathQuality, error) {
	select {
	case <-ctx.Done():
		return transport.PathQuality{}, ctx.Err()
	default:
		return quality(), nil
	}
}

func (p *memoryPathConn) QualityContext(ctx context.Context) (transport.PathQuality, error) {
	return promptTestQualityContext(ctx, p.Quality)
}

func (p *policyTxUnitPath) QualityContext(ctx context.Context) (transport.PathQuality, error) {
	return promptTestQualityContext(ctx, p.Quality)
}

func (p *probeQualityPath) QualityContext(ctx context.Context) (transport.PathQuality, error) {
	return promptTestQualityContext(ctx, p.Quality)
}

func (p *selectorReentrantQualityPath) QualityContext(ctx context.Context) (transport.PathQuality, error) {
	return promptTestQualityContext(ctx, p.Quality)
}

func (p *observationBarrierPath) QualityContext(ctx context.Context) (transport.PathQuality, error) {
	return promptTestQualityContext(ctx, p.Quality)
}

func (p *qualityDeathPath) QualityContext(ctx context.Context) (transport.PathQuality, error) {
	return promptTestQualityContext(ctx, p.Quality)
}

func (p *captureDispatchPath) QualityContext(ctx context.Context) (transport.PathQuality, error) {
	reader, ok := p.PathConn.(transport.PathQualityReader)
	if !ok {
		return transport.PathQuality{}, errors.New("wrapped test path has no cancellable quality source")
	}
	return reader.QualityContext(ctx)
}
