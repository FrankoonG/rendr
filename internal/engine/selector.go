package engine

import (
	"fmt"
	"time"

	"github.com/FrankoonG/rendr/proto"
)

var (
	errStaleSelectorEvidence  = fmt.Errorf("%w: topology changed", ErrSelectorDecisionUnavailable)
	errNoAdmissiblePeakTarget = fmt.Errorf("%w: peak class has no admissible target", ErrSelectorDecisionUnavailable)
)

// selector is the per-Engine selector-mode scheduler state. It is created
// only when StartSelector is called; otherwise nil (and the engine
// behaves like fixed-path: only death-driven migration fires).
type selector struct {
	stop chan struct{}
	done chan struct{}
}

// StartSelector arms the selector-mode quality scheduler. tickEvery sets
// the cadence at which the engine re-scores paths; pass 0 for a
// 200ms default. The scheduler runs until Engine.Close.
//
// The runtime configuration owns latency-band, dwell and cooldown tuning. A
// graph without a selector has no scheduler to arm.
func (e *Engine) StartSelector(tickEvery time.Duration) {
	runtime := e.localExecutionRuntime()
	if runtime == nil || runtime.plan == nil || !runtime.plan.hasKind(proto.GraphNodeKindSelector) {
		return
	}
	if tickEvery <= 0 {
		tickEvery = 200 * time.Millisecond
	}
	p := &selector{
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	e.selectorMu.Lock()
	if e.selector != nil {
		e.selectorMu.Unlock()
		return
	}
	e.selector = p
	e.selectorMu.Unlock()

	e.probeStartOnce.Do(func() { close(e.probeStart) })
	go p.loop(e, tickEvery)
}

func (p *selector) loop(e *Engine, tick time.Duration) {
	defer close(p.done)
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-e.closed:
			return
		case <-t.C:
			p.evaluate(e)
		}
	}
}

// evaluate runs one tick of the scheduler.
func (p *selector) evaluate(e *Engine) {
	runtime := e.localExecutionRuntime()
	if runtime == nil {
		return
	}
	p.evaluateRecursive(e, runtime)
}

func (p *selector) evaluateRecursive(e *Engine, runtime *executionRuntime) {
	decisions, now := p.recursiveDecisions(e, runtime)
	p.applyRecursiveDecisions(e, runtime, decisions, now)
}

func (p *selector) recursiveDecisions(e *Engine, runtime *executionRuntime) ([]selectorDecision, time.Time) {
	policy := e.selectorEvidencePolicy()
	var decisions []selectorDecision
	var evaluatedAt time.Time
	for _, selectorID := range runtime.selectorIDs() {
		view, ok := e.selectorEvidenceSnapshotForSelector(runtime, selectorID)
		if !ok {
			continue
		}
		selectorDecisions := runtime.selectorDecisionFor(
			selectorID,
			senderDirection(e.side),
			view.observations,
			view.attached,
			view.capturedAt,
			policy,
			e.limits.SelectorDwell,
			e.limits.SelectorCooldown,
		)
		for i := range selectorDecisions {
			selectorDecisions[i].topologyEpoch = view.topologyEpoch
			selectorDecisions[i].evidence = view.commitEvidenceForSelector(
				runtime.plan, selectorID, selectorDecisions[i].selectorState,
			)
		}
		decisions = append(decisions, selectorDecisions...)
		evaluatedAt = view.capturedAt
	}
	return decisions, evaluatedAt
}

func (e *Engine) selectorEvidencePolicy() selectorEvidencePolicy {
	return selectorEvidencePolicy{
		latencyBandRatio:  e.limits.SelectorHysteresis,
		latencyBandFloor:  e.limits.SelectorLatencyFloor,
		minimumConfidence: 1,
	}
}

// SelectBestLocalTarget chooses the best immediate child in the requested
// peak class using the sender owner's recursive quality evidence. It is a
// read-only decision; callers still commit the returned target through the
// policy transaction path.
func (e *Engine) SelectBestLocalTarget(selectorID proto.TargetID, peak bool) (proto.TargetID, error) {
	ranked, err := e.RankLocalSelectorClass(selectorID, peak)
	if err != nil {
		return proto.TargetID{}, err
	}
	return ranked[0], nil
}

// RankLocalSelectorClass returns fresh healthy immediate children in the same
// order the local sender's selector comparator would choose them.
func (e *Engine) RankLocalSelectorClass(selectorID proto.TargetID, peak bool) ([]proto.TargetID, error) {
	ranked, _, err := e.rankLocalSelectorClass(selectorID, peak, nil, false)
	if err != nil {
		return nil, err
	}
	if len(ranked) == 0 {
		return nil, fmt.Errorf("engine: selector class has no fresh healthy target")
	}
	return ranked, nil
}

// RankLocalPeakTransferTargets returns fresh healthy immediate peak children
// after applying PeakTransfer's stricter loss and jitter admission. Ranking
// and admission share one evidence snapshot so a freshness boundary cannot
// split one decision into contradictory observations.
func (e *Engine) RankLocalPeakTransferTargets(
	selectorID proto.TargetID,
	excluded ...proto.TargetID,
) ([]proto.TargetID, error) {
	excludedSet := selectorTargetSet(excluded)
	ranked, _, err := e.rankLocalSelectorClass(selectorID, true, excludedSet, true)
	if err != nil {
		return nil, err
	}
	if len(ranked) == 0 {
		return nil, errNoAdmissiblePeakTarget
	}
	return ranked, nil
}

func (e *Engine) rankLocalSelectorClass(
	selectorID proto.TargetID,
	peak bool,
	excluded map[proto.TargetID]struct{},
	peakTransferAdmission bool,
) ([]proto.TargetID, selectorEvidenceView, error) {
	runtime := e.localExecutionRuntime()
	if runtime == nil {
		return nil, selectorEvidenceView{}, errExecutionRuntimeNotConfigured
	}
	view, ok := e.selectorEvidenceSnapshotForSelector(runtime, selectorID)
	if !ok {
		return nil, selectorEvidenceView{}, fmt.Errorf("%w: evidence changed during snapshot", ErrSelectorDecisionUnavailable)
	}
	ranked, state := runtime.rankSelectorClassTargetsWithAdmissionAtState(
		selectorID,
		peak,
		senderDirection(e.side),
		view.observations,
		view.capturedAt,
		e.selectorEvidencePolicy(),
		peakTransferAdmission,
		excluded,
	)
	view.selectorState = state
	return ranked, view, nil
}

// SelectBestLocalPeakTransferTarget ranks only currently admissible,
// non-suppressed peak targets and binds the resulting commit to that exact
// physical topology epoch. A same-target endpoint replacement therefore
// invalidates the decision instead of inheriting its predecessor's evidence.
func (e *Engine) SelectBestLocalPeakTransferTarget(
	selectorID proto.TargetID,
	excluded []proto.TargetID,
	cause string,
) (proto.TargetID, error) {
	excludedSet := selectorTargetSet(excluded)
	ranked, view, err := e.rankLocalSelectorClass(selectorID, true, excludedSet, true)
	if err != nil {
		return proto.TargetID{}, err
	}
	if len(ranked) == 0 {
		return proto.TargetID{}, errNoAdmissiblePeakTarget
	}
	if hook := e.peakTransferDecisionBeforeCommit; hook != nil {
		hook()
	}
	targetID := ranked[0]
	if err := e.selectLocalTargetCommittedAtEvidence(
		selectorID, targetID, cause, policySelectionPeakPromote,
		e.selectorEvidenceCommitFor(view, selectorID), nil,
	); err != nil {
		return proto.TargetID{}, err
	}
	return targetID, nil
}

// SelectBestLocalPeakTransferNormalTarget commits the best normal child using
// the same topology-bound decision contract as peak promotion.
func (e *Engine) SelectBestLocalPeakTransferNormalTarget(
	selectorID proto.TargetID,
	cause string,
) (proto.TargetID, error) {
	ranked, view, err := e.rankLocalSelectorClass(selectorID, false, nil, false)
	if err != nil {
		return proto.TargetID{}, err
	}
	if len(ranked) == 0 {
		return proto.TargetID{}, fmt.Errorf(
			"%w: normal class has no fresh healthy target",
			ErrSelectorDecisionUnavailable,
		)
	}
	if hook := e.peakTransferDecisionBeforeCommit; hook != nil {
		hook()
	}
	targetID := ranked[0]
	if err := e.selectLocalTargetCommittedAtEvidence(
		selectorID, targetID, cause, policySelectionPeakReturn,
		e.selectorEvidenceCommitFor(view, selectorID), nil,
	); err != nil {
		return proto.TargetID{}, err
	}
	return targetID, nil
}

func selectorTargetSet(targets []proto.TargetID) map[proto.TargetID]struct{} {
	if len(targets) == 0 {
		return nil
	}
	set := make(map[proto.TargetID]struct{}, len(targets))
	for _, targetID := range targets {
		if targetID != (proto.TargetID{}) {
			set[targetID] = struct{}{}
		}
	}
	return set
}

// LocalTargetInHealthySelectorClass verifies an exact sender-owned target
// against the same recursive evidence and class semantics used for ranking.
func (e *Engine) LocalTargetInHealthySelectorClass(selectorID, targetID proto.TargetID, peak bool) bool {
	ranked, err := e.RankLocalSelectorClass(selectorID, peak)
	if err != nil {
		return false
	}
	for _, candidate := range ranked {
		if candidate == targetID {
			return true
		}
	}
	return false
}

// LocalPeakTransferTargetHealthy applies PeakTransfer's bounded loss and
// jitter admission to one exact immediate peak child using the same recursive
// sender-owned evidence as selector ranking.
func (e *Engine) LocalPeakTransferTargetHealthy(selectorID, targetID proto.TargetID) bool {
	ranked, err := e.RankLocalPeakTransferTargets(selectorID)
	if err != nil {
		return false
	}
	for _, candidate := range ranked {
		if candidate == targetID {
			return true
		}
	}
	return false
}

// SelectorSelection returns one sender-owned selector's committed logical
// state. Generation changes only when that selector changes immediate child;
// nested selector activity and physical reattachment do not invalidate it.
func (e *Engine) SelectorSelection(selectorID proto.TargetID) (desired, effective proto.TargetID, generation uint64, ok bool) {
	runtime := e.localExecutionRuntime()
	if runtime == nil {
		return proto.TargetID{}, proto.TargetID{}, 0, false
	}
	return runtime.selectorSelection(selectorID)
}

// LocalTargetTiming returns fresh aggregate latency evidence for one target.
// PeakTransfer uses it only to size an internal observation window.
func (e *Engine) LocalTargetTiming(targetID proto.TargetID) (rtt, jitter time.Duration, ok bool) {
	runtime := e.localExecutionRuntime()
	if runtime == nil || runtime.plan == nil {
		return 0, 0, false
	}
	view, stable := e.selectorEvidenceSnapshot()
	if !stable {
		return 0, 0, false
	}
	runtime.mu.Lock()
	evidence := runtime.aggregateTargetEvidenceLocked(
		targetID,
		senderDirection(e.side),
		view.observations,
		make(map[proto.TargetID]schedulingEvidence, len(runtime.plan.nodes)),
		view.capturedAt,
	)
	runtime.mu.Unlock()
	if !evidence.latency.fresh(1) || evidence.latency.ewma <= 0 {
		return 0, 0, false
	}
	return evidence.latency.ewma, evidence.latency.jitter, true
}

// PeerTargetTiming returns conservative fresh carrier timing for one immediate
// child of the peer sender's root selector. The local endpoint cannot execute
// the peer graph, so a composite target uses the slowest live descendant; this
// only widens a passive observation window and never grants routing authority.
func (e *Engine) PeerTargetTiming(targetID proto.TargetID) (rtt, jitter time.Duration, ok bool) {
	binding := e.peerGraphBinding()
	if !binding.rootTracksWireAttribution || targetID == (proto.TargetID{}) {
		return 0, 0, false
	}
	topologyEpoch := e.currentPathTopologyEpoch()
	e.pathsMu.RLock()
	if e.currentPathTopologyEpoch() != topologyEpoch {
		e.pathsMu.RUnlock()
		return 0, 0, false
	}
	slots := make([]*pathSlot, 0, len(e.paths)+len(e.stagedPaths)+len(e.retainedPaths))
	for _, set := range []map[uint32]*pathSlot{e.paths, e.stagedPaths, e.retainedPaths} {
		for _, slot := range set {
			owner, owned := binding.rootTargetForLeaf(slot.peerTXTargetID)
			if !owned || owner != targetID {
				continue
			}
			slots = append(slots, slot)
		}
	}
	e.pathsMu.RUnlock()
	_ = observePathQualities(slots, selectorQualityObservationBudget)
	now := nowFn()
	for _, slot := range slots {
		quality := slot.latestSchedulingQuality(now, e.limits.ProbeInterval)
		if quality.RTT <= 0 {
			continue
		}
		if !ok || 4*quality.RTT+2*quality.Jitter > 4*rtt+2*jitter {
			rtt, jitter, ok = quality.RTT, quality.Jitter, true
		}
	}
	if e.currentPathTopologyEpoch() != topologyEpoch {
		return 0, 0, false
	}
	return rtt, jitter, ok
}

func (p *selector) applyRecursiveDecisions(
	e *Engine,
	runtime *executionRuntime,
	decisions []selectorDecision,
	now time.Time,
) (pathDeathApplied bool) {
	return p.applyRecursiveDecisionsWithReplay(e, runtime, decisions, now, true)
}

func (p *selector) applyRecursiveDecisionsWithReplay(
	e *Engine,
	runtime *executionRuntime,
	decisions []selectorDecision,
	now time.Time,
	replayPathDeath bool,
) (pathDeathApplied bool) {
	for _, decision := range decisions {
		origin := decision.origin
		if !replayPathDeath && origin == policySelectionPathDeath {
			origin = policySelectionPathDeathReplayed
		}
		evidence := decision.evidence
		if !evidence.bound() && decision.topologyEpoch != 0 {
			evidence = selectorEvidenceCommit{
				topologyEpoch: decision.topologyEpoch,
				selectorState: decision.selectorState,
			}
		}
		err := e.selectLocalTargetCommittedAtEvidence(
			decision.selectorID,
			decision.targetID,
			decision.cause,
			origin,
			evidence,
			func() {
				if hook := e.selectorDecisionAfterCommit; hook != nil {
					hook()
				}
				runtime.noteSelectorDecision(decision, now)
			},
		)
		if err == nil {
			if decision.origin == policySelectionPathDeath {
				pathDeathApplied = true
			}
		}
	}
	return pathDeathApplied
}

const selectorPathDeathAlignmentAttempts = 8

func (p *selector) reconcilePathDeathProjection(
	e *Engine,
	runtime *executionRuntime,
	replayPathDeath bool,
) bool {
	applied := false
	for attempt := 0; attempt < selectorPathDeathAlignmentAttempts; attempt++ {
		decisions, now := e.pathDeathAlignmentDecisions(runtime)
		if len(decisions) == 0 {
			return applied
		}
		if p.applyRecursiveDecisionsWithReplay(e, runtime, decisions, now, replayPathDeath) {
			applied = true
			replayPathDeath = false
		}
	}
	return applied
}
