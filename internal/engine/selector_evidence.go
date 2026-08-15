package engine

import (
	"fmt"
	"sort"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

const selectorEvidenceFreshFor = 5 * time.Second
const minimumSelectorProbeFreshFor = 500 * time.Millisecond
const maximumSelectorProbeFreshFor = 4 * time.Second
const selectorGoodputDwellGrace = time.Second
const maximumSelectorGoodputHold = 10 * time.Second
const selectorEvidenceCommitLease = minimumSelectorProbeFreshFor
const peakTransferMaximumLossPP = 50
const peakTransferMaximumJitter = 200 * time.Millisecond

type pathEvidenceObservation struct {
	targetID       proto.TargetID
	quality        transport.PathQuality
	loss           uint16
	lossAt         time.Time
	lossKnown      bool
	freshFor       time.Duration
	probeLiveness  qualityState
	probeLifecycle pathProbeLifecycle
	probeFailure   pathProbeFailure
	dataProgress   uint64
	unexpectedDup  uint64
	goodput        speedEstimate
	live           bool
	gen            uint64
	topologyEpoch  uint64
}

type selectorDecision struct {
	selectorID    proto.TargetID
	targetID      proto.TargetID
	cause         string
	origin        policySelectionOrigin
	topologyEpoch uint64
	evidence      selectorEvidenceCommit
}

type selectorEvidenceView struct {
	observations  map[proto.TargetID]pathEvidenceObservation
	topologyEpoch uint64
	capturedAt    time.Time
	validUntil    time.Time
	generations   []selectorPathGenerationBinding
}

type selectorPathGenerationBinding struct {
	targetID        proto.TargetID
	pathID          uint32
	owner           uint64
	slotGeneration  uint64
	probeGeneration pathProbeGeneration
}

type selectorEvidenceCommit struct {
	topologyEpoch uint64
	capturedAt    time.Time
	validUntil    time.Time
	generations   []selectorPathGenerationBinding
}

type selectorPathEvidenceSample struct {
	slot             *pathSlot
	targetID         proto.TargetID
	slotGeneration   uint64
	probeGeneration  pathProbeGeneration
	quality          transport.PathQuality
	probeEvidence    pathProbeEvidence
	hasProbeEvidence bool
	probeStatus      pathProbeStatus
	dataProgress     uint64
	unexpectedDup    uint64
}

func (e *Engine) selectorEvidenceObservations() map[proto.TargetID]pathEvidenceObservation {
	view, ok := e.selectorEvidenceSnapshot()
	if !ok {
		return nil
	}
	return view.observations
}

func (e *Engine) selectorEvidenceSnapshot() (selectorEvidenceView, bool) {
	for attempt := 0; attempt < 3; attempt++ {
		view, ok := e.selectorEvidenceSnapshotOnce()
		if ok {
			return view, true
		}
	}
	return selectorEvidenceView{}, false
}

func (e *Engine) selectorEvidenceSnapshotOnce() (selectorEvidenceView, bool) {
	topologyEpoch := e.currentPathTopologyEpoch()
	e.pathsMu.RLock()
	if e.currentPathTopologyEpoch() != topologyEpoch {
		e.pathsMu.RUnlock()
		return selectorEvidenceView{}, false
	}
	latest := make(map[proto.TargetID]selectorPathEvidenceSample, len(e.paths))
	for _, slot := range e.paths {
		if slot.localTXTargetID == (proto.TargetID{}) {
			continue
		}
		previous, exists := latest[slot.localTXTargetID]
		if exists && previous.slotGeneration > slot.gen {
			continue
		}
		latest[slot.localTXTargetID] = selectorPathEvidenceSample{
			slot:            slot,
			targetID:        slot.localTXTargetID,
			slotGeneration:  slot.gen,
			probeGeneration: pathProbeGenerationForSlot(slot),
			dataProgress:    slot.dataDispatches.Load(),
			unexpectedDup:   slot.recvDups.Load(),
		}
	}
	e.pathsMu.RUnlock()

	samples := make([]selectorPathEvidenceSample, 0, len(latest))
	for _, sample := range latest {
		samples = append(samples, sample)
	}
	slots := make([]*pathSlot, 0, len(samples))
	for i := range samples {
		slots = append(slots, samples[i].slot)
	}
	qualities := observePathQualities(slots, selectorQualityObservationBudget)
	for i := range samples {
		samples[i].quality = qualities[samples[i].slot]
	}
	capturedAt := nowFn()

	generations := make(map[*pathSlot]pathProbeGeneration, len(samples))
	for i := range samples {
		generations[samples[i].slot] = samples[i].probeGeneration
	}
	e.probeMu.Lock()
	e.expirePathProbesLocked(capturedAt)
	probeStable := true
	for i := range samples {
		if pathProbeGenerationForSlot(samples[i].slot) != samples[i].probeGeneration {
			probeStable = false
			break
		}
	}
	if probeStable {
		for _, observation := range e.probeOutstanding {
			expected, tracked := generations[observation.slot]
			if !tracked || observation.generation != expected {
				continue
			}
			candidate := pathProbeStatus{lifecycle: observation.lifecycle}
			switch observation.lifecycle {
			case pathProbeDataStarved:
				candidate.failure = pathProbeFailureDataStarved
			case pathProbeWriteStalled:
				candidate.failure = pathProbeFailureWriteStalled
			}
			for i := range samples {
				if samples[i].slot == observation.slot &&
					pathProbeStatusPriority(candidate) > pathProbeStatusPriority(samples[i].probeStatus) {
					samples[i].probeStatus = candidate
					break
				}
			}
		}
		for i := range samples {
			evidence := samples[i].slot.probeEvidence.Load()
			if evidence == nil || evidence.generation != samples[i].probeGeneration {
				continue
			}
			samples[i].probeEvidence = *evidence
			samples[i].hasProbeEvidence = true
		}
	}
	e.probeMu.Unlock()
	if !probeStable {
		return selectorEvidenceView{}, false
	}

	goodput, ok := e.targetDeliverySpeedsAtEpoch(capturedAt, topologyEpoch)
	if !ok {
		return selectorEvidenceView{}, false
	}

	// Serialize the final validation with every path publication/replacement.
	// A mutation may update a generation before it publishes the new epoch, so
	// an atomic epoch check alone is not a sufficient read barrier.
	e.pathsMu.RLock()
	stable := e.currentPathTopologyEpoch() == topologyEpoch
	if stable {
		for i := range samples {
			current := e.paths[samples[i].slot.id]
			if current != samples[i].slot || current.gen != samples[i].slotGeneration ||
				pathProbeGenerationForSlot(current) != samples[i].probeGeneration {
				stable = false
				break
			}
		}
	}
	e.pathsMu.RUnlock()
	if !stable {
		return selectorEvidenceView{}, false
	}

	observations := make(map[proto.TargetID]pathEvidenceObservation, len(samples)+len(goodput))
	validUntil := capturedAt.Add(selectorEvidenceCommitLease)
	generationBindings := make([]selectorPathGenerationBinding, 0, len(samples))
	for i := range samples {
		sample := &samples[i]
		quality := selectorEvidenceQuality(sample.quality, sample.probeEvidence, sample.hasProbeEvidence)
		loss, lossAt, lossKnown := selectorLossEvidence(
			sample.quality, sample.probeEvidence, sample.hasProbeEvidence, capturedAt,
		)
		probeLiveness := selectorProbeLiveness(
			sample.probeEvidence, sample.hasProbeEvidence, capturedAt, e.limits.ProbeInterval,
		)
		probeStatus := sample.probeStatus
		if probeStatus.lifecycle == pathProbeReserved && sample.hasProbeEvidence {
			probeStatus.lifecycle = sample.probeEvidence.lastLifecycle
		}
		if probeStatus.failure == pathProbeFailureNone && probeLiveness == qualityStateStale {
			probeStatus.failure = pathProbeFailureWireTimeout
		}
		observations[sample.targetID] = pathEvidenceObservation{
			targetID:       sample.targetID,
			quality:        quality,
			loss:           loss,
			lossAt:         lossAt,
			lossKnown:      lossKnown,
			freshFor:       selectorProbeFreshFor(e.limits.ProbeInterval, quality),
			probeLiveness:  probeLiveness,
			probeLifecycle: probeStatus.lifecycle,
			probeFailure:   probeStatus.failure,
			dataProgress:   sample.dataProgress,
			unexpectedDup:  sample.unexpectedDup,
			goodput:        goodput[sample.targetID],
			live:           true,
			gen:            sample.slotGeneration,
			topologyEpoch:  topologyEpoch,
		}
		generationBindings = append(generationBindings, selectorPathGenerationBinding{
			targetID: sample.targetID, pathID: sample.slot.id, owner: sample.slot.owner,
			slotGeneration: sample.slotGeneration, probeGeneration: sample.probeGeneration,
		})
		if quality.RTT > 0 && !quality.At.IsZero() && !quality.At.After(capturedAt) {
			expires := quality.At.Add(selectorProbeFreshFor(e.limits.ProbeInterval, quality))
			if expires.After(capturedAt) && expires.Before(validUntil) {
				validUntil = expires
			}
		}
		if lossKnown && !lossAt.After(capturedAt) {
			expires := lossAt.Add(selectorEvidenceFreshFor)
			if expires.After(capturedAt) && expires.Before(validUntil) {
				validUntil = expires
			}
		}
	}
	for targetID, estimate := range goodput {
		observation := observations[targetID]
		observation.targetID = targetID
		observation.goodput = estimate
		observation.topologyEpoch = topologyEpoch
		observations[targetID] = observation
		if !estimate.sampleTime.IsZero() && !estimate.sampleTime.After(capturedAt) {
			expires := estimate.sampleTime.Add(selectorEvidenceFreshFor)
			if expires.After(capturedAt) && expires.Before(validUntil) {
				validUntil = expires
			}
		}
	}
	sort.Slice(generationBindings, func(i, j int) bool {
		return generationBindings[i].pathID < generationBindings[j].pathID
	})
	if checkAt := nowFn(); checkAt.Before(capturedAt) || !checkAt.Before(validUntil) {
		return selectorEvidenceView{}, false
	}
	return selectorEvidenceView{
		observations: observations, topologyEpoch: topologyEpoch, capturedAt: capturedAt,
		validUntil: validUntil, generations: generationBindings,
	}, true
}

func (v selectorEvidenceView) commitEvidence() selectorEvidenceCommit {
	return selectorEvidenceCommit{
		topologyEpoch: v.topologyEpoch,
		capturedAt:    v.capturedAt,
		validUntil:    v.validUntil,
		generations:   append([]selectorPathGenerationBinding(nil), v.generations...),
	}
}

func (c selectorEvidenceCommit) bound() bool {
	return c.topologyEpoch != 0
}

func (c selectorEvidenceCommit) physicallyBound() bool {
	return c.bound() && !c.capturedAt.IsZero() && len(c.generations) != 0
}

func (c selectorEvidenceCommit) physicalEqual(other selectorEvidenceCommit) bool {
	if !c.bound() || !other.bound() || c.topologyEpoch != other.topologyEpoch ||
		len(c.generations) != len(other.generations) {
		return false
	}
	for i := range c.generations {
		if c.generations[i] != other.generations[i] {
			return false
		}
	}
	return true
}

func (e *Engine) validateSelectorEvidenceCommitLocked(commit selectorEvidenceCommit) error {
	if !commit.bound() {
		return nil
	}
	if e.currentPathTopologyEpoch() != commit.topologyEpoch {
		return errStaleSelectorEvidence
	}
	now := nowFn()
	if !commit.capturedAt.IsZero() &&
		(now.Before(commit.capturedAt) || commit.validUntil.IsZero() || !now.Before(commit.validUntil)) {
		return fmt.Errorf("%w: evidence freshness expired", ErrSelectorDecisionUnavailable)
	}
	for _, expected := range commit.generations {
		current := e.paths[expected.pathID]
		if current == nil || current.owner != expected.owner || current.gen != expected.slotGeneration ||
			current.localTXTargetID != expected.targetID ||
			pathProbeGenerationForSlot(current) != expected.probeGeneration {
			return errStaleSelectorEvidence
		}
	}
	return nil
}

func selectorEvidenceQuality(
	quality transport.PathQuality,
	evidence pathProbeEvidence,
	hasEvidence bool,
) transport.PathQuality {
	if !hasEvidence || evidence.lastSuccess.IsZero() {
		return quality
	}
	if !quality.At.IsZero() && quality.At.After(evidence.quality.At) {
		return quality
	}
	quality.RTT = evidence.quality.RTT
	quality.Jitter = evidence.quality.Jitter
	quality.At = evidence.quality.At
	return quality
}

func selectorLossEvidence(
	transportQuality transport.PathQuality,
	probe pathProbeEvidence,
	hasProbe bool,
	now time.Time,
) (uint16, time.Time, bool) {
	var loss uint16
	var sampledAt time.Time
	known := false
	if !transportQuality.At.IsZero() && !transportQuality.At.After(now) &&
		now.Sub(transportQuality.At) <= selectorEvidenceFreshFor {
		loss, sampledAt, known = transportQuality.LossPP, transportQuality.At, true
	}
	if !hasProbe || probe.generation == (pathProbeGeneration{}) {
		return loss, sampledAt, known
	}
	total := saturatingAddUint64(probe.succeeded, probe.timedOut)
	probeAt := probe.lastTransition
	if probeAt.IsZero() || probe.lastSuccess.After(probeAt) {
		probeAt = probe.lastSuccess
	}
	if probeAt.IsZero() || probe.lastWireTimeout.After(probeAt) {
		probeAt = probe.lastWireTimeout
	}
	if total == 0 || probeAt.IsZero() || probeAt.After(now) || now.Sub(probeAt) > selectorEvidenceFreshFor {
		return loss, sampledAt, known
	}
	probeLoss := uint64(1000)
	if probe.timedOut <= ^uint64(0)/1000 {
		probeLoss = probe.timedOut * 1000 / total
	}
	if probeLoss > 1000 {
		probeLoss = 1000
	}
	if !known || probeAt.After(sampledAt) {
		return uint16(probeLoss), probeAt, true
	}
	return loss, sampledAt, true
}

func selectorProbeLiveness(
	evidence pathProbeEvidence,
	hasEvidence bool,
	now time.Time,
	interval time.Duration,
) qualityState {
	if !hasEvidence || evidence.issued == 0 || evidence.firstIssued.IsZero() {
		return qualityStateUnknown
	}
	base := evidence.firstIssued
	if evidence.succeeded > 0 && !evidence.lastSuccess.IsZero() {
		base = evidence.lastSuccess
	}
	if now.Before(base) {
		return qualityStateUnknown
	}
	if evidence.lastWireTimeout.After(evidence.lastSuccess) &&
		now.Sub(base) > selectorProbeFreshFor(interval, evidence.quality) {
		return qualityStateStale
	}
	if evidence.succeeded > 0 && now.Sub(base) <= selectorProbeFreshFor(interval, evidence.quality) {
		return qualityStateFresh
	}
	return qualityStateUnknown
}

func (r *executionRuntime) selectorDecisions(
	direction proto.SenderDirection,
	observations map[proto.TargetID]pathEvidenceObservation,
	now time.Time,
	policy selectorEvidencePolicy,
	dwell time.Duration,
	cooldown time.Duration,
) []selectorDecision {
	if r == nil || r.plan == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	memo := make(map[proto.TargetID]schedulingEvidence, len(r.plan.nodes))
	selectors := make([]proto.TargetID, 0)
	r.collectSelectorIDsLocked(r.plan.rootID, &selectors)
	decisions := make([]selectorDecision, 0, len(selectors))
	for _, selectorID := range selectors {
		node, ok := r.plan.node(selectorID)
		if !ok {
			continue
		}
		state := r.selectors[selectorID]
		if state == nil {
			state = &selectorExecutionState{}
			r.selectors[selectorID] = state
		}
		decisionTopologyEpoch, coherentTopology := selectorObservationTopologyEpoch(observations)
		if !coherentTopology {
			state.clearQualityCandidate()
			continue
		}
		if state.qualityTopologyEpoch != 0 &&
			decisionTopologyEpoch != 0 && state.qualityTopologyEpoch != decisionTopologyEpoch {
			state.clearQualityCandidate()
		}
		// A hard path departure may already have projected DATA onto the
		// manifest-order fallback while desired remains the policy-plane truth.
		// Preserve that physical projection until the death transaction commits;
		// otherwise fresh RTT noise can turn one carrier death into two visible
		// migrations (dead -> fallback -> best sibling).
		projected := state.effective
		// Observations are captured before taking r.mu and may already be stale.
		// Use their current child only for this decision; projection and policy
		// commit paths exclusively own effective publication.
		current := r.effectiveSelectorChildLocked(node, observations)

		candidates := make([]selectorCandidate, 0, len(node.children))
		hasLiveNormal := false
		peaks := make(map[proto.TargetID]bool, len(node.peakCandidates))
		for _, peakID := range node.peakCandidates {
			peaks[peakID] = true
		}
		for _, childID := range node.children {
			// A nested selector's committed child can die before its own death
			// decision settles. The target still has a normal route while any
			// descendant is live; aggregate evidence intentionally describes only
			// the committed child and must not authorize a transient class change.
			if !peaks[childID] && r.targetLiveLocked(childID, observations) {
				hasLiveNormal = true
			}
		}
		for order, childID := range node.children {
			if hasLiveNormal && peaks[childID] {
				continue
			}
			evidence := r.aggregateTargetEvidenceLocked(childID, direction, observations, memo, now)
			candidates = append(candidates, selectorCandidate{
				targetID:      childID,
				evidence:      evidence,
				manifestOrder: uint16(order),
				current:       childID == current,
			})
		}
		currentEvidence := r.aggregateTargetEvidenceLocked(current, direction, observations, memo, now)
		if current == (proto.TargetID{}) || !currentEvidence.live {
			selected, found := selectSelectorCandidate(direction, candidates, policy)
			if !found {
				state.clearQualityCandidate()
				continue
			}
			if projected != (proto.TargetID{}) && projected != current && r.targetLiveLocked(projected, observations) {
				for _, candidate := range candidates {
					if candidate.targetID == projected {
						selected = candidate
						break
					}
				}
			}
			if selected.targetID != current {
				decisions = append(decisions, selectorDecision{
					selectorID: selectorID,
					targetID:   selected.targetID,
					cause:      "death",
					origin:     policySelectionPathDeath,
				})
			}
			state.clearQualityCandidate()
			continue
		}
		failure := r.aggregateTargetProbeFailureLocked(current, observations)
		if failure != pathProbeFailureNone {
			alternatives := make([]selectorCandidate, 0, len(candidates)-1)
			for _, candidate := range candidates {
				if candidate.targetID == current ||
					r.aggregateTargetProbeFailureLocked(candidate.targetID, observations) != pathProbeFailureNone ||
					candidate.evidence.probeLiveness != qualityStateFresh ||
					!candidate.evidence.latency.fresh(policy.minimumConfidence) {
					continue
				}
				candidate.current = false
				alternatives = append(alternatives, candidate)
			}
			replacement, replacementFound := selectSelectorCandidate(direction, alternatives, policy)
			cause, origin, factual := selectorProbeFailureDecision(failure)
			if !replacementFound || !factual {
				state.clearQualityCandidate()
				continue
			}
			decisions = append(decisions, selectorDecision{
				selectorID: selectorID,
				targetID:   replacement.targetID,
				cause:      cause,
				origin:     origin,
			})
			state.clearQualityCandidate()
			continue
		}
		if state.peakHeld {
			state.clearQualityCandidate()
			continue
		}
		candidatePending := state.qualityCandidate != (proto.TargetID{})
		if candidatePending && (state.qualityCurrent != current || now.Before(state.qualitySince)) {
			state.clearQualityCandidate()
			candidatePending = false
		}
		holding := candidatePending && now.Sub(state.qualitySince) <= selectorGoodputHoldDuration(dwell)
		if holding {
			for i := range candidates {
				switch candidates[i].targetID {
				case current:
					candidates[i].evidence.speed = heldSelectorSpeed(
						candidates[i].evidence.speed, state.qualityCurrentSpeed, now,
					)
				case state.qualityCandidate:
					candidates[i].evidence.speed = heldSelectorSpeed(
						candidates[i].evidence.speed, state.qualityCandidateSpeed, now,
					)
				}
			}
		}
		selected, found := selectSelectorCandidate(direction, candidates, policy)
		if !found {
			state.clearQualityCandidate()
			continue
		}
		if selected.targetID == current {
			state.clearQualityCandidate()
			continue
		}
		if state.qualityCandidate != selected.targetID {
			state.qualityCandidate = selected.targetID
			state.qualityCurrent = current
			state.qualityCandidateSpeed = selected.evidence.speed
			state.qualityCurrentSpeed = currentEvidence.speed
			state.qualityTopologyEpoch = decisionTopologyEpoch
			state.qualitySince = now
			continue
		}
		if dwell > 0 && now.Sub(state.qualitySince) < dwell {
			continue
		}
		if cooldown > 0 && !state.lastQualityMove.IsZero() && now.Sub(state.lastQualityMove) < cooldown {
			continue
		}
		decisions = append(decisions, selectorDecision{
			selectorID: selectorID,
			targetID:   selected.targetID,
			cause:      "quality",
			origin:     policySelectionQuality,
		})
	}
	return decisions
}

func selectorObservationTopologyEpoch(
	observations map[proto.TargetID]pathEvidenceObservation,
) (uint64, bool) {
	var topologyEpoch uint64
	for _, observation := range observations {
		if observation.topologyEpoch == 0 {
			continue
		}
		if topologyEpoch == 0 {
			topologyEpoch = observation.topologyEpoch
			continue
		}
		if topologyEpoch != observation.topologyEpoch {
			return 0, false
		}
	}
	return topologyEpoch, true
}

func (r *executionRuntime) rankSelectorClassTargets(
	selectorID proto.TargetID,
	peak bool,
	direction proto.SenderDirection,
	observations map[proto.TargetID]pathEvidenceObservation,
	now time.Time,
	policy selectorEvidencePolicy,
) []proto.TargetID {
	return r.rankSelectorClassTargetsWithAdmission(
		selectorID, peak, direction, observations, now, policy, false, nil,
	)
}

func (r *executionRuntime) rankPeakTransferTargets(
	selectorID proto.TargetID,
	direction proto.SenderDirection,
	observations map[proto.TargetID]pathEvidenceObservation,
	now time.Time,
	policy selectorEvidencePolicy,
) []proto.TargetID {
	return r.rankSelectorClassTargetsWithAdmission(
		selectorID, true, direction, observations, now, policy, true, nil,
	)
}

func (r *executionRuntime) rankSelectorClassTargetsWithAdmission(
	selectorID proto.TargetID,
	peak bool,
	direction proto.SenderDirection,
	observations map[proto.TargetID]pathEvidenceObservation,
	now time.Time,
	policy selectorEvidencePolicy,
	peakTransferAdmission bool,
	excluded map[proto.TargetID]struct{},
) []proto.TargetID {
	if r == nil || r.plan == nil || !direction.Valid() {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	node, ok := r.plan.node(selectorID)
	if !ok || node.kind != proto.GraphNodeKindSelector {
		return nil
	}
	peaks := make(map[proto.TargetID]bool, len(node.peakCandidates))
	for _, id := range node.peakCandidates {
		peaks[id] = true
	}
	memo := make(map[proto.TargetID]schedulingEvidence, len(r.plan.nodes))
	candidates := make([]selectorCandidate, 0, len(node.children))
	for order, childID := range node.children {
		if peaks[childID] != peak {
			continue
		}
		if _, skip := excluded[childID]; skip {
			continue
		}
		evidence := r.aggregateTargetEvidenceLocked(childID, direction, observations, memo, now)
		if !selectorClassEvidenceHealthy(evidence, policy.minimumConfidence) ||
			r.aggregateTargetProbeFailureLocked(childID, observations) != pathProbeFailureNone {
			continue
		}
		if peakTransferAdmission &&
			(!evidence.stability.lossKnown || evidence.stability.loss > peakTransferMaximumLossPP ||
				evidence.latency.jitter > peakTransferMaximumJitter) {
			continue
		}
		candidates = append(candidates, selectorCandidate{
			targetID: childID, evidence: evidence, manifestOrder: uint16(order),
		})
	}
	comparison := newSelectorComparisonContext(direction, candidates, policy)
	sort.SliceStable(candidates, func(i, j int) bool {
		return compareSelectorCandidates(comparison, candidates[i], candidates[j]) < 0
	})
	ranked := make([]proto.TargetID, len(candidates))
	for i := range candidates {
		ranked[i] = candidates[i].targetID
	}
	return ranked
}

func selectorClassEvidenceHealthy(evidence schedulingEvidence, minimumConfidence evidenceConfidence) bool {
	return evidence.live && evidence.probeLiveness != qualityStateStale &&
		evidence.latency.fresh(minimumConfidence) && evidence.stability.fresh(minimumConfidence)
}

func (r *executionRuntime) peakTransferTargetHealthy(
	selectorID, targetID proto.TargetID,
	direction proto.SenderDirection,
	observations map[proto.TargetID]pathEvidenceObservation,
	now time.Time,
	policy selectorEvidencePolicy,
) bool {
	for _, candidate := range r.rankPeakTransferTargets(selectorID, direction, observations, now, policy) {
		if candidate == targetID {
			return true
		}
	}
	return false
}

func (r *executionRuntime) noteSelectorDecision(decision selectorDecision, now time.Time) {
	if r == nil {
		return
	}
	r.mu.Lock()
	state := r.selectors[decision.selectorID]
	if state == nil {
		state = &selectorExecutionState{}
		r.selectors[decision.selectorID] = state
	}
	// commitSelectorChild already published desired/effective under the policy
	// owner lock. This post-commit step records scheduler evidence only.
	state.clearQualityCandidate()
	if decision.cause == "quality" {
		state.lastQualityMove = now
	}
	r.mu.Unlock()
}

func selectorGoodputHoldDuration(dwell time.Duration) time.Duration {
	if dwell < 0 {
		dwell = 0
	}
	hold := dwell + selectorGoodputDwellGrace
	if hold < selectorGoodputDwellGrace {
		return maximumSelectorGoodputHold
	}
	if hold > maximumSelectorGoodputHold {
		return maximumSelectorGoodputHold
	}
	return hold
}

func heldSelectorSpeed(current, held speedEvidence, now time.Time) speedEvidence {
	if current.uniqueGoodput.fresh(1) {
		held.uniqueGoodput = current.uniqueGoodput
	}
	if current.capacity.fresh(1) {
		held.capacity = current.capacity
	}
	if !held.uniqueGoodput.sampleTime.IsZero() && now.Before(held.uniqueGoodput.sampleTime) {
		held.uniqueGoodput = speedEstimate{}
	}
	if !held.capacity.sampleTime.IsZero() && now.Before(held.capacity.sampleTime) {
		held.capacity = speedEstimate{}
	}
	return held
}

func (r *executionRuntime) collectSelectorIDsLocked(id proto.TargetID, out *[]proto.TargetID) {
	node, ok := r.plan.node(id)
	if !ok {
		return
	}
	if node.kind == proto.GraphNodeKindSelector {
		*out = append(*out, id)
	}
	for _, childID := range node.children {
		r.collectSelectorIDsLocked(childID, out)
	}
}

func (r *executionRuntime) effectiveSelectorChildLocked(node executionPlanNode, observations map[proto.TargetID]pathEvidenceObservation) proto.TargetID {
	state := r.selectors[node.targetID]
	if state != nil {
		// desired is the policy-plane truth even when its evidence disappears.
		// Returning a live sibling here would make that sibling look committed
		// and suppress the death decision that is required to authorize a move.
		if state.desired != (proto.TargetID{}) {
			return state.desired
		}
		if state.effective != (proto.TargetID{}) && r.targetLiveLocked(state.effective, observations) {
			return state.effective
		}
	}
	peaks := make(map[proto.TargetID]bool, len(node.peakCandidates))
	for _, peakID := range node.peakCandidates {
		peaks[peakID] = true
	}
	for _, peakPass := range []bool{false, true} {
		for _, childID := range node.children {
			if peaks[childID] == peakPass && r.targetLiveLocked(childID, observations) {
				return childID
			}
		}
	}
	return proto.TargetID{}
}

func (r *executionRuntime) targetLiveLocked(id proto.TargetID, observations map[proto.TargetID]pathEvidenceObservation) bool {
	node, ok := r.plan.node(id)
	if !ok {
		return false
	}
	if node.kind == proto.GraphNodeKindPath {
		return observations[id].live
	}
	for _, childID := range node.children {
		if r.targetLiveLocked(childID, observations) {
			return true
		}
	}
	return false
}

func selectorProbeFailureDecision(failure pathProbeFailure) (string, policySelectionOrigin, bool) {
	switch failure {
	case pathProbeFailureWireTimeout:
		return "probe-wire-timeout", policySelectionProbeFailure, true
	case pathProbeFailureDataStarved:
		return "probe-starved-data", policySelectionProbeStarvedData, true
	case pathProbeFailureWriteStalled:
		return "probe-write-stalled", policySelectionWriteStalled, true
	default:
		return "", policySelectionExternal, false
	}
}

// aggregateTargetProbeFailureLocked is deliberately separate from quality
// aggregation. A local writer stall is not a wire RTT/loss sample, and a
// bond/race target is not failed while any live descendant remains free of a
// factual probe failure.
func (r *executionRuntime) aggregateTargetProbeFailureLocked(
	id proto.TargetID,
	observations map[proto.TargetID]pathEvidenceObservation,
) pathProbeFailure {
	node, ok := r.plan.node(id)
	if !ok {
		return pathProbeFailureNone
	}
	if node.kind == proto.GraphNodeKindPath {
		observation := observations[id]
		if !observation.live {
			return pathProbeFailureNone
		}
		return observation.probeFailure
	}
	if node.kind == proto.GraphNodeKindSelector {
		active := r.effectiveSelectorChildLocked(node, observations)
		if active == (proto.TargetID{}) {
			return pathProbeFailureNone
		}
		return r.aggregateTargetProbeFailureLocked(active, observations)
	}

	failure := pathProbeFailureNone
	hasLiveChild := false
	for _, childID := range node.children {
		if !r.targetLiveLocked(childID, observations) {
			continue
		}
		hasLiveChild = true
		childFailure := r.aggregateTargetProbeFailureLocked(childID, observations)
		if childFailure == pathProbeFailureNone {
			return pathProbeFailureNone
		}
		if probeFailurePriority(childFailure) > probeFailurePriority(failure) {
			failure = childFailure
		}
	}
	if !hasLiveChild {
		return pathProbeFailureNone
	}
	return failure
}

func probeFailurePriority(failure pathProbeFailure) uint8 {
	switch failure {
	case pathProbeFailureDataStarved:
		return 3
	case pathProbeFailureWriteStalled:
		return 2
	case pathProbeFailureWireTimeout:
		return 1
	default:
		return 0
	}
}

func (r *executionRuntime) aggregateTargetEvidenceLocked(
	id proto.TargetID,
	direction proto.SenderDirection,
	observations map[proto.TargetID]pathEvidenceObservation,
	memo map[proto.TargetID]schedulingEvidence,
	now time.Time,
) schedulingEvidence {
	if evidence, ok := memo[id]; ok {
		return evidence
	}
	node, ok := r.plan.node(id)
	if !ok {
		return schedulingEvidence{direction: direction}
	}
	if node.kind == proto.GraphNodeKindPath {
		evidence := evidenceFromPathObservation(direction, observations[id], now)
		memo[id] = evidence
		return evidence
	}
	active := proto.TargetID{}
	if node.kind == proto.GraphNodeKindSelector {
		active = r.effectiveSelectorChildLocked(node, observations)
	}
	children := make([]aggregateChildEvidence, 0, len(node.children))
	for _, childID := range node.children {
		evidence := r.aggregateTargetEvidenceLocked(childID, direction, observations, memo, now)
		children = append(children, aggregateChildEvidence{
			evidence: evidence,
			eligible: evidence.live,
			active:   childID == active,
		})
	}
	evidence, valid := aggregateSchedulingEvidence(node.kind, direction, children)
	if !valid {
		evidence = schedulingEvidence{direction: direction}
	}
	if observation := observations[id]; (node.kind == proto.GraphNodeKindBond || node.kind == proto.GraphNodeKindRace) && observation.goodput.observed() {
		evidence.speed.uniqueGoodput = observation.goodput
	}
	memo[id] = evidence
	return evidence
}

func evidenceFromPathObservation(direction proto.SenderDirection, observation pathEvidenceObservation, now time.Time) schedulingEvidence {
	evidence := schedulingEvidence{
		direction: direction, live: observation.live, probeLiveness: observation.probeLiveness,
	}
	if !observation.live {
		return evidence
	}
	quality := observation.quality
	if quality.RTT > 0 && !quality.At.IsZero() {
		if quality.At.After(now) {
			return evidence
		}
		state := qualityStateFresh
		freshFor := observation.freshFor
		if freshFor <= 0 {
			freshFor = selectorEvidenceFreshFor
		}
		if now.Sub(quality.At) > freshFor {
			state = qualityStateStale
		}
		evidence.latency = latencyEvidence{
			state:       state,
			latest:      quality.RTT,
			minimum:     quality.RTT,
			ewma:        quality.RTT,
			jitter:      quality.Jitter,
			sampleTime:  quality.At,
			confidence:  evidenceConfidenceFull,
			sampleCount: 1,
		}
		evidence.stability = stabilityEvidence{
			state:    state,
			progress: 1,
			loss:     uint64(observation.loss),
			lossKnown: observation.lossKnown && !observation.lossAt.IsZero() &&
				!observation.lossAt.After(now) && now.Sub(observation.lossAt) <= selectorEvidenceFreshFor,
			sampleTime:  observation.lossAt,
			confidence:  evidenceConfidenceFull,
			sampleCount: 1,
		}
		if evidence.stability.sampleTime.IsZero() {
			evidence.stability.sampleTime = quality.At
		}
	}
	if observation.goodput.observed() {
		evidence.speed.uniqueGoodput = observation.goodput
	}
	return evidence
}

// selectorProbeFreshFor converts successful same-carrier RTT replies into a
// conservative external liveness window. Three missed default probes fit
// inside G4's five-second failover budget, while measured RTT and jitter widen
// the window for legitimately slow paths.
func selectorProbeFreshFor(interval time.Duration, quality transport.PathQuality) time.Duration {
	if interval <= 0 {
		interval = DefaultLimits().ProbeInterval
	}
	freshFor := 3 * interval
	transportBudget := 4*quality.RTT + 2*quality.Jitter + interval
	if transportBudget > freshFor {
		freshFor = transportBudget
	}
	if freshFor < minimumSelectorProbeFreshFor {
		freshFor = minimumSelectorProbeFreshFor
	}
	if freshFor > maximumSelectorProbeFreshFor {
		freshFor = maximumSelectorProbeFreshFor
	}
	return freshFor
}
