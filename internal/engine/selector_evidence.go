package engine

import (
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

const selectorEvidenceFreshFor = 5 * time.Second

type pathEvidenceObservation struct {
	targetID      proto.TargetID
	quality       transport.PathQuality
	dataProgress  uint64
	unexpectedDup uint64
	weight        uint16
	live          bool
	gen           uint64
}

type selectorDecision struct {
	selectorID proto.TargetID
	targetID   proto.TargetID
	cause      string
}

func (e *Engine) selectorEvidenceObservations() map[proto.TargetID]pathEvidenceObservation {
	e.pathsMu.RLock()
	observations := make(map[proto.TargetID]pathEvidenceObservation, len(e.paths))
	for _, slot := range e.paths {
		if slot.localTXTargetID == (proto.TargetID{}) {
			continue
		}
		previous, exists := observations[slot.localTXTargetID]
		if exists && previous.gen > slot.gen {
			continue
		}
		observations[slot.localTXTargetID] = pathEvidenceObservation{
			targetID:      slot.localTXTargetID,
			quality:       slot.conn.Quality(),
			dataProgress:  slot.dataDispatches.Load(),
			unexpectedDup: slot.recvDups.Load(),
			weight:        slot.spec.Weight,
			live:          true,
			gen:           slot.gen,
		}
	}
	e.pathsMu.RUnlock()
	return observations
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
		current := r.effectiveSelectorChildLocked(node, observations)
		state.effective = current

		candidates := make([]selectorCandidate, 0, len(node.children))
		hasLiveNormal := false
		peaks := make(map[proto.TargetID]bool, len(node.peakCandidates))
		for _, peakID := range node.peakCandidates {
			peaks[peakID] = true
		}
		for _, childID := range node.children {
			evidence := r.aggregateTargetEvidenceLocked(childID, direction, observations, memo, now)
			if evidence.live && !peaks[childID] {
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
		selected, found := selectSelectorCandidate(direction, candidates, policy)
		if !found || selected.targetID == current {
			state.qualityCandidate = proto.TargetID{}
			state.qualitySince = time.Time{}
			continue
		}
		currentEvidence := r.aggregateTargetEvidenceLocked(current, direction, observations, memo, now)
		if current == (proto.TargetID{}) || !currentEvidence.live {
			decisions = append(decisions, selectorDecision{selectorID: selectorID, targetID: selected.targetID, cause: "death"})
			state.qualityCandidate = proto.TargetID{}
			state.qualitySince = time.Time{}
			continue
		}
		if state.qualityCandidate != selected.targetID {
			state.qualityCandidate = selected.targetID
			state.qualitySince = now
			continue
		}
		if dwell > 0 && now.Sub(state.qualitySince) < dwell {
			continue
		}
		if cooldown > 0 && !state.lastQualityMove.IsZero() && now.Sub(state.lastQualityMove) < cooldown {
			continue
		}
		decisions = append(decisions, selectorDecision{selectorID: selectorID, targetID: selected.targetID, cause: "quality"})
	}
	return decisions
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
	state.desired = decision.targetID
	state.effective = decision.targetID
	state.qualityCandidate = proto.TargetID{}
	state.qualitySince = time.Time{}
	if decision.cause == "quality" {
		state.lastQualityMove = now
	}
	r.mu.Unlock()
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
		if state.desired != (proto.TargetID{}) && r.targetLiveLocked(state.desired, observations) {
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
	memo[id] = evidence
	return evidence
}

func evidenceFromPathObservation(direction proto.SenderDirection, observation pathEvidenceObservation, now time.Time) schedulingEvidence {
	evidence := schedulingEvidence{direction: direction, live: observation.live}
	if !observation.live {
		return evidence
	}
	quality := observation.quality
	if quality.RTT > 0 && !quality.At.IsZero() {
		state := qualityStateFresh
		if now.Sub(quality.At) > selectorEvidenceFreshFor {
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
			state:       state,
			progress:    1,
			loss:        uint64(quality.LossPP),
			sampleTime:  quality.At,
			confidence:  evidenceConfidenceFull,
			sampleCount: 1,
		}
	}
	if observation.weight > 0 {
		evidence.speed.capacity = speedEstimate{
			state:          qualityStateFresh,
			bytesPerSecond: uint64(observation.weight),
			confidence:     1,
			source:         speedSourceTransport,
			sampleTime:     now,
			sampleCount:    1,
		}
	}
	return evidence
}
