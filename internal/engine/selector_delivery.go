package engine

import "github.com/FrankoonG/rendr/proto"

func selectorFrameAttributionsForState(
	binding graphBinding,
	state *selectorStateRecord,
) []selectorFrameAttribution {
	if state == nil || len(binding.peakSelectors) == 0 {
		return nil
	}
	out := make([]selectorFrameAttribution, 0, len(binding.peakSelectors))
	for _, selectorID := range binding.peakSelectors {
		if !binding.selectorActiveInState(selectorID, state) {
			continue
		}
		entry, ok := state.entry(selectorID)
		if !ok {
			continue
		}
		out = append(out, selectorFrameAttribution{
			cohort: rootDeliveryCohort{
				selectorID: selectorID,
				targetID:   entry.DesiredTargetID,
				generation: entry.Generation,
			},
			committed: entry.DesiredTargetID == entry.EffectiveTargetID,
		})
	}
	return out
}

func nextSelectorEvidenceEpoch(current uint64) uint64 {
	current++
	if current == 0 {
		current++
	}
	return current
}

func beginSelectorDeliveryEvidence(
	previous selectorDeliveryEvidence,
	cohort rootDeliveryCohort,
	stateEpoch, topologyEpoch uint64,
	attributable bool,
) selectorDeliveryEvidence {
	return selectorDeliveryEvidence{
		cohort:        cohort,
		stateEpoch:    stateEpoch,
		evidenceEpoch: nextSelectorEvidenceEpoch(previous.evidenceEpoch),
		topologyEpoch: topologyEpoch,
		attributable:  attributable,
	}
}

// publishSelectorAttributionLocked freezes the policy identity at the DATA
// replay boundary. Physical route evidence is deliberately deferred until the
// frame is dispatched and proof-valid ACK/custody establishes delivery.
func (e *Engine) publishSelectorAttributionLocked(entry *sendHistoryEntry) {
	if entry == nil || entry.applicationBytes == 0 || len(entry.selectorAttributions) == 0 {
		return
	}
	if e.sendHist.selectorDelivery == nil {
		e.sendHist.selectorDelivery = make(map[proto.TargetID]selectorDeliveryEvidence)
	}
	topologyEpoch := e.currentPathTopologyEpoch()
	for index := range entry.selectorAttributions {
		attribution := &entry.selectorAttributions[index]
		current := e.sendHist.selectorDelivery[attribution.cohort.selectorID]
		if current.cohort != attribution.cohort || current.topologyEpoch != topologyEpoch {
			current = beginSelectorDeliveryEvidence(
				current, attribution.cohort, entry.selectorStateEpoch,
				topologyEpoch, attribution.committed,
			)
		} else if attribution.committed && !current.attributable {
			current = beginSelectorDeliveryEvidence(
				current, attribution.cohort, entry.selectorStateEpoch,
				topologyEpoch, true,
			)
		} else if attribution.committed {
			current.stateEpoch = entry.selectorStateEpoch
		}
		e.sendHist.selectorDelivery[attribution.cohort.selectorID] = current
		attribution.evidenceEpoch = current.evidenceEpoch
		attribution.topologyEpoch = current.topologyEpoch
	}
}

func selectorRouteForAttribution(
	binding graphBinding,
	state applicationDispatchRouteState,
	attribution selectorFrameAttribution,
) (belongs, valid bool) {
	if !state.deliveryRouteSeen || !state.deliveryAttributable ||
		state.topologyEpoch == 0 || state.topologyEpoch != attribution.topologyEpoch {
		return false, false
	}
	if !binding.targetDescendsFrom(state.deliveryRouteTarget, attribution.cohort.selectorID) {
		return false, true
	}
	childID, ok := binding.immediateChildForDescendant(
		attribution.cohort.selectorID, state.deliveryRouteTarget,
	)
	return true, ok && attribution.committed && childID == attribution.cohort.targetID
}

func (e *Engine) settleSelectorDeliveryLocked(
	binding graphBinding,
	state applicationDispatchRouteState,
	attributions []selectorFrameAttribution,
	applicationBytes uint64,
	demand bool,
) {
	if applicationBytes == 0 || len(attributions) == 0 {
		return
	}
	currentTopology := e.currentPathTopologyEpoch()
	for _, attribution := range attributions {
		current, ok := e.sendHist.selectorDelivery[attribution.cohort.selectorID]
		if !ok || current.cohort != attribution.cohort ||
			current.evidenceEpoch != attribution.evidenceEpoch ||
			current.topologyEpoch != attribution.topologyEpoch ||
			currentTopology != attribution.topologyEpoch || !current.attributable {
			continue
		}
		belongs, valid := selectorRouteForAttribution(binding, state, attribution)
		if !belongs || !valid {
			continue
		}
		current.ackedBytes = saturatingAddUint64(current.ackedBytes, applicationBytes)
		if demand {
			current.demandAckedBytes = saturatingAddUint64(
				current.demandAckedBytes, applicationBytes,
			)
		}
		e.sendHist.selectorDelivery[attribution.cohort.selectorID] = current
	}
}

func selectorAttributionFor(
	attributions []selectorFrameAttribution,
	selectorID proto.TargetID,
	evidenceEpoch uint64,
) (selectorFrameAttribution, bool) {
	for _, attribution := range attributions {
		if attribution.cohort.selectorID == selectorID &&
			attribution.evidenceEpoch == evidenceEpoch {
			return attribution, true
		}
	}
	return selectorFrameAttribution{}, false
}

func (e *Engine) pendingSelectorDeliveryLocked(
	binding graphBinding,
	selectorID proto.TargetID,
	evidence selectorDeliveryEvidence,
) (uint64, bool) {
	pending := uint64(0)
	for index := range e.sendHist.entries {
		entry := &e.sendHist.entries[index]
		if !entry.application || entry.applicationBytes == 0 {
			continue
		}
		attributions := entry.selectorAttributions
		state := applicationDispatchRouteStateFromEntry(entry)
		if record := entry.batchAttribution; record != nil {
			attributions = record.selectorAttributions
			state = record.state
		}
		attribution, ok := selectorAttributionFor(
			attributions, selectorID, evidence.evidenceEpoch,
		)
		if !ok || attribution.cohort != evidence.cohort {
			continue
		}
		belongs, valid := selectorRouteForAttribution(binding, state, attribution)
		if !state.deliveryRouteSeen || !state.deliveryAttributable {
			continue
		}
		if !belongs || !valid {
			continue
		}
		pending = saturatingAddUint64(pending, entry.applicationBytes)
	}
	return pending, true
}

// TargetApplicationDeliveryForSelector reports proof-confirmed DATA for one
// selector at any graph depth. A zero targetID selects its current child.
func (e *Engine) TargetApplicationDeliveryForSelector(
	selectorID, targetID proto.TargetID,
) TargetDeliverySnapshot {
	if e == nil || selectorID == (proto.TargetID{}) {
		return TargetDeliverySnapshot{}
	}
	topologyEpoch := e.currentPathTopologyEpoch()
	binding := e.localGraphBinding()
	e.sendHistMu.Lock()
	evidence, ok := e.sendHist.selectorDelivery[selectorID]
	state := e.sendSelectorState
	snapshot := selectorDeliverySnapshot(binding, state, evidence, selectorID, targetID, topologyEpoch)
	if ok && snapshot.Attributable && e.sendHist.selectorPendingDispatches == 0 {
		pending, valid := e.pendingSelectorDeliveryLocked(binding, selectorID, evidence)
		if valid {
			snapshot.AckedBytes = evidence.ackedBytes
			snapshot.PublishedBytes = saturatingAddUint64(evidence.ackedBytes, pending)
			snapshot.DemandBytes = evidence.demandAckedBytes
		} else {
			clearTargetDeliveryAttribution(&snapshot)
		}
	} else {
		clearTargetDeliveryAttribution(&snapshot)
	}
	e.sendHistMu.Unlock()
	if e.currentPathTopologyEpoch() != topologyEpoch {
		clearTargetDeliveryAttribution(&snapshot)
	}
	return snapshot
}

func selectorDeliverySnapshot(
	binding graphBinding,
	state *selectorStateRecord,
	evidence selectorDeliveryEvidence,
	selectorID, targetID proto.TargetID,
	topologyEpoch uint64,
) TargetDeliverySnapshot {
	snapshot := TargetDeliverySnapshot{
		SelectorID:         selectorID,
		TargetID:           targetID,
		SelectorGeneration: evidence.cohort.generation,
		EvidenceEpoch:      evidence.evidenceEpoch,
		Attributable:       evidence.attributable && evidence.topologyEpoch == topologyEpoch,
	}
	entry, entryOK := state.entry(selectorID)
	if targetID == (proto.TargetID{}) {
		snapshot.TargetID = evidence.cohort.targetID
		targetID = snapshot.TargetID
	}
	if !entryOK || !binding.selectorActiveInState(selectorID, state) ||
		entry.DesiredTargetID != entry.EffectiveTargetID ||
		entry.DesiredTargetID != evidence.cohort.targetID ||
		entry.Generation != evidence.cohort.generation ||
		targetID != evidence.cohort.targetID {
		snapshot.Attributable = false
	}
	snapshot.SelectorName, _ = binding.targetName(selectorID)
	snapshot.TargetName, _ = binding.targetName(snapshot.TargetID)
	return snapshot
}

func (e *Engine) latestReadyPeerSelectorStateLocked() *selectorStateRecord {
	var latest *selectorStateRecord
	var latestSeq uint64
	for _, record := range e.recvSelectorStates {
		if record == nil || !record.ready || record.controlSeq < latestSeq {
			continue
		}
		latest = record.state
		latestSeq = record.controlSeq
	}
	return latest
}

func (e *Engine) commitPeerSelectorDeliveryLocked(
	stateEpoch uint64,
	leafID proto.TargetID,
	topologyEpoch uint64,
	demand bool,
	bytes int,
) {
	if bytes <= 0 || leafID == (proto.TargetID{}) ||
		topologyEpoch == 0 || topologyEpoch != e.currentPathTopologyEpoch() {
		return
	}
	record := e.recvSelectorStates[stateEpoch]
	if record == nil || !record.ready || record.state == nil {
		return
	}
	binding := e.peerGraphBinding()
	if !binding.containsLeaf(leafID) {
		return
	}
	if e.recvSelectorDelivery == nil {
		e.recvSelectorDelivery = make(map[proto.TargetID]selectorDeliveryEvidence)
	}
	for _, selectorID := range binding.peakSelectors {
		if !binding.targetDescendsFrom(leafID, selectorID) {
			continue
		}
		entry, ok := record.state.entry(selectorID)
		childID, childOK := binding.immediateChildForDescendant(selectorID, leafID)
		cohort := rootDeliveryCohort{
			selectorID: selectorID,
			targetID:   entry.DesiredTargetID,
			generation: entry.Generation,
		}
		attributable := ok && childOK &&
			binding.selectorActiveInState(selectorID, record.state) &&
			entry.DesiredTargetID == entry.EffectiveTargetID && childID == entry.DesiredTargetID
		current := e.recvSelectorDelivery[selectorID]
		if current.cohort != cohort || current.topologyEpoch != topologyEpoch {
			current = beginSelectorDeliveryEvidence(
				current, cohort, stateEpoch, topologyEpoch, attributable,
			)
		} else if attributable && !current.attributable {
			current = beginSelectorDeliveryEvidence(
				current, cohort, stateEpoch, topologyEpoch, true,
			)
		} else if attributable {
			current.stateEpoch = stateEpoch
		}
		if attributable {
			current.ackedBytes = saturatingAddUint64(current.ackedBytes, uint64(bytes))
			if demand {
				current.demandAckedBytes = saturatingAddUint64(
					current.demandAckedBytes, uint64(bytes),
				)
			}
		}
		e.recvSelectorDelivery[selectorID] = current
	}
}

// PeerTargetDeliveryForSelector reports first-custody unique DATA for one
// selector at any depth in the peer's graph.
func (e *Engine) PeerTargetDeliveryForSelector(
	selectorID, targetID proto.TargetID,
) TargetDeliverySnapshot {
	if e == nil || selectorID == (proto.TargetID{}) {
		return TargetDeliverySnapshot{}
	}
	topologyEpoch := e.currentPathTopologyEpoch()
	binding := e.peerGraphBinding()
	e.recvMu.Lock()
	evidence, ok := e.recvSelectorDelivery[selectorID]
	state := e.latestReadyPeerSelectorStateLocked()
	snapshot := selectorDeliverySnapshot(binding, state, evidence, selectorID, targetID, topologyEpoch)
	if ok && snapshot.Attributable {
		snapshot.AckedBytes = evidence.ackedBytes
		snapshot.PublishedBytes = evidence.ackedBytes
		snapshot.DemandBytes = evidence.demandAckedBytes
	} else {
		clearTargetDeliveryAttribution(&snapshot)
	}
	e.recvMu.Unlock()
	if e.currentPathTopologyEpoch() != topologyEpoch {
		clearTargetDeliveryAttribution(&snapshot)
	}
	return snapshot
}
