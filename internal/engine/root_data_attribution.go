package engine

import (
	"fmt"
	"time"

	"github.com/FrankoonG/rendr/proto"
)

type rootDataAttribution struct {
	cohort               rootDeliveryCohort
	committed            bool
	demand               bool
	stateEpoch           uint64
	selectorState        *selectorStateRecord
	selectorAttributions []selectorFrameAttribution
}

const (
	rootDemandBacklogBytes        = 64 << 10
	minimumDemandDispatchDuration = time.Millisecond
	minimumDemandApplicationGap   = 10 * time.Millisecond
)

type applicationDispatchDemandEvidence struct {
	cohort        rootDeliveryCohort
	topologyEpoch uint64
	finished      time.Time
	duration      time.Duration
}

func (e *Engine) currentRootDataAttribution(
	runtime *executionRuntime,
	selectorState *selectorStateRecord,
) (rootDataAttribution, bool, error) {
	if runtime == nil || runtime.plan == nil {
		return rootDataAttribution{}, false, errExecutionRuntimeNotConfigured
	}
	binding := e.localGraphBinding()
	globalDemand := e.applicationDemand()
	if !binding.rootTracksLocalDelivery {
		return rootDataAttribution{
			selectorState:        selectorState,
			selectorAttributions: selectorFrameAttributionsForState(binding, selectorState),
			demand:               globalDemand,
		}, binding.tracksSelectorState, nil
	}
	selectorID, desired, effective, generation, ok := runtime.rootPublicationAttribution()
	if selectorState != nil {
		entry, exists := selectorState.entry(binding.rootSelectorID)
		if !exists {
			return rootDataAttribution{}, true, fmt.Errorf("engine: selector state omits root selector")
		}
		selectorID = entry.SelectorID
		desired = entry.DesiredTargetID
		effective = entry.EffectiveTargetID
		generation = entry.Generation
		ok = true
	}
	if !ok || selectorID != binding.rootSelectorID || desired == (proto.TargetID{}) || generation == 0 {
		return rootDataAttribution{}, true, errNoExecutionRoute
	}
	return rootDataAttribution{
		selectorState:        selectorState,
		selectorAttributions: selectorFrameAttributionsForState(binding, selectorState),
		cohort: rootDeliveryCohort{
			selectorID: selectorID,
			targetID:   desired,
			generation: generation,
		},
		committed: desired == effective && effective != (proto.TargetID{}),
		demand:    globalDemand,
		stateEpoch: func() uint64 {
			if selectorState == nil {
				return 0
			}
			return selectorState.payload.StateEpoch
		}(),
	}, true, nil
}

func (e *Engine) applicationDemand() bool {
	topologyEpoch := e.currentPathTopologyEpoch()
	e.sendHistMu.Lock()
	demand := e.sendHist.creditWaiters != 0 ||
		e.sendHist.pendingApplicationBytes >= rootDemandBacklogBytes
	e.sendHistMu.Unlock()
	if demand {
		return true
	}
	evidence := e.lastApplicationDispatch.Load()
	if evidence == nil || evidence.topologyEpoch != topologyEpoch ||
		evidence.duration < minimumDemandDispatchDuration {
		return false
	}
	gap := nowFn().Sub(evidence.finished)
	if gap < 0 {
		return false
	}
	maximumGap := evidence.duration
	if maximumGap < minimumDemandApplicationGap {
		maximumGap = minimumDemandApplicationGap
	}
	return gap <= maximumGap
}

func (e *Engine) applicationDemandForRoot(selectorID, targetID proto.TargetID, generation uint64) bool {
	cohort := rootDeliveryCohort{
		selectorID: selectorID,
		targetID:   targetID,
		generation: generation,
	}
	e.sendHistMu.Lock()
	demand := e.sendHist.rootCohort == cohort &&
		e.sendHist.rootTopologyEpoch == e.currentPathTopologyEpoch() &&
		e.sendHist.rootPublishedBytes >= e.sendHist.rootAckedBytes &&
		(e.sendHist.creditWaiters != 0 ||
			e.sendHist.rootPublishedBytes-e.sendHist.rootAckedBytes >= rootDemandBacklogBytes)
	e.sendHistMu.Unlock()
	if demand {
		return true
	}
	evidence := e.lastApplicationDispatch.Load()
	if evidence == nil || evidence.cohort != cohort ||
		evidence.topologyEpoch != e.currentPathTopologyEpoch() ||
		evidence.duration < minimumDemandDispatchDuration {
		return false
	}
	gap := nowFn().Sub(evidence.finished)
	if gap < 0 {
		return false
	}
	maximumGap := evidence.duration
	if maximumGap < minimumDemandApplicationGap {
		maximumGap = minimumDemandApplicationGap
	}
	return gap <= maximumGap
}

func (e *Engine) noteApplicationDispatchDuration(
	cohort rootDeliveryCohort,
	topologyEpoch uint64,
	started, finished time.Time,
	successful bool,
) {
	if !successful || topologyEpoch == 0 || topologyEpoch != e.currentPathTopologyEpoch() ||
		!finished.After(started) {
		return
	}
	duration := finished.Sub(started)
	if duration < minimumDemandDispatchDuration {
		// Consumers reject sub-threshold evidence. Publish that same negative
		// result without allocating, and prevent an older pressured dispatch from
		// surviving a newer fast completion.
		e.lastApplicationDispatch.Store(nil)
		return
	}
	e.lastApplicationDispatch.Store(&applicationDispatchDemandEvidence{
		cohort: cohort, topologyEpoch: topologyEpoch,
		finished: finished, duration: duration,
	})
}

// applicationRootCohortFromFrame recovers immutable sender attribution from
// the local replay owner when it is still present. PeakTransfer wire metadata
// is the fallback after a fast peer ACK has already released that owner;
// ordinary selectors deliberately have no such wire representation.
func (e *Engine) applicationRootCohortFromFrame(frame []byte) rootDeliveryCohort {
	if len(frame) < proto.HeaderSize {
		return rootDeliveryCohort{}
	}
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil || header.Type != proto.FrameData {
		return rootDeliveryCohort{}
	}
	e.sendHistMu.Lock()
	entry := e.sendHistoryEntryLocked(header.Seq)
	if entry != nil && entry.rootCohort.targetID != (proto.TargetID{}) {
		cohort := entry.rootCohort
		e.sendHistMu.Unlock()
		return cohort
	}
	e.sendHistMu.Unlock()
	if len(frame) < proto.HeaderSize+proto.DataSelectorStateEpochSize {
		return rootDeliveryCohort{}
	}
	binding := e.localGraphBinding()
	if !binding.tracksSelectorState || !binding.rootTracksWireAttribution {
		return rootDeliveryCohort{}
	}
	stateEpoch, _, err := proto.DecodeDataSelectorStateEpoch(frame[proto.HeaderSize:])
	if err != nil {
		return rootDeliveryCohort{}
	}
	e.sendHistMu.Lock()
	state := e.sendSelectorStates[stateEpoch]
	e.sendHistMu.Unlock()
	selectorEntry, ok := state.entry(binding.rootSelectorID)
	if !ok {
		return rootDeliveryCohort{}
	}
	return rootDeliveryCohort{
		selectorID: binding.rootSelectorID,
		targetID:   selectorEntry.DesiredTargetID,
		generation: selectorEntry.Generation,
	}
}

func (e *Engine) encodeApplicationPayload(
	payload []byte,
	runtime *executionRuntime,
	selectorState *selectorStateRecord,
) (uint16, []byte, rootDataAttribution, error) {
	attribution, tracked, err := e.currentRootDataAttribution(runtime, selectorState)
	if err != nil {
		return 0, nil, rootDataAttribution{}, err
	}
	binding := e.localGraphBinding()
	flags, err := proto.DataFlagsForSelectorState(
		binding.tracksSelectorState,
		binding.tracksSelectorState && tracked && attribution.demand,
	)
	if err != nil {
		return 0, nil, rootDataAttribution{}, err
	}
	if !binding.tracksSelectorState {
		return flags, payload, attribution, nil
	}
	if selectorState == nil || selectorState.payload.StateEpoch == 0 {
		return 0, nil, rootDataAttribution{}, fmt.Errorf("engine: DATA has no selector state")
	}
	attribution.stateEpoch = selectorState.payload.StateEpoch
	wirePayload, err := proto.EncodeDataSelectorStateEpoch(selectorState.payload.StateEpoch, payload)
	if err != nil {
		return 0, nil, rootDataAttribution{}, err
	}
	return flags, wirePayload, attribution, nil
}

func (e *Engine) decodePeerApplicationPayload(
	slot *pathSlot,
	dataSeq uint64,
	flags uint16,
	wirePayload []byte,
) (payload []byte, stateEpoch uint64, cohort rootDeliveryCohort, eligible, demand bool, err error) {
	binding := e.peerGraphBinding()
	if !binding.configured {
		return nil, 0, rootDeliveryCohort{}, false, false, fmt.Errorf("peer graph is not configured")
	}
	var selectorState *selectorStateRecord
	if binding.tracksSelectorState {
		stateEpoch, payload, err = proto.DecodeDataSelectorStateEpoch(wirePayload)
		if err != nil {
			return nil, 0, rootDeliveryCohort{}, false, false, err
		}
		selectorState, err = e.peerSelectorStateForDataLocked(stateEpoch, dataSeq)
		if err != nil {
			return nil, stateEpoch, rootDeliveryCohort{}, false, false, err
		}
	} else {
		payload = wirePayload
	}
	demand, err = proto.DemandFromDataFlags(binding.tracksSelectorState, flags)
	if err != nil {
		return nil, stateEpoch, rootDeliveryCohort{}, false, false, err
	}
	if !binding.rootTracksWireAttribution {
		return payload, stateEpoch, rootDeliveryCohort{}, false, demand, nil
	}
	entry, ok := selectorState.entry(binding.rootSelectorID)
	if !ok {
		return nil, stateEpoch, rootDeliveryCohort{}, false, false, fmt.Errorf("selector state omits root selector")
	}
	targetID := entry.DesiredTargetID
	committed := targetID == entry.EffectiveTargetID
	cohort = rootDeliveryCohort{
		selectorID: binding.rootSelectorID,
		targetID:   targetID,
		generation: entry.Generation,
	}
	physicalTarget, physicalOK := binding.rootTargetForLeaf(slotPeerTargetID(slot))
	eligible = committed && physicalOK && physicalTarget == targetID
	return payload, stateEpoch, cohort, eligible, demand, nil
}

func slotPeerTargetID(slot *pathSlot) proto.TargetID {
	if slot == nil {
		return proto.TargetID{}
	}
	return slot.peerTXTargetID
}

func (e *Engine) applicationWireFrameBytes(payloadBytes int) int {
	return e.applicationPayloadOverhead() + payloadBytes
}

func (e *Engine) applicationPayloadOverhead() int {
	binding := e.localGraphBinding()
	if binding.tracksSelectorState {
		return proto.HeaderSize + proto.DataSelectorStateEpochSize
	}
	return proto.HeaderSize
}
