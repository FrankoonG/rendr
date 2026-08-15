package engine

import (
	"fmt"
	"time"

	"github.com/FrankoonG/rendr/proto"
)

type rootDataAttribution struct {
	cohort    rootDeliveryCohort
	committed bool
	demand    bool
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

func (e *Engine) currentRootDataAttribution(runtime *executionRuntime) (rootDataAttribution, bool, error) {
	if runtime == nil || runtime.plan == nil {
		return rootDataAttribution{}, false, errExecutionRuntimeNotConfigured
	}
	binding := e.localGraphBinding()
	if !binding.rootTracksLocalDelivery {
		return rootDataAttribution{}, false, nil
	}
	selectorID, desired, effective, generation, ok := runtime.rootPublicationAttribution()
	if !ok || selectorID != binding.rootSelectorID || desired == (proto.TargetID{}) || generation == 0 {
		return rootDataAttribution{}, true, errNoExecutionRoute
	}
	return rootDataAttribution{
		cohort: rootDeliveryCohort{
			selectorID: selectorID,
			targetID:   desired,
			generation: generation,
		},
		committed: desired == effective && effective != (proto.TargetID{}),
		demand:    e.applicationDemandForRoot(selectorID, desired, generation),
	}, true, nil
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
		!finished.After(started) || cohort.targetID == (proto.TargetID{}) {
		return
	}
	e.lastApplicationDispatch.Store(&applicationDispatchDemandEvidence{
		cohort: cohort, topologyEpoch: topologyEpoch,
		finished: finished, duration: finished.Sub(started),
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
	if len(frame) < proto.HeaderSize+proto.DataRootGenerationSize {
		return rootDeliveryCohort{}
	}
	binding := e.localGraphBinding()
	if !binding.rootTracksWireAttribution {
		return rootDeliveryCohort{}
	}
	targetID, _, _, err := binding.rootTargetFromDataFlags(header.Flags)
	if err != nil {
		return rootDeliveryCohort{}
	}
	generation, _, err := proto.DecodeDataRootGeneration(frame[proto.HeaderSize:])
	if err != nil {
		return rootDeliveryCohort{}
	}
	return rootDeliveryCohort{
		selectorID: binding.rootSelectorID,
		targetID:   targetID,
		generation: generation,
	}
}

func (e *Engine) encodeApplicationPayload(payload []byte, runtime *executionRuntime) (uint16, []byte, rootDataAttribution, error) {
	attribution, tracked, err := e.currentRootDataAttribution(runtime)
	if err != nil {
		return 0, nil, rootDataAttribution{}, err
	}
	binding := e.localGraphBinding()
	if !tracked {
		flags, err := binding.dataFlagsForRootTarget(proto.TargetID{}, false, false)
		return flags, payload, rootDataAttribution{}, err
	}
	if !binding.rootTracksWireAttribution {
		return 0, payload, attribution, nil
	}
	flags, err := binding.dataFlagsForRootTarget(attribution.cohort.targetID, attribution.committed, attribution.demand)
	if err != nil {
		return 0, nil, rootDataAttribution{}, err
	}
	wirePayload, err := proto.EncodeDataRootGeneration(attribution.cohort.generation, payload)
	if err != nil {
		return 0, nil, rootDataAttribution{}, err
	}
	return flags, wirePayload, attribution, nil
}

func (e *Engine) decodePeerApplicationPayload(
	slot *pathSlot,
	flags uint16,
	wirePayload []byte,
) (payload []byte, cohort rootDeliveryCohort, eligible, demand bool, err error) {
	binding := e.peerGraphBinding()
	if !binding.configured {
		return nil, rootDeliveryCohort{}, false, false, fmt.Errorf("peer graph is not configured")
	}
	targetID, committed, demand, err := binding.rootTargetFromDataFlags(flags)
	if err != nil {
		return nil, rootDeliveryCohort{}, false, false, err
	}
	if !binding.rootTracksWireAttribution {
		return wirePayload, rootDeliveryCohort{}, false, false, nil
	}
	generation, payload, err := proto.DecodeDataRootGeneration(wirePayload)
	if err != nil {
		return nil, rootDeliveryCohort{}, false, false, err
	}
	cohort = rootDeliveryCohort{
		selectorID: binding.rootSelectorID,
		targetID:   targetID,
		generation: generation,
	}
	physicalTarget, physicalOK := binding.rootTargetForLeaf(slotPeerTargetID(slot))
	eligible = committed && physicalOK && physicalTarget == targetID
	return payload, cohort, eligible, demand, nil
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
	if binding.rootTracksWireAttribution {
		return proto.HeaderSize + proto.DataRootGenerationSize
	}
	return proto.HeaderSize
}
