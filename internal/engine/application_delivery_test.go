package engine

import (
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
)

func peakDeliveryManifest(t *testing.T) (proto.GraphManifest, proto.TargetID, proto.TargetID) {
	t.Helper()
	normal := proto.GraphNode{
		ID:   proto.DeriveTargetID(proto.GraphNodeKindPath, "normal"),
		Kind: proto.GraphNodeKindPath, Name: "normal",
	}
	peak := proto.GraphNode{
		ID:   proto.DeriveTargetID(proto.GraphNodeKindPath, "peak"),
		Kind: proto.GraphNodeKindPath, Name: "peak",
	}
	root := proto.GraphNode{
		ID:   proto.DeriveTargetID(proto.GraphNodeKindSelector, "root"),
		Kind: proto.GraphNodeKindSelector, Name: "root",
		Children: []proto.TargetID{normal.ID, peak.ID}, PeakCandidates: []proto.TargetID{peak.ID},
	}
	manifest := proto.GraphManifest{RootID: root.ID, Nodes: []proto.GraphNode{root, normal, peak}}
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	return manifest, normal.ID, peak.ID
}

func attributedDataFrame(
	t *testing.T,
	manifest proto.GraphManifest,
	targetID proto.TargetID,
	stateEpoch, seq uint64,
	payload []byte,
) (proto.Header, []byte, []byte) {
	t.Helper()
	flags, err := proto.DataFlagsForSelectorState(true, true)
	if err != nil {
		t.Fatal(err)
	}
	wirePayload, err := proto.EncodeDataSelectorStateEpoch(stateEpoch, payload)
	if err != nil {
		t.Fatal(err)
	}
	header := proto.Header{Version: proto.Version, Type: proto.FrameData, Flags: flags, Seq: seq}
	frame := make([]byte, proto.HeaderSize+len(wirePayload))
	if err := header.Encode(frame[:proto.HeaderSize]); err != nil {
		t.Fatal(err)
	}
	copy(frame[proto.HeaderSize:], wirePayload)
	return header, wirePayload, frame
}

func peerSelectorStateFrame(
	t *testing.T,
	e *Engine,
	manifest proto.GraphManifest,
	targetID proto.TargetID,
	generation, stateEpoch, seq uint64,
) (proto.Header, []byte) {
	t.Helper()
	digest, err := manifest.Digest()
	if err != nil {
		t.Fatal(err)
	}
	payload := proto.SelectorStatePayload{
		SessionEpoch: proto.SessionEpoch(e.FlowID()), Direction: peerSenderDirection(e.side),
		GraphRevision: 1, GraphDigest: digest, StateEpoch: stateEpoch,
		Entries: []proto.SelectorStateEntry{{
			SelectorID: manifest.RootID, DesiredTargetID: targetID,
			EffectiveTargetID: targetID, Generation: generation,
		}},
	}
	wire, err := proto.EncodeSelectorState(payload, manifest, proto.GraphBinding{Revision: 1, Digest: digest})
	if err != nil {
		t.Fatal(err)
	}
	return proto.Header{
		Version: proto.Version, Type: proto.FrameCtrl,
		Flags: proto.FlagsForCtrl(proto.CtrlSelectorState), Seq: seq,
	}, wire
}

func TestApplicationDeliveryRequiresProofValidPeerAck(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })

	reserveDeliveryFrame := func(seq uint64, frameType proto.FrameType, payload []byte) {
		t.Helper()
		frame := make([]byte, proto.HeaderSize+len(payload))
		if err := (proto.Header{Version: proto.Version, Type: frameType, Seq: seq}).Encode(frame[:proto.HeaderSize]); err != nil {
			t.Fatal(err)
		}
		copy(frame[proto.HeaderSize:], payload)
		if err := e.acquireSendSlot(frameType == proto.FrameCtrl, len(frame)); err != nil {
			t.Fatal(err)
		}
		if err := e.reserveOwnedSendFrame(frame); err != nil {
			t.Fatal(err)
		}
		e.publishSendSeq(seq + 1)
	}

	reserveDeliveryFrame(0, proto.FrameData, []byte("first"))
	reserveDeliveryFrame(1, proto.FrameCtrl, []byte("control"))
	reserveDeliveryFrame(2, proto.FrameData, []byte("second-payload"))

	before := e.ApplicationDelivery()
	if before.PublishedNext != 3 || before.AckNext != 0 || before.AckedPayloadBytes != 0 ||
		before.PendingPayloadBytes != uint64(len("first")+len("second-payload")) ||
		before.PublishedPayloadBytes != before.PendingPayloadBytes {
		t.Fatalf("before ACK snapshot=%+v", before)
	}

	bad := currentAck(e, 3)
	bad.Proof[0]++
	if e.notePeerAck(bad) {
		t.Fatal("invalid proof advanced application delivery")
	}
	if got := e.ApplicationDelivery(); got.AckedPayloadBytes != 0 || got.PendingPayloadBytes != before.PendingPayloadBytes {
		t.Fatalf("invalid ACK changed delivery=%+v", got)
	}

	if !e.notePeerAck(currentAck(e, 3)) {
		t.Fatal("valid cumulative ACK was rejected")
	}
	after := e.ApplicationDelivery()
	if after.AckNext != 3 || after.AckedPayloadBytes != before.PublishedPayloadBytes ||
		after.PendingPayloadBytes != 0 || after.PublishedPayloadBytes != before.PublishedPayloadBytes {
		t.Fatalf("after ACK snapshot=%+v", after)
	}
}

func TestApplicationDeliveryExcludesUnpublishedReservation(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })

	payload := []byte("reserved-but-not-published")
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := (proto.Header{Version: proto.Version, Type: proto.FrameData, Seq: 0}).Encode(frame[:proto.HeaderSize]); err != nil {
		t.Fatal(err)
	}
	copy(frame[proto.HeaderSize:], payload)
	if err := e.acquireSendSlot(false, len(frame)); err != nil {
		t.Fatal(err)
	}
	if err := e.reserveOwnedSendFrame(frame); err != nil {
		t.Fatal(err)
	}

	if got := e.ApplicationDelivery(); got.PublishedPayloadBytes != 0 || got.PendingPayloadBytes != 0 || got.PublishedNext != 0 {
		t.Fatalf("unpublished reservation appeared as delivery=%+v", got)
	}
	if !e.rollbackReservedSendFrame(0) {
		t.Fatal("rollback unpublished reservation")
	}
}

func TestShortDispatchClearsOlderDemandEvidenceWithoutAllocation(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	epoch := e.currentPathTopologyEpoch()
	finished := nowFn()
	pressured := &applicationDispatchDemandEvidence{
		topologyEpoch: epoch, finished: finished, duration: 2 * time.Millisecond,
	}
	retained := false
	allocations := testing.AllocsPerRun(1000, func() {
		e.lastApplicationDispatch.Store(pressured)
		e.noteApplicationDispatchDuration(
			rootDeliveryCohort{}, epoch, finished.Add(time.Millisecond),
			finished.Add(time.Millisecond+time.Microsecond), true,
		)
		if e.lastApplicationDispatch.Load() != nil {
			retained = true
		}
	})
	if retained {
		t.Fatal("sub-threshold dispatch retained older evidence")
	}
	if allocations != 0 {
		t.Fatalf("sub-threshold evidence clear allocations/run=%.2f want 0", allocations)
	}
}

func TestPacketTargetDeliveryIgnoresLateOlderGeneration(t *testing.T) {
	manifest, normalID, _ := peakDeliveryManifest(t)
	e := New(SideServer, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	e.SetPacketMode()
	slot := &pathSlot{peerTXTargetID: normalID}

	oldStateHeader, oldStateWire := peerSelectorStateFrame(t, e, manifest, normalID, 1, 1, 0)
	newStateHeader, newStateWire := peerSelectorStateFrame(t, e, manifest, normalID, 2, 2, 2)
	newHeader, newWire, _ := attributedDataFrame(t, manifest, normalID, 2, 3, []byte("new"))
	oldHeader, oldWire, _ := attributedDataFrame(t, manifest, normalID, 1, 1, []byte("old"))
	delivered := make([][]byte, 0, 2)
	e.recvMu.Lock()
	e.onFrameRecvLocked(slot, oldStateHeader, oldStateWire, &delivered)
	e.onFrameRecvLocked(slot, newStateHeader, newStateWire, &delivered)
	if e.onFrameRecvLocked(slot, newHeader, newWire, &delivered) {
		e.recvMu.Unlock()
		t.Fatal("newer packet was delivered before its selector-state predecessor chain")
	}
	if !e.onFrameRecvLocked(slot, oldHeader, oldWire, &delivered) {
		e.recvMu.Unlock()
		t.Fatal("valid older packet did not release the selector-state chain")
	}
	newSnapshot := e.peerTargetDeliveryLocked(proto.TargetID{})
	after := e.peerTargetDeliveryLocked(proto.TargetID{})
	unique := e.recvUniqueBytes
	terminal := e.recvTerminal
	e.recvMu.Unlock()

	if len(delivered) != 2 || string(delivered[0]) != "old" || string(delivered[1]) != "new" {
		t.Fatalf("packet delivery=%q", delivered)
	}
	if terminal {
		t.Fatal("valid generation reordering terminated the session")
	}
	if after.SelectorGeneration != 2 || after.TargetID != normalID ||
		after.AckedBytes != newSnapshot.AckedBytes || after.DemandBytes != newSnapshot.DemandBytes {
		t.Fatalf("older generation moved current telemetry: before=%+v after=%+v", newSnapshot, after)
	}
	if unique != uint64(len("new")+len("old")) {
		t.Fatalf("unique application bytes=%d", unique)
	}
}

func TestPacketTargetDeliveryAlternateLeafWithinStateIsUnattributable(t *testing.T) {
	manifest, normalID, peakID := peakDeliveryManifest(t)
	e := New(SideServer, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	e.SetPacketMode()
	normalSlot := &pathSlot{peerTXTargetID: normalID}
	peakSlot := &pathSlot{peerTXTargetID: peakID}

	stateHeader, stateWire := peerSelectorStateFrame(t, e, manifest, peakID, 7, 1, 0)
	peakHeader, peakWire, _ := attributedDataFrame(t, manifest, peakID, 1, 2, []byte("peak"))
	normalHeader, normalWire, _ := attributedDataFrame(t, manifest, normalID, 1, 1, []byte("normal"))
	delivered := make([][]byte, 0, 2)
	e.recvMu.Lock()
	e.onFrameRecvLocked(peakSlot, stateHeader, stateWire, &delivered)
	if !e.onFrameRecvLocked(peakSlot, peakHeader, peakWire, &delivered) {
		e.recvMu.Unlock()
		t.Fatal("first packet was not accepted")
	}
	before := e.peerTargetDeliveryLocked(proto.TargetID{})
	if !e.onFrameRecvLocked(normalSlot, normalHeader, normalWire, &delivered) {
		e.recvMu.Unlock()
		t.Fatal("alternate replay leaf was not application-readable")
	}
	snapshot := e.peerTargetDeliveryLocked(proto.TargetID{})
	terminalErr := e.recvFinalErr
	terminal := e.recvTerminal
	e.recvMu.Unlock()

	if terminal || terminalErr != nil {
		t.Fatalf("alternate replay leaf terminal=%t err=%v", terminal, terminalErr)
	}
	if len(delivered) != 2 || string(delivered[0]) != "peak" || string(delivered[1]) != "normal" {
		t.Fatalf("alternate replay delivery=%q", delivered)
	}
	if !before.Attributable || before.TargetID != peakID || before.AckedBytes != uint64(len("peak")) {
		t.Fatalf("selected leaf was not attributable before alternate delivery: %+v", before)
	}
	if snapshot.Attributable || snapshot.TargetID != peakID || snapshot.AckedBytes != 0 {
		t.Fatalf("alternate physical leaf remained attributable: %+v", snapshot)
	}
}

func TestPeerTargetDeliveryDoesNotCrossPhysicalTopologyEpoch(t *testing.T) {
	manifest, normalID, _ := peakDeliveryManifest(t)
	e := New(SideServer, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}

	oldEpoch := e.currentPathTopologyEpoch()
	slot := &pathSlot{peerTXTargetID: normalID}
	slot.topologyEpoch.Store(oldEpoch)
	stateHeader, stateWire := peerSelectorStateFrame(t, e, manifest, normalID, 1, 1, 0)
	oldHeader, oldWire, _ := attributedDataFrame(
		t, manifest, normalID, 1, 2, []byte("old-topology-delayed"),
	)
	newHeader, newWire, _ := attributedDataFrame(
		t, manifest, normalID, 1, 1, []byte("new-topology-frontier"),
	)

	e.recvMu.Lock()
	e.onFrameRecvLocked(slot, stateHeader, stateWire, nil)
	if e.onFrameRecvLocked(slot, oldHeader, oldWire, nil) {
		e.recvMu.Unlock()
		t.Fatal("out-of-order old-topology frame became readable before its gap closed")
	}
	e.recvMu.Unlock()

	e.pathsMu.Lock()
	newEpoch := e.advancePathTopologyEpochLocked()
	e.pathsMu.Unlock()
	slot.topologyEpoch.Store(newEpoch)

	e.recvMu.Lock()
	if !e.onFrameRecvLocked(slot, newHeader, newWire, nil) {
		e.recvMu.Unlock()
		t.Fatal("new topology frontier did not release contiguous stream data")
	}
	snapshot := e.peerTargetDeliveryLocked(proto.TargetID{})
	unique := e.recvUniqueBytes
	delivered := append([]byte(nil), e.recvDeliver...)
	e.recvMu.Unlock()

	wantDelivered := "new-topology-frontierold-topology-delayed"
	if string(delivered) != wantDelivered {
		t.Fatalf("stream delivery=%q want %q", delivered, wantDelivered)
	}
	if unique != uint64(len(wantDelivered)) {
		t.Fatalf("unique bytes=%d want %d", unique, len(wantDelivered))
	}
	if !snapshot.Attributable || snapshot.TargetID != normalID ||
		snapshot.AckedBytes != uint64(len("new-topology-frontier")) {
		t.Fatalf("current-topology peer delivery=%+v", snapshot)
	}
}

func TestDispatchDurationEvidenceSurvivesEarlyPeerAck(t *testing.T) {
	manifest, normalID, _ := peakDeliveryManifest(t)
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	digest, err := manifest.Digest()
	if err != nil {
		t.Fatal(err)
	}
	e.rememberSendSelectorStateLocked(newSelectorStateRecord(proto.SelectorStatePayload{
		SessionEpoch: proto.SessionEpoch(e.FlowID()), Direction: senderDirection(e.side),
		GraphRevision: 1, GraphDigest: digest, StateEpoch: 1,
		Entries: []proto.SelectorStateEntry{{
			SelectorID: manifest.RootID, DesiredTargetID: normalID,
			EffectiveTargetID: normalID, Generation: 1,
		}},
	}, nil))
	_, _, frame := attributedDataFrame(t, manifest, normalID, 1, 0, []byte("payload"))
	cohort := rootDeliveryCohort{selectorID: manifest.RootID, targetID: normalID, generation: 1}
	if err := e.acquireSendSlot(false, len(frame)); err != nil {
		t.Fatal(err)
	}
	if err := e.reserveOwnedApplicationFrame(frame, rootDataAttribution{
		cohort: cohort, committed: true, stateEpoch: 1,
	}, len("payload")); err != nil {
		t.Fatal(err)
	}
	e.publishSendSeq(1)
	e.noteApplicationDispatchRoute(frame, &pathSlot{localTXTargetID: normalID})
	e.sendHistMu.Lock()
	proof := e.sendHist.entries[0].proof
	e.sendHistMu.Unlock()
	if valid, _ := e.acknowledgeSendFrames(1, proof); !valid {
		t.Fatal("peer ACK was rejected")
	}
	e.sendHistMu.Lock()
	remaining := len(e.sendHist.entries)
	e.sendHistMu.Unlock()
	if remaining != 0 {
		t.Fatalf("ACK retained %d replay entries", remaining)
	}

	finished := nowFn()
	e.noteApplicationDispatchDuration(
		e.applicationRootCohortFromFrame(frame), e.currentPathTopologyEpoch(),
		finished.Add(-2*time.Millisecond), finished, true,
	)
	if !e.applicationDemandForRoot(cohort.selectorID, cohort.targetID, cohort.generation) {
		t.Fatal("physical blocking evidence was lost after an early ACK released the ledger")
	}
}

func TestLeafGoodputRequiresProofValidSingleLeafDelivery(t *testing.T) {
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

	payload := make([]byte, selectorGoodputMinimumBytes)
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := (proto.Header{Version: proto.Version, Type: proto.FrameData, Seq: 0}).Encode(frame[:proto.HeaderSize]); err != nil {
		t.Fatal(err)
	}
	copy(frame[proto.HeaderSize:], payload)
	if err := e.acquireSendSlot(false, len(frame)); err != nil {
		t.Fatal(err)
	}
	if err := e.reserveOwnedSendFrame(frame); err != nil {
		t.Fatal(err)
	}
	e.publishSendSeq(1)
	e.noteApplicationDispatchRoute(frame, &pathSlot{localTXTargetID: ids["a"]})

	e.sendHistMu.Lock()
	state := e.sendHist.targetDelivery[ids["a"]]
	state.windowStart = nowFn().Add(-time.Second)
	e.sendHist.targetDelivery[ids["a"]] = state
	proof := e.sendHist.entries[0].proof
	e.sendHistMu.Unlock()
	if valid, _ := e.acknowledgeSendFrames(1, proof); !valid {
		t.Fatal("proof-valid cumulative ACK was rejected")
	}

	speeds := e.targetDeliverySpeeds(nowFn())
	got, ok := speeds[ids["a"]]
	if !ok || !got.fresh(1) || got.source != speedSourceDelivered || got.bytesPerSecond == 0 {
		t.Fatalf("single-leaf delivered goodput=%+v present=%t", got, ok)
	}
	if _, ok := speeds[ids["b"]]; ok {
		t.Fatal("idle sibling acquired fabricated delivered goodput")
	}
}

func TestLeafGoodputPromotesCrossLeafReplayOnlyToCommonGroup(t *testing.T) {
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

	payload := make([]byte, selectorGoodputMinimumBytes)
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := (proto.Header{Version: proto.Version, Type: proto.FrameData, Seq: 0}).Encode(frame[:proto.HeaderSize]); err != nil {
		t.Fatal(err)
	}
	copy(frame[proto.HeaderSize:], payload)
	if err := e.acquireSendSlot(false, len(frame)); err != nil {
		t.Fatal(err)
	}
	if err := e.reserveOwnedSendFrame(frame); err != nil {
		t.Fatal(err)
	}
	e.publishSendSeq(1)
	e.noteApplicationDispatchRoute(frame, &pathSlot{localTXTargetID: ids["a"]})
	e.noteApplicationDispatchRoute(frame, &pathSlot{localTXTargetID: ids["b"]})

	e.sendHistMu.Lock()
	for targetID, state := range e.sendHist.targetDelivery {
		state.windowStart = nowFn().Add(-time.Second)
		e.sendHist.targetDelivery[targetID] = state
	}
	proof := e.sendHist.entries[0].proof
	e.sendHistMu.Unlock()
	if valid, _ := e.acknowledgeSendFrames(1, proof); !valid {
		t.Fatal("proof-valid cumulative ACK was rejected")
	}
	if speeds := e.targetDeliverySpeeds(nowFn()); len(speeds) != 0 {
		t.Fatalf("cross-selector-child replay produced child delivered goodput=%+v", speeds)
	}

	unknown := make([]byte, len(frame))
	copy(unknown, frame)
	if err := (proto.Header{Version: proto.Version, Type: proto.FrameData, Seq: 1}).Encode(unknown[:proto.HeaderSize]); err != nil {
		t.Fatal(err)
	}
	if err := e.acquireSendSlot(false, len(unknown)); err != nil {
		t.Fatal(err)
	}
	if err := e.reserveOwnedSendFrame(unknown); err != nil {
		t.Fatal(err)
	}
	e.publishSendSeq(2)
	e.noteApplicationDispatchRoute(unknown, &pathSlot{localTXTargetID: proto.TargetID{0xff}})
	e.sendHistMu.Lock()
	_, unknownRecorded := e.sendHist.targetDelivery[proto.TargetID{0xff}]
	e.sendHistMu.Unlock()
	if unknownRecorded {
		t.Fatal("non-manifest leaf expanded bounded telemetry state")
	}
}

func TestRaceGoodputCreditsUniquePayloadOnceToRaceTarget(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "redundant", "direct"),
		runtimeNode(proto.GraphNodeKindRace, "redundant", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
		runtimeNode(proto.GraphNodeKindPath, "direct"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, selectorGoodputMinimumBytes)
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := (proto.Header{Version: proto.Version, Type: proto.FrameData, Seq: 0}).Encode(frame[:proto.HeaderSize]); err != nil {
		t.Fatal(err)
	}
	if err := e.acquireSendSlot(false, len(frame)); err != nil {
		t.Fatal(err)
	}
	if err := e.reserveOwnedSendFrame(frame); err != nil {
		t.Fatal(err)
	}
	e.publishSendSeq(1)
	e.noteApplicationDispatchPlan(frame, []dispatchRoute{{targetID: ids["a"]}, {targetID: ids["b"]}})
	e.sendHistMu.Lock()
	state := e.sendHist.targetDelivery[ids["redundant"]]
	state.windowStart = nowFn().Add(-time.Second)
	e.sendHist.targetDelivery[ids["redundant"]] = state
	proof := e.sendHist.entries[0].proof
	e.sendHistMu.Unlock()
	if valid, _ := e.acknowledgeSendFrames(1, proof); !valid {
		t.Fatal("proof-valid cumulative ACK was rejected")
	}
	speeds := e.targetDeliverySpeeds(nowFn())
	if got := speeds[ids["redundant"]]; !got.fresh(1) || got.bytesPerSecond == 0 {
		t.Fatalf("race aggregate goodput=%+v", got)
	}
	if _, ok := speeds[ids["a"]]; ok {
		t.Fatal("race copy was credited as unique leaf goodput")
	}
	if _, ok := speeds[ids["b"]]; ok {
		t.Fatal("race copy was credited as unique leaf goodput")
	}
}

func TestTargetGoodputSamplesWholeCumulativeAckBatch(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}

	for seq := uint64(0); seq < 2; seq++ {
		frame := make([]byte, proto.HeaderSize+selectorGoodputMinimumBytes)
		if err := (proto.Header{Version: proto.Version, Type: proto.FrameData, Seq: seq}).Encode(frame[:proto.HeaderSize]); err != nil {
			t.Fatal(err)
		}
		if err := e.acquireSendSlot(false, len(frame)); err != nil {
			t.Fatal(err)
		}
		if err := e.reserveOwnedSendFrame(frame); err != nil {
			t.Fatal(err)
		}
		e.publishSendSeq(seq + 1)
		e.noteApplicationDispatchRoute(frame, &pathSlot{localTXTargetID: ids["a"]})
	}
	e.sendHistMu.Lock()
	state := e.sendHist.targetDelivery[ids["a"]]
	state.windowStart = nowFn().Add(-time.Second)
	e.sendHist.targetDelivery[ids["a"]] = state
	proof := e.sendHist.entries[1].proof
	e.sendHistMu.Unlock()
	if valid, _ := e.acknowledgeSendFrames(2, proof); !valid {
		t.Fatal("proof-valid cumulative ACK was rejected")
	}
	got := e.targetDeliverySpeeds(nowFn())[ids["a"]]
	if !got.fresh(1) || got.bytesPerSecond < 3*selectorGoodputMinimumBytes/2 {
		t.Fatalf("cumulative ACK goodput=%+v, want whole two-frame batch", got)
	}
}

func TestLeafGoodputFreshnessAndClockRollback(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	targetID := proto.DeriveTargetID(proto.GraphNodeKindPath, "sample")
	sampledAt := time.Unix(500, 0)
	e.sendHistMu.Lock()
	e.sendHist.targetDelivery = map[proto.TargetID]targetDeliveryEvidence{
		targetID: {topologyEpoch: e.currentPathTopologyEpoch(), estimate: speedEstimate{
			state: qualityStateFresh, bytesPerSecond: 1 << 20,
			confidence: evidenceConfidenceFull, source: speedSourceDelivered,
			sampleTime: sampledAt, sampleCount: 1,
		}},
	}
	e.sendHistMu.Unlock()

	if got := e.targetDeliverySpeeds(sampledAt.Add(selectorEvidenceFreshFor + time.Nanosecond))[targetID]; got.state != qualityStateStale {
		t.Fatalf("expired goodput state=%v", got.state)
	}
	if got := e.targetDeliverySpeeds(sampledAt.Add(-time.Nanosecond)); len(got) != 0 {
		t.Fatalf("clock rollback retained goodput=%+v", got)
	}
}

func TestLeafGoodputDoesNotCrossPhysicalTopologyEpoch(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "path"),
		runtimeNode(proto.GraphNodeKindPath, "path"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}

	payload := make([]byte, selectorGoodputMinimumBytes)
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := (proto.Header{Version: proto.Version, Type: proto.FrameData, Seq: 0}).Encode(frame[:proto.HeaderSize]); err != nil {
		t.Fatal(err)
	}
	copy(frame[proto.HeaderSize:], payload)
	if err := e.acquireSendSlot(false, len(frame)); err != nil {
		t.Fatal(err)
	}
	if err := e.reserveOwnedSendFrame(frame); err != nil {
		t.Fatal(err)
	}
	e.publishSendSeq(1)
	dispatchEpoch := e.currentPathTopologyEpoch()
	e.noteApplicationDispatchRouteAtEpoch(
		frame, &pathSlot{localTXTargetID: ids["path"]}, dispatchEpoch,
	)
	e.sendHistMu.Lock()
	state := e.sendHist.targetDelivery[ids["path"]]
	state.windowStart = nowFn().Add(-time.Second)
	e.sendHist.targetDelivery[ids["path"]] = state
	proof := e.sendHist.entries[0].proof
	e.sendHistMu.Unlock()

	e.pathsMu.Lock()
	e.advancePathTopologyEpochLocked()
	e.pathsMu.Unlock()
	if valid, application := e.acknowledgeSendFrames(1, proof); !valid || !application {
		t.Fatalf("proof-valid old-topology ACK valid/application=%t/%t", valid, application)
	}
	if got := e.ApplicationDelivery().AckedPayloadBytes; got != uint64(len(payload)) {
		t.Fatalf("old-topology application delivery=%d want %d", got, len(payload))
	}
	if speeds := e.targetDeliverySpeeds(nowFn()); len(speeds) != 0 {
		t.Fatalf("old-topology ACK produced current speed evidence=%+v", speeds)
	}

	currentEpoch := e.currentPathTopologyEpoch()
	e.sendHistMu.Lock()
	e.beginTargetDeliveryWindowLocked(ids["path"], currentEpoch, nowFn().Add(-time.Second))
	e.addTargetDeliveryLocked(ids["path"], currentEpoch, selectorGoodputMinimumBytes, nowFn())
	e.sampleTargetDeliveryLocked(ids["path"], nowFn())
	e.sendHistMu.Unlock()
	if got := e.targetDeliverySpeeds(nowFn())[ids["path"]]; !got.fresh(1) {
		t.Fatalf("current topology could not rebuild speed evidence=%+v", got)
	}
}

func TestBatchAckBeforeReturnCannotCrossPhysicalTopologyEpoch(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "path"),
		runtimeNode(proto.GraphNodeKindPath, "path"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}

	payload := make([]byte, selectorGoodputMinimumBytes)
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := (proto.Header{Version: proto.Version, Type: proto.FrameData, Seq: 0}).Encode(frame[:proto.HeaderSize]); err != nil {
		t.Fatal(err)
	}
	copy(frame[proto.HeaderSize:], payload)
	if err := e.acquireSendSlot(false, len(frame)); err != nil {
		t.Fatal(err)
	}
	if err := e.reserveOwnedSendFrame(frame); err != nil {
		t.Fatal(err)
	}
	e.publishSendSeq(1)
	dispatchEpoch := e.currentPathTopologyEpoch()
	receipt := e.beginApplicationBatchDispatch(
		frame, &pathSlot{localTXTargetID: ids["path"]}, dispatchEpoch,
	)
	if receipt == nil {
		t.Fatal("batch dispatch did not create attribution receipt")
	}
	e.sendHistMu.Lock()
	proof := e.sendHist.entries[0].proof
	e.sendHistMu.Unlock()
	if valid, application := e.acknowledgeSendFrames(1, proof); !valid || !application {
		t.Fatalf("early batch ACK valid/application=%t/%t", valid, application)
	}

	e.pathsMu.Lock()
	e.advancePathTopologyEpochLocked()
	e.pathsMu.Unlock()
	receipt.started = nowFn().Add(-time.Second)
	e.resolveApplicationBatchDispatch([]*batchDispatchAttributionReceipt{receipt}, 1)
	if got := e.ApplicationDelivery().AckedPayloadBytes; got != uint64(len(payload)) {
		t.Fatalf("early batch application delivery=%d want %d", got, len(payload))
	}
	if speeds := e.targetDeliverySpeeds(nowFn()); len(speeds) != 0 {
		t.Fatalf("detached old-topology batch receipt produced speed=%+v", speeds)
	}
}
