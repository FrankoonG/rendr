package engine

import (
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
)

func selectorStateControlFrame(
	t *testing.T,
	e *Engine,
	manifest proto.GraphManifest,
	desired, effective proto.TargetID,
	generation, stateEpoch, seq uint64,
) (proto.Header, []byte) {
	t.Helper()
	digest, err := manifest.Digest()
	if err != nil {
		t.Fatal(err)
	}
	payload := proto.SelectorStatePayload{
		SessionEpoch:  proto.SessionEpoch(e.FlowID()),
		Direction:     peerSenderDirection(e.side),
		GraphRevision: 1,
		GraphDigest:   digest,
		StateEpoch:    stateEpoch,
		Entries: []proto.SelectorStateEntry{{
			SelectorID:        manifest.RootID,
			DesiredTargetID:   desired,
			EffectiveTargetID: effective,
			Generation:        generation,
		}},
	}
	wire, err := proto.EncodeSelectorState(
		payload, manifest, proto.GraphBinding{Revision: 1, Digest: digest},
	)
	if err != nil {
		t.Fatal(err)
	}
	return proto.Header{
		Version: proto.Version,
		Type:    proto.FrameCtrl,
		Flags:   proto.FlagsForCtrl(proto.CtrlSelectorState),
		Seq:     seq,
	}, wire
}

func TestSelectorStateBundlePublishesControlImmediatelyBeforeData(t *testing.T) {
	manifest, ids := rootDeliveryTestManifest(t, "bundle-root", "bundle-a", "bundle-b", true)
	e, runtime := newRootDeliveryTestEngine(t, manifest, ids["first"])

	first := publishRootDeliveryTestFrame(t, e, runtime, []byte("first"))
	second := publishRootDeliveryTestFrame(t, e, runtime, []byte("second"))
	selectRootDeliveryTestTarget(t, runtime, ids["root"], ids["second"], ids["first"], ids["second"])
	third := publishRootDeliveryTestFrame(t, e, runtime, []byte("third"))

	e.sendHistMu.Lock()
	entries := append([]sendHistoryEntry(nil), e.sendHist.entries...)
	e.sendHistMu.Unlock()
	if len(entries) != 5 {
		t.Fatalf("ledger entries=%d want 5", len(entries))
	}
	wantTypes := []proto.FrameType{
		proto.FrameCtrl, proto.FrameData, proto.FrameData, proto.FrameCtrl, proto.FrameData,
	}
	for index, entry := range entries {
		header, err := proto.DecodeHeader(entry.frame[:proto.HeaderSize])
		if err != nil {
			t.Fatal(err)
		}
		if header.Seq != uint64(index) || header.Type != wantTypes[index] {
			t.Fatalf("ledger[%d] header=%+v", index, header)
		}
		if header.Type == proto.FrameCtrl && proto.CtrlCodeFromFlags(header.Flags) != proto.CtrlSelectorState {
			t.Fatalf("ledger[%d] control=%s want SELECTOR_STATE", index, proto.CtrlCodeFromFlags(header.Flags))
		}
	}

	firstHeader, err := proto.DecodeHeader(first[:proto.HeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	secondHeader, err := proto.DecodeHeader(second[:proto.HeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	thirdHeader, err := proto.DecodeHeader(third[:proto.HeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	if firstHeader.Seq != 1 || secondHeader.Seq != 2 || thirdHeader.Seq != 4 {
		t.Fatalf("DATA sequences=%d,%d,%d want 1,2,4", firstHeader.Seq, secondHeader.Seq, thirdHeader.Seq)
	}
	firstEpoch, _, err := proto.DecodeDataSelectorStateEpoch(first[proto.HeaderSize:])
	if err != nil {
		t.Fatal(err)
	}
	secondEpoch, _, err := proto.DecodeDataSelectorStateEpoch(second[proto.HeaderSize:])
	if err != nil {
		t.Fatal(err)
	}
	thirdEpoch, _, err := proto.DecodeDataSelectorStateEpoch(third[proto.HeaderSize:])
	if err != nil {
		t.Fatal(err)
	}
	if firstEpoch == 0 || secondEpoch != firstEpoch || thirdEpoch <= firstEpoch {
		t.Fatalf("DATA state epochs=%d,%d,%d", firstEpoch, secondEpoch, thirdEpoch)
	}
}

func TestPacketDataWaitsForReferencedSelectorState(t *testing.T) {
	manifest, normalID, _ := peakDeliveryManifest(t)
	e := New(SideServer, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	e.SetPacketMode()
	slot := &pathSlot{peerTXTargetID: normalID}
	stateHeader, stateWire := selectorStateControlFrame(t, e, manifest, normalID, normalID, 1, 1, 0)
	dataHeader, dataWire, _ := attributedDataFrame(t, manifest, normalID, 1, 1, []byte("deferred"))
	delivered := make([][]byte, 0, 1)

	e.recvMu.Lock()
	if e.onFrameRecvLocked(slot, dataHeader, dataWire, &delivered) {
		e.recvMu.Unlock()
		t.Fatal("DATA became readable before its selector state reached custody")
	}
	if len(delivered) != 0 || e.recvSelectorStatePendingBytes != len(dataWire) {
		e.recvMu.Unlock()
		t.Fatalf("pending delivery=%q bytes=%d want 0/%d", delivered, e.recvSelectorStatePendingBytes, len(dataWire))
	}
	if !e.onFrameRecvLocked(slot, stateHeader, stateWire, &delivered) {
		e.recvMu.Unlock()
		t.Fatal("selector state did not release deferred packet DATA")
	}
	if e.onFrameRecvLocked(slot, dataHeader, dataWire, &delivered) {
		e.recvMu.Unlock()
		t.Fatal("duplicate deferred DATA became readable twice")
	}
	terminal := e.recvTerminal
	pendingBytes := e.recvSelectorStatePendingBytes
	e.recvMu.Unlock()

	if terminal || pendingBytes != 0 || len(delivered) != 1 || string(delivered[0]) != "deferred" {
		t.Fatalf("terminal=%t pending=%d delivery=%q", terminal, pendingBytes, delivered)
	}
}

func TestSelectorStateRejectsWrongSessionDirectionRevisionAndDigest(t *testing.T) {
	manifest, normalID, _ := peakDeliveryManifest(t)
	e := New(SideServer, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	_, base := selectorStateControlFrame(t, e, manifest, normalID, normalID, 1, 1, 0)

	tests := []struct {
		name   string
		mutate func([]byte)
	}{
		{"session", func(wire []byte) { wire[44] ^= 0x80 }},
		{"direction", func(wire []byte) { wire[1] = byte(senderDirection(e.side)) }},
		{"revision", func(wire []byte) { binary.BigEndian.PutUint64(wire[4:12], 2) }},
		{"digest", func(wire []byte) { wire[12] ^= 0x80 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wire := append([]byte(nil), base...)
			test.mutate(wire)
			if _, err := e.decodePeerSelectorState(wire); err == nil {
				t.Fatal("accepted selector state with wrong binding")
			}
		})
	}
}

func TestSelectorStateRejectsDuplicateEpochAndAlteredSequence(t *testing.T) {
	manifest, normalID, peakID := peakDeliveryManifest(t)
	for _, test := range []struct {
		name string
		run  func(*testing.T, *Engine, *pathSlot)
	}{
		{
			name: "same epoch at different sequence",
			run: func(t *testing.T, e *Engine, slot *pathSlot) {
				firstHeader, firstWire := selectorStateControlFrame(t, e, manifest, normalID, normalID, 1, 1, 0)
				secondHeader := firstHeader
				secondHeader.Seq = 1
				e.onFrameRecvLocked(slot, firstHeader, firstWire, nil)
				e.onFrameRecvLocked(slot, secondHeader, firstWire, nil)
			},
		},
		{
			name: "altered payload at same sequence",
			run: func(t *testing.T, e *Engine, slot *pathSlot) {
				firstHeader, firstWire := selectorStateControlFrame(t, e, manifest, normalID, normalID, 1, 1, 0)
				_, alteredWire := selectorStateControlFrame(t, e, manifest, peakID, peakID, 1, 1, 0)
				e.onFrameRecvLocked(slot, firstHeader, firstWire, nil)
				e.onFrameRecvLocked(slot, firstHeader, alteredWire, nil)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			e := New(SideServer, NewClientFlowID(), Limits{}.Clamp())
			t.Cleanup(func() { _ = e.Close() })
			if err := e.ConfigurePeerGraph(1, manifest); err != nil {
				t.Fatal(err)
			}
			e.recvMu.Lock()
			test.run(t, e, &pathSlot{peerTXTargetID: normalID})
			terminal, terminalErr := e.recvTerminal, e.recvFinalErr
			e.recvMu.Unlock()
			if !terminal || !errors.Is(terminalErr, ErrPeerProtocol) {
				t.Fatalf("terminal=%t err=%v want peer protocol failure", terminal, terminalErr)
			}
		})
	}
}

func TestSelectorStateRejectsEpochSequenceInversion(t *testing.T) {
	manifest, normalID, peakID := peakDeliveryManifest(t)
	e := New(SideServer, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	slot := &pathSlot{peerTXTargetID: normalID}
	state2Header, state2Wire := selectorStateControlFrame(t, e, manifest, peakID, peakID, 2, 2, 2)
	state1Header, state1Wire := selectorStateControlFrame(t, e, manifest, normalID, normalID, 1, 1, 0)
	state3Header, state3Wire := selectorStateControlFrame(t, e, manifest, normalID, normalID, 3, 3, 1)

	e.recvMu.Lock()
	e.onFrameRecvLocked(slot, state2Header, state2Wire, nil)
	e.onFrameRecvLocked(slot, state1Header, state1Wire, nil)
	if e.recvTerminal {
		e.recvMu.Unlock()
		t.Fatal("valid out-of-order state publication terminated the peer")
	}
	e.onFrameRecvLocked(slot, state3Header, state3Wire, nil)
	terminal, terminalErr := e.recvTerminal, e.recvFinalErr
	e.recvMu.Unlock()
	if !terminal || !errors.Is(terminalErr, ErrPeerProtocol) {
		t.Fatalf("terminal=%t err=%v want epoch/sequence inversion failure", terminal, terminalErr)
	}
}

func TestSelectorStateAllowsEffectiveFallbackWithinGeneration(t *testing.T) {
	manifest, normalID, peakID := peakDeliveryManifest(t)
	e := New(SideServer, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	slot := &pathSlot{peerTXTargetID: peakID}
	committedHeader, committedWire := selectorStateControlFrame(t, e, manifest, peakID, peakID, 2, 1, 0)
	rollbackHeader, rollbackWire := selectorStateControlFrame(t, e, manifest, peakID, normalID, 2, 2, 1)

	e.recvMu.Lock()
	e.onFrameRecvLocked(slot, committedHeader, committedWire, nil)
	if e.recvTerminal {
		e.recvMu.Unlock()
		t.Fatal("valid committed selector state terminated the peer")
	}
	e.onFrameRecvLocked(slot, rollbackHeader, rollbackWire, nil)
	terminal, terminalErr := e.recvTerminal, e.recvFinalErr
	e.recvMu.Unlock()
	if terminal || terminalErr != nil {
		t.Fatalf("effective availability fallback terminated peer: terminal=%t err=%v", terminal, terminalErr)
	}
}

func TestSelectorStateRejectsDataThatPredatesItsControl(t *testing.T) {
	manifest, normalID, _ := peakDeliveryManifest(t)
	e := New(SideServer, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	e.SetPacketMode()
	slot := &pathSlot{peerTXTargetID: normalID}
	stateHeader, stateWire := selectorStateControlFrame(t, e, manifest, normalID, normalID, 1, 1, 2)
	dataHeader, dataWire, _ := attributedDataFrame(t, manifest, normalID, 1, 1, []byte("backward"))
	delivered := make([][]byte, 0, 1)

	e.recvMu.Lock()
	e.onFrameRecvLocked(slot, stateHeader, stateWire, &delivered)
	e.onFrameRecvLocked(slot, dataHeader, dataWire, &delivered)
	terminal, terminalErr := e.recvTerminal, e.recvFinalErr
	e.recvMu.Unlock()
	if !terminal || !errors.Is(terminalErr, ErrPeerProtocol) || len(delivered) != 0 {
		t.Fatalf("terminal=%t err=%v delivered=%q want backward-reference failure", terminal, terminalErr, delivered)
	}
}

func TestSelectorStateDoesNotAuthorizeDataBeforePredecessorChain(t *testing.T) {
	manifest, normalID, peakID := peakDeliveryManifest(t)
	e := New(SideServer, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	e.SetPacketMode()
	peakSlot := &pathSlot{peerTXTargetID: peakID}
	normalSlot := &pathSlot{peerTXTargetID: normalID}
	laterHeader, laterWire := selectorStateControlFrame(t, e, manifest, peakID, peakID, 1, 2, 2)
	dataHeader, dataWire, _ := attributedDataFrame(t, manifest, peakID, 2, 3, []byte("provisional"))
	earlierHeader, earlierWire := selectorStateControlFrame(t, e, manifest, normalID, normalID, 2, 1, 0)
	delivered := make([][]byte, 0, 1)

	e.recvMu.Lock()
	e.onFrameRecvLocked(peakSlot, laterHeader, laterWire, &delivered)
	e.onFrameRecvLocked(peakSlot, dataHeader, dataWire, &delivered)
	if len(delivered) != 0 || e.recvTerminal {
		e.recvMu.Unlock()
		t.Fatalf("provisional state leaked DATA: terminal=%t delivered=%q", e.recvTerminal, delivered)
	}
	e.onFrameRecvLocked(normalSlot, earlierHeader, earlierWire, &delivered)
	terminal, terminalErr := e.recvTerminal, e.recvFinalErr
	e.recvMu.Unlock()
	if !terminal || !errors.Is(terminalErr, ErrPeerProtocol) || len(delivered) != 0 {
		t.Fatalf("terminal=%t err=%v delivered=%q want invalid predecessor failure", terminal, terminalErr, delivered)
	}
}

func TestPendingSelectorStatePacketCannotCrossReceiveWindow(t *testing.T) {
	manifest, normalID, _ := peakDeliveryManifest(t)
	e := New(SideServer, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	e.SetPacketMode()
	seq := e.packetSeenCapLocked()
	header, wire, _ := attributedDataFrame(t, manifest, normalID, 1, seq, []byte("outside"))
	delivered := make([][]byte, 0, 1)

	e.recvMu.Lock()
	e.onFrameRecvLocked(&pathSlot{peerTXTargetID: normalID}, header, wire, &delivered)
	_, retained := e.recvQueue[seq]
	pendingBytes := e.recvSelectorStatePendingBytes
	e.recvMu.Unlock()
	if retained || pendingBytes != 0 || len(delivered) != 0 {
		t.Fatalf("outside-window pending DATA retained=%t bytes=%d delivered=%q", retained, pendingBytes, delivered)
	}
}

func TestSelectorStateControlCreditHonorsWriteDeadline(t *testing.T) {
	manifest, ids := rootDeliveryTestManifest(t, "deadline-root", "deadline-a", "deadline-b", true)
	e, runtime := newRootDeliveryTestEngine(t, manifest, ids["first"])
	for index := 0; index < sendControlReserve; index++ {
		e.sendControlSlots <- struct{}{}
	}
	deadline := time.Now().Add(20 * time.Millisecond)
	if err := e.SetWriteDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, credit, err := e.lockApplicationSendWithSelectorState(runtime)
	if !errors.Is(err, ErrWriteDeadlineExceeded) || credit {
		t.Fatalf("selector-state credit result credit=%t err=%v", credit, err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("selector-state credit ignored write deadline for %s", elapsed)
	}
}

func TestSelectorStateHistoryRetainsFrontierStateThroughControlReserve(t *testing.T) {
	manifest, normalID, peakID := peakDeliveryManifest(t)
	e := New(SideServer, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	normalSlot := &pathSlot{peerTXTargetID: normalID}
	peakSlot := &pathSlot{peerTXTargetID: peakID}

	state1Header, state1Wire := selectorStateControlFrame(t, e, manifest, normalID, normalID, 1, 1, 0)
	data1Header, data1Wire, _ := attributedDataFrame(t, manifest, normalID, 1, 1, []byte("1"))
	e.recvMu.Lock()
	e.onFrameRecvLocked(normalSlot, state1Header, state1Wire, nil)
	for epoch := uint64(2); epoch <= uint64(selectorStateHistoryLimit); epoch++ {
		target := normalID
		slot := normalSlot
		if epoch%2 == 0 {
			target = peakID
			slot = peakSlot
		}
		controlSeq := (epoch - 1) * 2
		stateHeader, stateWire := selectorStateControlFrame(t, e, manifest, target, target, epoch, epoch, controlSeq)
		dataHeader, dataWire, _ := attributedDataFrame(t, manifest, target, epoch, controlSeq+1, []byte{byte('0' + epoch)})
		e.onFrameRecvLocked(slot, stateHeader, stateWire, nil)
		e.onFrameRecvLocked(slot, dataHeader, dataWire, nil)
	}
	if e.recvTerminal || len(e.recvSelectorStates) != selectorStateHistoryLimit || e.recvSelectorStates[1] == nil {
		e.recvMu.Unlock()
		t.Fatalf("before delayed DATA terminal=%t states=%d frontier-state=%t",
			e.recvTerminal, len(e.recvSelectorStates), e.recvSelectorStates[1] != nil)
	}
	if !e.onFrameRecvLocked(normalSlot, data1Header, data1Wire, nil) {
		e.recvMu.Unlock()
		t.Fatal("delayed frontier DATA did not release the contiguous stream")
	}
	if e.recvTerminal || e.expectedRecvSeq != uint64(selectorStateHistoryLimit*2) {
		e.recvMu.Unlock()
		t.Fatalf("after delayed DATA terminal=%t expected=%d", e.recvTerminal, e.expectedRecvSeq)
	}

	epoch := uint64(selectorStateHistoryLimit + 1)
	target := peakID
	controlSeq := (epoch - 1) * 2
	stateHeader, stateWire := selectorStateControlFrame(t, e, manifest, target, target, epoch, epoch, controlSeq)
	dataHeader, dataWire, _ := attributedDataFrame(t, manifest, target, epoch, controlSeq+1, []byte("x"))
	e.onFrameRecvLocked(peakSlot, stateHeader, stateWire, nil)
	e.onFrameRecvLocked(peakSlot, dataHeader, dataWire, nil)
	terminal := e.recvTerminal
	stateCount := len(e.recvSelectorStates)
	oldPruned := e.recvSelectorStates[1] == nil
	latestPresent := e.recvSelectorStates[epoch] != nil
	e.recvMu.Unlock()
	if terminal || stateCount != selectorStateHistoryLimit || !oldPruned || !latestPresent {
		t.Fatalf("post-frontier terminal=%t states=%d old-pruned=%t latest=%t",
			terminal, stateCount, oldPruned, latestPresent)
	}
}

func TestSelectorStateHistoryFailsClosedBeyondCausalCreditBound(t *testing.T) {
	manifest, normalID, peakID := peakDeliveryManifest(t)
	e := New(SideServer, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	slot := &pathSlot{peerTXTargetID: normalID}
	e.recvMu.Lock()
	for epoch := uint64(1); epoch <= uint64(selectorStateHistoryLimit+1); epoch++ {
		target := normalID
		if epoch%2 == 0 {
			target = peakID
		}
		header, wire := selectorStateControlFrame(
			t, e, manifest, target, target, epoch, epoch, (epoch-1)*2,
		)
		e.onFrameRecvLocked(slot, header, wire, nil)
		if e.recvTerminal {
			break
		}
	}
	terminal, terminalErr := e.recvTerminal, e.recvFinalErr
	frontierPresent := e.recvSelectorStates[1] != nil
	e.recvMu.Unlock()
	if !terminal || !errors.Is(terminalErr, ErrPeerProtocol) || !frontierPresent {
		t.Fatalf("terminal=%t err=%v frontier-state=%t", terminal, terminalErr, frontierPresent)
	}
}

func TestSelectorStatePendingDataHonorsReceiveByteBudget(t *testing.T) {
	manifest, normalID, _ := peakDeliveryManifest(t)
	e := New(SideServer, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	header, wire, _ := attributedDataFrame(t, manifest, normalID, 1, 1, []byte("bounded"))
	e.recvMu.Lock()
	e.recvSelectorStatePendingBytes = sendHistoryByteLimit - len(wire) + 1
	e.onFrameRecvLocked(&pathSlot{peerTXTargetID: normalID}, header, wire, nil)
	terminal, terminalErr := e.recvTerminal, e.recvFinalErr
	e.recvMu.Unlock()
	if !terminal || !errors.Is(terminalErr, ErrPeerProtocol) {
		t.Fatalf("terminal=%t err=%v want pending byte-budget failure", terminal, terminalErr)
	}
}

func TestSelectorStateCutoverWinsPublicationRace(t *testing.T) {
	manifest, ids := rootDeliveryTestManifest(t, "cutover-root", "cutover-a", "cutover-b", true)
	e, runtime := newRootDeliveryTestEngine(t, manifest, ids["first"])
	payload := []byte("cutover")
	frameBytes := e.applicationWireFrameBytes(len(payload))
	type result struct {
		state []byte
		data  []byte
		err   error
	}
	done := make(chan result, 1)

	e.sendMu.Lock()
	go func() {
		if err := e.acquireSendSlot(false, frameBytes); err != nil {
			done <- result{err: err}
			return
		}
		state, credit, err := e.lockApplicationSendWithSelectorState(runtime)
		if err != nil {
			e.releaseSendSlot(false, frameBytes)
			done <- result{err: err}
			return
		}
		stateFrame, dataFrame, err := e.buildAndPublishApplicationBundle(payload, runtime, state, credit)
		e.sendMu.Unlock()
		if err != nil {
			e.releaseSendSlot(false, frameBytes)
		}
		done <- result{state: stateFrame, data: dataFrame, err: err}
	}()

	deadline := time.Now().Add(time.Second)
	for len(e.sendControlSlots) != 1 {
		if time.Now().After(deadline) {
			e.sendMu.Unlock()
			t.Fatal("writer did not reserve selector-state control credit")
		}
		time.Sleep(time.Millisecond)
	}
	selectRootDeliveryTestTarget(t, runtime, ids["root"], ids["second"], ids["first"], ids["second"])
	e.sendMu.Unlock()

	var got result
	select {
	case got = <-done:
	case <-time.After(time.Second):
		t.Fatal("writer did not complete after cutover")
	}
	if got.err != nil {
		t.Fatal(got.err)
	}
	if len(got.state) == 0 || len(got.data) == 0 {
		t.Fatal("cutover publication omitted state or DATA")
	}
	record, err := e.decodeLocalSelectorStateForTest(got.state[proto.HeaderSize:])
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := record.entry(ids["root"])
	if !ok || entry.DesiredTargetID != ids["second"] || entry.EffectiveTargetID != ids["second"] || entry.Generation != 2 {
		t.Fatalf("published cutover state=%+v present=%t", entry, ok)
	}
	stateEpoch, _, err := proto.DecodeDataSelectorStateEpoch(got.data[proto.HeaderSize:])
	if err != nil {
		t.Fatal(err)
	}
	if stateEpoch != record.payload.StateEpoch {
		t.Fatalf("DATA state epoch=%d want %d", stateEpoch, record.payload.StateEpoch)
	}
}

func (e *Engine) decodeLocalSelectorStateForTest(wire []byte) (*selectorStateRecord, error) {
	binding := e.localGraphBinding()
	payload, err := proto.DecodeSelectorState(wire, binding.manifest, binding.protoBinding())
	if err != nil {
		return nil, err
	}
	return newSelectorStateRecord(payload, wire), nil
}

func TestSelectorStateSequenceExhaustionPublishesNoOrphanBundle(t *testing.T) {
	manifest, ids := rootDeliveryTestManifest(t, "exhaust-root", "exhaust-a", "exhaust-b", true)
	e, runtime := newRootDeliveryTestEngine(t, manifest, ids["first"])
	payload := []byte("exhaust")
	frameBytes := e.applicationWireFrameBytes(len(payload))
	e.sendSeq = proto.MaxSeq - 1
	if err := e.acquireSendSlot(false, frameBytes); err != nil {
		t.Fatal(err)
	}
	state, credit, err := e.lockApplicationSendWithSelectorState(runtime)
	if err != nil {
		e.releaseSendSlot(false, frameBytes)
		t.Fatal(err)
	}
	stateFrame, dataFrame, err := e.buildAndPublishApplicationBundle(payload, runtime, state, credit)
	if !errors.Is(err, ErrSequenceExhausted) {
		e.sendMu.Unlock()
		e.releaseSendSlot(false, frameBytes)
		t.Fatalf("bundle error=%v want ErrSequenceExhausted", err)
	}
	if len(stateFrame) != 0 || len(dataFrame) != 0 || len(e.sendHist.entries) != 0 ||
		e.sendPublishedNext.Load() != 0 || e.sendSelectorStateEpoch.Load() != 0 || len(e.sendControlSlots) != 0 {
		e.sendMu.Unlock()
		e.releaseSendSlot(false, frameBytes)
		t.Fatalf("orphan bundle state=%d data=%d ledger=%d published=%d epoch=%d controls=%d",
			len(stateFrame), len(dataFrame), len(e.sendHist.entries), e.sendPublishedNext.Load(),
			e.sendSelectorStateEpoch.Load(), len(e.sendControlSlots))
	}
	e.releaseSendSlot(false, frameBytes)
	e.sendMu.Unlock()
}
