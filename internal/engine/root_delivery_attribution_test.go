package engine

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

func rootDeliveryTestManifest(t *testing.T, rootName, firstName, secondName string, peak bool) (
	proto.GraphManifest,
	map[string]proto.TargetID,
) {
	t.Helper()
	first := proto.GraphNode{
		ID:   proto.DeriveTargetID(proto.GraphNodeKindPath, firstName),
		Kind: proto.GraphNodeKindPath, Name: firstName,
	}
	second := proto.GraphNode{
		ID:   proto.DeriveTargetID(proto.GraphNodeKindPath, secondName),
		Kind: proto.GraphNodeKindPath, Name: secondName,
	}
	root := proto.GraphNode{
		ID:   proto.DeriveTargetID(proto.GraphNodeKindSelector, rootName),
		Kind: proto.GraphNodeKindSelector, Name: rootName,
		Children: []proto.TargetID{first.ID, second.ID},
	}
	if peak {
		root.PeakCandidates = []proto.TargetID{second.ID}
	}
	manifest := proto.GraphManifest{RootID: root.ID, Nodes: []proto.GraphNode{root, first, second}}
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	return manifest, map[string]proto.TargetID{
		"root": root.ID, "first": first.ID, "second": second.ID,
	}
}

func newRootDeliveryTestEngine(
	t *testing.T,
	manifest proto.GraphManifest,
	initial proto.TargetID,
) (*Engine, *executionRuntime) {
	t.Helper()
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	runtime := e.localExecutionRuntime()
	initialized := runtime.initializeSelectorsForLeaf(initial)
	if len(initialized) == 0 {
		t.Fatal("root selector was not initialized")
	}
	return e, runtime
}

func publishRootDeliveryTestFrame(
	t *testing.T,
	e *Engine,
	runtime *executionRuntime,
	payload []byte,
) []byte {
	t.Helper()
	frameBytes := e.applicationWireFrameBytes(len(payload))
	if err := e.acquireSendSlot(false, frameBytes); err != nil {
		t.Fatal(err)
	}
	selectorState, selectorStateCredit, err := e.lockApplicationSendWithSelectorState(runtime)
	if err != nil {
		e.releaseSendSlot(false, frameBytes)
		t.Fatal(err)
	}
	_, frame, err := e.buildAndPublishApplicationBundle(
		payload, runtime, selectorState, selectorStateCredit,
	)
	e.sendMu.Unlock()
	if err != nil {
		e.releaseSendSlot(false, frameBytes)
		t.Fatal(err)
	}
	return frame
}

func acknowledgeRootDeliveryTestFrame(t *testing.T, e *Engine, frame []byte) {
	t.Helper()
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	e.sendHistMu.Lock()
	entry := e.sendHistoryEntryLocked(header.Seq)
	if entry == nil {
		e.sendHistMu.Unlock()
		t.Fatalf("sequence %d has no replay owner", header.Seq)
	}
	proof := entry.proof
	e.sendHistMu.Unlock()
	if valid, _ := e.acknowledgeSendFrames(header.Seq+1, proof); !valid {
		t.Fatalf("proof-valid ACK for sequence %d was rejected", header.Seq)
	}
}

func selectRootDeliveryTestTarget(
	t *testing.T,
	runtime *executionRuntime,
	rootID, targetID proto.TargetID,
	available ...proto.TargetID,
) {
	t.Helper()
	attached := make(map[proto.TargetID]bool, len(available))
	for _, id := range available {
		attached[id] = true
	}
	if err := runtime.commitSelectorChild(rootID, targetID, attached, nil); err != nil {
		t.Fatal(err)
	}
}

type rootDeliveryTestWireOracle struct {
	manifest     proto.GraphManifest
	binding      proto.GraphBinding
	sessionEpoch proto.SessionEpoch
	direction    proto.SenderDirection
	states       map[uint64]proto.SelectorStatePayload
}

func newRootDeliveryTestWireOracle(
	t *testing.T,
	e *Engine,
	manifest proto.GraphManifest,
) *rootDeliveryTestWireOracle {
	t.Helper()
	digest, err := manifest.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return &rootDeliveryTestWireOracle{
		manifest:     manifest,
		binding:      proto.GraphBinding{Revision: 1, Digest: digest},
		sessionEpoch: proto.SessionEpoch(e.FlowID()),
		direction:    senderDirection(e.side),
		states:       make(map[uint64]proto.SelectorStatePayload),
	}
}

func (o *rootDeliveryTestWireOracle) observeSelectorState(t *testing.T, wire []byte) {
	t.Helper()
	state, err := proto.DecodeSelectorState(wire, o.manifest, o.binding)
	if err != nil {
		t.Fatalf("decode SELECTOR_STATE: %v", err)
	}
	if state.SessionEpoch != o.sessionEpoch || state.Direction != o.direction {
		t.Fatalf("SELECTOR_STATE binding=%x/%d, want %x/%d",
			state.SessionEpoch, state.Direction, o.sessionEpoch, o.direction)
	}
	if previous, exists := o.states[state.StateEpoch]; exists && !reflect.DeepEqual(previous, state) {
		t.Fatalf("SELECTOR_STATE epoch %d changed payload", state.StateEpoch)
	}
	o.states[state.StateEpoch] = state
}

func (o *rootDeliveryTestWireOracle) rootState(
	t *testing.T,
	stateEpoch uint64,
) (uint64, bool) {
	t.Helper()
	state, ok := o.states[stateEpoch]
	if !ok {
		t.Fatalf("DATA references unpublished SELECTOR_STATE epoch %d", stateEpoch)
	}
	for _, entry := range state.Entries {
		if entry.SelectorID == o.manifest.RootID {
			return entry.Generation, entry.DesiredTargetID == entry.EffectiveTargetID
		}
	}
	t.Fatalf("SELECTOR_STATE epoch %d omits root selector", stateEpoch)
	return 0, false
}

func readRootDeliveryTestDataFrame(
	t *testing.T,
	peer *sequencerTestPath,
	oracle *rootDeliveryTestWireOracle,
	wantPayload []byte,
) ([]byte, uint64, bool) {
	t.Helper()
	tracked := proto.GraphTracksSelectorState(oracle.manifest)
	var pendingFrame []byte
	var pendingStateEpoch uint64
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for {
		select {
		case frame := <-peer.in:
			if len(frame) < proto.HeaderSize {
				continue
			}
			header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
			if err != nil {
				continue
			}
			if header.Type == proto.FrameCtrl && proto.CtrlCodeFromFlags(header.Flags) == proto.CtrlSelectorState {
				if err := proto.ValidateSelectorStateCtrlFlags(header.Flags); err != nil {
					t.Fatalf("invalid SELECTOR_STATE flags: %v", err)
				}
				oracle.observeSelectorState(t, frame[proto.HeaderSize:])
				if len(pendingFrame) != 0 && oracle.states[pendingStateEpoch].StateEpoch != 0 {
					generation, committed := oracle.rootState(t, pendingStateEpoch)
					return pendingFrame, generation, committed
				}
				continue
			}
			if header.Type != proto.FrameData {
				continue
			}
			payload := frame[proto.HeaderSize:]
			stateEpoch := uint64(0)
			if tracked {
				_, err = proto.DemandFromDataFlags(tracked, header.Flags)
				if err != nil {
					t.Fatalf("decode PeakTransfer DATA flags 0x%x: %v", header.Flags, err)
				}
				stateEpoch, payload, err = proto.DecodeDataSelectorStateEpoch(payload)
				if err != nil {
					t.Fatalf("decode PeakTransfer DATA state epoch: %v", err)
				}
			} else if header.Flags != 0 {
				t.Fatalf("plain selector DATA flags=0x%x, want zero", header.Flags)
			}
			if bytes.Equal(payload, wantPayload) {
				if !tracked {
					return frame, 0, false
				}
				if _, ok := oracle.states[stateEpoch]; ok {
					generation, committed := oracle.rootState(t, stateEpoch)
					return frame, generation, committed
				}
				pendingFrame = append([]byte(nil), frame...)
				pendingStateEpoch = stateEpoch
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for DATA payload %q", wantPayload)
			return nil, 0, false
		}
	}
}

func assertNoRootDeliveryDuplicate(
	t *testing.T,
	peer *sequencerTestPath,
	wantFrame []byte,
	quiet time.Duration,
) {
	t.Helper()
	want, err := proto.DecodeHeader(wantFrame[:proto.HeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	timer := time.NewTimer(quiet)
	defer timer.Stop()
	for {
		select {
		case frame := <-peer.in:
			if len(frame) < proto.HeaderSize {
				continue
			}
			header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
			if err == nil && header.Type == proto.FrameData && header.Seq == want.Seq {
				t.Fatalf("recovery attach dispatched DATA sequence %d more than once without loss", want.Seq)
			}
		case <-timer.C:
			return
		}
	}
}

func TestRootDeliveryPostEstablishmentLossRecoversPublishedWrite(t *testing.T) {
	for _, peak := range []bool{false, true} {
		name := "plain-selector"
		if peak {
			name = "peak-transfer-selector"
		}
		t.Run(name, func(t *testing.T) {
			manifest, ids := rootDeliveryTestManifest(t, name+"-root", name+"-a", name+"-b", peak)
			e := New(SideClient, NewClientFlowID(), Limits{MigrationBudget: 5 * time.Second})
			t.Cleanup(func() { _ = e.Close() })
			if err := e.ConfigureLocalGraph(1, manifest); err != nil {
				t.Fatal(err)
			}
			if err := e.ConfigurePeerGraph(1, manifest); err != nil {
				t.Fatal(err)
			}

			initial, initialPeer := newSequencerTestPathPair()
			t.Cleanup(func() { _ = initialPeer.Close() })
			attachFixturePath(t, e, initial,
				transport.PathSpec{Transport: "memory", Address: name + "-initial"},
				ids["first"],
			)
			runtime := e.localExecutionRuntime()
			selectorID, targetID, _, generation, ok := runtime.rootPublicationAttribution()
			if !ok || selectorID != ids["root"] || targetID != ids["first"] || generation != 1 {
				t.Fatalf("established root publication=%x/%x/%d ok=%t", selectorID, targetID, generation, ok)
			}

			pathDeath := errors.New("injected established root path death")
			initial.Fail(pathDeath)
			initial.notifyFailure(pathDeath)
			waitWriteDeadlineCondition(t, time.Second, func() bool {
				return e.ActivePath() == 0 && e.State() == BridgeMigrating
			}, "established root path death")

			firstPayload := []byte("published-while-all-routes-are-lost")
			firstDone := make(chan struct {
				n   int
				err error
			}, 1)
			go func() {
				n, err := (&Conn{E: e}).Write(firstPayload)
				firstDone <- struct {
					n   int
					err error
				}{n: n, err: err}
			}()
			publicationDeadline := time.NewTimer(2 * time.Second)
			publicationTicker := time.NewTicker(time.Millisecond)
			for e.ApplicationDelivery().PublishedPayloadBytes < uint64(len(firstPayload)) {
				select {
				case result := <-firstDone:
					publicationTicker.Stop()
					publicationDeadline.Stop()
					t.Fatalf("all-path-loss Write returned before DATA publication: (%d,%v)", result.n, result.err)
				case <-publicationTicker.C:
				case <-publicationDeadline.C:
					publicationTicker.Stop()
					t.Fatalf("timed out waiting for all-path-loss DATA publication: delivery=%+v root=%+v",
						e.ApplicationDelivery(), e.TargetApplicationDelivery(proto.TargetID{}))
				}
			}
			publicationTicker.Stop()
			if !publicationDeadline.Stop() {
				select {
				case <-publicationDeadline.C:
				default:
				}
			}
			published := e.TargetApplicationDelivery(proto.TargetID{})
			if published.SelectorGeneration != 1 || published.TargetID != ids["first"] {
				t.Fatalf("loss publication changed root cohort: %+v", published)
			}

			recovery, recoveryPeer := newSequencerTestPathPair()
			t.Cleanup(func() { _ = recoveryPeer.Close() })
			attachFixturePath(t, e, recovery,
				transport.PathSpec{Transport: "memory", Address: name + "-recovery"},
				ids["first"],
			)
			select {
			case result := <-firstDone:
				if result.n != len(firstPayload) || result.err != nil {
					t.Fatalf("recovered Write=(%d,%v), want (%d,nil)", result.n, result.err, len(firstPayload))
				}
			case <-time.After(2 * time.Second):
				t.Fatal("published Write did not recover after matching route attach")
			}
			wireOracle := newRootDeliveryTestWireOracle(t, e, manifest)
			firstFrame, firstWireGeneration, _ := readRootDeliveryTestDataFrame(t, recoveryPeer, wireOracle, firstPayload)
			if peak && firstWireGeneration != 1 {
				t.Fatalf("recovered first wire generation=%d, want 1", firstWireGeneration)
			}
			acknowledgeRootDeliveryTestFrame(t, e, firstFrame)
			assertNoRootDeliveryDuplicate(t, recoveryPeer, firstFrame, 50*time.Millisecond)

			settledPayload := []byte("stable-post-recovery-generation")
			if n, err := (&Conn{E: e}).Write(settledPayload); n != len(settledPayload) || err != nil {
				t.Fatalf("settled Write=(%d,%v), want (%d,nil)", n, err, len(settledPayload))
			}
			settledFrame, settledWireGeneration, committed := readRootDeliveryTestDataFrame(t, recoveryPeer, wireOracle, settledPayload)
			if peak && (settledWireGeneration != 1 || !committed) {
				t.Fatalf("settled PeakTransfer generation/committed=%d/%t, want 1/true", settledWireGeneration, committed)
			}
			acknowledgeRootDeliveryTestFrame(t, e, settledFrame)
			settled := e.TargetApplicationDelivery(proto.TargetID{})
			if !settled.Attributable || settled.SelectorGeneration != 1 ||
				settled.TargetID != ids["first"] || settled.TargetName != name+"-a" ||
				settled.PublishedBytes != uint64(len(settledPayload)) ||
				settled.AckedBytes != uint64(len(settledPayload)) {
				t.Fatalf("settled recovery attribution=%+v", settled)
			}
		})
	}
}

func TestPeakRootDeliveryPostEstablishmentLossExpiresAtMigrationBudget(t *testing.T) {
	manifest, ids := rootDeliveryTestManifest(t, "budget-peak-root", "budget-peak-a", "budget-peak-b", true)
	e := New(SideClient, NewClientFlowID(), Limits{MigrationBudget: 500 * time.Millisecond})
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	path, peer := newSequencerTestPathPair()
	t.Cleanup(func() { _ = peer.Close() })
	attachFixturePath(t, e, path,
		transport.PathSpec{Transport: "memory", Address: "budget-peak-initial"},
		ids["first"],
	)
	pathDeath := errors.New("injected PeakTransfer last-path death")
	path.Fail(pathDeath)
	path.notifyFailure(pathDeath)
	waitWriteDeadlineCondition(t, time.Second, func() bool {
		return e.ActivePath() == 0 && e.State() == BridgeMigrating
	}, "PeakTransfer last-path death")
	if err := e.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("peak-published-before-migration-budget")
	result := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := (&Conn{E: e}).Write(payload)
		result <- struct {
			n   int
			err error
		}{n: n, err: err}
	}()
	publicationDeadline := time.NewTimer(250 * time.Millisecond)
	publicationTicker := time.NewTicker(time.Millisecond)
	for e.ApplicationDelivery().PublishedPayloadBytes != uint64(len(payload)) {
		select {
		case writeResult := <-result:
			publicationTicker.Stop()
			publicationDeadline.Stop()
			t.Fatalf("PeakTransfer Write returned before migration-budget DATA publication: (%d,%v)",
				writeResult.n, writeResult.err)
		case <-publicationTicker.C:
		case <-publicationDeadline.C:
			publicationTicker.Stop()
			t.Fatalf("timed out waiting for PeakTransfer migration-budget DATA publication: %+v",
				e.ApplicationDelivery())
		}
	}
	publicationTicker.Stop()
	if !publicationDeadline.Stop() {
		select {
		case <-publicationDeadline.C:
		default:
		}
	}
	var n int
	var err error
	select {
	case writeResult := <-result:
		n, err = writeResult.n, writeResult.err
	case <-time.After(2 * time.Second):
		t.Fatal("PeakTransfer write did not expire at migration budget")
	}
	if n != len(payload) || !errors.Is(err, ErrMigrationBudgetExceeded) {
		t.Fatalf("PeakTransfer migration-budget Write=(%d,%v), want (%d,%v)",
			n, err, len(payload), ErrMigrationBudgetExceeded)
	}
	select {
	case <-e.Closed():
	case <-time.After(time.Second):
		t.Fatal("PeakTransfer migration-budget close did not quiesce")
	}
	if closeErr := e.Close(); closeErr != nil {
		t.Fatalf("PeakTransfer application writer caused teardown self-wait: %v", closeErr)
	}
}

func TestPlainSelectorLocalRootDeliveryPreservesWireBytes(t *testing.T) {
	manifest, ids := rootDeliveryTestManifest(t, "plain-root", "plain-a", "plain-b", false)
	if proto.RootTracksDataAttribution(manifest) {
		t.Fatal("plain selector unexpectedly enables wire DATA attribution")
	}
	e, runtime := newRootDeliveryTestEngine(t, manifest, ids["first"])
	payload := []byte("plain-selector-wire-payload")
	frame := publishRootDeliveryTestFrame(t, e, runtime, payload)
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	if header.Flags != 0 || len(frame) != proto.HeaderSize+len(payload) ||
		!bytes.Equal(frame[proto.HeaderSize:], payload) {
		t.Fatalf("plain selector changed DATA wire bytes: header=%+v frame=%x payload=%x", header, frame, payload)
	}
	e.noteApplicationDispatchRoute(frame, &pathSlot{localTXTargetID: ids["first"]})
	acknowledgeRootDeliveryTestFrame(t, e, frame)

	snapshot := e.TargetApplicationDelivery(proto.TargetID{})
	if !snapshot.Attributable || snapshot.SelectorID != ids["root"] ||
		snapshot.TargetID != ids["first"] || snapshot.SelectorName != "plain-root" ||
		snapshot.TargetName != "plain-a" || snapshot.SelectorGeneration != 1 ||
		snapshot.EvidenceEpoch == 0 || snapshot.PublishedBytes != uint64(len(payload)) ||
		snapshot.AckedBytes != uint64(len(payload)) {
		t.Fatalf("plain selector local delivery=%+v", snapshot)
	}
}

func TestNonSelectorRootRetainsUnattributedWireBytes(t *testing.T) {
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindBond, "bond-root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	payload := []byte("bond-wire-payload")
	frame := publishRootDeliveryTestFrame(t, e, e.localExecutionRuntime(), payload)
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	if header.Flags != 0 || !bytes.Equal(frame[proto.HeaderSize:], payload) {
		t.Fatalf("non-selector DATA wire changed: header=%+v frame=%x", header, frame)
	}
	if snapshot := e.TargetApplicationDelivery(proto.TargetID{}); snapshot != (TargetDeliverySnapshot{}) {
		t.Fatalf("non-selector root exposed selector delivery=%+v", snapshot)
	}
}

func TestRootDeliveryEarlyAckWaitsForInitialRouteResult(t *testing.T) {
	manifest, ids := rootDeliveryTestManifest(t, "early-root", "early-a", "early-b", false)
	e, runtime := newRootDeliveryTestEngine(t, manifest, ids["first"])
	payload := []byte("early-ack")
	frame := publishRootDeliveryTestFrame(t, e, runtime, payload)
	receipt := e.beginApplicationBatchDispatch(
		frame, &pathSlot{localTXTargetID: ids["first"]}, e.currentPathTopologyEpoch(),
	)
	if receipt == nil {
		t.Fatal("batch dispatch did not retain attribution receipt")
	}
	acknowledgeRootDeliveryTestFrame(t, e, frame)
	before := e.TargetApplicationDelivery(proto.TargetID{})
	if before.Attributable || before.PublishedBytes != 0 || before.AckedBytes != 0 || before.DemandBytes != 0 {
		t.Fatalf("early ACK exposed attribution before physical route result: %+v", before)
	}
	e.resolveApplicationBatchDispatch([]*batchDispatchAttributionReceipt{receipt}, 1)
	after := e.TargetApplicationDelivery(proto.TargetID{})
	if !after.Attributable || after.AckedBytes != uint64(len(payload)) || after.PublishedBytes != after.AckedBytes {
		t.Fatalf("early ACK did not settle after route result: %+v", after)
	}
}

func TestRootDeliveryBlockedOldWriteReleaseBeforeAndAfterCutover(t *testing.T) {
	for _, releaseAfterFinal := range []bool{false, true} {
		name := "before-cutover"
		if releaseAfterFinal {
			name = "after-final-snapshot"
		}
		t.Run(name, func(t *testing.T) {
			manifest, ids := rootDeliveryTestManifest(t, "blocked-root", "blocked-a", "blocked-b", false)
			e, runtime := newRootDeliveryTestEngine(t, manifest, ids["first"])
			oldPayload := []byte("old-generation")
			oldFrame := publishRootDeliveryTestFrame(t, e, runtime, oldPayload)
			oldReceipt := e.beginApplicationBatchDispatch(
				oldFrame, &pathSlot{localTXTargetID: ids["first"]}, e.currentPathTopologyEpoch(),
			)
			acknowledgeRootDeliveryTestFrame(t, e, oldFrame)
			if !releaseAfterFinal {
				e.resolveApplicationBatchDispatch([]*batchDispatchAttributionReceipt{oldReceipt}, 1)
			}

			selectRootDeliveryTestTarget(t, runtime, ids["root"], ids["second"], ids["first"], ids["second"])
			newPayload := []byte("new-generation-proof")
			newFrame := publishRootDeliveryTestFrame(t, e, runtime, newPayload)
			e.noteApplicationDispatchRoute(newFrame, &pathSlot{localTXTargetID: ids["second"]})
			acknowledgeRootDeliveryTestFrame(t, e, newFrame)
			finalBeforeRelease := e.TargetApplicationDelivery(proto.TargetID{})
			if releaseAfterFinal {
				e.resolveApplicationBatchDispatch([]*batchDispatchAttributionReceipt{oldReceipt}, 1)
			}
			final := e.TargetApplicationDelivery(proto.TargetID{})
			if final != finalBeforeRelease || !final.Attributable || final.TargetID != ids["second"] ||
				final.TargetName != "blocked-b" || final.SelectorGeneration != 2 ||
				final.PublishedBytes != uint64(len(newPayload)) || final.AckedBytes != uint64(len(newPayload)) {
				t.Fatalf("old write release changed final generation: before=%+v after=%+v", finalBeforeRelease, final)
			}
		})
	}
}

func TestRootDeliveryRejectsWrongInitialRootRoute(t *testing.T) {
	manifest, ids := rootDeliveryTestManifest(t, "wrong-root", "wrong-a", "wrong-b", false)
	e, runtime := newRootDeliveryTestEngine(t, manifest, ids["first"])
	frame := publishRootDeliveryTestFrame(t, e, runtime, []byte("wrong-route"))
	e.noteApplicationDispatchRoute(frame, &pathSlot{localTXTargetID: ids["second"]})
	acknowledgeRootDeliveryTestFrame(t, e, frame)
	if snapshot := e.TargetApplicationDelivery(proto.TargetID{}); snapshot.Attributable ||
		snapshot.PublishedBytes != 0 || snapshot.AckedBytes != 0 {
		t.Fatalf("wrong initial root route remained attributable: %+v", snapshot)
	}
}

func TestRootDeliveryDoesNotCreditReplayOnlyTargetTraffic(t *testing.T) {
	manifest, ids := rootDeliveryTestManifest(t, "replay-root", "replay-a", "replay-b", false)
	e, runtime := newRootDeliveryTestEngine(t, manifest, ids["first"])
	frame := publishRootDeliveryTestFrame(t, e, runtime, []byte("replay-only"))
	e.noteApplicationDispatchRoute(frame, &pathSlot{localTXTargetID: ids["first"]})
	e.noteApplicationDispatchRoute(frame, &pathSlot{localTXTargetID: ids["second"]})
	acknowledgeRootDeliveryTestFrame(t, e, frame)
	for _, targetID := range []proto.TargetID{ids["first"], ids["second"]} {
		if snapshot := e.TargetApplicationDelivery(targetID); snapshot.Attributable ||
			snapshot.PublishedBytes != 0 || snapshot.AckedBytes != 0 {
			t.Fatalf("replay-only target %x received unique delivery credit: %+v", targetID, snapshot)
		}
	}
}

func TestRootDeliveryGenerationRolloverResetsCountersAndTargetKey(t *testing.T) {
	manifest, ids := rootDeliveryTestManifest(t, "rollover-root", "rollover-a", "rollover-b", false)
	e, runtime := newRootDeliveryTestEngine(t, manifest, ids["first"])
	firstPayload := []byte("first-generation-is-longer")
	firstFrame := publishRootDeliveryTestFrame(t, e, runtime, firstPayload)
	e.noteApplicationDispatchRoute(firstFrame, &pathSlot{localTXTargetID: ids["first"]})
	acknowledgeRootDeliveryTestFrame(t, e, firstFrame)
	first := e.TargetApplicationDelivery(proto.TargetID{})

	selectRootDeliveryTestTarget(t, runtime, ids["root"], ids["second"], ids["first"], ids["second"])
	secondPayload := []byte("second")
	secondFrame := publishRootDeliveryTestFrame(t, e, runtime, secondPayload)
	e.noteApplicationDispatchRoute(secondFrame, &pathSlot{localTXTargetID: ids["second"]})
	acknowledgeRootDeliveryTestFrame(t, e, secondFrame)
	second := e.TargetApplicationDelivery(proto.TargetID{})
	if !second.Attributable || second.TargetID != ids["second"] || second.TargetName != "rollover-b" ||
		second.SelectorGeneration <= first.SelectorGeneration || second.EvidenceEpoch <= first.EvidenceEpoch ||
		second.PublishedBytes != uint64(len(secondPayload)) || second.AckedBytes != uint64(len(secondPayload)) {
		t.Fatalf("generation rollover first=%+v second=%+v", first, second)
	}
	missing := e.TargetApplicationDelivery(proto.DeriveTargetID(proto.GraphNodeKindPath, "missing"))
	if missing.Attributable || missing.PublishedBytes != 0 || missing.AckedBytes != 0 || missing.TargetName != "" {
		t.Fatalf("missing target key retained delivery facts: %+v", missing)
	}
}

func TestServerDirectionalRootDeliveryUsesLocalFrozenNames(t *testing.T) {
	local, localIDs := rootDeliveryTestManifest(t, "server-root", "server-west", "server-east", false)
	peer, _ := rootDeliveryTestManifest(t, "client-root", "client-east", "client-west", false)
	e := New(SideServer, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, local); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, peer); err != nil {
		t.Fatal(err)
	}
	runtime := e.localExecutionRuntime()
	runtime.initializeSelectorsForLeaf(localIDs["second"])
	payload := []byte("server-local-direction")
	frame := publishRootDeliveryTestFrame(t, e, runtime, payload)
	e.noteApplicationDispatchRoute(frame, &pathSlot{localTXTargetID: localIDs["second"]})
	acknowledgeRootDeliveryTestFrame(t, e, frame)
	snapshot := e.TargetApplicationDelivery(proto.TargetID{})
	if !snapshot.Attributable || snapshot.SelectorName != "server-root" || snapshot.TargetName != "server-east" {
		t.Fatalf("server delivery projected peer or swapped names: %+v", snapshot)
	}
}
