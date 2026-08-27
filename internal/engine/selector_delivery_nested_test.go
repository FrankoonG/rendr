package engine

import (
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
)

func nestedPeakDeliveryManifest(t *testing.T) (proto.GraphManifest, map[string]proto.TargetID) {
	t.Helper()
	ids := map[string]proto.TargetID{
		"root":     proto.DeriveTargetID(proto.GraphNodeKindBond, "nested-delivery-root"),
		"selector": proto.DeriveTargetID(proto.GraphNodeKindSelector, "nested-delivery-selector"),
		"normal":   proto.DeriveTargetID(proto.GraphNodeKindPath, "nested-delivery-normal"),
		"peak":     proto.DeriveTargetID(proto.GraphNodeKindPath, "nested-delivery-peak"),
		"sibling":  proto.DeriveTargetID(proto.GraphNodeKindPath, "nested-delivery-sibling"),
	}
	manifest := proto.GraphManifest{
		RootID: ids["root"],
		Nodes: []proto.GraphNode{
			{ID: ids["root"], Kind: proto.GraphNodeKindBond, Name: "nested-delivery-root", Children: []proto.TargetID{ids["selector"], ids["sibling"]}},
			{ID: ids["selector"], Kind: proto.GraphNodeKindSelector, Name: "nested-delivery-selector", Children: []proto.TargetID{ids["normal"], ids["peak"]}, PeakCandidates: []proto.TargetID{ids["peak"]}},
			{ID: ids["normal"], Kind: proto.GraphNodeKindPath, Name: "nested-delivery-normal"},
			{ID: ids["peak"], Kind: proto.GraphNodeKindPath, Name: "nested-delivery-peak"},
			{ID: ids["sibling"], Kind: proto.GraphNodeKindPath, Name: "nested-delivery-sibling"},
		},
	}
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	return manifest, ids
}

func publishNestedSelectorData(
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
	state, credit, err := e.lockApplicationSendWithSelectorState(runtime)
	if err != nil {
		e.releaseSendSlot(false, frameBytes)
		t.Fatal(err)
	}
	_, frame, err := e.buildAndPublishApplicationBundle(payload, runtime, state, credit)
	e.sendMu.Unlock()
	if err != nil {
		e.releaseSendSlot(false, frameBytes)
		t.Fatal(err)
	}
	return frame
}

func acknowledgeNestedSelectorData(t *testing.T, e *Engine, frame []byte) {
	t.Helper()
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	e.sendHistMu.Lock()
	entry := e.sendHistoryEntryLocked(header.Seq)
	if entry == nil {
		e.sendHistMu.Unlock()
		t.Fatalf("DATA sequence %d has no replay owner", header.Seq)
	}
	proof := entry.proof
	e.sendHistMu.Unlock()
	if valid, _ := e.acknowledgeSendFramesAt(header.Seq+1, proof, time.Now()); !valid {
		t.Fatalf("DATA sequence %d ACK was rejected", header.Seq)
	}
}

func TestNestedSelectorTXDeliveryUsesPhysicalRoute(t *testing.T) {
	manifest, ids := nestedPeakDeliveryManifest(t)
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	runtime := e.localExecutionRuntime()
	runtime.initializeSelectorsForLeaf(ids["normal"])
	e.pathTopologyEpoch.Store(1)

	normal := publishNestedSelectorData(t, e, runtime, []byte("normal"))
	e.noteApplicationDispatchRouteAtEpoch(
		normal, &pathSlot{localTXTargetID: ids["normal"]}, 1,
	)
	pending := e.TargetApplicationDeliveryForSelector(ids["selector"], proto.TargetID{})
	if !pending.Attributable || pending.TargetID != ids["normal"] ||
		pending.PublishedBytes != uint64(len("normal")) || pending.AckedBytes != 0 {
		t.Fatalf("nested pending delivery=%+v", pending)
	}
	acknowledgeNestedSelectorData(t, e, normal)
	settled := e.TargetApplicationDeliveryForSelector(ids["selector"], proto.TargetID{})
	if !settled.Attributable || settled.AckedBytes != uint64(len("normal")) {
		t.Fatalf("nested settled delivery=%+v", settled)
	}

	sibling := publishNestedSelectorData(t, e, runtime, []byte("sibling"))
	e.noteApplicationDispatchRouteAtEpoch(
		sibling, &pathSlot{localTXTargetID: ids["sibling"]}, 1,
	)
	acknowledgeNestedSelectorData(t, e, sibling)
	afterSibling := e.TargetApplicationDeliveryForSelector(ids["selector"], proto.TargetID{})
	if !afterSibling.Attributable || afterSibling.AckedBytes != settled.AckedBytes ||
		afterSibling.PublishedBytes != settled.PublishedBytes {
		t.Fatalf("sibling traffic polluted nested selector: before=%+v after=%+v", settled, afterSibling)
	}
}

func TestNestedSelectorDemandDoesNotRequireSelectorRoot(t *testing.T) {
	manifest, ids := nestedPeakDeliveryManifest(t)
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	runtime := e.localExecutionRuntime()
	runtime.initializeSelectorsForLeaf(ids["normal"])
	e.pathTopologyEpoch.Store(1)
	e.sendHistMu.Lock()
	e.sendHist.creditWaiters = 1
	e.sendHistMu.Unlock()
	frame := publishNestedSelectorData(t, e, runtime, []byte("demand"))
	e.sendHistMu.Lock()
	e.sendHist.creditWaiters = 0
	e.sendHistMu.Unlock()
	e.noteApplicationDispatchRouteAtEpoch(
		frame, &pathSlot{localTXTargetID: ids["normal"]}, 1,
	)
	acknowledgeNestedSelectorData(t, e, frame)
	snapshot := e.TargetApplicationDeliveryForSelector(ids["selector"], proto.TargetID{})
	if !snapshot.Attributable || snapshot.DemandBytes != uint64(len("demand")) {
		t.Fatalf("nested non-root demand=%+v", snapshot)
	}
}

func TestSelectorDeliverySkipsWrongRouteFramesWithoutErasingProof(t *testing.T) {
	manifest, ids := nestedPeakDeliveryManifest(t)
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	runtime := e.localExecutionRuntime()
	runtime.initializeSelectorsForLeaf(ids["normal"])
	e.pathTopologyEpoch.Store(1)

	publish := func(payload string, route proto.TargetID) {
		frame := publishNestedSelectorData(t, e, runtime, []byte(payload))
		e.noteApplicationDispatchRouteAtEpoch(
			frame, &pathSlot{localTXTargetID: route}, 1,
		)
		acknowledgeNestedSelectorData(t, e, frame)
	}
	publish("before", ids["normal"])
	before := e.TargetApplicationDeliveryForSelector(ids["selector"], proto.TargetID{})
	if !before.Attributable || before.AckedBytes != uint64(len("before")) {
		t.Fatalf("initial delivery=%+v", before)
	}

	publish("wrong-route", ids["peak"])
	during := e.TargetApplicationDeliveryForSelector(ids["selector"], proto.TargetID{})
	if !during.Attributable || during.AckedBytes != before.AckedBytes ||
		during.EvidenceEpoch != before.EvidenceEpoch {
		t.Fatalf("wrong-route frame erased prior proof: before=%+v during=%+v", before, during)
	}

	publish("after", ids["normal"])
	after := e.TargetApplicationDeliveryForSelector(ids["selector"], proto.TargetID{})
	want := uint64(len("before") + len("after"))
	if !after.Attributable || after.AckedBytes != want ||
		after.EvidenceEpoch != before.EvidenceEpoch {
		t.Fatalf("proof was erased by a wrong-route frame: before=%+v during=%+v after=%+v want_ack=%d",
			before, during, after, want)
	}
}

func nestedPeerSelectorStateFrame(
	t *testing.T,
	e *Engine,
	manifest proto.GraphManifest,
	selectorID, targetID proto.TargetID,
) (proto.Header, []byte) {
	t.Helper()
	digest, err := manifest.Digest()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := proto.EncodeSelectorState(proto.SelectorStatePayload{
		SessionEpoch: proto.SessionEpoch(e.FlowID()), Direction: peerSenderDirection(e.side),
		GraphRevision: 1, GraphDigest: digest, StateEpoch: 1,
		Entries: []proto.SelectorStateEntry{{
			SelectorID: selectorID, DesiredTargetID: targetID,
			EffectiveTargetID: targetID, Generation: 1,
		}},
	}, manifest, proto.GraphBinding{Revision: 1, Digest: digest})
	if err != nil {
		t.Fatal(err)
	}
	return proto.Header{
		Version: proto.Version, Type: proto.FrameCtrl,
		Flags: proto.FlagsForCtrl(proto.CtrlSelectorState), Seq: 0,
	}, wire
}

func TestNestedSelectorRXDeliveryUsesFirstCustodyLeaf(t *testing.T) {
	manifest, ids := nestedPeakDeliveryManifest(t)
	e := New(SideServer, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	e.SetPacketMode()
	e.pathTopologyEpoch.Store(1)
	stateHeader, stateWire := nestedPeerSelectorStateFrame(
		t, e, manifest, ids["selector"], ids["normal"],
	)
	dataHeader, dataWire, _ := attributedDataFrame(
		t, manifest, ids["normal"], 1, 1, []byte("custody"),
	)
	delivered := make([][]byte, 0, 1)
	e.recvMu.Lock()
	e.onFrameRecvLocked(&pathSlot{peerTXTargetID: ids["normal"]}, stateHeader, stateWire, &delivered)
	e.onFrameRecvLocked(&pathSlot{peerTXTargetID: ids["normal"]}, dataHeader, dataWire, &delivered)
	e.recvMu.Unlock()
	snapshot := e.PeerTargetDeliveryForSelector(ids["selector"], proto.TargetID{})
	if len(delivered) != 1 || string(delivered[0]) != "custody" ||
		!snapshot.Attributable || snapshot.TargetID != ids["normal"] ||
		snapshot.AckedBytes != uint64(len("custody")) ||
		snapshot.DemandBytes != uint64(len("custody")) {
		t.Fatalf("nested RX delivered=%q snapshot=%+v", delivered, snapshot)
	}
}
