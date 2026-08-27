package proto

import "testing"

func TestDataSelectorStateFlagsRoundTrip(t *testing.T) {
	for _, demand := range []bool{false, true} {
		flags, err := DataFlagsForSelectorState(true, demand)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DemandFromDataFlags(true, flags)
		if err != nil || got != demand {
			t.Fatalf("flags 0x%x decoded demand=%t err=%v", flags, got, err)
		}
	}
	if flags, err := DataFlagsForSelectorState(false, false); err != nil || flags != 0 {
		t.Fatalf("untracked zero flags=(0x%x,%v)", flags, err)
	}
	if _, err := DataFlagsForSelectorState(false, true); err == nil {
		t.Fatal("untracked DATA encoded demand")
	}
	if _, err := DemandFromDataFlags(false, dataSelectorDemandFlag); err == nil {
		t.Fatal("untracked DATA decoded non-zero flags")
	}
	for _, flags := range []uint16{2, 0x1000, 0xffff} {
		if _, err := DemandFromDataFlags(true, flags); err == nil {
			t.Fatalf("reserved flags 0x%x were accepted", flags)
		}
	}
}

func TestDataSelectorStateEpochRoundTrip(t *testing.T) {
	wire, err := EncodeDataSelectorStateEpoch(0x0102030405060708, []byte("payload"))
	if err != nil || len(wire) != DataSelectorStateEpochSize+len("payload") {
		t.Fatalf("encode=(%x,%v)", wire, err)
	}
	stateEpoch, payload, err := DecodeDataSelectorStateEpoch(wire)
	if err != nil || stateEpoch != 0x0102030405060708 || string(payload) != "payload" {
		t.Fatalf("decode=(%x,%q,%v)", stateEpoch, payload, err)
	}
	if _, err := EncodeDataSelectorStateEpoch(0, nil); err == nil {
		t.Fatal("encoded zero state epoch")
	}
	if _, _, err := DecodeDataSelectorStateEpoch(make([]byte, DataSelectorStateEpochSize)); err == nil {
		t.Fatal("decoded zero state epoch")
	}
}

func TestGraphTracksNestedSelectorState(t *testing.T) {
	leafA := GraphNode{ID: DeriveTargetID(GraphNodeKindPath, "state-a"), Kind: GraphNodeKindPath, Name: "state-a"}
	leafB := GraphNode{ID: DeriveTargetID(GraphNodeKindPath, "state-b"), Kind: GraphNodeKindPath, Name: "state-b"}
	inner := GraphNode{
		ID: DeriveTargetID(GraphNodeKindSelector, "state-inner"), Kind: GraphNodeKindSelector, Name: "state-inner",
		Children: []TargetID{leafA.ID, leafB.ID}, PeakCandidates: []TargetID{leafB.ID},
	}
	root := GraphNode{
		ID: DeriveTargetID(GraphNodeKindBond, "state-root"), Kind: GraphNodeKindBond, Name: "state-root",
		Children: []TargetID{inner.ID},
	}
	manifest := GraphManifest{RootID: root.ID, Nodes: []GraphNode{root, inner, leafA, leafB}}
	if !GraphTracksSelectorState(manifest) {
		t.Fatal("nested PeakTransfer selector did not enable selector-state attribution")
	}
	inner.PeakCandidates = nil
	manifest.Nodes[1] = inner
	if GraphTracksSelectorState(manifest) {
		t.Fatal("graph without PeakTransfer candidates enabled selector-state attribution")
	}
}
