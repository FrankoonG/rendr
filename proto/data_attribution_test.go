package proto

import "testing"

func TestDataRootSelectorAttributionRoundTrip(t *testing.T) {
	first := GraphNode{ID: DeriveTargetID(GraphNodeKindPath, "first"), Kind: GraphNodeKindPath, Name: "first"}
	second := GraphNode{ID: DeriveTargetID(GraphNodeKindBond, "second"), Kind: GraphNodeKindBond, Name: "second"}
	secondLeaf := GraphNode{ID: DeriveTargetID(GraphNodeKindPath, "second-leaf"), Kind: GraphNodeKindPath, Name: "second-leaf"}
	second.Children = []TargetID{secondLeaf.ID}
	root := GraphNode{ID: DeriveTargetID(GraphNodeKindSelector, "root"), Kind: GraphNodeKindSelector, Name: "root", Children: []TargetID{first.ID, second.ID}, PeakCandidates: []TargetID{second.ID}}
	manifest := GraphManifest{RootID: root.ID, Nodes: []GraphNode{secondLeaf, root, first, second}}

	for i, targetID := range root.Children {
		for _, committed := range []bool{false, true} {
			for _, demand := range []bool{false, true} {
				flags, err := DataFlagsForRootTarget(manifest, targetID, committed, demand)
				if err != nil {
					t.Fatalf("child %d encode: %v", i, err)
				}
				want := uint16(i + 1)
				if committed {
					want |= dataRootCommittedFlag
				}
				if demand {
					want |= dataRootDemandFlag
				}
				if flags != want {
					t.Fatalf("child %d flags=%d want=%d", i, flags, want)
				}
				got, gotCommitted, gotDemand, err := RootTargetFromDataFlags(manifest, flags)
				if err != nil || got != targetID || gotCommitted != committed || gotDemand != demand {
					t.Fatalf("child %d decode=(%x,%t,%t,%v)", i, got, gotCommitted, gotDemand, err)
				}
			}
		}
	}
}

func TestDataRootSelectorAttributionRejectsInvalidValues(t *testing.T) {
	child := GraphNode{ID: DeriveTargetID(GraphNodeKindPath, "child"), Kind: GraphNodeKindPath, Name: "child"}
	other := DeriveTargetID(GraphNodeKindPath, "other")
	root := GraphNode{ID: DeriveTargetID(GraphNodeKindSelector, "root"), Kind: GraphNodeKindSelector, Name: "root", Children: []TargetID{child.ID}, PeakCandidates: []TargetID{child.ID}}
	manifest := GraphManifest{RootID: root.ID, Nodes: []GraphNode{root, child}}

	for _, targetID := range []TargetID{{}, other, manifest.RootID} {
		if flags, err := DataFlagsForRootTarget(manifest, targetID, true, true); err == nil {
			t.Fatalf("target %x encoded as flags %d", targetID, flags)
		}
	}
	for _, flags := range []uint16{0, 2, 0x0fff, 0x1001, 0xffff} {
		if targetID, _, _, err := RootTargetFromDataFlags(manifest, flags); err == nil {
			t.Fatalf("flags 0x%x decoded as target %x", flags, targetID)
		}
	}
}

func TestDataNonSelectorRootRequiresZeroAttribution(t *testing.T) {
	for _, kind := range []GraphNodeKind{GraphNodeKindPath, GraphNodeKindBond, GraphNodeKindRace} {
		leaf := GraphNode{ID: DeriveTargetID(GraphNodeKindPath, kind.String()+"-leaf"), Kind: GraphNodeKindPath, Name: kind.String() + "-leaf"}
		root := GraphNode{ID: DeriveTargetID(kind, kind.String()+"-root"), Kind: kind, Name: kind.String() + "-root"}
		manifest := GraphManifest{RootID: root.ID, Nodes: []GraphNode{root}}
		if kind != GraphNodeKindPath {
			root.Children = []TargetID{leaf.ID}
			manifest.Nodes = []GraphNode{root, leaf}
		}

		flags, err := DataFlagsForRootTarget(manifest, TargetID{}, false, false)
		if err != nil || flags != 0 {
			t.Fatalf("%s zero encode=(%d,%v), want (0,nil)", kind, flags, err)
		}
		targetID, committed, demand, err := RootTargetFromDataFlags(manifest, 0)
		if err != nil || targetID != (TargetID{}) || committed || demand {
			t.Fatalf("%s zero decode=(%x,%v), want (zero,nil)", kind, targetID, err)
		}
		if _, err := DataFlagsForRootTarget(manifest, root.ID, true, true); err == nil {
			t.Fatalf("%s accepted non-zero target", kind)
		}
		if _, _, _, err := RootTargetFromDataFlags(manifest, 1); err == nil {
			t.Fatalf("%s accepted non-zero flags", kind)
		}
	}
}

func TestDataRootSelectorAttributionRequiresValidFrozenManifest(t *testing.T) {
	invalid := GraphManifest{RootID: TargetID{1}}
	if _, err := DataFlagsForRootTarget(invalid, TargetID{}, false, false); err == nil {
		t.Fatal("encoder accepted invalid manifest")
	}
	if _, _, _, err := RootTargetFromDataFlags(invalid, 0); err == nil {
		t.Fatal("decoder accepted invalid manifest")
	}
}

func TestDataRootGenerationRoundTrip(t *testing.T) {
	wire, err := EncodeDataRootGeneration(0x0102030405060708, []byte("payload"))
	if err != nil || len(wire) != DataRootGenerationSize+len("payload") {
		t.Fatalf("encode=(%x,%v)", wire, err)
	}
	generation, payload, err := DecodeDataRootGeneration(wire)
	if err != nil || generation != 0x0102030405060708 || string(payload) != "payload" {
		t.Fatalf("decode=(%x,%q,%v)", generation, payload, err)
	}
	if _, err := EncodeDataRootGeneration(0, nil); err == nil {
		t.Fatal("encoded zero generation")
	}
	if _, _, err := DecodeDataRootGeneration(make([]byte, DataRootGenerationSize)); err == nil {
		t.Fatal("decoded zero generation")
	}
}

func TestDataRootSelectorOrdinalLimitTracksGraphLimit(t *testing.T) {
	if maxDataRootSelectorOrdinal != 1023 {
		t.Fatalf("maximum DATA root selector ordinal=%d want=1023", maxDataRootSelectorOrdinal)
	}
}
