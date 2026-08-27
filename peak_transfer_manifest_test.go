package rendr

import (
	"bytes"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
)

func TestPeakTargetSetsEnumerateNestedSelectorsCanonically(t *testing.T) {
	normal := proto.GraphNode{ID: proto.DeriveTargetID(proto.GraphNodeKindPath, "manifest-normal"), Kind: proto.GraphNodeKindPath, Name: "manifest-normal"}
	rootPeak := proto.GraphNode{ID: proto.DeriveTargetID(proto.GraphNodeKindPath, "manifest-root-peak"), Kind: proto.GraphNodeKindPath, Name: "manifest-root-peak"}
	innerNormal := proto.GraphNode{ID: proto.DeriveTargetID(proto.GraphNodeKindPath, "manifest-inner-normal"), Kind: proto.GraphNodeKindPath, Name: "manifest-inner-normal"}
	innerPeak := proto.GraphNode{ID: proto.DeriveTargetID(proto.GraphNodeKindPath, "manifest-inner-peak"), Kind: proto.GraphNodeKindPath, Name: "manifest-inner-peak"}
	inner := proto.GraphNode{
		ID: proto.DeriveTargetID(proto.GraphNodeKindSelector, "manifest-inner"), Kind: proto.GraphNodeKindSelector, Name: "manifest-inner",
		Children: []proto.TargetID{innerNormal.ID, innerPeak.ID}, PeakCandidates: []proto.TargetID{innerPeak.ID},
	}
	bond := proto.GraphNode{
		ID: proto.DeriveTargetID(proto.GraphNodeKindBond, "manifest-bond"), Kind: proto.GraphNodeKindBond, Name: "manifest-bond",
		Children: []proto.TargetID{inner.ID},
	}
	root := proto.GraphNode{
		ID: proto.DeriveTargetID(proto.GraphNodeKindSelector, "manifest-root"), Kind: proto.GraphNodeKindSelector, Name: "manifest-root",
		Children: []proto.TargetID{normal.ID, rootPeak.ID, bond.ID}, PeakCandidates: []proto.TargetID{rootPeak.ID, bond.ID},
	}
	manifest := proto.GraphManifest{RootID: root.ID, Nodes: []proto.GraphNode{
		innerPeak, root, normal, bond, inner, rootPeak, innerNormal,
	}}
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}

	sets := peakTargetSetsFromManifest(manifest)
	if len(sets) != 2 {
		t.Fatalf("peak selector count=%d want=2", len(sets))
	}
	if bytes.Compare(sets[0].selectorID[:], sets[1].selectorID[:]) >= 0 {
		t.Fatalf("peak selector sets are not canonical: %x %x", sets[0].selectorID, sets[1].selectorID)
	}
	byID := map[proto.TargetID]peakTransferTargets{sets[0].selectorID: sets[0], sets[1].selectorID: sets[1]}
	rootTargets := byID[root.ID]
	if rootTargets.normalTargetID != normal.ID || len(rootTargets.normalTargetIDs) != 1 || len(rootTargets.peakTargetIDs) != 2 {
		t.Fatalf("root targets=%+v", rootTargets)
	}
	innerTargets := byID[inner.ID]
	if innerTargets.normalTargetID != innerNormal.ID || len(innerTargets.normalTargetIDs) != 1 ||
		len(innerTargets.peakTargetIDs) != 1 || innerTargets.peakTargetIDs[0] != innerPeak.ID {
		t.Fatalf("inner targets=%+v", innerTargets)
	}
	if got := peakTargetsFromManifest(manifest); got.selectorID != root.ID {
		t.Fatalf("legacy root projection selected %x want %x", got.selectorID, root.ID)
	}
}

func TestPeakTransferControllerOwnsEveryNestedSelector(t *testing.T) {
	root := Bond("controller-root", []Target{
		Selector("controller-a", []Target{
			Path("controller-a-normal", PathSpec{}),
			Path("controller-a-peak", PathSpec{}),
		}, PeakTransfer{Targets: []string{"controller-a-peak"}}),
		Selector("controller-b", []Target{
			Path("controller-b-normal", PathSpec{}),
			Path("controller-b-peak", PathSpec{}),
		}, PeakTransfer{Targets: []string{"controller-b-peak"}}),
	})
	plan, err := compileTargetForDial(root)
	if err != nil {
		t.Fatal(err)
	}
	e := engine.New(engine.SideClient, engine.NewClientFlowID(), engine.Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, plan.graph.manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, plan.graph.manifest); err != nil {
		t.Fatal(err)
	}

	controller := newPeakTransferController(e, plan)
	members := controller.members()
	if len(members) != 2 {
		t.Fatalf("controller members=%d want=2", len(members))
	}
	sets := orderedPeakTargetSets(plan.graph.manifest)
	for index, member := range members {
		if member.localTargets.selectorID != sets[index].selectorID ||
			member.peerTargets.selectorID != sets[index].selectorID {
			t.Fatalf("member %d targets=(local=%x peer=%x) want=%x", index,
				member.localTargets.selectorID, member.peerTargets.selectorID, sets[index].selectorID)
		}
	}

	second := members[1]
	secondPeak := second.localTargets.peakTargetIDs[0]
	secondNormal := second.localTargets.normalTargetID
	controller.observeCommittedPeakPolicy(second.localTargets.selectorID, secondPeak, 1, true, "peak-transfer")
	controller.observeCommittedPeakPolicy(second.localTargets.selectorID, secondNormal, 2, false, "peak-verify-failed")
	now := time.Now()
	if !second.tx.peakTargetSuppressed(secondPeak, now) {
		t.Fatal("second selector did not receive its policy callback")
	}
	first := members[0]
	if first.tx.peakTargetSuppressed(first.localTargets.peakTargetIDs[0], now) {
		t.Fatal("second selector callback polluted first selector state")
	}
}

func TestListenerPeakAdmissionDispatchesNestedSelectorsIndependently(t *testing.T) {
	firstSelector := proto.DeriveTargetID(proto.GraphNodeKindSelector, "listener-nested-a")
	firstNormal := proto.DeriveTargetID(proto.GraphNodeKindPath, "listener-nested-a-normal")
	firstPeak := proto.DeriveTargetID(proto.GraphNodeKindPath, "listener-nested-a-peak")
	secondSelector := proto.DeriveTargetID(proto.GraphNodeKindSelector, "listener-nested-b")
	secondNormal := proto.DeriveTargetID(proto.GraphNodeKindPath, "listener-nested-b-normal")
	secondPeak := proto.DeriveTargetID(proto.GraphNodeKindPath, "listener-nested-b-peak")
	admission := &listenerPeakTransferAdmission{
		targets: peakTransferTargets{
			selectorID: firstSelector, normalTargetID: firstNormal,
			normalTargetIDs: []proto.TargetID{firstNormal}, peakTargetIDs: []proto.TargetID{firstPeak},
		},
	}
	second := &listenerPeakTransferAdmission{targets: peakTransferTargets{
		selectorID: secondSelector, normalTargetID: secondNormal,
		normalTargetIDs: []proto.TargetID{secondNormal}, peakTargetIDs: []proto.TargetID{secondPeak},
	}}
	admission.additional = []*listenerPeakTransferAdmission{second}

	admission.observe(secondSelector, secondPeak, 1, true, "peak-transfer-rx")
	admission.observe(secondSelector, secondNormal, 2, false, "peak-verify-failed-rx")
	if err := admission.admit(secondSelector, secondPeak, "peak-transfer-rx"); err == nil {
		t.Fatal("suppressed nested selector candidate remained admissible")
	}
	if err := admission.admit(firstSelector, firstPeak, "peak-transfer-rx"); err != nil {
		t.Fatalf("nested selector suppression leaked to sibling: %v", err)
	}
}
