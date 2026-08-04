package engine

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/FrankoonG/rendr/proto"
)

func TestCompileExecutionPlanPreservesRecursiveModes(t *testing.T) {
	tests := []struct {
		name               string
		manifest           proto.GraphManifest
		rootKind           proto.GraphNodeKind
		rootChildren       []string
		rootLeaves         []string
		logicalChildName   string
		logicalChildKind   proto.GraphNodeKind
		logicalChildLeaves []string
	}{
		{
			name:               "selector root",
			manifest:           executionPlanSelectorManifest(),
			rootKind:           proto.GraphNodeKindSelector,
			rootChildren:       []string{"interactive", "bulk", "first"},
			rootLeaves:         []string{"interactive", "bulk-a", "bulk-b", "first-a", "first-b"},
			logicalChildName:   "bulk",
			logicalChildKind:   proto.GraphNodeKindBond,
			logicalChildLeaves: []string{"bulk-a", "bulk-b"},
		},
		{
			name:               "bond root",
			manifest:           executionPlanBondManifest(),
			rootKind:           proto.GraphNodeKindBond,
			rootChildren:       []string{"preferred", "redundant", "direct"},
			rootLeaves:         []string{"preferred-a", "preferred-b", "redundant-a", "redundant-b", "direct"},
			logicalChildName:   "preferred",
			logicalChildKind:   proto.GraphNodeKindSelector,
			logicalChildLeaves: []string{"preferred-a", "preferred-b"},
		},
		{
			name:               "race root",
			manifest:           executionPlanRaceManifest(),
			rootKind:           proto.GraphNodeKindRace,
			rootChildren:       []string{"aggregate", "choice", "direct"},
			rootLeaves:         []string{"aggregate-a", "aggregate-b", "choice-a", "choice-b", "direct"},
			logicalChildName:   "aggregate",
			logicalChildKind:   proto.GraphNodeKindBond,
			logicalChildLeaves: []string{"aggregate-a", "aggregate-b"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, err := compileExecutionPlan(test.manifest)
			if err != nil {
				t.Fatal(err)
			}
			root, ok := plan.root()
			if !ok {
				t.Fatal("compiled plan has no root")
			}
			if root.targetID != test.manifest.RootID || root.kind != test.rootKind {
				t.Fatalf("root=(%x,%s), want (%x,%s)", root.targetID, root.kind, test.manifest.RootID, test.rootKind)
			}
			if got := executionPlanNodeNames(t, plan, root.children); !reflect.DeepEqual(got, test.rootChildren) {
				t.Fatalf("root children=%v want %v", got, test.rootChildren)
			}
			if got := executionPlanLeafNames(t, plan, root.targetID); !reflect.DeepEqual(got, test.rootLeaves) {
				t.Fatalf("root leaves=%v want %v", got, test.rootLeaves)
			}

			logicalChild := executionPlanNodeByName(t, plan, test.logicalChildName)
			if logicalChild.kind != test.logicalChildKind {
				t.Fatalf("logical child %q kind=%s want %s", logicalChild.name, logicalChild.kind, test.logicalChildKind)
			}
			if err := plan.validateImmediateChild(root.targetID, logicalChild.targetID); err != nil {
				t.Fatalf("immediate logical child rejected: %v", err)
			}
			if got := executionPlanLeafNames(t, plan, logicalChild.targetID); !reflect.DeepEqual(got, test.logicalChildLeaves) {
				t.Fatalf("logical child leaves=%v want %v", got, test.logicalChildLeaves)
			}
			leaf := executionPlanNodeByName(t, plan, test.logicalChildLeaves[0])
			if err := plan.validateImmediateChild(root.targetID, leaf.targetID); err == nil {
				t.Fatalf("descendant leaf %q accepted as an immediate root child", leaf.name)
			}
		})
	}
}

func TestCompileExecutionPlanPreservesNestedSelectors(t *testing.T) {
	a := executionPlanTestNode(proto.GraphNodeKindPath, "a")
	b := executionPlanTestNode(proto.GraphNodeKindPath, "b")
	innerSelector := executionPlanTestNode(proto.GraphNodeKindSelector, "inner-selector", a.ID, b.ID)
	outerSelector := executionPlanTestNode(proto.GraphNodeKindSelector, "outer-selector", innerSelector.ID)

	plan, err := compileExecutionPlan(proto.GraphManifest{
		RootID: outerSelector.ID,
		Nodes:  []proto.GraphNode{b, outerSelector, a, innerSelector},
	})
	if err != nil {
		t.Fatal(err)
	}
	root, _ := plan.root()
	if got := executionPlanNodeNames(t, plan, root.children); !reflect.DeepEqual(got, []string{"inner-selector"}) {
		t.Fatalf("outer selector children=%v", got)
	}
	inner, ok := plan.node(innerSelector.ID)
	if !ok || inner.kind != proto.GraphNodeKindSelector {
		t.Fatalf("inner selector was not retained: %+v", inner)
	}
	if err := plan.validateImmediateChild(outerSelector.ID, innerSelector.ID); err != nil {
		t.Fatalf("nested selector rejected: %v", err)
	}
	if err := plan.validateImmediateChild(outerSelector.ID, a.ID); err == nil {
		t.Fatal("selector skipped its immediate selector child")
	}
}

func TestCompileExecutionPlanDeterministicAndImmutable(t *testing.T) {
	manifest := executionPlanSelectorManifest()
	reordered := executionPlanCloneManifest(manifest)
	for left, right := 0, len(reordered.Nodes)-1; left < right; left, right = left+1, right-1 {
		reordered.Nodes[left], reordered.Nodes[right] = reordered.Nodes[right], reordered.Nodes[left]
	}

	first, err := compileExecutionPlan(manifest)
	if err != nil {
		t.Fatal(err)
	}
	second, err := compileExecutionPlan(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := executionPlanSnapshot(t, first), executionPlanSnapshot(t, second); got != want {
		t.Fatalf("node order changed plan\nfirst:  %s\nsecond: %s", got, want)
	}

	rootBefore, _ := first.root()
	leavesBefore, _ := first.leafDescendants(rootBefore.targetID)
	wantChildren := append([]proto.TargetID(nil), rootBefore.children...)
	wantLeaves := append([]executionPlanLeaf(nil), leavesBefore...)

	for i := range manifest.Nodes {
		manifest.Nodes[i].Name = "mutated"
		if len(manifest.Nodes[i].Children) != 0 {
			manifest.Nodes[i].Children[0] = proto.TargetID{0xff}
		}
		if len(manifest.Nodes[i].PeakCandidates) != 0 {
			manifest.Nodes[i].PeakCandidates[0] = proto.TargetID{0xee}
		}
	}
	rootBefore.children[0] = proto.TargetID{0xdd}
	rootBefore.peakCandidates[0] = proto.TargetID{0xcc}
	leavesBefore[0].name = "changed"
	leavesBefore[0].targetID = proto.TargetID{0xbb}

	rootAfter, _ := first.root()
	leavesAfter, _ := first.leafDescendants(rootAfter.targetID)
	if !reflect.DeepEqual(rootAfter.children, wantChildren) {
		t.Fatalf("query or source mutation changed children: %x want %x", rootAfter.children, wantChildren)
	}
	if !reflect.DeepEqual(leavesAfter, wantLeaves) {
		t.Fatalf("query or source mutation changed leaves: %+v want %+v", leavesAfter, wantLeaves)
	}

	childReordered := executionPlanSelectorManifest()
	rootIndex := executionPlanManifestNodeIndex(t, childReordered, childReordered.RootID)
	children := childReordered.Nodes[rootIndex].Children
	children[0], children[1] = children[1], children[0]
	third, err := compileExecutionPlan(childReordered)
	if err != nil {
		t.Fatal(err)
	}
	if executionPlanSnapshot(t, first) == executionPlanSnapshot(t, third) {
		t.Fatal("semantically significant child order did not change the plan")
	}
}

func TestCompileExecutionPlanLeafIdentityAndSelectorCandidates(t *testing.T) {
	manifest := executionPlanSelectorManifest()
	plan, err := compileExecutionPlan(manifest)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := plan.root()
	wantPeaks := append([]proto.TargetID(nil), root.peakCandidates...)
	sort.Slice(wantPeaks, func(i, j int) bool {
		return bytes.Compare(wantPeaks[i][:], wantPeaks[j][:]) < 0
	})
	if !reflect.DeepEqual(root.peakCandidates, wantPeaks) {
		t.Fatalf("selector peak candidates are not canonical: %x", root.peakCandidates)
	}
	if got := executionPlanNodeNames(t, plan, root.peakCandidates); !executionPlanSameNames(got, []string{"bulk", "first"}) {
		t.Fatalf("selector peak candidates=%v", got)
	}

	leaves, ok := plan.leafDescendants(root.targetID)
	if !ok {
		t.Fatal("root leaf query failed")
	}
	for _, leaf := range leaves {
		want := proto.DeriveTargetID(proto.GraphNodeKindPath, leaf.name)
		if leaf.targetID != want {
			t.Fatalf("leaf %q id=%x want %x", leaf.name, leaf.targetID, want)
		}
		node, ok := plan.node(leaf.targetID)
		if !ok || node.kind != proto.GraphNodeKindPath || node.name != leaf.name {
			t.Fatalf("leaf %q does not resolve to its path node", leaf.name)
		}
		self, ok := plan.leafDescendants(leaf.targetID)
		if !ok || len(self) != 1 || self[0] != leaf {
			t.Fatalf("leaf self descendants=%+v", self)
		}
		wantWeight := uint16(0)
		if leaf.name == "bulk-a" {
			wantWeight = 3
		}
		if leaf.weight != wantWeight {
			t.Fatalf("leaf %q weight=%d want %d", leaf.name, leaf.weight, wantWeight)
		}
	}
	if _, ok := plan.node(proto.TargetID{1}); ok {
		t.Fatal("unknown node resolved")
	}
	if _, ok := plan.leafDescendants(proto.TargetID{1}); ok {
		t.Fatal("unknown leaf query succeeded")
	}
	if err := plan.validateImmediateChild(root.targetID, proto.TargetID{1}); err == nil {
		t.Fatal("unknown child accepted")
	}
	interactive := executionPlanNodeByName(t, plan, "interactive")
	if err := plan.validateImmediateChild(interactive.targetID, root.targetID); err == nil {
		t.Fatal("path accepted a child")
	}
}

func TestCompileExecutionPlanRejectsMalformedManifests(t *testing.T) {
	path := executionPlanTestNode(proto.GraphNodeKindPath, "path")
	other := executionPlanTestNode(proto.GraphNodeKindPath, "other")
	group := executionPlanTestNode(proto.GraphNodeKindSelector, "group", path.ID)
	bondChild := executionPlanTestNode(proto.GraphNodeKindBond, "bond-child", path.ID)
	bondParent := executionPlanTestNode(proto.GraphNodeKindBond, "bond-parent", bondChild.ID)
	raceChild := executionPlanTestNode(proto.GraphNodeKindRace, "race-child", path.ID)
	raceParent := executionPlanTestNode(proto.GraphNodeKindRace, "race-parent", raceChild.ID)
	left := executionPlanTestNode(proto.GraphNodeKindSelector, "left", path.ID)
	right := executionPlanTestNode(proto.GraphNodeKindBond, "right", path.ID)
	dagRoot := executionPlanTestNode(proto.GraphNodeKindRace, "dag-root", left.ID, right.ID)

	tests := []struct {
		name     string
		manifest proto.GraphManifest
		want     string
	}{
		{name: "empty", manifest: proto.GraphManifest{}, want: "no nodes"},
		{name: "missing root", manifest: proto.GraphManifest{RootID: group.ID, Nodes: []proto.GraphNode{path}}, want: "root"},
		{name: "duplicate node id", manifest: proto.GraphManifest{RootID: path.ID, Nodes: []proto.GraphNode{path, path}}, want: "duplicate"},
		{name: "duplicate node name", manifest: proto.GraphManifest{RootID: group.ID, Nodes: []proto.GraphNode{group, {ID: proto.DeriveTargetID(proto.GraphNodeKindPath, group.Name), Kind: proto.GraphNodeKindPath, Name: group.Name}}}, want: "duplicate"},
		{name: "missing child", manifest: proto.GraphManifest{RootID: group.ID, Nodes: []proto.GraphNode{group}}, want: "missing child"},
		{name: "duplicate child", manifest: proto.GraphManifest{RootID: group.ID, Nodes: []proto.GraphNode{{ID: group.ID, Kind: group.Kind, Name: group.Name, Children: []proto.TargetID{path.ID, path.ID}}, path}}, want: "repeats child"},
		{name: "cycle", manifest: executionPlanCycleManifest(), want: "cycle"},
		{name: "too deep", manifest: executionPlanDepthManifest(proto.GraphManifestMaxDepth + 1), want: "depth"},
		{name: "multiple parents", manifest: proto.GraphManifest{RootID: dagRoot.ID, Nodes: []proto.GraphNode{dagRoot, left, right, path}}, want: "multiple parents"},
		{name: "unnormalized bond", manifest: proto.GraphManifest{RootID: bondParent.ID, Nodes: []proto.GraphNode{bondParent, bondChild, path}}, want: "unnormalized"},
		{name: "unnormalized race", manifest: proto.GraphManifest{RootID: raceParent.ID, Nodes: []proto.GraphNode{raceParent, raceChild, path}}, want: "unnormalized"},
		{name: "unreachable", manifest: proto.GraphManifest{RootID: path.ID, Nodes: []proto.GraphNode{path, other}}, want: "unreachable"},
		{name: "path with child", manifest: proto.GraphManifest{RootID: path.ID, Nodes: []proto.GraphNode{{ID: path.ID, Kind: path.Kind, Name: path.Name, Children: []proto.TargetID{other.ID}}, other}}, want: "path node"},
		{name: "empty selector", manifest: proto.GraphManifest{RootID: group.ID, Nodes: []proto.GraphNode{{ID: group.ID, Kind: group.Kind, Name: group.Name}}}, want: "no children"},
		{name: "group weight", manifest: proto.GraphManifest{RootID: group.ID, Nodes: []proto.GraphNode{{ID: group.ID, Kind: group.Kind, Name: group.Name, Weight: 1, Children: group.Children}, path}}, want: "path-only weight"},
		{name: "invalid id", manifest: proto.GraphManifest{RootID: path.ID, Nodes: []proto.GraphNode{{ID: path.ID, Kind: path.Kind, Name: "renamed"}}}, want: "target id"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := compileExecutionPlan(test.manifest)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want substring %q", err, test.want)
			}
		})
	}

	if _, err := compileExecutionPlan(executionPlanDepthManifest(proto.GraphManifestMaxDepth)); err != nil {
		t.Fatalf("maximum graph depth rejected: %v", err)
	}
}

func executionPlanSelectorManifest() proto.GraphManifest {
	interactive := executionPlanTestNode(proto.GraphNodeKindPath, "interactive")
	bulkA := executionPlanTestNode(proto.GraphNodeKindPath, "bulk-a")
	bulkA.Weight = 3
	bulkB := executionPlanTestNode(proto.GraphNodeKindPath, "bulk-b")
	bulk := executionPlanTestNode(proto.GraphNodeKindBond, "bulk", bulkA.ID, bulkB.ID)
	firstA := executionPlanTestNode(proto.GraphNodeKindPath, "first-a")
	firstB := executionPlanTestNode(proto.GraphNodeKindPath, "first-b")
	first := executionPlanTestNode(proto.GraphNodeKindRace, "first", firstA.ID, firstB.ID)
	root := executionPlanTestNode(proto.GraphNodeKindSelector, "selector-root", interactive.ID, bulk.ID, first.ID)
	root.PeakCandidates = []proto.TargetID{first.ID, bulk.ID}
	return proto.GraphManifest{RootID: root.ID, Nodes: []proto.GraphNode{firstB, root, bulkA, first, interactive, bulk, firstA, bulkB}}
}

func executionPlanBondManifest() proto.GraphManifest {
	preferredA := executionPlanTestNode(proto.GraphNodeKindPath, "preferred-a")
	preferredB := executionPlanTestNode(proto.GraphNodeKindPath, "preferred-b")
	preferred := executionPlanTestNode(proto.GraphNodeKindSelector, "preferred", preferredA.ID, preferredB.ID)
	redundantA := executionPlanTestNode(proto.GraphNodeKindPath, "redundant-a")
	redundantB := executionPlanTestNode(proto.GraphNodeKindPath, "redundant-b")
	redundant := executionPlanTestNode(proto.GraphNodeKindRace, "redundant", redundantA.ID, redundantB.ID)
	direct := executionPlanTestNode(proto.GraphNodeKindPath, "direct")
	root := executionPlanTestNode(proto.GraphNodeKindBond, "bond-root", preferred.ID, redundant.ID, direct.ID)
	return proto.GraphManifest{RootID: root.ID, Nodes: []proto.GraphNode{redundantB, root, preferredA, direct, redundant, preferred, preferredB, redundantA}}
}

func executionPlanRaceManifest() proto.GraphManifest {
	aggregateA := executionPlanTestNode(proto.GraphNodeKindPath, "aggregate-a")
	aggregateB := executionPlanTestNode(proto.GraphNodeKindPath, "aggregate-b")
	aggregate := executionPlanTestNode(proto.GraphNodeKindBond, "aggregate", aggregateA.ID, aggregateB.ID)
	choiceA := executionPlanTestNode(proto.GraphNodeKindPath, "choice-a")
	choiceB := executionPlanTestNode(proto.GraphNodeKindPath, "choice-b")
	choice := executionPlanTestNode(proto.GraphNodeKindSelector, "choice", choiceA.ID, choiceB.ID)
	direct := executionPlanTestNode(proto.GraphNodeKindPath, "direct")
	root := executionPlanTestNode(proto.GraphNodeKindRace, "race-root", aggregate.ID, choice.ID, direct.ID)
	return proto.GraphManifest{RootID: root.ID, Nodes: []proto.GraphNode{choiceB, root, aggregateA, direct, choice, aggregate, choiceA, aggregateB}}
}

func executionPlanTestNode(kind proto.GraphNodeKind, name string, children ...proto.TargetID) proto.GraphNode {
	return proto.GraphNode{
		ID:       proto.DeriveTargetID(kind, name),
		Kind:     kind,
		Name:     name,
		Children: append([]proto.TargetID(nil), children...),
	}
}

func executionPlanNodeByName(t *testing.T, plan *executionPlan, name string) executionPlanNode {
	t.Helper()
	for id := range plan.nodes {
		node, ok := plan.node(id)
		if ok && node.name == name {
			return node
		}
	}
	t.Fatalf("execution node %q not found", name)
	return executionPlanNode{}
}

func executionPlanNodeNames(t *testing.T, plan *executionPlan, ids []proto.TargetID) []string {
	t.Helper()
	names := make([]string, 0, len(ids))
	for _, id := range ids {
		node, ok := plan.node(id)
		if !ok {
			t.Fatalf("execution node %x not found", id)
		}
		names = append(names, node.name)
	}
	return names
}

func executionPlanLeafNames(t *testing.T, plan *executionPlan, id proto.TargetID) []string {
	t.Helper()
	leaves, ok := plan.leafDescendants(id)
	if !ok {
		t.Fatalf("leaf descendants for %x not found", id)
	}
	names := make([]string, len(leaves))
	for i := range leaves {
		names[i] = leaves[i].name
	}
	return names
}

func executionPlanSnapshot(t *testing.T, plan *executionPlan) string {
	t.Helper()
	root, ok := plan.root()
	if !ok {
		t.Fatal("execution plan has no root")
	}
	var visit func(executionPlanNode) string
	visit = func(node executionPlanNode) string {
		children := make([]string, 0, len(node.children))
		for _, childID := range node.children {
			child, ok := plan.node(childID)
			if !ok {
				t.Fatalf("execution child %x not found", childID)
			}
			children = append(children, visit(child))
		}
		return fmt.Sprintf("%s:%s[%s]", node.kind, node.name, strings.Join(children, ","))
	}
	return visit(root)
}

func executionPlanCloneManifest(manifest proto.GraphManifest) proto.GraphManifest {
	clone := proto.GraphManifest{RootID: manifest.RootID, Nodes: make([]proto.GraphNode, len(manifest.Nodes))}
	for i := range manifest.Nodes {
		clone.Nodes[i] = manifest.Nodes[i]
		clone.Nodes[i].Children = append([]proto.TargetID(nil), manifest.Nodes[i].Children...)
		clone.Nodes[i].PeakCandidates = append([]proto.TargetID(nil), manifest.Nodes[i].PeakCandidates...)
	}
	return clone
}

func executionPlanManifestNodeIndex(t *testing.T, manifest proto.GraphManifest, id proto.TargetID) int {
	t.Helper()
	for i := range manifest.Nodes {
		if manifest.Nodes[i].ID == id {
			return i
		}
	}
	t.Fatalf("manifest node %x not found", id)
	return -1
}

func executionPlanCycleManifest() proto.GraphManifest {
	a := executionPlanTestNode(proto.GraphNodeKindSelector, "cycle-a")
	b := executionPlanTestNode(proto.GraphNodeKindBond, "cycle-b")
	a.Children = []proto.TargetID{b.ID}
	b.Children = []proto.TargetID{a.ID}
	return proto.GraphManifest{RootID: a.ID, Nodes: []proto.GraphNode{a, b}}
}

func executionPlanDepthManifest(depth int) proto.GraphManifest {
	if depth < 1 {
		return proto.GraphManifest{}
	}
	nodes := make([]proto.GraphNode, depth)
	for i := depth - 1; i >= 0; i-- {
		name := fmt.Sprintf("plan-depth-%02d", i)
		if i == depth-1 {
			nodes[i] = executionPlanTestNode(proto.GraphNodeKindPath, name)
		} else {
			nodes[i] = executionPlanTestNode(proto.GraphNodeKindSelector, name, nodes[i+1].ID)
		}
	}
	return proto.GraphManifest{RootID: nodes[0].ID, Nodes: nodes}
}

func executionPlanSameNames(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	got = append([]string(nil), got...)
	want = append([]string(nil), want...)
	sort.Strings(got)
	sort.Strings(want)
	return reflect.DeepEqual(got, want)
}
