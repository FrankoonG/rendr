package engine

import (
	"bytes"
	"errors"
	"testing"

	"github.com/FrankoonG/rendr/proto"
)

func selectorStateSnapshotFixture(t *testing.T) (*executionRuntime, map[string]proto.TargetID) {
	t.Helper()
	ids := map[string]proto.TargetID{
		"root":   proto.DeriveTargetID(proto.GraphNodeKindSelector, "snapshot-root"),
		"normal": proto.DeriveTargetID(proto.GraphNodeKindPath, "snapshot-normal"),
		"bond":   proto.DeriveTargetID(proto.GraphNodeKindBond, "snapshot-bond"),
		"inner":  proto.DeriveTargetID(proto.GraphNodeKindSelector, "snapshot-inner"),
		"a":      proto.DeriveTargetID(proto.GraphNodeKindPath, "snapshot-a"),
		"b":      proto.DeriveTargetID(proto.GraphNodeKindPath, "snapshot-b"),
	}
	manifest := proto.GraphManifest{
		RootID: ids["root"],
		Nodes: []proto.GraphNode{
			{ID: ids["a"], Kind: proto.GraphNodeKindPath, Name: "snapshot-a"},
			{ID: ids["root"], Kind: proto.GraphNodeKindSelector, Name: "snapshot-root", Children: []proto.TargetID{ids["normal"], ids["bond"]}, PeakCandidates: []proto.TargetID{ids["bond"]}},
			{ID: ids["bond"], Kind: proto.GraphNodeKindBond, Name: "snapshot-bond", Children: []proto.TargetID{ids["inner"]}},
			{ID: ids["b"], Kind: proto.GraphNodeKindPath, Name: "snapshot-b"},
			{ID: ids["inner"], Kind: proto.GraphNodeKindSelector, Name: "snapshot-inner", Children: []proto.TargetID{ids["a"], ids["b"]}, PeakCandidates: []proto.TargetID{ids["b"]}},
			{ID: ids["normal"], Kind: proto.GraphNodeKindPath, Name: "snapshot-normal"},
		},
	}
	plan, err := compileExecutionPlan(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return newExecutionRuntime(plan), ids
}

func TestSelectorStateSnapshotRequiresEverySelector(t *testing.T) {
	runtime, ids := selectorStateSnapshotFixture(t)
	runtime.mu.Lock()
	runtime.selectorRevision = 1
	runtime.selectors[ids["root"]] = &selectorExecutionState{
		desired: ids["normal"], effective: ids["normal"], generation: 1,
	}
	runtime.mu.Unlock()
	if snapshot, ok := runtime.selectorStateSnapshot(); ok || snapshot.StateEpoch != 0 || len(snapshot.Entries) != 0 {
		t.Fatalf("partial selector vector published: %+v", snapshot)
	}

	runtime.mu.Lock()
	runtime.selectors[ids["inner"]] = &selectorExecutionState{
		desired: ids["a"], effective: ids["b"], generation: 3,
	}
	runtime.selectorRevision = 9
	runtime.mu.Unlock()
	snapshot, ok := runtime.selectorStateSnapshot()
	if !ok || snapshot.StateEpoch != 9 || len(snapshot.Entries) != 2 {
		t.Fatalf("complete selector vector=%+v ok=%t", snapshot, ok)
	}
	if bytes.Compare(snapshot.Entries[0].SelectorID[:], snapshot.Entries[1].SelectorID[:]) >= 0 {
		t.Fatalf("selector vector is not canonical: %+v", snapshot.Entries)
	}
}

func TestSelectorStateSnapshotRejectsInvalidStateAndOwnsCopy(t *testing.T) {
	runtime, ids := selectorStateSnapshotFixture(t)
	runtime.mu.Lock()
	runtime.selectorRevision = 4
	runtime.selectors[ids["root"]] = &selectorExecutionState{
		desired: ids["normal"], effective: ids["normal"], generation: 1,
	}
	runtime.selectors[ids["inner"]] = &selectorExecutionState{
		desired: ids["a"], effective: ids["b"], generation: 2,
	}
	runtime.mu.Unlock()

	snapshot, ok := runtime.selectorStateSnapshot()
	if !ok {
		t.Fatal("valid state was not publishable")
	}
	before := append([]proto.SelectorStateEntry(nil), snapshot.Entries...)
	runtime.mu.Lock()
	runtime.selectors[ids["inner"]].effective = ids["a"]
	runtime.selectorRevision++
	runtime.mu.Unlock()
	for index := range before {
		if snapshot.Entries[index] != before[index] {
			t.Fatal("published selector snapshot aliases runtime state")
		}
	}

	runtime.mu.Lock()
	runtime.selectors[ids["inner"]].desired = ids["normal"]
	runtime.mu.Unlock()
	if invalid, ok := runtime.selectorStateSnapshot(); ok || len(invalid.Entries) != 0 {
		t.Fatalf("invalid immediate child published: %+v", invalid)
	}
}

func TestSelectorStateEpochExhaustionDoesNotReuseIdentity(t *testing.T) {
	runtime, ids := selectorStateSnapshotFixture(t)
	attached := map[proto.TargetID]bool{
		ids["normal"]: true,
		ids["a"]:      true,
		ids["b"]:      true,
	}
	if err := runtime.commitSelectorChild(ids["root"], ids["normal"], attached, nil); err != nil {
		t.Fatal(err)
	}

	runtime.mu.Lock()
	before := *runtime.selectors[ids["root"]]
	runtime.selectorRevision = ^uint64(0)
	runtime.mu.Unlock()
	applyCalled := false
	err := runtime.commitSelectorChild(ids["root"], ids["bond"], attached, func(map[proto.TargetID]bool) error {
		applyCalled = true
		return nil
	})
	if !errors.Is(err, ErrSelectorStateEpochExhausted) {
		t.Fatalf("commit error=%v want ErrSelectorStateEpochExhausted", err)
	}
	if applyCalled {
		t.Fatal("exhausted selector state epoch reached physical projection")
	}
	runtime.mu.Lock()
	after := *runtime.selectors[ids["root"]]
	epoch := runtime.selectorRevision
	runtime.mu.Unlock()
	if after != before || epoch != ^uint64(0) {
		t.Fatalf("exhausted commit mutated state: before=%+v after=%+v epoch=%d", before, after, epoch)
	}

	deferredPanicked := false
	runtime.mu.Lock()
	func() {
		defer runtime.mu.Unlock()
		defer func() { deferredPanicked = recover() != nil }()
		runtime.setSelectorEffectiveLocked(runtime.selectors[ids["root"]], ids["bond"])
	}()
	if !deferredPanicked {
		t.Fatal("automatic effective-route mutation reused an exhausted StateEpoch")
	}
	runtime.mu.Lock()
	final := *runtime.selectors[ids["root"]]
	epoch = runtime.selectorRevision
	runtime.mu.Unlock()
	if final != before || epoch != ^uint64(0) {
		t.Fatalf("fail-stop effective mutation changed state: before=%+v after=%+v epoch=%d", before, final, epoch)
	}
}
