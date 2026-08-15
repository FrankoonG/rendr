package engine

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

func TestExecutionRuntimePreservesCrossModeBoundaries(t *testing.T) {
	t.Run("race invokes bond as one logical child", func(t *testing.T) {
		manifest, ids := runtimeGraph(t,
			runtimeNode(proto.GraphNodeKindRace, "root", "direct", "aggregate"),
			runtimeNode(proto.GraphNodeKindPath, "direct"),
			runtimeNode(proto.GraphNodeKindBond, "aggregate", "b", "c"),
			runtimeNode(proto.GraphNodeKindPath, "b"),
			runtimeNode(proto.GraphNodeKindPath, "c"),
		)
		runtime := mustExecutionRuntime(t, manifest)
		attached := runtimeAttached(ids, "direct", "b", "c")
		first := runtimeRouteNames(t, runtime, attached, true)
		second := runtimeRouteNames(t, runtime, attached, true)
		if !reflect.DeepEqual(first, []string{"direct", "b"}) || !reflect.DeepEqual(second, []string{"direct", "c"}) {
			t.Fatalf("race(bond) routes=%v then %v, want [direct b] then [direct c]", first, second)
		}
	})

	t.Run("bond invokes race as one logical child", func(t *testing.T) {
		manifest, ids := runtimeGraph(t,
			runtimeNode(proto.GraphNodeKindBond, "root", "direct", "redundant"),
			runtimeNode(proto.GraphNodeKindPath, "direct"),
			runtimeNode(proto.GraphNodeKindRace, "redundant", "b", "c"),
			runtimeNode(proto.GraphNodeKindPath, "b"),
			runtimeNode(proto.GraphNodeKindPath, "c"),
		)
		runtime := mustExecutionRuntime(t, manifest)
		attached := runtimeAttached(ids, "direct", "b", "c")
		first := runtimeRouteNames(t, runtime, attached, true)
		second := runtimeRouteNames(t, runtime, attached, true)
		if !reflect.DeepEqual(first, []string{"direct"}) || !reflect.DeepEqual(second, []string{"b", "c"}) {
			t.Fatalf("bond(race) routes=%v then %v, want [direct] then [b c]", first, second)
		}
	})
}

func TestExecutionRuntimeNestedSelectorsKeepIndependentState(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "direct", "inner"),
		runtimeNode(proto.GraphNodeKindPath, "direct"),
		runtimeNode(proto.GraphNodeKindSelector, "inner", "b", "c"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
		runtimeNode(proto.GraphNodeKindPath, "c"),
	)
	runtime := mustExecutionRuntime(t, manifest)
	attached := runtimeAttached(ids, "direct", "b", "c")
	if got := runtimeRouteNames(t, runtime, attached, true); !reflect.DeepEqual(got, []string{"direct"}) {
		t.Fatalf("initial root route=%v", got)
	}
	if err := runtime.selectChild(ids["root"], ids["inner"]); err != nil {
		t.Fatal(err)
	}
	if got := runtimeRouteNames(t, runtime, attached, true); !reflect.DeepEqual(got, []string{"b"}) {
		t.Fatalf("initial inner route=%v", got)
	}
	if err := runtime.selectChild(ids["inner"], ids["c"]); err != nil {
		t.Fatal(err)
	}
	if got := runtimeRouteNames(t, runtime, attached, true); !reflect.DeepEqual(got, []string{"c"}) {
		t.Fatalf("selected inner route=%v", got)
	}
}

func TestExecutionRuntimeFlatSelectorQualificationIsExact(t *testing.T) {
	flatManifest, flatIDs := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	flat := mustExecutionRuntime(t, flatManifest)
	if !flat.flatLeafSelector || !flat.ownsFlatSelectorLeaf(flatIDs["a"]) || !flat.ownsFlatSelectorLeaf(flatIDs["b"]) {
		t.Fatalf("flat selector was not qualified: runtime=%+v", flat)
	}
	if flat.ownsFlatSelectorLeaf(proto.DeriveTargetID(proto.GraphNodeKindPath, "other")) {
		t.Fatal("flat selector accepted a non-child leaf")
	}

	for _, test := range []struct {
		name     string
		manifest proto.GraphManifest
	}{
		{name: "bond root", manifest: func() proto.GraphManifest {
			manifest, _ := runtimeGraph(t,
				runtimeNode(proto.GraphNodeKindBond, "root", "a", "b"),
				runtimeNode(proto.GraphNodeKindPath, "a"),
				runtimeNode(proto.GraphNodeKindPath, "b"),
			)
			return manifest
		}()},
		{name: "selector nested group", manifest: func() proto.GraphManifest {
			manifest, _ := runtimeGraph(t,
				runtimeNode(proto.GraphNodeKindSelector, "root", "aggregate", "c"),
				runtimeNode(proto.GraphNodeKindBond, "aggregate", "a", "b"),
				runtimeNode(proto.GraphNodeKindPath, "a"),
				runtimeNode(proto.GraphNodeKindPath, "b"),
				runtimeNode(proto.GraphNodeKindPath, "c"),
			)
			return manifest
		}()},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := mustExecutionRuntime(t, test.manifest)
			if runtime.flatLeafSelector {
				t.Fatal("non-flat execution graph qualified for the flat selector dispatcher")
			}
		})
	}
}

func TestExecutionRuntimeBondPinsFourFramesPerChild(t *testing.T) {
	for _, pinSize := range []int{4, DefaultLimits().BondPinSize} {
		t.Run(fmt.Sprintf("pin-%d", pinSize), func(t *testing.T) {
			manifest, ids := runtimeGraph(t,
				runtimeNode(proto.GraphNodeKindBond, "root", "a", "b"),
				runtimeNode(proto.GraphNodeKindPath, "a"),
				runtimeNode(proto.GraphNodeKindPath, "b"),
			)
			runtime := mustExecutionRuntime(t, manifest)
			attached := runtimeAttached(ids, "a", "b")
			frameCount := pinSize * 8
			routes := make([]proto.TargetID, 0, frameCount)
			for frame := 0; frame < frameCount; frame++ {
				ticket, err := runtime.buildTicket(attached, false, pinSize)
				if err != nil {
					t.Fatalf("ticket %d: %v", frame, err)
				}
				if len(ticket.routes) != 1 {
					t.Fatalf("ticket %d routes=%v, want one bond route", frame, ticket.routes)
				}
				routes = append(routes, ticket.routes[0].targetID)
			}

			var previousRun proto.TargetID
			for start := 0; start < frameCount; start += pinSize {
				run := routes[start]
				for offset := 1; offset < pinSize; offset++ {
					if routes[start+offset] != run {
						t.Fatalf("run %d split at offset %d: routes=%x", start/pinSize, offset, routes)
					}
				}
				if start != 0 && run == previousRun {
					t.Fatalf("runs %d and %d reused child %x: routes=%x", start/pinSize-1, start/pinSize, run, routes)
				}
				previousRun = run
			}
		})
	}

	t.Run("weighted-3-to-1", func(t *testing.T) {
		a := runtimeNode(proto.GraphNodeKindPath, "a")
		a.Weight = 3
		b := runtimeNode(proto.GraphNodeKindPath, "b")
		b.Weight = 1
		root := runtimeNode(proto.GraphNodeKindBond, "root", "a", "b")
		manifest, ids := runtimeGraph(t, root, a, b)
		runtime := mustExecutionRuntime(t, manifest)
		attached := runtimeAttached(ids, "a", "b")
		capacities := map[proto.TargetID]uint64{ids["a"]: 3, ids["b"]: 1}
		counts := map[proto.TargetID]int{}
		for frame := 0; frame < 64; frame++ {
			ticket, err := runtime.buildTicketObserved(attached, nil, capacities, false, DefaultLimits().BondPinSize, 0)
			if err != nil {
				t.Fatalf("ticket %d: %v", frame, err)
			}
			if len(ticket.routes) != 1 {
				t.Fatalf("ticket %d routes=%v, want one bond route", frame, ticket.routes)
			}
			counts[ticket.routes[0].targetID]++
		}
		if counts[ids["a"]] != 48 || counts[ids["b"]] != 16 {
			t.Fatalf("weighted routes a=%d b=%d, want 48:16", counts[ids["a"]], counts[ids["b"]])
		}
	})
}

func TestExecutionRuntimeSelectorHardDeathFallsBackAndRecoversDesired(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	runtime := mustExecutionRuntime(t, manifest)
	if err := runtime.selectChild(ids["root"], ids["b"]); err != nil {
		t.Fatal(err)
	}
	if got := runtimeRouteNames(t, runtime, runtimeAttached(ids, "a"), true); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("death fallback route=%v", got)
	}
	desired, effective, ok := runtime.selectedChild(ids["root"])
	if !ok || desired != ids["b"] || effective != ids["a"] {
		t.Fatalf("fallback state desired=%x effective=%x ok=%t", desired, effective, ok)
	}
	projected := runtime.effectiveLeafTargets(runtimeAttached(ids, "a", "b"))
	if !projected[ids["b"]] || projected[ids["a"]] || len(projected) != 1 {
		t.Fatalf("recovered desired projection=%v want only b before first dispatch", projected)
	}
	if got := runtimeRouteNames(t, runtime, runtimeAttached(ids, "a", "b"), true); !reflect.DeepEqual(got, []string{"b"}) {
		t.Fatalf("recovered desired route=%v", got)
	}
}

func TestExecutionRuntimePolicySwitchUsesEffectiveSelectorLeaf(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b", "c"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
		runtimeNode(proto.GraphNodeKindPath, "c"),
	)
	runtime := mustExecutionRuntime(t, manifest)
	if err := runtime.selectChild(ids["root"], ids["b"]); err != nil {
		t.Fatal(err)
	}
	if got := runtimeRouteNames(t, runtime, runtimeAttached(ids, "a", "c"), true); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("fallback route=%v want [a]", got)
	}

	leaves := runtime.policySwitchLeaves(ids["root"], ids["c"], runtimeAttached(ids, "a", "c"))
	if !leaves[ids["a"]] || !leaves[ids["c"]] || leaves[ids["b"]] {
		t.Fatalf("policy switch leaves=%v want effective a plus destination c", leaves)
	}
}

func TestPolicySelectionRouteChangeFactExcludesInactiveNestedSelector(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "inner"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindSelector, "inner", "b", "c"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
		runtimeNode(proto.GraphNodeKindPath, "c"),
	)
	runtime := mustExecutionRuntime(t, manifest)
	attached := runtimeAttached(ids, "a", "b", "c")
	if err := runtime.selectChild(ids["root"], ids["a"]); err != nil {
		t.Fatal(err)
	}
	if err := runtime.selectChild(ids["inner"], ids["b"]); err != nil {
		t.Fatal(err)
	}
	if runtime.policySelectionChangesEffectiveRoute(ids["inner"], ids["c"], attached) {
		t.Fatal("inactive nested selector was treated as a data-plane cutover")
	}
	if err := runtime.selectChild(ids["root"], ids["inner"]); err != nil {
		t.Fatal(err)
	}
	if !runtime.policySelectionChangesEffectiveRoute(ids["inner"], ids["c"], attached) {
		t.Fatal("active nested selector route change did not require cutover custody")
	}
	if runtime.policySelectionChangesEffectiveRoute(ids["inner"], ids["b"], attached) {
		t.Fatal("same effective child was treated as a route change")
	}
}

func TestExecutionRuntimeFailedSelectorCommitRestoresState(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	runtime := mustExecutionRuntime(t, manifest)
	if err := runtime.selectChild(ids["root"], ids["a"]); err != nil {
		t.Fatal(err)
	}
	if got := runtimeRouteNames(t, runtime, runtimeAttached(ids, "a", "b"), true); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("initial route=%v", got)
	}
	injected := errors.New("injected projection failure")
	err := runtime.commitSelectorChild(ids["root"], ids["b"], runtimeAttached(ids, "a", "b"), func(map[proto.TargetID]bool) error {
		return injected
	})
	if !errors.Is(err, injected) {
		t.Fatalf("commit error=%v want=%v", err, injected)
	}
	desired, effective, ok := runtime.selectedChild(ids["root"])
	if !ok || desired != ids["a"] || effective != ids["a"] {
		t.Fatalf("failed commit state desired=%x effective=%x ok=%t", desired, effective, ok)
	}
	if err := runtime.commitSelectorChild(ids["root"], ids["b"], runtimeAttached(ids, "a"), nil); err == nil {
		t.Fatal("commit accepted a target without an attached leaf")
	}
	desired, effective, ok = runtime.selectedChild(ids["root"])
	if !ok || desired != ids["a"] || effective != ids["a"] {
		t.Fatalf("unavailable commit state desired=%x effective=%x ok=%t", desired, effective, ok)
	}
}

func TestExecutionRuntimePolicySwitchProjectsNestedEffectiveLeaves(t *testing.T) {
	root := proto.GraphNode{
		ID:       proto.DeriveTargetID(proto.GraphNodeKindSelector, "root"),
		Kind:     proto.GraphNodeKindSelector,
		Name:     "root",
		Children: []proto.TargetID{proto.DeriveTargetID(proto.GraphNodeKindBond, "aggregate"), proto.DeriveTargetID(proto.GraphNodeKindPath, "fallback")},
	}
	aggregate := proto.GraphNode{
		ID:       proto.DeriveTargetID(proto.GraphNodeKindBond, "aggregate"),
		Kind:     proto.GraphNodeKindBond,
		Name:     "aggregate",
		Children: []proto.TargetID{proto.DeriveTargetID(proto.GraphNodeKindSelector, "choice"), proto.DeriveTargetID(proto.GraphNodeKindRace, "redundant")},
	}
	choice := proto.GraphNode{
		ID:       proto.DeriveTargetID(proto.GraphNodeKindSelector, "choice"),
		Kind:     proto.GraphNodeKindSelector,
		Name:     "choice",
		Children: []proto.TargetID{proto.DeriveTargetID(proto.GraphNodeKindPath, "a"), proto.DeriveTargetID(proto.GraphNodeKindPath, "b")},
	}
	redundant := proto.GraphNode{
		ID:       proto.DeriveTargetID(proto.GraphNodeKindRace, "redundant"),
		Kind:     proto.GraphNodeKindRace,
		Name:     "redundant",
		Children: []proto.TargetID{proto.DeriveTargetID(proto.GraphNodeKindPath, "c"), proto.DeriveTargetID(proto.GraphNodeKindPath, "d")},
	}
	manifest, ids := runtimeGraph(t,
		root,
		aggregate,
		choice,
		redundant,
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
		runtimeNode(proto.GraphNodeKindPath, "c"),
		runtimeNode(proto.GraphNodeKindPath, "d"),
		runtimeNode(proto.GraphNodeKindPath, "fallback"),
	)
	runtime := mustExecutionRuntime(t, manifest)
	if err := runtime.selectChild(ids["root"], ids["aggregate"]); err != nil {
		t.Fatal(err)
	}
	if err := runtime.selectChild(ids["choice"], ids["b"]); err != nil {
		t.Fatal(err)
	}
	attached := runtimeAttached(ids, "a", "c", "d", "fallback")
	if _, _, err := runtime.activeLeafTargets(attached); err != nil {
		t.Fatal(err)
	}

	leaves := runtime.policySwitchLeaves(ids["root"], ids["fallback"], attached)
	for _, name := range []string{"a", "c", "d", "fallback"} {
		if !leaves[ids[name]] {
			t.Fatalf("policy switch projection omitted effective leaf %s: %v", name, leaves)
		}
	}
	if leaves[ids["b"]] {
		t.Fatalf("policy switch projection retained unavailable desired leaf b: %v", leaves)
	}
	recovered := runtime.effectiveLeafTargets(runtimeAttached(ids, "a", "b", "c", "d", "fallback"))
	for _, name := range []string{"b", "c", "d"} {
		if !recovered[ids[name]] {
			t.Fatalf("recovered nested projection omitted desired leaf %s: %v", name, recovered)
		}
	}
	if recovered[ids["a"]] || recovered[ids["fallback"]] || len(recovered) != 3 {
		t.Fatalf("recovered nested projection=%v want exactly b/c/d", recovered)
	}
}

func TestExecutionRuntimeSelectorDispatchStallWaitsForPolicyDecision(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	runtime := mustExecutionRuntime(t, manifest)
	if err := runtime.selectChild(ids["root"], ids["a"]); err != nil {
		t.Fatal(err)
	}
	eligible := runtimeAttached(ids, "b")
	present := runtimeAttached(ids, "a", "b")
	ticket, err := runtime.buildTicketObservedPresence(eligible, present, nil, nil, false, 1, 0)
	if !errors.Is(err, errNoExecutionRoute) || len(ticket.routes) != 0 {
		t.Fatalf("stalled selected child ticket=%v err=%v want no execution route", ticket.routes, err)
	}
	desired, effective, ok := runtime.selectedChild(ids["root"])
	if !ok || desired != ids["a"] || effective != (proto.TargetID{}) {
		t.Fatalf("stalled state desired=%x effective=%x ok=%t want a/zero/true", desired, effective, ok)
	}
}

func TestExecutionRuntimeSelectorAggregateRTTUsesEffectiveChild(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindBond, "root", "choice", "direct"),
		runtimeNode(proto.GraphNodeKindSelector, "choice", "fast", "slow"),
		runtimeNode(proto.GraphNodeKindPath, "fast"),
		runtimeNode(proto.GraphNodeKindPath, "slow"),
		runtimeNode(proto.GraphNodeKindPath, "direct"),
	)
	runtime := mustExecutionRuntime(t, manifest)
	if err := runtime.selectChild(ids["choice"], ids["slow"]); err != nil {
		t.Fatal(err)
	}
	attached := runtimeAttached(ids, "fast", "slow", "direct")
	var available func(proto.TargetID) bool
	available = func(id proto.TargetID) bool {
		node, ok := runtime.plan.node(id)
		if !ok {
			return false
		}
		if node.kind == proto.GraphNodeKindPath {
			return attached[id]
		}
		for _, child := range node.children {
			if available(child) {
				return true
			}
		}
		return false
	}
	qualities := map[proto.TargetID]transport.PathQuality{
		ids["fast"]:   {RTT: time.Millisecond},
		ids["slow"]:   {RTT: time.Second},
		ids["direct"]: {RTT: 100 * time.Millisecond},
	}
	if got := runtime.aggregateRTT(ids["choice"], available, qualities); got != time.Second {
		t.Fatalf("selector aggregate RTT=%v, want effective slow child RTT=1s", got)
	}
}

func runtimeNode(kind proto.GraphNodeKind, name string, children ...string) proto.GraphNode {
	node := proto.GraphNode{ID: proto.DeriveTargetID(kind, name), Kind: kind, Name: name}
	for _, child := range children {
		var childKind proto.GraphNodeKind
		switch child {
		case "inner":
			childKind = proto.GraphNodeKindSelector
		case "choice":
			childKind = proto.GraphNodeKindSelector
		case "aggregate":
			childKind = proto.GraphNodeKindBond
		case "redundant":
			childKind = proto.GraphNodeKindRace
		default:
			childKind = proto.GraphNodeKindPath
		}
		node.Children = append(node.Children, proto.DeriveTargetID(childKind, child))
	}
	return node
}

func runtimeGraph(t *testing.T, nodes ...proto.GraphNode) (proto.GraphManifest, map[string]proto.TargetID) {
	t.Helper()
	manifest := proto.GraphManifest{RootID: nodes[0].ID, Nodes: nodes}
	if err := manifest.Validate(); err != nil {
		t.Fatalf("invalid runtime test graph: %v", err)
	}
	ids := make(map[string]proto.TargetID, len(nodes))
	for _, node := range nodes {
		ids[node.Name] = node.ID
	}
	return manifest, ids
}

func mustExecutionRuntime(t *testing.T, manifest proto.GraphManifest) *executionRuntime {
	t.Helper()
	plan, err := compileExecutionPlan(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return newExecutionRuntime(plan)
}

func runtimeAttached(ids map[string]proto.TargetID, names ...string) map[proto.TargetID]bool {
	attached := make(map[proto.TargetID]bool, len(names))
	for _, name := range names {
		attached[ids[name]] = true
	}
	return attached
}

func runtimeRouteNames(t *testing.T, runtime *executionRuntime, attached map[proto.TargetID]bool, packetized bool) []string {
	t.Helper()
	ticket, err := runtime.buildTicket(attached, packetized, 0)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(ticket.routes))
	for _, route := range ticket.routes {
		node, ok := runtime.plan.node(route.targetID)
		if !ok {
			t.Fatalf("route target %x missing", route.targetID)
		}
		names = append(names, node.name)
	}
	return names
}
