package engine

import (
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

func TestExecutionRuntimeBondPinsFourFramesPerChild(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindBond, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	runtime := mustExecutionRuntime(t, manifest)
	attached := runtimeAttached(ids, "a", "b")

	const (
		frameCount = 64
		pinSize    = 4
	)
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
}

func TestExecutionRuntimeSelectorDeathBypassesPolicyAndRecoversDesired(t *testing.T) {
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
	if got := runtimeRouteNames(t, runtime, runtimeAttached(ids, "a", "b"), true); !reflect.DeepEqual(got, []string{"b"}) {
		t.Fatalf("recovered desired route=%v", got)
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
