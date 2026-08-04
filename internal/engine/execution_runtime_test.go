package engine

import (
	"reflect"
	"testing"

	"github.com/FrankoonG/rendr/proto"
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

func runtimeNode(kind proto.GraphNodeKind, name string, children ...string) proto.GraphNode {
	node := proto.GraphNode{ID: proto.DeriveTargetID(kind, name), Kind: kind, Name: name}
	for _, child := range children {
		var childKind proto.GraphNodeKind
		switch child {
		case "inner":
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
