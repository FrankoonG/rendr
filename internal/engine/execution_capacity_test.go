package engine

import (
	"reflect"
	"testing"

	"github.com/FrankoonG/rendr/proto"
)

func TestExecutionRuntimeRecursiveBondCapacity(t *testing.T) {
	t.Run("parent bond uses selector effective child capacity", func(t *testing.T) {
		a := capacityTestPath("selector-a")
		b := capacityTestPath("selector-b")
		choice := capacityTestGroup(proto.GraphNodeKindSelector, "selector-choice", a, b)
		direct := capacityTestPath("selector-direct")
		root := capacityTestGroup(proto.GraphNodeKindBond, "selector-root", choice, direct)
		runtime := capacityTestRuntime(t, root, choice, a, b, direct)

		if err := runtime.selectChild(choice.ID, b.ID); err != nil {
			t.Fatalf("select effective child: %v", err)
		}
		got := capacityTestDistribution(t, runtime,
			capacityTestAttached(a, b, direct),
			map[proto.TargetID]uint64{a.ID: 97, b.ID: 3, direct.ID: 1},
			400,
		)
		want := map[string]int{"selector-b": 300, "selector-direct": 100}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("route distribution=%v, want %v", got, want)
		}
	})

	t.Run("nested bond capacity is the sum of available leaves", func(t *testing.T) {
		a := capacityTestPath("nested-a")
		b := capacityTestPath("nested-b")
		aggregate := capacityTestGroup(proto.GraphNodeKindBond, "nested-aggregate", a, b)
		// The selector preserves the cross-mode boundary required by canonical
		// graphs; direct bond(bond(...)) nodes are normalized before execution.
		wrapper := capacityTestGroup(proto.GraphNodeKindSelector, "nested-wrapper", aggregate)
		direct := capacityTestPath("nested-direct")
		root := capacityTestGroup(proto.GraphNodeKindBond, "nested-root", wrapper, direct)
		runtime := capacityTestRuntime(t, root, wrapper, aggregate, a, b, direct)

		got := capacityTestDistribution(t, runtime,
			capacityTestAttached(a, b, direct),
			map[proto.TargetID]uint64{a.ID: 2, b.ID: 3, direct.ID: 2},
			700,
		)
		want := map[string]int{"nested-a": 200, "nested-b": 300, "nested-direct": 200}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("route distribution=%v, want %v", got, want)
		}
	})

	t.Run("race capacity is maximum rather than duplicate sum", func(t *testing.T) {
		a := capacityTestPath("race-a")
		b := capacityTestPath("race-b")
		redundant := capacityTestGroup(proto.GraphNodeKindRace, "race-redundant", a, b)
		direct := capacityTestPath("race-direct")
		root := capacityTestGroup(proto.GraphNodeKindBond, "race-root", redundant, direct)
		runtime := capacityTestRuntime(t, root, redundant, a, b, direct)

		got := capacityTestDistribution(t, runtime,
			capacityTestAttached(a, b, direct),
			map[proto.TargetID]uint64{a.ID: 2, b.ID: 3, direct.ID: 1},
			1200,
		)
		// The race target receives 3/4 of parent tickets and duplicates each
		// selected ticket to both leaves. Summing duplicate capacity would
		// instead produce a 5:1 parent distribution.
		want := map[string]int{"race-a": 900, "race-b": 900, "race-direct": 300}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("route distribution=%v, want %v", got, want)
		}
	})

	t.Run("zero and unknown capacities remain explorable", func(t *testing.T) {
		zero := capacityTestPath("explore-zero")
		unknown := capacityTestPath("explore-unknown")
		known := capacityTestPath("explore-known")
		root := capacityTestGroup(proto.GraphNodeKindBond, "explore-root", zero, unknown, known)
		runtime := capacityTestRuntime(t, root, zero, unknown, known)

		got := capacityTestDistribution(t, runtime,
			capacityTestAttached(zero, unknown, known),
			map[proto.TargetID]uint64{zero.ID: 0, known.ID: 2},
			400,
		)
		want := map[string]int{"explore-zero": 100, "explore-unknown": 100, "explore-known": 200}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("route distribution=%v, want %v", got, want)
		}
	})

	t.Run("unavailable children are excluded from capacity", func(t *testing.T) {
		a := capacityTestPath("available-a")
		unavailable := capacityTestPath("unavailable-heavy")
		c := capacityTestPath("available-c")
		root := capacityTestGroup(proto.GraphNodeKindBond, "available-root", a, unavailable, c)
		runtime := capacityTestRuntime(t, root, a, unavailable, c)

		got := capacityTestDistribution(t, runtime,
			capacityTestAttached(a, c),
			map[proto.TargetID]uint64{a.ID: 1, unavailable.ID: 997, c.ID: 2},
			300,
		)
		want := map[string]int{"available-a": 100, "available-c": 200}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("route distribution=%v, want %v", got, want)
		}
	})
}

func capacityTestPath(name string) proto.GraphNode {
	return proto.GraphNode{
		ID:   proto.DeriveTargetID(proto.GraphNodeKindPath, name),
		Kind: proto.GraphNodeKindPath,
		Name: name,
	}
}

func capacityTestGroup(kind proto.GraphNodeKind, name string, children ...proto.GraphNode) proto.GraphNode {
	node := proto.GraphNode{
		ID:   proto.DeriveTargetID(kind, name),
		Kind: kind,
		Name: name,
	}
	for _, child := range children {
		node.Children = append(node.Children, child.ID)
	}
	return node
}

func capacityTestRuntime(t *testing.T, nodes ...proto.GraphNode) *executionRuntime {
	t.Helper()
	manifest := proto.GraphManifest{RootID: nodes[0].ID, Nodes: nodes}
	if err := manifest.Validate(); err != nil {
		t.Fatalf("invalid capacity test graph: %v", err)
	}
	plan, err := compileExecutionPlan(manifest)
	if err != nil {
		t.Fatalf("compile capacity test graph: %v", err)
	}
	return newExecutionRuntime(plan)
}

func capacityTestAttached(nodes ...proto.GraphNode) map[proto.TargetID]bool {
	attached := make(map[proto.TargetID]bool, len(nodes))
	for _, node := range nodes {
		attached[node.ID] = true
	}
	return attached
}

func capacityTestDistribution(
	t *testing.T,
	runtime *executionRuntime,
	attached map[proto.TargetID]bool,
	capacities map[proto.TargetID]uint64,
	ticketCount int,
) map[string]int {
	t.Helper()
	distribution := make(map[string]int)
	for ticketIndex := 0; ticketIndex < ticketCount; ticketIndex++ {
		ticket, err := runtime.buildTicketObserved(attached, nil, capacities, true, 1, 0)
		if err != nil {
			t.Fatalf("ticket %d: %v", ticketIndex, err)
		}
		for _, route := range ticket.routes {
			node, ok := runtime.plan.node(route.targetID)
			if !ok {
				t.Fatalf("ticket %d references missing route %x", ticketIndex, route.targetID)
			}
			distribution[node.name]++
		}
	}
	return distribution
}
