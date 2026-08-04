package rendr

import (
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCompileTargetGraphCanonicalGolden(t *testing.T) {
	root := Selector("root", []Target{
		Path("primary", PathSpec{
			Transport: "tcp",
			Address:   "edge.example:443",
			Local:     "source-a",
			Weight:    7,
			Opts:      map[string]string{"zeta": "last", "alpn": "rendr"},
		}),
		Bond("bulk", []Target{
			Path("bulk-a", PathSpec{Transport: "quic", Address: "bulk-a.example:443"}),
			Bond("bulk-inner", []Target{
				Path("bulk-b", PathSpec{Transport: "tcp", Address: "bulk-b.example:443", Weight: 2}),
				Path("bulk-c", PathSpec{Transport: "tcp", Address: "bulk-c.example:443", Weight: 3}),
			}),
		}),
		Race("fast", []Target{
			Race("fast-inner", []Target{
				Path("fast-a", PathSpec{Transport: "udp", Address: "fast-a.example:443"}),
			}),
			Path("fast-b", PathSpec{Transport: "udp", Address: "fast-b.example:443"}),
		}),
	}, PeakTransfer{
		Targets:         []string{"fast", "bulk"},
		SaturationRatio: 0.8,
		SaturationFor:   2 * time.Second,
		ReturnRatio:     0.5,
		ReturnFor:       3 * time.Second,
		ProbeBudget:     9,
	})

	graph, err := compileTargetGraph(root)
	if err != nil {
		t.Fatal(err)
	}
	const wantCanonical = `{"version":1,"root":{"kind":"selector","name":"root","peak":{"targets":["bulk","fast"],"saturation_ratio_bits":4605380978949069210,"saturation_for_ns":2000000000,"return_ratio_bits":4602678819172646912,"return_for_ns":3000000000,"probe_budget":9},"children":[{"kind":"path","name":"primary","path":{"carrier":"tcp","address":"edge.example:443","local":"source-a","weight":7,"options":[{"key":"alpn","value":"rendr"},{"key":"name","value":"primary"},{"key":"zeta","value":"last"}]}},{"kind":"bond","name":"bulk","children":[{"kind":"path","name":"bulk-a","path":{"carrier":"quic","address":"bulk-a.example:443","local":"","weight":0,"options":[{"key":"name","value":"bulk-a"}]}},{"kind":"path","name":"bulk-b","path":{"carrier":"tcp","address":"bulk-b.example:443","local":"","weight":2,"options":[{"key":"name","value":"bulk-b"}]}},{"kind":"path","name":"bulk-c","path":{"carrier":"tcp","address":"bulk-c.example:443","local":"","weight":3,"options":[{"key":"name","value":"bulk-c"}]}}]},{"kind":"race","name":"fast","children":[{"kind":"path","name":"fast-a","path":{"carrier":"udp","address":"fast-a.example:443","local":"","weight":0,"options":[{"key":"name","value":"fast-a"}]}},{"kind":"path","name":"fast-b","path":{"carrier":"udp","address":"fast-b.example:443","local":"","weight":0,"options":[{"key":"name","value":"fast-b"}]}}]}]},"flattened":[{"kind":"bond","name":"bulk-inner"},{"kind":"race","name":"fast-inner"}]}`
	if got := string(graph.canonical); got != wantCanonical {
		t.Fatalf("canonical graph mismatch\n got: %s\nwant: %s", got, wantCanonical)
	}
	const wantDigest = "e86418596b40e1305a05e3379b3ca001c7946fd450f0af313903242fb0ba180a"
	if got := hex.EncodeToString(graph.digest[:]); got != wantDigest {
		t.Fatalf("digest=%s want %s", got, wantDigest)
	}
	if graph.nodeCount != 11 || graph.maxDepth != 4 {
		t.Fatalf("bounds metadata=(nodes=%d depth=%d) want (11,4)", graph.nodeCount, graph.maxDepth)
	}
	if !graph.nodesByName["bulk-inner"].flattened || !graph.nodesByName["fast-inner"].flattened {
		t.Fatal("same-kind groups were not recorded as flattened")
	}
	if got := targetGraphChildNames(graph.nodesByName["bulk"]); strings.Join(got, ",") != "bulk-a,bulk-b,bulk-c" {
		t.Fatalf("flattened bond children=%v", got)
	}
	if got := targetGraphChildNames(graph.nodesByName["fast"]); strings.Join(got, ",") != "fast-a,fast-b" {
		t.Fatalf("flattened race children=%v", got)
	}
}

func TestCompileTargetGraphCanonicalDeterminism(t *testing.T) {
	makeRoot := func(opts map[string]string, peak []string) Target {
		return Selector("root", []Target{
			Path("a", PathSpec{Transport: "tcp", Address: "a", Opts: opts}),
			Bond("bulk", []Target{Path("b", PathSpec{Transport: "tcp", Address: "b"})}),
		}, PeakTransfer{Targets: peak})
	}
	first, err := compileTargetGraph(makeRoot(
		map[string]string{"two": "2", "one": "1"},
		[]string{"bulk", "a"},
	))
	if err != nil {
		t.Fatal(err)
	}
	second, err := compileTargetGraph(makeRoot(
		map[string]string{"one": "1", "two": "2", "name": "a"},
		[]string{"a", "bulk"},
	))
	if err != nil {
		t.Fatal(err)
	}
	if string(first.canonical) != string(second.canonical) || first.digest != second.digest {
		t.Fatalf("equivalent graphs differ\nfirst:  %s\nsecond: %s", first.canonical, second.canonical)
	}

	reordered, err := compileTargetGraph(Selector("root", []Target{
		Bond("bulk", []Target{Path("b", PathSpec{Transport: "tcp", Address: "b"})}),
		Path("a", PathSpec{Transport: "tcp", Address: "a", Opts: map[string]string{"one": "1", "two": "2"}}),
	}, PeakTransfer{Targets: []string{"a", "bulk"}}))
	if err != nil {
		t.Fatal(err)
	}
	if first.digest == reordered.digest {
		t.Fatal("child order did not affect graph digest")
	}
}

func TestCompileTargetGraphPreservesNestedSelectors(t *testing.T) {
	nested, err := compileTargetGraph(Selector("outer", []Target{
		Selector("inner", []Target{Path("a", PathSpec{Transport: "tcp", Address: "a"})}),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := nested.root.children[0]; got.kind != TargetKindSelector || got.name != "inner" || got.flattened {
		t.Fatalf("nested selector was changed: %+v", got)
	}
	flat, err := compileTargetGraph(Selector("outer", []Target{
		Path("a", PathSpec{Transport: "tcp", Address: "a"}),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if nested.digest == flat.digest {
		t.Fatal("selector/selector and flat selector have the same digest")
	}
}

func TestCompileTargetGraphRejectsInvalidGraphs(t *testing.T) {
	var nilPath *PathTarget
	var nilGroup *GroupTarget
	cycle := &GroupTarget{TargetName: "cycle", Kind: TargetKindSelector}
	cycle.Children = []Target{cycle}

	tests := []struct {
		name string
		root Target
		want string
	}{
		{name: "nil", root: nil, want: "nil target"},
		{name: "typed nil path", root: nilPath, want: "nil target"},
		{name: "typed nil group", root: nilGroup, want: "nil target"},
		{name: "cycle", root: cycle, want: "cycle"},
		{name: "empty path name", root: Path("", PathSpec{}), want: "target name is empty"},
		{name: "empty group name", root: Selector("", []Target{Path("a", PathSpec{})}), want: "target name is empty"},
		{name: "duplicate name", root: Selector("root", []Target{Path("a", PathSpec{}), Path("a", PathSpec{})}), want: "duplicate target name"},
		{name: "empty group", root: Selector("root", nil), want: "group target has no children"},
		{name: "unknown kind", root: GroupTarget{TargetName: "root", Kind: "other", Children: []Target{Path("a", PathSpec{})}}, want: "unknown target kind"},
		{name: "peak on bond", root: GroupTarget{TargetName: "root", Kind: TargetKindBond, Children: []Target{Path("a", PathSpec{})}, Peak: &PeakTransfer{Targets: []string{"a"}}}, want: "only valid on selector"},
		{name: "duplicate peak", root: Selector("root", []Target{Path("a", PathSpec{})}, PeakTransfer{Targets: []string{"a", "a"}}), want: "duplicate PeakTransfer reference"},
		{name: "unknown peak", root: Selector("root", []Target{Path("a", PathSpec{})}, PeakTransfer{Targets: []string{"missing"}}), want: "unknown PeakTransfer reference"},
		{name: "non-immediate peak", root: Selector("root", []Target{Bond("bulk", []Target{Path("a", PathSpec{})})}, PeakTransfer{Targets: []string{"a"}}), want: "unknown PeakTransfer reference"},
		{name: "conflicting path name", root: Path("a", PathSpec{Opts: map[string]string{"name": "b"}}), want: "conflicts with PathSpec option name"},
		{name: "too deep", root: targetGraphAtDepth(targetGraphMaxDepth + 1), want: "depth exceeds"},
		{name: "too many nodes", root: targetGraphWithNodes(targetGraphMaxNodes + 1), want: "node count exceeds"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := compileTargetGraph(test.root)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want substring %q", err, test.want)
			}
		})
	}
}

func TestCompileTargetGraphAcceptsBounds(t *testing.T) {
	depthGraph, err := compileTargetGraph(targetGraphAtDepth(targetGraphMaxDepth))
	if err != nil {
		t.Fatalf("depth boundary rejected: %v", err)
	}
	if depthGraph.maxDepth != targetGraphMaxDepth {
		t.Fatalf("maxDepth=%d want %d", depthGraph.maxDepth, targetGraphMaxDepth)
	}

	nodeGraph, err := compileTargetGraph(targetGraphWithNodes(targetGraphMaxNodes))
	if err != nil {
		t.Fatalf("node boundary rejected: %v", err)
	}
	if nodeGraph.nodeCount != targetGraphMaxNodes {
		t.Fatalf("nodeCount=%d want %d", nodeGraph.nodeCount, targetGraphMaxNodes)
	}
}

func TestCompileTargetGraphOwnsSnapshot(t *testing.T) {
	opts := map[string]string{"alpn": "rendr"}
	peakTargets := []string{"a"}
	graph, err := compileTargetGraph(Selector("root", []Target{
		Path("a", PathSpec{Transport: "tcp", Opts: opts}),
	}, PeakTransfer{Targets: peakTargets}))
	if err != nil {
		t.Fatal(err)
	}
	wantCanonical := string(graph.canonical)
	wantDigest := graph.digest

	opts["alpn"] = "changed"
	peakTargets[0] = "changed"
	if string(graph.canonical) != wantCanonical || graph.digest != wantDigest {
		t.Fatal("compiled graph changed after caller mutation")
	}
	if got := graph.nodesByName["a"].path.Opts["alpn"]; got != "rendr" {
		t.Fatalf("compiled path option=%q want rendr", got)
	}
	if got := graph.root.peak.Targets[0]; got != "a" {
		t.Fatalf("compiled peak target=%q want a", got)
	}
}

func targetGraphChildNames(node *targetGraphNode) []string {
	names := make([]string, 0, len(node.children))
	for _, child := range node.children {
		names = append(names, child.name)
	}
	return names
}

func targetGraphAtDepth(depth int) Target {
	var target Target = Path("leaf", PathSpec{Transport: "tcp"})
	for current := 2; current <= depth; current++ {
		target = Selector("level-"+strings.Repeat("x", current), []Target{target})
	}
	return target
}

func targetGraphWithNodes(nodes int) Target {
	children := make([]Target, 0, nodes-1)
	for i := 0; i < nodes-1; i++ {
		children = append(children, Path("path-"+strconv.Itoa(i), PathSpec{Transport: "tcp"}))
	}
	return Selector("root", children)
}
