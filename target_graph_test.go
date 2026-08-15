package rendr

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
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
	})

	graph, err := compileTargetGraph(root)
	if err != nil {
		t.Fatal(err)
	}
	const wantCanonical = `{"version":1,"root":{"kind":"selector","name":"root","peak":{"targets":["bulk","fast"],"saturation_ratio_bits":4605380978949069210,"saturation_for_ns":2000000000,"return_ratio_bits":4602678819172646912,"return_for_ns":3000000000},"children":[{"kind":"path","name":"primary","path":{"carrier":"tcp","address":"edge.example:443","local":"source-a","weight":7,"options":[{"key":"alpn","value":"rendr"},{"key":"name","value":"primary"},{"key":"zeta","value":"last"}]}},{"kind":"bond","name":"bulk","children":[{"kind":"path","name":"bulk-a","path":{"carrier":"quic","address":"bulk-a.example:443","local":"","weight":0,"options":[{"key":"name","value":"bulk-a"}]}},{"kind":"path","name":"bulk-b","path":{"carrier":"tcp","address":"bulk-b.example:443","local":"","weight":2,"options":[{"key":"name","value":"bulk-b"}]}},{"kind":"path","name":"bulk-c","path":{"carrier":"tcp","address":"bulk-c.example:443","local":"","weight":3,"options":[{"key":"name","value":"bulk-c"}]}}]},{"kind":"race","name":"fast","children":[{"kind":"path","name":"fast-a","path":{"carrier":"udp","address":"fast-a.example:443","local":"","weight":0,"options":[{"key":"name","value":"fast-a"}]}},{"kind":"path","name":"fast-b","path":{"carrier":"udp","address":"fast-b.example:443","local":"","weight":0,"options":[{"key":"name","value":"fast-b"}]}}]}]},"flattened":[{"kind":"bond","name":"bulk-inner"},{"kind":"race","name":"fast-inner"}]}`
	if got := string(graph.canonical); got != wantCanonical {
		t.Fatalf("canonical graph mismatch\n got: %s\nwant: %s", got, wantCanonical)
	}
	const wantLocalDigest = "de06385e9b3658b4727c98342f31942ff264eeadeb2db45376e6bfc7115b7689"
	if got := hex.EncodeToString(graph.localDigest[:]); got != wantLocalDigest {
		t.Fatalf("local digest=%s want %s", got, wantLocalDigest)
	}
	const wantManifestDigest = "b584dfdcdd53fc875adee3ad9ecd95ffb0406de7872f16a12e129a07444088dd"
	if got := hex.EncodeToString(graph.digest[:]); got != wantManifestDigest {
		t.Fatalf("manifest digest=%s want %s", got, wantManifestDigest)
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

	if err := graph.manifest.Validate(); err != nil {
		t.Fatalf("manifest validation: %v", err)
	}
	calculatedDigest, err := graph.manifest.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if graph.digest != calculatedDigest {
		t.Fatalf("session digest=%x manifest digest=%x", graph.digest, calculatedDigest)
	}
	if graph.manifest.RootID != proto.DeriveTargetID(proto.GraphNodeKindSelector, "root") {
		t.Fatalf("root id=%x", graph.manifest.RootID)
	}
	if len(graph.manifest.Nodes) != 9 || len(graph.nodesByID) != 9 || len(graph.leafIDs) != 6 {
		t.Fatalf("wire metadata=(nodes=%d indexed=%d leaves=%d) want (9,9,6)", len(graph.manifest.Nodes), len(graph.nodesByID), len(graph.leafIDs))
	}
	for _, flattened := range []struct {
		kind proto.GraphNodeKind
		name string
	}{
		{kind: proto.GraphNodeKindBond, name: "bulk-inner"},
		{kind: proto.GraphNodeKindRace, name: "fast-inner"},
	} {
		if _, exists := graph.nodesByID[proto.DeriveTargetID(flattened.kind, flattened.name)]; exists {
			t.Fatalf("flattened target %q entered wire manifest", flattened.name)
		}
	}
	for name, weight := range map[string]uint16{"primary": 7, "bulk-b": 2, "bulk-c": 3} {
		node := manifestNodeByName(t, graph.manifest, name)
		if node.Weight != weight {
			t.Fatalf("manifest path %q weight=%d want %d", name, node.Weight, weight)
		}
		if indexed := graph.nodesByID[node.ID]; indexed == nil || indexed.name != name {
			t.Fatalf("manifest path %q is not indexed by id", name)
		}
		if _, leaf := graph.leafIDs[node.ID]; !leaf {
			t.Fatalf("manifest path %q is not in leaf membership", name)
		}
	}
	rootNode := manifestNodeByName(t, graph.manifest, "root")
	if got := manifestTargetNames(graph, rootNode.Children); strings.Join(got, ",") != "primary,bulk,fast" {
		t.Fatalf("manifest root children=%v", got)
	}
	if got := manifestTargetNames(graph, rootNode.PeakCandidates); !sameStrings(got, []string{"bulk", "fast"}) {
		t.Fatalf("manifest root peak candidates=%v", got)
	}
	wire, err := graph.manifest.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, localOnly := range []string{"edge.example:443", "source-a", "rendr", "zeta"} {
		if bytes.Contains(wire, []byte(localOnly)) {
			t.Fatalf("local-only value %q entered wire manifest", localOnly)
		}
	}
}

func TestResolveSelectorChildSelectsNestedGroupAsOneTarget(t *testing.T) {
	graph, err := compileTargetGraph(Selector("root", []Target{
		Path("A", PathSpec{}),
		Bond("bulk", []Target{
			Path("B", PathSpec{}),
			Path("C", PathSpec{}),
		}),
	}))
	if err != nil {
		t.Fatal(err)
	}

	selectorID, targetID, err := graph.resolveSelectorChild("root", "bulk")
	if err != nil {
		t.Fatalf("select bond group: %v", err)
	}
	if selectorID != proto.DeriveTargetID(proto.GraphNodeKindSelector, "root") {
		t.Fatalf("selector id=%x", selectorID)
	}
	if targetID != proto.DeriveTargetID(proto.GraphNodeKindBond, "bulk") {
		t.Fatalf("target id=%x; bond group was not selected as one target", targetID)
	}
	if _, _, err := graph.resolveSelectorChild("root", "B"); err == nil || !strings.Contains(err.Error(), "not an immediate child") {
		t.Fatalf("nested leaf selection error=%v", err)
	}
	if _, _, err := graph.resolveSelectorChild("bulk", "B"); err == nil || !strings.Contains(err.Error(), "not a selector") {
		t.Fatalf("non-selector selection error=%v", err)
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
	if string(first.canonical) != string(second.canonical) || first.localDigest != second.localDigest || first.digest != second.digest {
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

func TestCompileTargetGraphWireManifestExcludesLocalConfiguration(t *testing.T) {
	first, err := compileTargetGraph(Selector("root", []Target{
		Path("a", PathSpec{
			Transport: "tcp",
			Address:   "first.example:443",
			Local:     "source-a",
			Weight:    3,
			Opts:      map[string]string{"credential": "first", "alpn": "one"},
		}),
	}, PeakTransfer{Targets: []string{"a"}, SaturationRatio: 0.8, SaturationFor: time.Second}))
	if err != nil {
		t.Fatal(err)
	}
	second, err := compileTargetGraph(Selector("root", []Target{
		Path("a", PathSpec{
			Transport: "quic",
			Address:   "second.example:8443",
			Local:     "source-b",
			Weight:    3,
			Opts:      map[string]string{"credential": "second", "alpn": "two"},
		}),
	}, PeakTransfer{Targets: []string{"a"}, SaturationRatio: 0.95, SaturationFor: 20 * time.Second}))
	if err != nil {
		t.Fatal(err)
	}
	if first.digest != second.digest {
		t.Fatalf("local configuration changed session graph digest: %x != %x", first.digest, second.digest)
	}
	if first.localDigest == second.localDigest || bytes.Equal(first.canonical, second.canonical) {
		t.Fatal("distinct local configuration did not change local snapshot")
	}

	changedWeight, err := compileTargetGraph(Selector("root", []Target{
		Path("a", PathSpec{Transport: "tcp", Weight: 4}),
	}, PeakTransfer{Targets: []string{"a"}}))
	if err != nil {
		t.Fatal(err)
	}
	if first.digest == changedWeight.digest {
		t.Fatal("path weight did not change session graph digest")
	}
}

func TestCompileTargetGraphSameModeNormalizationHasStableManifest(t *testing.T) {
	tests := []struct {
		name   string
		nested Target
		flat   Target
	}{
		{
			name: "bond",
			nested: Bond("root", []Target{
				Path("a", PathSpec{Weight: 1}),
				Bond("absorbed", []Target{Path("b", PathSpec{Weight: 2}), Path("c", PathSpec{Weight: 3})}),
			}),
			flat: Bond("root", []Target{
				Path("a", PathSpec{Weight: 1}),
				Path("b", PathSpec{Weight: 2}),
				Path("c", PathSpec{Weight: 3}),
			}),
		},
		{
			name: "race",
			nested: Race("root", []Target{
				Race("absorbed", []Target{Path("a", PathSpec{}), Path("b", PathSpec{})}),
				Path("c", PathSpec{}),
			}),
			flat: Race("root", []Target{
				Path("a", PathSpec{}),
				Path("b", PathSpec{}),
				Path("c", PathSpec{}),
			}),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			nested, err := compileTargetGraph(test.nested)
			if err != nil {
				t.Fatal(err)
			}
			flat, err := compileTargetGraph(test.flat)
			if err != nil {
				t.Fatal(err)
			}
			if nested.digest != flat.digest {
				t.Fatalf("equivalent normalized manifests differ: %x != %x", nested.digest, flat.digest)
			}
			nestedWire, err := nested.manifest.Encode()
			if err != nil {
				t.Fatal(err)
			}
			flatWire, err := flat.manifest.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(nestedWire, flatWire) {
				t.Fatalf("equivalent normalized manifest bytes differ\nnested: %x\nflat:   %x", nestedWire, flatWire)
			}
			if bytes.Equal(nested.canonical, flat.canonical) || nested.localDigest == flat.localDigest {
				t.Fatal("local snapshot lost absorbed group identity")
			}
			absorbedKind, err := graphNodeKind(nested.nodesByName["absorbed"].kind)
			if err != nil {
				t.Fatal(err)
			}
			if _, exists := nested.nodesByID[proto.DeriveTargetID(absorbedKind, "absorbed")]; exists {
				t.Fatal("absorbed group identity entered manifest index")
			}
		})
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

func TestCompileTargetGraphRejectsNonRootPeakTransfer(t *testing.T) {
	peakSelector := func(name, path string) Target {
		return Selector(name, []Target{Path(path, PathSpec{})}, PeakTransfer{Targets: []string{path}})
	}
	tests := []struct {
		name string
		root Target
		want string
	}{
		{
			name: "selector ancestor",
			root: Selector("root-selector", []Target{peakSelector("offending-selector", "a")}),
			want: `rendr: PeakTransfer selector "offending-selector" must be the target graph root`,
		},
		{
			name: "bond ancestor",
			root: Bond("root-bond", []Target{peakSelector("offending-selector", "a")}),
			want: `rendr: PeakTransfer selector "offending-selector" must be the target graph root`,
		},
		{
			name: "race ancestor",
			root: Race("root-race", []Target{peakSelector("offending-selector", "a")}),
			want: `rendr: PeakTransfer selector "offending-selector" must be the target graph root`,
		},
		{
			name: "root and descendant policies",
			root: Selector("root-selector", []Target{
				Path("normal", PathSpec{}),
				peakSelector("descendant-selector", "descendant-peak"),
			}, PeakTransfer{Targets: []string{"descendant-selector"}}),
			want: `rendr: PeakTransfer selector "descendant-selector" must be the target graph root`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := compileTargetGraph(test.root)
			if err == nil || err.Error() != test.want {
				t.Fatalf("error=%v want %q", err, test.want)
			}
		})
	}
}

func TestNonRootPeakTransferFailsBeforeDialing(t *testing.T) {
	const factoryName = "counting"
	calls := 0
	dialer := sessionDialer{
		Root: Bond("root", []Target{
			Selector("offending-selector", []Target{
				Path("leaf", PathSpec{Transport: factoryName}),
			}, PeakTransfer{Targets: []string{"leaf"}}),
		}),
		streamFactories: map[string]streamPathFactory{
			factoryName: func(context.Context, string) (net.Conn, error) {
				calls++
				return nil, errors.New("factory must not be called")
			},
		},
	}

	_, err := dialer.Dial(context.Background())
	want := `rendr: invalid SessionConfig: rendr: PeakTransfer selector "offending-selector" must be the target graph root`
	if err == nil || err.Error() != want {
		t.Fatalf("error=%v want %q", err, want)
	}
	if calls != 0 {
		t.Fatalf("factory calls=%d want 0", calls)
	}
}

func TestCompileTargetGraphAcceptsRootPeakTransferWithRecursiveChildren(t *testing.T) {
	root := Selector("root", []Target{
		Race("normal", []Target{
			Selector("normal-selector", []Target{
				Bond("normal-bond", []Target{Path("normal-a", PathSpec{}), Path("normal-b", PathSpec{})}),
			}),
		}),
		Bond("peak", []Target{
			Race("peak-race", []Target{
				Selector("peak-selector", []Target{Path("peak-a", PathSpec{}), Path("peak-b", PathSpec{})}),
			}),
		}),
	}, PeakTransfer{Targets: []string{"peak"}})

	graph, err := compileTargetGraph(root)
	if err != nil {
		t.Fatalf("compile valid root PeakTransfer graph: %v", err)
	}
	plan, err := graph.compileDialPlan()
	if err != nil {
		t.Fatalf("compile valid root PeakTransfer dial plan: %v", err)
	}
	got := make(map[string]bool, len(plan.paths))
	for i, path := range plan.paths {
		got[pathSpecName(path)] = plan.pathPeak[i]
	}
	want := map[string]bool{
		"normal-a": false,
		"normal-b": false,
		"peak-a":   true,
		"peak-b":   true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("path peak placement=%v want %v", got, want)
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
		{name: "invalid utf8 name", root: Path(string([]byte{0xff}), PathSpec{}), want: "valid UTF-8"},
		{name: "overlong name", root: Path(strings.Repeat("n", proto.GraphManifestMaxNameBytes+1), PathSpec{}), want: "maximum"},
		{name: "too deep", root: targetGraphAtDepth(targetGraphMaxDepth + 1), want: "depth exceeds"},
		{name: "manifest too large", root: targetGraphWithNodes(800), want: "wire size exceeds"},
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

	const acceptedNodes = 512
	nodeGraph, err := compileTargetGraph(targetGraphWithNodes(acceptedNodes))
	if err != nil {
		t.Fatalf("node boundary rejected: %v", err)
	}
	if nodeGraph.nodeCount != acceptedNodes || len(nodeGraph.manifest.Nodes) != acceptedNodes {
		t.Fatalf("nodeCount=(local=%d manifest=%d) want %d", nodeGraph.nodeCount, len(nodeGraph.manifest.Nodes), acceptedNodes)
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
	wantManifest, err := graph.manifest.Encode()
	if err != nil {
		t.Fatal(err)
	}
	wantLocalDigest := graph.localDigest
	wantDigest := graph.digest

	opts["alpn"] = "changed"
	peakTargets[0] = "changed"
	gotManifest, err := graph.manifest.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if string(graph.canonical) != wantCanonical || graph.localDigest != wantLocalDigest || graph.digest != wantDigest || !bytes.Equal(gotManifest, wantManifest) {
		t.Fatal("compiled graph changed after caller mutation")
	}
	if got := graph.nodesByName["a"].path.Opts["alpn"]; got != "rendr" {
		t.Fatalf("compiled path option=%q want rendr", got)
	}
	if got := graph.root.peak.Targets[0]; got != "a" {
		t.Fatalf("compiled peak target=%q want a", got)
	}
}

func manifestNodeByName(t *testing.T, manifest proto.GraphManifest, name string) proto.GraphNode {
	t.Helper()
	for _, node := range manifest.Nodes {
		if node.Name == name {
			return node
		}
	}
	t.Fatalf("manifest node %q not found", name)
	return proto.GraphNode{}
}

func manifestTargetNames(graph compiledTargetGraph, ids []proto.TargetID) []string {
	names := make([]string, 0, len(ids))
	for _, id := range ids {
		if node := graph.nodesByID[id]; node != nil {
			names = append(names, node.name)
		}
	}
	return names
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	got = append([]string(nil), got...)
	want = append([]string(nil), want...)
	sort.Strings(got)
	sort.Strings(want)
	return slices.Equal(got, want)
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
