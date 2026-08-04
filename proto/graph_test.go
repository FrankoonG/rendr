package proto

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

func graphTestNode(kind GraphNodeKind, name string, children ...TargetID) GraphNode {
	return GraphNode{
		ID:       DeriveTargetID(kind, name),
		Kind:     kind,
		Name:     name,
		Children: children,
	}
}

func graphTestManifest() GraphManifest {
	a := graphTestNode(GraphNodeKindPath, "a")
	a.Weight = 3
	b := graphTestNode(GraphNodeKindPath, "b")
	c := graphTestNode(GraphNodeKindPath, "c")
	bulk := graphTestNode(GraphNodeKindBond, "bulk", b.ID, c.ID)
	root := graphTestNode(GraphNodeKindSelector, "root", a.ID, bulk.ID)
	root.PeakCandidates = []TargetID{bulk.ID}
	return GraphManifest{
		RootID: root.ID,
		Nodes:  []GraphNode{c, root, a, bulk, b},
	}
}

func TestGraphNodeKindWireValues(t *testing.T) {
	tests := []struct {
		kind GraphNodeKind
		want byte
	}{
		{GraphNodeKindInvalid, 0},
		{GraphNodeKindPath, 1},
		{GraphNodeKindSelector, 2},
		{GraphNodeKindBond, 3},
		{GraphNodeKindRace, 4},
	}
	for _, tc := range tests {
		if byte(tc.kind) != tc.want {
			t.Fatalf("graph kind %s drifted: got %d want %d", tc.kind, tc.kind, tc.want)
		}
	}
	for _, kind := range []GraphNodeKind{GraphNodeKindPath, GraphNodeKindSelector, GraphNodeKindBond, GraphNodeKindRace} {
		if !kind.Valid() {
			t.Fatalf("kind %d should be valid", kind)
		}
	}
	for _, kind := range []GraphNodeKind{GraphNodeKindInvalid, 5, 255} {
		if kind.Valid() {
			t.Fatalf("kind %d should be invalid", kind)
		}
	}
}

func TestDeriveTargetIDStableAndKindBound(t *testing.T) {
	got := DeriveTargetID(GraphNodeKindPath, "edge-a")
	want, err := hex.DecodeString("3681421905153e56c84a1c210984fb00")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:], want) {
		t.Fatalf("target id drifted: got %x want %x", got, want)
	}
	if got == DeriveTargetID(GraphNodeKindSelector, "edge-a") {
		t.Fatal("target id does not bind node kind")
	}
	if got == DeriveTargetID(GraphNodeKindPath, "edge-b") {
		t.Fatal("target id does not bind node name")
	}
}

func TestGraphManifestRoundTripCanonicalAndDigest(t *testing.T) {
	want := graphTestManifest()
	wire, err := want.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeGraphManifest(wire)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := got.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reencoded, wire) {
		t.Fatalf("round trip drift:\n got=%x\nwant=%x", reencoded, wire)
	}
	digest1, err := want.Digest()
	if err != nil {
		t.Fatal(err)
	}
	digest2, err := got.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if digest1 != digest2 {
		t.Fatalf("digest drift: got %x want %x", digest2, digest1)
	}
	for _, forbidden := range [][]byte{[]byte("edge.example:443"), []byte("127.0.0.1"), []byte("secret-option")} {
		if bytes.Contains(wire, forbidden) {
			t.Fatalf("wire contains non-manifest data %q", forbidden)
		}
	}
}

func TestGraphManifestCanonicalizesNodeAndPeakOrder(t *testing.T) {
	base := graphTestManifest()
	wire1, err := base.Encode()
	if err != nil {
		t.Fatal(err)
	}

	reordered := graphTestManifest()
	for left, right := 0, len(reordered.Nodes)-1; left < right; left, right = left+1, right-1 {
		reordered.Nodes[left], reordered.Nodes[right] = reordered.Nodes[right], reordered.Nodes[left]
	}
	root := &reordered.Nodes[0]
	for i := range reordered.Nodes {
		if reordered.Nodes[i].ID == reordered.RootID {
			root = &reordered.Nodes[i]
			break
		}
	}
	root.PeakCandidates = append(root.PeakCandidates, root.Children[0])
	baseRoot := &base.Nodes[0]
	for i := range base.Nodes {
		if base.Nodes[i].ID == base.RootID {
			baseRoot = &base.Nodes[i]
			break
		}
	}
	baseRoot.PeakCandidates = append(baseRoot.PeakCandidates, baseRoot.Children[0])
	root.PeakCandidates[0], root.PeakCandidates[1] = root.PeakCandidates[1], root.PeakCandidates[0]

	wire1, err = base.Encode()
	if err != nil {
		t.Fatal(err)
	}
	wire2, err := reordered.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire1, wire2) {
		t.Fatal("equivalent manifests did not encode identically")
	}
}

func TestGraphManifestPreservesChildOrder(t *testing.T) {
	left := graphTestManifest()
	right := graphTestManifest()
	for i := range right.Nodes {
		if right.Nodes[i].ID == right.RootID {
			right.Nodes[i].Children[0], right.Nodes[i].Children[1] = right.Nodes[i].Children[1], right.Nodes[i].Children[0]
			break
		}
	}
	wireLeft, err := left.Encode()
	if err != nil {
		t.Fatal(err)
	}
	wireRight, err := right.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(wireLeft, wireRight) {
		t.Fatal("semantically significant child order was canonicalized away")
	}
}

func TestGraphManifestValidateRejectsInvalidGraphs(t *testing.T) {
	valid := graphTestManifest()
	path := graphTestNode(GraphNodeKindPath, "path")
	group := graphTestNode(GraphNodeKindSelector, "group", path.ID)

	deep := makeDepthManifest(GraphManifestMaxDepth + 1)
	tooMany := make([]GraphNode, GraphManifestMaxNodes+1)
	for i := range tooMany {
		name := "n" + strings.Repeat("x", i/10) + string(rune('0'+i%10))
		tooMany[i] = graphTestNode(GraphNodeKindPath, name)
	}

	tests := []struct {
		name     string
		manifest GraphManifest
	}{
		{name: "empty", manifest: GraphManifest{}},
		{name: "too many nodes", manifest: GraphManifest{Nodes: tooMany}},
		{name: "missing root", manifest: GraphManifest{RootID: group.ID, Nodes: []GraphNode{path}}},
		{name: "empty name", manifest: GraphManifest{RootID: DeriveTargetID(GraphNodeKindPath, ""), Nodes: []GraphNode{{ID: DeriveTargetID(GraphNodeKindPath, ""), Kind: GraphNodeKindPath}}}},
		{name: "invalid utf8", manifest: singlePathManifest(string([]byte{0xff}))},
		{name: "long name", manifest: singlePathManifest(strings.Repeat("x", GraphManifestMaxNameBytes+1))},
		{name: "invalid kind", manifest: GraphManifest{RootID: DeriveTargetID(99, "x"), Nodes: []GraphNode{{ID: DeriveTargetID(99, "x"), Kind: 99, Name: "x"}}}},
		{name: "id mismatch", manifest: GraphManifest{RootID: path.ID, Nodes: []GraphNode{{ID: path.ID, Kind: GraphNodeKindPath, Name: "other"}}}},
		{name: "duplicate id", manifest: GraphManifest{RootID: path.ID, Nodes: []GraphNode{path, path}}},
		{name: "duplicate name", manifest: GraphManifest{RootID: path.ID, Nodes: []GraphNode{path, {ID: DeriveTargetID(GraphNodeKindSelector, path.Name), Kind: GraphNodeKindSelector, Name: path.Name, Children: []TargetID{path.ID}}}}},
		{name: "dangling child", manifest: GraphManifest{RootID: group.ID, Nodes: []GraphNode{group}}},
		{name: "repeated child", manifest: GraphManifest{RootID: group.ID, Nodes: []GraphNode{{ID: group.ID, Kind: group.Kind, Name: group.Name, Children: []TargetID{path.ID, path.ID}}, path}}},
		{name: "cycle", manifest: cycleManifest()},
		{name: "unreachable", manifest: GraphManifest{RootID: path.ID, Nodes: []GraphNode{path, graphTestNode(GraphNodeKindPath, "other")}}},
		{name: "path children", manifest: GraphManifest{RootID: path.ID, Nodes: []GraphNode{{ID: path.ID, Kind: path.Kind, Name: path.Name, Children: []TargetID{path.ID}}}}},
		{name: "path peaks", manifest: GraphManifest{RootID: path.ID, Nodes: []GraphNode{{ID: path.ID, Kind: path.Kind, Name: path.Name, PeakCandidates: []TargetID{path.ID}}}}},
		{name: "empty group", manifest: GraphManifest{RootID: DeriveTargetID(GraphNodeKindBond, "empty"), Nodes: []GraphNode{graphTestNode(GraphNodeKindBond, "empty")}}},
		{name: "group weight", manifest: GraphManifest{RootID: group.ID, Nodes: []GraphNode{{ID: group.ID, Kind: group.Kind, Name: group.Name, Weight: 1, Children: group.Children}, path}}},
		{name: "peak on race", manifest: nonSelectorPeakManifest()},
		{name: "duplicate peak", manifest: duplicatePeakManifest()},
		{name: "peak not child", manifest: nonChildPeakManifest()},
		{name: "too deep", manifest: deep},
		{name: "wire too large", manifest: oversizedGraphManifest()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.manifest.Validate(); err == nil {
				t.Fatal("accepted invalid graph")
			}
		})
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid graph rejected: %v", err)
	}
	if err := makeDepthManifest(GraphManifestMaxDepth).Validate(); err != nil {
		t.Fatalf("maximum legal depth rejected: %v", err)
	}
}

func TestDecodeGraphManifestRejectsMalformedAndNonCanonicalWire(t *testing.T) {
	valid, err := graphTestManifest().Encode()
	if err != nil {
		t.Fatal(err)
	}

	badMagic := append([]byte(nil), valid...)
	badMagic[0] ^= 0xff
	badVersion := append([]byte(nil), valid...)
	badVersion[4]++
	badReserved := append([]byte(nil), valid...)
	badReserved[5] = 1
	zeroCount := append([]byte(nil), valid...)
	clear(zeroCount[6:8])
	floodNodes := append([]byte(nil), valid...)
	binary.BigEndian.PutUint16(floodNodes[6:8], 0xffff)
	trailing := append(append([]byte(nil), valid...), 0)
	oversized := make([]byte, GraphManifestMaxWireBytes+1)

	single, err := singlePathManifest("x").Encode()
	if err != nil {
		t.Fatal(err)
	}
	zeroName := append([]byte(nil), single...)
	zeroName[graphManifestHeaderSize+17] = 0
	invalidUTF8 := append([]byte(nil), single...)
	invalidUTF8[graphManifestHeaderSize+graphNodeHeaderSize] = 0xff
	floodChildren := append([]byte(nil), single...)
	binary.BigEndian.PutUint16(floodChildren[graphManifestHeaderSize+20:graphManifestHeaderSize+22], 0xffff)
	floodPeaks := append([]byte(nil), single...)
	binary.BigEndian.PutUint16(floodPeaks[graphManifestHeaderSize+22:graphManifestHeaderSize+24], 0xffff)

	nonCanonicalNodes := swapFirstTwoEncodedNodes(t, valid)
	nonCanonicalPeaks := unsortedPeakWire(t)

	tests := []struct {
		name string
		wire []byte
	}{
		{name: "nil", wire: nil},
		{name: "short header", wire: valid[:graphManifestHeaderSize-1]},
		{name: "bad magic", wire: badMagic},
		{name: "bad version", wire: badVersion},
		{name: "reserved", wire: badReserved},
		{name: "zero count", wire: zeroCount},
		{name: "node count flood", wire: floodNodes},
		{name: "truncated node", wire: single[:len(single)-1]},
		{name: "zero name", wire: zeroName},
		{name: "invalid utf8", wire: invalidUTF8},
		{name: "child count flood", wire: floodChildren},
		{name: "peak count flood", wire: floodPeaks},
		{name: "trailing", wire: trailing},
		{name: "oversized", wire: oversized},
		{name: "noncanonical nodes", wire: nonCanonicalNodes},
		{name: "noncanonical peaks", wire: nonCanonicalPeaks},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeGraphManifest(tc.wire); err == nil {
				t.Fatal("accepted malformed graph wire")
			}
		})
	}
}

func FuzzDecodeGraphManifestNeverPanics(f *testing.F) {
	valid, err := graphTestManifest().Encode()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte("RGMF\x01"))
	f.Add(bytes.Repeat([]byte{0xff}, 128))
	f.Fuzz(func(t *testing.T, wire []byte) {
		manifest, err := DecodeGraphManifest(wire)
		if err != nil {
			return
		}
		canonical, err := manifest.Encode()
		if err != nil {
			t.Fatalf("decoded graph cannot re-encode: %v", err)
		}
		if !bytes.Equal(canonical, wire) {
			t.Fatal("decoder accepted noncanonical input")
		}
	})
}

func singlePathManifest(name string) GraphManifest {
	node := graphTestNode(GraphNodeKindPath, name)
	return GraphManifest{RootID: node.ID, Nodes: []GraphNode{node}}
}

func cycleManifest() GraphManifest {
	a := graphTestNode(GraphNodeKindSelector, "a")
	b := graphTestNode(GraphNodeKindSelector, "b")
	a.Children = []TargetID{b.ID}
	b.Children = []TargetID{a.ID}
	return GraphManifest{RootID: a.ID, Nodes: []GraphNode{a, b}}
}

func nonSelectorPeakManifest() GraphManifest {
	path := graphTestNode(GraphNodeKindPath, "path")
	racer := graphTestNode(GraphNodeKindRace, "race", path.ID)
	racer.PeakCandidates = []TargetID{path.ID}
	return GraphManifest{RootID: racer.ID, Nodes: []GraphNode{racer, path}}
}

func duplicatePeakManifest() GraphManifest {
	path := graphTestNode(GraphNodeKindPath, "path")
	selector := graphTestNode(GraphNodeKindSelector, "selector", path.ID)
	selector.PeakCandidates = []TargetID{path.ID, path.ID}
	return GraphManifest{RootID: selector.ID, Nodes: []GraphNode{selector, path}}
}

func nonChildPeakManifest() GraphManifest {
	a := graphTestNode(GraphNodeKindPath, "a")
	b := graphTestNode(GraphNodeKindPath, "b")
	selector := graphTestNode(GraphNodeKindSelector, "selector", a.ID)
	selector.PeakCandidates = []TargetID{b.ID}
	return GraphManifest{RootID: selector.ID, Nodes: []GraphNode{selector, a, b}}
}

func makeDepthManifest(depth int) GraphManifest {
	if depth < 1 {
		return GraphManifest{}
	}
	nodes := make([]GraphNode, depth)
	for i := depth - 1; i >= 0; i-- {
		name := "depth-" + strings.Repeat("x", i)
		if i == depth-1 {
			nodes[i] = graphTestNode(GraphNodeKindPath, name)
		} else {
			nodes[i] = graphTestNode(GraphNodeKindSelector, name, nodes[i+1].ID)
		}
	}
	return GraphManifest{RootID: nodes[0].ID, Nodes: nodes}
}

func oversizedGraphManifest() GraphManifest {
	const groupWidth = 68
	layers := make([][]GraphNode, 16)
	layers[0] = []GraphNode{graphTestNode(GraphNodeKindBond, "wide-root")}
	for level := 1; level < len(layers)-1; level++ {
		layers[level] = make([]GraphNode, groupWidth)
		for i := range layers[level] {
			layers[level][i] = graphTestNode(GraphNodeKindBond, fmt.Sprintf("wide-%d-%d", level, i))
		}
	}
	leafCount := GraphManifestMaxNodes - 1 - groupWidth*(len(layers)-2)
	layers[len(layers)-1] = make([]GraphNode, leafCount)
	for i := range layers[len(layers)-1] {
		layers[len(layers)-1][i] = graphTestNode(GraphNodeKindPath, fmt.Sprintf("wide-leaf-%d", i))
	}
	for level := 0; level < len(layers)-1; level++ {
		children := make([]TargetID, len(layers[level+1]))
		for i := range layers[level+1] {
			children[i] = layers[level+1][i].ID
		}
		for i := range layers[level] {
			layers[level][i].Children = append([]TargetID(nil), children...)
		}
	}
	nodes := make([]GraphNode, 0, GraphManifestMaxNodes)
	for i := range layers {
		nodes = append(nodes, layers[i]...)
	}
	return GraphManifest{RootID: layers[0][0].ID, Nodes: nodes}
}

func swapFirstTwoEncodedNodes(t *testing.T, wire []byte) []byte {
	t.Helper()
	spans := encodedNodeSpans(t, wire)
	if len(spans) < 2 {
		t.Fatal("need two encoded nodes")
	}
	out := append([]byte(nil), wire[:graphManifestHeaderSize]...)
	out = append(out, wire[spans[1][0]:spans[1][1]]...)
	out = append(out, wire[spans[0][0]:spans[0][1]]...)
	for _, span := range spans[2:] {
		out = append(out, wire[span[0]:span[1]]...)
	}
	return out
}

func encodedNodeSpans(t *testing.T, wire []byte) [][2]int {
	t.Helper()
	count := int(binary.BigEndian.Uint16(wire[6:8]))
	spans := make([][2]int, 0, count)
	offset := graphManifestHeaderSize
	for i := 0; i < count; i++ {
		start := offset
		header := wire[offset : offset+graphNodeHeaderSize]
		offset += graphNodeHeaderSize
		offset += int(header[17])
		offset += 16 * (int(binary.BigEndian.Uint16(header[20:22])) + int(binary.BigEndian.Uint16(header[22:24])))
		spans = append(spans, [2]int{start, offset})
	}
	return spans
}

func unsortedPeakWire(t *testing.T) []byte {
	t.Helper()
	manifest := graphTestManifest()
	for i := range manifest.Nodes {
		if manifest.Nodes[i].ID == manifest.RootID {
			manifest.Nodes[i].PeakCandidates = append(manifest.Nodes[i].PeakCandidates, manifest.Nodes[i].Children[0])
			break
		}
	}
	wire, err := manifest.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, span := range encodedNodeSpans(t, wire) {
		header := wire[span[0] : span[0]+graphNodeHeaderSize]
		peakCount := int(binary.BigEndian.Uint16(header[22:24]))
		if peakCount != 2 {
			continue
		}
		nameLen := int(header[17])
		childCount := int(binary.BigEndian.Uint16(header[20:22]))
		peaksAt := span[0] + graphNodeHeaderSize + nameLen + childCount*16
		first := append([]byte(nil), wire[peaksAt:peaksAt+16]...)
		copy(wire[peaksAt:peaksAt+16], wire[peaksAt+16:peaksAt+32])
		copy(wire[peaksAt+16:peaksAt+32], first)
		return wire
	}
	t.Fatal("selector with two peaks not found")
	return nil
}

func TestGraphNameUTF8Boundary(t *testing.T) {
	name := strings.Repeat("a", GraphManifestMaxNameBytes)
	if !utf8.ValidString(name) {
		t.Fatal("test fixture is invalid UTF-8")
	}
	manifest := singlePathManifest(name)
	wire, err := manifest.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeGraphManifest(wire); err != nil {
		t.Fatalf("maximum name length rejected: %v", err)
	}
}
