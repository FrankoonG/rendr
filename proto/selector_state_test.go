package proto

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"sort"
	"testing"
)

func nestedSelectorStateFixture(t testing.TB) (GraphManifest, GraphBinding, SelectorStatePayload) {
	t.Helper()
	normal := graphTestNode(GraphNodeKindPath, "selector-state-normal")
	bulk := graphTestNode(GraphNodeKindPath, "selector-state-bulk")
	fastA := graphTestNode(GraphNodeKindPath, "selector-state-fast-a")
	fastB := graphTestNode(GraphNodeKindPath, "selector-state-fast-b")
	inner := graphTestNode(GraphNodeKindSelector, "selector-state-inner")
	inner.Children = []TargetID{fastA.ID, fastB.ID}
	inner.PeakCandidates = []TargetID{fastB.ID}
	bond := graphTestNode(GraphNodeKindBond, "selector-state-bond")
	bond.Children = []TargetID{inner.ID, bulk.ID}
	root := graphTestNode(GraphNodeKindSelector, "selector-state-root")
	root.Children = []TargetID{normal.ID, bond.ID}
	root.PeakCandidates = []TargetID{bond.ID}
	manifest := GraphManifest{
		RootID: root.ID,
		Nodes:  []GraphNode{fastB, bond, normal, root, bulk, inner, fastA},
	}
	digest, err := manifest.Digest()
	if err != nil {
		t.Fatal(err)
	}
	binding := GraphBinding{Revision: 7, Digest: digest}
	entries := []SelectorStateEntry{
		{
			SelectorID: root.ID, DesiredTargetID: bond.ID,
			EffectiveTargetID: normal.ID, Generation: 11,
		},
		{
			SelectorID: inner.ID, DesiredTargetID: fastB.ID,
			EffectiveTargetID: fastA.ID, Generation: 13,
		},
	}
	sort.Slice(entries, func(i, j int) bool {
		return bytes.Compare(entries[i].SelectorID[:], entries[j].SelectorID[:]) < 0
	})
	payload := SelectorStatePayload{
		SessionEpoch:  SessionEpoch{1, 2, 3, 4},
		Direction:     SenderDirectionClientToServer,
		GraphRevision: binding.Revision,
		GraphDigest:   binding.Digest,
		StateEpoch:    19,
		Entries:       entries,
	}
	return manifest, binding, payload
}

func TestSelectorStateNestedRoundTripAndWireLayout(t *testing.T) {
	manifest, binding, want := nestedSelectorStateFixture(t)
	wire, err := EncodeSelectorState(want, manifest, binding)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != SelectorStateHeaderSize+len(want.Entries)*SelectorStateEntrySize {
		t.Fatalf("wire length=%d", len(wire))
	}
	if wire[0] != SelectorStateVersion || wire[1] != byte(want.Direction) ||
		binary.BigEndian.Uint64(wire[4:12]) != want.GraphRevision ||
		binary.BigEndian.Uint64(wire[60:68]) != want.StateEpoch ||
		binary.BigEndian.Uint16(wire[68:70]) != uint16(len(want.Entries)) {
		t.Fatalf("wire header drift: %x", wire[:SelectorStateHeaderSize])
	}
	if !bytes.Equal(wire[12:44], want.GraphDigest[:]) || !bytes.Equal(wire[44:60], want.SessionEpoch[:]) {
		t.Fatal("wire binding drift")
	}
	got, err := DecodeSelectorState(wire, manifest, binding)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip\n got: %#v\nwant: %#v", got, want)
	}
	second, err := EncodeSelectorState(got, manifest, binding)
	if err != nil || !bytes.Equal(second, wire) {
		t.Fatalf("non-deterministic re-encode: err=%v", err)
	}
}

func TestSelectorStateControlSurfaceIsCanonical(t *testing.T) {
	if ProtocolMinor != 22 {
		t.Fatalf("protocol minor=%d want=22", ProtocolMinor)
	}
	if CtrlSelectorState != 0x16 || CtrlSelectorState.String() != "SELECTOR_STATE" {
		t.Fatalf("selector state control=0x%02x/%q", byte(CtrlSelectorState), CtrlSelectorState)
	}
	if FeatureSelectorStateVector != 1<<24 ||
		SupportedFeatures&FeatureSelectorStateVector == 0 ||
		RequiredFeatures&FeatureSelectorStateVector == 0 {
		t.Fatal("selector state vector feature is not stable and mandatory")
	}
	if err := ValidateSelectorStateCtrlFlags(FlagsForCtrl(CtrlSelectorState)); err != nil {
		t.Fatalf("canonical selector state flags rejected: %v", err)
	}
	for _, reserved := range []uint16{1 << 8, 1 << 9, 1 << 10, 1 << 11} {
		if err := ValidateSelectorStateCtrlFlags(FlagsForCtrl(CtrlSelectorState) | reserved); err == nil {
			t.Fatalf("reserved selector state flag 0x%03x accepted", reserved)
		}
	}
	if err := ValidateSelectorStateCtrlFlags(FlagsForCtrl(CtrlPolicyPrepare)); err == nil {
		t.Fatal("non-selector-state control accepted")
	}
}

func TestSelectorStateRejectsNonCanonicalOrIncompleteVectors(t *testing.T) {
	manifest, binding, base := nestedSelectorStateFixture(t)
	unknown := DeriveTargetID(GraphNodeKindSelector, "selector-state-unknown")
	tests := []struct {
		name   string
		mutate func(*SelectorStatePayload)
	}{
		{"permuted", func(p *SelectorStatePayload) { p.Entries[0], p.Entries[1] = p.Entries[1], p.Entries[0] }},
		{"missing", func(p *SelectorStatePayload) { p.Entries = p.Entries[:1] }},
		{"duplicate", func(p *SelectorStatePayload) { p.Entries[1] = p.Entries[0] }},
		{"unknown selector", func(p *SelectorStatePayload) { p.Entries[0].SelectorID = unknown }},
		{"wrong desired child", func(p *SelectorStatePayload) { p.Entries[0].DesiredTargetID = unknown }},
		{"wrong effective child", func(p *SelectorStatePayload) { p.Entries[0].EffectiveTargetID = unknown }},
		{"zero selector", func(p *SelectorStatePayload) { p.Entries[0].SelectorID = TargetID{} }},
		{"zero desired", func(p *SelectorStatePayload) { p.Entries[0].DesiredTargetID = TargetID{} }},
		{"zero effective", func(p *SelectorStatePayload) { p.Entries[0].EffectiveTargetID = TargetID{} }},
		{"zero generation", func(p *SelectorStatePayload) { p.Entries[0].Generation = 0 }},
		{"zero state epoch", func(p *SelectorStatePayload) { p.StateEpoch = 0 }},
		{"zero session epoch", func(p *SelectorStatePayload) { p.SessionEpoch = SessionEpoch{} }},
		{"bad direction", func(p *SelectorStatePayload) { p.Direction = SenderDirection(99) }},
		{"wrong revision", func(p *SelectorStatePayload) { p.GraphRevision++ }},
		{"wrong digest", func(p *SelectorStatePayload) { p.GraphDigest[0]++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := base
			payload.Entries = append([]SelectorStateEntry(nil), base.Entries...)
			test.mutate(&payload)
			if _, err := EncodeSelectorState(payload, manifest, binding); err == nil {
				t.Fatal("accepted invalid selector state")
			}
		})
	}
}

func TestSelectorStateRejectsWrongManifestBinding(t *testing.T) {
	manifest, binding, payload := nestedSelectorStateFixture(t)
	other := singlePathManifest("selector-state-other")
	if _, err := EncodeSelectorState(payload, other, binding); err == nil {
		t.Fatal("accepted manifest/binding mismatch")
	}
	badBinding := binding
	badBinding.Digest[0]++
	if _, err := EncodeSelectorState(payload, manifest, badBinding); err == nil {
		t.Fatal("accepted foreign binding")
	}
	badBinding = binding
	badBinding.Revision = 0
	if _, err := EncodeSelectorState(payload, manifest, badBinding); err == nil {
		t.Fatal("accepted zero binding revision")
	}
}

func TestDecodeSelectorStateRejectsMalformedWire(t *testing.T) {
	manifest, binding, payload := nestedSelectorStateFixture(t)
	base, err := EncodeSelectorState(payload, manifest, binding)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		wire   func() []byte
		mutate func([]byte)
	}{
		{"empty", func() []byte { return nil }, nil},
		{"truncated header", func() []byte { return append([]byte(nil), base[:SelectorStateHeaderSize-1]...) }, nil},
		{"truncated entry", func() []byte { return append([]byte(nil), base[:len(base)-1]...) }, nil},
		{"trailing", func() []byte { return append(append([]byte(nil), base...), 0) }, nil},
		{"bad version", func() []byte { return append([]byte(nil), base...) }, func(b []byte) { b[0]++ }},
		{"reserved header", func() []byte { return append([]byte(nil), base...) }, func(b []byte) { b[2] = 1 }},
		{"reserved tail", func() []byte { return append([]byte(nil), base...) }, func(b []byte) { b[71] = 1 }},
		{"wrong count", func() []byte { return append([]byte(nil), base...) }, func(b []byte) { binary.BigEndian.PutUint16(b[68:70], 1) }},
		{"noncanonical entries", func() []byte {
			wire := append([]byte(nil), base...)
			first := append([]byte(nil), wire[SelectorStateHeaderSize:SelectorStateHeaderSize+SelectorStateEntrySize]...)
			copy(wire[SelectorStateHeaderSize:SelectorStateHeaderSize+SelectorStateEntrySize], wire[SelectorStateHeaderSize+SelectorStateEntrySize:])
			copy(wire[SelectorStateHeaderSize+SelectorStateEntrySize:], first)
			return wire
		}, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wire := test.wire()
			if test.mutate != nil {
				test.mutate(wire)
			}
			if _, err := DecodeSelectorState(wire, manifest, binding); err == nil {
				t.Fatal("accepted malformed selector state")
			}
		})
	}
}

func TestSelectorStateWideGraphStaysBounded(t *testing.T) {
	// The graph's 30 KiB wire cap is tighter than its node-count cap for a
	// selector plus its required child. Three hundred fifty short-name selectors sit
	// close to that factual limit while keeping the fixture canonical.
	const selectors = 350
	root := graphTestNode(GraphNodeKindBond, "r")
	nodes := make([]GraphNode, 0, 1+2*selectors)
	entries := make([]SelectorStateEntry, 0, selectors)
	for index := 0; index < selectors; index++ {
		leaf := graphTestNode(GraphNodeKindPath, "l"+decimal(index))
		selector := graphTestNode(GraphNodeKindSelector, "s"+decimal(index))
		selector.Children = []TargetID{leaf.ID}
		root.Children = append(root.Children, selector.ID)
		nodes = append(nodes, selector, leaf)
		entries = append(entries, SelectorStateEntry{
			SelectorID: selector.ID, DesiredTargetID: leaf.ID,
			EffectiveTargetID: leaf.ID, Generation: uint64(index + 1),
		})
	}
	nodes = append(nodes, root)
	manifest := GraphManifest{RootID: root.ID, Nodes: nodes}
	digest, err := manifest.Digest()
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(entries, func(i, j int) bool { return bytes.Compare(entries[i].SelectorID[:], entries[j].SelectorID[:]) < 0 })
	binding := GraphBinding{Revision: 1, Digest: digest}
	payload := SelectorStatePayload{
		SessionEpoch: SessionEpoch{1}, Direction: SenderDirectionServerToClient,
		GraphRevision: 1, GraphDigest: digest, StateEpoch: 1, Entries: entries,
	}
	wire, err := EncodeSelectorState(payload, manifest, binding)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) > SelectorStateMaxWireBytes {
		t.Fatalf("wide selector state length=%d max=%d", len(wire), SelectorStateMaxWireBytes)
	}
	if _, err := DecodeSelectorState(wire, manifest, binding); err != nil {
		t.Fatal(err)
	}
}

func FuzzDecodeSelectorStateNeverPanics(f *testing.F) {
	manifest, binding, payload := nestedSelectorStateFixture(f)
	wire, err := EncodeSelectorState(payload, manifest, binding)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, candidate []byte) {
		_, _ = DecodeSelectorState(candidate, manifest, binding)
	})
}

func decimal(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	index := len(digits)
	for value != 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}
