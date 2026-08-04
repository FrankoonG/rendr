package proto

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func graphHandshakeManifest(rootName string, rootKind GraphNodeKind, leafNames ...string) (GraphManifest, []TargetID) {
	leaves := make([]GraphNode, len(leafNames))
	leafIDs := make([]TargetID, len(leafNames))
	for i, name := range leafNames {
		leaves[i] = GraphNode{
			ID:   DeriveTargetID(GraphNodeKindPath, name),
			Kind: GraphNodeKindPath,
			Name: name,
		}
		leafIDs[i] = leaves[i].ID
	}
	root := GraphNode{
		ID:       DeriveTargetID(rootKind, rootName),
		Kind:     rootKind,
		Name:     rootName,
		Children: append([]TargetID(nil), leafIDs...),
	}
	nodes := make([]GraphNode, 0, len(leaves)+1)
	nodes = append(nodes, root)
	nodes = append(nodes, leaves...)
	return GraphManifest{RootID: root.ID, Nodes: nodes}, leafIDs
}

func graphHandshakeNegotiation(t *testing.T, flow [16]byte, revision uint64, manifest GraphManifest) Negotiation {
	t.Helper()
	digest, err := manifest.Digest()
	if err != nil {
		t.Fatalf("digest graph manifest: %v", err)
	}
	n := NewNegotiation(SessionEpoch(flow))
	n.GraphRevision = revision
	n.GraphDigest = digest
	return n
}

func graphHandshakeBinding(n Negotiation) GraphBinding {
	return GraphBinding{Revision: n.GraphRevision, Digest: n.GraphDigest}
}

func mustEncodeGraphHandshakeHello(t *testing.T, payload HelloPayload) []byte {
	t.Helper()
	wire, err := payload.Encode()
	if err != nil {
		t.Fatalf("encode HELLO: %v", err)
	}
	return wire
}

func mustEncodeGraphHandshakeHelloAck(t *testing.T, payload HelloAckPayload) []byte {
	t.Helper()
	wire, err := payload.Encode()
	if err != nil {
		t.Fatalf("encode HELLO_ACK: %v", err)
	}
	return wire
}

func assertGraphHandshakeManifestEqual(t *testing.T, got, want GraphManifest) {
	t.Helper()
	gotWire, err := got.Encode()
	if err != nil {
		t.Fatalf("encode decoded manifest: %v", err)
	}
	wantWire, err := want.Encode()
	if err != nil {
		t.Fatalf("encode expected manifest: %v", err)
	}
	if !bytes.Equal(gotWire, wantWire) {
		t.Fatalf("manifest mismatch:\n got=%x\nwant=%x", gotWire, wantWire)
	}
}

func TestHelloCarriesCanonicalBoundedLocalTXManifest(t *testing.T) {
	flow := [16]byte{1, 2, 3, 4, 5, 6, 7, 8}
	manifest, leaves := graphHandshakeManifest("client-root", GraphNodeKindSelector, "client-a", "client-b")
	negotiation := graphHandshakeNegotiation(t, flow, 7, manifest)
	want := HelloPayload{
		Negotiation:     negotiation,
		FlowID:          flow,
		InstanceID:      InstanceID{0x11},
		Caps:            CapsPacketMode,
		LocalTXManifest: manifest,
		InitialTargetID: leaves[0],
	}

	got, err := DecodeHello(mustEncodeGraphHandshakeHello(t, want))
	if err != nil {
		t.Fatalf("DecodeHello: %v", err)
	}
	if got.InitialTargetID != leaves[0] {
		t.Fatalf("initial target = %x, want %x", got.InitialTargetID, leaves[0])
	}
	if got.GraphRevision != negotiation.GraphRevision || got.GraphDigest != negotiation.GraphDigest {
		t.Fatalf("HELLO graph binding drifted: revision=%d digest=%x", got.GraphRevision, got.GraphDigest)
	}
	assertGraphHandshakeManifestEqual(t, got.LocalTXManifest, manifest)

	manifestWire, err := manifest.Encode()
	if err != nil {
		t.Fatal(err)
	}
	encoded := mustEncodeGraphHandshakeHello(t, want)
	if !bytes.Contains(encoded, manifestWire) {
		t.Fatal("HELLO does not carry the canonical local-TX manifest bytes")
	}
	oversized := append(append([]byte(nil), encoded...), make([]byte, GraphManifestMaxWireBytes+1)...)
	if _, err := DecodeHello(oversized); err == nil {
		t.Fatal("HELLO accepted a payload larger than the bounded manifest envelope")
	}
}

func TestHelloAckSeparatesAsymmetricLocalTXFromAcceptedPeerBinding(t *testing.T) {
	flow := [16]byte{9, 8, 7, 6, 5, 4, 3, 2}
	clientManifest, clientLeaves := graphHandshakeManifest("client-selector", GraphNodeKindSelector, "client-low", "client-fast")
	serverManifest, serverLeaves := graphHandshakeManifest("server-race", GraphNodeKindRace, "server-left", "server-right")
	clientNegotiation := graphHandshakeNegotiation(t, flow, 11, clientManifest)
	serverNegotiation := graphHandshakeNegotiation(t, flow, 19, serverManifest)
	if clientNegotiation.GraphDigest == serverNegotiation.GraphDigest {
		t.Fatal("test setup produced identical client and server graph digests")
	}

	hello, err := DecodeHello(mustEncodeGraphHandshakeHello(t, HelloPayload{
		Negotiation:     clientNegotiation,
		FlowID:          flow,
		InstanceID:      InstanceID{0x21},
		LocalTXManifest: clientManifest,
		InitialTargetID: clientLeaves[0],
	}))
	if err != nil {
		t.Fatalf("decode client HELLO: %v", err)
	}

	wantAck := HelloAckPayload{
		Negotiation:         serverNegotiation,
		FlowID:              flow,
		InstanceID:          InstanceID{0x31},
		LocalTXManifest:     serverManifest,
		InitialTargetID:     serverLeaves[1],
		AcceptedPeerBinding: graphHandshakeBinding(clientNegotiation),
	}
	ack, err := DecodeHelloAck(mustEncodeGraphHandshakeHelloAck(t, wantAck))
	if err != nil {
		t.Fatalf("DecodeHelloAck: %v", err)
	}
	if ack.GraphDigest == hello.GraphDigest {
		t.Fatal("HELLO_ACK incorrectly mirrored the peer graph as its local-TX graph")
	}
	if ack.GraphRevision != serverNegotiation.GraphRevision || ack.GraphDigest != serverNegotiation.GraphDigest {
		t.Fatalf("HELLO_ACK local binding = (%d,%x), want (%d,%x)", ack.GraphRevision, ack.GraphDigest, serverNegotiation.GraphRevision, serverNegotiation.GraphDigest)
	}
	if ack.AcceptedPeerBinding != graphHandshakeBinding(clientNegotiation) {
		t.Fatalf("accepted peer binding = %+v, want %+v", ack.AcceptedPeerBinding, graphHandshakeBinding(clientNegotiation))
	}
	if ack.InitialTargetID != serverLeaves[1] {
		t.Fatalf("server initial target = %x, want %x", ack.InitialTargetID, serverLeaves[1])
	}
	assertGraphHandshakeManifestEqual(t, ack.LocalTXManifest, serverManifest)
}

func TestHandshakeRejectsInitialTargetOutsideLocalTXPathSet(t *testing.T) {
	flow := [16]byte{0x42}
	manifest, leaves := graphHandshakeManifest("root", GraphNodeKindSelector, "path-a", "path-b")
	negotiation := graphHandshakeNegotiation(t, flow, 3, manifest)
	validHello := mustEncodeGraphHandshakeHello(t, HelloPayload{
		Negotiation:     negotiation,
		FlowID:          flow,
		InstanceID:      InstanceID{1},
		LocalTXManifest: manifest,
		InitialTargetID: leaves[0],
	})
	validAck := mustEncodeGraphHandshakeHelloAck(t, HelloAckPayload{
		Negotiation:         negotiation,
		FlowID:              flow,
		InstanceID:          InstanceID{2},
		LocalTXManifest:     manifest,
		InitialTargetID:     leaves[0],
		AcceptedPeerBinding: graphHandshakeBinding(negotiation),
	})
	manifestWire, err := manifest.Encode()
	if err != nil {
		t.Fatal(err)
	}

	badTargets := map[string]TargetID{
		"foreign path": DeriveTargetID(GraphNodeKindPath, "not-in-graph"),
		"group node":   manifest.RootID,
	}
	decoders := []struct {
		name   string
		wire   []byte
		decode func([]byte) error
	}{
		{name: "hello", wire: validHello, decode: func(wire []byte) error { _, err := DecodeHello(wire); return err }},
		{name: "hello_ack", wire: validAck, decode: func(wire []byte) error { _, err := DecodeHelloAck(wire); return err }},
	}
	for targetName, targetID := range badTargets {
		for _, decoder := range decoders {
			t.Run(decoder.name+"/"+targetName, func(t *testing.T) {
				wire := replaceGraphHandshakeInitialTarget(t, decoder.wire, manifestWire, leaves[0], targetID)
				if err := decoder.decode(wire); err == nil {
					t.Fatal("accepted an initial target that is not a path in the advertised local-TX manifest")
				}
			})
		}
	}
}

func TestHandshakeRejectsNonCanonicalLocalTXManifest(t *testing.T) {
	flow := [16]byte{0x73}
	manifest, leaves := graphHandshakeManifest("canonical-root", GraphNodeKindBond, "canonical-a", "canonical-b")
	negotiation := graphHandshakeNegotiation(t, flow, 5, manifest)
	manifestWire, err := manifest.Encode()
	if err != nil {
		t.Fatal(err)
	}
	nonCanonical := swapGraphHandshakeManifestNodes(t, manifestWire)

	tests := []struct {
		name   string
		wire   []byte
		decode func([]byte) error
	}{
		{
			name: "hello",
			wire: mustEncodeGraphHandshakeHello(t, HelloPayload{
				Negotiation:     negotiation,
				FlowID:          flow,
				InstanceID:      InstanceID{1},
				LocalTXManifest: manifest,
				InitialTargetID: leaves[0],
			}),
			decode: func(wire []byte) error { _, err := DecodeHello(wire); return err },
		},
		{
			name: "hello_ack",
			wire: mustEncodeGraphHandshakeHelloAck(t, HelloAckPayload{
				Negotiation:         negotiation,
				FlowID:              flow,
				InstanceID:          InstanceID{2},
				LocalTXManifest:     manifest,
				InitialTargetID:     leaves[1],
				AcceptedPeerBinding: graphHandshakeBinding(negotiation),
			}),
			decode: func(wire []byte) error { _, err := DecodeHelloAck(wire); return err },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			at := bytes.Index(tc.wire, manifestWire)
			if at < 0 {
				t.Fatal("handshake payload does not contain canonical manifest bytes")
			}
			wire := append([]byte(nil), tc.wire...)
			copy(wire[at:at+len(nonCanonical)], nonCanonical)
			if err := tc.decode(wire); err == nil {
				t.Fatal("accepted a semantically valid but non-canonical local-TX manifest")
			}
		})
	}
}

func replaceGraphHandshakeInitialTarget(t *testing.T, wire, manifestWire []byte, oldID, newID TargetID) []byte {
	t.Helper()
	manifestAt := bytes.Index(wire, manifestWire)
	if manifestAt < 0 {
		t.Fatal("handshake payload does not contain manifest")
	}
	manifestEnd := manifestAt + len(manifestWire)
	out := append([]byte(nil), wire...)
	for searchAt := 0; searchAt+len(oldID) <= len(out); {
		relative := bytes.Index(out[searchAt:], oldID[:])
		if relative < 0 {
			break
		}
		at := searchAt + relative
		if at < manifestAt || at >= manifestEnd {
			copy(out[at:at+len(newID)], newID[:])
			return out
		}
		searchAt = at + 1
	}
	t.Fatal("initial target field was not encoded outside the manifest")
	return nil
}

func swapGraphHandshakeManifestNodes(t *testing.T, wire []byte) []byte {
	t.Helper()
	if len(wire) < graphManifestHeaderSize || binary.BigEndian.Uint16(wire[6:8]) < 2 {
		t.Fatal("need at least two graph nodes")
	}
	spans := make([][2]int, 0, 2)
	offset := graphManifestHeaderSize
	for i := 0; i < 2; i++ {
		if len(wire)-offset < graphNodeHeaderSize {
			t.Fatal("truncated graph node")
		}
		start := offset
		header := wire[offset : offset+graphNodeHeaderSize]
		offset += graphNodeHeaderSize
		offset += int(header[17])
		offset += 16 * (int(binary.BigEndian.Uint16(header[20:22])) + int(binary.BigEndian.Uint16(header[22:24])))
		if offset > len(wire) {
			t.Fatal("truncated graph node body")
		}
		spans = append(spans, [2]int{start, offset})
	}
	out := append([]byte(nil), wire[:spans[0][0]]...)
	out = append(out, wire[spans[1][0]:spans[1][1]]...)
	out = append(out, wire[spans[0][0]:spans[0][1]]...)
	out = append(out, wire[spans[1][1]:]...)
	return out
}
