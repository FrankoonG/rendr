package proto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func testNegotiation(flow [16]byte) Negotiation {
	return testNegotiationFor(flow, testGraphManifest("path"))
}

func testNegotiationFor(flow [16]byte, manifest GraphManifest) Negotiation {
	n := NewNegotiation(SessionEpoch(flow))
	n.GraphDigest, _ = manifest.Digest()
	return n
}

func testGraphManifest(name string) GraphManifest {
	id := DeriveTargetID(GraphNodeKindPath, name)
	return GraphManifest{RootID: id, Nodes: []GraphNode{{ID: id, Kind: GraphNodeKindPath, Name: name}}}
}

func mustHelloWire(t *testing.T, payload HelloPayload) []byte {
	t.Helper()
	wire, err := payload.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func mustHelloAckWire(t *testing.T, payload HelloAckPayload) []byte {
	t.Helper()
	wire, err := payload.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func mutateNegotiationWireForDecodeTest(t *testing.T, wire []byte, mutate func(*Negotiation)) []byte {
	t.Helper()
	if len(wire) < NegotiationSize {
		t.Fatalf("wire length=%d want at least %d", len(wire), NegotiationSize)
	}
	negotiation, err := decodeNegotiation(wire[:NegotiationSize])
	if err != nil {
		t.Fatalf("decode valid negotiation fixture: %v", err)
	}
	mutate(&negotiation)
	out := append([]byte(nil), wire...)
	negotiation.encodeTo(out[:NegotiationSize])
	return out
}

func testBridgeTag(bridgeID [16]byte, name string) BridgeTagPayload {
	return BridgeTagPayload{
		BridgeID:      bridgeID,
		AttachID:      [16]byte{1},
		SessionEpoch:  SessionEpoch(bridgeID),
		Direction:     SenderDirectionClientToServer,
		GraphRevision: 1,
		TargetID:      DeriveTargetID(GraphNodeKindPath, name),
	}
}

func TestCtrlCodeFromFlags(t *testing.T) {
	if got := CtrlCodeFromFlags(FlagsForCtrl(CtrlHello)); got != CtrlHello {
		t.Fatalf("hello round-trip: got %v want %v", got, CtrlHello)
	}
	if got := CtrlCodeFromFlags(FlagsForCtrl(CtrlBridgeTag)); got != CtrlBridgeTag {
		t.Fatalf("bridge_tag round-trip: got %v want %v", got, CtrlBridgeTag)
	}
	if got := CtrlCodeFromFlags(FlagsForCtrl(CtrlBridgeAck)); got != CtrlBridgeAck {
		t.Fatalf("bridge_ack round-trip: got %v want %v", got, CtrlBridgeAck)
	}
	if got := CtrlCodeFromFlags(FlagsForCtrl(CtrlLeafMobilityCommit)); got != CtrlLeafMobilityCommit {
		t.Fatalf("leaf_mobility_commit round-trip: got %v want %v", got, CtrlLeafMobilityCommit)
	}
}

func TestHelloRoundTrip(t *testing.T) {
	flow := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	manifest := testGraphManifest("path")
	want := HelloPayload{Negotiation: testNegotiationFor(flow, manifest), FlowID: flow, InstanceID: InstanceID{1}, Caps: 0xAABB_CCDD, InitialTargetID: manifest.RootID, LocalTXManifest: manifest}
	wire := mustHelloWire(t, want)
	got, err := DecodeHello(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustHelloWire(t, got), wire) {
		t.Fatalf("hello: got %+v want %+v", got, want)
	}
}

func TestLeafMobilityEnvelope(t *testing.T) {
	if ProtocolMinor != 10 {
		t.Fatalf("protocol minor=%d want=10", ProtocolMinor)
	}
	if FeatureLeafMobilityEnvelope != 1<<10 || SupportedFeatures&FeatureLeafMobilityEnvelope == 0 || RequiredFeatures&FeatureLeafMobilityEnvelope == 0 {
		t.Fatal("leaf mobility envelope feature is not stable and mandatory")
	}
	if FeatureLeafMobilityTransaction != 1<<11 || SupportedFeatures&FeatureLeafMobilityTransaction == 0 || RequiredFeatures&FeatureLeafMobilityTransaction == 0 {
		t.Fatal("leaf mobility transaction feature is not stable and mandatory")
	}
	if FeatureLeafMobilityOOBTransaction != 1<<12 || SupportedFeatures&FeatureLeafMobilityOOBTransaction == 0 || RequiredFeatures&FeatureLeafMobilityOOBTransaction == 0 {
		t.Fatal("leaf mobility OOB transaction feature is not stable and mandatory")
	}
	if FeatureServerAssignedSessionEpoch != 1<<13 || SupportedFeatures&FeatureServerAssignedSessionEpoch == 0 || RequiredFeatures&FeatureServerAssignedSessionEpoch == 0 {
		t.Fatal("server-assigned session epoch feature is not stable and mandatory")
	}
	if NegotiationSize != 80 {
		t.Fatalf("negotiation size=%d want=80", NegotiationSize)
	}
	if LeafMobilityTCPRepair != 1<<0 || LeafMobilityQUICCIDRebind != 1<<1 || LeafMobilityUDPFlowRebind != 1<<2 || LeafMobilityGVisorLinkRebind != 1<<3 {
		t.Fatal("leaf mobility bit assignment drifted")
	}
	if LeafMobilityKnownMask != 0x0f {
		t.Fatalf("known leaf mobility mask=0x%x want=0x0f", LeafMobilityKnownMask)
	}
	if LeafMobilityKnownMask.Has(0) {
		t.Fatal("Has accepted a zero request")
	}
	if !LeafMobilityKnownMask.Has(LeafMobilityTCPRepair | LeafMobilityUDPFlowRebind) {
		t.Fatal("Has rejected present operations")
	}

	flow := [16]byte{0x71}
	manifest := testGraphManifest("mobility-envelope")
	payload := HelloPayload{Negotiation: testNegotiationFor(flow, manifest), FlowID: flow, InstanceID: InstanceID{1}, InitialTargetID: manifest.RootID, LocalTXManifest: manifest}
	wire := mustHelloWire(t, payload)
	if !bytes.Equal(wire[4:8], []byte{0, 0, 0, 0}) {
		t.Fatalf("default mobility bytes=%x want=00000000", wire[4:8])
	}
	got, err := DecodeHello(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.MobilitySupported != 0 || got.MobilityRequired != 0 {
		t.Fatalf("default mobility round-trip=(0x%x,0x%x) want=(0,0)", got.MobilitySupported, got.MobilityRequired)
	}
}

func TestLeafMobilityTransactionIsMandatoryOnCurrentMinor(t *testing.T) {
	flow := [16]byte{0x75}
	manifest := testGraphManifest("mobility-transaction-feature")
	negotiation := testNegotiationFor(flow, manifest)
	withoutTransaction := func(n *Negotiation) {
		n.Supported &^= FeatureLeafMobilityTransaction
		n.Required &^= FeatureLeafMobilityTransaction
	}

	helloWire := mutateNegotiationWireForDecodeTest(t, mustHelloWire(t, HelloPayload{
		Negotiation: negotiation, FlowID: flow, InstanceID: InstanceID{1},
		InitialTargetID: manifest.RootID, LocalTXManifest: manifest,
	}), withoutTransaction)
	if _, err := DecodeHello(helloWire); !errors.Is(err, ErrNegotiationIncompatible) {
		t.Fatalf("HELLO without leaf mobility transaction error=%v, want %v", err, ErrNegotiationIncompatible)
	}

	ackWire := mutateNegotiationWireForDecodeTest(t, mustHelloAckWire(t, HelloAckPayload{
		Negotiation: negotiation, FlowID: flow, InstanceID: InstanceID{1},
		InitialTargetID:      manifest.RootID,
		AcceptedPeerBinding:  GraphBinding{Revision: negotiation.GraphRevision, Digest: negotiation.GraphDigest},
		AcceptedPeerTargetID: manifest.RootID,
		LocalTXManifest:      manifest,
	}), withoutTransaction)
	if _, err := DecodeHelloAck(ackWire); !errors.Is(err, ErrNegotiationIncompatible) {
		t.Fatalf("HELLO_ACK without leaf mobility transaction error=%v, want %v", err, ErrNegotiationIncompatible)
	}
}

func TestServerAssignedSessionEpochIsMandatoryOnCurrentMinor(t *testing.T) {
	flow := [16]byte{0x76}
	manifest := testGraphManifest("server-session-epoch-feature")
	negotiation := testNegotiationFor(flow, manifest)
	base := HelloPayload{
		Negotiation: negotiation, FlowID: flow, InstanceID: InstanceID{1},
		InitialTargetID: manifest.RootID, LocalTXManifest: manifest,
	}
	tests := []struct {
		name   string
		mutate func(*Negotiation)
	}{
		{name: "feature missing", mutate: func(n *Negotiation) {
			n.Supported &^= FeatureServerAssignedSessionEpoch
			n.Required &^= FeatureServerAssignedSessionEpoch
		}},
		{name: "minor nine", mutate: func(n *Negotiation) {
			n.ProtocolMinor = 9
			n.Supported &^= FeatureServerAssignedSessionEpoch
			n.Required &^= FeatureServerAssignedSessionEpoch
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wire := mutateNegotiationWireForDecodeTest(t, mustHelloWire(t, base), test.mutate)
			if _, err := DecodeHello(wire); !errors.Is(err, ErrNegotiationIncompatible) {
				t.Fatalf("error=%v want=%v", err, ErrNegotiationIncompatible)
			}
		})
	}
}

func TestLeafMobilityEnvelopeValidation(t *testing.T) {
	flow := [16]byte{0x72}
	manifest := testGraphManifest("mobility-validation")
	base := HelloPayload{Negotiation: testNegotiationFor(flow, manifest), FlowID: flow, InstanceID: InstanceID{1}, InitialTargetID: manifest.RootID, LocalTXManifest: manifest}

	t.Run("unknown supported is preserved", func(t *testing.T) {
		wire := mustHelloWire(t, base)
		wire[4] = 0x80
		got, err := DecodeHello(wire)
		if err != nil {
			t.Fatalf("unknown supported mobility rejected: %v", err)
		}
		if got.MobilitySupported != 1<<15 {
			t.Fatalf("supported mobility=0x%x want=0x8000", got.MobilitySupported)
		}
	})

	tests := []struct {
		name   string
		mutate func([]byte)
	}{
		{name: "unknown required", mutate: func(b []byte) { b[6] = 0x80; b[4] = 0x80 }},
		{name: "required not supported", mutate: func(b []byte) { b[7] = byte(LeafMobilityTCPRepair) }},
		{name: "minor 7 without transaction", mutate: func(b []byte) {
			b[3] = 7
			b[14] &^= byte(FeatureLeafMobilityTransaction >> 8)
			b[22] &^= byte(FeatureLeafMobilityTransaction >> 8)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wire := mustHelloWire(t, base)
			test.mutate(wire)
			if _, err := DecodeHello(wire); !errors.Is(err, ErrNegotiationIncompatible) {
				t.Fatalf("error=%v want %v", err, ErrNegotiationIncompatible)
			}
		})
	}
}

func TestLeafMobilityEnvelopeHelloAckDecodeValidation(t *testing.T) {
	flow := [16]byte{0x74}
	manifest := testGraphManifest("mobility-ack-validation")
	negotiation := testNegotiationFor(flow, manifest)
	base := HelloAckPayload{
		Negotiation: negotiation, FlowID: flow, InstanceID: InstanceID{1},
		InitialTargetID:      manifest.RootID,
		AcceptedPeerBinding:  GraphBinding{Revision: negotiation.GraphRevision, Digest: negotiation.GraphDigest},
		AcceptedPeerTargetID: manifest.RootID,
		LocalTXManifest:      manifest,
	}

	t.Run("unknown supported is preserved", func(t *testing.T) {
		wire := mutateNegotiationWireForDecodeTest(t, mustHelloAckWire(t, base), func(n *Negotiation) {
			n.MobilitySupported = 1 << 15
		})
		got, err := DecodeHelloAck(wire)
		if err != nil {
			t.Fatalf("unknown supported mobility rejected: %v", err)
		}
		if got.MobilitySupported != 1<<15 {
			t.Fatalf("supported mobility=0x%x want=0x8000", got.MobilitySupported)
		}
	})

	tests := []struct {
		name   string
		mutate func(*Negotiation)
	}{
		{name: "unknown required", mutate: func(n *Negotiation) {
			n.MobilitySupported = 1 << 15
			n.MobilityRequired = 1 << 15
		}},
		{name: "required not supported", mutate: func(n *Negotiation) {
			n.MobilityRequired = LeafMobilityTCPRepair
		}},
		{name: "minor 7 without transaction", mutate: func(n *Negotiation) {
			n.ProtocolMinor = 7
			n.Supported &^= FeatureLeafMobilityTransaction
			n.Required &^= FeatureLeafMobilityTransaction
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wire := mutateNegotiationWireForDecodeTest(t, mustHelloAckWire(t, base), test.mutate)
			if _, err := DecodeHelloAck(wire); !errors.Is(err, ErrNegotiationIncompatible) {
				t.Fatalf("error=%v want=%v", err, ErrNegotiationIncompatible)
			}
		})
	}
}

func TestLeafMobilityEnvelopeRoundTripAndEncodeValidation(t *testing.T) {
	flow := [16]byte{0x73}
	manifest := testGraphManifest("mobility-round-trip")
	negotiation := testNegotiationFor(flow, manifest)
	negotiation.MobilitySupported = LeafMobilityTCPRepair | LeafMobilityUDPFlowRebind
	negotiation.MobilityRequired = LeafMobilityUDPFlowRebind

	hello := HelloPayload{
		Negotiation: negotiation, FlowID: flow, InstanceID: InstanceID{1},
		InitialTargetID: manifest.RootID, LocalTXManifest: manifest,
	}
	helloWire := mustHelloWire(t, hello)
	wantPrefix, err := hex.DecodeString("0001000a000500040000000000003fff0000000000003fff")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(helloWire[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("HELLO negotiation prefix=%x want=%x", helloWire[:len(wantPrefix)], wantPrefix)
	}
	gotHello, err := DecodeHello(helloWire)
	if err != nil {
		t.Fatal(err)
	}
	if gotHello.Negotiation != negotiation {
		t.Fatalf("HELLO negotiation=%+v want=%+v", gotHello.Negotiation, negotiation)
	}

	ack := HelloAckPayload{
		Negotiation: negotiation, FlowID: flow, InstanceID: InstanceID{1},
		InitialTargetID:      manifest.RootID,
		AcceptedPeerBinding:  GraphBinding{Revision: negotiation.GraphRevision, Digest: negotiation.GraphDigest},
		AcceptedPeerTargetID: manifest.RootID,
		LocalTXManifest:      manifest,
	}
	ackWire := mustHelloAckWire(t, ack)
	if !bytes.Equal(ackWire[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("HELLO_ACK negotiation prefix=%x want=%x", ackWire[:len(wantPrefix)], wantPrefix)
	}
	gotAck, err := DecodeHelloAck(ackWire)
	if err != nil {
		t.Fatal(err)
	}
	if gotAck.Negotiation != negotiation {
		t.Fatalf("HELLO_ACK negotiation=%+v want=%+v", gotAck.Negotiation, negotiation)
	}

	tests := []struct {
		name   string
		mutate func(*Negotiation)
	}{
		{name: "unknown required", mutate: func(n *Negotiation) {
			n.MobilitySupported = 1 << 15
			n.MobilityRequired = 1 << 15
		}},
		{name: "required not supported", mutate: func(n *Negotiation) {
			n.MobilitySupported = 0
			n.MobilityRequired = LeafMobilityTCPRepair
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			badHello := hello
			test.mutate(&badHello.Negotiation)
			if _, err := badHello.Encode(); !errors.Is(err, ErrNegotiationIncompatible) {
				t.Fatalf("HELLO encode error=%v want=%v", err, ErrNegotiationIncompatible)
			}
			badAck := ack
			test.mutate(&badAck.Negotiation)
			if _, err := badAck.Encode(); !errors.Is(err, ErrNegotiationIncompatible) {
				t.Fatalf("HELLO_ACK encode error=%v want=%v", err, ErrNegotiationIncompatible)
			}
		})
	}
}

func TestMigrateNotifyRoundTrip(t *testing.T) {
	want := MigrateNotifyPayload{NewPathID: 0xDEADBEEF}
	got, err := DecodeMigrateNotify(want.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("migrate_notify: got %+v want %+v", got, want)
	}
}

func TestPathQualityRoundTrip(t *testing.T) {
	want := PathQualityPayload{RTTus: 12345, JitterUs: 678, LossPP: 7}
	got, err := DecodePathQuality(want.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("path_quality: got %+v want %+v", got, want)
	}
}

func TestHeartbeatRoundTrip(t *testing.T) {
	want := HeartbeatPayload{Timestamp: 1_700_000_000_000_000_000}
	got, err := DecodeHeartbeat(want.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("heartbeat: got %+v want %+v", got, want)
	}
}

func TestByeRoundTrip(t *testing.T) {
	want := ByePayload{Reason: ByeMigBudget}
	got, err := DecodeBye(want.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("bye: got %+v want %+v", got, want)
	}
}

func TestBridgeTagRoundTrip(t *testing.T) {
	want := testBridgeTag([16]byte{0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8}, "")
	got, err := DecodeBridgeTag(want.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("bridge_tag: got %+v want %+v", got, want)
	}
}

func TestHelloAckRoundTrip(t *testing.T) {
	flow := [16]byte{1, 2, 3, 4}
	want := HelloAckPayload{
		Negotiation:          testNegotiation(flow),
		FlowID:               flow,
		InstanceID:           InstanceID{5, 6, 7, 8},
		Caps:                 0xAABB_CCDD,
		InitialTargetID:      testGraphManifest("path").RootID,
		AcceptedPeerBinding:  GraphBinding{Revision: 1, Digest: testNegotiation(flow).GraphDigest},
		AcceptedPeerTargetID: testGraphManifest("path").RootID,
		LocalTXManifest:      testGraphManifest("path"),
	}
	wire := mustHelloAckWire(t, want)
	got, err := DecodeHelloAck(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustHelloAckWire(t, got), wire) {
		t.Fatalf("hello_ack: got %+v want %+v", got, want)
	}
}

func TestBridgeAckRoundTrip(t *testing.T) {
	bridgeID := [16]byte{0xFE, 0xED}
	want := BridgeAckPayload{
		BridgeID:          bridgeID,
		AttachID:          [16]byte{9},
		InstanceID:        InstanceID{1, 2, 3, 4},
		SessionEpoch:      SessionEpoch(bridgeID),
		Direction:         SenderDirectionClientToServer,
		GraphRevision:     1,
		TargetID:          DeriveTargetID(GraphNodeKindPath, "B"),
		ResponderTargetID: DeriveTargetID(GraphNodeKindPath, "B"),
		Code:              AckRejectInstance,
		Reason:            "instance mismatch",
	}
	got, err := DecodeBridgeAck(want.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("bridge_ack: got %+v want %+v", got, want)
	}
}

func TestHelloPathNameRoundTrip(t *testing.T) {
	flow := [16]byte{1, 2, 3, 4}
	manifest := testGraphManifest("A")
	want := HelloPayload{Negotiation: testNegotiationFor(flow, manifest), FlowID: flow, InstanceID: InstanceID{1}, Caps: CapsPacketMode, InitialTargetID: manifest.RootID, LocalTXManifest: manifest}
	wire := mustHelloWire(t, want)
	got, err := DecodeHello(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustHelloWire(t, got), wire) {
		t.Fatalf("hello path name: got %+v want %+v", got, want)
	}
}

func TestBridgeTagPathNameRoundTrip(t *testing.T) {
	want := testBridgeTag([16]byte{0xFE, 0xED}, "B")
	got, err := DecodeBridgeTag(want.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("bridge tag path name: got %+v want %+v", got, want)
	}
}

func TestExecutionKindStability(t *testing.T) {
	cases := []struct {
		kind ExecutionKind
		want byte
	}{
		{ExecutionKindInvalid, 0},
		{ExecutionKindSelector, 1},
		{ExecutionKindBond, 2},
		{ExecutionKindRace, 3},
	}
	for _, tc := range cases {
		if byte(tc.kind) != tc.want {
			t.Errorf("execution kind drifted: got %d want %d", tc.kind, tc.want)
		}
	}
}

func TestExecutionKindValid(t *testing.T) {
	for _, kind := range []ExecutionKind{ExecutionKindSelector, ExecutionKindBond, ExecutionKindRace} {
		if !kind.Valid() {
			t.Errorf("kind %d is not valid", kind)
		}
	}
	for _, kind := range []ExecutionKind{ExecutionKindInvalid, 4, 255} {
		if kind.Valid() {
			t.Errorf("kind %d is unexpectedly valid", kind)
		}
	}
}

func TestRejectLegacyHandshakePayloads(t *testing.T) {
	legacyHello := make([]byte, 20)
	if _, err := DecodeHello(legacyHello); err == nil {
		t.Fatal("accepted legacy 20-byte HELLO")
	}

	legacyBridgeTag := make([]byte, 16)
	if _, err := DecodeBridgeTag(legacyBridgeTag); err == nil {
		t.Fatal("accepted legacy 16-byte BRIDGE_TAG")
	}
}

func TestHelloRejectsInvalidNegotiationBeforeUse(t *testing.T) {
	flow := [16]byte{1, 2, 3, 4}
	manifest := testGraphManifest("path")
	base := mustHelloWire(t, HelloPayload{Negotiation: testNegotiationFor(flow, manifest), FlowID: flow, InstanceID: InstanceID{1}, InitialTargetID: manifest.RootID, LocalTXManifest: manifest})
	mutations := map[string]func([]byte){
		"protocol major":                  func(b []byte) { b[1] = 2 },
		"mobility required not supported": func(b []byte) { b[7] = 1 },
		"unknown required":                func(b []byte) { b[16] = 0x80 },
		"zero revision":                   func(b []byte) { clear(b[40:48]) },
		"epoch mismatch":                  func(b []byte) { b[24]++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			wire := append([]byte(nil), base...)
			mutate(wire)
			if _, err := DecodeHello(wire); err == nil {
				t.Fatal("accepted invalid negotiation")
			}
		})
	}
}

func TestHandshakePayloadsRejectMalformedExtensions(t *testing.T) {
	tests := []struct {
		name   string
		base   []byte
		decode func([]byte) error
	}{
		{
			name: "hello",
			base: func() []byte {
				flow := [16]byte{1}
				manifest := testGraphManifest("path")
				return mustHelloWire(t, HelloPayload{Negotiation: testNegotiationFor(flow, manifest), FlowID: flow, InstanceID: InstanceID{1}, InitialTargetID: manifest.RootID, LocalTXManifest: manifest})
			}(),
			decode: func(b []byte) error {
				_, err := DecodeHello(b)
				return err
			},
		},
		{
			name: "bridge_tag",
			base: testBridgeTag([16]byte{1}, "path").Encode(),
			decode: func(b []byte) error {
				_, err := DecodeBridgeTag(b)
				return err
			},
		},
		{
			name: "bridge_ack",
			base: BridgeAckPayload{BridgeID: [16]byte{1}, AttachID: [16]byte{1}, SessionEpoch: SessionEpoch{1}, Direction: SenderDirectionClientToServer, GraphRevision: 1, TargetID: DeriveTargetID(GraphNodeKindPath, "path"), ResponderTargetID: DeriveTargetID(GraphNodeKindPath, "path")}.Encode(),
			decode: func(b []byte) error {
				_, err := DecodeBridgeAck(b)
				return err
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name+"/empty", func(t *testing.T) {
			wire := append(append([]byte(nil), tc.base...), 0)
			if err := tc.decode(wire); err == nil {
				t.Fatal("accepted empty extension")
			}
		})
		t.Run(tc.name+"/truncated", func(t *testing.T) {
			wire := append(append([]byte(nil), tc.base...), 2, 'x')
			if err := tc.decode(wire); err == nil {
				t.Fatal("accepted truncated extension")
			}
		})
		t.Run(tc.name+"/trailing", func(t *testing.T) {
			wire := append(append([]byte(nil), tc.base...), 1, 'x', 0)
			if err := tc.decode(wire); err == nil {
				t.Fatal("accepted trailing extension")
			}
		})
	}
}

func TestFixedPayloadsRejectTrailingBytes(t *testing.T) {
	tests := []struct {
		name   string
		wire   []byte
		decode func([]byte) bool
	}{
		{"probe", ProbePayload{}.Encode(), func(b []byte) bool { _, err := DecodeProbe(b); return err == nil }},
		{"ack", AckPayload{Direction: SenderDirectionClientToServer}.Encode(), func(b []byte) bool { _, ok := DecodeAck(b); return ok }},
		{"hello_ack", func() []byte {
			flow := [16]byte{1}
			manifest := testGraphManifest("path")
			return mustHelloAckWire(t, HelloAckPayload{Negotiation: testNegotiationFor(flow, manifest), FlowID: flow, InstanceID: InstanceID{1}, InitialTargetID: manifest.RootID, AcceptedPeerBinding: GraphBinding{Revision: 1, Digest: testNegotiationFor(flow, manifest).GraphDigest}, AcceptedPeerTargetID: manifest.RootID, LocalTXManifest: manifest})
		}(), func(b []byte) bool { _, err := DecodeHelloAck(b); return err == nil }},
		{"migrate_notify", MigrateNotifyPayload{}.Encode(), func(b []byte) bool { _, err := DecodeMigrateNotify(b); return err == nil }},
		{"path_quality", PathQualityPayload{}.Encode(), func(b []byte) bool { _, err := DecodePathQuality(b); return err == nil }},
		{"heartbeat", HeartbeatPayload{}.Encode(), func(b []byte) bool { _, err := DecodeHeartbeat(b); return err == nil }},
		{"bye", ByePayload{}.Encode(), func(b []byte) bool { _, err := DecodeBye(b); return err == nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wire := append(append([]byte(nil), tc.wire...), 0)
			if tc.decode(wire) {
				t.Fatal("accepted trailing byte")
			}
		})
	}
}

func TestRejectShortPayloads(t *testing.T) {
	short := []byte{0}
	if _, err := DecodeHello(short); err == nil {
		t.Error("hello accepted short input")
	}
	if _, err := DecodeMigrateNotify(short); err == nil {
		t.Error("migrate_notify accepted short input")
	}
	if _, err := DecodePathQuality(short); err == nil {
		t.Error("path_quality accepted short input")
	}
	if _, err := DecodeHeartbeat(short); err == nil {
		t.Error("heartbeat accepted short input")
	}
	if _, err := DecodeBridgeTag(short); err == nil {
		t.Error("bridge_tag accepted short input")
	}
	if _, err := DecodeHelloAck(short); err == nil {
		t.Error("hello_ack accepted short input")
	}
	if _, err := DecodeBridgeAck(short); err == nil {
		t.Error("bridge_ack accepted short input")
	}
	if _, err := DecodeBye(nil); err == nil {
		t.Error("bye accepted nil input")
	}
}

func TestCtrlCodeStability(t *testing.T) {
	cases := []struct {
		code CtrlCode
		want byte
	}{
		{CtrlHello, 0x01},
		{CtrlMigrateNotify, 0x02},
		{CtrlPathQuality, 0x03},
		{CtrlHeartbeat, 0x04},
		{CtrlBye, 0x05},
		{CtrlPathProbe, 0x06},
		{CtrlPathProbeReply, 0x07},
		{CtrlPolicyPrepare, 0x08},
		{CtrlHelloAck, 0x09},
		{CtrlPolicyAck, 0x0A},
		{CtrlPolicyCommit, 0x0B},
		{CtrlPathAdmissionCommit, 0x0C},
		{CtrlPathAdmissionAck, 0x0D},
		{CtrlPathAdmissionConfirm, 0x0E},
		{CtrlBridgeTag, 0x10},
		{CtrlBridgeAck, 0x11},
		{CtrlLeafMobilityPrepare, 0x12},
		{CtrlLeafMobilityAck, 0x13},
		{CtrlLeafMobilityCommit, 0x14},
	}
	for _, c := range cases {
		if byte(c.code) != c.want {
			t.Errorf("%s drifted: got 0x%02x want 0x%02x (bump proto.Version if intentional)", c.code, byte(c.code), c.want)
		}
	}
}

func TestCapsBitStability(t *testing.T) {
	if CapsPacketMode != 0x00000001 {
		t.Errorf("CapsPacketMode drifted: got 0x%08x want 0x00000001 (bump proto.Version if intentional)",
			CapsPacketMode)
	}
	if CapsL3Identity != 0x00000002 {
		t.Errorf("CapsL3Identity drifted: got 0x%08x want 0x00000002 (bump proto.Version if intentional)",
			CapsL3Identity)
	}
}

func TestProbeWireStability(t *testing.T) {
	p := ProbePayload{TS: 0x1122334455667788, ID: 0x99AABBCCDDEEFF00}
	want := []byte{
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
	}
	if !bytes.Equal(p.Encode(), want) {
		t.Fatalf("probe wire drift:\n got=%x\nwant=%x", p.Encode(), want)
	}
}

func TestAckPayloadRoundTrip(t *testing.T) {
	want := AckPayload{
		SessionEpoch:  SessionEpoch{1, 2, 3, 4},
		Direction:     SenderDirectionClientToServer,
		GraphRevision: 0x1112131415161718,
		NextSeq:       0x0102030405060708,
		Gap:           true,
	}
	got, ok := DecodeAck(want.Encode())
	if !ok {
		t.Fatal("DecodeAck rejected encoded ack")
	}
	if got != want {
		t.Fatalf("ack: got %+v want %+v", got, want)
	}
	if _, ok := DecodeAck(ProbePayload{TS: 1, ID: 2}.Encode()); ok {
		t.Fatal("DecodeAck accepted ordinary probe payload")
	}
}

func TestAckPayloadWireStability(t *testing.T) {
	p := AckPayload{
		SessionEpoch:  SessionEpoch{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Direction:     SenderDirectionServerToClient,
		GraphRevision: 0x1112131415161718,
		GraphDigest: GraphDigest{
			0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
			0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
			0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
			0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
		},
		NextSeq: 0x0102030405060708,
		Gap:     true,
		Proof:   AckProof{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30},
	}
	want := []byte{
		0x52, 0x45, 0x4e, 0x44, 0x52, 0x5f, 0x41, 0x43,
		0x01, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
		0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
		0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
	}
	if !bytes.Equal(p.Encode(), want) {
		t.Fatalf("ack wire drift:\n got=%x\nwant=%x", p.Encode(), want)
	}
}

func TestAckPayloadRejectsInvalidBindingFields(t *testing.T) {
	base := AckPayload{Direction: SenderDirectionClientToServer}.Encode()
	mutations := map[string]func([]byte){
		"version":   func(b []byte) { b[8]++ },
		"direction": func(b []byte) { b[9] = 0 },
		"flags":     func(b []byte) { b[10] = 0x80 },
		"reserved":  func(b []byte) { b[15] = 1 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			wire := append([]byte(nil), base...)
			mutate(wire)
			if _, ok := DecodeAck(wire); ok {
				t.Fatal("accepted invalid ACK binding")
			}
		})
	}
}

func TestBridgeTagWireStability(t *testing.T) {
	bridgeID := [16]byte{
		0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	}
	p := BridgeTagPayload{
		BridgeID:               bridgeID,
		AttachID:               [16]byte{0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF},
		InstanceID:             InstanceID{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F},
		ExpectedPeerInstanceID: InstanceID{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F},
		SessionEpoch:           SessionEpoch(bridgeID),
		Direction:              SenderDirectionClientToServer,
		GraphRevision:          0x0102030405060708,
		GraphDigest:            GraphDigest{0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F},
		TargetID:               TargetID{0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F},
	}
	want := []byte{
		0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
		0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
		0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
		0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
		0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
		0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
		0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
	}
	if !bytes.Equal(p.Encode(), want) {
		t.Fatalf("bridge_tag wire drift:\n got=%x\nwant=%x", p.Encode(), want)
	}
}

func TestMigrateNotifyWireStability(t *testing.T) {
	p := MigrateNotifyPayload{NewPathID: 0xDEADBEEF}
	want := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	if !bytes.Equal(p.Encode(), want) {
		t.Fatalf("migrate_notify wire drift:\n got=%x\nwant=%x", p.Encode(), want)
	}
}

func TestPathQualityWireStability(t *testing.T) {
	p := PathQualityPayload{RTTus: 0x11223344, JitterUs: 0x55667788, LossPP: 0x99AA}
	want := []byte{
		0x11, 0x22, 0x33, 0x44,
		0x55, 0x66, 0x77, 0x88,
		0x99, 0xAA,
	}
	if !bytes.Equal(p.Encode(), want) {
		t.Fatalf("path_quality wire drift:\n got=%x\nwant=%x", p.Encode(), want)
	}
}

func TestHeartbeatWireStability(t *testing.T) {
	p := HeartbeatPayload{Timestamp: 0x0102030405060708}
	want := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if !bytes.Equal(p.Encode(), want) {
		t.Fatalf("heartbeat wire drift:\n got=%x\nwant=%x", p.Encode(), want)
	}
}

func TestByeWireStability(t *testing.T) {
	cases := []struct {
		reason ByeReason
		want   byte
	}{
		{ByeNormal, 0x00},
		{ByeMigBudget, 0x01},
		{ByeProtoVer, 0x03},
	}
	for _, c := range cases {
		p := ByePayload{Reason: c.reason}
		enc := p.Encode()
		if len(enc) != 1 || enc[0] != c.want {
			t.Errorf("bye(%v) wire drift: got %x want %02x", c.reason, enc, c.want)
		}
	}
}

func TestHelloWireStability(t *testing.T) {
	flow := [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	p := HelloPayload{
		FlowID:     flow,
		InstanceID: InstanceID{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F},
		Caps:       0x01020304,
	}
	p.LocalTXManifest = testGraphManifest("path")
	p.InitialTargetID = p.LocalTXManifest.RootID
	p.Negotiation = testNegotiationFor(flow, p.LocalTXManifest)
	want := []byte{
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
		0x01, 0x02, 0x03, 0x04,
	}
	var err error
	want, err = hex.DecodeString("0001000a000000000000000000003fff0000000000003fff00112233445566778899aabbccddeeff0000000000000001d74e06a99ea594a5106805da30032ef33e038536aad785038229b47bc8e6c31600112233445566778899aabbccddeeff101112131415161718191a1b1c1d1e1f01020304143288a952e5b7a301f4c23d0b09e0190000003452474d4601000001143288a952e5b7a301f4c23d0b09e019143288a952e5b7a301f4c23d0b09e019010400000000000070617468")
	if err != nil {
		t.Fatal(err)
	}
	got := mustHelloWire(t, p)
	if !bytes.Equal(got, want) {
		t.Fatalf("hello wire drift:\n got=%x\nwant=%x", got, want)
	}
}
