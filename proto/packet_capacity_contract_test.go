package proto

import (
	"strings"
	"testing"
)

func TestDirectionalPacketCapacityHandshakeRoundTrip(t *testing.T) {
	if ProtocolMinor != 22 {
		t.Fatalf("protocol minor=%d want=22 for directional packet capacity", ProtocolMinor)
	}
	if SupportedFeatures&FeatureDirectionalPacketCapacity == 0 || RequiredFeatures&FeatureDirectionalPacketCapacity == 0 {
		t.Fatal("directional packet capacity is not a mandatory negotiated feature")
	}

	flow := [16]byte{1, 2, 3, 4}
	manifest := testGraphManifest("packet-capacity")
	hello := HelloPayload{
		Negotiation:          testNegotiationFor(flow, manifest),
		FlowID:               flow,
		InstanceID:           InstanceID{1},
		Caps:                 CapsPacketMode,
		InitialTargetID:      manifest.RootID,
		ReceiveFrameCapacity: 1088,
		LocalTXManifest:      manifest,
	}
	wire, err := hello.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decodedHello, err := DecodeHello(wire)
	if err != nil {
		t.Fatal(err)
	}
	if decodedHello.ReceiveFrameCapacity != hello.ReceiveFrameCapacity {
		t.Fatalf("HELLO receive capacity=%d want=%d", decodedHello.ReceiveFrameCapacity, hello.ReceiveFrameCapacity)
	}

	ack := HelloAckPayload{
		Negotiation:                      testNegotiationFor(flow, manifest),
		FlowID:                           flow,
		InstanceID:                       InstanceID{2},
		Caps:                             CapsPacketMode,
		InitialTargetID:                  manifest.RootID,
		ReceiveFrameCapacity:             1238,
		AcceptedPeerReceiveFrameCapacity: hello.ReceiveFrameCapacity,
		AcceptedPeerBinding:              hello.Negotiation.GraphBinding(),
		AcceptedPeerTargetID:             manifest.RootID,
		LocalTXManifest:                  manifest,
	}
	ackWire, err := ack.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decodedAck, err := DecodeHelloAck(ackWire)
	if err != nil {
		t.Fatal(err)
	}
	if decodedAck.ReceiveFrameCapacity != ack.ReceiveFrameCapacity ||
		decodedAck.AcceptedPeerReceiveFrameCapacity != hello.ReceiveFrameCapacity {
		t.Fatalf("HELLO_ACK capacities=(%d,%d) want=(%d,%d)",
			decodedAck.ReceiveFrameCapacity, decodedAck.AcceptedPeerReceiveFrameCapacity,
			ack.ReceiveFrameCapacity, hello.ReceiveFrameCapacity)
	}

	hello.ReceiveFrameCapacity = 0
	if _, err := hello.Encode(); err == nil {
		t.Fatal("packet HELLO accepted missing receive capacity")
	}
	ack.AcceptedPeerReceiveFrameCapacity++
	if err := ack.ValidatePeerReceiveFrameCapacity(1088); err == nil {
		t.Fatal("HELLO_ACK accepted an inconsistent peer-capacity echo")
	}
}

func TestDirectionalPacketCapacityBridgeRoundTrip(t *testing.T) {
	tag := BridgeTagPayload{
		BridgeID:               [16]byte{1},
		AttachID:               [16]byte{2},
		InstanceID:             InstanceID{3},
		ExpectedPeerInstanceID: InstanceID{4},
		SessionEpoch:           SessionEpoch([16]byte{1}),
		Direction:              SenderDirectionClientToServer,
		GraphRevision:          1,
		GraphDigest:            GraphDigest{5},
		TargetID:               TargetID{6},
		ReceiveFrameCapacity:   1096,
	}
	tagWire := tag.Encode()
	decodedTag, err := DecodeBridgeTag(tagWire)
	if err != nil {
		t.Fatal(err)
	}
	if decodedTag.ReceiveFrameCapacity != tag.ReceiveFrameCapacity {
		t.Fatalf("BRIDGE_TAG receive capacity=%d want=%d", decodedTag.ReceiveFrameCapacity, tag.ReceiveFrameCapacity)
	}

	ack := BridgeAckPayload{
		BridgeID:                         tag.BridgeID,
		AttachID:                         tag.AttachID,
		InstanceID:                       InstanceID{4},
		SessionEpoch:                     tag.SessionEpoch,
		Direction:                        tag.Direction,
		GraphRevision:                    tag.GraphRevision,
		GraphDigest:                      tag.GraphDigest,
		TargetID:                         tag.TargetID,
		ResponderTargetID:                TargetID{7},
		ReceiveFrameCapacity:             1240,
		AcceptedPeerReceiveFrameCapacity: tag.ReceiveFrameCapacity,
		Code:                             AckOK,
	}
	ackWire := ack.Encode()
	decodedAck, err := DecodeBridgeAck(ackWire)
	if err != nil {
		t.Fatal(err)
	}
	if decodedAck.ReceiveFrameCapacity != ack.ReceiveFrameCapacity ||
		decodedAck.AcceptedPeerReceiveFrameCapacity != tag.ReceiveFrameCapacity {
		t.Fatalf("BRIDGE_ACK capacities=(%d,%d) want=(%d,%d)",
			decodedAck.ReceiveFrameCapacity, decodedAck.AcceptedPeerReceiveFrameCapacity,
			ack.ReceiveFrameCapacity, tag.ReceiveFrameCapacity)
	}
	if err := decodedAck.ValidatePeerReceiveFrameCapacity(tag.ReceiveFrameCapacity + 1); err == nil {
		t.Fatal("BRIDGE_ACK accepted an inconsistent peer-capacity echo")
	}
}

func TestPacketControlFrameBoundsClassifyEveryControlCode(t *testing.T) {
	for code := CtrlHello; code < CtrlCodeLimit; code++ {
		bound, ok := PacketControlFrameBoundFor(code, GraphManifestMaxNodes)
		if !ok {
			t.Fatalf("control code %s (0x%02x) has no packet-frame classification", code, byte(code))
		}
		if bound.Class != PacketControlStreamOnly && bound.MaxFrameSize <= HeaderSize {
			t.Fatalf("control code %s has invalid frame bound %+v", code, bound)
		}
	}

	tests := []struct {
		code  CtrlCode
		class PacketControlClass
		want  int
	}{
		{CtrlHello, PacketControlHandshakeOnly, HeaderSize + HelloPayloadSize + GraphManifestMaxWireBytes},
		{CtrlHelloAck, PacketControlHandshakeOnly, HeaderSize + HelloAckPayloadSize + GraphManifestMaxWireBytes},
		{CtrlBridgeTag, PacketControlHandshakeOnly, HeaderSize + BridgeTagPayloadSize},
		{CtrlBridgeAck, PacketControlHandshakeOnly, HeaderSize + BridgeAckMaxSize},
		{CtrlPathProbeReply, PacketControlRuntime, HeaderSize + AckPayloadSize},
		{CtrlPathAdmissionAck, PacketControlRuntime, HeaderSize + PathAdmissionAckMaxSize},
		{CtrlPolicyPrepare, PacketControlRuntime, HeaderSize + PolicyPrepareHeaderSize + PolicyMaxCauseBytes},
		{CtrlPolicyAck, PacketControlRuntime, HeaderSize + PolicyAckHeaderSize + PolicyMaxReasonBytes},
		{CtrlLeafMobilityAck, PacketControlRuntime, HeaderSize + LeafMobilityPeerPlanAckMaxSize},
		{CtrlPathRetire, PacketControlRuntime, HeaderSize + PathRetirementPayloadSize},
		{CtrlSelectorState, PacketControlGraphDependent, HeaderSize + SelectorStateMaxWireBytes},
		{CtrlStreamFin, PacketControlStreamOnly, HeaderSize},
	}
	for _, test := range tests {
		bound, ok := PacketControlFrameBoundFor(test.code, GraphManifestMaxNodes)
		if !ok || bound.Class != test.class || bound.MaxFrameSize != test.want {
			t.Fatalf("%s bound=%+v/%t want class=%d size=%d", test.code, bound, ok, test.class, test.want)
		}
	}
}

func TestPacketControlFrameBoundsCoverActualMaximumEncodings(t *testing.T) {
	type encodedControl struct {
		payload       []byte
		selectorCount int
		exact         bool
	}
	controls := make(map[CtrlCode]encodedControl, int(CtrlCodeLimit)-1)
	add := func(code CtrlCode, payload []byte, selectorCount int, exact bool) {
		t.Helper()
		if _, exists := controls[code]; exists {
			t.Fatalf("duplicate encoder fixture for %s", code)
		}
		controls[code] = encodedControl{payload: payload, selectorCount: selectorCount, exact: exact}
	}
	mustEncode := func(code CtrlCode, encode func() ([]byte, error)) []byte {
		t.Helper()
		payload, err := encode()
		if err != nil {
			t.Fatalf("encode %s: %v", code, err)
		}
		return payload
	}

	flow := [16]byte{0x31}
	manifest := testGraphManifest("packet-control-encoder")
	initial, ok := manifest.NodeByName("packet-control-encoder")
	if !ok {
		t.Fatal("packet handshake fixture lost its initial path")
	}
	negotiation := testNegotiationFor(flow, manifest)
	hello := HelloPayload{
		Negotiation: negotiation, FlowID: flow, InstanceID: InstanceID{1},
		Caps: CapsPacketMode, InitialTargetID: initial.ID, ReceiveFrameCapacity: 1400,
		LocalTXManifest: manifest,
	}
	add(CtrlHello, mustEncode(CtrlHello, hello.Encode), 0, false)
	helloAck := HelloAckPayload{
		Negotiation: negotiation, FlowID: flow, InstanceID: InstanceID{2},
		Caps: CapsPacketMode, InitialTargetID: initial.ID,
		AcceptedPeerBinding: negotiation.GraphBinding(), AcceptedPeerTargetID: initial.ID,
		ReceiveFrameCapacity: 1500, AcceptedPeerReceiveFrameCapacity: hello.ReceiveFrameCapacity,
		LocalTXManifest: manifest,
	}
	add(CtrlHelloAck, mustEncode(CtrlHelloAck, helloAck.Encode), 0, false)

	add(CtrlMigrateNotify, (MigrateNotifyPayload{NewPathID: 1}).Encode(), 0, true)
	add(CtrlPathQuality, (PathQualityPayload{RTTus: 1, JitterUs: 2, LossPP: 3}).Encode(), 0, true)
	add(CtrlHeartbeat, (HeartbeatPayload{Timestamp: 1}).Encode(), 0, true)
	add(CtrlBye, (ByePayload{Reason: ByeAppRequest}).Encode(), 0, true)
	add(CtrlPathProbe, (ProbePayload{TS: 1, ID: 2}).Encode(), 0, true)
	add(CtrlPathProbeReply, (AckPayload{
		SessionEpoch: SessionEpoch{1}, Direction: SenderDirectionClientToServer,
		GraphRevision: 1, GraphDigest: GraphDigest{2}, NextSeq: 3, Proof: AckProof{4},
	}).Encode(), 0, true)

	policyBinding := testPolicyBinding()
	policyPrepare := PolicyPrepare{
		PolicyTransactionBinding: policyBinding,
		BaseGeneration:           1,
		Action:                   PolicyActionSelectChild,
		SelectorID:               TargetID{1},
		TargetID:                 TargetID{2},
		Cause:                    strings.Repeat("c", PolicyMaxCauseBytes),
	}
	add(CtrlPolicyPrepare, mustEncode(CtrlPolicyPrepare, policyPrepare.Encode), 0, true)
	policyAck := PolicyAck{
		PolicyTransactionBinding: policyBinding,
		Phase:                    PolicyAckPhasePrepare,
		Code:                     PolicyAckCodeReject,
		ProposalDigest:           PolicyProposalDigest{1},
		Reason:                   strings.Repeat("r", PolicyMaxReasonBytes),
	}
	add(CtrlPolicyAck, mustEncode(CtrlPolicyAck, policyAck.Encode), 0, true)
	policyCommit := PolicyCommit{
		PolicyTransactionBinding: policyBinding,
		Generation:               1,
		ProposalDigest:           PolicyProposalDigest{1},
		ReservationID:            PolicyReservationID{2},
		CommitChallenge:          PolicyCommitChallenge{3},
	}
	add(CtrlPolicyCommit, mustEncode(CtrlPolicyCommit, policyCommit.Encode), 0, true)

	pathBinding := testPathAdmissionBinding()
	pathCommit := PathAdmissionCommit{PathAdmissionBinding: pathBinding, Phase: PathAdmissionPhaseCommit}
	add(CtrlPathAdmissionCommit, mustEncode(CtrlPathAdmissionCommit, pathCommit.Encode), 0, true)
	pathAck := PathAdmissionAck{
		PathAdmissionBinding: pathBinding,
		Phase:                PathAdmissionPhaseFinal,
		Code:                 AckRejectProtoState,
		Reason:               strings.Repeat("r", PathAdmissionMaxReasonBytes),
	}
	add(CtrlPathAdmissionAck, mustEncode(CtrlPathAdmissionAck, pathAck.Encode), 0, true)
	pathGeneration, err := pathBinding.CommittedGeneration()
	if err != nil {
		t.Fatal(err)
	}
	pathConfirm := PathAdmissionConfirm{PathAdmissionBinding: pathBinding, CommittedGeneration: pathGeneration}
	add(CtrlPathAdmissionConfirm, mustEncode(CtrlPathAdmissionConfirm, pathConfirm.Encode), 0, true)

	retirement := PathRetirementPayload{
		SessionEpoch: SessionEpoch{1}, Direction: SenderDirectionClientToServer,
		Reason:              PathRetirementReasonAdministrative,
		SenderGraphRevision: 1, SenderGraphDigest: GraphDigest{2}, SenderTargetID: TargetID{3},
		ReceiverGraphRevision: 4, ReceiverGraphDigest: GraphDigest{5}, ReceiverTargetID: TargetID{6},
		RouteGeneration: 7,
	}
	add(CtrlPathRetire, mustEncode(CtrlPathRetire, retirement.Encode), 0, true)

	bridgeTag := BridgeTagPayload{
		BridgeID: [16]byte{1}, AttachID: [16]byte{2}, InstanceID: InstanceID{3},
		ExpectedPeerInstanceID: InstanceID{4}, SessionEpoch: SessionEpoch{1},
		Direction: SenderDirectionClientToServer, GraphRevision: 1,
		GraphDigest: GraphDigest{5}, TargetID: TargetID{6}, ReceiveFrameCapacity: 1400,
	}
	add(CtrlBridgeTag, bridgeTag.Encode(), 0, true)
	bridgeAck := BridgeAckPayload{
		BridgeID: bridgeTag.BridgeID, AttachID: bridgeTag.AttachID, InstanceID: InstanceID{4},
		SessionEpoch: bridgeTag.SessionEpoch, Direction: bridgeTag.Direction,
		GraphRevision: bridgeTag.GraphRevision, GraphDigest: bridgeTag.GraphDigest,
		TargetID: bridgeTag.TargetID, ResponderTargetID: TargetID{7},
		ReceiveFrameCapacity: 1500, AcceptedPeerReceiveFrameCapacity: bridgeTag.ReceiveFrameCapacity,
		Code: AckRejectProtoState, Reason: strings.Repeat("r", 255),
	}
	add(CtrlBridgeAck, bridgeAck.Encode(), 0, true)

	leafPrepare := testLeafMobilityPeerPlanPrepare()
	add(CtrlLeafMobilityPrepare, mustEncode(CtrlLeafMobilityPrepare, leafPrepare.Encode), 0, true)
	leafAck := testLeafMobilityPeerPlanPreparedAckFor(t, leafPrepare)
	leafAck.Code = LeafMobilityPeerPlanAckCodeReject
	leafAck.Generation = 0
	leafAck.PeerEndpointGeneration = 0
	leafAck.PeerPlanDigest = LeafMobilityPeerDigest{}
	leafAck.AgreementDigest = LeafMobilityAgreementDigest{}
	leafAck.ReservationID = LeafMobilityReservationID{}
	leafAck.Reason = strings.Repeat("r", LeafMobilityPeerPlanMaxReasonBytes)
	add(CtrlLeafMobilityAck, mustEncode(CtrlLeafMobilityAck, leafAck.Encode), 0, true)
	leafCommit := testLeafMobilityPeerPlanCommit(t)
	add(CtrlLeafMobilityCommit, mustEncode(CtrlLeafMobilityCommit, leafCommit.Encode), 0, true)

	selectorManifest, selectorBinding, selectorState := nestedSelectorStateFixture(t)
	selectorWire := mustEncode(CtrlSelectorState, func() ([]byte, error) {
		return EncodeSelectorState(selectorState, selectorManifest, selectorBinding)
	})
	add(CtrlSelectorState, selectorWire, len(selectorState.Entries), true)
	add(CtrlStreamFin, nil, 0, true)

	for code := CtrlHello; code < CtrlCodeLimit; code++ {
		control, exists := controls[code]
		if !exists {
			t.Fatalf("control code %s (0x%02x) has no actual encoder fixture", code, byte(code))
		}
		frame := make([]byte, HeaderSize+len(control.payload))
		if err := (Header{Version: Version, Type: FrameCtrl, Flags: FlagsForCtrl(code)}).Encode(frame); err != nil {
			t.Fatalf("encode %s header: %v", code, err)
		}
		copy(frame[HeaderSize:], control.payload)
		bound, ok := PacketControlFrameBoundFor(code, control.selectorCount)
		if !ok {
			t.Fatalf("control code %s has no bound", code)
		}
		if control.exact && len(frame) != bound.MaxFrameSize {
			t.Fatalf("%s actual maximum frame=%d bound=%d", code, len(frame), bound.MaxFrameSize)
		}
		if !control.exact && len(frame) > bound.MaxFrameSize {
			t.Fatalf("%s legal handshake frame=%d exceeds bound=%d", code, len(frame), bound.MaxFrameSize)
		}
	}
}
