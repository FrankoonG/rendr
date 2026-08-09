package proto

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

func testLeafMobilityPeerPlanBinding() LeafMobilityPeerPlanBinding {
	return LeafMobilityPeerPlanBinding{
		CoordinatorSide: LeafMobilityActorClient,
		ActorSide:       LeafMobilityActorClient,
		Direction:       SenderDirectionClientToServer,
		SessionKind:     LeafMobilitySessionStream,
		Operation:       LeafMobilityOperationTCPRepair,
		Fallback:        LeafMobilityFallbackRedialAttach,
		LeaseMillis:     LeafMobilityPeerPlanMaxLeaseMillis,
		SessionEpoch:    SessionEpoch{0x11, 0x12},
		TransactionID:   [16]byte{0x21, 0x22},
		ClientGraph:     GraphBinding{Revision: 3, Digest: GraphDigest{0x31, 0x32}},
		ServerGraph:     GraphBinding{Revision: 4, Digest: GraphDigest{0x41, 0x42}},
		ClientTargetID:  TargetID{0x51, 0x52},
		ServerTargetID:  TargetID{0x61, 0x62},
		BaseGeneration:  7,
		ResourceScope:   LeafMobilityResourceEndpoint,
		ResourceID:      LeafMobilityResourceID{0x63, 0x64},
		RouteGeneration: 9,
	}
}

func testLeafMobilityPeerPlanPrepare() LeafMobilityPeerPlanPrepare {
	return LeafMobilityPeerPlanPrepare{
		LeafMobilityPeerPlanBinding: testLeafMobilityPeerPlanBinding(),
		ActorEndpointGeneration:     11,
		ActorPlanDigest:             LeafMobilityPlanDigest{0x71, 0x72},
	}
}

func testLeafMobilityPeerPlanPreparedAck(t testing.TB) LeafMobilityPeerPlanAck {
	t.Helper()
	return testLeafMobilityPeerPlanPreparedAckFor(t, testLeafMobilityPeerPlanPrepare())
}

func testLeafMobilityPeerPlanPreparedAckFor(t testing.TB, prepare LeafMobilityPeerPlanPrepare) LeafMobilityPeerPlanAck {
	t.Helper()
	proposal, err := prepare.ProposalDigest()
	if err != nil {
		t.Fatal(err)
	}
	reservation := LeafMobilityReservationID{0x81, 0x82}
	peerDigest := LeafMobilityPeerDigest{0x91, 0x92}
	generation, _ := prepare.ReservedGeneration()
	agreement, err := ComputeLeafMobilityAgreementDigest(
		prepare.LeafMobilityPeerPlanBinding,
		generation,
		prepare.ActorEndpointGeneration,
		13,
		proposal,
		peerDigest,
		reservation,
	)
	if err != nil {
		t.Fatal(err)
	}
	return LeafMobilityPeerPlanAck{
		LeafMobilityPeerPlanBinding: prepare.LeafMobilityPeerPlanBinding,
		Phase:                       LeafMobilityPeerPlanAckPhasePrepared,
		Code:                        LeafMobilityPeerPlanAckCodeAccept,
		CurrentGeneration:           prepare.BaseGeneration,
		Generation:                  generation,
		ActorEndpointGeneration:     prepare.ActorEndpointGeneration,
		PeerEndpointGeneration:      13,
		ProposalDigest:              proposal,
		PeerPlanDigest:              peerDigest,
		AgreementDigest:             agreement,
		ReservationID:               reservation,
	}
}

func testLeafMobilityPeerPlanCommit(t testing.TB) LeafMobilityPeerPlanCommit {
	t.Helper()
	return testLeafMobilityPeerPlanCommitForAck(testLeafMobilityPeerPlanPreparedAck(t))
}

func testLeafMobilityPeerPlanCommitForAck(ack LeafMobilityPeerPlanAck) LeafMobilityPeerPlanCommit {
	return LeafMobilityPeerPlanCommit{
		LeafMobilityPeerPlanBinding: ack.LeafMobilityPeerPlanBinding,
		Stage:                       LeafMobilityPeerPlanCommitStageCommit,
		Generation:                  ack.Generation,
		ActorEndpointGeneration:     ack.ActorEndpointGeneration,
		PeerEndpointGeneration:      ack.PeerEndpointGeneration,
		ProposalDigest:              ack.ProposalDigest,
		PeerPlanDigest:              ack.PeerPlanDigest,
		AgreementDigest:             ack.AgreementDigest,
		ReservationID:               ack.ReservationID,
	}
}

func TestLeafMobilityPeerPlanRoundTripAndAgreement(t *testing.T) {
	prepare := testLeafMobilityPeerPlanPrepare()
	prepareWire, err := prepare.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(prepareWire) != LeafMobilityPeerPlanPrepareSize || !bytes.Equal(prepareWire[:4], leafMobilityPeerPlanMagic[:]) {
		t.Fatalf("prepare envelope size=%d magic=%x", len(prepareWire), prepareWire[:4])
	}
	decodedPrepare, err := DecodeLeafMobilityPeerPlanPrepare(prepareWire)
	if err != nil || decodedPrepare != prepare {
		t.Fatalf("decoded prepare=%+v err=%v", decodedPrepare, err)
	}

	prepared := testLeafMobilityPeerPlanPreparedAck(t)
	ackWire, err := prepared.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decodedAck, err := DecodeLeafMobilityPeerPlanAck(ackWire)
	if err != nil || decodedAck != prepared {
		t.Fatalf("decoded prepared ACK=%+v err=%v", decodedAck, err)
	}
	if err := decodedAck.ValidateForPrepare(decodedPrepare); err != nil {
		t.Fatalf("prepared ACK validation: %v", err)
	}

	commit := testLeafMobilityPeerPlanCommit(t)
	commitWire, err := commit.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decodedCommit, err := DecodeLeafMobilityPeerPlanCommit(commitWire)
	if err != nil || decodedCommit != commit {
		t.Fatalf("decoded commit=%+v err=%v", decodedCommit, err)
	}
	if err := decodedCommit.ValidateForPrepared(decodedPrepare, decodedAck); err != nil {
		t.Fatalf("commit validation: %v", err)
	}

	final := prepared
	final.Phase = LeafMobilityPeerPlanAckPhaseFinal
	final.Stage = LeafMobilityPeerPlanCommitStageCommit
	final.CurrentGeneration = final.Generation
	finalWire, err := final.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decodedFinal, err := DecodeLeafMobilityPeerPlanAck(finalWire)
	if err != nil || decodedFinal != final {
		t.Fatalf("decoded final ACK=%+v err=%v", decodedFinal, err)
	}
	if err := decodedFinal.ValidateForCommit(decodedCommit); err != nil {
		t.Fatalf("final ACK validation: %v", err)
	}
}

func TestLeafMobilityExecutionResolutionRoundTrip(t *testing.T) {
	prepare := testLeafMobilityPeerPlanPrepare()
	prepared := testLeafMobilityPeerPlanPreparedAckFor(t, prepare)
	commit := testLeafMobilityPeerPlanCommitForAck(prepared)
	final := prepared
	final.Phase = LeafMobilityPeerPlanAckPhaseFinal
	final.Stage = LeafMobilityPeerPlanCommitStageCommit
	final.CurrentGeneration = final.Generation
	if err := final.ValidateForCommit(commit); err != nil {
		t.Fatal(err)
	}

	for _, stage := range []LeafMobilityPeerPlanCommitStage{
		LeafMobilityPeerPlanCommitStageComplete,
		LeafMobilityPeerPlanCommitStageRolledBack,
		LeafMobilityPeerPlanCommitStageAbort,
	} {
		t.Run(fmt.Sprintf("stage-%d", stage), func(t *testing.T) {
			resolution := commit
			resolution.Stage = stage
			wire, err := resolution.Encode()
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeLeafMobilityPeerPlanCommit(wire)
			if err != nil || decoded != resolution {
				t.Fatalf("decoded resolution=%+v err=%v", decoded, err)
			}
			if err := decoded.ValidateForPrepared(prepare, prepared); err != nil {
				t.Fatal(err)
			}

			released := prepared
			released.Phase = LeafMobilityPeerPlanAckPhaseReleased
			released.Stage = stage
			released.CurrentGeneration = released.Generation
			ackWire, err := released.Encode()
			if err != nil {
				t.Fatal(err)
			}
			decodedAck, err := DecodeLeafMobilityPeerPlanAck(ackWire)
			if err != nil || decodedAck != released {
				t.Fatalf("decoded RELEASED=%+v err=%v", decodedAck, err)
			}
			if err := decodedAck.ValidateForCommit(decoded); err != nil {
				t.Fatal(err)
			}
		})
	}

	wrong := final
	wrong.Phase = LeafMobilityPeerPlanAckPhaseReleased
	wrong.Stage = LeafMobilityPeerPlanCommitStageComplete
	if err := wrong.ValidateForCommit(commit); err == nil {
		t.Fatal("RELEASED receipt authorized the COMMIT stage")
	}
}

func TestLeafMobilityCtrlFlagsAreCanonical(t *testing.T) {
	for _, code := range []CtrlCode{
		CtrlLeafMobilityPrepare,
		CtrlLeafMobilityAck,
		CtrlLeafMobilityCommit,
	} {
		t.Run(code.String(), func(t *testing.T) {
			flags := FlagsForCtrl(code)
			if err := ValidateLeafMobilityCtrlFlags(flags); err != nil {
				t.Fatalf("canonical flags rejected: %v", err)
			}
			for _, reserved := range []uint16{0x0100, 0x0800, 0x1000} {
				if err := ValidateLeafMobilityCtrlFlags(flags | reserved); err == nil {
					t.Fatalf("reserved flags 0x%04x accepted", reserved)
				}
			}
		})
	}

	if err := ValidateLeafMobilityCtrlFlags(FlagsForCtrl(CtrlPolicyPrepare)); err == nil {
		t.Fatal("non-leaf transaction control accepted")
	}
}

func TestLeafMobilityProposalDigestBindsEverySemanticField(t *testing.T) {
	tests := []struct {
		name  string
		left  func(*LeafMobilityPeerPlanPrepare)
		right func(*LeafMobilityPeerPlanPrepare)
	}{
		{
			name: "actor side",
			right: func(p *LeafMobilityPeerPlanPrepare) {
				p.ActorSide = LeafMobilityActorServer
			},
		},
		{name: "direction", right: func(p *LeafMobilityPeerPlanPrepare) { p.Direction = SenderDirectionServerToClient }},
		{
			name: "QUIC stream and packet session",
			left: func(p *LeafMobilityPeerPlanPrepare) {
				p.Operation = LeafMobilityOperationQUICCIDRebind
				p.SessionKind = LeafMobilitySessionStream
			},
			right: func(p *LeafMobilityPeerPlanPrepare) {
				p.Operation = LeafMobilityOperationQUICCIDRebind
				p.SessionKind = LeafMobilitySessionPacket
			},
		},
		{name: "operation", right: func(p *LeafMobilityPeerPlanPrepare) { p.Operation = LeafMobilityOperationQUICCIDRebind }},
		{name: "lease", right: func(p *LeafMobilityPeerPlanPrepare) { p.LeaseMillis-- }},
		{name: "epoch", right: func(p *LeafMobilityPeerPlanPrepare) { p.SessionEpoch[2] ^= 0xff }},
		{name: "transaction", right: func(p *LeafMobilityPeerPlanPrepare) { p.TransactionID[2] ^= 0xff }},
		{name: "client revision", right: func(p *LeafMobilityPeerPlanPrepare) { p.ClientGraph.Revision++ }},
		{name: "client graph", right: func(p *LeafMobilityPeerPlanPrepare) { p.ClientGraph.Digest[2] ^= 0xff }},
		{name: "server revision", right: func(p *LeafMobilityPeerPlanPrepare) { p.ServerGraph.Revision++ }},
		{name: "server graph", right: func(p *LeafMobilityPeerPlanPrepare) { p.ServerGraph.Digest[2] ^= 0xff }},
		{name: "client target", right: func(p *LeafMobilityPeerPlanPrepare) { p.ClientTargetID[2] ^= 0xff }},
		{name: "server target", right: func(p *LeafMobilityPeerPlanPrepare) { p.ServerTargetID[2] ^= 0xff }},
		{name: "base generation", right: func(p *LeafMobilityPeerPlanPrepare) { p.BaseGeneration++ }},
		{name: "resource scope", right: func(p *LeafMobilityPeerPlanPrepare) { p.ResourceScope = LeafMobilityResourceSharedLink }},
		{name: "resource id", right: func(p *LeafMobilityPeerPlanPrepare) { p.ResourceID[2] ^= 0xff }},
		{name: "endpoint generation", right: func(p *LeafMobilityPeerPlanPrepare) { p.ActorEndpointGeneration++ }},
		{name: "actor plan", right: func(p *LeafMobilityPeerPlanPrepare) { p.ActorPlanDigest[2] ^= 0xff }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			left := testLeafMobilityPeerPlanPrepare()
			if test.left != nil {
				test.left(&left)
			}
			right := testLeafMobilityPeerPlanPrepare()
			if test.right != nil {
				test.right(&right)
			}
			assertValidLeafMobilitySemanticDigestsDiffer(t, left, right)
		})
	}

	invalidFallback := testLeafMobilityPeerPlanPrepare()
	invalidFallback.Fallback = LeafMobilityFallbackInvalid
	if _, err := invalidFallback.ProposalDigest(); err == nil {
		t.Fatal("invalid fallback entered proposal digest")
	}
}

func assertValidLeafMobilitySemanticDigestsDiffer(
	t *testing.T,
	left LeafMobilityPeerPlanPrepare,
	right LeafMobilityPeerPlanPrepare,
) {
	t.Helper()
	if err := left.validate(); err != nil {
		t.Fatalf("left prepare is not valid: %v", err)
	}
	if err := right.validate(); err != nil {
		t.Fatalf("right prepare is not valid: %v", err)
	}
	leftProposal, err := left.ProposalDigest()
	if err != nil {
		t.Fatal(err)
	}
	rightProposal, err := right.ProposalDigest()
	if err != nil {
		t.Fatal(err)
	}
	if leftProposal == rightProposal {
		t.Fatal("valid semantic alternatives have the same proposal digest")
	}

	peerDigest := LeafMobilityPeerDigest{0xa1, 0xa2}
	reservation := LeafMobilityReservationID{0xb1, 0xb2}
	leftGeneration, err := left.ReservedGeneration()
	if err != nil {
		t.Fatal(err)
	}
	rightGeneration, err := right.ReservedGeneration()
	if err != nil {
		t.Fatal(err)
	}
	leftAgreement, err := ComputeLeafMobilityAgreementDigest(
		left.LeafMobilityPeerPlanBinding, leftGeneration, left.ActorEndpointGeneration, 13,
		leftProposal, peerDigest, reservation,
	)
	if err != nil {
		t.Fatal(err)
	}
	rightAgreement, err := ComputeLeafMobilityAgreementDigest(
		right.LeafMobilityPeerPlanBinding, rightGeneration, right.ActorEndpointGeneration, 13,
		rightProposal, peerDigest, reservation,
	)
	if err != nil {
		t.Fatal(err)
	}
	if leftAgreement == rightAgreement {
		t.Fatal("valid semantic alternatives have the same agreement digest")
	}
}

func TestLeafMobilityAgreementDigestDirectlyBindsValidSideAndQUICSessionAlternatives(t *testing.T) {
	tests := []struct {
		name  string
		left  func(*LeafMobilityPeerPlanPrepare)
		right func(*LeafMobilityPeerPlanPrepare)
	}{
		{
			name: "actor side",
			right: func(p *LeafMobilityPeerPlanPrepare) {
				p.ActorSide = LeafMobilityActorServer
			},
		},
		{
			name: "QUIC stream and packet session",
			left: func(p *LeafMobilityPeerPlanPrepare) {
				p.Operation = LeafMobilityOperationQUICCIDRebind
				p.SessionKind = LeafMobilitySessionStream
			},
			right: func(p *LeafMobilityPeerPlanPrepare) {
				p.Operation = LeafMobilityOperationQUICCIDRebind
				p.SessionKind = LeafMobilitySessionPacket
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			left := testLeafMobilityPeerPlanPrepare()
			if test.left != nil {
				test.left(&left)
			}
			right := testLeafMobilityPeerPlanPrepare()
			if test.right != nil {
				test.right(&right)
			}
			if err := left.validate(); err != nil {
				t.Fatalf("left prepare is not valid: %v", err)
			}
			if err := right.validate(); err != nil {
				t.Fatalf("right prepare is not valid: %v", err)
			}

			// Keep all opaque evidence identical so this comparison isolates the
			// canonical binding encoded directly into the agreement digest.
			proposal := LeafMobilityProposalDigest{0xc1, 0xc2}
			peerDigest := LeafMobilityPeerDigest{0xd1, 0xd2}
			reservation := LeafMobilityReservationID{0xe1, 0xe2}
			leftGeneration, err := left.ReservedGeneration()
			if err != nil {
				t.Fatal(err)
			}
			rightGeneration, err := right.ReservedGeneration()
			if err != nil {
				t.Fatal(err)
			}
			leftAgreement, err := ComputeLeafMobilityAgreementDigest(
				left.LeafMobilityPeerPlanBinding, leftGeneration, 11, 13,
				proposal, peerDigest, reservation,
			)
			if err != nil {
				t.Fatal(err)
			}
			rightAgreement, err := ComputeLeafMobilityAgreementDigest(
				right.LeafMobilityPeerPlanBinding, rightGeneration, 11, 13,
				proposal, peerDigest, reservation,
			)
			if err != nil {
				t.Fatal(err)
			}
			if leftAgreement == rightAgreement {
				t.Fatal("valid binding alternatives have the same agreement digest")
			}
		})
	}
}

func TestLeafMobilityPeerPlanRejectsUnsupportedV1Semantics(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*LeafMobilityPeerPlanPrepare)
	}{
		{name: "non-client coordinator", mutate: func(p *LeafMobilityPeerPlanPrepare) { p.CoordinatorSide = LeafMobilityActorServer }},
		{name: "TCP repair packet", mutate: func(p *LeafMobilityPeerPlanPrepare) { p.SessionKind = LeafMobilitySessionPacket }},
		{name: "UDP flow stream", mutate: func(p *LeafMobilityPeerPlanPrepare) {
			p.Operation = LeafMobilityOperationUDPFlowRebind
			p.SessionKind = LeafMobilitySessionStream
		}},
		{name: "gVisor packet", mutate: func(p *LeafMobilityPeerPlanPrepare) {
			p.Operation = LeafMobilityOperationGVisorLinkRebind
			p.SessionKind = LeafMobilitySessionPacket
		}},
		{name: "zero resource", mutate: func(p *LeafMobilityPeerPlanPrepare) { p.ResourceID = LeafMobilityResourceID{} }},
		{name: "invalid resource scope", mutate: func(p *LeafMobilityPeerPlanPrepare) { p.ResourceScope = LeafMobilityResourceInvalid }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepare := testLeafMobilityPeerPlanPrepare()
			test.mutate(&prepare)
			if _, err := prepare.Encode(); err == nil {
				t.Fatal("unsupported v1 peer-plan semantics encoded")
			}
		})
	}

	for _, session := range []LeafMobilitySessionKind{LeafMobilitySessionStream, LeafMobilitySessionPacket} {
		prepare := testLeafMobilityPeerPlanPrepare()
		prepare.Operation = LeafMobilityOperationQUICCIDRebind
		prepare.SessionKind = session
		if _, err := prepare.Encode(); err != nil {
			t.Fatalf("QUIC session kind %d: %v", session, err)
		}
	}
}

func TestLeafMobilityPeerPlanCanonicalizesClientAndServerViews(t *testing.T) {
	want := testLeafMobilityPeerPlanBinding()
	clientView := LeafMobilityPeerPlanView{
		LocalSide:       LeafMobilityActorClient,
		CoordinatorSide: want.CoordinatorSide,
		ActorSide:       want.ActorSide,
		Direction:       want.Direction,
		SessionKind:     want.SessionKind,
		Operation:       want.Operation,
		Fallback:        want.Fallback,
		LeaseMillis:     want.LeaseMillis,
		SessionEpoch:    want.SessionEpoch,
		TransactionID:   want.TransactionID,
		LocalGraph:      want.ClientGraph,
		PeerGraph:       want.ServerGraph,
		LocalTargetID:   want.ClientTargetID,
		PeerTargetID:    want.ServerTargetID,
		BaseGeneration:  want.BaseGeneration,
		ResourceScope:   want.ResourceScope,
		ResourceID:      want.ResourceID,
		RouteGeneration: want.RouteGeneration,
	}
	serverView := clientView
	serverView.LocalSide = LeafMobilityActorServer
	serverView.LocalGraph, serverView.PeerGraph = want.ServerGraph, want.ClientGraph
	serverView.LocalTargetID, serverView.PeerTargetID = want.ServerTargetID, want.ClientTargetID
	clientBinding, err := clientView.CanonicalBinding()
	if err != nil {
		t.Fatal(err)
	}
	serverBinding, err := serverView.CanonicalBinding()
	if err != nil {
		t.Fatal(err)
	}
	if clientBinding != want || serverBinding != want || clientBinding != serverBinding {
		t.Fatalf("canonical bindings differ:\nclient=%+v\nserver=%+v\nwant=%+v", clientBinding, serverBinding, want)
	}
	clientWire, _ := encodeLeafMobilityPeerPlanBinding(clientBinding, leafMobilityPeerPlanMessagePrepare)
	serverWire, _ := encodeLeafMobilityPeerPlanBinding(serverBinding, leafMobilityPeerPlanMessagePrepare)
	if !bytes.Equal(clientWire, serverWire) {
		t.Fatal("client/server canonical binding bytes differ")
	}
	if clientBinding.LeaseKey() != serverBinding.LeaseKey() {
		t.Fatal("client/server lease keys differ")
	}
}

func TestLeafMobilityAgreementBindsDifferentEndpointFacts(t *testing.T) {
	prepare := testLeafMobilityPeerPlanPrepare()
	proposal, _ := prepare.ProposalDigest()
	binding := prepare.LeafMobilityPeerPlanBinding
	generation, _ := binding.ReservedGeneration()
	peerDigest := LeafMobilityPeerDigest{0xa1}
	reservation := LeafMobilityReservationID{0xb1}
	want, err := ComputeLeafMobilityAgreementDigest(binding, generation, 11, 13, proposal, peerDigest, reservation)
	if err != nil {
		t.Fatal(err)
	}
	if want == (LeafMobilityAgreementDigest{}) {
		t.Fatal("zero agreement digest")
	}
	tests := []struct {
		name  string
		build func() (LeafMobilityAgreementDigest, error)
	}{
		{"transaction generation", func() (LeafMobilityAgreementDigest, error) {
			changed := binding
			changed.BaseGeneration--
			return ComputeLeafMobilityAgreementDigest(changed, generation, 11, 13, proposal, peerDigest, reservation)
		}},
		{"actor endpoint", func() (LeafMobilityAgreementDigest, error) {
			return ComputeLeafMobilityAgreementDigest(binding, generation, 12, 13, proposal, peerDigest, reservation)
		}},
		{"peer endpoint", func() (LeafMobilityAgreementDigest, error) {
			return ComputeLeafMobilityAgreementDigest(binding, generation, 11, 14, proposal, peerDigest, reservation)
		}},
		{"proposal", func() (LeafMobilityAgreementDigest, error) {
			changed := proposal
			changed[0] ^= 0xff
			return ComputeLeafMobilityAgreementDigest(binding, generation, 11, 13, changed, peerDigest, reservation)
		}},
		{"peer plan", func() (LeafMobilityAgreementDigest, error) {
			changed := peerDigest
			changed[0] ^= 0xff
			return ComputeLeafMobilityAgreementDigest(binding, generation, 11, 13, proposal, changed, reservation)
		}},
		{"reservation", func() (LeafMobilityAgreementDigest, error) {
			changed := reservation
			changed[0] ^= 0xff
			return ComputeLeafMobilityAgreementDigest(binding, generation, 11, 13, proposal, peerDigest, changed)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.build()
			if err == nil && got == want {
				t.Fatal("agreement mutation was not bound")
			}
		})
	}
}

func TestLeafMobilityAgreementDoesNotSortEndpointPlans(t *testing.T) {
	actorPrepare := testLeafMobilityPeerPlanPrepare()
	actorPrepare.ActorPlanDigest = LeafMobilityPlanDigest{0xa1, 0xa2}
	actorProposal, err := actorPrepare.ProposalDigest()
	if err != nil {
		t.Fatal(err)
	}
	peerPlan := LeafMobilityPeerDigest{0xb1, 0xb2}
	reservation := LeafMobilityReservationID{0xc1}
	generation, _ := actorPrepare.ReservedGeneration()
	want, err := ComputeLeafMobilityAgreementDigest(actorPrepare.LeafMobilityPeerPlanBinding, generation, 11, 13, actorProposal, peerPlan, reservation)
	if err != nil {
		t.Fatal(err)
	}
	swappedPrepare := actorPrepare
	copy(swappedPrepare.ActorPlanDigest[:], peerPlan[:])
	swappedProposal, err := swappedPrepare.ProposalDigest()
	if err != nil {
		t.Fatal(err)
	}
	var swappedPeer LeafMobilityPeerDigest
	copy(swappedPeer[:], actorPrepare.ActorPlanDigest[:])
	swapped, err := ComputeLeafMobilityAgreementDigest(actorPrepare.LeafMobilityPeerPlanBinding, generation, 13, 11, swappedProposal, swappedPeer, reservation)
	if err != nil {
		t.Fatal(err)
	}
	if swapped == want {
		t.Fatal("actor and responder facts were order-insensitively hashed")
	}
}

func TestLeafMobilityPeerPlanStrictDecode(t *testing.T) {
	prepare, _ := testLeafMobilityPeerPlanPrepare().Encode()
	ack, _ := testLeafMobilityPeerPlanPreparedAck(t).Encode()
	commit, _ := testLeafMobilityPeerPlanCommit(t).Encode()
	zeroRoute := append([]byte(nil), prepare...)
	clear(zeroRoute[192:200])
	tests := []struct {
		name string
		wire []byte
		fn   func([]byte) error
	}{
		{"prepare short", prepare[:len(prepare)-1], func(b []byte) error { _, err := DecodeLeafMobilityPeerPlanPrepare(b); return err }},
		{"prepare trailing", append(append([]byte(nil), prepare...), 0), func(b []byte) error { _, err := DecodeLeafMobilityPeerPlanPrepare(b); return err }},
		{"prepare binding reserved", mutateLeafMobilityWire(prepare, 169), func(b []byte) error { _, err := DecodeLeafMobilityPeerPlanPrepare(b); return err }},
		{"prepare zero route generation", zeroRoute, func(b []byte) error { _, err := DecodeLeafMobilityPeerPlanPrepare(b); return err }},
		{"prepare version", mutateLeafMobilityWire(prepare, 4), func(b []byte) error { _, err := DecodeLeafMobilityPeerPlanPrepare(b); return err }},
		{"ACK short", ack[:LeafMobilityPeerPlanAckHeaderSize-1], func(b []byte) error { _, err := DecodeLeafMobilityPeerPlanAck(b); return err }},
		{"ACK trailing", append(append([]byte(nil), ack...), 0), func(b []byte) error { _, err := DecodeLeafMobilityPeerPlanAck(b); return err }},
		{"ACK phase reserved", mutateLeafMobilityWire(ack, LeafMobilityPeerPlanBindingSize+2), func(b []byte) error { _, err := DecodeLeafMobilityPeerPlanAck(b); return err }},
		{"ACK tail reserved", mutateLeafMobilityWire(ack, LeafMobilityPeerPlanBindingSize+154), func(b []byte) error { _, err := DecodeLeafMobilityPeerPlanAck(b); return err }},
		{"commit short", commit[:len(commit)-1], func(b []byte) error { _, err := DecodeLeafMobilityPeerPlanCommit(b); return err }},
		{"commit trailing", append(append([]byte(nil), commit...), 0), func(b []byte) error { _, err := DecodeLeafMobilityPeerPlanCommit(b); return err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.fn(test.wire); err == nil {
				t.Fatal("malformed peer-plan message was accepted")
			}
		})
	}

	reject := testLeafMobilityPeerPlanPreparedAck(t)
	reject.Code = LeafMobilityPeerPlanAckCodeReject
	reject.Generation = 0
	reject.PeerEndpointGeneration = 0
	reject.PeerPlanDigest = LeafMobilityPeerDigest{}
	reject.AgreementDigest = LeafMobilityAgreementDigest{}
	reject.ReservationID = LeafMobilityReservationID{}
	reject.Reason = string([]byte{0xff})
	if _, err := reject.Encode(); err == nil {
		t.Fatal("invalid UTF-8 rejection reason was accepted")
	}
}

func TestLeafMobilityPeerPlanCrossPhaseMutationRejected(t *testing.T) {
	prepare := testLeafMobilityPeerPlanPrepare()
	prepared := testLeafMobilityPeerPlanPreparedAck(t)
	commit := testLeafMobilityPeerPlanCommit(t)
	final := prepared
	final.Phase = LeafMobilityPeerPlanAckPhaseFinal
	final.Stage = LeafMobilityPeerPlanCommitStageCommit
	final.CurrentGeneration = final.Generation

	changedAck := prepared
	changedAck.ActorEndpointGeneration++
	if err := changedAck.ValidateForPrepare(prepare); err == nil {
		t.Fatal("mutated prepared ACK matched prepare")
	}
	changedCurrent := prepared
	changedCurrent.CurrentGeneration++
	if _, err := changedCurrent.Encode(); err == nil {
		t.Fatal("prepared ACK with mismatched current generation encoded")
	}
	changedCommit := commit
	changedCommit.ReservationID[0] ^= 0xff
	if err := changedCommit.ValidateForPrepared(prepare, prepared); err == nil {
		t.Fatal("mutated commit matched prepared ACK")
	}
	changedFinal := final
	changedFinal.PeerEndpointGeneration++
	if err := changedFinal.ValidateForCommit(commit); err == nil {
		t.Fatal("mutated final ACK matched commit")
	}
	if err := final.ValidateForPrepare(prepare); err == nil {
		t.Fatal("final ACK was accepted as prepared ACK")
	}
}

func TestLeafMobilityPreparedAckGenerationAndCorrelation(t *testing.T) {
	prepare := testLeafMobilityPeerPlanPrepare()
	otherPrepare := prepare
	otherPrepare.TransactionID[3] ^= 0xff
	tests := []struct {
		name   string
		code   LeafMobilityPeerPlanAckCode
		reason string
	}{
		{name: "accept", code: LeafMobilityPeerPlanAckCodeAccept},
		{name: "reject", code: LeafMobilityPeerPlanAckCodeReject, reason: "peer rejected the proposal"},
		{name: "busy", code: LeafMobilityPeerPlanAckCodeBusy, reason: "peer resource is busy"},
		{name: "stale", code: LeafMobilityPeerPlanAckCodeStale, reason: "proposal generation is stale"},
		{name: "superseded", code: LeafMobilityPeerPlanAckCodeSuperseded, reason: "proposal was superseded"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ack := testLeafMobilityPeerPlanPreparedAckFor(t, prepare)
			ack.Code = test.code
			ack.Reason = test.reason
			if test.code != LeafMobilityPeerPlanAckCodeAccept {
				ack.Generation = 0
				ack.PeerEndpointGeneration = 0
				ack.PeerPlanDigest = LeafMobilityPeerDigest{}
				ack.AgreementDigest = LeafMobilityAgreementDigest{}
				ack.ReservationID = LeafMobilityReservationID{}
			}

			wire, err := ack.Encode()
			if err != nil {
				t.Fatalf("valid prepared ACK did not encode: %v", err)
			}
			decoded, err := DecodeLeafMobilityPeerPlanAck(wire)
			if err != nil || decoded != ack {
				t.Fatalf("decoded prepared ACK=%+v err=%v", decoded, err)
			}
			if err := decoded.ValidateForPrepare(prepare); err != nil {
				t.Fatalf("valid prepared ACK did not correlate: %v", err)
			}

			objectMutation := decoded
			objectMutation.CurrentGeneration++
			if _, err := objectMutation.Encode(); err == nil {
				t.Fatal("prepared ACK object with non-base current generation encoded")
			}

			wireMutation := mutateLeafMobilityWire(wire, LeafMobilityPeerPlanBindingSize+15)
			if _, err := DecodeLeafMobilityPeerPlanAck(wireMutation); err == nil {
				t.Fatal("prepared ACK wire with non-base current generation decoded")
			}

			phaseMutation := decoded
			phaseMutation.Phase = LeafMobilityPeerPlanAckPhaseFinal
			phaseMutation.Stage = LeafMobilityPeerPlanCommitStageCommit
			if _, err := phaseMutation.Encode(); err == nil {
				t.Fatal("prepared ACK reclassified as final without reserved current generation")
			}
			if err := decoded.ValidateForPrepare(otherPrepare); err == nil {
				t.Fatal("prepared ACK correlated with a different transaction")
			}
		})
	}
}

func TestLeafMobilityPreparedRejectRequiresZeroPeerEndpointGeneration(t *testing.T) {
	for _, code := range []LeafMobilityPeerPlanAckCode{
		LeafMobilityPeerPlanAckCodeReject,
		LeafMobilityPeerPlanAckCodeBusy,
		LeafMobilityPeerPlanAckCodeStale,
		LeafMobilityPeerPlanAckCodeSuperseded,
	} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			ack := testLeafMobilityPeerPlanPreparedAck(t)
			ack.Code = code
			ack.Generation = 0
			ack.PeerEndpointGeneration = 0
			ack.PeerPlanDigest = LeafMobilityPeerDigest{}
			ack.AgreementDigest = LeafMobilityAgreementDigest{}
			ack.ReservationID = LeafMobilityReservationID{}
			ack.Reason = "proposal was not accepted"

			wire, err := ack.Encode()
			if err != nil {
				t.Fatalf("valid prepared rejection did not encode: %v", err)
			}

			objectMutation := ack
			objectMutation.PeerEndpointGeneration = 1
			if _, err := objectMutation.Encode(); err == nil {
				t.Fatal("prepared rejection object with peer endpoint generation encoded")
			}

			wireMutation := mutateLeafMobilityWire(wire, LeafMobilityPeerPlanBindingSize+39)
			if _, err := DecodeLeafMobilityPeerPlanAck(wireMutation); err == nil {
				t.Fatal("prepared rejection wire with peer endpoint generation decoded")
			}
		})
	}
}

func TestLeafMobilityFinalRejectedAckGenerationAndCorrelation(t *testing.T) {
	prepared := testLeafMobilityPeerPlanPreparedAck(t)
	commit := testLeafMobilityPeerPlanCommitForAck(prepared)
	finalReject := prepared
	finalReject.Phase = LeafMobilityPeerPlanAckPhaseFinal
	finalReject.Stage = LeafMobilityPeerPlanCommitStageCommit
	finalReject.Code = LeafMobilityPeerPlanAckCodeSuperseded
	finalReject.CurrentGeneration = finalReject.Generation
	finalReject.Reason = "actor path retired before authority publication"

	wire, err := finalReject.Encode()
	if err != nil {
		t.Fatalf("correlated final rejection did not encode: %v", err)
	}
	if err := finalReject.ValidateForCommit(commit); err != nil {
		t.Fatalf("correlated final rejection did not match commit: %v", err)
	}

	for name, generation := range map[string]uint64{
		"base generation":  finalReject.BaseGeneration,
		"later generation": finalReject.Generation + 1,
	} {
		t.Run(name, func(t *testing.T) {
			changed := finalReject
			changed.CurrentGeneration = generation
			if _, err := changed.Encode(); err == nil {
				t.Fatal("final rejection with non-reserved current generation encoded")
			}
			if err := changed.ValidateForCommit(commit); err == nil {
				t.Fatal("final rejection with non-reserved current generation matched commit")
			}
		})
	}

	mutatedWire := mutateLeafMobilityWire(wire, LeafMobilityPeerPlanBindingSize+15)
	if _, err := DecodeLeafMobilityPeerPlanAck(mutatedWire); err == nil {
		t.Fatal("wire-mutated final rejection current generation decoded")
	}

	otherPrepare := testLeafMobilityPeerPlanPrepare()
	otherPrepare.TransactionID[3] ^= 0xff
	otherPrepared := testLeafMobilityPeerPlanPreparedAckFor(t, otherPrepare)
	otherCommit := testLeafMobilityPeerPlanCommitForAck(otherPrepared)
	if err := finalReject.ValidateForCommit(otherCommit); err == nil {
		t.Fatal("final rejection matched a different committed transaction")
	}
}

func TestLeafMobilityPeerPlanWireStability(t *testing.T) {
	prepare := testLeafMobilityPeerPlanPrepare()
	proposal, err := prepare.ProposalDigest()
	if err != nil {
		t.Fatal(err)
	}
	prepared := testLeafMobilityPeerPlanPreparedAck(t)
	const wantProposal = "878123722a1f117d180e801dc60c60110f0416693852dbb31a929d7ade9bd1f7"
	const wantAgreement = "feb0c529b9c4aa9e78355253e392e9eb0c23db0e08e67795b92ac930b3cd2789"
	if got := hex.EncodeToString(proposal[:]); got != wantProposal {
		t.Fatalf("proposal digest=%s want=%s", got, wantProposal)
	}
	if got := hex.EncodeToString(prepared.AgreementDigest[:]); got != wantAgreement {
		t.Fatalf("agreement digest=%s want=%s", got, wantAgreement)
	}
	if LeafMobilityPeerPlanBindingSize != 200 || LeafMobilityPeerPlanPrepareSize != 240 ||
		LeafMobilityPeerPlanAckHeaderSize != 360 || LeafMobilityPeerPlanCommitSize != 344 {
		t.Fatal("leaf mobility peer-plan wire sizes drifted")
	}
}

func mutateLeafMobilityWire(wire []byte, index int) []byte {
	changed := append([]byte(nil), wire...)
	changed[index] ^= 0xff
	return changed
}

func FuzzDecodeLeafMobilityPeerPlan(f *testing.F) {
	prepare, _ := testLeafMobilityPeerPlanPrepare().Encode()
	ack, _ := testLeafMobilityPeerPlanPreparedAck(f).Encode()
	commit, _ := testLeafMobilityPeerPlanCommit(f).Encode()
	f.Add(uint8(1), prepare)
	f.Add(uint8(2), ack)
	f.Add(uint8(3), commit)
	f.Fuzz(func(t *testing.T, kind uint8, wire []byte) {
		switch kind % 3 {
		case 0:
			_, _ = DecodeLeafMobilityPeerPlanPrepare(wire)
		case 1:
			_, _ = DecodeLeafMobilityPeerPlanAck(wire)
		case 2:
			_, _ = DecodeLeafMobilityPeerPlanCommit(wire)
		}
	})
}
