package proto

import (
	"bytes"
	"strings"
	"testing"
)

type protocolFuzzSeed struct {
	name string
	kind uint8
	wire []byte
}

type protocolFuzzEncoder interface {
	Encode() ([]byte, error)
}

func mustProtocolFuzzWire(t testing.TB, name string, value protocolFuzzEncoder) []byte {
	t.Helper()
	wire, err := value.Encode()
	if err != nil {
		t.Fatalf("encode %s fuzz seed: %v", name, err)
	}
	return wire
}

func protocolFuzzRoundTrip[T comparable](
	t testing.TB,
	wire []byte,
	decode func([]byte) (T, error),
	encode func(T) ([]byte, error),
) bool {
	t.Helper()
	original := append([]byte(nil), wire...)
	decoded, err := decode(wire)
	if err != nil {
		return false
	}
	if !bytes.Equal(wire, original) {
		t.Fatal("protocol decoder mutated its input")
	}
	canonical, err := encode(decoded)
	if err != nil {
		t.Fatalf("decoded protocol state cannot re-encode: %v", err)
	}
	if !bytes.Equal(canonical, wire) {
		t.Fatalf("protocol decoder accepted noncanonical wire:\n got=%x\nwant=%x", canonical, wire)
	}
	decodedAgain, err := decode(canonical)
	if err != nil {
		t.Fatalf("canonical protocol wire cannot be decoded again: %v", err)
	}
	if decodedAgain != decoded {
		t.Fatalf("protocol state changed across decode/encode/decode:\n got=%+v\nwant=%+v", decodedAgain, decoded)
	}
	return true
}

func protocolFuzzBoundaries(wire []byte) []protocolFuzzSeed {
	truncated := append([]byte(nil), wire[:len(wire)-1]...)
	trailing := append(append([]byte(nil), wire...), 0)
	return []protocolFuzzSeed{
		{name: "truncated", wire: truncated},
		{name: "trailing", wire: trailing},
	}
}

func leafMobilityPeerPlanFuzzSeeds(t testing.TB) []protocolFuzzSeed {
	t.Helper()
	prepare := testLeafMobilityPeerPlanPrepare()
	minimumPrepare := prepare
	minimumPrepare.LeaseMillis = 1
	minimumPrepare.BaseGeneration = 0
	packetPrepare := prepare
	packetPrepare.SessionKind = LeafMobilitySessionPacket
	packetPrepare.Operation = LeafMobilityOperationUDPFlowRebind

	prepared := testLeafMobilityPeerPlanPreparedAckFor(t, prepare)
	proposal, err := prepare.ProposalDigest()
	if err != nil {
		t.Fatal(err)
	}
	preparedReject := LeafMobilityPeerPlanAck{
		LeafMobilityPeerPlanBinding: prepare.LeafMobilityPeerPlanBinding,
		Phase:                       LeafMobilityPeerPlanAckPhasePrepared,
		Code:                        LeafMobilityPeerPlanAckCodeSuperseded,
		CurrentGeneration:           prepare.BaseGeneration,
		ActorEndpointGeneration:     prepare.ActorEndpointGeneration,
		ProposalDigest:              proposal,
		Reason:                      strings.Repeat("r", LeafMobilityPeerPlanMaxReasonBytes),
	}

	commit := testLeafMobilityPeerPlanCommitForAck(prepared)
	final := prepared
	final.Phase = LeafMobilityPeerPlanAckPhaseFinal
	final.Stage = LeafMobilityPeerPlanCommitStageCommit
	final.CurrentGeneration = final.Generation
	final.PublicationDigest = commit.PublicationDigest
	finalReject := final
	finalReject.Code = LeafMobilityPeerPlanAckCodeReject
	finalReject.Reason = "publication rejected"

	seeds := []protocolFuzzSeed{
		{name: "prepare-minimum", kind: uint8(leafMobilityPeerPlanMessagePrepare), wire: mustProtocolFuzzWire(t, "prepare-minimum", minimumPrepare)},
		{name: "prepare-lease-maximum", kind: uint8(leafMobilityPeerPlanMessagePrepare), wire: mustProtocolFuzzWire(t, "prepare-lease-maximum", prepare)},
		{name: "prepare-packet", kind: uint8(leafMobilityPeerPlanMessagePrepare), wire: mustProtocolFuzzWire(t, "prepare-packet", packetPrepare)},
		{name: "ack-prepared-accept", kind: uint8(leafMobilityPeerPlanMessageAck), wire: mustProtocolFuzzWire(t, "ack-prepared-accept", prepared)},
		{name: "ack-prepared-reject-max-reason", kind: uint8(leafMobilityPeerPlanMessageAck), wire: mustProtocolFuzzWire(t, "ack-prepared-reject-max-reason", preparedReject)},
		{name: "ack-final-accept", kind: uint8(leafMobilityPeerPlanMessageAck), wire: mustProtocolFuzzWire(t, "ack-final-accept", final)},
		{name: "ack-final-reject", kind: uint8(leafMobilityPeerPlanMessageAck), wire: mustProtocolFuzzWire(t, "ack-final-reject", finalReject)},
		{name: "commit", kind: uint8(leafMobilityPeerPlanMessageCommit), wire: mustProtocolFuzzWire(t, "commit", commit)},
	}

	for _, stage := range []LeafMobilityPeerPlanCommitStage{
		LeafMobilityPeerPlanCommitStageComplete,
		LeafMobilityPeerPlanCommitStageRolledBack,
		LeafMobilityPeerPlanCommitStageAbort,
	} {
		resolution := commit
		resolution.Stage = stage
		if stage == LeafMobilityPeerPlanCommitStageAbort {
			resolution.PublicationDigest = LeafMobilityPublicationDigest{}
		}
		stageName := map[LeafMobilityPeerPlanCommitStage]string{
			LeafMobilityPeerPlanCommitStageComplete:   "complete",
			LeafMobilityPeerPlanCommitStageRolledBack: "rolled-back",
			LeafMobilityPeerPlanCommitStageAbort:      "abort",
		}[stage]
		seeds = append(seeds, protocolFuzzSeed{
			name: "commit-" + stageName,
			kind: uint8(leafMobilityPeerPlanMessageCommit),
			wire: mustProtocolFuzzWire(t, "commit-"+stageName, resolution),
		})

		released := prepared
		released.Phase = LeafMobilityPeerPlanAckPhaseReleased
		released.Stage = stage
		released.CurrentGeneration = released.Generation
		released.PublicationDigest = resolution.PublicationDigest
		seeds = append(seeds, protocolFuzzSeed{
			name: "ack-released-" + stageName,
			kind: uint8(leafMobilityPeerPlanMessageAck),
			wire: mustProtocolFuzzWire(t, "ack-released-"+stageName, released),
		})
	}

	preCommitRollback := commit
	preCommitRollback.Stage = LeafMobilityPeerPlanCommitStageRolledBack
	preCommitRollback.PublicationDigest = LeafMobilityPublicationDigest{}
	seeds = append(seeds, protocolFuzzSeed{
		name: "commit-pre-publication-rollback",
		kind: uint8(leafMobilityPeerPlanMessageCommit),
		wire: mustProtocolFuzzWire(t, "commit-pre-publication-rollback", preCommitRollback),
	})
	return seeds
}

func pathAdmissionFuzzSeeds(t testing.TB) []protocolFuzzSeed {
	t.Helper()
	binding := testPathAdmissionBinding()
	helloBinding := binding
	helloBinding.Kind = PathAdmissionKindHello
	helloBinding.Direction = SenderDirectionClientToServer
	helloBinding.BaseLeafGeneration = 0

	seeds := []protocolFuzzSeed{
		{name: "commit-bridge", kind: uint8(pathAdmissionMessageCommit), wire: mustProtocolFuzzWire(t, "commit-bridge", PathAdmissionCommit{PathAdmissionBinding: binding, Phase: PathAdmissionPhaseCommit})},
		{name: "commit-hello-base-zero", kind: uint8(pathAdmissionMessageCommit), wire: mustProtocolFuzzWire(t, "commit-hello-base-zero", PathAdmissionCommit{PathAdmissionBinding: helloBinding, Phase: PathAdmissionPhaseCommit})},
		{name: "ack-prepared", kind: uint8(pathAdmissionMessageAck), wire: mustProtocolFuzzWire(t, "ack-prepared", PathAdmissionAck{PathAdmissionBinding: binding, Phase: PathAdmissionPhasePrepared, Code: AckOK})},
		{name: "ack-committed", kind: uint8(pathAdmissionMessageAck), wire: mustProtocolFuzzWire(t, "ack-committed", PathAdmissionAck{PathAdmissionBinding: binding, Phase: PathAdmissionPhaseCommitted, Code: AckOK})},
		{name: "ack-final-max-reason", kind: uint8(pathAdmissionMessageAck), wire: mustProtocolFuzzWire(t, "ack-final-max-reason", PathAdmissionAck{PathAdmissionBinding: binding, Phase: PathAdmissionPhaseFinal, Code: AckRejectProtoState, Reason: strings.Repeat("r", PathAdmissionMaxReasonBytes)})},
		{name: "ack-activated", kind: uint8(pathAdmissionMessageAck), wire: mustProtocolFuzzWire(t, "ack-activated", PathAdmissionAck{PathAdmissionBinding: binding, Phase: PathAdmissionPhaseActivated, Code: AckOK})},
		{name: "confirm", kind: uint8(pathAdmissionMessageConfirm), wire: mustProtocolFuzzWire(t, "confirm", PathAdmissionConfirm{PathAdmissionBinding: binding, CommittedGeneration: binding.BaseLeafGeneration + 1})},
		{name: "confirm-base-zero", kind: uint8(pathAdmissionMessageConfirm), wire: mustProtocolFuzzWire(t, "confirm-base-zero", PathAdmissionConfirm{PathAdmissionBinding: helloBinding, CommittedGeneration: 1})},
	}
	return seeds
}

func policyTransactionFuzzSeeds(t testing.TB) []protocolFuzzSeed {
	t.Helper()
	binding := testPolicyBinding()
	prepare := PolicyPrepare{
		PolicyTransactionBinding: binding,
		Action:                   PolicyActionSelectChild,
		SelectorID:               TargetID{1},
		TargetID:                 TargetID{2},
	}
	prepareMaxCause := prepare
	prepareMaxCause.Cause = strings.Repeat("c", PolicyMaxCauseBytes)
	accepted := PolicyAck{
		PolicyTransactionBinding: binding,
		Phase:                    PolicyAckPhasePrepare,
		Code:                     PolicyAckCodeAccept,
		Generation:               1,
		SelectorGeneration:       1,
		CurrentTargetID:          TargetID{1},
		ResolvedTargetID:         TargetID{2},
		ProposalDigest:           testPolicyProposalDigest(),
		ReservationID:            testPolicyReservationID(),
	}
	finalAccepted := accepted
	finalAccepted.Phase = PolicyAckPhaseFinal
	finalAccepted.CommitChallenge = testPolicyCommitChallenge()
	rejected := PolicyAck{
		PolicyTransactionBinding: binding,
		Phase:                    PolicyAckPhasePrepare,
		Code:                     PolicyAckCodeSuperseded,
		CurrentGeneration:        7,
		CurrentTargetID:          TargetID{3},
		ProposalDigest:           testPolicyProposalDigest(),
		Reason:                   strings.Repeat("r", PolicyMaxReasonBytes),
	}
	finalRejected := rejected
	finalRejected.Phase = PolicyAckPhaseFinal
	finalRejected.Code = PolicyAckCodeReject
	finalRejected.CommitChallenge = testPolicyCommitChallenge()
	finalRejected.Reason = "final rejection"
	commit := PolicyCommit{
		PolicyTransactionBinding: binding,
		Generation:               1,
		ProposalDigest:           testPolicyProposalDigest(),
		ReservationID:            testPolicyReservationID(),
		CommitChallenge:          testPolicyCommitChallenge(),
	}
	return []protocolFuzzSeed{
		{name: "prepare-empty-cause", kind: uint8(policyTransactionPrepare), wire: mustProtocolFuzzWire(t, "prepare-empty-cause", prepare)},
		{name: "prepare-max-cause", kind: uint8(policyTransactionPrepare), wire: mustProtocolFuzzWire(t, "prepare-max-cause", prepareMaxCause)},
		{name: "ack-prepare-accept", kind: uint8(policyTransactionAck), wire: mustProtocolFuzzWire(t, "ack-prepare-accept", accepted)},
		{name: "ack-final-accept", kind: uint8(policyTransactionAck), wire: mustProtocolFuzzWire(t, "ack-final-accept", finalAccepted)},
		{name: "ack-prepare-reject-max-reason", kind: uint8(policyTransactionAck), wire: mustProtocolFuzzWire(t, "ack-prepare-reject-max-reason", rejected)},
		{name: "ack-final-reject", kind: uint8(policyTransactionAck), wire: mustProtocolFuzzWire(t, "ack-final-reject", finalRejected)},
		{name: "commit", kind: uint8(policyTransactionCommit), wire: mustProtocolFuzzWire(t, "commit", commit)},
	}
}

func exerciseLeafMobilityPeerPlanFuzzWire(t testing.TB, kind uint8, wire []byte) int {
	t.Helper()
	switch leafMobilityPeerPlanMessage(kind) {
	case leafMobilityPeerPlanMessagePrepare:
		if protocolFuzzRoundTrip(t, wire, DecodeLeafMobilityPeerPlanPrepare, LeafMobilityPeerPlanPrepare.Encode) {
			return 1
		}
	case leafMobilityPeerPlanMessageAck:
		if protocolFuzzRoundTrip(t, wire, DecodeLeafMobilityPeerPlanAck, LeafMobilityPeerPlanAck.Encode) {
			return 1
		}
	case leafMobilityPeerPlanMessageCommit:
		if protocolFuzzRoundTrip(t, wire, DecodeLeafMobilityPeerPlanCommit, LeafMobilityPeerPlanCommit.Encode) {
			return 1
		}
	default:
		matches := 0
		matches += exerciseLeafMobilityPeerPlanFuzzWire(t, uint8(leafMobilityPeerPlanMessagePrepare), wire)
		matches += exerciseLeafMobilityPeerPlanFuzzWire(t, uint8(leafMobilityPeerPlanMessageAck), wire)
		matches += exerciseLeafMobilityPeerPlanFuzzWire(t, uint8(leafMobilityPeerPlanMessageCommit), wire)
		return matches
	}
	return 0
}

func exercisePathAdmissionFuzzWire(t testing.TB, wire []byte) int {
	t.Helper()
	matches := 0
	if protocolFuzzRoundTrip(t, wire, DecodePathAdmissionCommit, PathAdmissionCommit.Encode) {
		matches++
	}
	if protocolFuzzRoundTrip(t, wire, DecodePathAdmissionAck, PathAdmissionAck.Encode) {
		matches++
	}
	if protocolFuzzRoundTrip(t, wire, DecodePathAdmissionConfirm, PathAdmissionConfirm.Encode) {
		matches++
	}
	return matches
}

func exercisePolicyTransactionFuzzWire(t testing.TB, wire []byte) int {
	t.Helper()
	matches := 0
	if protocolFuzzRoundTrip(t, wire, DecodePolicyPrepare, PolicyPrepare.Encode) {
		matches++
	}
	if protocolFuzzRoundTrip(t, wire, DecodePolicyAck, PolicyAck.Encode) {
		matches++
	}
	if protocolFuzzRoundTrip(t, wire, DecodePolicyCommit, PolicyCommit.Encode) {
		matches++
	}
	return matches
}

func TestProtocolTransactionFuzzSeedProperties(t *testing.T) {
	groups := []struct {
		name     string
		seeds    []protocolFuzzSeed
		exercise func(testing.TB, protocolFuzzSeed) int
	}{
		{
			name:  "leaf-mobility",
			seeds: leafMobilityPeerPlanFuzzSeeds(t),
			exercise: func(tb testing.TB, seed protocolFuzzSeed) int {
				return exerciseLeafMobilityPeerPlanFuzzWire(tb, seed.kind, seed.wire)
			},
		},
		{
			name:  "path-admission",
			seeds: pathAdmissionFuzzSeeds(t),
			exercise: func(tb testing.TB, seed protocolFuzzSeed) int {
				return exercisePathAdmissionFuzzWire(tb, seed.wire)
			},
		},
		{
			name:  "policy",
			seeds: policyTransactionFuzzSeeds(t),
			exercise: func(tb testing.TB, seed protocolFuzzSeed) int {
				return exercisePolicyTransactionFuzzWire(tb, seed.wire)
			},
		},
	}

	for _, group := range groups {
		group := group
		t.Run(group.name, func(t *testing.T) {
			for _, seed := range group.seeds {
				seed := seed
				t.Run(seed.name, func(t *testing.T) {
					if matches := group.exercise(t, seed); matches != 1 {
						t.Fatalf("valid seed matched %d protocol decoders, want exactly 1", matches)
					}
					for _, boundary := range protocolFuzzBoundaries(seed.wire) {
						boundary := boundary
						t.Run(boundary.name, func(t *testing.T) {
							boundary.kind = seed.kind
							if matches := group.exercise(t, boundary); matches != 0 {
								t.Fatalf("%s wire matched %d protocol decoders, want 0", boundary.name, matches)
							}
						})
					}
				})
			}
		})
	}
}
