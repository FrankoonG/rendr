package proto

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func testPolicyBinding() PolicyTransactionBinding {
	return PolicyTransactionBinding{
		SessionEpoch:  SessionEpoch{1},
		Direction:     SenderDirectionServerToClient,
		GraphBinding:  GraphBinding{Revision: 7, Digest: GraphDigest{2}},
		TransactionID: [16]byte{3},
	}
}

func testPolicyProposalDigest() PolicyProposalDigest {
	return PolicyProposalDigest{9}
}

func testPolicyReservationID() PolicyReservationID {
	return PolicyReservationID{8}
}

func TestPolicyTransactionsAreRequiredByNegotiation(t *testing.T) {
	if ProtocolMinor != 6 {
		t.Fatalf("protocol minor=%d want=6", ProtocolMinor)
	}
	if SupportedFeatures&FeaturePolicyTransaction == 0 || RequiredFeatures&FeaturePolicyTransaction == 0 {
		t.Fatal("policy transaction feature is not required by negotiation")
	}
	if SupportedFeatures&FeaturePolicyReservation == 0 || RequiredFeatures&FeaturePolicyReservation == 0 {
		t.Fatal("policy reservation feature is not required by negotiation")
	}
	if SupportedFeatures&FeatureDirectionalPathBinding == 0 || RequiredFeatures&FeatureDirectionalPathBinding == 0 {
		t.Fatal("directional path binding feature is not required by negotiation")
	}
	if SupportedFeatures&FeatureRecursiveExecutor == 0 || RequiredFeatures&FeatureRecursiveExecutor == 0 {
		t.Fatal("recursive executor feature is not required by negotiation")
	}
}

func TestHelloRejectsLegacyPolicyPeerDuringDecode(t *testing.T) {
	flow := [16]byte{0x44}
	manifest := testGraphManifest("legacy-policy-peer")
	tests := []struct {
		name    string
		minor   uint16
		feature FeatureSet
	}{
		{name: "one phase request", minor: 0, feature: FeaturePolicyTransaction},
		{name: "transaction without owner reservation", minor: 1, feature: FeaturePolicyReservation},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			negotiation := testNegotiationFor(flow, manifest)
			negotiation.ProtocolMinor = test.minor
			negotiation.Supported &^= test.feature
			negotiation.Required &^= test.feature
			wire := mustHelloWire(t, HelloPayload{
				Negotiation:     negotiation,
				FlowID:          flow,
				InstanceID:      InstanceID{1},
				InitialTargetID: manifest.RootID,
				LocalTXManifest: manifest,
			})
			if _, err := DecodeHello(wire); !errors.Is(err, ErrNegotiationIncompatible) {
				t.Fatalf("legacy peer error=%v, want incompatible negotiation", err)
			}
		})
	}
}

func TestHelloAcceptsCompatibleHigherMinor(t *testing.T) {
	flow := [16]byte{0x45}
	manifest := testGraphManifest("higher-minor-peer")
	negotiation := testNegotiationFor(flow, manifest)
	negotiation.ProtocolMinor++
	wire := mustHelloWire(t, HelloPayload{
		Negotiation:     negotiation,
		FlowID:          flow,
		InstanceID:      InstanceID{1},
		InitialTargetID: manifest.RootID,
		LocalTXManifest: manifest,
	})
	if _, err := DecodeHello(wire); err != nil {
		t.Fatalf("compatible higher minor rejected: %v", err)
	}
}

func TestPolicyPrepareRoundTrip(t *testing.T) {
	want := PolicyPrepare{
		PolicyTransactionBinding: testPolicyBinding(),
		BaseGeneration:           11,
		Action:                   PolicyActionSelectChild,
		SelectorID:               TargetID{4},
		TargetID:                 TargetID{5},
		Cause:                    "peak-transfer",
	}
	wire, err := want.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodePolicyPrepare(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("prepare=%+v want %+v", got, want)
	}
	if len(wire) != PolicyPrepareHeaderSize+len(want.Cause) || !bytes.Equal(wire[:4], policyTransactionMagic[:]) {
		t.Fatalf("prepare wire shape=%x", wire)
	}
}

func TestPolicyProposalDigestBindsEverySemanticField(t *testing.T) {
	base := PolicyPrepare{
		PolicyTransactionBinding: testPolicyBinding(),
		BaseGeneration:           11,
		Action:                   PolicyActionSelectChild,
		SelectorID:               TargetID{4},
		TargetID:                 TargetID{5},
		Cause:                    "quality",
	}
	want, err := base.ProposalDigest()
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*PolicyPrepare){
		"epoch":       func(p *PolicyPrepare) { p.SessionEpoch[1] ^= 1 },
		"direction":   func(p *PolicyPrepare) { p.Direction = SenderDirectionClientToServer },
		"revision":    func(p *PolicyPrepare) { p.GraphBinding.Revision++ },
		"graph":       func(p *PolicyPrepare) { p.GraphBinding.Digest[1] ^= 1 },
		"transaction": func(p *PolicyPrepare) { p.TransactionID[1] ^= 1 },
		"base":        func(p *PolicyPrepare) { p.BaseGeneration++ },
		"selector":    func(p *PolicyPrepare) { p.SelectorID[1] ^= 1 },
		"target":      func(p *PolicyPrepare) { p.TargetID[1] ^= 1 },
		"cause":       func(p *PolicyPrepare) { p.Cause += "-changed" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			got, err := changed.ProposalDigest()
			if err != nil {
				t.Fatal(err)
			}
			if got == want {
				t.Fatal("proposal digest did not change")
			}
		})
	}
}

func TestPolicyAckRoundTrip(t *testing.T) {
	accepted := PolicyAck{
		PolicyTransactionBinding: testPolicyBinding(),
		Phase:                    PolicyAckPhasePrepare,
		Code:                     PolicyAckCodeAccept,
		Generation:               12,
		CurrentGeneration:        11,
		CurrentTargetID:          TargetID{6},
		ProposalDigest:           testPolicyProposalDigest(),
		ReservationID:            testPolicyReservationID(),
	}
	wire, err := accepted.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodePolicyAck(wire)
	if err != nil || got != accepted {
		t.Fatalf("ack=%+v err=%v want %+v", got, err, accepted)
	}

	rejected := accepted
	rejected.Code = PolicyAckCodeStale
	rejected.Generation = 0
	rejected.Reason = "base generation changed"
	wire, err = rejected.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err = DecodePolicyAck(wire)
	if err != nil || got != rejected {
		t.Fatalf("reject=%+v err=%v want %+v", got, err, rejected)
	}
}

func TestPolicyCommitRoundTrip(t *testing.T) {
	want := PolicyCommit{PolicyTransactionBinding: testPolicyBinding(), Generation: 12, ProposalDigest: testPolicyProposalDigest(), ReservationID: testPolicyReservationID()}
	wire, err := want.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != PolicyCommitSize {
		t.Fatalf("commit size=%d", len(wire))
	}
	got, err := DecodePolicyCommit(wire)
	if err != nil || got != want {
		t.Fatalf("commit=%+v err=%v want %+v", got, err, want)
	}
}

func TestPolicyTransactionWireStability(t *testing.T) {
	prepare := PolicyPrepare{
		PolicyTransactionBinding: testPolicyBinding(),
		BaseGeneration:           11,
		Action:                   PolicyActionSelectChild,
		SelectorID:               TargetID{4},
		TargetID:                 TargetID{5},
		Cause:                    "wire-stability",
	}
	digest, err := prepare.ProposalDigest()
	if err != nil {
		t.Fatal(err)
	}
	prepareWire, _ := prepare.Encode()
	ackWire, _ := (PolicyAck{
		PolicyTransactionBinding: prepare.PolicyTransactionBinding,
		Phase:                    PolicyAckPhaseFinal,
		Code:                     PolicyAckCodeAccept,
		Generation:               12,
		CurrentGeneration:        12,
		CurrentTargetID:          prepare.TargetID,
		ProposalDigest:           digest,
		ReservationID:            testPolicyReservationID(),
	}).Encode()
	commitWire, _ := (PolicyCommit{
		PolicyTransactionBinding: prepare.PolicyTransactionBinding,
		Generation:               12,
		ProposalDigest:           digest,
		ReservationID:            testPolicyReservationID(),
	}).Encode()
	tests := []struct {
		name string
		wire []byte
		want string
	}{
		{name: "prepare", wire: prepareWire, want: "849f9beae745ef6e4e3de5defd3c1b3c4152347d2fd51e52f6b712e3d6cc8e1d"},
		{name: "ack", wire: ackWire, want: "d27a416d49100e6bc3ad607bc276c8ed67116747341912c408ad1df4f87ca906"},
		{name: "commit", wire: commitWire, want: "e9e244b76f6e41808264e9ca76472871cb466002141e8a6a7f41045c7a37d327"},
	}
	for _, test := range tests {
		if got := sha256.Sum256(test.wire); test.want != fmt.Sprintf("%x", got) {
			t.Errorf("%s wire sha256=%x want=%s", test.name, got, test.want)
		}
	}
}

func TestPolicyPayloadsRejectMalformedAndTrailing(t *testing.T) {
	prepare, _ := (PolicyPrepare{
		PolicyTransactionBinding: testPolicyBinding(),
		Action:                   PolicyActionSelectChild,
		SelectorID:               TargetID{1},
		TargetID:                 TargetID{2},
		Cause:                    "quality",
	}).Encode()
	ack, _ := (PolicyAck{
		PolicyTransactionBinding: testPolicyBinding(),
		Phase:                    PolicyAckPhaseFinal,
		Code:                     PolicyAckCodeAccept,
		Generation:               1,
		ProposalDigest:           testPolicyProposalDigest(),
		ReservationID:            testPolicyReservationID(),
	}).Encode()
	commit, _ := (PolicyCommit{PolicyTransactionBinding: testPolicyBinding(), Generation: 1, ProposalDigest: testPolicyProposalDigest(), ReservationID: testPolicyReservationID()}).Encode()

	tests := []struct {
		name   string
		wire   []byte
		decode func([]byte) error
	}{
		{"prepare short", prepare[:PolicyPrepareHeaderSize-1], func(b []byte) error { _, err := DecodePolicyPrepare(b); return err }},
		{"prepare trailing", append(append([]byte(nil), prepare...), 0), func(b []byte) error { _, err := DecodePolicyPrepare(b); return err }},
		{"ack short", ack[:PolicyAckHeaderSize-1], func(b []byte) error { _, err := DecodePolicyAck(b); return err }},
		{"ack trailing", append(append([]byte(nil), ack...), 0), func(b []byte) error { _, err := DecodePolicyAck(b); return err }},
		{"commit short", commit[:len(commit)-1], func(b []byte) error { _, err := DecodePolicyCommit(b); return err }},
		{"commit trailing", append(append([]byte(nil), commit...), 0), func(b []byte) error { _, err := DecodePolicyCommit(b); return err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.decode(test.wire); err == nil {
				t.Fatal("accepted malformed policy payload")
			}
		})
	}

	mutations := map[string]func([]byte){
		"magic":     func(b []byte) { b[0] ^= 0xff },
		"version":   func(b []byte) { b[4]++ },
		"message":   func(b []byte) { b[5] = byte(policyTransactionAck) },
		"direction": func(b []byte) { b[6] = 0 },
		"reserved":  func(b []byte) { b[7] = 1 },
		"epoch":     func(b []byte) { clear(b[8:24]) },
		"revision":  func(b []byte) { clear(b[24:32]) },
		"digest":    func(b []byte) { clear(b[32:64]) },
		"txid":      func(b []byte) { clear(b[64:80]) },
	}
	for name, mutate := range mutations {
		t.Run("prepare "+name, func(t *testing.T) {
			wire := append([]byte(nil), prepare...)
			mutate(wire)
			if _, err := DecodePolicyPrepare(wire); err == nil {
				t.Fatal("accepted malformed binding")
			}
		})
	}
}

func TestPolicyPayloadBoundsAndSemanticValidation(t *testing.T) {
	base := PolicyPrepare{
		PolicyTransactionBinding: testPolicyBinding(),
		Action:                   PolicyActionSelectChild,
		SelectorID:               TargetID{1},
		TargetID:                 TargetID{2},
	}
	base.Cause = strings.Repeat("x", PolicyMaxCauseBytes)
	if _, err := base.Encode(); err != nil {
		t.Fatalf("rejected cause boundary: %v", err)
	}
	base.Cause += "x"
	if _, err := base.Encode(); err == nil {
		t.Fatal("accepted oversized cause")
	}

	bad := []PolicyPrepare{
		{PolicyTransactionBinding: testPolicyBinding(), Action: PolicyActionInvalid, SelectorID: TargetID{1}, TargetID: TargetID{2}},
		{PolicyTransactionBinding: testPolicyBinding(), Action: PolicyActionSelectChild, TargetID: TargetID{2}},
		{PolicyTransactionBinding: testPolicyBinding(), Action: PolicyActionSelectChild, SelectorID: TargetID{1}},
	}
	for i, prepare := range bad {
		if _, err := prepare.Encode(); err == nil {
			t.Errorf("accepted invalid prepare %d", i)
		}
	}

	acceptedWithReason := PolicyAck{PolicyTransactionBinding: testPolicyBinding(), Phase: PolicyAckPhasePrepare, Code: PolicyAckCodeAccept, Generation: 1, ProposalDigest: testPolicyProposalDigest(), ReservationID: testPolicyReservationID(), Reason: "no"}
	if _, err := acceptedWithReason.Encode(); err == nil {
		t.Fatal("accepted success ACK with reason")
	}
	rejectedWithoutReason := acceptedWithReason
	rejectedWithoutReason.Code = PolicyAckCodeReject
	rejectedWithoutReason.Generation = 0
	rejectedWithoutReason.Reason = ""
	if _, err := rejectedWithoutReason.Encode(); err == nil {
		t.Fatal("accepted rejected ACK without reason")
	}
}

func FuzzDecodePolicyTransactions(f *testing.F) {
	prepare, _ := (PolicyPrepare{PolicyTransactionBinding: testPolicyBinding(), Action: PolicyActionSelectChild, SelectorID: TargetID{1}, TargetID: TargetID{2}}).Encode()
	ack, _ := (PolicyAck{PolicyTransactionBinding: testPolicyBinding(), Phase: PolicyAckPhasePrepare, Code: PolicyAckCodeAccept, Generation: 1, ProposalDigest: testPolicyProposalDigest(), ReservationID: testPolicyReservationID()}).Encode()
	commit, _ := (PolicyCommit{PolicyTransactionBinding: testPolicyBinding(), Generation: 1, ProposalDigest: testPolicyProposalDigest(), ReservationID: testPolicyReservationID()}).Encode()
	f.Add(prepare)
	f.Add(ack)
	f.Add(commit)
	f.Fuzz(func(t *testing.T, wire []byte) {
		_, _ = DecodePolicyPrepare(wire)
		_, _ = DecodePolicyAck(wire)
		_, _ = DecodePolicyCommit(wire)
	})
}
