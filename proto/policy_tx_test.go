package proto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
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

func testPolicyCommitChallenge() PolicyCommitChallenge {
	return PolicyCommitChallenge{7}
}

func TestPolicyTransactionsAreRequiredByNegotiation(t *testing.T) {
	if PolicyTransactionWireVersion != 4 {
		t.Fatalf("policy transaction wire version=%d want=4", PolicyTransactionWireVersion)
	}
	if ProtocolMinor != 20 {
		t.Fatalf("protocol minor=%d want=20", ProtocolMinor)
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
	if SupportedFeatures&FeatureLeafMobilityEnvelope == 0 || RequiredFeatures&FeatureLeafMobilityEnvelope == 0 {
		t.Fatal("leaf mobility envelope feature is not required by negotiation")
	}
	if SupportedFeatures&FeatureLeafMobilityTransaction == 0 || RequiredFeatures&FeatureLeafMobilityTransaction == 0 {
		t.Fatal("leaf mobility transaction feature is not required by negotiation")
	}
	if SupportedFeatures&FeaturePolicyClassSelection == 0 || RequiredFeatures&FeaturePolicyClassSelection == 0 {
		t.Fatal("policy class selection feature is not required by negotiation")
	}
	if SupportedFeatures&FeaturePolicyEarlyCustody == 0 || RequiredFeatures&FeaturePolicyEarlyCustody == 0 {
		t.Fatal("policy early-custody feature is not required by negotiation")
	}
	if SupportedFeatures&FeaturePolicyCommitChallenge == 0 || RequiredFeatures&FeaturePolicyCommitChallenge == 0 {
		t.Fatal("policy commit-challenge feature is not required by negotiation")
	}
	if SupportedFeatures&FeaturePolicySelectorGeneration == 0 || RequiredFeatures&FeaturePolicySelectorGeneration == 0 {
		t.Fatal("policy selector-generation feature is not required by negotiation")
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
			wire := mustHelloWire(t, HelloPayload{
				Negotiation:     negotiation,
				FlowID:          flow,
				InstanceID:      InstanceID{1},
				InitialTargetID: manifest.RootID,
				LocalTXManifest: manifest,
			})
			wire = mutateNegotiationWireForDecodeTest(t, wire, func(n *Negotiation) {
				n.ProtocolMinor = test.minor
				n.Supported &^= test.feature
				n.Required &^= test.feature
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
		SelectorGeneration:       7,
		CurrentTargetID:          TargetID{6},
		ResolvedTargetID:         TargetID{5},
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
	rejected.ResolvedTargetID = TargetID{}
	rejected.Reason = "base generation changed"
	wire, err = rejected.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err = DecodePolicyAck(wire)
	if err != nil || got != rejected {
		t.Fatalf("reject=%+v err=%v want %+v", got, err, rejected)
	}
	rejected.SelectorGeneration = 0
	wire, err = rejected.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err = DecodePolicyAck(wire)
	if err != nil || got != rejected {
		t.Fatalf("zero-selector reject=%+v err=%v want %+v", got, err, rejected)
	}
}

func TestPolicyAckV4LayoutAndReservedBytes(t *testing.T) {
	want := PolicyAck{
		PolicyTransactionBinding: testPolicyBinding(),
		Phase:                    PolicyAckPhaseFinal,
		Code:                     PolicyAckCodeAccept,
		Generation:               0x0102030405060708,
		CurrentGeneration:        0x1112131415161718,
		SelectorGeneration:       0x2122232425262728,
		CurrentTargetID:          TargetID{0x31},
		ResolvedTargetID:         TargetID{0x41},
		ProposalDigest:           PolicyProposalDigest{0x51},
		ReservationID:            PolicyReservationID{0x61},
		CommitChallenge:          PolicyCommitChallenge{0x71},
	}
	wire, err := want.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != PolicyAckHeaderSize || PolicyAckHeaderSize != 232 {
		t.Fatalf("ACK size=%d header=%d want=232", len(wire), PolicyAckHeaderSize)
	}
	if wire[4] != 4 || wire[80] != byte(want.Phase) || wire[81] != byte(want.Code) {
		t.Fatalf("ACK prefix version=%d phase=%d code=%d", wire[4], wire[80], wire[81])
	}
	if got := binary.BigEndian.Uint64(wire[88:96]); got != want.Generation {
		t.Fatalf("generation=%x want=%x", got, want.Generation)
	}
	if got := binary.BigEndian.Uint64(wire[96:104]); got != want.CurrentGeneration {
		t.Fatalf("current generation=%x want=%x", got, want.CurrentGeneration)
	}
	if got := binary.BigEndian.Uint64(wire[104:112]); got != want.SelectorGeneration {
		t.Fatalf("selector generation=%x want=%x", got, want.SelectorGeneration)
	}
	if !bytes.Equal(wire[112:128], want.CurrentTargetID[:]) ||
		!bytes.Equal(wire[128:144], want.ResolvedTargetID[:]) ||
		!bytes.Equal(wire[144:176], want.ProposalDigest[:]) ||
		!bytes.Equal(wire[176:192], want.ReservationID[:]) ||
		!bytes.Equal(wire[192:224], want.CommitChallenge[:]) {
		t.Fatal("ACK semantic field offsets do not match the v4 layout")
	}
	if got := binary.BigEndian.Uint16(wire[224:226]); got != 0 {
		t.Fatalf("reason length=%d want=0", got)
	}

	for _, bounds := range [][2]int{{82, 88}, {226, 232}} {
		for index := bounds[0]; index < bounds[1]; index++ {
			t.Run(fmt.Sprintf("reserved-%d", index), func(t *testing.T) {
				mutated := append([]byte(nil), wire...)
				mutated[index] = 1
				if _, err := DecodePolicyAck(mutated); err == nil || !strings.Contains(err.Error(), "reserved bytes") {
					t.Fatalf("reserved-byte mutation decoded: %v", err)
				}
			})
		}
	}
}

func TestPolicyAckSelectorGenerationIsMandatoryAndWireBound(t *testing.T) {
	ack := PolicyAck{
		PolicyTransactionBinding: testPolicyBinding(),
		Phase:                    PolicyAckPhasePrepare,
		Code:                     PolicyAckCodeAccept,
		Generation:               12,
		SelectorGeneration:       7,
		CurrentTargetID:          TargetID{4},
		ResolvedTargetID:         TargetID{5},
		ProposalDigest:           testPolicyProposalDigest(),
		ReservationID:            testPolicyReservationID(),
	}
	first, err := ack.Encode()
	if err != nil {
		t.Fatal(err)
	}

	zero := ack
	zero.SelectorGeneration = 0
	if _, err := zero.Encode(); err == nil {
		t.Fatal("encoded accepted ACK with zero selector generation")
	}
	zeroWire := append([]byte(nil), first...)
	clear(zeroWire[104:112])
	if _, err := DecodePolicyAck(zeroWire); err == nil {
		t.Fatal("decoded accepted ACK with zero selector generation")
	}
	zero = ack
	zero.CurrentTargetID = TargetID{}
	if _, err := zero.Encode(); err == nil {
		t.Fatal("encoded accepted ACK with zero current target")
	}

	changed := ack
	changed.SelectorGeneration++
	second, err := changed.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) || sha256.Sum256(first) == sha256.Sum256(second) {
		t.Fatal("selector-generation mutation did not change the ACK wire digest")
	}
	decoded, err := DecodePolicyAck(second)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.SelectorGeneration != changed.SelectorGeneration {
		t.Fatalf("decoded selector generation=%d want=%d", decoded.SelectorGeneration, changed.SelectorGeneration)
	}
}

func TestPolicyCommitRoundTrip(t *testing.T) {
	want := PolicyCommit{PolicyTransactionBinding: testPolicyBinding(), Generation: 12, ProposalDigest: testPolicyProposalDigest(), ReservationID: testPolicyReservationID(), CommitChallenge: testPolicyCommitChallenge()}
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

func TestPolicyCommitChallengeIsPhaseBoundAndMandatory(t *testing.T) {
	prepareAck := PolicyAck{
		PolicyTransactionBinding: testPolicyBinding(),
		Phase:                    PolicyAckPhasePrepare,
		Code:                     PolicyAckCodeAccept,
		Generation:               1,
		SelectorGeneration:       1,
		CurrentTargetID:          TargetID{1},
		ResolvedTargetID:         TargetID{2},
		ProposalDigest:           testPolicyProposalDigest(),
		ReservationID:            testPolicyReservationID(),
	}
	withChallenge := prepareAck
	withChallenge.CommitChallenge = testPolicyCommitChallenge()
	if _, err := withChallenge.Encode(); err == nil {
		t.Fatal("prepare ACK accepted a commit challenge")
	}
	finalAck := prepareAck
	finalAck.Phase = PolicyAckPhaseFinal
	if _, err := finalAck.Encode(); err == nil {
		t.Fatal("FINAL ACK accepted a zero commit challenge")
	}
	finalAck.CommitChallenge = testPolicyCommitChallenge()
	if _, err := finalAck.Encode(); err != nil {
		t.Fatalf("FINAL ACK rejected its commit challenge: %v", err)
	}

	commit := PolicyCommit{
		PolicyTransactionBinding: testPolicyBinding(),
		Generation:               1,
		ProposalDigest:           testPolicyProposalDigest(),
		ReservationID:            testPolicyReservationID(),
	}
	if _, err := commit.Encode(); err == nil {
		t.Fatal("COMMIT accepted a zero challenge")
	}
	commit.CommitChallenge = testPolicyCommitChallenge()
	first, err := commit.Encode()
	if err != nil {
		t.Fatal(err)
	}
	commit.CommitChallenge[31] ^= 1
	second, err := commit.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("COMMIT wire did not bind every challenge byte")
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
		SelectorGeneration:       9,
		CurrentTargetID:          prepare.TargetID,
		ResolvedTargetID:         prepare.TargetID,
		ProposalDigest:           digest,
		ReservationID:            testPolicyReservationID(),
		CommitChallenge:          testPolicyCommitChallenge(),
	}).Encode()
	commitWire, _ := (PolicyCommit{
		PolicyTransactionBinding: prepare.PolicyTransactionBinding,
		Generation:               12,
		ProposalDigest:           digest,
		ReservationID:            testPolicyReservationID(),
		CommitChallenge:          testPolicyCommitChallenge(),
	}).Encode()
	tests := []struct {
		name string
		wire []byte
		want string
	}{
		{name: "prepare", wire: prepareWire, want: "225fc40b463990fec7343b8fa9996c205cec8c0a4daddb5d2886495f55bdbba2"},
		{name: "ack", wire: ackWire, want: "19f7c783b0394081d91855f3136d2dffca40f611cfd56fd6d981fcf26774279f"},
		{name: "commit", wire: commitWire, want: "3808e9c0eb535d0ee7bf8700610a47323c4457a5c539297a929265265ffe3f6f"},
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
		SelectorGeneration:       1,
		CurrentTargetID:          TargetID{1},
		ResolvedTargetID:         TargetID{2},
		ProposalDigest:           testPolicyProposalDigest(),
		ReservationID:            testPolicyReservationID(),
		CommitChallenge:          testPolicyCommitChallenge(),
	}).Encode()
	commit, _ := (PolicyCommit{PolicyTransactionBinding: testPolicyBinding(), Generation: 1, ProposalDigest: testPolicyProposalDigest(), ReservationID: testPolicyReservationID(), CommitChallenge: testPolicyCommitChallenge()}).Encode()

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
	legacy := append([]byte(nil), prepare...)
	legacy[4] = 3
	if _, err := DecodePolicyPrepare(legacy); err == nil {
		t.Fatal("v4 decoder accepted a policy transaction v3 envelope")
	}
}

func TestPolicyPayloadsRejectLegacyWireVersion(t *testing.T) {
	prepare, _ := (PolicyPrepare{
		PolicyTransactionBinding: testPolicyBinding(),
		Action:                   PolicyActionSelectChild,
		SelectorID:               TargetID{1},
		TargetID:                 TargetID{2},
		Cause:                    "legacy-version",
	}).Encode()
	ack, _ := (PolicyAck{
		PolicyTransactionBinding: testPolicyBinding(),
		Phase:                    PolicyAckPhaseFinal,
		Code:                     PolicyAckCodeAccept,
		Generation:               1,
		SelectorGeneration:       1,
		CurrentTargetID:          TargetID{1},
		ResolvedTargetID:         TargetID{2},
		ProposalDigest:           testPolicyProposalDigest(),
		ReservationID:            testPolicyReservationID(),
		CommitChallenge:          testPolicyCommitChallenge(),
	}).Encode()
	commit, _ := (PolicyCommit{
		PolicyTransactionBinding: testPolicyBinding(),
		Generation:               1,
		ProposalDigest:           testPolicyProposalDigest(),
		ReservationID:            testPolicyReservationID(),
		CommitChallenge:          testPolicyCommitChallenge(),
	}).Encode()

	for _, test := range []struct {
		name   string
		wire   []byte
		decode func([]byte) error
	}{
		{name: "prepare", wire: prepare, decode: func(value []byte) error { _, err := DecodePolicyPrepare(value); return err }},
		{name: "ack", wire: ack, decode: func(value []byte) error { _, err := DecodePolicyAck(value); return err }},
		{name: "commit", wire: commit, decode: func(value []byte) error { _, err := DecodePolicyCommit(value); return err }},
	} {
		t.Run(test.name, func(t *testing.T) {
			legacy := append([]byte(nil), test.wire...)
			legacy[4] = 3
			if err := test.decode(legacy); err == nil {
				t.Fatal("accepted policy transaction wire v3")
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
		{PolicyTransactionBinding: testPolicyBinding(), Action: PolicyActionSelectBestNormal, SelectorID: TargetID{1}, TargetID: TargetID{2}},
		{PolicyTransactionBinding: testPolicyBinding(), Action: PolicyActionSelectBestPeak, SelectorID: TargetID{1}, TargetID: TargetID{2}},
	}
	for i, prepare := range bad {
		if _, err := prepare.Encode(); err == nil {
			t.Errorf("accepted invalid prepare %d", i)
		}
	}

	acceptedWithReason := PolicyAck{PolicyTransactionBinding: testPolicyBinding(), Phase: PolicyAckPhasePrepare, Code: PolicyAckCodeAccept, Generation: 1, SelectorGeneration: 1, CurrentTargetID: TargetID{1}, ResolvedTargetID: TargetID{2}, ProposalDigest: testPolicyProposalDigest(), ReservationID: testPolicyReservationID(), Reason: "no"}
	if _, err := acceptedWithReason.Encode(); err == nil {
		t.Fatal("accepted success ACK with reason")
	}
	rejectedWithoutReason := acceptedWithReason
	rejectedWithoutReason.Code = PolicyAckCodeReject
	rejectedWithoutReason.Generation = 0
	rejectedWithoutReason.ResolvedTargetID = TargetID{}
	rejectedWithoutReason.Reason = ""
	if _, err := rejectedWithoutReason.Encode(); err == nil {
		t.Fatal("accepted rejected ACK without reason")
	}
}

func TestPolicySelectorClassPrepareRoundTrip(t *testing.T) {
	for _, action := range []PolicyAction{PolicyActionSelectBestNormal, PolicyActionSelectBestPeak} {
		want := PolicyPrepare{
			PolicyTransactionBinding: testPolicyBinding(),
			BaseGeneration:           7,
			Action:                   action,
			SelectorID:               TargetID{4},
			Cause:                    "peak-transfer",
		}
		wire, err := want.Encode()
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodePolicyPrepare(wire)
		if err != nil || got != want {
			t.Fatalf("action=%d got=%+v err=%v want=%+v", action, got, err, want)
		}
	}
}

func FuzzDecodePolicyTransactions(f *testing.F) {
	for _, seed := range policyTransactionFuzzSeeds(f) {
		f.Add(seed.wire)
		for _, boundary := range protocolFuzzBoundaries(seed.wire) {
			f.Add(boundary.wire)
		}
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, wire []byte) {
		_ = exercisePolicyTransactionFuzzWire(t, wire)
	})
}
