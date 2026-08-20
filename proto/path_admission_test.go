package proto

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestPathAdmissionTerminalFeatureIsNegotiatedOnCurrentMinor(t *testing.T) {
	for _, feature := range []FeatureSet{FeaturePathAdmissionTerminalCommit, FeaturePathAdmissionCrossRouteTerminal} {
		t.Run(fmt.Sprintf("feature-0x%x", feature), func(t *testing.T) {
			flow := [16]byte{0x46}
			manifest := testGraphManifest("terminal-feature-peer")
			negotiation := testNegotiationFor(flow, manifest)

			helloWire := mustHelloWire(t, HelloPayload{
				Negotiation: negotiation, FlowID: flow, InstanceID: InstanceID{1},
				InitialTargetID: manifest.RootID, LocalTXManifest: manifest,
			})
			helloWire = mutateNegotiationWireForDecodeTest(t, helloWire, func(n *Negotiation) {
				n.Supported &^= feature
				n.Required &^= feature
			})
			if _, err := DecodeHello(helloWire); !errors.Is(err, ErrNegotiationIncompatible) {
				t.Fatalf("HELLO without terminal feature error=%v, want %v", err, ErrNegotiationIncompatible)
			}

			ackWire := mustHelloAckWire(t, HelloAckPayload{
				Negotiation: negotiation, FlowID: flow, InstanceID: InstanceID{1},
				InitialTargetID:      manifest.RootID,
				AcceptedPeerBinding:  GraphBinding{Revision: negotiation.GraphRevision, Digest: negotiation.GraphDigest},
				AcceptedPeerTargetID: manifest.RootID,
				LocalTXManifest:      manifest,
			})
			ackWire = mutateNegotiationWireForDecodeTest(t, ackWire, func(n *Negotiation) {
				n.Supported &^= feature
				n.Required &^= feature
			})
			if _, err := DecodeHelloAck(ackWire); !errors.Is(err, ErrNegotiationIncompatible) {
				t.Fatalf("HELLO_ACK without terminal feature error=%v, want %v", err, ErrNegotiationIncompatible)
			}
		})
	}
}

func testPathAdmissionBinding() PathAdmissionBinding {
	return PathAdmissionBinding{
		Kind:                   PathAdmissionKindBridge,
		Direction:              SenderDirectionServerToClient,
		SessionEpoch:           SessionEpoch{1, 2, 3, 4},
		AdmissionID:            PathAdmissionID{5, 6, 7, 8},
		InitiatorGraphRevision: 0x1112131415161718,
		InitiatorGraphDigest:   GraphDigest{0x21, 0x22, 0x23, 0x24},
		InitiatorTargetID:      TargetID{0x31, 0x32, 0x33, 0x34},
		ResponderTargetID:      TargetID{0x35, 0x36, 0x37, 0x38},
		BaseLeafGeneration:     8,
		ProposalDigest:         PathAdmissionProposalDigest{0x41, 0x42, 0x43, 0x44},
		ResponderPlanDigest:    PathAdmissionPlanDigest{0x51, 0x52, 0x53, 0x54},
	}
}

func TestPathAdmissionProtocolAndControlCodeStability(t *testing.T) {
	if Version != 3 {
		t.Fatalf("frame envelope version=%d want=3", Version)
	}
	if ProtocolMinor != 20 {
		t.Fatalf("protocol minor=%d want=20", ProtocolMinor)
	}
	if SupportedFeatures&FeaturePathAdmissionTransaction == 0 || RequiredFeatures&FeaturePathAdmissionTransaction == 0 {
		t.Fatal("path admission transaction feature is not mandatory")
	}
	if SupportedFeatures&FeaturePathAdmissionTerminalCommit == 0 || RequiredFeatures&FeaturePathAdmissionTerminalCommit == 0 {
		t.Fatal("path admission terminal-commit feature is not mandatory")
	}
	if SupportedFeatures&FeaturePathAdmissionCrossRouteTerminal == 0 || RequiredFeatures&FeaturePathAdmissionCrossRouteTerminal == 0 {
		t.Fatal("path admission cross-route terminal feature is not mandatory")
	}
	if SupportedFeatures&FeatureLeafMobilityEnvelope == 0 || RequiredFeatures&FeatureLeafMobilityEnvelope == 0 {
		t.Fatal("leaf mobility envelope feature is not mandatory")
	}
	if SupportedFeatures&FeatureLeafMobilityTransaction == 0 || RequiredFeatures&FeatureLeafMobilityTransaction == 0 {
		t.Fatal("leaf mobility transaction feature is not mandatory")
	}
	if PathAdmissionWireVersion != 1 {
		t.Fatalf("path admission wire version=%d want=1", PathAdmissionWireVersion)
	}
	codes := []struct {
		code CtrlCode
		want byte
		name string
	}{
		{CtrlPathAdmissionCommit, 0x0C, "PATH_ADMISSION_COMMIT"},
		{CtrlPathAdmissionAck, 0x0D, "PATH_ADMISSION_ACK"},
		{CtrlPathAdmissionConfirm, 0x0E, "PATH_ADMISSION_CONFIRM"},
	}
	for _, test := range codes {
		if byte(test.code) != test.want || test.code.String() != test.name {
			t.Errorf("control code drift: got 0x%02x/%q want 0x%02x/%q", byte(test.code), test.code, test.want, test.name)
		}
	}
}

func TestPathAdmissionRoundTrip(t *testing.T) {
	binding := testPathAdmissionBinding()
	commit := PathAdmissionCommit{PathAdmissionBinding: binding, Phase: PathAdmissionPhaseCommit}
	commitWire, err := commit.Encode()
	if err != nil {
		t.Fatal(err)
	}
	gotCommit, err := DecodePathAdmissionCommit(commitWire)
	if err != nil || gotCommit != commit {
		t.Fatalf("commit=%+v err=%v want %+v", gotCommit, err, commit)
	}

	for _, ack := range []PathAdmissionAck{
		{PathAdmissionBinding: binding, Phase: PathAdmissionPhasePrepared, Code: AckOK},
		{PathAdmissionBinding: binding, Phase: PathAdmissionPhaseCommitted, Code: AckOK},
		{PathAdmissionBinding: binding, Phase: PathAdmissionPhaseFinal, Code: AckRejectProtoState, Reason: "already superseded"},
	} {
		wire, err := ack.Encode()
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodePathAdmissionAck(wire)
		if err != nil || got != ack {
			t.Fatalf("ack=%+v err=%v want %+v", got, err, ack)
		}
	}

	confirm := PathAdmissionConfirm{PathAdmissionBinding: binding, CommittedGeneration: binding.BaseLeafGeneration + 1}
	confirmWire, err := confirm.Encode()
	if err != nil {
		t.Fatal(err)
	}
	gotConfirm, err := DecodePathAdmissionConfirm(confirmWire)
	if err != nil || gotConfirm != confirm {
		t.Fatalf("confirm=%+v err=%v want %+v", gotConfirm, err, confirm)
	}
}

func TestPathAdmissionWireStability(t *testing.T) {
	binding := testPathAdmissionBinding()
	commit, _ := (PathAdmissionCommit{PathAdmissionBinding: binding, Phase: PathAdmissionPhaseCommit}).Encode()
	ack, _ := (PathAdmissionAck{PathAdmissionBinding: binding, Phase: PathAdmissionPhaseFinal, Code: AckRejectAttach, Reason: "wire-stability"}).Encode()
	confirm, _ := (PathAdmissionConfirm{PathAdmissionBinding: binding, CommittedGeneration: 9}).Encode()
	tests := []struct {
		name string
		wire []byte
		size int
		want string
	}{
		{name: "commit", wire: commit, size: PathAdmissionCommitSize, want: "99ea7b05f2333cdd748fe949d6efce6f63ddaad475c37405a5a4dda3182af9a6"},
		{name: "ack", wire: ack, size: PathAdmissionAckHeaderSize + len("wire-stability"), want: "bb007c398a9d4746d88a0311dff405ac2fb462f213deb2c882272beaf174a680"},
		{name: "confirm", wire: confirm, size: PathAdmissionConfirmSize, want: "39d42476d3a776ed07f498da1f9e6d6afcb9fa49af3ae346d71b2bf5ec360a5b"},
	}
	for _, test := range tests {
		if len(test.wire) != test.size {
			t.Errorf("%s size=%d want=%d", test.name, len(test.wire), test.size)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(test.wire)); got != test.want {
			t.Errorf("%s wire sha256=%s want=%s", test.name, got, test.want)
		}
	}
}

func TestPathAdmissionRejectsTruncationAndTrailingBytes(t *testing.T) {
	binding := testPathAdmissionBinding()
	commit, _ := (PathAdmissionCommit{PathAdmissionBinding: binding, Phase: PathAdmissionPhaseCommit}).Encode()
	ack, _ := (PathAdmissionAck{PathAdmissionBinding: binding, Phase: PathAdmissionPhaseCommitted, Code: AckOK, Reason: "ok"}).Encode()
	confirm, _ := (PathAdmissionConfirm{PathAdmissionBinding: binding, CommittedGeneration: 9}).Encode()
	tests := []struct {
		name   string
		wire   []byte
		decode func([]byte) error
	}{
		{"commit short", commit[:len(commit)-1], func(b []byte) error { _, err := DecodePathAdmissionCommit(b); return err }},
		{"commit trailing", append(append([]byte(nil), commit...), 0), func(b []byte) error { _, err := DecodePathAdmissionCommit(b); return err }},
		{"ack short", ack[:len(ack)-1], func(b []byte) error { _, err := DecodePathAdmissionAck(b); return err }},
		{"ack trailing", append(append([]byte(nil), ack...), 0), func(b []byte) error { _, err := DecodePathAdmissionAck(b); return err }},
		{"confirm short", confirm[:len(confirm)-1], func(b []byte) error { _, err := DecodePathAdmissionConfirm(b); return err }},
		{"confirm trailing", append(append([]byte(nil), confirm...), 0), func(b []byte) error { _, err := DecodePathAdmissionConfirm(b); return err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.decode(test.wire); err == nil {
				t.Fatal("accepted non-canonical payload size")
			}
		})
	}
}

func TestPathAdmissionRejectsInvalidEnvelopeAndBinding(t *testing.T) {
	base, _ := (PathAdmissionCommit{PathAdmissionBinding: testPathAdmissionBinding(), Phase: PathAdmissionPhaseCommit}).Encode()
	mutations := map[string]func([]byte){
		"magic":            func(b []byte) { b[0] ^= 0xff },
		"wire version":     func(b []byte) { b[4]++ },
		"message":          func(b []byte) { b[5] = byte(pathAdmissionMessageAck) },
		"kind zero":        func(b []byte) { b[6] = 0 },
		"kind range":       func(b []byte) { b[6] = 3 },
		"direction":        func(b []byte) { b[7] = 0 },
		"phase":            func(b []byte) { b[8] = byte(PathAdmissionPhaseCommitted) },
		"reserved code":    func(b []byte) { b[9] = byte(AckRejectAttach) },
		"reserved":         func(b []byte) { b[15] = 1 },
		"session epoch":    func(b []byte) { clear(b[16:32]) },
		"admission id":     func(b []byte) { clear(b[32:48]) },
		"graph revision":   func(b []byte) { clear(b[48:56]) },
		"graph digest":     func(b []byte) { clear(b[56:88]) },
		"target id":        func(b []byte) { clear(b[88:104]) },
		"responder target": func(b []byte) { clear(b[104:120]) },
		"base generation": func(b []byte) {
			for i := 120; i < 128; i++ {
				b[i] = 0xff
			}
		},
		"proposal digest": func(b []byte) { clear(b[128:160]) },
		"plan digest":     func(b []byte) { clear(b[160:192]) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			wire := append([]byte(nil), base...)
			mutate(wire)
			if _, err := DecodePathAdmissionCommit(wire); err == nil {
				t.Fatal("accepted malformed path admission commit")
			}
		})
	}
}

func TestPathAdmissionAckBoundsAndReservedFields(t *testing.T) {
	binding := testPathAdmissionBinding()
	boundary := PathAdmissionAck{
		PathAdmissionBinding: binding,
		Phase:                PathAdmissionPhaseCommitted,
		Code:                 AckOK,
		Reason:               strings.Repeat("x", PathAdmissionMaxReasonBytes),
	}
	wire, err := boundary.Encode()
	if err != nil {
		t.Fatalf("rejected reason boundary: %v", err)
	}
	if _, err := DecodePathAdmissionAck(wire); err != nil {
		t.Fatalf("failed to decode reason boundary: %v", err)
	}
	if len(wire) != PathAdmissionAckMaxSize {
		t.Fatalf("reason boundary wire size=%d want=%d", len(wire), PathAdmissionAckMaxSize)
	}
	boundary.Reason += "x"
	if _, err := boundary.Encode(); err == nil {
		t.Fatal("accepted oversized reason")
	}
	boundary.Reason = string([]byte{0xff})
	if _, err := boundary.Encode(); err == nil {
		t.Fatal("accepted invalid UTF-8 reason")
	}

	valid, _ := (PathAdmissionAck{PathAdmissionBinding: binding, Phase: PathAdmissionPhaseFinal, Code: AckOK, Reason: "x"}).Encode()
	mutations := map[string]func([]byte){
		"phase":           func(b []byte) { b[8] = byte(PathAdmissionPhaseConfirm) },
		"ack code":        func(b []byte) { b[9] = 0xff },
		"header reserved": func(b []byte) { b[199] = 1 },
		"reason length":   func(b []byte) { b[193]++ },
		"reason utf8":     func(b []byte) { b[PathAdmissionAckHeaderSize] = 0xff },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			wire := append([]byte(nil), valid...)
			mutate(wire)
			if _, err := DecodePathAdmissionAck(wire); err == nil {
				t.Fatal("accepted malformed path admission ack")
			}
		})
	}
}

func TestPathAdmissionConfirmRequiresNextGeneration(t *testing.T) {
	binding := testPathAdmissionBinding()
	for _, generation := range []uint64{0, binding.BaseLeafGeneration, binding.BaseLeafGeneration + 2} {
		confirm := PathAdmissionConfirm{PathAdmissionBinding: binding, CommittedGeneration: generation}
		if _, err := confirm.Encode(); err == nil {
			t.Errorf("accepted committed generation %d", generation)
		}
	}
	valid, _ := (PathAdmissionConfirm{PathAdmissionBinding: binding, CommittedGeneration: binding.BaseLeafGeneration + 1}).Encode()
	mutations := map[string]func([]byte){
		"phase":            func(b []byte) { b[8] = byte(PathAdmissionPhaseFinal) },
		"reserved code":    func(b []byte) { b[9] = byte(AckRejectAttach) },
		"zero generation":  func(b []byte) { clear(b[192:200]) },
		"wrong generation": func(b []byte) { b[199]++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			wire := append([]byte(nil), valid...)
			mutate(wire)
			if _, err := DecodePathAdmissionConfirm(wire); err == nil {
				t.Fatal("accepted malformed path admission confirmation")
			}
		})
	}

	initial := binding
	initial.BaseLeafGeneration = 0
	if _, err := (PathAdmissionCommit{PathAdmissionBinding: initial, Phase: PathAdmissionPhaseCommit}).Encode(); err != nil {
		t.Fatalf("initial admission rejected base generation zero: %v", err)
	}
	if _, err := (PathAdmissionConfirm{PathAdmissionBinding: initial, CommittedGeneration: 1}).Encode(); err != nil {
		t.Fatalf("initial admission rejected generation one: %v", err)
	}
}

func TestPathAdmissionPhaseMatchingRejectsMutatedIdentity(t *testing.T) {
	commit := PathAdmissionCommit{PathAdmissionBinding: testPathAdmissionBinding(), Phase: PathAdmissionPhaseCommit}
	ack := PathAdmissionAck{PathAdmissionBinding: commit.PathAdmissionBinding, Phase: PathAdmissionPhaseCommitted, Code: AckOK}
	confirm := PathAdmissionConfirm{PathAdmissionBinding: commit.PathAdmissionBinding, CommittedGeneration: commit.BaseLeafGeneration + 1}
	if err := ack.ValidateForCommit(commit); err != nil {
		t.Fatalf("matching ack rejected: %v", err)
	}
	if err := confirm.ValidateForCommit(commit); err != nil {
		t.Fatalf("matching confirm rejected: %v", err)
	}

	mutations := map[string]func(*PathAdmissionBinding){
		"kind":           func(b *PathAdmissionBinding) { b.Kind = PathAdmissionKindHello },
		"direction":      func(b *PathAdmissionBinding) { b.Direction = SenderDirectionClientToServer },
		"session":        func(b *PathAdmissionBinding) { b.SessionEpoch[15] ^= 1 },
		"admission":      func(b *PathAdmissionBinding) { b.AdmissionID[15] ^= 1 },
		"revision":       func(b *PathAdmissionBinding) { b.InitiatorGraphRevision++ },
		"graph digest":   func(b *PathAdmissionBinding) { b.InitiatorGraphDigest[31] ^= 1 },
		"target":         func(b *PathAdmissionBinding) { b.InitiatorTargetID[15] ^= 1 },
		"responder":      func(b *PathAdmissionBinding) { b.ResponderTargetID[15] ^= 1 },
		"generation":     func(b *PathAdmissionBinding) { b.BaseLeafGeneration++ },
		"proposal":       func(b *PathAdmissionBinding) { b.ProposalDigest[31] ^= 1 },
		"responder plan": func(b *PathAdmissionBinding) { b.ResponderPlanDigest[31] ^= 1 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changedAck := ack
			mutate(&changedAck.PathAdmissionBinding)
			if err := changedAck.ValidateForCommit(commit); err == nil {
				t.Fatal("accepted ACK with mutated identity")
			}

			changedConfirm := confirm
			mutate(&changedConfirm.PathAdmissionBinding)
			changedConfirm.CommittedGeneration = changedConfirm.BaseLeafGeneration + 1
			if err := changedConfirm.ValidateForCommit(commit); err == nil {
				t.Fatal("accepted confirmation with mutated identity")
			}
		})
	}
}

func FuzzDecodePathAdmissionTransactions(f *testing.F) {
	for _, seed := range pathAdmissionFuzzSeeds(f) {
		f.Add(seed.wire)
		for _, boundary := range protocolFuzzBoundaries(seed.wire) {
			f.Add(boundary.wire)
		}
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, wire []byte) {
		_ = exercisePathAdmissionFuzzWire(t, wire)
	})
}
