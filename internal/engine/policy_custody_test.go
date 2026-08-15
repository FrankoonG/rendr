package engine

import (
	"errors"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
)

func TestPolicyEarlyCustodyDoesNotAdvanceAckAcrossDataGap(t *testing.T) {
	fixture := newPolicyTxUnitFixture(t)
	prepare := policyTxUnitPrepare(
		fixture.engine, 0x81, 0, fixture.selectorID, fixture.targetB,
	)
	payload, err := prepare.Encode()
	if err != nil {
		t.Fatal(err)
	}
	prepareHeader := proto.Header{
		Version: proto.Version,
		Type:    proto.FrameCtrl,
		Flags:   proto.FlagsForCtrl(proto.CtrlPolicyPrepare),
		Seq:     1,
	}

	fixture.engine.recvMu.Lock()
	initialProof := fixture.engine.recvProof
	woke := fixture.engine.onFrameRecvLocked(nil, prepareHeader, payload, nil)
	item, queued := fixture.engine.recvQueue[prepareHeader.Seq]
	expected := fixture.engine.expectedRecvSeq
	proof := fixture.engine.recvProof
	fixture.engine.recvMu.Unlock()
	if woke {
		t.Fatal("policy custody woke an application reader across a DATA gap")
	}
	if !queued || !item.ctrlApplied {
		t.Fatalf("PREPARE custody queued=%t applied=%t", queued, item.ctrlApplied)
	}
	if expected != 0 || proof != initialProof {
		t.Fatalf("policy custody advanced cumulative proof: next=%d proof=%x initial=%x", expected, proof, initialProof)
	}

	deadline := time.Now().Add(time.Second)
	for {
		observations, decodeErr := fixture.recorder.snapshot()
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if len(observations) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("PREPARE was not handled from custody; ACKs=%d", len(observations))
		}
		time.Sleep(time.Millisecond)
	}

	dataHeader := proto.Header{Version: proto.Version, Type: proto.FrameData, Seq: 0}
	fixture.engine.recvMu.Lock()
	woke = fixture.engine.onFrameRecvLocked(nil, dataHeader, []byte("ordered-data"), nil)
	expected = fixture.engine.expectedRecvSeq
	_, queued = fixture.engine.recvQueue[prepareHeader.Seq]
	proof = fixture.engine.recvProof
	fixture.engine.recvMu.Unlock()
	if !woke {
		t.Fatal("closing the DATA gap did not wake the application reader")
	}
	if expected != 2 || queued || proof == initialProof {
		t.Fatalf("ordered drain next=%d prepareQueued=%t proof=%x", expected, queued, proof)
	}
	time.Sleep(10 * time.Millisecond)
	observations, decodeErr := fixture.recorder.snapshot()
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if len(observations) != 1 {
		t.Fatalf("PREPARE executed %d times after ordered drain", len(observations))
	}
}

func TestPolicyEarlyCustodyRejectsCommitBelowPrepareSequence(t *testing.T) {
	e := newPolicyCustodyUnitEngine(4)
	prepare, prepareItem, commit, commitItem := policyCustodyUnitFrames(t, 10, 5)
	e.recvQueue[10] = prepareItem
	if !e.applyPolicyCtrlAtCustodyLocked(10, prepareItem) {
		t.Fatal("valid PREPARE did not enter custody")
	}
	e.recvQueue[5] = commitItem
	if e.applyPolicyCtrlAtCustodyLocked(5, commitItem) {
		t.Fatal("COMMIT below PREPARE sequence entered custody")
	}
	if !e.recvTerminal || !errors.Is(e.recvFinalErr, ErrPeerProtocol) {
		t.Fatalf("inverse sequence terminal=%t err=%v", e.recvTerminal, e.recvFinalErr)
	}
	if got := len(e.policyInbox); got != 1 {
		t.Fatalf("policy inbox length=%d want only PREPARE", got)
	}
	message := <-e.policyInbox
	if message.prepare != prepare || message.kind != policyMessagePrepare {
		t.Fatalf("first custody message=%+v", message)
	}
	if commit.ProposalDigest == (proto.PolicyProposalDigest{}) {
		t.Fatal("test COMMIT has zero proposal digest")
	}
}

func TestPolicyEarlyCustodyRejectsChangedCommitReceipt(t *testing.T) {
	e := newPolicyCustodyUnitEngine(4)
	_, prepareItem, commit, commitItem := policyCustodyUnitFrames(t, 1, 2)
	e.recvQueue[1] = prepareItem
	if !e.applyPolicyCtrlAtCustodyLocked(1, prepareItem) {
		t.Fatal("valid PREPARE did not enter custody")
	}
	e.recvQueue[2] = commitItem
	if !e.applyPolicyCtrlAtCustodyLocked(2, commitItem) {
		t.Fatal("valid COMMIT did not enter custody")
	}

	altered := commit
	altered.ReservationID[0] ^= 0xff
	payload, err := altered.Encode()
	if err != nil {
		t.Fatal(err)
	}
	header := proto.Header{
		Version: proto.Version, Type: proto.FrameCtrl,
		Flags: proto.FlagsForCtrl(proto.CtrlPolicyCommit), Seq: 3,
	}
	item := recvItem{
		isCtrl: true, flags: header.Flags, payload: payload,
		digest: recvFrameDigest(header, payload),
	}
	if e.applyPolicyCtrlAtCustodyLocked(3, item) {
		t.Fatal("changed COMMIT receipt entered custody")
	}
	if !e.recvTerminal || !errors.Is(e.recvFinalErr, ErrPeerProtocol) {
		t.Fatalf("changed COMMIT terminal=%t err=%v", e.recvTerminal, e.recvFinalErr)
	}
	if got := len(e.policyInbox); got != 2 {
		t.Fatalf("policy inbox length=%d want PREPARE+original COMMIT", got)
	}
}

func TestPolicyInboxOverflowDoesNotAdvanceCumulativeProof(t *testing.T) {
	e := newPolicyCustodyUnitEngine(1)
	e.policyInbox <- policyMessage{
		kind: policyMessageAck,
		key:  policyMessageKey{kind: policyMessageAck, seq: 99, frameDigest: proto.FrameDigest{99}},
	}
	prepare, _, _, _ := policyCustodyUnitFrames(t, 0, 1)
	payload, err := prepare.Encode()
	if err != nil {
		t.Fatal(err)
	}
	header := proto.Header{
		Version: proto.Version, Type: proto.FrameCtrl,
		Flags: proto.FlagsForCtrl(proto.CtrlPolicyPrepare), Seq: 0,
	}
	initialProof := e.recvProof
	e.recvMu.Lock()
	e.onFrameRecvLocked(nil, header, payload, nil)
	item, queued := e.recvQueue[0]
	next, proof := e.expectedRecvSeq, e.recvProof
	e.recvMu.Unlock()
	if !e.recvTerminal || !errors.Is(e.recvFinalErr, ErrPeerProtocol) {
		t.Fatalf("overflow terminal=%t err=%v", e.recvTerminal, e.recvFinalErr)
	}
	if !queued || item.ctrlApplied {
		t.Fatalf("overflow frame queued=%t applied=%t", queued, item.ctrlApplied)
	}
	if next != 0 || proof != initialProof {
		t.Fatalf("overflow advanced proof next=%d proof=%x initial=%x", next, proof, initialProof)
	}
	if len(e.recvPolicyPhases) != 0 {
		t.Fatalf("overflow retained %d false custody receipts", len(e.recvPolicyPhases))
	}
}

func TestPolicyEarlyCustodyRejectsWorkAfterTerminalOrClose(t *testing.T) {
	for _, test := range []struct {
		name  string
		close bool
	}{
		{name: "terminal"},
		{name: "close", close: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			e := newPolicyCustodyUnitEngine(1)
			prepare, item, _, _ := policyCustodyUnitFrames(t, 1, 2)
			if test.close {
				e.closing.Store(true)
			} else {
				e.recvTerminal = true
			}
			if e.applyPolicyCtrlAtCustodyLocked(1, item) {
				t.Fatal("policy work entered custody after terminal boundary")
			}
			if len(e.policyInbox) != 0 || len(e.recvPolicyPhases) != 0 {
				t.Fatalf("post-terminal inbox=%d receipts=%d", len(e.policyInbox), len(e.recvPolicyPhases))
			}
			if prepare.TransactionID == ([16]byte{}) {
				t.Fatal("test PREPARE has zero transaction id")
			}
		})
	}
}

func TestPolicyEarlyCustodyPreservesPrepareBeforeCommitCausality(t *testing.T) {
	e := newPolicyCustodyUnitEngine(4)
	prepare, prepareItem, _, commitItem := policyCustodyUnitFrames(t, 1, 2)
	commitPayload := commitItem.payload
	commitItem.ctrlApplied = false
	e.recvQueue[2] = commitItem
	if e.applyPolicyCtrlAtCustodyLocked(2, commitItem) {
		t.Fatal("COMMIT entered policy FIFO before its PREPARE")
	}
	if len(e.policyInbox) != 0 {
		t.Fatalf("policy inbox length=%d before PREPARE", len(e.policyInbox))
	}

	e.recvQueue[1] = prepareItem
	if !e.applyPolicyCtrlAtCustodyLocked(1, prepareItem) {
		t.Fatal("valid PREPARE did not enter policy FIFO")
	}
	deferred := e.recvQueue[2]
	if !deferred.ctrlApplied {
		t.Fatal("matching deferred COMMIT was not admitted after PREPARE")
	}
	if len(e.policyInbox) != 2 {
		t.Fatalf("policy inbox length=%d want=2", len(e.policyInbox))
	}
	first := <-e.policyInbox
	second := <-e.policyInbox
	if first.kind != policyMessagePrepare || second.kind != policyMessageCommit {
		t.Fatalf("policy FIFO order=%d,%d want PREPARE,COMMIT", first.kind, second.kind)
	}
	if first.prepare != prepare || len(commitPayload) == 0 {
		t.Fatal("policy FIFO payload changed")
	}
}

func newPolicyCustodyUnitEngine(inboxCapacity int) *Engine {
	return &Engine{
		recvQueue:        make(map[uint64]recvItem),
		recvPolicyPhases: make(map[recvPolicyPhaseKey]recvPolicyPhaseReceipt),
		policyInbox:      make(chan policyMessage, inboxCapacity),
		policyQueued:     make(map[policyMessageKey]struct{}),
	}
}

func policyCustodyUnitFrames(
	t *testing.T,
	prepareSeq, commitSeq uint64,
) (proto.PolicyPrepare, recvItem, proto.PolicyCommit, recvItem) {
	t.Helper()
	prepare := proto.PolicyPrepare{
		PolicyTransactionBinding: proto.PolicyTransactionBinding{
			SessionEpoch:  proto.SessionEpoch{1},
			Direction:     proto.SenderDirectionClientToServer,
			GraphBinding:  proto.GraphBinding{Revision: 1, Digest: proto.GraphDigest{2}},
			TransactionID: [16]byte{3},
		},
		BaseGeneration: 0,
		Action:         proto.PolicyActionSelectChild,
		SelectorID:     proto.TargetID{4},
		TargetID:       proto.TargetID{5},
		Cause:          "early-custody-causality",
	}
	digest, err := prepare.ProposalDigest()
	if err != nil {
		t.Fatal(err)
	}
	commit := proto.PolicyCommit{
		PolicyTransactionBinding: prepare.PolicyTransactionBinding,
		Generation:               1,
		ProposalDigest:           digest,
		ReservationID:            proto.PolicyReservationID{6},
		CommitChallenge:          proto.PolicyCommitChallenge{7},
	}
	preparePayload, err := prepare.Encode()
	if err != nil {
		t.Fatal(err)
	}
	commitPayload, err := commit.Encode()
	if err != nil {
		t.Fatal(err)
	}
	commitHeader := proto.Header{
		Version: proto.Version, Type: proto.FrameCtrl,
		Flags: proto.FlagsForCtrl(proto.CtrlPolicyCommit), Seq: commitSeq,
	}
	commitItem := recvItem{
		isCtrl:  true,
		flags:   commitHeader.Flags,
		payload: commitPayload,
		digest:  recvFrameDigest(commitHeader, commitPayload),
	}
	prepareHeader := proto.Header{
		Version: proto.Version, Type: proto.FrameCtrl,
		Flags: proto.FlagsForCtrl(proto.CtrlPolicyPrepare), Seq: prepareSeq,
	}
	prepareItem := recvItem{
		isCtrl:  true,
		flags:   prepareHeader.Flags,
		payload: preparePayload,
		digest:  recvFrameDigest(prepareHeader, preparePayload),
	}
	return prepare, prepareItem, commit, commitItem
}
