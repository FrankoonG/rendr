package engine

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
)

type policyControlProgressCase struct {
	name     string
	ctrl     proto.CtrlCode
	ackPhase proto.PolicyAckPhase
}

var policyControlProgressCases = []policyControlProgressCase{
	{name: "prepare", ctrl: proto.CtrlPolicyPrepare},
	{name: "prepare-ack", ctrl: proto.CtrlPolicyAck, ackPhase: proto.PolicyAckPhasePrepare},
	{name: "commit", ctrl: proto.CtrlPolicyCommit},
	{name: "final-ack", ctrl: proto.CtrlPolicyAck, ackPhase: proto.PolicyAckPhaseFinal},
}

func TestPolicyFinalReserveTracksOrdinaryControlCausality(t *testing.T) {
	if sendPolicyFinalReserve != sendControlReserve+1 {
		t.Fatalf("FINAL reserve=%d want ordinary control reserve + 1 = %d",
			sendPolicyFinalReserve, sendControlReserve+1)
	}
}

func TestFreshPolicyControlEscapesBlockedDataReplay(t *testing.T) {
	for i, test := range policyControlProgressCases {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPolicyTxUnitFixture(t)
			releaseReplay := blockPolicyControlDataReplay(t, fixture)
			defer releaseReplay()

			send := policyControlProgressSender(t, fixture, test, byte(0x90+i))
			done := make(chan error, 1)
			go func() {
				_, err := send()
				done <- err
			}()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("fresh %s: %v", test.name, err)
				}
			case <-time.After(time.Second):
				t.Fatalf("fresh %s remained blocked behind DATA replay", test.name)
			}
			if frame := findPolicyControlFrame(fixture.handleB.Frames(), test); frame == nil {
				t.Fatalf("fresh %s did not escape on the healthy control route", test.name)
			}
		})
	}
}

func TestCommittedPolicyFinalHasReservedCreditWhileFreshControlWaitsForCutover(t *testing.T) {
	fixture := newPolicyTxUnitFixture(t)
	fixture.engine.tailReplayInitialDelay = time.Hour
	fixture.engine.tailReplayMaxBackoff = time.Hour
	prepareCase := policyControlProgressCase{name: "prepare", ctrl: proto.CtrlPolicyPrepare}
	for i := 0; i < sendControlReserve-1; i++ {
		send := policyControlProgressSender(t, fixture, prepareCase, byte(0x20+i))
		if _, err := send(); err != nil {
			t.Fatalf("fill ordinary control credit %d: %v", i, err)
		}
	}

	freshSend := policyControlProgressSender(t, fixture, prepareCase, 0x38)
	generation := fixture.engine.beginSelectorCutover()
	freshDone := make(chan error, 1)
	go func() {
		_, err := freshSend()
		freshDone <- err
	}()
	eventuallyEngine(t, time.Second, func() bool {
		return len(fixture.engine.sendControlSlots) == sendControlReserve
	})
	select {
	case err := <-freshDone:
		fixture.engine.finishSelectorCutover(generation)
		t.Fatalf("fresh control did not wait on the held cutover: %v", err)
	default:
	}

	prepare := policyTxUnitPrepare(fixture.engine, 0x39, 0, fixture.selectorID, fixture.targetB)
	digest, err := prepare.ProposalDigest()
	if err != nil {
		fixture.engine.finishSelectorCutover(generation)
		t.Fatal(err)
	}
	finalAck := proto.PolicyAck{
		PolicyTransactionBinding: prepare.PolicyTransactionBinding,
		Phase:                    proto.PolicyAckPhaseFinal,
		Code:                     proto.PolicyAckCodeAccept,
		Generation:               1,
		CurrentGeneration:        1,
		SelectorGeneration:       1,
		CurrentTargetID:          fixture.targetB,
		ResolvedTargetID:         fixture.targetB,
		ProposalDigest:           digest,
		ReservationID:            proto.PolicyReservationID{0x39, 1},
		CommitChallenge:          proto.PolicyCommitChallenge{0x39, 2},
	}
	finalDone := make(chan error, 1)
	go func() {
		_, sendErr := fixture.engine.sendPolicyFinalWithExistingCutover(finalAck, generation)
		finalDone <- sendErr
	}()
	select {
	case err := <-finalDone:
		if err != nil {
			t.Fatalf("reserved FINAL publication: %v", err)
		}
	case <-time.After(time.Second):
		fixture.engine.finishSelectorCutover(generation)
		t.Fatal("committed FINAL deadlocked behind ordinary control credit")
	}
	select {
	case err := <-freshDone:
		if err != nil {
			t.Fatalf("fresh control after FINAL: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("fresh control did not acquire the released cutover")
	}
	if got := len(fixture.engine.sendPolicyFinalSlots); got != 1 {
		t.Fatalf("FINAL credits in use=%d want 1 of bounded capacity %d", got, sendPolicyFinalReserve)
	}
	fixture.engine.notePeerAck(currentAck(fixture.engine, fixture.engine.sendPublishedNext.Load()))
	if got := len(fixture.engine.sendControlSlots); got != 0 {
		t.Fatalf("ordinary control credits remained after cumulative ACK: %d", got)
	}
	if got := len(fixture.engine.sendPolicyFinalSlots); got != 0 {
		t.Fatalf("FINAL credit remained after cumulative ACK: %d", got)
	}
}

func TestConsecutiveCommittedCutoversRetainIndependentFinalCredits(t *testing.T) {
	fixture := newPolicyTxUnitFixture(t)
	fixture.engine.tailReplayInitialDelay = time.Hour
	fixture.engine.tailReplayMaxBackoff = time.Hour

	payload := []byte("unacknowledged DATA before consecutive policy FINALs")
	if n, err := fixture.engine.SendData(payload); n != len(payload) || err != nil {
		t.Fatalf("SendData=(%d,%v), want (%d,nil)", n, err, len(payload))
	}

	commit := func(txByte byte, base uint64, target proto.TargetID) {
		t.Helper()
		prepare := policyTxUnitPrepare(fixture.engine, txByte, base, fixture.selectorID, target)
		prepared := policyTxUnitRequireAck(t, fixture.recorder, func() error {
			return fixture.engine.handlePolicyPrepare(prepare)
		})
		finalDone := make(chan policyTxUnitAckObservation, 1)
		go func() {
			commit := policyTxUnitCommit(t, prepare, prepared.ack.Generation, prepared.ack.ReservationID)
			finalDone <- policyTxUnitRequireAck(t, fixture.recorder, func() error {
				return fixture.engine.handlePolicyCommit(commit)
			})
		}()
		select {
		case final := <-finalDone:
			if final.ack.Code != proto.PolicyAckCodeAccept || final.ack.CurrentTargetID != target {
				t.Fatalf("FINAL=%+v want accepted target %x", final.ack, target)
			}
		case <-time.After(time.Second):
			t.Fatalf("generation %d committed cutover deadlocked behind an older unacknowledged FINAL", base+1)
		}
	}

	commit(0x61, 0, fixture.targetB)
	if got := len(fixture.engine.sendPolicyFinalSlots); got != 1 {
		t.Fatalf("first FINAL credits=%d want 1", got)
	}
	commit(0x62, 1, fixture.targetA)
	if got := len(fixture.engine.sendPolicyFinalSlots); got != 2 {
		t.Fatalf("independent FINAL credits=%d want 2", got)
	}
	fixture.engine.policyStateMu.Lock()
	generation, selection := fixture.engine.policyGeneration, fixture.engine.policySelections[fixture.selectorID]
	fixture.engine.policyStateMu.Unlock()
	if generation != 2 || selection != fixture.targetA {
		t.Fatalf("policy state generation/selection=%d/%x want 2/%x", generation, selection, fixture.targetA)
	}
	if got := fixture.engine.MigrationCount(); got != 2 {
		t.Fatalf("migration count=%d want exactly 2", got)
	}

	fixture.engine.notePeerAck(currentAck(fixture.engine, fixture.engine.sendPublishedNext.Load()))
	if got := len(fixture.engine.sendPolicyFinalSlots); got != 0 {
		t.Fatalf("FINAL credits remained after cumulative ACK: %d", got)
	}
}

func TestCachedPolicyControlReplayPreservesOwnershipWhileEscapingDataReplay(t *testing.T) {
	for i, test := range policyControlProgressCases {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPolicyTxUnitFixture(t)
			fixture.engine.tailReplayInitialDelay = time.Hour
			fixture.engine.tailReplayMaxBackoff = time.Hour
			send := policyControlProgressSender(t, fixture, test, byte(0xa0+i))
			frame, err := send()
			if err != nil {
				t.Fatalf("publish cached %s: %v", test.name, err)
			}
			if got := findPolicyControlFrame(fixture.handleA.Frames(), test); !bytes.Equal(got, frame) {
				t.Fatalf("initial %s bytes changed on publication", test.name)
			}

			releaseReplay := blockPolicyControlDataReplay(t, fixture)
			defer releaseReplay()
			before := snapshotPolicyControlReplayOwnership(fixture.engine)
			done := make(chan error, 1)
			go func() { done <- fixture.engine.replaySequencedFrame(frame) }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("cached %s replay: %v", test.name, err)
				}
			case <-time.After(time.Second):
				t.Fatalf("cached %s remained blocked behind DATA replay", test.name)
			}
			replayed := findPolicyControlFrame(fixture.handleB.Frames(), test)
			if !bytes.Equal(replayed, frame) {
				t.Fatalf("cached %s replay changed immutable bytes", test.name)
			}
			after := snapshotPolicyControlReplayOwnership(fixture.engine)
			if before != after {
				t.Fatalf("cached %s changed replay ownership: before=%+v after=%+v", test.name, before, after)
			}
		})
	}
}

func TestCachedPolicyResponseReplayAfterACKRetirementKeepsExactBoundedOwner(t *testing.T) {
	for _, phase := range []proto.PolicyAckPhase{
		proto.PolicyAckPhasePrepare,
		proto.PolicyAckPhaseFinal,
	} {
		t.Run(policyAckPhaseName(phase), func(t *testing.T) {
			fixture := newPolicyTxUnitFixture(t)
			fixture.engine.tailReplayInitialDelay = time.Hour
			fixture.engine.tailReplayMaxBackoff = time.Hour
			base := time.Unix(1_700_000_000, 0)
			clock := atomic.Int64{}
			clock.Store(base.UnixNano())
			fixture.engine.policyReplayNow = func() time.Time { return time.Unix(0, clock.Load()) }

			prepare := policyTxUnitPrepare(fixture.engine, byte(0xc0+phase), 0, fixture.selectorID, fixture.targetB)
			prepared := policyTxUnitRequireAck(t, fixture.recorder, func() error {
				return fixture.engine.handlePolicyPrepare(prepare)
			})
			var (
				record    *policyReplayRecord
				replay    func() error
				wantCount = 1
			)
			if phase == proto.PolicyAckPhasePrepare {
				fixture.engine.policyStateMu.Lock()
				record = fixture.engine.policyIncoming.prepareReplay
				fixture.engine.policyStateMu.Unlock()
				replay = func() error { return fixture.engine.handlePolicyPrepare(prepare) }
			} else {
				fixture.engine.notePeerAck(currentAck(fixture.engine, fixture.engine.sendPublishedNext.Load()))
				commit := policyTxUnitCommit(t, prepare, prepared.ack.Generation, prepared.ack.ReservationID)
				policyTxUnitRequireAck(t, fixture.recorder, func() error {
					return fixture.engine.handlePolicyCommit(commit)
				})
				fixture.engine.policyStateMu.Lock()
				record = fixture.engine.policyCompleted[prepare.TransactionID].finalReplay
				fixture.engine.policyStateMu.Unlock()
				replay = func() error { return fixture.engine.handlePolicyCommit(commit) }
				wantCount = 2
			}
			if record == nil {
				t.Fatal("policy response did not retain an explicit replay owner")
			}
			fixture.engine.policyReplayMu.Lock()
			original := append([]byte(nil), record.frame...)
			originalSeq, originalDigest := record.seq, record.digest
			cacheCount, cacheBytes := fixture.engine.policyReplayCount, fixture.engine.policyReplayBytes
			fixture.engine.policyReplayMu.Unlock()
			if cacheCount != wantCount || cacheBytes < len(original) {
				t.Fatalf("policy replay cache count/bytes=%d/%d want count=%d bytes>=%d",
					cacheCount, cacheBytes, wantCount, len(original))
			}

			frontier := fixture.engine.sendPublishedNext.Load()
			fixture.engine.notePeerAck(currentAck(fixture.engine, frontier))
			if got := len(fixture.engine.sendControlSlots); got != 0 {
				t.Fatalf("ordinary control credit remained after ACK retirement: %d", got)
			}
			fixture.engine.sendHistMu.Lock()
			history := len(fixture.engine.sendHist.entries)
			proof := fixture.engine.sendProof
			fixture.engine.sendHistMu.Unlock()
			if history != 0 {
				t.Fatalf("ACK-retired policy response remained in replay ledger: %d", history)
			}
			beforeCopies := countPolicyTxFixtureFrames(fixture, original)
			if err := replay(); err != nil {
				t.Fatalf("paced immediate duplicate: %v", err)
			}
			if got := countPolicyTxFixtureFrames(fixture, original); got != beforeCopies {
				t.Fatalf("immediate duplicate escaped replay pacing: copies=%d want %d", got, beforeCopies)
			}

			clock.Store(base.Add(policyRetryInterval).UnixNano())
			for i := 0; i < 100; i++ {
				if err := replay(); err != nil {
					t.Fatalf("cached duplicate %d: %v", i, err)
				}
			}
			eventuallyEngine(t, time.Second, func() bool {
				return countPolicyTxFixtureFrames(fixture, original) >= beforeCopies+1
			})
			if got := countPolicyTxFixtureFrames(fixture, original); got != beforeCopies+1 {
				t.Fatalf("duplicate burst physical copies=%d want %d", got, beforeCopies+1)
			}
			if atomic.LoadUint64(&fixture.engine.sendSeq) != frontier ||
				fixture.engine.sendPublishedNext.Load() != frontier || fixture.engine.sendProof != proof {
				t.Fatal("cached replay minted a SEQ, publication frontier, or proof")
			}
			eventuallyEngine(t, time.Second, func() bool {
				fixture.engine.policyReplayMu.Lock()
				defer fixture.engine.policyReplayMu.Unlock()
				return !record.inFlight
			})
			fixture.engine.policyReplayMu.Lock()
			changed := record.seq != originalSeq || record.digest != originalDigest || !bytes.Equal(record.frame, original) ||
				record.inFlight || record.retired || fixture.engine.policyReplayCount != wantCount
			recordSnapshot, countSnapshot := *record, fixture.engine.policyReplayCount
			fixture.engine.policyReplayMu.Unlock()
			if changed {
				t.Fatalf("cached owner changed after replay: %+v count=%d", recordSnapshot, countSnapshot)
			}
		})
	}
}

func TestCachedPolicyReplayCannotMintDataWindowReplay(t *testing.T) {
	fixture := newPolicyTxUnitFixture(t)
	fixture.engine.tailReplayInitialDelay = time.Hour
	fixture.engine.tailReplayMaxBackoff = time.Hour
	prepare := policyTxUnitPrepare(fixture.engine, 0xd0, 0, fixture.selectorID, fixture.targetB)
	policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyPrepare(prepare)
	})
	fixture.engine.policyStateMu.Lock()
	record := fixture.engine.policyIncoming.prepareReplay
	fixture.engine.policyStateMu.Unlock()
	if record == nil {
		t.Fatal("PREPARE response has no replay owner")
	}
	fixture.engine.notePeerAck(currentAck(fixture.engine, fixture.engine.sendPublishedNext.Load()))

	before := len(fixture.handleA.Frames())
	if n, err := fixture.engine.SendData([]byte("cached-policy-must-not-mint-window-replay")); n == 0 || err != nil {
		t.Fatalf("publish DATA owner=(%d,%v)", n, err)
	}
	var dataFrame []byte
	for _, frame := range fixture.handleA.Frames()[before:] {
		if len(frame) < proto.HeaderSize {
			continue
		}
		header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err == nil && header.Type == proto.FrameData {
			dataFrame = frame
			break
		}
	}
	if dataFrame == nil {
		t.Fatal("DATA owner was not captured")
	}
	header, err := proto.DecodeHeader(dataFrame[:proto.HeaderSize])
	if err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	release := make(chan struct{})
	var startedOnce, releaseOnce sync.Once
	fixture.handleA.SetBeforeWrite(func(frame []byte) {
		if len(frame) < proto.HeaderSize {
			return
		}
		decoded, decodeErr := proto.DecodeHeader(frame[:proto.HeaderSize])
		if decodeErr != nil || decoded.Type != proto.FrameData {
			return
		}
		startedOnce.Do(func() { close(started) })
		<-release
	})
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	var queued atomic.Uint64
	fixture.engine.replayQueueForTest = func(replayRequest) { queued.Add(1) }
	fixture.engine.requestReplayRange(header.Seq, header.Seq+1)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("bounded DATA replay did not enter blocked path")
	}
	if got := queued.Load(); got != 1 {
		t.Fatalf("initial replay requests=%d want 1", got)
	}
	allowPolicyReplayNow(fixture.engine, record)
	if err := fixture.engine.handlePolicyPrepare(prepare); err != nil {
		t.Fatalf("cached PREPARE replay: %v", err)
	}
	if got := queued.Load(); got != 1 {
		t.Fatalf("cached response minted replay request count=%d want 1", got)
	}
	releaseOnce.Do(func() { close(release) })
	eventuallyEngine(t, time.Second, func() bool { return fixture.handleA.dataWrites.Load() > 1 })
}

func TestPolicyReplayOwnerRetirementWaitsForInflightLease(t *testing.T) {
	fixture := newPolicyTxUnitFixture(t)
	prepare := policyTxUnitPrepare(fixture.engine, 0xd1, 0, fixture.selectorID, fixture.targetB)
	policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyPrepare(prepare)
	})
	fixture.engine.policyStateMu.Lock()
	record := fixture.engine.policyIncoming.prepareReplay
	fixture.engine.policyStateMu.Unlock()
	allowPolicyReplayNow(fixture.engine, record)
	lease, ok := fixture.engine.acquirePolicyReplay(record, nowFn())
	if !ok {
		t.Fatal("explicit replay owner did not grant a lease")
	}
	fixture.engine.retirePolicyReplayRecord(record)
	fixture.engine.policyReplayMu.Lock()
	if !record.retired || record.released || fixture.engine.policyReplayCount != 1 {
		t.Fatalf("in-flight retirement released credit early: record=%+v count=%d", record, fixture.engine.policyReplayCount)
	}
	fixture.engine.policyReplayMu.Unlock()
	fixture.engine.finishPolicyReplay(lease)
	fixture.engine.retirePolicyReplayRecord(record)
	fixture.engine.policyReplayMu.Lock()
	defer fixture.engine.policyReplayMu.Unlock()
	if !record.released || fixture.engine.policyReplayCount != 0 || fixture.engine.policyReplayBytes != 0 {
		t.Fatalf("retired replay credit count/bytes/released=%d/%d/%t want 0/0/true",
			fixture.engine.policyReplayCount, fixture.engine.policyReplayBytes, record.released)
	}
}

type policyControlReplayOwnership struct {
	sendSeq       uint64
	publishedNext uint64
	controlCredit int
	history       int
	proof         proto.AckProof
}

func snapshotPolicyControlReplayOwnership(e *Engine) policyControlReplayOwnership {
	e.sendHistMu.Lock()
	snapshot := policyControlReplayOwnership{
		sendSeq:       atomic.LoadUint64(&e.sendSeq),
		publishedNext: e.sendPublishedNext.Load(),
		controlCredit: len(e.sendControlSlots),
		history:       len(e.sendHist.entries),
		proof:         e.sendProof,
	}
	e.sendHistMu.Unlock()
	return snapshot
}

func policyControlProgressSender(
	t *testing.T,
	fixture *policyTxUnitFixture,
	test policyControlProgressCase,
	txByte byte,
) func() ([]byte, error) {
	t.Helper()
	prepare := policyTxUnitPrepare(fixture.engine, txByte, 0, fixture.selectorID, fixture.targetB)
	digest, err := prepare.ProposalDigest()
	if err != nil {
		t.Fatal(err)
	}
	reservation := proto.PolicyReservationID{txByte, 1}
	switch test.ctrl {
	case proto.CtrlPolicyPrepare:
		return func() ([]byte, error) { return fixture.engine.sendPolicyPrepare(prepare) }
	case proto.CtrlPolicyCommit:
		commit := policyTxUnitCommit(t, prepare, 1, reservation)
		return func() ([]byte, error) { return fixture.engine.sendPolicyCommit(commit) }
	case proto.CtrlPolicyAck:
		ack := proto.PolicyAck{
			PolicyTransactionBinding: prepare.PolicyTransactionBinding,
			Phase:                    test.ackPhase,
			Code:                     proto.PolicyAckCodeAccept,
			Generation:               1,
			CurrentGeneration:        1,
			SelectorGeneration:       1,
			CurrentTargetID:          fixture.targetB,
			ResolvedTargetID:         fixture.targetB,
			ProposalDigest:           digest,
			ReservationID:            reservation,
		}
		if test.ackPhase == proto.PolicyAckPhasePrepare {
			ack.CurrentGeneration = 0
			ack.CurrentTargetID = fixture.targetA
		} else {
			ack.CommitChallenge = proto.PolicyCommitChallenge{txByte, 2}
		}
		return func() ([]byte, error) { return fixture.engine.sendPolicyAck(ack) }
	default:
		t.Fatalf("unsupported policy control %d", test.ctrl)
		return nil
	}
}

func blockPolicyControlDataReplay(t *testing.T, fixture *policyTxUnitFixture) func() {
	t.Helper()
	fixture.engine.tailReplayInitialDelay = time.Hour
	fixture.engine.tailReplayMaxBackoff = time.Hour
	before := len(fixture.handleA.Frames())
	if n, err := fixture.engine.SendData([]byte("policy-control-blocked-replay")); n == 0 || err != nil {
		t.Fatalf("publish DATA replay owner=(%d,%v)", n, err)
	}
	var dataFrame []byte
	for _, frame := range fixture.handleA.Frames()[before:] {
		if len(frame) < proto.HeaderSize {
			continue
		}
		header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err == nil && header.Type == proto.FrameData {
			dataFrame = frame
			break
		}
	}
	if dataFrame == nil {
		t.Fatal("published DATA frame was not captured")
	}

	started := make(chan struct{})
	release := make(chan struct{})
	var startOnce, releaseOnce sync.Once
	fixture.handleA.SetBeforeWrite(func(frame []byte) {
		if len(frame) < proto.HeaderSize {
			return
		}
		header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err != nil || header.Type != proto.FrameData {
			return
		}
		startOnce.Do(func() { close(started) })
		<-release
	})
	replayDone := make(chan error, 1)
	go func() { replayDone <- fixture.engine.replaySequencedFrame(dataFrame) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		releaseOnce.Do(func() { close(release) })
		t.Fatal("DATA replay did not enter the blocked physical writer")
	}
	return func() {
		releaseOnce.Do(func() { close(release) })
		select {
		case err := <-replayDone:
			if err != nil && !errors.Is(err, errSelectorCutoverHandoff) {
				t.Errorf("blocked DATA replay completed with %v", err)
			}
		case <-time.After(time.Second):
			t.Error("blocked DATA replay did not release during cleanup")
		}
	}
}

func countExactPolicyFrames(frames [][]byte, want []byte) int {
	count := 0
	for _, frame := range frames {
		if bytes.Equal(frame, want) {
			count++
		}
	}
	return count
}

func countPolicyTxFixtureFrames(fixture *policyTxUnitFixture, want []byte) int {
	return countExactPolicyFrames(fixture.handleA.Frames(), want) +
		countExactPolicyFrames(fixture.handleB.Frames(), want)
}

func findPolicyControlFrame(frames [][]byte, want policyControlProgressCase) []byte {
	for _, frame := range frames {
		if len(frame) < proto.HeaderSize {
			continue
		}
		header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err != nil || header.Type != proto.FrameCtrl || proto.CtrlCodeFromFlags(header.Flags) != want.ctrl {
			continue
		}
		if want.ctrl == proto.CtrlPolicyAck {
			ack, err := proto.DecodePolicyAck(frame[proto.HeaderSize:])
			if err != nil || ack.Phase != want.ackPhase {
				continue
			}
		}
		return append([]byte(nil), frame...)
	}
	return nil
}
