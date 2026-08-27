package engine

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

func TestProbeReplyCannotRefreshAnotherPathGeneration(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	aBase, aPeer := newMemoryPathPair()
	bBase, bPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = aBase.Close(); _ = aPeer.Close() })
	t.Cleanup(func() { _ = bBase.Close(); _ = bPeer.Close() })
	a := &probeQualityPath{PathConn: aBase}
	b := &probeQualityPath{PathConn: bBase}
	aSlot := &pathSlot{id: 1, owner: 11, conn: a}
	bSlot := &pathSlot{id: 2, owner: 22, conn: b}

	const probeID = 7
	seedOutstandingProbe(t, e, aSlot, probeID, time.Now().Add(-10*time.Millisecond))
	payload := proto.ProbePayload{ID: probeID}.Encode()
	e.handlePathProbeReply(bSlot, payload)
	if quality := bSlot.quality(); quality.RTT != 0 || !quality.At.IsZero() {
		t.Fatalf("cross-path reply refreshed b quality: %+v", quality)
	}
	e.probeMu.Lock()
	_, retained := e.probeOutstanding[probeID]
	e.probeMu.Unlock()
	if !retained {
		t.Fatal("cross-path reply consumed the expected path's probe")
	}

	e.handlePathProbeReply(aSlot, payload)
	quality := aSlot.quality()
	if quality.RTT <= 0 || quality.At.IsZero() {
		t.Fatalf("same-path reply did not refresh a quality: %+v", quality)
	}
	if quality := a.Quality(); quality.RTT != 0 || !quality.At.IsZero() {
		t.Fatalf("engine probe mutated transport quality: %+v", quality)
	}
	if calls := a.setterCalls.Load(); calls != 0 {
		t.Fatalf("engine invoked undocumented SetQuality %d times", calls)
	}
	e.probeMu.Lock()
	_, retained = e.probeOutstanding[probeID]
	e.probeMu.Unlock()
	if retained {
		t.Fatal("same-path reply did not consume the probe")
	}
}

func TestProbeReplyUpdatesEngineQualityWithoutOptionalSetter(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	path, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = path.Close(); _ = peer.Close() })
	slot := &pathSlot{id: 3, owner: 33, conn: path}

	const probeID = 9
	seedOutstandingProbe(t, e, slot, probeID, time.Now().Add(-5*time.Millisecond))
	e.handlePathProbeReply(slot, proto.ProbePayload{ID: probeID}.Encode())
	quality := slot.quality()
	if quality.RTT <= 0 || quality.At.IsZero() {
		t.Fatalf("engine-owned probe quality=%+v", quality)
	}
	if path.Quality().RTT != 0 {
		t.Fatal("test PathConn unexpectedly provided a quality setter")
	}
}

func TestSelectorProbeFreshWindowMeetsDefaultG4BudgetAndWidensForSlowPath(t *testing.T) {
	ordinary := selectorProbeFreshFor(time.Second, transport.PathQuality{RTT: 100 * time.Millisecond})
	if ordinary != 3*time.Second {
		t.Fatalf("ordinary fresh window=%v want 3s", ordinary)
	}
	slow := selectorProbeFreshFor(time.Second, transport.PathQuality{RTT: 2 * time.Second, Jitter: 500 * time.Millisecond})
	if slow != maximumSelectorProbeFreshFor {
		t.Fatalf("slow fresh window=%v want hard cap %v", slow, maximumSelectorProbeFreshFor)
	}
	fastCadence := selectorProbeFreshFor(10*time.Millisecond, transport.PathQuality{RTT: time.Millisecond})
	if fastCadence != minimumSelectorProbeFreshFor {
		t.Fatalf("fast-cadence fresh window=%v want floor %v", fastCadence, minimumSelectorProbeFreshFor)
	}
	if got := pathProbeDataStarvationFor(time.Second); got != 2*time.Second {
		t.Fatalf("default DATA-starvation window=%v want two 1s probe cadences", got)
	}
	if got := pathProbeDataStarvationFor(10 * time.Millisecond); got != 20*time.Millisecond {
		t.Fatalf("fast DATA-starvation window=%v want two probe cadences", got)
	}
	if got := pathProbeDataStarvationFor(30 * time.Second); got != maximumPathProbeDataStarvationFor {
		t.Fatalf("bounded DATA-starvation window=%v want %v", got, maximumPathProbeDataStarvationFor)
	}
}

func TestProberIssuesFirstProbeImmediately(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: time.Second}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	ids := configureLeafSelectorRuntime(t, e, "probe")
	path, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = peer.Close() })
	attachFixturePath(t, e, path, transport.PathSpec{Transport: "memory", Address: "probe"}, ids["probe"])
	e.StartSelector(time.Second)
	deadline := time.Now().Add(200 * time.Millisecond)
	for {
		e.probeMu.Lock()
		committed := false
		for _, observation := range e.probeOutstanding {
			committed = committed || observation.lifecycle == pathProbeWriteCommitted
		}
		e.probeMu.Unlock()
		if committed {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("first probe waited for the one-second cadence")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestProbeWithoutFirstReplyBecomesHardStaleWithinG4Budget(t *testing.T) {
	slot := &pathSlot{id: 4, owner: 44, conn: &probeQualityPath{}}
	issued := time.Unix(100, 0)
	generation := pathProbeGenerationForSlot(slot)
	slot.probeEvidence.Store(&pathProbeEvidence{
		generation: generation, firstIssued: issued, lastIssued: issued,
		lastWireTimeout: issued.Add(maximumSelectorProbeFreshFor),
		lastLifecycle:   pathProbeWireTimeout, issued: 1, timedOut: 1,
	})
	if state := slot.probeLiveness(issued.Add(maximumSelectorProbeFreshFor-time.Nanosecond), 30*time.Second); state != qualityStateUnknown {
		t.Fatalf("pre-deadline liveness=%d want unknown", state)
	}
	if state := slot.probeLiveness(issued.Add(maximumSelectorProbeFreshFor+time.Nanosecond), 30*time.Second); state != qualityStateStale {
		t.Fatalf("post-deadline liveness=%d want stale", state)
	}
}

func TestProbeTokenRolloverDoesNotInheritHistoricalFreshness(t *testing.T) {
	tests := []struct {
		name     string
		rollover func(*Engine, *pathSlot)
	}{
		{
			name: "TX fence epoch",
			rollover: func(_ *Engine, slot *pathSlot) {
				slot.txFenceEpoch.Add(1)
			},
		},
		{
			name: "migration epoch",
			rollover: func(e *Engine, _ *pathSlot) {
				e.migrationEpoch.Add(1)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: time.Second}.Clamp())
			t.Cleanup(func() { _ = e.Close() })
			slot := &pathSlot{id: 40, owner: 400, migrationEpochSource: &e.migrationEpoch}
			generation := pathProbeGenerationForSlot(slot)
			oldSuccess := time.Unix(10_000, 0)
			slot.probeEvidence.Store(&pathProbeEvidence{
				generation: generation, fenceEpoch: slot.txFenceEpoch.Load(), fenceTracked: true,
				migrationEpoch: e.migrationEpoch.Load(), migrationTracked: true,
				firstIssued: oldSuccess.Add(-time.Second), lastIssued: oldSuccess,
				lastSuccess: oldSuccess, lastWireTimeout: oldSuccess.Add(-time.Millisecond),
				lastLifecycle: pathProbeWriteCommitted, lastTransition: oldSuccess,
				quality: transport.PathQuality{RTT: 10 * time.Millisecond, At: oldSuccess},
				issued:  4, succeeded: 3, timedOut: 1,
			})

			test.rollover(e, slot)
			committedAt := oldSuccess.Add(time.Hour)
			observation := pathProbeObservation{
				slot: slot, generation: generation,
				fenceEpoch:         slot.txFenceEpoch.Load(),
				wireMigrationEpoch: e.migrationEpoch.Load(), wireProgressTracked: true,
				lifecycle: pathProbeWriteCommitted, writeCommittedAt: committedAt,
				quality: transport.PathQuality{RTT: 20 * time.Millisecond, At: committedAt},
			}
			e.probeMu.Lock()
			e.recordPathProbeIssuedLocked(observation)
			e.probeMu.Unlock()

			evidence, ok := slot.probeSnapshot()
			if !ok {
				t.Fatal("new probe token evidence was unavailable")
			}
			if evidence.issued != 5 || evidence.succeeded != 3 || evidence.timedOut != 1 {
				t.Fatalf("cumulative diagnostics=%+v want issued/succeeded/timedOut 5/3/1", evidence)
			}
			if state := slot.probeLiveness(committedAt.Add(time.Millisecond), e.limits.ProbeInterval); state != qualityStateUnknown {
				t.Fatalf("new unanswered token liveness=%d want unknown", state)
			}
			if state := selectorProbeLiveness(evidence, true, committedAt.Add(time.Millisecond), e.limits.ProbeInterval); state != qualityStateUnknown {
				t.Fatalf("selector liveness from new unanswered token=%d want unknown", state)
			}
			if loss, at, known := selectorLossEvidence(
				transport.PathQuality{}, evidence, true, committedAt.Add(time.Millisecond),
			); known {
				t.Fatalf("historical token produced current loss=%d at %v", loss, at)
			}

			replyAt := committedAt.Add(20 * time.Millisecond)
			accepted := false
			e.probeMu.Lock()
			slot.mutateHealthEvidence(func() {
				accepted = e.recordPathProbeSuccessLocked(observation, replyAt)
			})
			e.probeMu.Unlock()
			if !accepted {
				t.Fatal("first reply for the new probe token was rejected")
			}
			evidence, ok = slot.probeSnapshot()
			if !ok || evidence.issued != 5 || evidence.succeeded != 4 || evidence.timedOut != 1 {
				t.Fatalf("post-reply cumulative diagnostics=%+v available=%t", evidence, ok)
			}
			if state := slot.probeLiveness(replyAt, e.limits.ProbeInterval); state != qualityStateFresh {
				t.Fatalf("new token liveness after first reply=%d want fresh", state)
			}
			loss, _, known := selectorLossEvidence(transport.PathQuality{}, evidence, true, replyAt)
			if !known || loss != 0 {
				t.Fatalf("new token loss after first reply=%d known=%t want 0/true", loss, known)
			}
		})
	}
}

func TestProbeReplyCannotCrossEndpointGeneration(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	path := &probeQualityPath{}
	slot := &pathSlot{id: 5, owner: 55, conn: path}
	slot.probeEndpointGen.Store(1)
	const probeID = 11
	seedOutstandingProbe(t, e, slot, probeID, time.Now().Add(-time.Millisecond))
	slot.probeEndpointGen.Store(2)
	e.handlePathProbeReply(slot, proto.ProbePayload{ID: probeID}.Encode())
	if quality := slot.quality(); quality.RTT != 0 || !quality.At.IsZero() {
		t.Fatalf("old endpoint reply refreshed successor quality: %+v", quality)
	}
	e.probeMu.Lock()
	_, retained := e.probeOutstanding[probeID]
	e.probeMu.Unlock()
	if retained {
		t.Fatal("obsolete endpoint probe remained outstanding")
	}
}

func TestProbeTimeoutAndTransportQualityRemainIndependent(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	path := &probeQualityPath{}
	path.setTransportQuality(transport.PathQuality{LossPP: 17})
	slot := &pathSlot{id: 6, owner: 66, conn: path}
	const probeID = 13
	issued := time.Now().Add(-time.Second)
	seedOutstandingProbe(t, e, slot, probeID, issued)
	e.probeMu.Lock()
	observation := e.probeOutstanding[probeID]
	observation.deadline = time.Now().Add(-time.Nanosecond)
	e.probeOutstanding[probeID] = observation
	e.probeMu.Unlock()
	e.expirePathProbes(time.Now())
	evidence, ok := slot.probeSnapshot()
	if !ok || evidence.issued != 1 || evidence.succeeded != 0 || evidence.timedOut != 1 {
		t.Fatalf("probe counters=%+v ok=%t", evidence, ok)
	}

	const replyID = 14
	seedOutstandingProbe(t, e, slot, replyID, time.Now().Add(-time.Millisecond))
	e.handlePathProbeReply(slot, proto.ProbePayload{ID: replyID}.Encode())
	quality := slot.quality()
	if quality.RTT <= 0 || quality.LossPP != 17 {
		t.Fatalf("merged quality after probe=%+v", quality)
	}
	path.setTransportQuality(transport.PathQuality{LossPP: 29})
	if quality := slot.quality(); quality.RTT <= 0 || quality.LossPP != 29 {
		t.Fatalf("transport update was masked by probe overlay: %+v", quality)
	}
	if calls := path.setterCalls.Load(); calls != 0 {
		t.Fatalf("engine invoked undocumented SetQuality %d times", calls)
	}
}

func TestNewerTransportTimingSupersedesOlderEngineProbe(t *testing.T) {
	path := &probeQualityPath{}
	slot := &pathSlot{id: 61, owner: 66, conn: path}
	generation := pathProbeGenerationForSlot(slot)
	probeAt := time.Unix(100, 0)
	slot.probeEvidence.Store(&pathProbeEvidence{
		generation:  generation,
		lastSuccess: probeAt,
		quality: transport.PathQuality{
			RTT: 10 * time.Millisecond, Jitter: time.Millisecond, At: probeAt,
		},
	})

	newer := transport.PathQuality{
		RTT: 80 * time.Millisecond, Jitter: 7 * time.Millisecond,
		LossPP: 23, At: probeAt.Add(time.Second),
	}
	path.setTransportQuality(newer)
	if got := slot.quality(); got != newer {
		t.Fatalf("newer transport timing=%+v want %+v", got, newer)
	}

	older := transport.PathQuality{
		RTT: 90 * time.Millisecond, Jitter: 8 * time.Millisecond,
		LossPP: 29, At: probeAt.Add(-time.Second),
	}
	path.setTransportQuality(older)
	got := slot.quality()
	if got.RTT != 10*time.Millisecond || got.Jitter != time.Millisecond || got.At != probeAt || got.LossPP != older.LossPP {
		t.Fatalf("older transport timing did not retain newer probe overlay: %+v", got)
	}
}

func TestFailedProbeWriteDoesNotCreateLivenessEvidence(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	path, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = path.Close() })
	t.Cleanup(func() { _ = peer.Close() })
	// A retired slot rejects the writer lease before any wire attempt.
	slot := &pathSlot{id: 7, owner: 77, conn: path, quit: make(chan struct{}), writePermit: newPathWritePermit()}
	slot.probeControlClosed = true
	e.issuePathProbe(slot)
	if _, ok := slot.probeSnapshot(); ok {
		t.Fatal("failed probe write created selector liveness evidence")
	}
	e.probeMu.Lock()
	outstanding := len(e.probeOutstanding)
	e.probeMu.Unlock()
	if outstanding != 0 {
		t.Fatalf("failed probe write retained %d outstanding observations", outstanding)
	}
}

func TestFirstProbeUsesTransportQualityForFreshnessBudget(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: time.Second}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	path, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = path.Close(); _ = peer.Close() })
	qualified := &probeQualityPath{PathConn: path}
	qualified.setTransportQuality(transport.PathQuality{RTT: 2 * time.Second, Jitter: 500 * time.Millisecond})
	slot := startProbeTestWriter(t, e, &pathSlot{id: 8, owner: 88, conn: qualified})
	e.issuePathProbe(slot)
	var evidence pathProbeEvidence
	var ok bool
	eventuallyEngine(t, time.Second, func() bool {
		evidence, ok = slot.probeSnapshot()
		return ok && evidence.issued == 1
	})
	if !ok || evidence.issued != 1 || evidence.succeeded != 0 {
		t.Fatalf("first probe evidence=%+v ok=%t", evidence, ok)
	}
	if evidence.quality.RTT != 2*time.Second || evidence.quality.Jitter != 500*time.Millisecond {
		t.Fatalf("first probe freshness quality=%+v", evidence.quality)
	}
	if state := slot.probeLiveness(evidence.firstIssued.Add(3500*time.Millisecond), time.Second); state != qualityStateUnknown {
		t.Fatalf("slow in-flight first probe liveness=%d want unknown before 4s hard cap", state)
	}
}

func TestProbeReplyBeforeWriteReturnsCommitsAfterSuccessfulWrite(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	const physicalRTT = 7 * time.Millisecond
	path := &synchronousProbeReplyPath{engine: e, replyDelay: physicalRTT}
	slot := startProbeTestWriter(t, e, &pathSlot{id: 9, owner: 99, conn: path})
	path.slot = slot
	e.issuePathProbe(slot)
	var evidence pathProbeEvidence
	var ok bool
	eventuallyEngine(t, time.Second, func() bool {
		evidence, ok = slot.probeSnapshot()
		return ok && evidence.succeeded == 1
	})
	if !ok || evidence.issued != 1 || evidence.succeeded != 1 || evidence.lastSuccess.IsZero() {
		t.Fatalf("synchronous reply evidence=%+v ok=%t", evidence, ok)
	}
	if evidence.quality.RTT != physicalRTT {
		t.Fatalf("synchronous reply RTT=%v want physical Write duration %v", evidence.quality.RTT, physicalRTT)
	}
	e.probeMu.Lock()
	outstanding := len(e.probeOutstanding)
	e.probeMu.Unlock()
	if outstanding != 0 {
		t.Fatalf("synchronous reply retained %d outstanding observations", outstanding)
	}
}

func TestProbePreWriteDelayIsNotWireEvidence(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: 10 * time.Millisecond}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	const physicalRTT = 11 * time.Millisecond
	path := &synchronousProbeReplyPath{engine: e, replyDelay: physicalRTT}
	slot := startProbeTestWriter(t, e, &pathSlot{id: 27, owner: 270, conn: path})
	path.slot = slot
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	slot.probeAfterFinalValidation = func() {
		once.Do(func() { close(entered) })
		<-release
	}

	e.issuePathProbe(slot)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("probe did not reach the final local pre-Write boundary")
	}
	e.probeMu.Lock()
	var observation pathProbeObservation
	for _, candidate := range e.probeOutstanding {
		if candidate.slot == slot {
			observation = candidate
			break
		}
	}
	e.probeMu.Unlock()
	if observation.lifecycle != pathProbeQueued || !observation.writeStartedAt.IsZero() ||
		!observation.writeStallDeadline.IsZero() {
		t.Fatalf("local pre-Write delay became wire evidence: %+v", observation)
	}
	status := e.pathProbeStatuses(time.Now().Add(maximumSelectorProbeFreshFor + time.Hour))[slot]
	if status.lifecycle != pathProbeQueued || status.failure != pathProbeFailureNone {
		t.Fatalf("local pre-Write delay became a path failure: %+v", status)
	}

	close(release)
	var evidence pathProbeEvidence
	var ok bool
	eventuallyEngine(t, time.Second, func() bool {
		evidence, ok = slot.probeSnapshot()
		return ok && evidence.succeeded == 1
	})
	if evidence.quality.RTT != physicalRTT {
		t.Fatalf("post-delay RTT=%v want physical Write duration %v", evidence.quality.RTT, physicalRTT)
	}
}

func TestBlockedProbeWriteDoesNotBecomeWireStale(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: 10 * time.Millisecond}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	base, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = base.Close(); _ = peer.Close() })
	blocked := newBlockingProbePath(base, 1)
	slot := startProbeTestWriter(t, e, &pathSlot{id: 10, owner: 100, conn: blocked})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(blocked.release) }) }
	t.Cleanup(release)

	e.issuePathProbe(slot)
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("probe write did not enter the blocked carrier")
	}
	e.probeMu.Lock()
	var probeID uint64
	var observation pathProbeObservation
	for id, candidate := range e.probeOutstanding {
		if candidate.slot == slot {
			probeID, observation = id, candidate
			break
		}
	}
	e.probeMu.Unlock()
	if probeID == 0 || observation.lifecycle != pathProbeWriteStarted || observation.writeStartedAt.IsZero() {
		t.Fatalf("blocked probe observation=%+v id=%d", observation, probeID)
	}
	farPastWireBudget := observation.writeStallDeadline.Add(maximumSelectorProbeFreshFor + time.Second)
	status := e.pathProbeStatuses(farPastWireBudget)[slot]
	if status.lifecycle != pathProbeWriteStalled || status.failure != pathProbeFailureWriteStalled {
		t.Fatalf("blocked probe status=%+v want write-stalled", status)
	}
	if _, ok := slot.probeSnapshot(); ok {
		t.Fatal("uncommitted blocked Write created wire evidence")
	}
	if state := slot.probeLiveness(farPastWireBudget, e.limits.ProbeInterval); state != qualityStateUnknown {
		t.Fatalf("blocked probe liveness=%d want unknown", state)
	}

	releasedAt := time.Now()
	release()
	eventuallyEngine(t, time.Second, func() bool {
		e.probeMu.Lock()
		observation, ok := e.probeOutstanding[probeID]
		e.probeMu.Unlock()
		return ok && observation.lifecycle == pathProbeWriteCommitted
	})
	e.probeMu.Lock()
	committed := e.probeOutstanding[probeID]
	e.probeMu.Unlock()
	if committed.writeCommittedAt.Before(releasedAt) || committed.deadline.IsZero() ||
		!committed.deadline.After(committed.writeCommittedAt) {
		t.Fatalf("commit-anchored observation=%+v release=%v", committed, releasedAt)
	}
	if !e.acceptPathProbeReply(slot, proto.ProbePayload{ID: probeID, TS: committed.wireTS}, committed.writeCommittedAt.Add(5*time.Millisecond)) {
		t.Fatal("committed probe reply was rejected")
	}
	evidence, ok := slot.probeSnapshot()
	if !ok || evidence.timedOut != 0 || evidence.quality.RTT != 5*time.Millisecond {
		t.Fatalf("post-commit evidence=%+v ok=%t", evidence, ok)
	}
}

func TestProbeReplyQueueDoesNotBlockReaderBehindDataWrite(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	base, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = base.Close(); _ = peer.Close() })
	blocked := newBlockingProbePath(base, 1)
	slot := startProbeTestWriter(t, e, &pathSlot{id: 11, owner: 110, conn: blocked})
	result := make(chan pathDispatchResult, 1)
	if !slot.submitDispatch(pathDispatchJob{
		frame: makeProbeTestFrame(t, proto.CtrlPathProbeReply, 1), result: result,
	}) {
		t.Fatal("submit blocking control frame")
	}
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("first write did not block")
	}

	returned := make(chan struct{})
	go func() {
		e.handlePathProbeRequest(slot, proto.ProbePayload{ID: 2}.Encode())
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("probe reply waited behind the blocked path writer")
	}
	close(blocked.release)
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("blocked write did not finish")
	}
}

func TestProbeReplyBeforeQueuedWriteStartsIsRejected(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	base, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = base.Close(); _ = peer.Close() })
	blocked := newBlockingProbePath(base, 1)
	slot := startProbeTestWriter(t, e, &pathSlot{id: 12, owner: 120, conn: blocked})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(blocked.release) }) }
	t.Cleanup(release)
	result := make(chan pathDispatchResult, 1)
	dispatchIdentity, submitted := slot.submitDispatchTracked(pathDispatchJob{
		frame: makeProbeTestFrame(t, proto.CtrlPathProbeReply, 4), result: result,
	})
	if !submitted {
		t.Fatal("submit blocking predecessor frame")
	}
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("predecessor write did not block")
	}
	e.issuePathProbe(slot)
	e.probeMu.Lock()
	var probeID uint64
	for id, observation := range e.probeOutstanding {
		if observation.slot == slot {
			probeID = id
			break
		}
	}
	e.probeMu.Unlock()
	if probeID == 0 {
		t.Fatal("queued probe reservation is absent")
	}
	eventuallyEngine(t, time.Second, func() bool {
		e.probeMu.Lock()
		observation := e.probeOutstanding[probeID]
		e.probeMu.Unlock()
		return observation.lifecycle == pathProbeQueued
	})
	slot.markDispatchStalled(dispatchIdentity)
	blockedAt := time.Now()
	status := e.pathProbeStatuses(blockedAt)[slot]
	if status.lifecycle != pathProbeDataBlocked || status.failure != pathProbeFailureNone {
		t.Fatalf("initial queued-behind-DATA status=%+v", status)
	}
	starvationFor := pathProbeDataStarvationFor(e.limits.ProbeInterval)
	status = e.pathProbeStatuses(blockedAt.Add(starvationFor - time.Nanosecond))[slot]
	if status.lifecycle != pathProbeDataBlocked || status.failure != pathProbeFailureNone {
		t.Fatalf("pre-starvation queued-behind-DATA status=%+v", status)
	}
	status = e.pathProbeStatuses(blockedAt.Add(starvationFor))[slot]
	if status.lifecycle != pathProbeDataStarved || status.failure != pathProbeFailureDataStarved {
		t.Fatalf("queued-behind-DATA status=%+v", status)
	}
	if _, ok := slot.probeSnapshot(); ok {
		t.Fatal("DATA-starved probe created wire evidence")
	}
	e.probeMu.Lock()
	wireTS := e.probeOutstanding[probeID].wireTS
	e.probeMu.Unlock()
	if e.acceptPathProbeReply(slot, proto.ProbePayload{ID: probeID, TS: wireTS}, time.Now()) {
		t.Fatal("reply was accepted before the queued probe entered Conn.Write")
	}
	release()
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("predecessor write did not finish")
	}
	eventuallyEngine(t, time.Second, func() bool {
		e.probeMu.Lock()
		observation, ok := e.probeOutstanding[probeID]
		e.probeMu.Unlock()
		return ok && observation.lifecycle == pathProbeWriteCommitted
	})
	evidence, ok := slot.probeSnapshot()
	if !ok || evidence.succeeded != 0 {
		t.Fatalf("pre-write reply created success evidence: %+v ok=%t", evidence, ok)
	}
}

func TestProbeDataStarvationRequiresSameDispatchGenerationHighCount(t *testing.T) {
	const generations = 256
	e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: time.Second}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	slot := &pathSlot{id: 26, owner: 260}
	generation := pathProbeGenerationForSlot(slot)
	queuedAt := time.Unix(3_000, 0)
	e.probeMu.Lock()
	e.probeOutstanding[1] = pathProbeObservation{
		queuedAt: queuedAt, generation: generation, slot: slot, lifecycle: pathProbeQueued,
	}
	e.probeMu.Unlock()

	starvationFor := pathProbeDataStarvationFor(e.limits.ProbeInterval)
	for dispatchGeneration := uint64(1); dispatchGeneration <= generations; dispatchGeneration++ {
		observedAt := queuedAt.Add(time.Duration(dispatchGeneration) * starvationFor)
		slot.markDispatchStalled(pathDispatchIdentity{
			generation:     dispatchGeneration,
			pathGeneration: generation,
		})
		status := e.pathProbeStatuses(observedAt)[slot]
		if status.lifecycle != pathProbeDataBlocked || status.failure != pathProbeFailureNone {
			t.Fatalf("generation %d initial status=%+v", dispatchGeneration, status)
		}
		status = e.pathProbeStatuses(observedAt.Add(starvationFor - time.Nanosecond))[slot]
		if status.lifecycle != pathProbeDataBlocked || status.failure != pathProbeFailureNone {
			t.Fatalf("generation %d pre-threshold status=%+v", dispatchGeneration, status)
		}
	}

	finalAt := queuedAt.Add(time.Duration(generations) * starvationFor)
	status := e.pathProbeStatuses(finalAt.Add(starvationFor))[slot]
	if status.lifecycle != pathProbeDataStarved || status.failure != pathProbeFailureDataStarved {
		t.Fatalf("same-generation threshold status=%+v", status)
	}
	e.probeMu.Lock()
	observation := e.probeOutstanding[1]
	e.probeMu.Unlock()
	if observation.dataStallGeneration != generations || observation.dataBlockedAt != finalAt ||
		!observation.deadline.IsZero() || !observation.writeCommittedAt.IsZero() {
		t.Fatalf("same-generation starvation observation=%+v", observation)
	}
	if _, ok := slot.probeSnapshot(); ok {
		t.Fatal("DATA-starvation age created wire evidence")
	}

}

func TestPredecessorProbeInvalidationSnapshotsGenerationUnderProbeLock(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	slot := &pathSlot{id: 27, owner: 270}
	predecessor := pathProbeGenerationForSlot(slot)
	predecessorEvidence := &pathProbeEvidence{generation: predecessor, issued: 1}
	slot.probeEvidence.Store(predecessorEvidence)

	const predecessorID, successorID = uint64(0x2701), uint64(0x2702)
	e.probeMu.Lock()
	e.probeOutstanding[predecessorID] = pathProbeObservation{
		generation: predecessor, slot: slot, lifecycle: pathProbeQueued,
	}
	attempting := make(chan struct{})
	done := make(chan struct{})
	go func() {
		close(attempting)
		e.probeMu.Lock()
		e.invalidatePredecessorPathProbeEvidenceLocked(slot)
		e.probeMu.Unlock()
		close(done)
	}()
	<-attempting

	// Publish a successor while the delayed cleanup is waiting for probeMu.
	// Its generation snapshot must be taken only after that lock is acquired.
	slot.peerMobilityEpoch.Add(1)
	successor := pathProbeGenerationForSlot(slot)
	successorEvidence := &pathProbeEvidence{generation: successor, issued: 1}
	e.probeOutstanding[successorID] = pathProbeObservation{
		generation: successor, slot: slot, lifecycle: pathProbeQueued,
	}
	slot.probeEvidence.Store(successorEvidence)
	e.probeMu.Unlock()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("delayed predecessor cleanup did not finish")
	}
	e.probeMu.Lock()
	_, predecessorPresent := e.probeOutstanding[predecessorID]
	observedSuccessor, successorPresent := e.probeOutstanding[successorID]
	e.probeMu.Unlock()
	if predecessorPresent {
		t.Fatal("predecessor observation survived delayed cleanup")
	}
	if !successorPresent || observedSuccessor.generation != successor {
		t.Fatalf("successor observation was erased: %+v present=%t", observedSuccessor, successorPresent)
	}
	if got := slot.probeEvidence.Load(); got != successorEvidence {
		t.Fatalf("successor evidence was erased: %p want %p", got, successorEvidence)
	}
}

func TestProbeDataStarvationDoesNotCrossPeerMobilityGeneration(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: 10 * time.Millisecond}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	slot := &pathSlot{id: 28, owner: 280}
	predecessor := pathProbeGenerationForSlot(slot)
	queuedAt := time.Unix(7_000, 0)
	const predecessorID, successorID = uint64(0x2801), uint64(0x2802)

	predecessorDispatch := pathDispatchIdentity{
		generation:     slot.nextDispatchGeneration(),
		pathGeneration: predecessor,
	}
	slot.markDispatchStalled(predecessorDispatch)
	e.probeMu.Lock()
	e.probeOutstanding[predecessorID] = pathProbeObservation{
		queuedAt: queuedAt, generation: predecessor, slot: slot, lifecycle: pathProbeQueued,
	}
	e.probeMu.Unlock()
	blockedAt := queuedAt.Add(time.Millisecond)
	if status := e.pathProbeStatuses(blockedAt)[slot]; status.lifecycle != pathProbeDataBlocked {
		t.Fatalf("predecessor initial stall status=%+v", status)
	}
	starvationFor := pathProbeDataStarvationFor(e.limits.ProbeInterval)
	if status := e.pathProbeStatuses(blockedAt.Add(starvationFor))[slot]; status.failure != pathProbeFailureDataStarved {
		t.Fatalf("predecessor stall did not become factual failure: %+v", status)
	}

	slot.peerMobilityEpoch.Add(1)
	successor := pathProbeGenerationForSlot(slot)
	e.invalidatePredecessorPathProbeEvidence(slot)
	if got, ok := slot.currentDispatchStall(); !ok || got != predecessorDispatch {
		t.Fatalf("route commit changed physical custody got=%+v present=%t want=%+v",
			got, ok, predecessorDispatch)
	}

	e.probeMu.Lock()
	_, predecessorPresent := e.probeOutstanding[predecessorID]
	outstandingAfterCleanup := len(e.probeOutstanding)
	e.probeOutstanding[successorID] = pathProbeObservation{
		queuedAt: blockedAt, generation: successor, slot: slot, lifecycle: pathProbeQueued,
	}
	e.probeMu.Unlock()
	if predecessorPresent {
		t.Fatal("predecessor probe remained authoritative after peer mobility commit")
	}
	if outstandingAfterCleanup != 0 {
		t.Fatalf("predecessor cleanup retained %d non-wire probe states", outstandingAfterCleanup)
	}

	farPastStarvation := blockedAt.Add(100 * starvationFor)
	if status := e.pathProbeStatuses(farPastStarvation)[slot]; status.lifecycle != pathProbeQueued || status.failure != pathProbeFailureNone {
		t.Fatalf("predecessor custody became successor probe failure: %+v", status)
	}
	e.probeMu.Lock()
	ignored := e.probeOutstanding[successorID]
	e.probeMu.Unlock()
	if ignored.dataStallGeneration != 0 || !ignored.dataBlockedAt.IsZero() {
		t.Fatalf("successor probe aged against predecessor custody: %+v", ignored)
	}
	if got, ok := slot.currentDispatchStall(); !ok || got != predecessorDispatch {
		t.Fatal("probe classification cleared predecessor physical custody")
	}

	slot.completeDispatch(predecessorDispatch)
	if status := e.pathProbeStatuses(farPastStarvation.Add(time.Millisecond))[slot]; status.lifecycle != pathProbeQueued || status.failure != pathProbeFailureNone {
		t.Fatalf("successor probe did not remain queued after predecessor completion: %+v", status)
	}

	successorDispatch := pathDispatchIdentity{
		generation:     slot.nextDispatchGeneration(),
		pathGeneration: successor,
	}
	slot.markDispatchStalled(successorDispatch)
	successorBlockedAt := farPastStarvation.Add(time.Second)
	if status := e.pathProbeStatuses(successorBlockedAt)[slot]; status.lifecycle != pathProbeDataBlocked {
		t.Fatalf("genuine successor stall initial status=%+v", status)
	}
	if status := e.pathProbeStatuses(successorBlockedAt.Add(starvationFor))[slot]; status.lifecycle != pathProbeDataStarved || status.failure != pathProbeFailureDataStarved {
		t.Fatalf("genuine successor stall did not produce failure: %+v", status)
	}
}

func TestSuccessorDispatchStallBeforePredecessorCleanupIsClassifiable(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: 10 * time.Millisecond}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	slot := &pathSlot{id: 29, owner: 290, dispatchQ: make(chan pathDispatchJob, 1)}
	predecessor := pathProbeGenerationForSlot(slot)
	const predecessorID, successorID = uint64(0x2901), uint64(0x2902)
	queuedAt := time.Unix(8_000, 0)

	e.probeMu.Lock()
	e.probeOutstanding[predecessorID] = pathProbeObservation{
		queuedAt: queuedAt, generation: predecessor, slot: slot, lifecycle: pathProbeQueued,
	}
	e.probeMu.Unlock()

	// Model the responder ordering that triggered the adversarial finding: the
	// peer epoch advances, successor DATA enters custody and stalls, and only
	// then does terminal cleanup acquire probeMu.
	slot.peerMobilityEpoch.Add(1)
	successor := pathProbeGenerationForSlot(slot)
	successorDispatch, submitted := slot.submitDispatchTracked(pathDispatchJob{})
	if !submitted {
		t.Fatal("successor dispatch was not admitted")
	}
	if successorDispatch.pathGeneration != successor {
		t.Fatalf("successor dispatch generation=%+v want %+v", successorDispatch.pathGeneration, successor)
	}
	slot.markDispatchStalled(successorDispatch)
	e.probeMu.Lock()
	e.probeOutstanding[successorID] = pathProbeObservation{
		queuedAt: queuedAt, generation: successor, slot: slot, lifecycle: pathProbeQueued,
	}
	e.probeMu.Unlock()

	e.invalidatePredecessorPathProbeEvidence(slot)
	e.probeMu.Lock()
	_, predecessorPresent := e.probeOutstanding[predecessorID]
	observedSuccessor, successorPresent := e.probeOutstanding[successorID]
	outstandingAfterCleanup := len(e.probeOutstanding)
	e.probeMu.Unlock()
	if predecessorPresent || !successorPresent || observedSuccessor.generation != successor {
		t.Fatalf("cleanup predecessor/successor presence=%t/%t successor=%+v", predecessorPresent, successorPresent, observedSuccessor)
	}
	if outstandingAfterCleanup != 1 {
		t.Fatalf("cleanup retained %d probe states, want one wire successor", outstandingAfterCleanup)
	}

	blockedAt := queuedAt.Add(time.Millisecond)
	if status := e.pathProbeStatuses(blockedAt)[slot]; status.lifecycle != pathProbeDataBlocked || status.failure != pathProbeFailureNone {
		t.Fatalf("successor initial stall status=%+v", status)
	}
	starvedAt := blockedAt.Add(pathProbeDataStarvationFor(e.limits.ProbeInterval))
	if status := e.pathProbeStatuses(starvedAt)[slot]; status.lifecycle != pathProbeDataStarved || status.failure != pathProbeFailureDataStarved {
		t.Fatalf("successor stall was suppressed as predecessor custody: %+v", status)
	}
	job := <-slot.dispatchQ
	if job.pathGeneration != successor || job.generation != successorDispatch.generation {
		t.Fatalf("queued successor identity=(%d,%+v) want %+v", job.generation, job.pathGeneration, successorDispatch)
	}
	slot.completeDispatch(successorDispatch)
}

func TestProbeReplyIsRejectedBeforePhysicalWriteStarts(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	base, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = base.Close(); _ = peer.Close() })
	slot := startProbeTestWriter(t, e, &pathSlot{id: 13, owner: 130, conn: base})
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	slot.probeBeforeConnWrite = func() {
		once.Do(func() { close(started) })
		<-release
	}
	e.issuePathProbe(slot)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("probe did not reach the pre-Write boundary")
	}
	e.probeMu.Lock()
	var probeID, wireTS uint64
	for id, observation := range e.probeOutstanding {
		if observation.slot == slot {
			probeID, wireTS = id, observation.wireTS
			break
		}
	}
	e.probeMu.Unlock()
	if probeID == 0 {
		t.Fatal("probe reservation is absent")
	}
	if e.acceptPathProbeReply(slot, proto.ProbePayload{ID: probeID, TS: wireTS}, time.Now()) {
		t.Fatal("exact wire token was accepted before PathConn.Write")
	}
	if e.acceptPathProbeReply(slot, proto.ProbePayload{ID: probeID, TS: wireTS + 1}, time.Now()) {
		t.Fatal("mismatched wire token was accepted before PathConn.Write")
	}
	close(release)
	eventuallyEngine(t, time.Second, func() bool {
		e.probeMu.Lock()
		observation, ok := e.probeOutstanding[probeID]
		e.probeMu.Unlock()
		return ok && observation.lifecycle == pathProbeWriteCommitted
	})
	evidence, ok := slot.probeSnapshot()
	if !ok || evidence.succeeded != 0 {
		t.Fatalf("mismatched token created success evidence: %+v ok=%t", evidence, ok)
	}
}

func TestBlockedProbeIsSingleFlightAndDoesNotConsumeDispatchQueue(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: 10 * time.Millisecond}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	base, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = base.Close(); _ = peer.Close() })
	blocked := newBlockingProbePath(base, 1)
	slot := startProbeTestWriter(t, e, &pathSlot{id: 14, owner: 140, conn: blocked})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(blocked.release) }) }
	t.Cleanup(release)
	e.issuePathProbe(slot)
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("probe write did not block")
	}
	var first pathProbeObservation
	e.probeMu.Lock()
	for _, observation := range e.probeOutstanding {
		if observation.slot == slot {
			first = observation
			break
		}
	}
	e.probeMu.Unlock()
	if first.queuedAt.IsZero() {
		t.Fatal("blocked probe observation is absent")
	}
	status := e.pathProbeStatuses(first.writeStallDeadline.Add(maximumSelectorProbeFreshFor + time.Second))[slot]
	if status.lifecycle != pathProbeWriteStalled || status.failure != pathProbeFailureWriteStalled {
		t.Fatalf("blocked probe status=%+v", status)
	}
	if _, ok := slot.probeSnapshot(); ok {
		t.Fatal("blocked probe created committed wire evidence")
	}
	for i := 0; i < 1000; i++ {
		e.issuePathProbe(slot)
	}
	e.probeMu.Lock()
	outstanding := len(e.probeOutstanding)
	e.probeMu.Unlock()
	if outstanding != 1 {
		t.Fatalf("blocked probe cardinality=%d want 1", outstanding)
	}
	if queued := len(slot.dispatchQ); queued != 0 {
		t.Fatalf("probe traffic consumed %d DATA dispatch queue entries", queued)
	}
	if next, done := slot.dispatchNextGen.Load(), slot.dispatchDoneGen.Load(); next != 0 || done != 0 {
		t.Fatalf("probe traffic changed DATA dispatch generations next/done=%d/%d", next, done)
	}
	result := make(chan pathDispatchResult, 1)
	generation := slot.dispatchNextGen.Add(1)
	if !slot.submitDispatch(pathDispatchJob{
		frame: makeProbeTestDataFrame(t, []byte("dispatch-remains-admissible")), result: result, generation: generation,
	}) {
		t.Fatal("DATA writer queue rejected work behind a blocked probe")
	}
	release()
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("queued DATA-writer work did not recover")
	}
}

func TestProbeSingleFlightEndsAtWriteCommitNotReply(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: 10 * time.Millisecond}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	base, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = base.Close(); _ = peer.Close() })
	counted := &countingProbePath{PathConn: base}
	blocked := newBlockingProbePath(counted, 1)
	slot := startProbeTestWriter(t, e, &pathSlot{id: 22, owner: 220, conn: blocked})

	e.issuePathProbe(slot)
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("first probe write did not block")
	}
	for i := 0; i < 100; i++ {
		e.issuePathProbe(slot)
	}
	e.probeMu.Lock()
	blockedOutstanding := len(e.probeOutstanding)
	e.probeMu.Unlock()
	if blockedOutstanding != 1 {
		t.Fatalf("uncommitted probe cardinality=%d want 1", blockedOutstanding)
	}

	close(blocked.release)
	eventuallyEngine(t, time.Second, func() bool {
		e.probeMu.Lock()
		defer e.probeMu.Unlock()
		for _, observation := range e.probeOutstanding {
			if observation.slot == slot && observation.lifecycle == pathProbeWriteCommitted {
				return true
			}
		}
		return false
	})

	// Deliberately leave the first request unanswered. A committed write no
	// longer owns the single-flight lease, so the next cadence may sample again.
	e.issuePathProbe(slot)
	eventuallyEngine(t, time.Second, func() bool {
		e.probeMu.Lock()
		defer e.probeMu.Unlock()
		committed := 0
		for _, observation := range e.probeOutstanding {
			if observation.slot == slot && observation.lifecycle == pathProbeWriteCommitted {
				committed++
			}
		}
		return committed == 2
	})
	if writes := counted.writes.Load(); writes != 2 {
		t.Fatalf("physical probe writes=%d want 2", writes)
	}
	evidence, ok := slot.probeSnapshot()
	if !ok || evidence.issued != 2 || evidence.succeeded != 0 || evidence.timedOut != 0 {
		t.Fatalf("unanswered committed probe evidence=%+v ok=%t", evidence, ok)
	}

	if !slot.tryFenceDispatch() {
		t.Fatal("failed to establish TX fence")
	}
	e.issuePathProbe(slot)
	time.Sleep(20 * time.Millisecond)
	if writes := counted.writes.Load(); writes != 2 {
		t.Fatalf("fenced path admitted another probe write: %d", writes)
	}
}

func TestCommittedProbeTimeoutAllowsRecoveryProbe(t *testing.T) {
	t.Run("physical write witness preserves replay order and token bounds", func(t *testing.T) {
		e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
		t.Cleanup(func() { _ = e.Close() })
		slot := &pathSlot{id: 90, owner: 900}
		slot.txEnabled.Store(true)
		token := e.pathDataWriteToken(slot, slot.txFenceEpoch.Load())
		for _, seq := range []uint64{11, 3, 9, 3} {
			slot.noteFirstDataWriteSequence(seq, token)
		}
		if next, ok := slot.earliestDataWriteAfter(4, token); !ok || next != 10 {
			t.Fatalf("replay-order witness=(%d,%t), want (10,true)", next, ok)
		}
		if next, ok := slot.earliestDataWriteAfter(10, token); !ok || next != 12 {
			t.Fatalf("later witness=(%d,%t), want (12,true)", next, ok)
		}
		for seq := uint64(0); seq < sendHistoryWindow+17; seq++ {
			slot.noteFirstDataWriteSequence(seq, token)
		}
		slot.dataWriteMu.Lock()
		witnessCount := len(slot.dataWriteWitness.sequences)
		slot.dataWriteMu.Unlock()
		if witnessCount != sendHistoryWindow {
			t.Fatalf("bounded witness entries=%d want %d", witnessCount, sendHistoryWindow)
		}

		slot.txFenceEpoch.Add(1)
		newToken := e.pathDataWriteToken(slot, slot.txFenceEpoch.Load())
		slot.noteFirstDataWriteSequence(42, newToken)
		if _, ok := slot.earliestDataWriteAfter(0, token); ok {
			t.Fatal("old fence token retained access to a reset write witness")
		}
		if next, ok := slot.earliestDataWriteAfter(0, newToken); !ok || next != 43 {
			t.Fatalf("new fence witness=(%d,%t), want (43,true)", next, ok)
		}
	})

	t.Run("flat selector wire progress defers only causal expiry", func(t *testing.T) {
		progress := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: 10 * time.Millisecond}.Clamp())
		t.Cleanup(func() { _ = progress.Close() })
		ids := configureLeafSelectorRuntime(t, progress, "a", "b")
		aBase, aPeer := newMemoryPathPair()
		bBase, bPeer := newMemoryPathPair()
		t.Cleanup(func() { _ = aPeer.Close(); _ = bPeer.Close() })
		aID := attachFixturePath(t, progress, aBase, transport.PathSpec{Transport: "memory", Address: "a"}, ids["a"])
		bID := attachFixturePath(t, progress, bBase, transport.PathSpec{Transport: "memory", Address: "b"}, ids["b"])
		progress.pathsMu.RLock()
		aSlot, bSlot := progress.paths[aID], progress.paths[bID]
		progress.pathsMu.RUnlock()

		commit := func(id uint64, slot *pathSlot, at time.Time) pathProbeObservation {
			t.Helper()
			generation := pathProbeGenerationForSlot(slot)
			progress.probeMu.Lock()
			progress.probeOutstanding[id] = pathProbeObservation{
				queuedAt: at.Add(-time.Second), generation: generation, slot: slot,
				wireTS: id, lifecycle: pathProbeQueued,
			}
			progress.probeMu.Unlock()
			if !progress.markPathProbeWriteStarted(id, slot, at.Add(-time.Millisecond)) {
				t.Fatalf("probe %d did not enter physical Write", id)
			}
			progress.completePathProbeWrite(id, slot, nil, at)
			progress.probeMu.Lock()
			observation, ok := progress.probeOutstanding[id]
			progress.probeMu.Unlock()
			if !ok || observation.lifecycle != pathProbeWriteCommitted {
				t.Fatalf("probe %d commit observation=%+v present=%t", id, observation, ok)
			}
			return observation
		}
		publishOn := func(seq uint64, slot *pathSlot, ackAt time.Time) {
			t.Helper()
			reserveAckTestFrame(t, progress, seq, proto.FrameData)
			progress.publishSendSeq(seq + 1)
			progress.sendAckNext.Store(seq)
			progress.sendACKProgress.Store(&sendACKProgressObservation{next: seq, at: ackAt})
			frame := make([]byte, proto.HeaderSize+1)
			if err := (proto.Header{Version: proto.Version, Type: proto.FrameData, Seq: seq}).Encode(frame[:proto.HeaderSize]); err != nil {
				t.Fatal(err)
			}
			progress.noteApplicationDispatchRoute(frame, slot)
			slot.noteFirstDataWriteSequence(seq, progress.pathDataWriteToken(slot, slot.txFenceEpoch.Load()))
		}

		committedAt := time.Unix(4_000, 0)
		publishOn(0, aSlot, committedAt.Add(-time.Second))
		first := commit(101, aSlot, committedAt)
		if first.wireAckBaseline != 0 || first.wireDataWitnessNext != 1 ||
			first.wireMigrationEpoch != 0 || !first.wireProgressTracked {
			t.Fatalf("initial wire progress=%+v", first)
		}
		progress.sendACKProgress.Store(&sendACKProgressObservation{
			next: 1, at: first.writeCommittedAt,
		})
		if observed, causal := progress.flatSelectorCausalACK(first, first.deadline); causal {
			t.Fatalf("ACK at the write-commit boundary became causal: %+v", observed)
		}
		ackAt := committedAt.Add(minimumSelectorProbeFreshFor / 2)
		progress.sendACKProgress.Store(&sendACKProgressObservation{next: 1, at: ackAt})
		progress.expirePathProbes(first.deadline)
		progress.probeMu.Lock()
		deferred, retained := progress.probeOutstanding[101]
		progress.probeMu.Unlock()
		if !retained || !deferred.deadline.After(first.deadline) ||
			deferred.wireAckBaseline != 1 || !deferred.wireProgressDeferred ||
			deferred.deadline != ackAt.Add(minimumSelectorProbeFreshFor) ||
			deferred.deadline.After(first.writeStartedAt.Add(maximumCommittedProbeLifetime)) {
			t.Fatalf("causal progress did not defer expiry: %+v retained=%t", deferred, retained)
		}
		if evidence, ok := aSlot.probeSnapshot(); !ok || evidence.timedOut != 0 {
			t.Fatalf("deferred probe evidence=%+v present=%t", evidence, ok)
		}
		progress.expirePathProbes(deferred.deadline.Add(-time.Nanosecond))
		progress.probeMu.Lock()
		_, retained = progress.probeOutstanding[101]
		progress.probeMu.Unlock()
		if !retained {
			t.Fatal("deferred probe expired before its refreshed deadline")
		}
		progress.sendACKProgress.Store(&sendACKProgressObservation{
			next: 2, at: deferred.deadline.Add(-time.Millisecond),
		})
		progress.expirePathProbes(deferred.deadline)
		progress.probeMu.Lock()
		_, retained = progress.probeOutstanding[101]
		progress.probeMu.Unlock()
		if retained {
			t.Fatal("probe with no further progress survived its refreshed deadline")
		}
		if evidence, ok := aSlot.probeSnapshot(); !ok || evidence.timedOut != 1 {
			t.Fatalf("eventual timeout evidence=%+v present=%t", evidence, ok)
		}

		publishOn(1, aSlot, committedAt.Add(time.Hour-time.Second))
		backup := commit(102, bSlot, committedAt.Add(time.Hour))
		progress.sendACKProgress.Store(&sendACKProgressObservation{next: 2, at: backup.writeCommittedAt.Add(minimumSelectorProbeFreshFor / 2)})
		progress.expirePathProbes(backup.deadline)
		progress.probeMu.Lock()
		_, retained = progress.probeOutstanding[102]
		progress.probeMu.Unlock()
		if retained {
			t.Fatal("another leaf's DATA progress masked the probed leaf timeout")
		}
		if evidence, ok := bSlot.probeSnapshot(); !ok || evidence.timedOut != 1 {
			t.Fatalf("backup timeout evidence=%+v present=%t", evidence, ok)
		}

		publishOn(2, aSlot, committedAt.Add(2*time.Hour-time.Second))
		staleRoute := commit(103, aSlot, committedAt.Add(2*time.Hour))
		progress.migrationEpoch.Add(1)
		progress.sendACKProgress.Store(&sendACKProgressObservation{
			next: 3, at: staleRoute.writeCommittedAt.Add(minimumSelectorProbeFreshFor / 2),
		})
		progress.expirePathProbes(staleRoute.deadline)
		progress.probeMu.Lock()
		_, retained = progress.probeOutstanding[103]
		progress.probeMu.Unlock()
		if retained {
			t.Fatal("ACK from a later migration epoch masked the stale route timeout")
		}

		lateCommitAt := committedAt.Add(3 * time.Hour)
		publishOn(3, aSlot, lateCommitAt.Add(-time.Second))
		late := commit(104, aSlot, lateCommitAt)
		progress.sendACKProgress.Store(&sendACKProgressObservation{
			next: 4, at: late.writeCommittedAt.Add(100 * time.Millisecond),
		})
		progress.expirePathProbes(late.writeCommittedAt.Add(2 * time.Second))
		progress.probeMu.Lock()
		_, retained = progress.probeOutstanding[104]
		progress.probeMu.Unlock()
		if retained {
			t.Fatal("stale progress observed after its bounded deadline deferred timeout")
		}
	})

	invalidations := []struct {
		name string
		do   func(*Engine, *pathSlot)
	}{
		{name: "migration epoch", do: func(e *Engine, _ *pathSlot) { e.migrationEpoch.Add(1) }},
		{name: "TX fence epoch", do: func(_ *Engine, slot *pathSlot) { slot.txFenceEpoch.Add(1) }},
		{name: "path generation", do: func(_ *Engine, slot *pathSlot) { slot.routeGeneration.Add(1) }},
	}
	for _, invalidation := range invalidations {
		t.Run("deferred progress is revoked by "+invalidation.name, func(t *testing.T) {
			e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: 10 * time.Millisecond}.Clamp())
			t.Cleanup(func() { _ = e.Close() })
			ids := configureLeafSelectorRuntime(t, e, "path")
			base, peer := newMemoryPathPair()
			t.Cleanup(func() { _ = peer.Close() })
			pathID := attachFixturePath(t, e, base, transport.PathSpec{Transport: "memory", Address: "path"}, ids["path"])
			e.pathsMu.RLock()
			slot := e.paths[pathID]
			e.pathsMu.RUnlock()

			started := time.Unix(5_000, 0)
			reserveAckTestFrame(t, e, 0, proto.FrameData)
			e.publishSendSeq(1)
			e.sendAckNext.Store(0)
			slot.noteFirstDataWriteSequence(0, e.pathDataWriteToken(slot, slot.txFenceEpoch.Load()))
			const probeID = 201
			generation := pathProbeGenerationForSlot(slot)
			e.probeMu.Lock()
			e.probeOutstanding[probeID] = pathProbeObservation{
				queuedAt: started.Add(-time.Second), generation: generation, slot: slot,
				wireTS: probeID, fenceEpoch: slot.txFenceEpoch.Load(), lifecycle: pathProbeQueued,
			}
			e.probeMu.Unlock()
			if !e.markPathProbeWriteStarted(probeID, slot, started) {
				t.Fatal("probe did not enter physical Write")
			}
			e.completePathProbeWrite(probeID, slot, nil, started.Add(time.Millisecond))
			e.probeMu.Lock()
			committed, ok := e.probeOutstanding[probeID]
			e.probeMu.Unlock()
			if !ok || !committed.wireProgressTracked {
				t.Fatalf("committed tracked probe=%+v present=%t", committed, ok)
			}
			ackAt := committed.writeStartedAt.Add(minimumSelectorProbeFreshFor / 2)
			e.sendACKProgress.Store(&sendACKProgressObservation{next: 1, at: ackAt})
			e.expirePathProbes(committed.deadline)
			e.probeMu.Lock()
			deferred, ok := e.probeOutstanding[probeID]
			e.probeMu.Unlock()
			if !ok || !deferred.wireProgressDeferred {
				t.Fatalf("probe did not earn one causal extension: %+v present=%t", deferred, ok)
			}

			invalidation.do(e, slot)
			e.expirePathProbes(deferred.deadline.Add(-time.Nanosecond))
			e.probeMu.Lock()
			_, retained := e.probeOutstanding[probeID]
			e.probeMu.Unlock()
			if retained {
				t.Fatal("invalidated progress extension remained outstanding")
			}
			if evidence := slot.probeEvidence.Load(); evidence != nil && evidence.timedOut != 0 {
				t.Fatalf("invalidated observation published timeout evidence: %+v", *evidence)
			}
			if evidence, ok := slot.probeSnapshot(); ok {
				t.Fatalf("invalidated token remained visible through probeSnapshot: %+v", evidence)
			}
			if e.acceptPathProbeReply(slot, proto.ProbePayload{ID: probeID, TS: probeID}, deferred.deadline) {
				t.Fatal("invalidated observation accepted a late reply")
			}
		})
	}

	t.Run("slow physical Write consumes the five second total budget", func(t *testing.T) {
		e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: 10 * time.Millisecond}.Clamp())
		t.Cleanup(func() { _ = e.Close() })
		ids := configureLeafSelectorRuntime(t, e, "path")
		base, peer := newMemoryPathPair()
		t.Cleanup(func() { _ = peer.Close() })
		pathID := attachFixturePath(t, e, base, transport.PathSpec{Transport: "memory", Address: "path"}, ids["path"])
		e.pathsMu.RLock()
		slot := e.paths[pathID]
		e.pathsMu.RUnlock()

		started := time.Unix(6_000, 0)
		completed := started.Add(maximumCommittedProbeLifetime + time.Millisecond)
		const probeID = 301
		e.probeMu.Lock()
		e.probeOutstanding[probeID] = pathProbeObservation{
			queuedAt: started.Add(-time.Second), generation: pathProbeGenerationForSlot(slot), slot: slot,
			wireTS: probeID, fenceEpoch: slot.txFenceEpoch.Load(), lifecycle: pathProbeQueued,
		}
		e.probeMu.Unlock()
		if !e.markPathProbeWriteStarted(probeID, slot, started) {
			t.Fatal("slow probe did not enter physical Write")
		}
		e.completePathProbeWrite(probeID, slot, nil, completed)
		e.probeMu.Lock()
		_, retained := e.probeOutstanding[probeID]
		e.probeMu.Unlock()
		if retained {
			t.Fatal("slow Write survived beyond its total probe lifetime")
		}
		evidence := slot.probeEvidence.Load()
		if evidence == nil || evidence.issued != 1 || evidence.timedOut != 1 || evidence.lastWireTimeout != completed {
			t.Fatalf("slow-Write timeout evidence=%+v", evidence)
		}
	})

	e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: 10 * time.Millisecond}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	base, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = base.Close(); _ = peer.Close() })
	slot := startProbeTestWriter(t, e, &pathSlot{id: 16, owner: 160, conn: base})
	e.issuePathProbe(slot)
	var firstID uint64
	var first pathProbeObservation
	eventuallyEngine(t, time.Second, func() bool {
		e.probeMu.Lock()
		defer e.probeMu.Unlock()
		for id, observation := range e.probeOutstanding {
			if observation.slot == slot && observation.lifecycle == pathProbeWriteCommitted {
				firstID, first = id, observation
				return true
			}
		}
		return false
	})
	e.expirePathProbes(first.deadline.Add(time.Nanosecond))
	e.probeMu.Lock()
	_, retained := e.probeOutstanding[firstID]
	e.probeMu.Unlock()
	if retained {
		t.Fatal("committed timed-out probe retained the single-flight lease")
	}
	e.issuePathProbe(slot)
	eventuallyEngine(t, time.Second, func() bool {
		e.probeMu.Lock()
		defer e.probeMu.Unlock()
		for id, observation := range e.probeOutstanding {
			if id != firstID && observation.slot == slot && observation.lifecycle == pathProbeWriteCommitted {
				return true
			}
		}
		return false
	})
	evidence, ok := slot.probeSnapshot()
	if !ok || evidence.issued != 2 || evidence.timedOut != 1 {
		t.Fatalf("recovery probe evidence=%+v ok=%t", evidence, ok)
	}
}

func TestProbePermitQueueAndFenceHighCount(t *testing.T) {
	const iterations = 256
	e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: 10 * time.Millisecond}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	base, peer := newMemoryPathPair()
	base.dropWrites.Store(true)
	t.Cleanup(func() { _ = base.Close(); _ = peer.Close() })
	counted := &countingProbePath{PathConn: base}
	slot := startProbeTestWriter(t, e, &pathSlot{id: 23, owner: 230, conn: counted})

	for iteration := 0; iteration < iterations; iteration++ {
		func() {
			if err := slot.acquireWrite(context.Background()); err != nil {
				t.Fatal(err)
			}
			permitHeld := true
			defer func() {
				if permitHeld {
					slot.releaseWrite()
				}
			}()

			e.issuePathProbe(slot)
			var probeID uint64
			var queued pathProbeObservation
			eventuallyEngine(t, time.Second, func() bool {
				e.probeMu.Lock()
				defer e.probeMu.Unlock()
				for id, observation := range e.probeOutstanding {
					if observation.slot == slot && observation.lifecycle == pathProbeQueued {
						probeID, queued = id, observation
						return true
					}
				}
				return false
			})
			status := e.pathProbeStatuses(queued.queuedAt.Add(time.Hour))[slot]
			if status.lifecycle != pathProbeQueued || status.failure != pathProbeFailureNone {
				t.Fatalf("iteration %d queued status=%+v", iteration, status)
			}
			if state := slot.probeLiveness(queued.queuedAt.Add(time.Hour), e.limits.ProbeInterval); state == qualityStateStale {
				t.Fatalf("iteration %d queued probe became wire-stale", iteration)
			}

			if iteration%2 == 0 {
				if !slot.tryFenceDispatch() {
					t.Fatalf("iteration %d could not fence queued probe", iteration)
				}
				slot.releaseWrite()
				permitHeld = false
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				err := slot.waitProbeWriters(ctx)
				cancel()
				if err != nil {
					t.Fatalf("iteration %d fence drain: %v", iteration, err)
				}
				e.probeMu.Lock()
				_, retained := e.probeOutstanding[probeID]
				e.probeMu.Unlock()
				if retained {
					t.Fatalf("iteration %d retained fenced queued probe", iteration)
				}
				slot.unfenceDispatch()
				return
			}

			slot.releaseWrite()
			permitHeld = false
			eventuallyEngine(t, time.Second, func() bool {
				e.probeMu.Lock()
				observation, ok := e.probeOutstanding[probeID]
				e.probeMu.Unlock()
				return ok && observation.lifecycle == pathProbeWriteCommitted
			})
			e.probeMu.Lock()
			committed := e.probeOutstanding[probeID]
			e.probeMu.Unlock()
			if !e.acceptPathProbeReply(slot, proto.ProbePayload{ID: probeID, TS: committed.wireTS}, committed.writeCommittedAt.Add(time.Millisecond)) {
				t.Fatalf("iteration %d committed reply rejected", iteration)
			}
		}()
	}

	evidence, ok := slot.probeSnapshot()
	wantCommitted := uint64(iterations / 2)
	if !ok || evidence.issued != wantCommitted || evidence.succeeded != wantCommitted || evidence.timedOut != 0 ||
		evidence.quality.RTT != time.Millisecond {
		t.Fatalf("high-count evidence=%+v ok=%t want committed=%d", evidence, ok, wantCommitted)
	}
	if writes := counted.writes.Load(); writes != wantCommitted {
		t.Fatalf("physical writes=%d want %d", writes, wantCommitted)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	if err := slot.waitProbeWriters(ctx); err != nil {
		cancel()
		t.Fatalf("high-count probe writers did not drain: %v", err)
	}
	cancel()
	slot.probeControlMu.Lock()
	writers := slot.probeWriterCount
	slot.probeControlMu.Unlock()
	e.probeMu.Lock()
	outstanding := len(e.probeOutstanding)
	e.probeMu.Unlock()
	if writers != 0 || outstanding != 0 {
		t.Fatalf("high-count writers/outstanding=%d/%d want 0/0", writers, outstanding)
	}
}

func TestProbeReplyBeforeWriteCompletionHighCount(t *testing.T) {
	const probes = 512
	e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: 10 * time.Millisecond}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	slot := &pathSlot{id: 24, owner: 240}
	generation := pathProbeGenerationForSlot(slot)
	startedAt := time.Unix(1_000, 0)
	committedAt := startedAt.Add(time.Millisecond)

	e.probeMu.Lock()
	for id := uint64(1); id <= probes; id++ {
		e.probeOutstanding[id] = pathProbeObservation{
			queuedAt: startedAt.Add(-time.Second), writeStartedAt: startedAt,
			generation: generation, slot: slot, wireTS: id, lifecycle: pathProbeWriteStarted,
		}
	}
	e.probeMu.Unlock()

	var replies sync.WaitGroup
	replies.Add(probes)
	for id := uint64(1); id <= probes; id++ {
		go func(id uint64) {
			defer replies.Done()
			if !e.acceptPathProbeReply(slot, proto.ProbePayload{ID: id, TS: id}, startedAt) {
				t.Errorf("probe %d early reply rejected", id)
			}
		}(id)
	}
	replies.Wait()

	var completions sync.WaitGroup
	completions.Add(probes)
	for id := uint64(1); id <= probes; id++ {
		go func(id uint64) {
			defer completions.Done()
			e.completePathProbeWrite(id, slot, nil, committedAt)
		}(id)
	}
	completions.Wait()

	evidence, ok := slot.probeSnapshot()
	if !ok || evidence.issued != probes || evidence.succeeded != probes || evidence.timedOut != 0 ||
		evidence.quality.RTT != time.Nanosecond {
		t.Fatalf("reply-before-completion evidence=%+v ok=%t", evidence, ok)
	}
	e.probeMu.Lock()
	outstanding := len(e.probeOutstanding)
	e.probeMu.Unlock()
	if outstanding != 0 {
		t.Fatalf("reply-before-completion retained %d probes", outstanding)
	}
}

func TestProbeCommittedWireExpiryHighCount(t *testing.T) {
	const probes = 1024
	e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: 10 * time.Millisecond}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	slot := &pathSlot{id: 25, owner: 250}
	generation := pathProbeGenerationForSlot(slot)
	startedAt := time.Unix(2_000, 0)
	committedAt := startedAt.Add(time.Millisecond)

	e.probeMu.Lock()
	for id := uint64(1); id <= probes; id++ {
		e.probeOutstanding[id] = pathProbeObservation{
			queuedAt: startedAt.Add(-time.Hour), writeStartedAt: startedAt,
			generation: generation, slot: slot, wireTS: id, lifecycle: pathProbeWriteStarted,
		}
	}
	e.probeMu.Unlock()
	for id := uint64(1); id <= probes; id++ {
		e.completePathProbeWrite(id, slot, nil, committedAt)
	}

	status := e.pathProbeStatuses(committedAt.Add(minimumSelectorProbeFreshFor - time.Nanosecond))[slot]
	if status.lifecycle != pathProbeWriteCommitted || status.failure != pathProbeFailureNone {
		t.Fatalf("pre-expiry status=%+v", status)
	}
	e.expirePathProbes(committedAt.Add(minimumSelectorProbeFreshFor))
	evidence, ok := slot.probeSnapshot()
	if !ok || evidence.issued != probes || evidence.succeeded != 0 || evidence.timedOut != probes ||
		evidence.lastLifecycle != pathProbeWireTimeout {
		t.Fatalf("wire-expiry evidence=%+v ok=%t", evidence, ok)
	}
	if state := slot.probeLiveness(committedAt.Add(minimumSelectorProbeFreshFor+time.Nanosecond), e.limits.ProbeInterval); state != qualityStateStale {
		t.Fatalf("post-expiry liveness=%d want stale", state)
	}
	e.probeMu.Lock()
	outstanding := len(e.probeOutstanding)
	e.probeMu.Unlock()
	if outstanding != 0 {
		t.Fatalf("wire expiry retained %d probes", outstanding)
	}
}

func TestProbeWaitingAtTXFenceCannotCrossDrain(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	base, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = base.Close(); _ = peer.Close() })
	counted := &countingProbePath{PathConn: base}
	slot := startProbeTestWriter(t, e, &pathSlot{id: 17, owner: 170, conn: counted})
	if err := slot.acquireWrite(context.Background()); err != nil {
		t.Fatal(err)
	}
	released := false
	defer func() {
		if !released {
			slot.releaseWrite()
		}
	}()
	e.issuePathProbe(slot)
	eventuallyEngine(t, time.Second, func() bool {
		e.probeMu.Lock()
		defer e.probeMu.Unlock()
		for _, observation := range e.probeOutstanding {
			if observation.slot == slot && observation.lifecycle != pathProbeReserved {
				return true
			}
		}
		return false
	})
	if !slot.tryFenceDispatch() {
		t.Fatal("failed to establish TX fence")
	}
	slot.releaseWrite()
	released = true
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := slot.waitWriteIdle(ctx); err != nil {
		t.Fatalf("drain after fence: %v", err)
	}
	eventuallyEngine(t, time.Second, func() bool {
		e.probeMu.Lock()
		defer e.probeMu.Unlock()
		for _, observation := range e.probeOutstanding {
			if observation.slot == slot {
				return false
			}
		}
		return true
	})
	e.handlePathProbeRequest(slot, proto.ProbePayload{ID: 9, TS: 19}.Encode())
	time.Sleep(20 * time.Millisecond)
	if writes := counted.writes.Load(); writes != 0 {
		t.Fatalf("probe control crossed drained TX fence: writes=%d", writes)
	}
}

func TestProbeStartedBeforeTXFenceIsIncludedInDrain(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	base, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = base.Close(); _ = peer.Close() })
	counted := &countingProbePath{PathConn: base}
	blocked := newBlockingProbePath(counted, 1)
	slot := startProbeTestWriter(t, e, &pathSlot{id: 18, owner: 180, conn: blocked})
	e.issuePathProbe(slot)
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("probe did not enter Conn.Write")
	}
	if !slot.tryFenceDispatch() {
		t.Fatal("failed to establish TX fence")
	}
	drained := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		drained <- slot.waitWriteIdle(ctx)
	}()
	select {
	case err := <-drained:
		t.Fatalf("fence drained while probe Write was blocked: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(blocked.release)
	select {
	case err := <-drained:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("fence did not drain after probe Write completed")
	}
	e.issuePathProbe(slot)
	e.handlePathProbeRequest(slot, proto.ProbePayload{ID: 10, TS: 20}.Encode())
	time.Sleep(20 * time.Millisecond)
	if writes := counted.writes.Load(); writes != 1 {
		t.Fatalf("post-fence probe write count=%d want only pre-fence write", writes)
	}
}

func TestRegisteredProbeWriterCannotCrossTXFenceGeneration(t *testing.T) {
	tests := []struct {
		name  string
		start func(*Engine, *pathSlot)
	}{
		{
			name: "request",
			start: func(e *Engine, slot *pathSlot) {
				e.issuePathProbe(slot)
			},
		},
		{
			name: "reply",
			start: func(e *Engine, slot *pathSlot) {
				e.handlePathProbeRequest(slot, proto.ProbePayload{ID: 23, TS: 29}.Encode())
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
			t.Cleanup(func() { _ = e.Close() })
			base, peer := newMemoryPathPair()
			t.Cleanup(func() { _ = base.Close(); _ = peer.Close() })
			counted := &countingProbePath{PathConn: base}
			slot := startProbeTestWriter(t, e, &pathSlot{id: 19, owner: 190, conn: counted})

			entered := make(chan struct{})
			release := make(chan struct{})
			var enteredOnce sync.Once
			var releaseOnce sync.Once
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			slot.probeBeforeWritePermit = func() {
				enteredOnce.Do(func() { close(entered) })
				<-release
			}
			test.start(e, slot)
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("probe writer was not registered before acquiring the write permit")
			}
			if !slot.tryFenceDispatch() {
				t.Fatal("failed to establish TX fence")
			}
			drained := make(chan error, 1)
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				drained <- slot.waitWriteIdle(ctx)
			}()
			select {
			case err := <-drained:
				t.Fatalf("fence omitted registered probe writer: %v", err)
			case <-time.After(50 * time.Millisecond):
			}

			releaseOnce.Do(func() { close(release) })
			select {
			case err := <-drained:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("fence did not drain after registered probe writer exited")
			}
			slot.probeEndpointGen.Add(1)
			e.invalidatePathProbeEvidence(slot)
			slot.unfenceDispatch()
			time.Sleep(20 * time.Millisecond)
			if writes := counted.writes.Load(); writes != 0 {
				t.Fatalf("pre-fence probe crossed into successor generation: writes=%d", writes)
			}
		})
	}
}

func TestProbeWaitingForHeldWritePermitIsCancelledByFence(t *testing.T) {
	tests := []struct {
		name  string
		start func(*Engine, *pathSlot, uint64)
	}{
		{
			name: "request",
			start: func(e *Engine, slot *pathSlot, _ uint64) {
				e.issuePathProbe(slot)
			},
		},
		{
			name: "reply",
			start: func(e *Engine, slot *pathSlot, id uint64) {
				e.handlePathProbeRequest(slot, proto.ProbePayload{ID: id, TS: id + 1}.Encode())
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
			t.Cleanup(func() { _ = e.Close() })
			base, peer := newMemoryPathPair()
			t.Cleanup(func() { _ = base.Close(); _ = peer.Close() })
			counted := &countingProbePath{PathConn: base}
			slot := startProbeTestWriter(t, e, &pathSlot{id: 21, owner: 210, conn: counted})

			if err := slot.acquireWrite(context.Background()); err != nil {
				t.Fatal(err)
			}
			permitHeld := true
			defer func() {
				if permitHeld {
					slot.releaseWrite()
				}
			}()

			atPermit := make(chan struct{})
			continueToPermit := make(chan struct{})
			var atPermitOnce sync.Once
			var continueOnce sync.Once
			continueProbe := func() { continueOnce.Do(func() { close(continueToPermit) }) }
			t.Cleanup(continueProbe)
			slot.probeBeforeWritePermit = func() {
				atPermitOnce.Do(func() { close(atPermit) })
				<-continueToPermit
			}
			test.start(e, slot, 61)
			select {
			case <-atPermit:
			case <-time.After(time.Second):
				t.Fatal("probe writer did not register before the held write permit")
			}
			if !slot.tryFenceDispatch() {
				t.Fatal("failed to establish TX fence")
			}
			continueProbe()

			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			err := slot.waitProbeWriters(ctx)
			cancel()
			if err != nil {
				t.Fatalf("fence could not supersede probe waiting for write permit: %v", err)
			}
			if writes := counted.writes.Load(); writes != 0 {
				t.Fatalf("cancelled pre-fence probe reached the wire: writes=%d", writes)
			}

			// Rollback may reopen TX while the application writer still owns the
			// permit. The cancelled probe must not revive and consume it later.
			slot.unfenceDispatch()
			slot.probeBeforeWritePermit = nil
			slot.releaseWrite()
			permitHeld = false
			time.Sleep(20 * time.Millisecond)
			if writes := counted.writes.Load(); writes != 0 {
				t.Fatalf("cancelled probe crossed rollback/unfence: writes=%d", writes)
			}

			test.start(e, slot, 67)
			eventuallyEngine(t, time.Second, func() bool { return counted.writes.Load() == 1 })
		})
	}
}

func TestProbeRequestReceivedBeforeFenceCannotReplyOnSuccessor(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	base, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = base.Close(); _ = peer.Close() })
	counted := &countingProbePath{PathConn: base}
	slot := startProbeTestWriter(t, e, &pathSlot{id: 20, owner: 200, conn: counted})

	captured := make(chan struct{})
	release := make(chan struct{})
	var capturedOnce sync.Once
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	slot.probeRequestBeforeSubmit = func() {
		capturedOnce.Do(func() { close(captured) })
		<-release
	}
	handled := make(chan struct{})
	go func() {
		e.handlePathProbeRequest(slot, proto.ProbePayload{ID: 41, TS: 43}.Encode())
		close(handled)
	}()
	select {
	case <-captured:
	case <-time.After(time.Second):
		t.Fatal("probe request did not capture predecessor generation")
	}
	if !slot.tryFenceDispatch() {
		t.Fatal("failed to establish TX fence")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := slot.waitWriteIdle(ctx); err != nil {
		t.Fatal(err)
	}
	slot.probeEndpointGen.Add(1)
	e.invalidatePathProbeEvidence(slot)
	slot.unfenceDispatch()
	releaseOnce.Do(func() { close(release) })
	select {
	case <-handled:
	case <-time.After(time.Second):
		t.Fatal("captured probe request did not finish")
	}
	time.Sleep(20 * time.Millisecond)
	if writes := counted.writes.Load(); writes != 0 {
		t.Fatalf("predecessor request produced %d successor reply writes", writes)
	}
}

func TestProbeRepliesCoalesceWithoutConsumingDispatchQueue(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	base, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = base.Close(); _ = peer.Close() })
	slot := startProbeTestWriter(t, e, &pathSlot{id: 15, owner: 150, conn: base})
	if err := slot.acquireWrite(context.Background()); err != nil {
		t.Fatal(err)
	}
	released := false
	defer func() {
		if !released {
			slot.releaseWrite()
		}
	}()
	const latestID = 1000
	for id := uint64(1); id <= latestID; id++ {
		e.handlePathProbeRequest(slot, proto.ProbePayload{TS: id + 10, ID: id}.Encode())
	}
	slot.probeControlMu.Lock()
	running := slot.probeReplyRunning
	pending := append([]byte(nil), slot.probeReplyPending...)
	slot.probeControlMu.Unlock()
	if !running || len(pending) < proto.HeaderSize {
		t.Fatalf("coalesced reply state running=%t bytes=%d", running, len(pending))
	}
	probe, err := proto.DecodeProbe(pending[proto.HeaderSize:])
	if err != nil || probe.ID != latestID {
		t.Fatalf("pending probe=%+v err=%v want latest ID %d", probe, err, latestID)
	}
	if queued := len(slot.dispatchQ); queued != 0 {
		t.Fatalf("probe replies consumed %d DATA dispatch queue entries", queued)
	}
	slot.releaseWrite()
	released = true
	eventuallyEngine(t, time.Second, func() bool {
		slot.probeControlMu.Lock()
		defer slot.probeControlMu.Unlock()
		return !slot.probeReplyRunning && len(slot.probeReplyPending) == 0
	})
	frame := make(chan []byte, 1)
	go func() {
		buf := make([]byte, proto.HeaderSize+proto.ProbePayloadSize)
		n, _ := peer.Read(buf)
		frame <- append([]byte(nil), buf[:n]...)
	}()
	select {
	case got := <-frame:
		if len(got) < proto.HeaderSize {
			t.Fatalf("wire reply bytes=%d", len(got))
		}
		probe, err := proto.DecodeProbe(got[proto.HeaderSize:])
		if err != nil || probe.ID != latestID {
			t.Fatalf("wire probe=%+v err=%v want latest ID %d", probe, err, latestID)
		}
	case <-time.After(time.Second):
		t.Fatal("coalesced probe reply was not written")
	}
}

func TestProbeRequestPartialWriteRetiresPath(t *testing.T) {
	for _, withError := range []bool{false, true} {
		t.Run(strconv.FormatBool(withError), func(t *testing.T) {
			testProbePartialWriteRetiresPath(t, proto.CtrlPathProbe, true, withError)
		})
	}
}

func TestProbeReplyPartialWriteRetiresPath(t *testing.T) {
	for _, withError := range []bool{false, true} {
		t.Run(strconv.FormatBool(withError), func(t *testing.T) {
			testProbePartialWriteRetiresPath(t, proto.CtrlPathProbeReply, false, withError)
		})
	}
}

func testProbePartialWriteRetiresPath(t *testing.T, code proto.CtrlCode, issue, withError bool) {
	t.Helper()
	e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: 10 * time.Millisecond}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	ids := configureLeafSelectorRuntime(t, e, "partial")
	base, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = base.Close(); _ = peer.Close() })
	partial := &partialProbeWritePath{PathConn: base, code: code, withError: withError}
	id := attachFixturePath(t, e, partial, transport.PathSpec{Transport: "probe-partial", Address: "partial"}, ids["partial"])
	e.pathsMu.RLock()
	slot := e.paths[id]
	e.pathsMu.RUnlock()
	if issue {
		e.StartSelector(time.Second)
	} else {
		e.handlePathProbeRequest(slot, proto.ProbePayload{ID: 3}.Encode())
	}
	eventuallyEngine(t, time.Second, func() bool {
		for _, info := range e.Paths() {
			if info.ID == id {
				return false
			}
		}
		return true
	})
}

func TestCloseClearsOutstandingProbeStateAndPathEvidence(t *testing.T) {
	t.Run("waits for cancellable quality observer cleanup", testCloseWaitsForQualityObserverCleanup)

	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	path, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = peer.Close() })
	id, err := e.AttachPath(path, transport.PathSpec{Transport: "probe-close"})
	if err != nil {
		t.Fatal(err)
	}
	e.pathsMu.RLock()
	slot := e.paths[id]
	e.pathsMu.RUnlock()
	issued := time.Now()
	generation := pathProbeGenerationForSlot(slot)
	slot.probeEvidence.Store(&pathProbeEvidence{generation: generation, firstIssued: issued, issued: 1024})
	e.probeMu.Lock()
	for probeID := uint64(1); probeID <= 1024; probeID++ {
		e.probeOutstanding[probeID] = pathProbeObservation{
			queuedAt: issued, writeStartedAt: issued, generation: generation, slot: slot,
			lifecycle: pathProbeWriteStarted,
		}
	}
	e.probeMu.Unlock()
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	e.probeMu.Lock()
	outstanding := len(e.probeOutstanding)
	e.probeMu.Unlock()
	if outstanding != 0 {
		t.Fatalf("Close retained %d probe observations", outstanding)
	}
	if evidence := slot.probeEvidence.Load(); evidence != nil {
		t.Fatalf("Close retained path probe evidence: %+v", *evidence)
	}
}

func seedOutstandingProbe(t *testing.T, e *Engine, slot *pathSlot, id uint64, issued time.Time) {
	t.Helper()
	generation := pathProbeGenerationForSlot(slot)
	evidence := pathProbeEvidence{
		generation: generation, fenceEpoch: slot.txFenceEpoch.Load(), fenceTracked: true,
		firstIssued: issued, lastIssued: issued,
		lastLifecycle: pathProbeWriteCommitted, lastTransition: issued, issued: 1,
	}
	slot.probeEvidence.Store(&evidence)
	e.probeMu.Lock()
	e.probeOutstanding[id] = pathProbeObservation{
		queuedAt: issued, writeStartedAt: issued, writeCommittedAt: issued,
		deadline: issued.Add(maximumSelectorProbeFreshFor), generation: generation, slot: slot,
		fenceEpoch: slot.txFenceEpoch.Load(), lifecycle: pathProbeWriteCommitted,
	}
	e.probeMu.Unlock()
}

func startProbeTestWriter(t *testing.T, e *Engine, slot *pathSlot) *pathSlot {
	t.Helper()
	slot.quit = make(chan struct{})
	slot.doneW = make(chan struct{})
	slot.dispatchQ = make(chan pathDispatchJob, pathDispatchQueueSize)
	slot.writePermit = newPathWritePermit()
	slot.admissionDone = make(chan struct{})
	slot.txEnabled.Store(true)
	slot.writerStarted.Store(true)
	go e.pathWriterLoop(slot)
	t.Cleanup(func() {
		slot.closeQuit()
		if slot.conn != nil {
			_ = slot.conn.Close()
		}
		select {
		case <-slot.doneW:
		case <-time.After(time.Second):
			t.Error("probe test writer did not stop")
		}
		probeDone := make(chan struct{})
		go func() {
			slot.probeWriteWG.Wait()
			close(probeDone)
		}()
		select {
		case <-probeDone:
		case <-time.After(time.Second):
			t.Error("probe control writer did not stop")
		}
	})
	return slot
}

func makeProbeTestFrame(t *testing.T, code proto.CtrlCode, id uint64) []byte {
	t.Helper()
	payload := proto.ProbePayload{ID: id}.Encode()
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := (proto.Header{Version: proto.Version, Type: proto.FrameCtrl, Flags: proto.FlagsForCtrl(code)}).Encode(frame[:proto.HeaderSize]); err != nil {
		t.Fatal(err)
	}
	copy(frame[proto.HeaderSize:], payload)
	return frame
}

func makeProbeTestDataFrame(t *testing.T, payload []byte) []byte {
	t.Helper()
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := (proto.Header{Version: proto.Version, Type: proto.FrameData, Seq: 1}).Encode(frame[:proto.HeaderSize]); err != nil {
		t.Fatal(err)
	}
	copy(frame[proto.HeaderSize:], payload)
	return frame
}

type blockingProbePath struct {
	transport.PathConn
	remaining atomic.Int64
	started   chan struct{}
	release   chan struct{}
	startOnce sync.Once
}

func newBlockingProbePath(path transport.PathConn, writes int64) *blockingProbePath {
	p := &blockingProbePath{PathConn: path, started: make(chan struct{}), release: make(chan struct{})}
	p.remaining.Store(writes)
	return p
}

func (p *blockingProbePath) Write(frame []byte) (int, error) {
	if p.remaining.Add(-1) >= 0 {
		p.startOnce.Do(func() { close(p.started) })
		<-p.release
	}
	return p.PathConn.Write(frame)
}

type partialProbeWritePath struct {
	transport.PathConn
	code      proto.CtrlCode
	withError bool
}

type countingProbePath struct {
	transport.PathConn
	writes atomic.Uint64
}

func (p *countingProbePath) Write(frame []byte) (int, error) {
	p.writes.Add(1)
	return p.PathConn.Write(frame)
}

func (p *partialProbeWritePath) Write(frame []byte) (int, error) {
	if len(frame) >= proto.HeaderSize {
		header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err == nil && header.Type == proto.FrameCtrl && proto.CtrlCodeFromFlags(header.Flags) == p.code {
			if p.withError {
				return len(frame) - 1, net.ErrClosed
			}
			return len(frame) - 1, nil
		}
	}
	return p.PathConn.Write(frame)
}

type synchronousProbeReplyPath struct {
	engine     *Engine
	slot       *pathSlot
	replyDelay time.Duration
}

func (*synchronousProbeReplyPath) Read([]byte) (int, error) { return 0, net.ErrClosed }

func (p *synchronousProbeReplyPath) Write(frame []byte) (int, error) {
	if len(frame) < proto.HeaderSize {
		return 0, net.ErrClosed
	}
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil || header.Type != proto.FrameCtrl || proto.CtrlCodeFromFlags(header.Flags) != proto.CtrlPathProbe {
		return 0, net.ErrClosed
	}
	probe, err := proto.DecodeProbe(frame[proto.HeaderSize:])
	if err != nil {
		return 0, err
	}
	p.engine.probeMu.Lock()
	observation, ok := p.engine.probeOutstanding[probe.ID]
	p.engine.probeMu.Unlock()
	if !ok || observation.writeStartedAt.IsZero() {
		return 0, errors.New("probe Write began without write-start evidence")
	}
	p.engine.acceptPathProbeReply(p.slot, probe, observation.writeStartedAt.Add(p.replyDelay))
	return len(frame), nil
}

func (*synchronousProbeReplyPath) Close() error { return nil }

func (*synchronousProbeReplyPath) Quality() transport.PathQuality { return transport.PathQuality{} }

func (*synchronousProbeReplyPath) OnDeath(func(transport.DeathCause, error)) {}

func (*synchronousProbeReplyPath) LocalAddr() string  { return "probe-local" }
func (*synchronousProbeReplyPath) RemoteAddr() string { return "probe-remote" }

type probeQualityPath struct {
	transport.PathConn
	mu          sync.Mutex
	quality     transport.PathQuality
	setterCalls atomic.Uint64
}

func (p *probeQualityPath) Quality() transport.PathQuality {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.quality
}

func (p *probeQualityPath) SetQuality(quality transport.PathQuality) {
	p.setterCalls.Add(1)
	p.setTransportQuality(quality)
}

func (p *probeQualityPath) setTransportQuality(quality transport.PathQuality) {
	p.mu.Lock()
	p.quality = quality
	p.mu.Unlock()
}
