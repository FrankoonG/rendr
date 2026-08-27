package engine

import (
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type policyCallbackBehavior uint8

const (
	policyCallbackPanic policyCallbackBehavior = iota
	policyCallbackGoexit
	policyCallbackBlock
)

func requirePolicyCallbackDiagnostic(
	t *testing.T,
	e *Engine,
	behavior policyCallbackBehavior,
) PolicyCallbackDiagnostic {
	t.Helper()
	diagnostic := e.PolicyCallbackDiagnostics()
	if diagnostic.Failures == 0 || diagnostic.LastError == nil {
		t.Fatalf("policy callback diagnostic=%+v, want recorded failure", diagnostic)
	}
	switch behavior {
	case policyCallbackPanic:
		var callbackErr *pathDispatchCallbackPanicError
		if !errors.As(diagnostic.LastError, &callbackErr) {
			t.Fatalf("diagnostic error=%v, want typed panic", diagnostic.LastError)
		}
	case policyCallbackGoexit:
		var callbackErr *pathDispatchCallbackGoexitError
		if !errors.As(diagnostic.LastError, &callbackErr) {
			t.Fatalf("diagnostic error=%v, want typed Goexit", diagnostic.LastError)
		}
	case policyCallbackBlock:
		var callbackErr *pathDispatchCallbackDeadlineError
		if !errors.As(diagnostic.LastError, &callbackErr) {
			t.Fatalf("diagnostic error=%v, want typed deadline", diagnostic.LastError)
		}
	}
	return diagnostic
}

func reserveOptionalCallbackClass(t *testing.T, operation string) []*externalPathCallbackLease {
	t.Helper()
	leases := make([]*externalPathCallbackLease, 0, externalPathCallbackClassLimit)
	complete := false
	defer func() {
		if complete {
			return
		}
		for _, lease := range leases {
			lease.release()
		}
	}()

	deadline := time.Now().Add(time.Second)
	for len(leases) < externalPathCallbackClassLimit {
		target := &struct{ index int }{index: len(leases)}
		lease, err := acquireExternalPathCallbackLease(operation, target)
		if err == nil {
			leases = append(leases, lease)
			continue
		}
		var capacityErr *pathDispatchCallbackCapacityError
		if !errors.As(err, &capacityErr) {
			t.Fatalf("reserve optional callback %d: %v", len(leases), err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("reserve optional callback %d: capacity did not recover: %v", len(leases), err)
		}
		time.Sleep(time.Millisecond)
	}
	complete = true
	return leases
}

func releaseOptionalCallbackClass(leases []*externalPathCallbackLease) {
	for _, lease := range leases {
		lease.release()
	}
}

func newPolicyCallbackUnitFixture(t *testing.T) *policyTxUnitFixture {
	t.Helper()
	const (
		rootName = "policy-callback-unit-root"
		nameA    = "policy-callback-unit-a"
		nameB    = "policy-callback-unit-b"
	)
	pathA := policyTxUnitNode(proto.GraphNodeKindPath, nameA)
	pathB := policyTxUnitNode(proto.GraphNodeKindPath, nameB)
	selector := policyTxUnitNode(proto.GraphNodeKindSelector, rootName, pathA.ID, pathB.ID)
	manifest := proto.GraphManifest{
		RootID: selector.ID,
		Nodes:  []proto.GraphNode{selector, pathA, pathB},
	}
	e, recorder, paths, handles := newPolicyTxUnitEngineWithOptions(
		t,
		Limits{ProbeInterval: time.Hour}.Clamp(),
		true,
		manifest,
		selector.ID,
		nameA,
		nameB,
	)
	return &policyTxUnitFixture{
		engine:     e,
		recorder:   recorder,
		selectorID: selector.ID,
		targetA:    pathA.ID,
		targetB:    pathB.ID,
		pathA:      paths[nameA],
		pathB:      paths[nameB],
		nameA:      nameA,
		nameB:      nameB,
		handleA:    handles[nameA],
		handleB:    handles[nameB],
	}
}

func TestPolicyAdmissionAbnormalCallbacksRejectPrepareAndRecover(t *testing.T) {
	for _, test := range []struct {
		name     string
		behavior policyCallbackBehavior
	}{
		{name: "panic", behavior: policyCallbackPanic},
		{name: "goexit", behavior: policyCallbackGoexit},
		{name: "forever-block", behavior: policyCallbackBlock},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPolicyCallbackUnitFixture(t)
			entered := make(chan struct{})
			release := make(chan struct{})
			var enteredOnce, releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			t.Cleanup(unblock)
			fixture.engine.SetPeerPolicyAdmission(func(_, _ proto.TargetID, _ string) error {
				switch test.behavior {
				case policyCallbackPanic:
					panic("hostile PREPARE admission")
				case policyCallbackGoexit:
					runtime.Goexit()
				case policyCallbackBlock:
					enteredOnce.Do(func() { close(entered) })
					<-release
				}
				return nil
			})
			fixture.engine.policyAdmissionMu.RLock()
			callback := fixture.engine.policyAdmission
			fixture.engine.policyAdmissionMu.RUnlock()

			prepare := policyTxUnitPrepare(
				fixture.engine, 0xc1, 0, fixture.selectorID, fixture.targetB,
			)
			started := time.Now()
			rejected := policyTxUnitRequireAck(t, fixture.recorder, func() error {
				return fixture.engine.handlePolicyPrepare(prepare)
			})
			if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
				t.Fatalf("hostile PREPARE admission escaped after %s", elapsed)
			}
			if rejected.ack.Phase != proto.PolicyAckPhasePrepare ||
				rejected.ack.Code != proto.PolicyAckCodeReject {
				t.Fatalf("PREPARE=%+v, want deterministic rejection", rejected.ack)
			}
			generation, selected, pending, _ := policyTxUnitState(fixture.engine, fixture.selectorID)
			if generation != 0 || selected != fixture.targetA || pending {
				t.Fatalf("PREPARE callback changed policy: generation=%d selected=%x pending=%t", generation, selected, pending)
			}
			requirePolicyCallbackDiagnostic(t, fixture.engine, test.behavior)

			if test.behavior == policyCallbackBlock {
				select {
				case <-entered:
				default:
					t.Fatal("blocking PREPARE admission did not enter")
				}
				if !externalPathCallbackInFlight(policyAdmissionCallbackOp, callback) {
					t.Fatal("blocking PREPARE admission did not retain its lease")
				}
				unblock()
				eventuallyEngine(t, time.Second, func() bool {
					return !externalPathCallbackInFlight(policyAdmissionCallbackOp, callback)
				})
			}

			fixture.engine.SetPeerPolicyAdmission(func(_, _ proto.TargetID, _ string) error { return nil })
			recovery := policyTxUnitPrepare(
				fixture.engine, 0xc2, 0, fixture.selectorID, fixture.targetB,
			)
			prepared := policyTxUnitRequireAck(t, fixture.recorder, func() error {
				return fixture.engine.handlePolicyPrepare(recovery)
			})
			if prepared.ack.Code != proto.PolicyAckCodeAccept {
				t.Fatalf("recovery PREPARE=%+v, want accept", prepared.ack)
			}
			commit := policyTxUnitCommit(t, recovery, prepared.ack.Generation, prepared.ack.ReservationID)
			final := policyTxUnitRequireAck(t, fixture.recorder, func() error {
				return fixture.engine.handlePolicyCommit(commit)
			})
			if final.ack.Code != proto.PolicyAckCodeAccept {
				t.Fatalf("recovery FINAL=%+v, want accept", final.ack)
			}
		})
	}
}

func TestPolicyAdmissionAbnormalCallbacksPublishRejectFinal(t *testing.T) {
	for _, test := range []struct {
		name     string
		behavior policyCallbackBehavior
	}{
		{name: "panic", behavior: policyCallbackPanic},
		{name: "goexit", behavior: policyCallbackGoexit},
		{name: "forever-block", behavior: policyCallbackBlock},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPolicyCallbackUnitFixture(t)
			prepare := policyTxUnitPrepare(
				fixture.engine, 0xd1, 0, fixture.selectorID, fixture.targetB,
			)
			prepared := policyTxUnitRequireAck(t, fixture.recorder, func() error {
				return fixture.engine.handlePolicyPrepare(prepare)
			})
			if prepared.ack.Code != proto.PolicyAckCodeAccept {
				t.Fatalf("PREPARE=%+v, want accept before hostile admission is installed", prepared.ack)
			}

			entered := make(chan struct{})
			release := make(chan struct{})
			var enteredOnce, releaseOnce sync.Once
			var calls atomic.Int32
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			t.Cleanup(unblock)
			fixture.engine.SetPeerPolicyAdmission(func(_, _ proto.TargetID, _ string) error {
				calls.Add(1)
				switch test.behavior {
				case policyCallbackPanic:
					panic("hostile admission")
				case policyCallbackGoexit:
					runtime.Goexit()
				case policyCallbackBlock:
					enteredOnce.Do(func() { close(entered) })
					<-release
				}
				return nil
			})
			fixture.engine.policyAdmissionMu.RLock()
			callback := fixture.engine.policyAdmission
			fixture.engine.policyAdmissionMu.RUnlock()

			commit := policyTxUnitCommit(t, prepare, prepared.ack.Generation, prepared.ack.ReservationID)
			started := time.Now()
			final := policyTxUnitRequireAck(t, fixture.recorder, func() error {
				return fixture.engine.handlePolicyCommit(commit)
			})
			if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
				t.Fatalf("hostile admission delayed FINAL for %s", elapsed)
			}
			if final.ack.Phase != proto.PolicyAckPhaseFinal || final.ack.Code != proto.PolicyAckCodeReject {
				t.Fatalf("FINAL=%+v, want deterministic reject", final.ack)
			}
			generation, selected, pending, _ := policyTxUnitState(fixture.engine, fixture.selectorID)
			if generation != 0 || selected != fixture.targetA || pending {
				t.Fatalf("hostile admission changed policy: generation=%d selected=%x pending=%t", generation, selected, pending)
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("admission calls=%d, want 1", got)
			}
			requirePolicyCallbackDiagnostic(t, fixture.engine, test.behavior)

			if test.behavior == policyCallbackBlock {
				select {
				case <-entered:
				default:
					t.Fatal("blocking admission callback did not enter")
				}
				if !externalPathCallbackInFlight(policyAdmissionCallbackOp, callback) {
					t.Fatal("blocking admission callback did not retain bounded ownership")
				}
				for attempt := 0; attempt < 128; attempt++ {
					err := fixture.engine.admitPeerPolicy(fixture.selectorID, fixture.targetB, "repeat")
					var busyErr *pathDispatchCallbackBusyError
					if !errors.As(err, &busyErr) {
						t.Fatalf("repeat %d admission error=%v, want typed busy", attempt, err)
					}
				}
				if got := calls.Load(); got != 1 {
					t.Fatalf("blocking admission spawned %d callbacks, want 1", got)
				}
			}

			closeStarted := time.Now()
			if err := fixture.engine.Close(); err != nil {
				t.Fatalf("Close with hostile admission callback: %v", err)
			}
			if elapsed := time.Since(closeStarted); elapsed > 500*time.Millisecond {
				t.Fatalf("hostile admission delayed Close for %s", elapsed)
			}
			if test.behavior == policyCallbackBlock {
				unblock()
				eventuallyEngine(t, time.Second, func() bool {
					return !externalPathCallbackInFlight(policyAdmissionCallbackOp, callback)
				})
			}
		})
	}
}

func newPolicyCallbackPeakFixture(
	t *testing.T,
) (*Engine, *policyTxUnitAckRecorder, proto.GraphNode, proto.GraphNode, proto.GraphNode) {
	t.Helper()
	normal := policyTxUnitNode(proto.GraphNodeKindPath, "callback-normal")
	peak := policyTxUnitNode(proto.GraphNodeKindPath, "callback-peak")
	selector := policyTxUnitNode(proto.GraphNodeKindSelector, "callback-selector", normal.ID, peak.ID)
	selector.PeakCandidates = []proto.TargetID{peak.ID}
	manifest := proto.GraphManifest{RootID: selector.ID, Nodes: []proto.GraphNode{selector, normal, peak}}
	e, recorder, _, paths := newPolicyTxUnitEngineWithOptions(
		t,
		Limits{ProbeInterval: time.Hour}.Clamp(),
		true,
		manifest,
		selector.ID,
		normal.Name,
		peak.Name,
	)
	now := time.Now()
	paths[normal.Name].SetQuality(transport.PathQuality{RTT: 2 * time.Millisecond, At: now})
	paths[peak.Name].SetQuality(transport.PathQuality{RTT: 3 * time.Millisecond, At: now})
	return e, recorder, selector, normal, peak
}

func TestPeakPolicyObserverAbnormalCallbacksCannotDelayAcceptFinal(t *testing.T) {
	for _, test := range []struct {
		name     string
		behavior policyCallbackBehavior
	}{
		{name: "panic", behavior: policyCallbackPanic},
		{name: "goexit", behavior: policyCallbackGoexit},
		{name: "forever-block", behavior: policyCallbackBlock},
	} {
		t.Run(test.name, func(t *testing.T) {
			e, recorder, selector, _, peak := newPolicyCallbackPeakFixture(t)
			prepare := policyTxUnitClassPrepare(e, 0xd2, 0, selector.ID, true)
			prepared := policyTxUnitRequireAck(t, recorder, func() error {
				return e.handlePolicyPrepare(prepare)
			})
			if prepared.ack.Code != proto.PolicyAckCodeAccept || prepared.ack.ResolvedTargetID != peak.ID {
				t.Fatalf("peak PREPARE=%+v", prepared.ack)
			}

			entered := make(chan struct{})
			release := make(chan struct{})
			var enteredOnce, releaseOnce sync.Once
			var calls atomic.Int32
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			t.Cleanup(unblock)
			e.SetPeakPolicyObserver(func(_, _ proto.TargetID, _ uint64, _ bool, _ string) {
				calls.Add(1)
				switch test.behavior {
				case policyCallbackPanic:
					panic("hostile observer")
				case policyCallbackGoexit:
					runtime.Goexit()
				case policyCallbackBlock:
					enteredOnce.Do(func() { close(entered) })
					<-release
				}
			})
			e.peakPolicyObserverMu.RLock()
			callback := e.peakPolicyObserver
			e.peakPolicyObserverMu.RUnlock()

			commit := policyTxUnitCommit(t, prepare, prepared.ack.Generation, prepared.ack.ReservationID)
			started := time.Now()
			final := policyTxUnitRequireAck(t, recorder, func() error {
				return e.handlePolicyCommit(commit)
			})
			if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
				t.Fatalf("hostile observer delayed FINAL for %s", elapsed)
			}
			if final.ack.Phase != proto.PolicyAckPhaseFinal || final.ack.Code != proto.PolicyAckCodeAccept ||
				final.ack.ResolvedTargetID != peak.ID {
				t.Fatalf("FINAL=%+v, want committed peak selection", final.ack)
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("observer calls=%d, want 1", got)
			}
			requirePolicyCallbackDiagnostic(t, e, test.behavior)

			if test.behavior == policyCallbackBlock {
				select {
				case <-entered:
				default:
					t.Fatal("blocking observer callback did not enter")
				}
				if !externalPathCallbackInFlight(peakPolicyObserverCallbackOp, callback) {
					t.Fatal("blocking observer callback did not retain bounded ownership")
				}
				for attempt := 0; attempt < 128; attempt++ {
					e.observePeakPolicy(
						selector.ID, peak.ID, final.ack.SelectorGeneration,
						policySelectionPeakPromote, "repeat",
					)
				}
				if got := calls.Load(); got != 1 {
					t.Fatalf("blocking observer spawned %d callbacks, want 1", got)
				}
			}

			closeStarted := time.Now()
			if err := e.Close(); err != nil {
				t.Fatalf("Close with hostile observer callback: %v", err)
			}
			if elapsed := time.Since(closeStarted); elapsed > 500*time.Millisecond {
				t.Fatalf("hostile observer delayed Close for %s", elapsed)
			}
			if test.behavior == policyCallbackBlock {
				unblock()
				eventuallyEngine(t, time.Second, func() bool {
					return !externalPathCallbackInFlight(peakPolicyObserverCallbackOp, callback)
				})
			}
		})
	}
}

func TestPeakPolicyObserverBlockStartsAfterFinalAndCannotStrandReplayOrLaterCommit(t *testing.T) {
	e, recorder, selector, normal, peak := newPolicyCallbackPeakFixture(t)
	prepare := policyTxUnitClassPrepare(e, 0xd5, 0, selector.ID, true)
	prepared := policyTxUnitRequireAck(t, recorder, func() error {
		return e.handlePolicyPrepare(prepare)
	})
	if prepared.ack.Code != proto.PolicyAckCodeAccept || prepared.ack.ResolvedTargetID != peak.ID {
		t.Fatalf("peak PREPARE=%+v", prepared.ack)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	var calls atomic.Int32
	e.SetPeakPolicyObserver(func(_, _ proto.TargetID, _ uint64, _ bool, _ string) {
		calls.Add(1)
		enteredOnce.Do(func() { close(entered) })
		<-release
	})
	e.peakPolicyObserverMu.RLock()
	callback := e.peakPolicyObserver
	e.peakPolicyObserverMu.RUnlock()

	commit := policyTxUnitCommit(t, prepare, prepared.ack.Generation, prepared.ack.ReservationID)
	commitDone := make(chan error, 1)
	go func() { commitDone <- e.handlePolicyCommit(commit) }()
	awaitSignal(t, entered, "blocking policy observer")

	observations, err := recorder.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) == 0 {
		t.Fatal("observer started before FINAL publication")
	}
	var final policyTxUnitAckObservation
	foundFinal := false
	for _, observation := range observations {
		if observation.ack.TransactionID == commit.TransactionID &&
			observation.ack.Phase == proto.PolicyAckPhaseFinal {
			final = observation
			foundFinal = true
			break
		}
	}
	if !foundFinal {
		t.Fatalf("observer started before factual FINAL: observations=%+v", observations)
	}
	if final.ack.Phase != proto.PolicyAckPhaseFinal || final.ack.Code != proto.PolicyAckCodeAccept ||
		final.ack.ResolvedTargetID != peak.ID {
		t.Fatalf("observer started without factual accepting FINAL: %+v", final.ack)
	}
	generation, selected, pending, _ := policyTxUnitState(e, selector.ID)
	if generation != 1 || selected != peak.ID || pending {
		t.Fatalf("observer owns committed state: generation=%d selected=%x pending=%t", generation, selected, pending)
	}

	replayDone := make(chan error, 1)
	go func() { replayDone <- e.handlePolicyCommit(commit) }()
	select {
	case err := <-replayDone:
		if err != nil {
			t.Fatalf("FINAL replay while observer blocked: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("blocking observer stranded completed FINAL replay")
	}
	generation, selected, pending, completed := policyTxUnitState(e, selector.ID)
	if generation != 1 || selected != peak.ID || pending || completed != 1 {
		t.Fatalf(
			"FINAL replay changed committed ownership: generation=%d selected=%x pending=%t completed=%d",
			generation, selected, pending, completed,
		)
	}

	returnPrepare := policyTxUnitPrepare(e, 0xd6, 1, selector.ID, normal.ID)
	returnPrepared := policyTxUnitRequireAck(t, recorder, func() error {
		return e.handlePolicyPrepare(returnPrepare)
	})
	if returnPrepared.ack.Code != proto.PolicyAckCodeAccept || returnPrepared.ack.ResolvedTargetID != normal.ID {
		t.Fatalf("later PREPARE=%+v, want normal", returnPrepared.ack)
	}
	returnCommit := policyTxUnitCommit(t, returnPrepare, returnPrepared.ack.Generation, returnPrepared.ack.ReservationID)
	returnFinal := policyTxUnitRequireAck(t, recorder, func() error {
		return e.handlePolicyCommit(returnCommit)
	})
	if returnFinal.ack.Code != proto.PolicyAckCodeAccept || returnFinal.ack.ResolvedTargetID != normal.ID {
		t.Fatalf("later FINAL=%+v, want normal commit", returnFinal.ack)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("blocked observer callback invocations=%d, want one leased invocation", got)
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- e.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close while observer callback retained lease: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("blocking observer prevented Close")
	}
	unblock()
	eventuallyEngine(t, time.Second, func() bool {
		return !externalPathCallbackInFlight(peakPolicyObserverCallbackOp, callback)
	})
	select {
	case err := <-commitDone:
		if err != nil {
			t.Fatalf("first committed handler returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("first committed handler did not return after observer release")
	}
}

func TestPeakPolicyObserverCapacitySaturationReportsAndRecovers(t *testing.T) {
	eventuallyEngine(t, time.Second, func() bool {
		externalPathCallbacks.Lock()
		defer externalPathCallbacks.Unlock()
		return externalPathCallbacks.classInflight[externalPathCallbackOptional] == 0
	})
	leases := reserveOptionalCallbackClass(t, "PeakObserverSaturationReservation")
	defer releaseOptionalCallbackClass(leases)

	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	var calls atomic.Int32
	e.SetPeakPolicyObserver(func(_, _ proto.TargetID, _ uint64, _ bool, _ string) {
		calls.Add(1)
	})
	selectorID := proto.TargetID{0x71}
	targetID := proto.TargetID{0x72}
	e.observePeakPolicy(selectorID, targetID, 1, policySelectionPeakPromote, "capacity")
	if got := calls.Load(); got != 0 {
		t.Fatalf("capacity-exhausted observer ran %d times", got)
	}
	diagnostic := e.PolicyCallbackDiagnostics()
	var capacityErr *pathDispatchCallbackCapacityError
	if diagnostic.Failures != 1 || !errors.As(diagnostic.LastError, &capacityErr) {
		t.Fatalf("observer capacity diagnostic=%+v, want one typed capacity failure", diagnostic)
	}

	releaseOptionalCallbackClass(leases)
	eventuallyEngine(t, time.Second, func() bool {
		externalPathCallbacks.Lock()
		defer externalPathCallbacks.Unlock()
		return externalPathCallbacks.classInflight[externalPathCallbackOptional] == 0
	})
	e.observePeakPolicy(selectorID, targetID, 2, policySelectionPeakPromote, "recovery")
	if got := calls.Load(); got != 1 {
		t.Fatalf("observer did not recover after capacity release: calls=%d", got)
	}
}

func TestPolicyAdmissionCapacityExhaustionPublishesRejectFinal(t *testing.T) {
	fixture := newPolicyCallbackUnitFixture(t)
	prepare := policyTxUnitPrepare(fixture.engine, 0xd3, 0, fixture.selectorID, fixture.targetB)
	prepared := policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyPrepare(prepare)
	})
	if prepared.ack.Code != proto.PolicyAckCodeAccept {
		t.Fatalf("PREPARE=%+v", prepared.ack)
	}
	var calls atomic.Int32
	fixture.engine.SetPeerPolicyAdmission(func(_, _ proto.TargetID, _ string) error {
		calls.Add(1)
		return nil
	})
	eventuallyEngine(t, time.Second, func() bool {
		externalPathCallbacks.Lock()
		defer externalPathCallbacks.Unlock()
		return externalPathCallbacks.classInflight[externalPathCallbackOptional] == 0
	})

	leases := reserveOptionalCallbackClass(t, "PolicyCallbackSaturationReservation")
	defer releaseOptionalCallbackClass(leases)
	externalPathCallbacks.Lock()
	saturated := externalPathCallbacks.classInflight[externalPathCallbackOptional]
	externalPathCallbacks.Unlock()
	if saturated != externalPathCallbackClassLimit {
		t.Fatalf("optional callback class=%d, want saturated=%d", saturated, externalPathCallbackClassLimit)
	}

	commit := policyTxUnitCommit(t, prepare, prepared.ack.Generation, prepared.ack.ReservationID)
	final := policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyCommit(commit)
	})
	if final.ack.Phase != proto.PolicyAckPhaseFinal || final.ack.Code != proto.PolicyAckCodeReject {
		t.Fatalf("capacity FINAL=%+v, want reject", final.ack)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("capacity-exhausted admission invoked callback %d times", got)
	}
	diagnostic := fixture.engine.PolicyCallbackDiagnostics()
	var capacityErr *pathDispatchCallbackCapacityError
	if diagnostic.Failures == 0 || !errors.As(diagnostic.LastError, &capacityErr) {
		t.Fatalf("capacity diagnostic=%+v, want typed capacity", diagnostic)
	}

	releaseOptionalCallbackClass(leases)
	eventuallyEngine(t, time.Second, func() bool {
		externalPathCallbacks.Lock()
		defer externalPathCallbacks.Unlock()
		return externalPathCallbacks.classInflight[externalPathCallbackOptional] == 0
	})
	recovery := policyTxUnitPrepare(fixture.engine, 0xd4, 0, fixture.selectorID, fixture.targetB)
	recovered := policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyPrepare(recovery)
	})
	if recovered.ack.Code != proto.PolicyAckCodeAccept || calls.Load() != 1 {
		t.Fatalf("capacity recovery PREPARE=%+v calls=%d", recovered.ack, calls.Load())
	}
}
