package engine

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
)

type deferredPolicyReplayFixture struct {
	fixture   *policyTxUnitFixture
	record    *policyReplayRecord
	original  []byte
	duplicate func() error
	clock     *atomic.Int64
	base      time.Time
}

func newDeferredPolicyReplayFixture(
	t *testing.T,
	phase proto.PolicyAckPhase,
	seed byte,
) deferredPolicyReplayFixture {
	t.Helper()
	fixture := newPolicyTxUnitFixture(t)
	fixture.engine.tailReplayInitialDelay = time.Hour
	fixture.engine.tailReplayMaxBackoff = time.Hour
	base := time.Unix(1_710_000_000+int64(seed), 0)
	clock := &atomic.Int64{}
	clock.Store(base.UnixNano())
	fixture.engine.policyReplayNow = func() time.Time {
		return time.Unix(0, clock.Load())
	}

	prepare := policyTxUnitPrepare(fixture.engine, seed, 0, fixture.selectorID, fixture.targetB)
	prepared := policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyPrepare(prepare)
	})
	var (
		record    *policyReplayRecord
		duplicate func() error
	)
	if phase == proto.PolicyAckPhasePrepare {
		fixture.engine.policyStateMu.Lock()
		record = fixture.engine.policyIncoming.prepareReplay
		fixture.engine.policyStateMu.Unlock()
		duplicate = func() error { return fixture.engine.handlePolicyPrepare(prepare) }
	} else {
		fixture.engine.notePeerAck(currentAck(fixture.engine, fixture.engine.sendPublishedNext.Load()))
		commit := policyTxUnitCommit(t, prepare, prepared.ack.Generation, prepared.ack.ReservationID)
		policyTxUnitRequireAck(t, fixture.recorder, func() error {
			return fixture.engine.handlePolicyCommit(commit)
		})
		fixture.engine.policyStateMu.Lock()
		record = fixture.engine.policyCompleted[prepare.TransactionID].finalReplay
		fixture.engine.policyStateMu.Unlock()
		duplicate = func() error { return fixture.engine.handlePolicyCommit(commit) }
	}
	if record == nil {
		t.Fatalf("%s response has no replay owner", policyAckPhaseName(phase))
	}
	fixture.engine.policyReplayMu.Lock()
	original := append([]byte(nil), record.frame...)
	fixture.engine.policyReplayMu.Unlock()
	if len(original) == 0 {
		t.Fatalf("%s replay owner has no immutable frame", policyAckPhaseName(phase))
	}
	fixture.engine.notePeerAck(currentAck(fixture.engine, fixture.engine.sendPublishedNext.Load()))
	return deferredPolicyReplayFixture{
		fixture:   fixture,
		record:    record,
		original:  original,
		duplicate: duplicate,
		clock:     clock,
		base:      base,
	}
}

type manualPolicyReplayWait struct {
	scheduled chan time.Duration
	ready     chan time.Time
	stops     atomic.Uint64
	stopHook  func()
}

func newManualPolicyReplayWait() *manualPolicyReplayWait {
	return &manualPolicyReplayWait{
		scheduled: make(chan time.Duration, 4),
		ready:     make(chan time.Time, 4),
	}
}

func (w *manualPolicyReplayWait) factory(delay time.Duration) policyReplayWait {
	w.scheduled <- delay
	return policyReplayWait{
		ready: w.ready,
		stop: func() bool {
			w.stops.Add(1)
			if w.stopHook != nil {
				w.stopHook()
			}
			return true
		},
	}
}

func installManualPolicyReplayWait(
	t *testing.T,
	e *Engine,
	record *policyReplayRecord,
	w *manualPolicyReplayWait,
) {
	t.Helper()
	e.policyReplayMu.Lock()
	invalid := record.retired || e.policyReplayRecords[record.key] != record
	if !invalid {
		record.deferredWait = w.factory
	}
	e.policyReplayMu.Unlock()
	if invalid {
		t.Fatal("cannot install wait factory on retired replay owner")
	}
}

func installPolicyReplayBeforeCleanup(
	t *testing.T,
	e *Engine,
	record *policyReplayRecord,
	hook func(),
) {
	t.Helper()
	e.policyReplayMu.Lock()
	invalid := record.retired || e.policyReplayRecords[record.key] != record ||
		record.deferredBeforeCleanup != nil
	if !invalid {
		record.deferredBeforeCleanup = hook
	}
	e.policyReplayMu.Unlock()
	if invalid {
		t.Fatal("cannot install cleanup hook on replay owner")
	}
}

func requirePolicyReplayScheduled(t *testing.T, w *manualPolicyReplayWait) time.Duration {
	t.Helper()
	select {
	case delay := <-w.scheduled:
		return delay
	case <-time.After(time.Second):
		t.Fatal("policy replay worker did not schedule its bounded retry")
		return 0
	}
}

func requirePolicyReplayWorker(t *testing.T, e *Engine, record *policyReplayRecord) <-chan struct{} {
	t.Helper()
	e.policyReplayMu.Lock()
	running, done := record.deferredRunning, record.deferredDone
	e.policyReplayMu.Unlock()
	if !running || done == nil {
		t.Fatal("policy replay worker is not running")
	}
	return done
}

func snapshotPolicyReplayRecord(e *Engine, record *policyReplayRecord) (policyReplayRecord, int, int) {
	e.policyReplayMu.Lock()
	defer e.policyReplayMu.Unlock()
	return *record, e.policyReplayCount, e.policyReplayBytes
}

func waitPolicyReplayWorker(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("policy replay worker did not stop")
	}
}

func TestPolicyReplayFinalEarlyDuplicateSchedulesExactRetry(t *testing.T) {
	for i, phase := range []proto.PolicyAckPhase{
		proto.PolicyAckPhasePrepare,
		proto.PolicyAckPhaseFinal,
	} {
		t.Run(policyAckPhaseName(phase), func(t *testing.T) {
			harness := newDeferredPolicyReplayFixture(t, phase, byte(0xe0+i))
			wait := newManualPolicyReplayWait()
			installManualPolicyReplayWait(t, harness.fixture.engine, harness.record, wait)

			beforeCopies := countPolicyTxFixtureFrames(harness.fixture, harness.original)
			beforeOwner := snapshotPolicyControlReplayOwnership(harness.fixture.engine)
			harness.fixture.engine.policyReplayMu.Lock()
			beforeCount := harness.fixture.engine.policyReplayCount
			beforeBytes := harness.fixture.engine.policyReplayBytes
			beforeSeq := harness.record.seq
			beforeDigest := harness.record.digest
			harness.fixture.engine.policyReplayMu.Unlock()
			var dataReplays atomic.Uint64
			harness.fixture.engine.replayQueueForTest = func(replayRequest) {
				dataReplays.Add(1)
			}

			// Treat the first physical response as dropped. This is the last
			// duplicate request: no later caller is allowed to drive replay.
			if err := harness.duplicate(); err != nil {
				t.Fatalf("early duplicate: %v", err)
			}
			done := requirePolicyReplayWorker(t, harness.fixture.engine, harness.record)
			if delay := requirePolicyReplayScheduled(t, wait); delay != policyRetryInterval {
				t.Fatalf("deferred delay=%s want %s", delay, policyRetryInterval)
			}
			if got := countPolicyTxFixtureFrames(harness.fixture, harness.original); got != beforeCopies {
				t.Fatalf("early duplicate bypassed pacing: copies=%d want %d", got, beforeCopies)
			}

			due := harness.base.Add(policyRetryInterval)
			harness.clock.Store(due.UnixNano())
			wait.ready <- due
			eventuallyEngine(t, time.Second, func() bool {
				return countPolicyTxFixtureFrames(harness.fixture, harness.original) == beforeCopies+1
			})
			waitPolicyReplayWorker(t, done)

			if got := countPolicyTxFixtureFrames(harness.fixture, harness.original); got != beforeCopies+1 {
				t.Fatalf("deferred replay copies=%d want %d", got, beforeCopies+1)
			}
			if got := snapshotPolicyControlReplayOwnership(harness.fixture.engine); got != beforeOwner {
				t.Fatalf("deferred replay changed sequenced ownership: got=%+v want=%+v", got, beforeOwner)
			}
			if got := dataReplays.Load(); got != 0 {
				t.Fatalf("deferred policy response minted %d DATA replay requests", got)
			}
			recordState, countState, bytesState := snapshotPolicyReplayRecord(
				harness.fixture.engine, harness.record,
			)
			if recordState.seq != beforeSeq || recordState.digest != beforeDigest ||
				!bytes.Equal(recordState.frame, harness.original) || recordState.inFlight ||
				recordState.deferred || recordState.deferredRunning || recordState.retired ||
				countState != beforeCount || bytesState != beforeBytes {
				t.Fatalf("deferred replay changed immutable owner or credit: record=%+v count=%d bytes=%d",
					recordState, countState, bytesState)
			}
			if wait.stops.Load() != 1 {
				t.Fatalf("deferred timer stops=%d want 1", wait.stops.Load())
			}
		})
	}
}

func TestPolicyReplayDuplicatesDuringInflightCoalesceOneFollowup(t *testing.T) {
	harness := newDeferredPolicyReplayFixture(t, proto.PolicyAckPhasePrepare, 0xe7)
	wait := newManualPolicyReplayWait()
	installManualPolicyReplayWait(t, harness.fixture.engine, harness.record, wait)
	firstTry := harness.base.Add(policyRetryInterval)
	harness.clock.Store(firstTry.UnixNano())
	beforeCopies := countPolicyTxFixtureFrames(harness.fixture, harness.original)

	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	var writes atomic.Uint64
	var concurrent, maxConcurrent atomic.Int64
	blockReplay := func(frame []byte) {
		if !bytes.Equal(frame, harness.original) {
			return
		}
		active := concurrent.Add(1)
		for {
			prior := maxConcurrent.Load()
			if active <= prior || maxConcurrent.CompareAndSwap(prior, active) {
				break
			}
		}
		if writes.Add(1) == 1 {
			close(entered)
			<-release
		}
		concurrent.Add(-1)
	}
	harness.fixture.handleA.SetBeforeWrite(blockReplay)
	harness.fixture.handleB.SetBeforeWrite(blockReplay)
	var dataReplays atomic.Uint64
	harness.fixture.engine.replayQueueForTest = func(replayRequest) { dataReplays.Add(1) }

	firstDone := make(chan error, 1)
	go func() { firstDone <- harness.duplicate() }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first cached replay did not enter the physical writer")
	}
	for i := 0; i < 64; i++ {
		if err := harness.duplicate(); err != nil {
			t.Fatalf("in-flight duplicate %d: %v", i, err)
		}
	}
	done := requirePolicyReplayWorker(t, harness.fixture.engine, harness.record)
	select {
	case delay := <-wait.scheduled:
		t.Fatalf("follow-up timer started before in-flight replay finished: %s", delay)
	default:
	}

	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatalf("first cached replay: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("first cached replay did not finish")
	}
	if delay := requirePolicyReplayScheduled(t, wait); delay != policyRetryInterval {
		t.Fatalf("follow-up delay=%s want %s", delay, policyRetryInterval)
	}
	eventuallyEngine(t, time.Second, func() bool {
		return countPolicyTxFixtureFrames(harness.fixture, harness.original) == beforeCopies+1
	})

	secondTry := firstTry.Add(policyRetryInterval)
	harness.clock.Store(secondTry.UnixNano())
	wait.ready <- secondTry
	eventuallyEngine(t, time.Second, func() bool {
		return countPolicyTxFixtureFrames(harness.fixture, harness.original) == beforeCopies+2
	})
	waitPolicyReplayWorker(t, done)
	if got := writes.Load(); got != 2 {
		t.Fatalf("physical cached response writes=%d want 2", got)
	}
	if got := maxConcurrent.Load(); got != 1 {
		t.Fatalf("concurrent cached response writes=%d want 1", got)
	}
	if got := dataReplays.Load(); got != 0 {
		t.Fatalf("coalesced policy responses minted %d DATA replay requests", got)
	}
	select {
	case delay := <-wait.scheduled:
		t.Fatalf("duplicate burst scheduled an extra retry: %s", delay)
	default:
	}
}

func TestPolicyReplayLastDuplicateBeforeWorkerCleanupIsReplayed(t *testing.T) {
	for i, phase := range []proto.PolicyAckPhase{
		proto.PolicyAckPhasePrepare,
		proto.PolicyAckPhaseFinal,
	} {
		t.Run(policyAckPhaseName(phase), func(t *testing.T) {
			harness := newDeferredPolicyReplayFixture(t, phase, byte(0xea+i))
			wait := newManualPolicyReplayWait()
			installManualPolicyReplayWait(t, harness.fixture.engine, harness.record, wait)

			exitDecided := make(chan struct{})
			allowCleanup := make(chan struct{})
			var allowCleanupOnce sync.Once
			t.Cleanup(func() { allowCleanupOnce.Do(func() { close(allowCleanup) }) })
			installPolicyReplayBeforeCleanup(t, harness.fixture.engine, harness.record, func() {
				close(exitDecided)
				<-allowCleanup
			})

			beforeCopies := countPolicyTxFixtureFrames(harness.fixture, harness.original)
			beforeOwner := snapshotPolicyControlReplayOwnership(harness.fixture.engine)
			harness.fixture.engine.policyReplayMu.Lock()
			beforeCount := harness.fixture.engine.policyReplayCount
			beforeBytes := harness.fixture.engine.policyReplayBytes
			beforeSeq := harness.record.seq
			beforeDigest := harness.record.digest
			harness.fixture.engine.policyReplayMu.Unlock()
			var dataReplays atomic.Uint64
			harness.fixture.engine.replayQueueForTest = func(replayRequest) {
				dataReplays.Add(1)
			}

			if err := harness.duplicate(); err != nil {
				t.Fatalf("initial early duplicate: %v", err)
			}
			done := requirePolicyReplayWorker(t, harness.fixture.engine, harness.record)
			if delay := requirePolicyReplayScheduled(t, wait); delay != policyRetryInterval {
				t.Fatalf("initial deferred delay=%s want %s", delay, policyRetryInterval)
			}
			firstDue := harness.base.Add(policyRetryInterval)
			harness.clock.Store(firstDue.UnixNano())
			wait.ready <- firstDue
			eventuallyEngine(t, time.Second, func() bool {
				return countPolicyTxFixtureFrames(harness.fixture, harness.original) == beforeCopies+1
			})
			select {
			case <-exitDecided:
			case <-time.After(time.Second):
				t.Fatal("policy replay worker did not reach its pre-cleanup exit point")
			}

			// This is the final duplicate. The worker has already decided to exit,
			// and no later request is available to restart a lost deferred replay.
			if err := harness.duplicate(); err != nil {
				t.Fatalf("last early duplicate: %v", err)
			}
			if currentDone := requirePolicyReplayWorker(t, harness.fixture.engine, harness.record); currentDone != done {
				t.Fatal("last duplicate replaced the single deferred replay worker")
			}
			allowCleanupOnce.Do(func() { close(allowCleanup) })

			if delay := requirePolicyReplayScheduled(t, wait); delay != policyRetryInterval {
				t.Fatalf("last deferred delay=%s want %s", delay, policyRetryInterval)
			}
			if currentDone := requirePolicyReplayWorker(t, harness.fixture.engine, harness.record); currentDone != done {
				t.Fatal("last duplicate restarted rather than retaining the single deferred replay worker")
			}
			select {
			case <-done:
				t.Fatal("policy replay worker exited with the last duplicate still deferred")
			default:
			}
			if got := countPolicyTxFixtureFrames(harness.fixture, harness.original); got != beforeCopies+1 {
				t.Fatalf("last duplicate bypassed pacing: copies=%d want %d", got, beforeCopies+1)
			}

			secondDue := firstDue.Add(policyRetryInterval)
			harness.clock.Store(secondDue.UnixNano())
			wait.ready <- secondDue
			eventuallyEngine(t, time.Second, func() bool {
				return countPolicyTxFixtureFrames(harness.fixture, harness.original) == beforeCopies+2
			})
			waitPolicyReplayWorker(t, done)

			if got := countPolicyTxFixtureFrames(harness.fixture, harness.original); got != beforeCopies+2 {
				t.Fatalf("last deferred replay copies=%d want %d", got, beforeCopies+2)
			}
			if got := snapshotPolicyControlReplayOwnership(harness.fixture.engine); got != beforeOwner {
				t.Fatalf("last deferred replay changed sequenced ownership: got=%+v want=%+v", got, beforeOwner)
			}
			if got := dataReplays.Load(); got != 0 {
				t.Fatalf("last deferred policy response minted %d DATA replay requests", got)
			}
			recordState, countState, bytesState := snapshotPolicyReplayRecord(
				harness.fixture.engine, harness.record,
			)
			if recordState.seq != beforeSeq || recordState.digest != beforeDigest ||
				!bytes.Equal(recordState.frame, harness.original) || recordState.inFlight ||
				recordState.deferred || recordState.deferredRunning || recordState.retired ||
				countState != beforeCount || bytesState != beforeBytes {
				t.Fatalf("last deferred replay changed immutable owner or credit: record=%+v count=%d bytes=%d",
					recordState, countState, bytesState)
			}
			if wait.stops.Load() != 2 {
				t.Fatalf("deferred timer stops=%d want 2", wait.stops.Load())
			}
			select {
			case delay := <-wait.scheduled:
				t.Fatalf("last duplicate scheduled an extra retry: %s", delay)
			default:
			}
		})
	}
}

func TestPolicyReplayEvictionCancelsDeferredRetryAndReleasesCredit(t *testing.T) {
	harness := newDeferredPolicyReplayFixture(t, proto.PolicyAckPhasePrepare, 0xe8)
	wait := newManualPolicyReplayWait()
	stopEntered := make(chan struct{})
	stopRelease := make(chan struct{})
	var stopEnteredOnce, stopReleaseOnce sync.Once
	wait.stopHook = func() {
		stopEnteredOnce.Do(func() { close(stopEntered) })
		<-stopRelease
	}
	t.Cleanup(func() { stopReleaseOnce.Do(func() { close(stopRelease) }) })
	installManualPolicyReplayWait(t, harness.fixture.engine, harness.record, wait)
	beforeCopies := countPolicyTxFixtureFrames(harness.fixture, harness.original)
	var dataReplays atomic.Uint64
	harness.fixture.engine.replayQueueForTest = func(replayRequest) { dataReplays.Add(1) }

	if err := harness.duplicate(); err != nil {
		t.Fatalf("early duplicate: %v", err)
	}
	done := requirePolicyReplayWorker(t, harness.fixture.engine, harness.record)
	requirePolicyReplayScheduled(t, wait)
	harness.fixture.engine.retirePolicyReplayRecord(harness.record)
	select {
	case <-stopEntered:
	case <-time.After(time.Second):
		t.Fatal("evicted replay worker did not enter timer cleanup")
	}
	recordState, countState, bytesState := snapshotPolicyReplayRecord(
		harness.fixture.engine, harness.record,
	)
	if recordState.released || !recordState.deferredRunning ||
		countState != 1 || bytesState != recordState.reserved {
		t.Fatalf("eviction released credit while worker retained frame: record=%+v count=%d bytes=%d",
			recordState, countState, bytesState)
	}
	stopReleaseOnce.Do(func() { close(stopRelease) })
	waitPolicyReplayWorker(t, done)
	wait.ready <- harness.base.Add(policyRetryInterval)

	if got := countPolicyTxFixtureFrames(harness.fixture, harness.original); got != beforeCopies {
		t.Fatalf("evicted replay owner emitted a frame: copies=%d want %d", got, beforeCopies)
	}
	if got := dataReplays.Load(); got != 0 {
		t.Fatalf("evicted replay owner minted %d DATA replay requests", got)
	}
	recordState, countState, bytesState = snapshotPolicyReplayRecord(
		harness.fixture.engine, harness.record,
	)
	if !recordState.retired || !recordState.released || recordState.inFlight ||
		recordState.deferred || recordState.deferredRunning || countState != 0 || bytesState != 0 {
		t.Fatalf("evicted replay credit/state=%+v count=%d bytes=%d",
			recordState, countState, bytesState)
	}
}

func TestPolicyReplayCloseCancelsDeferredRetryAndQuiescesWorker(t *testing.T) {
	harness := newDeferredPolicyReplayFixture(t, proto.PolicyAckPhaseFinal, 0xe9)
	wait := newManualPolicyReplayWait()
	stopEntered := make(chan struct{})
	stopRelease := make(chan struct{})
	var stopEnteredOnce, stopReleaseOnce sync.Once
	wait.stopHook = func() {
		stopEnteredOnce.Do(func() { close(stopEntered) })
		<-stopRelease
	}
	t.Cleanup(func() { stopReleaseOnce.Do(func() { close(stopRelease) }) })
	installManualPolicyReplayWait(t, harness.fixture.engine, harness.record, wait)
	beforeCopies := countPolicyTxFixtureFrames(harness.fixture, harness.original)
	var dataReplays atomic.Uint64
	harness.fixture.engine.replayQueueForTest = func(replayRequest) { dataReplays.Add(1) }

	if err := harness.duplicate(); err != nil {
		t.Fatalf("early duplicate: %v", err)
	}
	done := requirePolicyReplayWorker(t, harness.fixture.engine, harness.record)
	requirePolicyReplayScheduled(t, wait)
	closeDone := make(chan error, 1)
	go func() { closeDone <- harness.fixture.engine.Close() }()
	select {
	case <-stopEntered:
	case <-time.After(time.Second):
		t.Fatal("closed replay worker did not enter timer cleanup")
	}
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned before replay worker released frame custody: %v", err)
	default:
	}
	recordState, _, _ := snapshotPolicyReplayRecord(harness.fixture.engine, harness.record)
	if recordState.released || !recordState.deferredRunning {
		t.Fatalf("Close released credit while worker retained frame: %+v", recordState)
	}
	stopReleaseOnce.Do(func() { close(stopRelease) })
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not quiesce the deferred policy replay worker")
	}
	waitPolicyReplayWorker(t, done)
	wait.ready <- harness.base.Add(policyRetryInterval)

	if got := countPolicyTxFixtureFrames(harness.fixture, harness.original); got != beforeCopies {
		t.Fatalf("closed replay owner emitted a frame: copies=%d want %d", got, beforeCopies)
	}
	if got := dataReplays.Load(); got != 0 {
		t.Fatalf("closed replay owner minted %d DATA replay requests", got)
	}
	recordState, countState, bytesState := snapshotPolicyReplayRecord(
		harness.fixture.engine, harness.record,
	)
	if !recordState.retired || !recordState.released || recordState.inFlight ||
		recordState.deferred || recordState.deferredRunning || countState != 0 || bytesState != 0 {
		t.Fatalf("closed replay credit/state=%+v count=%d bytes=%d",
			recordState, countState, bytesState)
	}
}
