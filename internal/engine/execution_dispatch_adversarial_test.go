package engine

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

func TestLeafMobilityOutcomeUnknownRetainsFenceForAdmittedData(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	fixture.clientExecutionDriver.proveCommit.Store(false)
	fixture.clientExecutionDriver.failClosedEntered = make(chan struct{})
	fixture.clientExecutionDriver.failClosedRelease = make(chan struct{})
	var releaseCleanup sync.Once
	release := func() { releaseCleanup.Do(func() { close(fixture.clientExecutionDriver.failClosedRelease) }) }
	t.Cleanup(release)

	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xe1)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := authority.Consume()
	if err != nil {
		t.Fatal(err)
	}

	fixture.client.pathsMu.RLock()
	slot := fixture.client.paths[fixture.clientRef.ID]
	fixture.client.pathsMu.RUnlock()
	if slot == nil {
		t.Fatal("source slot disappeared")
	}
	precheckReached := make(chan struct{})
	continueWrite := make(chan struct{})
	var precheckOnce sync.Once
	slot.dispatchBeforeWritePermit = func() {
		precheckOnce.Do(func() { close(precheckReached) })
		<-continueWrite
	}
	frame := make([]byte, proto.HeaderSize+1)
	if err := (proto.Header{Version: proto.Version, Type: proto.FrameData, Seq: 0xf1}).Encode(frame[:proto.HeaderSize]); err != nil {
		t.Fatal(err)
	}
	frame[len(frame)-1] = 0xa5
	result := make(chan pathDispatchResult, 1)
	if !slot.submitDispatch(pathDispatchJob{frame: frame, firstPublication: true, result: result}) {
		t.Fatal("failed to admit DATA before mobility fence")
	}
	select {
	case <-precheckReached:
	case <-time.After(time.Second):
		t.Fatal("DATA did not reach the first TX fence check")
	}

	if err := permit.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := permit.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	authorizeLeafMobilityPublish(t, permit)
	if err := permit.PublishDriver(context.Background()); !errors.Is(err, leafmobility.ErrIncarnationUnproven) {
		t.Fatalf("PublishDriver = %v, want unproven incarnation", err)
	}
	permit.token.outcomeUnknownSerialized(leafmobility.ErrIncarnationUnproven)
	select {
	case <-fixture.clientExecutionDriver.failClosedEntered:
	case <-time.After(time.Second):
		t.Fatal("outcome-unknown did not start fail-closed cleanup")
	}
	close(continueWrite)
	select {
	case got := <-result:
		if !errors.Is(got.err, ErrPathTXFenced) {
			t.Fatalf("admitted DATA result=%v, want ErrPathTXFenced", got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("admitted DATA did not reach the second TX fence check")
	}
	release()
}

func TestLeafMobilityPrepareDrainsRegisteredProbeWriters(t *testing.T) {
	tests := []struct {
		name  string
		start func(*Engine, *pathSlot)
	}{
		{
			name:  "request",
			start: func(e *Engine, slot *pathSlot) { e.issuePathProbe(slot) },
		},
		{
			name: "reply",
			start: func(e *Engine, slot *pathSlot) {
				e.handlePathProbeRequest(slot, proto.ProbePayload{ID: 31, TS: 37}.Encode())
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
			plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xe2)
			authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
			if err != nil {
				t.Fatal(err)
			}
			permit, err := authority.Consume()
			if err != nil {
				t.Fatal(err)
			}
			fixture.client.pathsMu.RLock()
			slot := fixture.client.paths[fixture.clientRef.ID]
			fixture.client.pathsMu.RUnlock()
			if slot == nil {
				t.Fatal("source slot disappeared")
			}

			entered := make(chan struct{})
			release := make(chan struct{})
			var enteredOnce sync.Once
			var releaseOnce sync.Once
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			slot.probeBeforeWritePermit = func() {
				enteredOnce.Do(func() { close(entered) })
				<-release
			}
			test.start(fixture.client, slot)
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("probe writer did not reach the pre-permit boundary")
			}

			prepared := make(chan error, 1)
			go func() { prepared <- permit.Prepare(context.Background()) }()
			eventuallyEngine(t, time.Second, func() bool { return !slot.txEnabled.Load() })
			select {
			case err := <-prepared:
				releaseOnce.Do(func() { close(release) })
				t.Fatalf("Prepare crossed a registered probe writer: %v", err)
			case <-time.After(50 * time.Millisecond):
			}
			releaseOnce.Do(func() { close(release) })
			select {
			case err := <-prepared:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("Prepare did not continue after the probe writer drained")
			}
			if err := permit.RolledBack(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLeafMobilityFenceCancelsProbeWaitingForWritePermit(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xeb)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := authority.Consume()
	if err != nil {
		t.Fatal(err)
	}
	fixture.client.pathsMu.RLock()
	slot := fixture.client.paths[fixture.clientRef.ID]
	fixture.client.pathsMu.RUnlock()
	if slot == nil {
		t.Fatal("source slot disappeared")
	}

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
	controlsBefore := slot.controlWrites.Load()
	fixture.client.issuePathProbe(slot)
	select {
	case <-atPermit:
	case <-time.After(time.Second):
		t.Fatal("probe writer did not register before waiting for the held write permit")
	}

	fenced := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		fenced <- permit.token.fenceExecutionDispatch(ctx)
	}()
	eventuallyEngine(t, time.Second, func() bool { return !slot.txEnabled.Load() })
	continueProbe()
	select {
	case err := <-fenced:
		if err != nil {
			t.Fatalf("fenceExecutionDispatch remained pinned behind the application write permit: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("fenceExecutionDispatch did not supersede the waiting probe writer")
	}
	if writes := slot.controlWrites.Load(); writes != controlsBefore {
		t.Fatalf("cancelled probe reached the wire: controls=%d->%d", controlsBefore, writes)
	}

	if err := permit.execution.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	permit.token.releaseExecutionDispatch()
	if !slot.txEnabled.Load() {
		t.Fatal("rollback did not reopen TX after the cancelled probe drained")
	}
	slot.probeBeforeWritePermit = nil
	slot.releaseWrite()
	permitHeld = false
	time.Sleep(20 * time.Millisecond)
	if writes := slot.controlWrites.Load(); writes != controlsBefore {
		t.Fatalf("cancelled probe crossed rollback/unfence: controls=%d->%d", controlsBefore, writes)
	}
	permit.token.outcomeUnknownSerialized(leafmobility.ErrAuthorityStale)
}

func TestLeafMobilityUnfencePublishesProbeGenerationFirst(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	fixture.client.pathsMu.RLock()
	slot := fixture.client.paths[fixture.clientRef.ID]
	fixture.client.pathsMu.RUnlock()
	if slot == nil {
		t.Fatal("source slot disappeared")
	}
	originalGeneration := slot.probeEndpointGen.Load()
	slot.probeEvidence.Store(&pathProbeEvidence{
		generation:  pathProbeGenerationForSlot(slot),
		firstIssued: time.Now(),
		issued:      1,
	})
	type unfenceObservation struct {
		generation uint64
		evidence   *pathProbeEvidence
	}
	observed := make(chan unfenceObservation, 1)
	var observeOnce sync.Once
	slot.dispatchBeforeUnfence = func() {
		observeOnce.Do(func() {
			observed <- unfenceObservation{
				generation: slot.probeEndpointGen.Load(),
				evidence:   slot.probeEvidence.Load(),
			}
		})
	}

	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xe3)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := authority.Consume()
	if err != nil {
		t.Fatal(err)
	}
	if err := permit.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	var got unfenceObservation
	select {
	case got = <-observed:
	case <-time.After(time.Second):
		t.Fatal("successful authority never reopened path TX")
	}
	wantGeneration := fixture.clientClaim.Snapshot().Generation
	if wantGeneration <= originalGeneration {
		t.Fatalf("claim generation=%d did not advance from %d", wantGeneration, originalGeneration)
	}
	if got.generation != wantGeneration {
		t.Fatalf("generation at unfence=%d want committed claim generation=%d", got.generation, wantGeneration)
	}
	if got.evidence != nil {
		t.Fatalf("old endpoint probe evidence survived unfence: %+v", *got.evidence)
	}
}

func TestLeafMobilitySuccessfulUnfenceRejectsPreFenceData(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xe4)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := authority.Consume()
	if err != nil {
		t.Fatal(err)
	}
	fixture.client.pathsMu.RLock()
	slot := fixture.client.paths[fixture.clientRef.ID]
	fixture.client.pathsMu.RUnlock()
	if slot == nil {
		t.Fatal("source slot disappeared")
	}

	prePermit := make(chan struct{})
	release := make(chan struct{})
	var prePermitOnce sync.Once
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	slot.dispatchBeforeWritePermit = func() {
		prePermitOnce.Do(func() { close(prePermit) })
		<-release
	}
	frame := make([]byte, proto.HeaderSize+1)
	if err := (proto.Header{Version: proto.Version, Type: proto.FrameData, Seq: 0xe4}).Encode(frame[:proto.HeaderSize]); err != nil {
		t.Fatal(err)
	}
	frame[len(frame)-1] = 0x5a
	result := make(chan pathDispatchResult, 1)
	if !slot.submitDispatch(pathDispatchJob{frame: frame, firstPublication: true, result: result}) {
		t.Fatal("failed to queue pre-fence DATA")
	}
	select {
	case <-prePermit:
	case <-time.After(time.Second):
		t.Fatal("DATA did not reach the pre-permit boundary")
	}
	if err := permit.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slot.txEnabled.Load() {
		t.Fatal("successful mobility did not reopen TX")
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case got := <-result:
		if !errors.Is(got.err, ErrPathTXFenced) {
			t.Fatalf("pre-fence DATA result=%v want ErrPathTXFenced", got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("pre-fence DATA did not finish after mobility")
	}
	slot.dispatchBeforeWritePermit = nil
	if _, err := fixture.client.SendData([]byte("post-fence-data")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := fixture.server.Recv(buf)
	if err != nil || string(buf[:n]) != "post-fence-data" {
		t.Fatalf("post-fence DATA=(%q,%v)", buf[:n], err)
	}
}

func TestLeafMobilityFailClosedReleaseDoesNotUnfence(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	fixture.clientExecutionDriver.proveCommit.Store(false)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xe5)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := authority.Consume()
	if err != nil {
		t.Fatal(err)
	}
	if err := permit.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := permit.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	authorizeLeafMobilityPublish(t, permit)
	if err := permit.PublishDriver(context.Background()); !errors.Is(err, leafmobility.ErrIncarnationUnproven) {
		t.Fatalf("PublishDriver=%v want unproven incarnation", err)
	}
	fixture.client.pathsMu.RLock()
	slot := fixture.client.paths[fixture.clientRef.ID]
	fixture.client.pathsMu.RUnlock()
	if slot == nil {
		t.Fatal("source slot disappeared")
	}
	var unfences atomic.Int64
	slot.dispatchBeforeUnfence = func() { unfences.Add(1) }
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := permit.execution.FailClosed(ctx); err != nil {
		t.Fatal(err)
	}
	permit.forceLocalExecutionClosed()
	if got := unfences.Load(); got != 0 {
		t.Fatalf("fail-closed release attempted %d TX unfence(s)", got)
	}
	if slot.txEnabled.Load() {
		t.Fatal("fail-closed subject TX was reopened")
	}
	permit.token.outcomeUnknownSerialized(leafmobility.ErrIncarnationUnproven)
}

func TestLeafMobilityRollbackRejectsTimedOutPreFenceProbeWriter(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xe6)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := authority.Consume()
	if err != nil {
		t.Fatal(err)
	}
	fixture.client.pathsMu.RLock()
	slot := fixture.client.paths[fixture.clientRef.ID]
	fixture.client.pathsMu.RUnlock()
	if slot == nil {
		t.Fatal("source slot disappeared")
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	var enteredOnce sync.Once
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	slot.probeBeforeWritePermit = func() {
		enteredOnce.Do(func() { close(entered) })
		<-release
	}
	fixture.client.issuePathProbe(slot)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("probe writer did not reach pre-permit boundary")
	}
	executeCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := permit.Execute(executeCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Execute=%v want probe-drain deadline", err)
	}
	if slot.txEnabled.Load() {
		t.Fatal("rollback reopened source TX before the timed-out probe writer exited")
	}
	writesBefore := slot.controlWrites.Load()
	releaseOnce.Do(func() { close(release) })
	drainCtx, drainCancel := context.WithTimeout(context.Background(), time.Second)
	defer drainCancel()
	if err := slot.waitProbeWriters(drainCtx); err != nil {
		t.Fatal(err)
	}
	if writesAfter := slot.controlWrites.Load(); writesAfter != writesBefore {
		t.Fatalf("timed-out pre-fence probe crossed rollback: controls=%d->%d", writesBefore, writesAfter)
	}
	eventuallyEngine(t, time.Second, slot.txEnabled.Load)
}

func TestTXFenceDisablesBeforePublishingEpoch(t *testing.T) {
	local, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = local.Close(); _ = peer.Close() })
	slot := &pathSlot{conn: local, quit: make(chan struct{}), writePermit: newPathWritePermit()}
	slot.txEnabled.Store(true)
	midpoint := make(chan struct{})
	release := make(chan struct{})
	var midpointOnce sync.Once
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	slot.dispatchFenceMidpoint = func() {
		midpointOnce.Do(func() { close(midpoint) })
		<-release
	}
	fenced := make(chan bool, 1)
	go func() { fenced <- slot.tryFenceDispatch() }()
	select {
	case <-midpoint:
	case <-time.After(time.Second):
		t.Fatal("fence did not reach publication midpoint")
	}
	writeResult := make(chan error, 1)
	go func() {
		_, err := slot.writeDispatchedFrame([]byte("must-not-enter-fence-window"))
		writeResult <- err
	}()
	select {
	case err := <-writeResult:
		t.Fatalf("direct permit crossed fence publication lock: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case ok := <-fenced:
		if !ok {
			t.Fatal("fence was not established")
		}
	case <-time.After(time.Second):
		t.Fatal("fence did not finish")
	}
	select {
	case err := <-writeResult:
		if !errors.Is(err, ErrPathTXFenced) {
			t.Fatalf("write at fence midpoint=%v want ErrPathTXFenced", err)
		}
	case <-time.After(time.Second):
		t.Fatal("direct permit did not finish after fence publication")
	}
	select {
	case frame := <-peer.in:
		t.Fatalf("DATA entered wire during fence publication: %x", frame)
	default:
	}
}

func TestDirectDispatchPermitCannotSnapshotFencedEpochAcrossUnfence(t *testing.T) {
	local, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = local.Close(); _ = peer.Close() })
	slot := &pathSlot{conn: local, quit: make(chan struct{}), writePermit: newPathWritePermit()}
	slot.txEnabled.Store(true)
	if !slot.tryFenceDispatch() {
		t.Fatal("failed to establish TX fence")
	}

	snapshotted := make(chan struct{})
	releaseSnapshot := make(chan struct{})
	var snapshotOnce sync.Once
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseSnapshot) }) })
	slot.dispatchFencePermitSnapshot = func() {
		snapshotOnce.Do(func() { close(snapshotted) })
		<-releaseSnapshot
	}
	writeResult := make(chan error, 1)
	go func() {
		_, err := slot.writeDispatchedFrame([]byte("fenced-epoch-data"))
		writeResult <- err
	}()
	select {
	case <-snapshotted:
	case <-time.After(time.Second):
		t.Fatal("direct dispatch did not reach the fence permit snapshot")
	}

	unfenced := make(chan struct{})
	go func() {
		slot.unfenceDispatch()
		close(unfenced)
	}()
	unfencedEarly := false
	select {
	case <-unfenced:
		unfencedEarly = true
	case <-time.After(50 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(releaseSnapshot) })
	select {
	case err := <-writeResult:
		if !errors.Is(err, ErrPathTXFenced) {
			t.Fatalf("direct dispatch=%v want ErrPathTXFenced", err)
		}
	case <-time.After(time.Second):
		t.Fatal("direct dispatch did not leave the fenced permit snapshot")
	}
	select {
	case <-unfenced:
	case <-time.After(time.Second):
		t.Fatal("unfence did not continue after the permit decision")
	}
	if unfencedEarly {
		t.Fatal("unfence crossed an in-progress direct fence permit decision")
	}
	select {
	case frame := <-peer.in:
		t.Fatalf("fenced-epoch DATA reached successor wire: %x", frame)
	default:
	}
}

func TestLeafMobilityRollbackDefersUnfencePastPreWriteProbeWriter(t *testing.T) {
	tests := []struct {
		name  string
		start func(*Engine, *pathSlot)
	}{
		{name: "request", start: func(e *Engine, slot *pathSlot) { e.issuePathProbe(slot) }},
		{name: "reply", start: func(e *Engine, slot *pathSlot) {
			e.handlePathProbeRequest(slot, proto.ProbePayload{ID: 47, TS: 53}.Encode())
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
			plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xe7)
			authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
			if err != nil {
				t.Fatal(err)
			}
			permit, err := authority.Consume()
			if err != nil {
				t.Fatal(err)
			}
			fixture.client.pathsMu.RLock()
			slot := fixture.client.paths[fixture.clientRef.ID]
			fixture.client.pathsMu.RUnlock()
			if slot == nil {
				t.Fatal("source slot disappeared")
			}

			validated := make(chan struct{})
			releaseWriter := make(chan struct{})
			unfenceEntered := make(chan struct{})
			releaseUnfence := make(chan struct{})
			var validatedOnce sync.Once
			var writerReleaseOnce sync.Once
			var unfenceOnce sync.Once
			var unfenceReleaseOnce sync.Once
			t.Cleanup(func() {
				writerReleaseOnce.Do(func() { close(releaseWriter) })
				unfenceReleaseOnce.Do(func() { close(releaseUnfence) })
			})
			slot.probeAfterFinalValidation = func() {
				validatedOnce.Do(func() { close(validated) })
				<-releaseWriter
			}
			slot.dispatchBeforeUnfence = func() {
				unfenceOnce.Do(func() { close(unfenceEntered) })
				<-releaseUnfence
			}
			test.start(fixture.client, slot)
			select {
			case <-validated:
			case <-time.After(time.Second):
				t.Fatal("probe writer did not reach the post-validation boundary")
			}

			fenceCtx, cancelFence := context.WithTimeout(context.Background(), 50*time.Millisecond)
			err = permit.token.fenceExecutionDispatch(fenceCtx)
			cancelFence()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("fenceExecutionDispatch=%v want probe-drain deadline", err)
			}
			if err := permit.execution.Rollback(context.Background()); err != nil {
				t.Fatal(err)
			}
			controlsBefore := slot.controlWrites.Load()
			permit.token.releaseExecutionDispatch()
			select {
			case <-unfenceEntered:
				t.Fatal("rollback unfenced while a post-validation probe writer was still registered")
			case <-time.After(50 * time.Millisecond):
			}
			if slot.txEnabled.Load() {
				t.Fatal("rollback reopened TX before the probe writer physically completed")
			}

			writerReleaseOnce.Do(func() { close(releaseWriter) })
			select {
			case <-unfenceEntered:
			case <-time.After(time.Second):
				t.Fatal("deferred release did not continue after the probe writer completed")
			}
			if controlsAfter := slot.controlWrites.Load(); controlsAfter != controlsBefore {
				t.Fatalf("pre-fence probe crossed rollback: controls=%d->%d", controlsBefore, controlsAfter)
			}
			if slot.txEnabled.Load() {
				t.Fatal("TX reopened before the deferred unfence linearized")
			}
			unfenceReleaseOnce.Do(func() { close(releaseUnfence) })
			eventuallyEngine(t, time.Second, slot.txEnabled.Load)
			permit.token.outcomeUnknownSerialized(leafmobility.ErrAuthorityStale)
		})
	}
}

func TestDeferredProbeReleaseCannotReopenAfterShutdownWins(t *testing.T) {
	tests := []struct {
		name     string
		shutdown func(*Engine)
	}{
		{name: "Close", shutdown: func(e *Engine) { go e.Close() }},
		{name: "BeginGracefulClose", shutdown: func(e *Engine) { e.BeginGracefulClose() }},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
			plan := engineLeafPlan(t, fixture.client, fixture.clientRef, byte(0xe9+index))
			authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
			if err != nil {
				t.Fatal(err)
			}
			permit, err := authority.Consume()
			if err != nil {
				t.Fatal(err)
			}
			fixture.client.pathsMu.RLock()
			slot := fixture.client.paths[fixture.clientRef.ID]
			fixture.client.pathsMu.RUnlock()
			if slot == nil {
				t.Fatal("source slot disappeared")
			}

			validated := make(chan struct{})
			releaseWriter := make(chan struct{})
			reopenAttempted := make(chan struct{}, 1)
			var validatedOnce sync.Once
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(releaseWriter) }) }
			t.Cleanup(release)
			slot.probeAfterFinalValidation = func() {
				validatedOnce.Do(func() { close(validated) })
				<-releaseWriter
			}
			slot.dispatchBeforeUnfence = func() {
				select {
				case reopenAttempted <- struct{}{}:
				default:
				}
			}
			fixture.client.issuePathProbe(slot)
			select {
			case <-validated:
			case <-time.After(time.Second):
				t.Fatal("probe writer did not reach the post-validation physical-write boundary")
			}

			fenceCtx, cancelFence := context.WithTimeout(context.Background(), 50*time.Millisecond)
			err = permit.token.fenceExecutionDispatch(fenceCtx)
			cancelFence()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("fenceExecutionDispatch=%v want probe-drain deadline", err)
			}
			if err := permit.execution.Rollback(context.Background()); err != nil {
				t.Fatal(err)
			}
			permit.token.releaseExecutionDispatch()
			permit.token.dispatchMu.Lock()
			deferred := permit.token.dispatchFenced && permit.token.dispatchReleasePending
			permit.token.dispatchMu.Unlock()
			if !deferred {
				t.Fatal("probe writer did not force a deferred dispatch release")
			}
			if slot.txEnabled.Load() {
				t.Fatal("deferred release reopened TX before shutdown")
			}

			asyncDrained := make(chan struct{})
			go func() {
				fixture.client.leafTx.asyncWG.Wait()
				close(asyncDrained)
			}()
			probeDrained := make(chan struct{})
			go func() {
				slot.probeWriteWG.Wait()
				close(probeDrained)
			}()

			test.shutdown(fixture.client)
			if test.name == "Close" {
				select {
				case <-fixture.client.closed:
				case <-time.After(time.Second):
					release()
					t.Fatal("Close did not publish its terminal boundary")
				}
			} else if !fixture.client.sendClosing.Load() {
				t.Fatal("BeginGracefulClose did not publish the no-reopen boundary")
			}
			if slot.txEnabled.Load() {
				t.Fatal("shutdown boundary reopened fenced TX")
			}
			if test.name == "BeginGracefulClose" {
				// BeginGracefulClose does not terminate an in-flight authority by
				// itself. Resolve this test authority only after the no-reopen
				// boundary wins so its watchdog and deferred release must both drain.
				permit.token.outcomeUnknownSerialized(leafmobility.ErrAuthorityStale)
			}

			release()
			select {
			case <-probeDrained:
			case <-time.After(time.Second):
				t.Fatal("post-validation probe writer did not drain")
			}
			select {
			case <-asyncDrained:
			case <-time.After(time.Second):
				t.Fatal("deferred-release async tracking did not drain")
			}
			select {
			case <-reopenAttempted:
				t.Fatal("deferred release attempted to unfence after shutdown won")
			default:
			}
			if slot.txEnabled.Load() {
				t.Fatal("TX reopened after the deferred probe writer exited")
			}

			if test.name == "BeginGracefulClose" {
				if err := fixture.client.Close(); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-fixture.client.Closed():
			case <-time.After(2 * time.Second):
				t.Fatal("engine shutdown did not fully quiesce")
			}
		})
	}
}

func TestLeafMobilityReleaseLinearizesReopenBeforeClose(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xe8)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := authority.Consume()
	if err != nil {
		t.Fatal(err)
	}
	if err := permit.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.client.pathsMu.RLock()
	slot := fixture.client.paths[fixture.clientRef.ID]
	fixture.client.pathsMu.RUnlock()
	if slot == nil {
		t.Fatal("source slot disappeared")
	}

	reopenEntered := make(chan struct{})
	releaseReopen := make(chan struct{})
	var reopenOnce sync.Once
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseReopen) }) })
	slot.dispatchBeforeUnfence = func() {
		reopenOnce.Do(func() { close(reopenEntered) })
		<-releaseReopen
	}
	rolledBack := make(chan error, 1)
	go func() { rolledBack <- permit.RolledBack(context.Background()) }()
	select {
	case <-reopenEntered:
	case <-time.After(time.Second):
		t.Fatal("rollback release did not reach the reopen boundary")
	}

	closed := make(chan error, 1)
	go func() { closed <- fixture.client.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close crossed the serialized reopen boundary: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if fixture.client.closing.Load() || fixture.client.sendClosing.Load() {
		t.Fatal("Close published closing state before the earlier reopen linearized")
	}

	releaseOnce.Do(func() { close(releaseReopen) })
	select {
	case err := <-rolledBack:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("rollback did not finish after reopen was released")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not finish after serialized reopen")
	}
	if slot.txEnabled.Load() {
		t.Fatal("TX was enabled after Close linearized")
	}
}

func TestLeafMobilityDispatchFenceRejectsQueuedDataBeforeControl(t *testing.T) {
	local, peer := newMemoryPathPair()
	t.Cleanup(func() {
		_ = local.Close()
		_ = peer.Close()
	})
	slot := &pathSlot{
		id: 1, owner: 2, conn: local, quit: make(chan struct{}), writePermit: newPathWritePermit(),
	}
	slot.txEnabled.Store(true)

	// Hold the physical write permit while DATA callers pass the optimistic
	// precheck and queue. The post-acquire check must reject all of them after
	// the mobility fence, leaving the control lane as the only wire writer.
	<-slot.writePermit
	const writers = 64
	start := make(chan struct{})
	ready := make(chan struct{}, writers)
	results := make(chan error, writers)
	for index := 0; index < writers; index++ {
		go func(value byte) {
			ready <- struct{}{}
			<-start
			_, err := slot.writeDispatchedFrame([]byte{value})
			results <- err
		}(byte(index + 1))
	}
	for index := 0; index < writers; index++ {
		<-ready
	}
	close(start)
	time.Sleep(10 * time.Millisecond)
	if !slot.tryFenceDispatch() {
		t.Fatal("failed to acquire mobility dispatch fence")
	}
	slot.releaseWrite()

	control := []byte("terminal-control")
	if _, err := slot.writeFrame(control); err != nil {
		t.Fatalf("control write: %v", err)
	}
	for index := 0; index < writers; index++ {
		if err := <-results; !errors.Is(err, ErrPathTXFenced) {
			t.Fatalf("queued DATA[%d] error=%v want ErrPathTXFenced", index, err)
		}
	}
	select {
	case frame := <-peer.in:
		if !bytes.Equal(frame, control) {
			t.Fatalf("wire frame=%x want control=%x", frame, control)
		}
	default:
		t.Fatal("control frame was not written")
	}
	if len(peer.in) != 0 {
		t.Fatalf("DATA reached wire behind control: queued=%d", len(peer.in))
	}

	slot.unfenceDispatch()
	if _, err := slot.writeDispatchedFrame([]byte("data-after-terminal")); err != nil {
		t.Fatalf("DATA remained fenced after terminal: %v", err)
	}
}

func TestRecursiveDispatchCrossModeTrafficIsNotFlattened(t *testing.T) {
	tests := []struct {
		name     string
		manifest func(*testing.T) (proto.GraphManifest, map[string]proto.TargetID)
		paths    []string
		want     map[string]uint64
	}{
		{
			name: "selector invokes bond child",
			manifest: func(t *testing.T) (proto.GraphManifest, map[string]proto.TargetID) {
				return runtimeGraph(t,
					runtimeNode(proto.GraphNodeKindSelector, "root", "aggregate", "c"),
					runtimeNode(proto.GraphNodeKindBond, "aggregate", "a", "b"),
					runtimeNode(proto.GraphNodeKindPath, "a"),
					runtimeNode(proto.GraphNodeKindPath, "b"),
					runtimeNode(proto.GraphNodeKindPath, "c"),
				)
			},
			paths: []string{"a", "b", "c"},
			want:  map[string]uint64{"a": 2, "b": 2, "c": 0},
		},
		{
			name: "selector invokes race child",
			manifest: func(t *testing.T) (proto.GraphManifest, map[string]proto.TargetID) {
				return runtimeGraph(t,
					runtimeNode(proto.GraphNodeKindSelector, "root", "redundant", "c"),
					runtimeNode(proto.GraphNodeKindRace, "redundant", "a", "b"),
					runtimeNode(proto.GraphNodeKindPath, "a"),
					runtimeNode(proto.GraphNodeKindPath, "b"),
					runtimeNode(proto.GraphNodeKindPath, "c"),
				)
			},
			paths: []string{"a", "b", "c"},
			want:  map[string]uint64{"a": 4, "b": 4, "c": 0},
		},
		{
			name: "bond invokes selector child",
			manifest: func(t *testing.T) (proto.GraphManifest, map[string]proto.TargetID) {
				return runtimeGraph(t,
					runtimeNode(proto.GraphNodeKindBond, "root", "choice", "c"),
					runtimeNode(proto.GraphNodeKindSelector, "choice", "a", "b"),
					runtimeNode(proto.GraphNodeKindPath, "a"),
					runtimeNode(proto.GraphNodeKindPath, "b"),
					runtimeNode(proto.GraphNodeKindPath, "c"),
				)
			},
			paths: []string{"a", "b", "c"},
			want:  map[string]uint64{"a": 2, "b": 0, "c": 2},
		},
		{
			name: "race invokes one bond child per frame",
			manifest: func(t *testing.T) (proto.GraphManifest, map[string]proto.TargetID) {
				return runtimeGraph(t,
					runtimeNode(proto.GraphNodeKindRace, "root", "direct", "aggregate"),
					runtimeNode(proto.GraphNodeKindPath, "direct"),
					runtimeNode(proto.GraphNodeKindBond, "aggregate", "b", "c"),
					runtimeNode(proto.GraphNodeKindPath, "b"),
					runtimeNode(proto.GraphNodeKindPath, "c"),
				)
			},
			paths: []string{"direct", "b", "c"},
			want:  map[string]uint64{"direct": 4, "b": 2, "c": 2},
		},
		{
			name: "bond invokes whole race child",
			manifest: func(t *testing.T) (proto.GraphManifest, map[string]proto.TargetID) {
				return runtimeGraph(t,
					runtimeNode(proto.GraphNodeKindBond, "root", "direct", "redundant"),
					runtimeNode(proto.GraphNodeKindPath, "direct"),
					runtimeNode(proto.GraphNodeKindRace, "redundant", "b", "c"),
					runtimeNode(proto.GraphNodeKindPath, "b"),
					runtimeNode(proto.GraphNodeKindPath, "c"),
				)
			},
			paths: []string{"direct", "b", "c"},
			want:  map[string]uint64{"direct": 2, "b": 2, "c": 2},
		},
		{
			name: "race invokes selector child",
			manifest: func(t *testing.T) (proto.GraphManifest, map[string]proto.TargetID) {
				return runtimeGraph(t,
					runtimeNode(proto.GraphNodeKindRace, "root", "choice", "c"),
					runtimeNode(proto.GraphNodeKindSelector, "choice", "a", "b"),
					runtimeNode(proto.GraphNodeKindPath, "a"),
					runtimeNode(proto.GraphNodeKindPath, "b"),
					runtimeNode(proto.GraphNodeKindPath, "c"),
				)
			},
			paths: []string{"a", "b", "c"},
			want:  map[string]uint64{"a": 4, "b": 0, "c": 4},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest, _ := test.manifest(t)
			client, server, captures := newRecursiveEnginePair(t, manifest, test.paths...)
			client.SetPacketMode()
			server.SetPacketMode()
			for i := 0; i < 4; i++ {
				payload := []byte{byte(i + 1)}
				if err := client.SendPacket(payload); err != nil {
					t.Fatalf("SendPacket(%d): %v", i, err)
				}
				got, err := server.RecvPacket()
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("RecvPacket(%d)=(%x,%v), want %x", i, got, err, payload)
				}
			}
			waitForCapturedFrames(t, captures, test.want)
		})
	}
}

func TestRaceSlowChildCannotBlockFastChild(t *testing.T) {
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindRace, "root", "slow", "fast"),
		runtimeNode(proto.GraphNodeKindPath, "slow"),
		runtimeNode(proto.GraphNodeKindPath, "fast"),
	)
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	configureRecursivePair(t, client, server, manifest)

	slowClient, slowServer := newMemoryPathPair()
	block := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(block) }) }
	t.Cleanup(release)
	blocked := &blockedDispatchPath{PathConn: slowClient, block: block}
	attachRecursivePath(t, client, server, "slow", blocked, slowServer)
	fastClient, fastServer := newMemoryPathPair()
	attachRecursivePath(t, client, server, "fast", fastClient, fastServer)

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := client.SendData([]byte("latency"))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SendData: %v", err)
		}
		if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
			t.Fatalf("fast race child was delayed by slow sibling: %v", elapsed)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("slow race child caused head-of-line blocking")
	}
	buf := make([]byte, 16)
	n, err := server.Recv(buf)
	if err != nil || string(buf[:n]) != "latency" {
		t.Fatalf("server Recv=(%q,%v)", buf[:n], err)
	}
	release()
}

func TestRaceBlockedAndFailedChildrenRespectMigrationBudget(t *testing.T) {
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindRace, "root", "blocked", "failed"),
		runtimeNode(proto.GraphNodeKindPath, "blocked"),
		runtimeNode(proto.GraphNodeKindPath, "failed"),
	)
	limits := Limits{MigrationBudget: 40 * time.Millisecond}.Clamp()
	client := New(SideClient, NewClientFlowID(), limits)
	t.Cleanup(func() { _ = client.Close() })
	if err := client.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := client.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}

	blockedBase, blockedPeer := newMemoryPathPair()
	defer blockedPeer.Close()
	block := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(block) }) }
	t.Cleanup(release)
	blocked := &blockedDispatchPath{PathConn: blockedBase, block: block}
	failedBase, failedPeer := newMemoryPathPair()
	defer failedPeer.Close()
	failed := &failedDispatchPath{PathConn: failedBase}
	blockedSpec := transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "blocked"}}
	failedSpec := transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "failed"}}
	if _, err := client.AttachPath(blocked, blockedSpec); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AttachPath(failed, failedSpec); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	_, err := client.SendData([]byte("budget"))
	elapsed := time.Since(start)
	release()
	if err != ErrMigrationBudgetExceeded {
		t.Fatalf("SendData error=%v want %v", err, ErrMigrationBudgetExceeded)
	}
	if elapsed < limits.MigrationBudget || elapsed > 500*time.Millisecond {
		t.Fatalf("migration budget elapsed=%v want [%v,500ms]", elapsed, limits.MigrationBudget)
	}
}

func TestBondBlockedChildDoesNotHeadOfLineBlockHealthySibling(t *testing.T) {
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindBond, "root", "blocked", "healthy"),
		runtimeNode(proto.GraphNodeKindPath, "blocked"),
		runtimeNode(proto.GraphNodeKindPath, "healthy"),
	)
	flow := NewClientFlowID()
	limits := Limits{MigrationBudget: time.Second}.Clamp()
	client := New(SideClient, flow, limits)
	server := New(SideServer, flow, limits)
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	configureRecursivePair(t, client, server, manifest)

	blockedClient, blockedServer := newMemoryPathPair()
	block := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(block) }) }
	t.Cleanup(release)
	attachRecursivePath(t, client, server, "blocked", &blockedDispatchPath{PathConn: blockedClient, block: block}, blockedServer)
	healthyClient, healthyServer := newMemoryPathPair()
	attachRecursivePath(t, client, server, "healthy", healthyClient, healthyServer)

	start := time.Now()
	if _, err := client.SendData([]byte("bond-fallback")); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if elapsed < minimumDispatchStallWindow || elapsed > 600*time.Millisecond {
		t.Fatalf("bond fallback elapsed=%v, want [%v,600ms]", elapsed, minimumDispatchStallWindow)
	}
	buf := make([]byte, len("bond-fallback"))
	if n, err := server.Recv(buf); err != nil || string(buf[:n]) != "bond-fallback" {
		t.Fatalf("server Recv=(%q,%v)", buf[:n], err)
	}
	if got := client.BondStuckSkips(); got != 1 {
		t.Fatalf("writer-stall quarantine count=%d, want 1", got)
	}
	release()
}

func TestBondAllBlockedChildrenHonorMigrationBudget(t *testing.T) {
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindBond, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	limits := Limits{MigrationBudget: 275 * time.Millisecond}.Clamp()
	e := New(SideClient, NewClientFlowID(), limits)
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}

	blocks := []chan struct{}{make(chan struct{}), make(chan struct{})}
	var releases [2]sync.Once
	for i, name := range []string{"a", "b"} {
		path, peer := newMemoryPathPair()
		t.Cleanup(func() { _ = peer.Close() })
		t.Cleanup(func() { releases[i].Do(func() { close(blocks[i]) }) })
		spec := transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": name}}
		if _, err := e.AttachPath(&blockedDispatchPath{PathConn: path, block: blocks[i]}, spec); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	_, err := e.SendData([]byte("all-blocked"))
	elapsed := time.Since(start)
	for i := range blocks {
		releases[i].Do(func() { close(blocks[i]) })
	}
	if err != ErrMigrationBudgetExceeded {
		t.Fatalf("SendData error=%v, want %v", err, ErrMigrationBudgetExceeded)
	}
	if elapsed < limits.MigrationBudget || elapsed > limits.MigrationBudget+300*time.Millisecond {
		t.Fatalf("all-blocked elapsed=%v, want [%v,%v]", elapsed, limits.MigrationBudget, limits.MigrationBudget+300*time.Millisecond)
	}
}

func TestRecursivePolicySelectionIsOneSequencedBoundary(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	client := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = client.Close() })
	if err := client.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := client.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	captures := make(map[string]*captureDispatchPath, 2)
	for _, name := range []string{"a", "b"} {
		path, peer := newMemoryPathPair()
		t.Cleanup(func() { _ = peer.Close() })
		capture := &captureDispatchPath{PathConn: path}
		captures[name] = capture
		spec := transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": name}}
		if _, err := client.AttachPath(capture, spec); err != nil {
			t.Fatal(err)
		}
	}

	writesDone := make(chan error, 1)
	go func() {
		for i := 0; i < 20; i++ {
			if _, err := client.SendData([]byte{byte(i)}); err != nil {
				writesDone <- err
				return
			}
		}
		writesDone <- nil
	}()
	deadline := time.Now().Add(time.Second)
	for len(captures["a"].dataSequences()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if err := client.SelectLocalTarget(ids["root"], ids["b"], "linearization-test"); err != nil {
		t.Fatal(err)
	}
	if err := <-writesDone; err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if _, err := client.SendData([]byte{byte(i + 20)}); err != nil {
			t.Fatal(err)
		}
	}
	aSeqs := captures["a"].dataSequences()
	bSeqs := captures["b"].dataSequences()
	if len(aSeqs)+len(bSeqs) != 30 || len(aSeqs) == 0 || len(bSeqs) == 0 {
		t.Fatalf("selector route counts a=%v b=%v", aSeqs, bSeqs)
	}
	if aSeqs[len(aSeqs)-1] >= bSeqs[0] {
		t.Fatalf("policy boundary interleaved old and new routes: a=%v b=%v", aSeqs, bSeqs)
	}
}

func TestFlatSelectorFastPathIgnoresObservationalActivePath(t *testing.T) {
	for _, packetized := range []bool{false, true} {
		name := "stream"
		if packetized {
			name = "packet"
		}
		t.Run(name, func(t *testing.T) {
			manifest, ids := runtimeGraph(t,
				runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
				runtimeNode(proto.GraphNodeKindPath, "a"),
				runtimeNode(proto.GraphNodeKindPath, "b"),
			)
			client, server, captures := newRecursiveEnginePair(t, manifest, "a", "b")
			if packetized {
				client.SetPacketMode()
				server.SetPacketMode()
			}

			client.pathsMu.Lock()
			for pathID, slot := range client.paths {
				if slot.localTXTargetID == ids["b"] {
					// activeID is retained for status and migration hooks. Corrupting
					// it must not override the recursive selector's desired leaf A.
					client.activeID = pathID
					break
				}
			}
			client.pathsMu.Unlock()

			if packetized {
				if err := client.SendPacket([]byte("recursive-authority")); err != nil {
					t.Fatal(err)
				}
			} else if _, err := client.SendData([]byte("recursive-authority")); err != nil {
				t.Fatal(err)
			}
			waitForCapturedFrames(t, captures, map[string]uint64{"a": 1, "b": 0})
			if got := captures["b"].dataSequences(); len(got) != 0 {
				t.Fatalf("observational active path overrode selector: b DATA=%v", got)
			}
		})
	}
}

func TestRecursiveDispatchDeepGraphPreservesEveryBoundary(t *testing.T) {
	a := runtimeNode(proto.GraphNodeKindPath, "a")
	b := runtimeNode(proto.GraphNodeKindPath, "b")
	c := runtimeNode(proto.GraphNodeKindPath, "c")
	d := runtimeNode(proto.GraphNodeKindPath, "d")
	e := runtimeNode(proto.GraphNodeKindPath, "e")
	inner := proto.GraphNode{
		ID: proto.DeriveTargetID(proto.GraphNodeKindSelector, "inner"), Kind: proto.GraphNodeKindSelector, Name: "inner",
		Children: []proto.TargetID{a.ID, b.ID},
	}
	aggregate := proto.GraphNode{
		ID: proto.DeriveTargetID(proto.GraphNodeKindBond, "aggregate"), Kind: proto.GraphNodeKindBond, Name: "aggregate",
		Children: []proto.TargetID{inner.ID, c.ID},
	}
	redundant := proto.GraphNode{
		ID: proto.DeriveTargetID(proto.GraphNodeKindRace, "redundant"), Kind: proto.GraphNodeKindRace, Name: "redundant",
		Children: []proto.TargetID{aggregate.ID, d.ID},
	}
	root := proto.GraphNode{
		ID: proto.DeriveTargetID(proto.GraphNodeKindSelector, "root"), Kind: proto.GraphNodeKindSelector, Name: "root",
		Children: []proto.TargetID{redundant.ID, e.ID},
	}
	manifest := proto.GraphManifest{RootID: root.ID, Nodes: []proto.GraphNode{root, redundant, aggregate, inner, a, b, c, d, e}}
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	client, server, captures := newRecursiveEnginePair(t, manifest, "a", "b", "c", "d", "e")
	client.SetPacketMode()
	server.SetPacketMode()
	if err := client.SelectLocalTarget(inner.ID, b.ID, "deep-test"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		payload := []byte{byte(i)}
		if err := client.SendPacket(payload); err != nil {
			t.Fatal(err)
		}
		got, err := server.RecvPacket()
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("RecvPacket=(%x,%v), want %x", got, err, payload)
		}
	}
	want := map[string]uint64{"a": 0, "b": 2, "c": 2, "d": 4, "e": 0}
	waitForCapturedFrames(t, captures, want)
}

type blockedDispatchPath struct {
	transport.PathConn
	block <-chan struct{}
}

type failedDispatchPath struct{ transport.PathConn }

func (p *failedDispatchPath) Write([]byte) (int, error) { return 0, net.ErrClosed }

func (p *blockedDispatchPath) Write(frame []byte) (int, error) {
	select {
	case <-p.block:
		return p.PathConn.Write(frame)
	case <-time.After(5 * time.Second):
		return 0, net.ErrClosed
	}
}

func newRecursiveEnginePair(t *testing.T, manifest proto.GraphManifest, names ...string) (*Engine, *Engine, map[string]*captureDispatchPath) {
	t.Helper()
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	configureRecursivePair(t, client, server, manifest)
	captures := make(map[string]*captureDispatchPath, len(names))
	for _, name := range names {
		clientPath, serverPath := newMemoryPathPair()
		capture := &captureDispatchPath{PathConn: clientPath}
		captures[name] = capture
		attachRecursivePath(t, client, server, name, capture, serverPath)
	}
	return client, server, captures
}

func configureRecursivePair(t *testing.T, client, server *Engine, manifest proto.GraphManifest) {
	t.Helper()
	for _, engine := range []*Engine{client, server} {
		if err := engine.ConfigureLocalGraph(1, manifest); err != nil {
			t.Fatal(err)
		}
		if err := engine.ConfigurePeerGraph(1, manifest); err != nil {
			t.Fatal(err)
		}
	}
}

func attachRecursivePath(t *testing.T, client, server *Engine, name string, clientPath, serverPath transport.PathConn) {
	t.Helper()
	spec := transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": name}}
	if _, err := client.AttachPath(clientPath, spec); err != nil {
		t.Fatalf("attach client %s: %v", name, err)
	}
	if _, err := server.AttachPath(serverPath, spec); err != nil {
		t.Fatalf("attach server %s: %v", name, err)
	}
}

type captureDispatchPath struct {
	transport.PathConn
	mu   sync.Mutex
	seqs []uint64
}

func (p *captureDispatchPath) Write(frame []byte) (int, error) {
	n, err := p.PathConn.Write(frame)
	if err == nil && n == len(frame) && len(frame) >= proto.HeaderSize {
		header, decodeErr := proto.DecodeHeader(frame[:proto.HeaderSize])
		if decodeErr == nil && header.Type == proto.FrameData {
			p.mu.Lock()
			p.seqs = append(p.seqs, header.Seq)
			p.mu.Unlock()
		}
	}
	return n, err
}

func (p *captureDispatchPath) dataSequences() []uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]uint64(nil), p.seqs...)
}

func waitForCapturedFrames(t *testing.T, captures map[string]*captureDispatchPath, want map[string]uint64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		got := make(map[string]uint64, len(captures))
		for name, capture := range captures {
			got[name] = uint64(len(capture.dataSequences()))
		}
		if reflectDispatchCounts(got, want) {
			for name, capture := range captures {
				seqs := capture.dataSequences()
				for i := 1; i < len(seqs); i++ {
					if seqs[i] <= seqs[i-1] {
						t.Fatalf("path %s DATA sequences are not strictly increasing: %v", name, seqs)
					}
				}
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("dispatch counts=%v want=%v", got, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func reflectDispatchCounts(got, want map[string]uint64) bool {
	for name, count := range want {
		if got[name] != count {
			return false
		}
	}
	return true
}
