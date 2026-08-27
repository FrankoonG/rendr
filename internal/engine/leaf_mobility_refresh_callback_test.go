package engine

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/transport"
)

type abnormalLeafMobilityRefreshPath struct {
	transport.PathConn

	mode            string
	cancelMode      string
	claim           *leafmobility.Claim
	mu              sync.Mutex
	callback        func(leafmobility.RefreshEvidence)
	cancelCalls     atomic.Int32
	closeCalls      atomic.Int32
	cancelOnce      sync.Once
	cancelEnter     chan struct{}
	cancelBlock     chan struct{}
	cancelExit      chan struct{}
	closeEnter      chan struct{}
	subscribeEnter  chan struct{}
	subscribeBlock  chan struct{}
	latePublishDone chan struct{}
	closeOnce       sync.Once
}

func newAdmittedLeafMobilityRefreshTestOwner(
	callback func(leafmobility.RefreshEvidence),
) *leafMobilityRefreshSubscriptionOwner {
	owner := newLeafMobilityRefreshSubscriptionOwner(nil, callback)
	var generation atomic.Uint64
	owner.validateEvidence = func(leafmobility.RefreshEvidence) (leafmobility.RefreshSnapshot, error) {
		return leafmobility.RefreshSnapshot{Generation: generation.Add(1)}, nil
	}
	return owner
}

func invokeLeafMobilityRefreshSubscribe(
	source leafmobility.RefreshSource,
	ctx context.Context,
	callback func(leafmobility.RefreshEvidence),
) (func(), error) {
	callbackAuthority := &externalPathCallbackOwner{}
	cancellation, err := invokeLeafMobilityRefreshSubscribeOwned(
		source, ctx, newAdmittedLeafMobilityRefreshTestOwner(callback), callbackAuthority,
	)
	if err != nil {
		return nil, err
	}
	return func() {
		cancelCtx, stop := context.WithTimeout(context.Background(), externalPathValueCallbackTimeout)
		defer stop()
		_ = cancellation.run(cancelCtx)
	}, nil
}

func (path *abnormalLeafMobilityRefreshPath) setLeafMobilityTestClaim(claim *leafmobility.Claim) {
	path.claim = claim
}

func (path *abnormalLeafMobilityRefreshPath) Close() error {
	path.closeCalls.Add(1)
	if path.closeEnter != nil {
		path.closeOnce.Do(func() { close(path.closeEnter) })
	}
	if path.PathConn == nil {
		return nil
	}
	return path.PathConn.Close()
}

func (path *abnormalLeafMobilityRefreshPath) SubscribeLeafMobilityRefresh(
	ctx context.Context,
	callback func(leafmobility.RefreshEvidence),
) (func(), error) {
	switch path.mode {
	case "subscribe-panic":
		panic("refresh subscribe panic")
	case "subscribe-goexit":
		runtime.Goexit()
	case "subscribe-ignore-context":
		path.mu.Lock()
		path.callback = callback
		path.mu.Unlock()
		path.cancelOnce.Do(func() { close(path.subscribeEnter) })
		<-path.subscribeBlock
		if path.claim != nil {
			emitter, err := leafmobility.NewRefreshEmitter(path.claim)
			if err == nil {
				evidence, observeErr := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
				if observeErr == nil {
					callback(evidence)
				}
			}
		}
		if path.latePublishDone != nil {
			close(path.latePublishDone)
		}
	case "subscribe-wait-context":
		path.cancelOnce.Do(func() { close(path.subscribeEnter) })
		<-ctx.Done()
		return nil, context.Cause(ctx)
	}
	path.mu.Lock()
	path.callback = callback
	path.mu.Unlock()
	return func() {
		path.cancelCalls.Add(1)
		path.mu.Lock()
		path.callback = nil
		path.mu.Unlock()
		cancelMode := path.cancelMode
		if cancelMode == "" {
			cancelMode = path.mode
		}
		switch cancelMode {
		case "cancel-panic":
			panic("refresh cancel panic")
		case "cancel-goexit":
			runtime.Goexit()
		case "cancel-block":
			path.cancelOnce.Do(func() { close(path.cancelEnter) })
			<-path.cancelBlock
		}
		if path.cancelExit != nil {
			close(path.cancelExit)
		}
	}, nil
}

func TestLeafMobilityRefreshSubscribeIgnoringContextIsBoundedAndLateResultIsCleaned(t *testing.T) {
	for _, cancelMode := range []string{"", "cancel-panic", "cancel-goexit"} {
		name := cancelMode
		if name == "" {
			name = "normal-cancel"
		}
		t.Run(name, func(t *testing.T) {
			var source *abnormalLeafMobilityRefreshPath
			started := time.Now()
			fixture := newLeafMobilityEngineFixtureWithAllWrappers(
				t, leafmobility.Resource{}, leafmobility.Resource{},
				func(path *memoryPathConn) transport.PathConn {
					source = &abnormalLeafMobilityRefreshPath{
						PathConn: path, mode: "subscribe-ignore-context", cancelMode: cancelMode,
						subscribeEnter: make(chan struct{}), subscribeBlock: make(chan struct{}),
						latePublishDone: make(chan struct{}),
					}
					return source
				}, nil, nil, nil,
			)
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(source.subscribeBlock) }) }
			t.Cleanup(release)
			if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
				t.Fatalf("context-ignoring subscription blocked path attachment for %s", elapsed)
			}
			select {
			case <-source.subscribeEnter:
			default:
				t.Fatal("context-ignoring subscription stimulus did not enter")
			}
			status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
			if !ok || status.Phase != LeafMobilityInitiatorSubscriptionUnavailable ||
				!strings.Contains(status.Error, leafMobilityRefreshSubscribeOp) {
				t.Fatalf("bounded subscription status=%+v present=%t", status, ok)
			}
			fixture.client.pathsMu.RLock()
			slot := fixture.client.paths[fixture.clientRef.ID]
			fixture.client.pathsMu.RUnlock()
			if slot == nil {
				t.Fatal("bounded subscription failure removed the generic path")
			}
			actualSource, ok := slot.conn.(leafmobility.RefreshSource)
			if !ok {
				t.Fatal("attached path lost its refresh source wrapper")
			}

			secondCtx, stopSecond := context.WithTimeout(context.Background(), time.Second)
			_, secondErr := invokeLeafMobilityRefreshSubscribe(actualSource, secondCtx, func(leafmobility.RefreshEvidence) {})
			stopSecond()
			var busyErr *pathDispatchCallbackBusyError
			if !errors.As(secondErr, &busyErr) || busyErr.operation != leafMobilityRefreshSubscribeOp {
				t.Fatalf("second subscription error=%v want typed per-source busy", secondErr)
			}

			release()
			select {
			case <-source.latePublishDone:
			case <-time.After(time.Second):
				t.Fatal("late subscription result did not return")
			}
			eventuallyEngine(t, time.Second, func() bool { return source.cancelCalls.Load() == 1 })
			if cancelMode != "" {
				eventuallyEngine(t, time.Second, func() bool {
					err := fixture.client.teardownError()
					if cancelMode == "cancel-panic" {
						var panicErr *pathDispatchCallbackPanicError
						return errors.As(err, &panicErr) && panicErr.operation == leafMobilityRefreshCancelOp
					}
					var goexitErr *pathDispatchCallbackGoexitError
					return errors.As(err, &goexitErr) && goexitErr.operation == leafMobilityRefreshCancelOp
				})
			}
			status, ok = fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
			if !ok || status.Phase != LeafMobilityInitiatorSubscriptionUnavailable {
				t.Fatalf("late evidence crossed revoked ownership: status=%+v present=%t", status, ok)
			}
			if source.publish(leafmobility.RefreshEvidence{}) {
				t.Fatal("late subscription retained an admitted callback")
			}
			eventuallyEngine(t, time.Second, func() bool {
				return !externalPathCallbackInFlight(leafMobilityRefreshSubscribeOp, actualSource)
			})
		})
	}
	t.Run("revoke is bounded while an admitted callback drains", func(t *testing.T) {
		entered := make(chan struct{})
		release := make(chan struct{})
		var calls atomic.Int32
		owner := newAdmittedLeafMobilityRefreshTestOwner(func(leafmobility.RefreshEvidence) {
			calls.Add(1)
			close(entered)
			<-release
		})
		if err := owner.bindCallbackAuthority(&externalPathCallbackOwner{}); err != nil {
			t.Fatal(err)
		}
		published := make(chan struct{})
		go func() {
			owner.publish(leafmobility.RefreshEvidence{})
			close(published)
		}()
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("publication did not enter the admitted callback")
		}
		revoked := make(chan struct{})
		go func() {
			owner.revoke()
			close(revoked)
		}()
		select {
		case <-revoked:
		case <-time.After(time.Second):
			t.Fatal("revoke waited for an already admitted callback")
		}
		owner.publish(leafmobility.RefreshEvidence{})
		close(release)
		select {
		case <-published:
		case <-time.After(time.Second):
			t.Fatal("admitted publication did not finish")
		}
		if got := calls.Load(); got != 1 {
			t.Fatalf("post-revoke callback calls=%d want=1", got)
		}
	})
	t.Run("retirement waits for exact-generation subscription setup", func(t *testing.T) {
		var source *abnormalLeafMobilityRefreshPath
		var healthy *observedClosePath
		fixture := newLeafMobilityEngineFixtureWithAllWrappers(
			t, leafmobility.Resource{}, leafmobility.Resource{},
			func(path *memoryPathConn) transport.PathConn {
				source = &abnormalLeafMobilityRefreshPath{
					PathConn: path, mode: "subscribe-ignore-context",
					subscribeEnter: make(chan struct{}), subscribeBlock: make(chan struct{}),
					latePublishDone: make(chan struct{}), closeEnter: make(chan struct{}),
				}
				return source
			}, nil,
			func(path *memoryPathConn) transport.PathConn {
				healthy = &observedClosePath{PathConn: path}
				return healthy
			}, nil,
		)
		var releaseOnce sync.Once
		release := func() { releaseOnce.Do(func() { close(source.subscribeBlock) }) }
		permits := saturateExternalPathRetirementCapacity(t)
		t.Cleanup(func() {
			release()
			releaseExternalPathRetirementPermits(permits)
		})

		select {
		case <-source.subscribeEnter:
		default:
			t.Fatal("blocked subscription setup did not enter")
		}
		fixture.client.pathsMu.RLock()
		slot := fixture.client.paths[fixture.clientRef.ID]
		fixture.client.pathsMu.RUnlock()
		if slot == nil {
			t.Fatal("subscription source path is missing")
		}
		retirePathWithoutPeerNotification(
			t, fixture.client, fixture.clientRef, errors.New("retire blocked subscription setup"),
		)
		select {
		case <-source.closeEnter:
			t.Fatal("carrier closed while exact-generation subscription setup was still running")
		case <-time.After(2 * externalPathValueCallbackTimeout):
		}
		assertExternalPathRetirementCapacityExhausted(t)
		if _, present := fixture.client.PathRef(fixture.clientControlRef.ID); !present || healthy.closed.Load() {
			t.Fatal("retiring blocked path A disturbed healthy path B")
		}
		_, lateErr := invokeLeafMobilityRefreshSubscribeOwned(
			source, context.Background(), newLeafMobilityRefreshSubscriptionOwner(nil, nil), slot.callbackAuthority,
		)
		var stateErr *externalPathDurableCallbackStateError
		if !errors.As(lateErr, &stateErr) || stateErr.action != "invoke after exact-generation retirement" {
			t.Fatalf("post-retirement subscription error=%v want exact-generation rejection", lateErr)
		}

		release()
		select {
		case <-source.latePublishDone:
		case <-time.After(time.Second):
			t.Fatal("released subscription setup did not return")
		}
		select {
		case <-source.closeEnter:
		case <-time.After(time.Second):
			t.Fatal("carrier close did not follow subscription setup completion")
		}
		eventuallyEngine(t, time.Second, func() bool {
			return source.closeCalls.Load() == 1 && !slot.retirementPermit.active.Load()
		})
		permit, err := externalPathRetirements.reserve()
		if err != nil {
			t.Fatalf("retirement capacity did not recover after setup completion: %v", err)
		}
		permit.release()
		if _, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef); ok {
			t.Fatal("retired subscription setup published late initiator status")
		}
		fixture.client.leafRefreshMu.Lock()
		_, pending := fixture.client.leafRefreshPending[fixture.clientRef]
		_, status := fixture.client.leafRefreshStatus[fixture.clientRef]
		fixture.client.leafRefreshMu.Unlock()
		if pending || status {
			t.Fatalf("retired subscription retained pending/status=%t/%t", pending, status)
		}
	})
	t.Run("retirement waits for exact-generation subscription cancellation", func(t *testing.T) {
		var source *abnormalLeafMobilityRefreshPath
		var healthy *observedClosePath
		fixture := newLeafMobilityEngineFixtureWithAllWrappers(
			t, leafmobility.Resource{}, leafmobility.Resource{},
			func(path *memoryPathConn) transport.PathConn {
				source = &abnormalLeafMobilityRefreshPath{
					PathConn: path, mode: "cancel-block",
					cancelEnter: make(chan struct{}), cancelBlock: make(chan struct{}),
					closeEnter: make(chan struct{}),
				}
				return source
			}, nil,
			func(path *memoryPathConn) transport.PathConn {
				healthy = &observedClosePath{PathConn: path}
				return healthy
			}, nil,
		)
		var releaseOnce sync.Once
		release := func() { releaseOnce.Do(func() { close(source.cancelBlock) }) }
		permits := saturateExternalPathRetirementCapacity(t)
		t.Cleanup(func() {
			release()
			releaseExternalPathRetirementPermits(permits)
		})

		fixture.client.pathsMu.RLock()
		slot := fixture.client.paths[fixture.clientRef.ID]
		fixture.client.pathsMu.RUnlock()
		if slot == nil {
			t.Fatal("subscription source path is missing")
		}
		retirePathWithoutPeerNotification(
			t, fixture.client, fixture.clientRef, errors.New("retire blocked subscription cancellation"),
		)
		select {
		case <-source.cancelEnter:
		case <-time.After(time.Second):
			t.Fatal("subscription cancellation did not enter")
		}
		select {
		case <-source.closeEnter:
			t.Fatal("carrier closed while exact-generation cancellation was still running")
		case <-time.After(2 * externalPathValueCallbackTimeout):
		}
		assertExternalPathRetirementCapacityExhausted(t)
		if _, present := fixture.client.PathRef(fixture.clientControlRef.ID); !present || healthy.closed.Load() {
			t.Fatal("retiring blocked path A disturbed healthy path B")
		}
		_, lateErr := invokeLeafMobilityRefreshSubscribeOwned(
			source, context.Background(), newLeafMobilityRefreshSubscriptionOwner(nil, nil), slot.callbackAuthority,
		)
		var stateErr *externalPathDurableCallbackStateError
		if !errors.As(lateErr, &stateErr) || stateErr.action != "invoke after exact-generation retirement" {
			t.Fatalf("post-retirement subscription error=%v want exact-generation rejection", lateErr)
		}
		if source.publish(leafmobility.RefreshEvidence{}) {
			t.Fatal("retired subscription cancellation retained publication authority")
		}
		if _, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef); ok {
			t.Fatal("retired subscription cancellation retained initiator status")
		}

		release()
		select {
		case <-source.closeEnter:
		case <-time.After(time.Second):
			t.Fatal("carrier close did not follow subscription cancellation completion")
		}
		eventuallyEngine(t, time.Second, func() bool {
			return source.closeCalls.Load() == 1 && !slot.retirementPermit.active.Load()
		})
		permit, err := externalPathRetirements.reserve()
		if err != nil {
			t.Fatalf("retirement capacity did not recover after cancellation completion: %v", err)
		}
		permit.release()
		fixture.client.leafRefreshMu.Lock()
		_, pending := fixture.client.leafRefreshPending[fixture.clientRef]
		_, status := fixture.client.leafRefreshStatus[fixture.clientRef]
		fixture.client.leafRefreshMu.Unlock()
		if pending || status || source.closeCalls.Load() != 1 {
			t.Fatalf("retired cancellation pending/status/close=%t/%t/%d", pending, status, source.closeCalls.Load())
		}
	})
}

func saturateExternalPathRetirementCapacity(t *testing.T) []*externalPathRetirementPermit {
	t.Helper()
	permits := make([]*externalPathRetirementPermit, 0, externalPathRetirementPermitLimit)
	for {
		permit, err := externalPathRetirements.reserve()
		if err == nil {
			permits = append(permits, permit)
			continue
		}
		var capacityErr *pathDispatchCallbackCapacityError
		if !errors.As(err, &capacityErr) || capacityErr.operation != externalPathRetirementOperation {
			releaseExternalPathRetirementPermits(permits)
			t.Fatalf("fill retirement capacity: %v", err)
		}
		if len(permits) == 0 {
			t.Fatal("retirement capacity had no free permit for adversarial stimulus")
		}
		return permits
	}
}

func assertExternalPathRetirementCapacityExhausted(t *testing.T) {
	t.Helper()
	permit, err := externalPathRetirements.reserve()
	if permit != nil {
		permit.release()
		t.Fatal("retirement capacity was reused before exact-generation callback completion")
	}
	var capacityErr *pathDispatchCallbackCapacityError
	if !errors.As(err, &capacityErr) || capacityErr.operation != externalPathRetirementOperation {
		t.Fatalf("retirement overflow error=%v want typed capacity", err)
	}
}

func releaseExternalPathRetirementPermits(permits []*externalPathRetirementPermit) {
	for _, permit := range permits {
		permit.release()
	}
}

func retirePathWithoutPeerNotification(t *testing.T, e *Engine, ref PathRef, reason error) {
	t.Helper()
	e.sendMu.Lock()
	runtime := e.localExecutionRuntime()
	e.pathsMu.Lock()
	slot := e.paths[ref.ID]
	if slot == nil || slot.owner != ref.Owner {
		e.pathsMu.Unlock()
		e.sendMu.Unlock()
		t.Fatal("exact path generation is unavailable for local retirement")
	}
	departure := e.detachPathLockedWithPeerNotification(
		slot, runtime, transport.CauseCleanClose, reason, true, false,
	)
	e.pathsMu.Unlock()
	if departure.hasPaths {
		departure.replayCommitted = e.replayRangeLocked(
			e.sendAckNext.Load(), e.sendPublishedNext.Load(),
		) == nil
	}
	e.sendMu.Unlock()
	e.finishPathDeparture(departure)
}

func TestLeafMobilityRefreshCancellationFencesCallbackBeforePublication(t *testing.T) {
	var source *abnormalLeafMobilityRefreshPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			source = &abnormalLeafMobilityRefreshPath{
				PathConn: path, closeEnter: make(chan struct{}),
			}
			return source
		}, nil, nil, nil,
	)
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	var enterOnce sync.Once
	fixture.client.leafRefreshBeforePublish = func() {
		enterOnce.Do(func() { close(entered) })
		<-release
	}
	emitter, err := leafmobility.NewRefreshEmitter(fixture.clientClaim)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
	if err != nil {
		t.Fatal(err)
	}
	published := make(chan bool, 1)
	go func() { published <- source.publish(evidence) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("refresh callback did not reach the pre-publication boundary")
	}
	fixture.client.pathsMu.RLock()
	slot := fixture.client.paths[fixture.clientRef.ID]
	fixture.client.pathsMu.RUnlock()
	if slot == nil {
		t.Fatal("refresh source slot is missing")
	}
	retirePathWithoutPeerNotification(
		t, fixture.client, fixture.clientRef, errors.New("retire admitted refresh callback"),
	)
	eventuallyEngine(t, time.Second, func() bool { return source.cancelCalls.Load() == 1 })
	select {
	case <-source.closeEnter:
		unblock()
		t.Fatal("carrier closed while an exact-generation refresh callback was still running")
	case <-time.After(2 * externalPathValueCallbackTimeout):
	}
	if !slot.retirementPermit.active.Load() {
		unblock()
		t.Fatal("retirement capacity was released before the admitted refresh callback")
	}
	unblock()
	select {
	case invoked := <-published:
		if !invoked {
			t.Fatal("test source did not invoke the admitted callback")
		}
	case <-time.After(time.Second):
		t.Fatal("revoked callback did not drain")
	}
	select {
	case <-source.closeEnter:
	case <-time.After(time.Second):
		t.Fatal("carrier close did not follow refresh callback completion")
	}
	eventuallyEngine(t, time.Second, func() bool {
		fixture.client.leafRefreshMu.Lock()
		_, pending := fixture.client.leafRefreshPending[fixture.clientRef]
		_, status := fixture.client.leafRefreshStatus[fixture.clientRef]
		fixture.client.leafRefreshMu.Unlock()
		return !pending && !status && slot.mobilityPolicyHolds.Load() == 0 &&
			!slot.retirementPermit.active.Load() && source.closeCalls.Load() == 1
	})

	t.Run("concurrent newer evidence is coalesced instead of dropped", func(t *testing.T) {
		var concurrentSource *initiatorRefreshPath
		concurrentFixture := newLeafMobilityEngineFixtureWithAllWrappers(
			t, leafmobility.Resource{}, leafmobility.Resource{},
			func(path *memoryPathConn) transport.PathConn {
				concurrentSource = &initiatorRefreshPath{PathConn: path}
				return concurrentSource
			}, nil, nil, nil,
		)
		sourceState := leafmobility.NewRefreshSourceState()
		firstSource, err := sourceState.Update([32]byte{0x31})
		if err != nil {
			t.Fatal(err)
		}
		emitter, err := leafmobility.NewRefreshEmitterWithSourceState(
			concurrentFixture.clientClaim, sourceState,
		)
		if err != nil {
			t.Fatal(err)
		}
		first, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged, firstSource)
		if err != nil {
			t.Fatal(err)
		}
		entered := make(chan struct{})
		release := make(chan struct{})
		var releaseOnce sync.Once
		unblock := func() { releaseOnce.Do(func() { close(release) }) }
		t.Cleanup(unblock)
		var enterOnce sync.Once
		concurrentFixture.client.leafRefreshBeforePublish = func() {
			enterOnce.Do(func() {
				close(entered)
				<-release
			})
		}
		firstDone := make(chan bool, 1)
		go func() { firstDone <- concurrentSource.publish(first) }()
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("first refresh did not reach the coalescing boundary")
		}
		secondSource, err := sourceState.Update([32]byte{0x32})
		if err != nil {
			unblock()
			t.Fatal(err)
		}
		second, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged, secondSource)
		if err != nil {
			unblock()
			t.Fatal(err)
		}
		secondSnapshot, err := second.ValidateFor(concurrentFixture.clientClaim, 0)
		if err != nil {
			unblock()
			t.Fatal(err)
		}
		if !concurrentSource.publish(second) {
			unblock()
			t.Fatal("concurrent refresh source was not subscribed")
		}
		unblock()
		select {
		case published := <-firstDone:
			if !published {
				t.Fatal("first refresh source was not subscribed")
			}
		case <-time.After(time.Second):
			t.Fatal("coalesced refresh delivery did not drain")
		}
		eventuallyEngine(t, 3*time.Second, func() bool {
			status, ok := concurrentFixture.client.LeafMobilityInitiatorStatus(concurrentFixture.clientRef)
			return ok && status.EvidenceGeneration == secondSnapshot.Generation &&
				status.Phase == LeafMobilityInitiatorCommitted
		})
		if calls := concurrentFixture.clientDriver.calls.Load(); calls != 1 {
			t.Fatalf("coalesced refresh preflights=%d want=1", calls)
		}
	})

	t.Run("validated generation order wins over callback lock order", func(t *testing.T) {
		orderingFixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
		sourceState := leafmobility.NewRefreshSourceState()
		initialSource, err := sourceState.Update([32]byte{0x41})
		if err != nil {
			t.Fatal(err)
		}
		emitter, err := leafmobility.NewRefreshEmitterWithSourceState(
			orderingFixture.clientClaim, sourceState,
		)
		if err != nil {
			t.Fatal(err)
		}
		initial, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged, initialSource)
		if err != nil {
			t.Fatal(err)
		}
		callbackEntered := make(chan struct{})
		releaseCallback := make(chan struct{})
		admissionEntered := make(chan struct{})
		releaseAdmission := make(chan struct{})
		var releaseCallbackOnce, releaseAdmissionOnce sync.Once
		unblock := func() {
			releaseAdmissionOnce.Do(func() { close(releaseAdmission) })
			releaseCallbackOnce.Do(func() { close(releaseCallback) })
		}
		t.Cleanup(unblock)
		delivered := make(chan leafmobility.RefreshSnapshot, 2)
		var callbackCalls atomic.Int32
		owner := newLeafMobilityRefreshSubscriptionOwner(
			orderingFixture.clientClaim,
			func(evidence leafmobility.RefreshEvidence) {
				if callbackCalls.Add(1) == 1 {
					close(callbackEntered)
					<-releaseCallback
					return
				}
				snapshot, validateErr := evidence.ValidateFor(orderingFixture.clientClaim, 0)
				if validateErr != nil {
					delivered <- leafmobility.RefreshSnapshot{}
					return
				}
				delivered <- snapshot
			},
		)
		authority := &externalPathCallbackOwner{}
		if err := owner.bindCallbackAuthority(authority); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			owner.revoke()
			authority.waitRetired()
		})
		go owner.publish(initial)
		select {
		case <-callbackEntered:
		case <-time.After(time.Second):
			t.Fatal("initial refresh delivery did not block the worker")
		}

		olderSource, err := sourceState.Update([32]byte{0x42})
		if err != nil {
			t.Fatal(err)
		}
		older, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged, olderSource)
		if err != nil {
			t.Fatal(err)
		}
		olderSnapshot, err := older.ValidateFor(orderingFixture.clientClaim, 0)
		if err != nil {
			t.Fatal(err)
		}
		owner.beforeAdmission = func(snapshot leafmobility.RefreshSnapshot) {
			if snapshot.Generation == olderSnapshot.Generation {
				close(admissionEntered)
				<-releaseAdmission
			}
		}
		olderReturned := make(chan struct{})
		go func() {
			owner.publish(older)
			close(olderReturned)
		}()
		select {
		case <-admissionEntered:
		case <-time.After(time.Second):
			t.Fatal("older refresh did not reach the reverse-order admission boundary")
		}

		newerSource, err := sourceState.Update([32]byte{0x43})
		if err != nil {
			unblock()
			t.Fatal(err)
		}
		newer, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged, newerSource)
		if err != nil {
			unblock()
			t.Fatal(err)
		}
		newerSnapshot, err := newer.ValidateFor(orderingFixture.clientClaim, 0)
		if err != nil {
			unblock()
			t.Fatal(err)
		}
		owner.publish(newer)

		foreignState := leafmobility.NewRefreshSourceState()
		foreignSource, err := foreignState.Update([32]byte{0x44})
		if err != nil {
			unblock()
			t.Fatal(err)
		}
		foreignEmitter, err := leafmobility.NewRefreshEmitterWithSourceState(
			orderingFixture.serverClaim, foreignState,
		)
		if err != nil {
			unblock()
			t.Fatal(err)
		}
		foreign, err := foreignEmitter.Observe(leafmobility.RefreshReasonRouteSourceChanged, foreignSource)
		if err != nil {
			unblock()
			t.Fatal(err)
		}
		owner.publish(foreign)
		releaseAdmissionOnce.Do(func() { close(releaseAdmission) })
		select {
		case <-olderReturned:
		case <-time.After(time.Second):
			unblock()
			t.Fatal("delayed older refresh publisher did not return")
		}
		releaseCallbackOnce.Do(func() { close(releaseCallback) })
		select {
		case snapshot := <-delivered:
			if snapshot.Generation != newerSnapshot.Generation {
				t.Fatalf("coalesced generation=%d want newest=%d", snapshot.Generation, newerSnapshot.Generation)
			}
		case <-time.After(time.Second):
			t.Fatal("newest reverse-order refresh was not delivered")
		}
		time.Sleep(2 * externalPathValueCallbackTimeout)
		if calls := callbackCalls.Load(); calls != 2 {
			t.Fatalf("refresh callback calls=%d want initial+newest only", calls)
		}
	})

	t.Run("one subscription rejects a second source lineage for the same claim", func(t *testing.T) {
		fixture := newLeafMobilityEngineFixture(
			t, leafmobility.Resource{}, leafmobility.Resource{}, nil,
		)
		firstState := leafmobility.NewRefreshSourceState()
		firstSource, err := firstState.Update([32]byte{0x51})
		if err != nil {
			t.Fatal(err)
		}
		firstEmitter, err := leafmobility.NewRefreshEmitterWithSourceState(
			fixture.clientClaim, firstState,
		)
		if err != nil {
			t.Fatal(err)
		}
		firstEvidence, err := firstEmitter.Observe(
			leafmobility.RefreshReasonRouteSourceChanged, firstSource,
		)
		if err != nil {
			t.Fatal(err)
		}
		delivered := make(chan leafmobility.RefreshSnapshot, 4)
		owner := newLeafMobilityRefreshSubscriptionOwner(
			fixture.clientClaim,
			func(evidence leafmobility.RefreshEvidence) {
				snapshot, validateErr := evidence.ValidateFor(fixture.clientClaim, 0)
				if validateErr != nil {
					delivered <- leafmobility.RefreshSnapshot{}
					return
				}
				delivered <- snapshot
			},
		)
		authority := &externalPathCallbackOwner{}
		if err := owner.bindCallbackAuthority(authority); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			owner.revoke()
			authority.waitRetired()
		})
		owner.publish(firstEvidence)
		var firstDelivered leafmobility.RefreshSnapshot
		select {
		case firstDelivered = <-delivered:
		case <-time.After(time.Second):
			t.Fatal("first source lineage was not delivered")
		}
		eventuallyEngine(t, time.Second, func() bool {
			owner.mu.Lock()
			defer owner.mu.Unlock()
			return owner.deliveryRunning == nil && owner.deliveryReservation != nil
		})

		secondState := leafmobility.NewRefreshSourceState()
		secondSource, err := secondState.Update([32]byte{0x52})
		if err != nil {
			t.Fatal(err)
		}
		secondEmitter, err := leafmobility.NewRefreshEmitterWithSourceState(
			fixture.clientClaim, secondState,
		)
		if err != nil {
			t.Fatal(err)
		}
		secondEvidence, err := secondEmitter.Observe(
			leafmobility.RefreshReasonRouteSourceChanged, secondSource,
		)
		if err != nil {
			t.Fatal(err)
		}
		owner.publish(secondEvidence)

		firstSource, err = firstState.Update([32]byte{0x53})
		if err != nil {
			t.Fatal(err)
		}
		firstEvidence, err = firstEmitter.Observe(
			leafmobility.RefreshReasonRouteSourceChanged, firstSource,
		)
		if err != nil {
			t.Fatal(err)
		}
		want, err := firstEvidence.ValidateFor(fixture.clientClaim, 0)
		if err != nil {
			t.Fatal(err)
		}
		owner.publish(firstEvidence)
		select {
		case got := <-delivered:
			if got.Generation != want.Generation || got.SourceLineage != firstDelivered.SourceLineage {
				t.Fatalf("next delivery=%+v want same-lineage generation %+v", got, want)
			}
		case <-time.After(time.Second):
			t.Fatal("same source lineage did not remain deliverable")
		}
		select {
		case extra := <-delivered:
			t.Fatalf("foreign same-claim source lineage was delivered: %+v", extra)
		case <-time.After(2 * externalPathValueCallbackTimeout):
		}
	})

	t.Run("noisy subscriptions yield durable workers to queued owners", func(t *testing.T) {
		var stop atomic.Bool
		type noisySubscription struct {
			owner     *leafMobilityRefreshSubscriptionOwner
			authority *externalPathCallbackOwner
		}
		noisy := make([]noisySubscription, externalPathDurableCallbackWorkerLimit)
		var entered sync.WaitGroup
		entered.Add(len(noisy))
		for index := range noisy {
			var owner *leafMobilityRefreshSubscriptionOwner
			var enterOnce sync.Once
			owner = newAdmittedLeafMobilityRefreshTestOwner(func(leafmobility.RefreshEvidence) {
				enterOnce.Do(entered.Done)
				if !stop.Load() {
					owner.publish(leafmobility.RefreshEvidence{})
					time.Sleep(time.Millisecond)
				}
			})
			authority := &externalPathCallbackOwner{marker: byte(index)}
			if err := owner.bindCallbackAuthority(authority); err != nil {
				t.Fatalf("bind noisy refresh owner %d: %v", index, err)
			}
			noisy[index] = noisySubscription{owner: owner, authority: authority}
		}
		victimRan := make(chan struct{})
		victimOwner := newAdmittedLeafMobilityRefreshTestOwner(func(leafmobility.RefreshEvidence) {
			close(victimRan)
		})
		victimAuthority := &externalPathCallbackOwner{}
		if err := victimOwner.bindCallbackAuthority(victimAuthority); err != nil {
			t.Fatal(err)
		}
		cleanupDone := make(chan struct{})
		t.Cleanup(func() {
			stop.Store(true)
			victimOwner.revoke()
			for _, subscription := range noisy {
				subscription.owner.revoke()
			}
			go func() {
				victimAuthority.waitRetired()
				for _, subscription := range noisy {
					subscription.authority.waitRetired()
				}
				close(cleanupDone)
			}()
			select {
			case <-cleanupDone:
			case <-time.After(3 * time.Second):
				t.Error("durable event authorities did not retire after noisy-source cleanup")
			}
		})
		for _, subscription := range noisy {
			go subscription.owner.publish(leafmobility.RefreshEvidence{})
		}
		allEntered := make(chan struct{})
		go func() {
			entered.Wait()
			close(allEntered)
		}()
		select {
		case <-allEntered:
		case <-time.After(2 * time.Second):
			t.Fatal("noisy refresh sources did not occupy the initial worker turn")
		}
		go victimOwner.publish(leafmobility.RefreshEvidence{})
		select {
		case <-victimRan:
		case <-time.After(time.Second):
			t.Fatal("queued refresh owner made no progress behind noisy subscriptions")
		}
		victimOwner.revoke()
		victimRetired := make(chan struct{})
		go func() {
			victimAuthority.waitRetired()
			close(victimRetired)
		}()
		select {
		case <-victimRetired:
		case <-time.After(time.Second):
			t.Fatal("queued refresh owner retirement remained pinned after delivery")
		}
	})

	t.Run("queued subscription retirement drains without invoking callback", func(t *testing.T) {
		releaseWorkers := make(chan struct{})
		type blocker struct {
			owner     *leafMobilityRefreshSubscriptionOwner
			authority *externalPathCallbackOwner
		}
		blockers := make([]blocker, externalPathDurableCallbackWorkerLimit)
		var entered sync.WaitGroup
		entered.Add(len(blockers))
		for index := range blockers {
			owner := newAdmittedLeafMobilityRefreshTestOwner(func(leafmobility.RefreshEvidence) {
				entered.Done()
				<-releaseWorkers
			})
			authority := &externalPathCallbackOwner{marker: byte(index)}
			if err := owner.bindCallbackAuthority(authority); err != nil {
				t.Fatalf("bind blocker %d: %v", index, err)
			}
			blockers[index] = blocker{owner: owner, authority: authority}
		}
		var releaseOnce sync.Once
		cleanup := func() {
			releaseOnce.Do(func() { close(releaseWorkers) })
			for _, blocker := range blockers {
				blocker.owner.revoke()
			}
			for _, blocker := range blockers {
				blocker.authority.waitRetired()
			}
		}
		t.Cleanup(cleanup)
		for _, blocker := range blockers {
			go blocker.owner.publish(leafmobility.RefreshEvidence{})
		}
		allEntered := make(chan struct{})
		go func() {
			entered.Wait()
			close(allEntered)
		}()
		select {
		case <-allEntered:
		case <-time.After(2 * time.Second):
			t.Fatal("durable event workers were not saturated")
		}

		var victimCalls atomic.Int32
		victim := newAdmittedLeafMobilityRefreshTestOwner(func(leafmobility.RefreshEvidence) {
			victimCalls.Add(1)
		})
		victimAuthority := &externalPathCallbackOwner{}
		if err := victim.bindCallbackAuthority(victimAuthority); err != nil {
			t.Fatal(err)
		}
		publishReturned := make(chan struct{})
		go func() {
			victim.publish(leafmobility.RefreshEvidence{})
			close(publishReturned)
		}()
		var queued *externalPathDurableCallbackReservation
		eventuallyEngine(t, time.Second, func() bool {
			victim.mu.Lock()
			queued = victim.deliveryRunning
			victim.mu.Unlock()
			return queued != nil && queued.lifecycleState() == externalPathDurableCallbackQueued
		})
		victim.revoke()
		victimRetired := make(chan struct{})
		go func() {
			victimAuthority.waitRetired()
			close(victimRetired)
		}()
		select {
		case <-victimRetired:
			t.Fatal("queued authority retired before its executor turn completed")
		case <-time.After(20 * time.Millisecond):
		}
		cleanup()
		select {
		case <-victimRetired:
		case <-time.After(time.Second):
			t.Fatal("queued authority did not drain after worker release")
		}
		select {
		case <-publishReturned:
		case <-time.After(time.Second):
			t.Fatal("queued publisher did not return after retirement")
		}
		if calls := victimCalls.Load(); calls != 0 {
			t.Fatalf("retired queued callback calls=%d want=0", calls)
		}
	})

	t.Run("authority retirement between delivery and handoff is a clean stop", func(t *testing.T) {
		eventReservations := func() int {
			externalPathDurableCallbacks.Lock()
			defer externalPathDurableCallbacks.Unlock()
			return externalPathDurableCallbacks.classInflight[externalPathDurableEvent]
		}
		baseline := eventReservations()
		authority := &externalPathCallbackOwner{}
		entered := make(chan struct{})
		release := make(chan struct{})
		var releaseOnce sync.Once
		unblock := func() { releaseOnce.Do(func() { close(release) }) }
		t.Cleanup(unblock)
		owner := newAdmittedLeafMobilityRefreshTestOwner(func(leafmobility.RefreshEvidence) {
			close(entered)
			<-release
		})
		teardownErr := make(chan error, 1)
		owner.setCompletionTracker(nil, func(err error) {
			select {
			case teardownErr <- err:
			default:
			}
		})
		if err := owner.bindCallbackAuthority(authority); err != nil {
			t.Fatal(err)
		}
		deliveryReturned := make(chan struct{})
		go func() {
			owner.publish(leafmobility.RefreshEvidence{})
			close(deliveryReturned)
		}()
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("refresh delivery did not start")
		}
		authority.retire()
		retired := make(chan struct{})
		go func() {
			authority.waitRetired()
			close(retired)
		}()
		select {
		case <-retired:
			t.Fatal("generation retired before its running delivery completed")
		case <-time.After(2 * externalPathValueCallbackTimeout):
		}
		unblock()
		select {
		case <-retired:
		case <-time.After(time.Second):
			t.Fatal("generation retirement did not follow delivery completion")
		}
		select {
		case <-deliveryReturned:
		case <-time.After(time.Second):
			t.Fatal("refresh publisher did not return")
		}
		if owner.activeNow() {
			t.Fatal("retired generation retained an active refresh delivery owner")
		}
		select {
		case err := <-teardownErr:
			t.Fatalf("normal generation retirement reported teardown error: %v", err)
		default:
		}
		eventuallyEngine(t, time.Second, func() bool { return eventReservations() == baseline })
		owner.revoke()
	})
}

func TestLeafMobilityRefreshSubscribeCancellationContextIsBounded(t *testing.T) {
	source := &abnormalLeafMobilityRefreshPath{
		mode: "subscribe-wait-context", subscribeEnter: make(chan struct{}),
	}
	started := time.Now()
	_, err := invokeLeafMobilityRefreshSubscribe(source, context.Background(), func(leafmobility.RefreshEvidence) {})
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("subscription context cancellation took %s", elapsed)
	}
	var deadlineErr *pathDispatchCallbackDeadlineError
	if !errors.As(err, &deadlineErr) || !errors.Is(deadlineErr.cause, context.DeadlineExceeded) {
		t.Fatalf("subscription error=%v want deadline exceeded", err)
	}
	select {
	case <-source.subscribeEnter:
	default:
		t.Fatal("context-aware subscription stimulus did not enter")
	}
}

func (path *abnormalLeafMobilityRefreshPath) publish(evidence leafmobility.RefreshEvidence) bool {
	path.mu.Lock()
	callback := path.callback
	path.mu.Unlock()
	if callback == nil {
		return false
	}
	callback(evidence)
	return true
}

func TestLeafMobilityRefreshSubscribeAbnormalExitIsTypedAndObservable(t *testing.T) {
	tests := []struct {
		name      string
		mode      string
		operation string
	}{
		{name: "panic", mode: "subscribe-panic", operation: "RefreshSource.SubscribeLeafMobilityRefresh"},
		{name: "Goexit", mode: "subscribe-goexit", operation: "RefreshSource.SubscribeLeafMobilityRefresh"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			standalone := &abnormalLeafMobilityRefreshPath{mode: test.mode}
			_, err := invokeLeafMobilityRefreshSubscribe(standalone, context.Background(), func(leafmobility.RefreshEvidence) {})
			assertLeafMobilityRefreshCallbackError(t, err, test.mode, test.operation)

			fixture := newLeafMobilityEngineFixtureWithAllWrappers(
				t, leafmobility.Resource{}, leafmobility.Resource{},
				func(path *memoryPathConn) transport.PathConn {
					return &abnormalLeafMobilityRefreshPath{PathConn: path, mode: test.mode}
				}, nil, nil, nil,
			)
			status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
			if !ok || status.Phase != LeafMobilityInitiatorSubscriptionUnavailable {
				t.Fatalf("subscription status=%+v present=%t", status, ok)
			}
			if !strings.Contains(status.Error, test.operation) {
				t.Fatalf("subscription diagnostic=%q does not name %s", status.Error, test.operation)
			}
			fixture.client.pathsMu.RLock()
			slot := fixture.client.paths[fixture.clientRef.ID]
			fixture.client.pathsMu.RUnlock()
			if slot == nil {
				t.Fatal("subscription failure removed an otherwise usable generic path")
			}
			slot.mobilityRefreshMu.Lock()
			installed := slot.mobilityRefreshCancel != nil
			slot.mobilityRefreshMu.Unlock()
			if installed {
				t.Fatal("abnormal subscription installed a refresh monitor")
			}
		})
	}
}

func TestLeafMobilityRefreshCancelAbnormalExitRevokesAuthorityAndCompletesTeardown(t *testing.T) {
	for _, mode := range []string{"cancel-panic", "cancel-goexit"} {
		t.Run(mode, func(t *testing.T) {
			var source *abnormalLeafMobilityRefreshPath
			fixture := newLeafMobilityEngineFixtureWithAllWrappers(
				t, leafmobility.Resource{}, leafmobility.Resource{},
				func(path *memoryPathConn) transport.PathConn {
					source = &abnormalLeafMobilityRefreshPath{PathConn: path, mode: mode}
					return source
				}, nil, nil, nil,
			)

			cancelCtx, stopCancel := context.WithTimeout(context.Background(), time.Second)
			cancelErr := invokeLeafMobilityRefreshCancel(cancelCtx, &externalPathCallbackOwner{}, func() {
				if mode == "cancel-panic" {
					panic("standalone cancel panic")
				}
				runtime.Goexit()
			})
			stopCancel()
			assertLeafMobilityRefreshCallbackError(t, cancelErr, mode, "RefreshSource cancellation")

			if err := fixture.client.RetirePath(fixture.clientControlRef, errors.New("remove control route")); err != nil {
				t.Fatal(err)
			}
			eventuallyEngine(t, time.Second, func() bool {
				_, present := fixture.client.PathRef(fixture.clientControlRef.ID)
				return !present
			})
			emitter, err := leafmobility.NewRefreshEmitter(fixture.clientClaim)
			if err != nil {
				t.Fatal(err)
			}
			evidence, err := emitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
			if err != nil {
				t.Fatal(err)
			}
			if source == nil || !source.publish(evidence) {
				t.Fatal("refresh source was not subscribed")
			}
			fixture.client.pathsMu.RLock()
			subject := fixture.client.paths[fixture.clientRef.ID]
			fixture.client.pathsMu.RUnlock()
			if subject == nil {
				t.Fatal("subject path is missing")
			}
			eventuallyEngine(t, time.Second, func() bool {
				status, ok := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
				return ok && status.Phase == LeafMobilityInitiatorDeferred && subject.mobilityPolicyHolds.Load() != 0
			})

			if err := fixture.client.RetirePath(fixture.clientRef, errors.New("retire deferred subject")); err != nil {
				t.Fatal(err)
			}
			select {
			case <-subject.quit:
			case <-time.After(time.Second):
				t.Fatal("abnormal refresh cancel interrupted path teardown")
			}
			eventuallyEngine(t, time.Second, func() bool {
				fixture.client.leafRefreshMu.Lock()
				_, pending := fixture.client.leafRefreshPending[fixture.clientRef]
				_, running := fixture.client.leafRefreshRunning[fixture.clientRef]
				_, cancel := fixture.client.leafRefreshCancel[fixture.clientRef]
				_, status := fixture.client.leafRefreshStatus[fixture.clientRef]
				fixture.client.leafRefreshMu.Unlock()
				return !pending && !running && !cancel && !status && subject.mobilityPolicyHolds.Load() == 0
			})
			eventuallyEngine(t, time.Second, func() bool { return source.cancelCalls.Load() == 1 })
			eventuallyEngine(t, time.Second, func() bool {
				err := fixture.client.teardownError()
				if mode == "cancel-panic" {
					var panicErr *pathDispatchCallbackPanicError
					return errors.As(err, &panicErr) && panicErr.operation == leafMobilityRefreshCancelOp
				}
				var goexitErr *pathDispatchCallbackGoexitError
				return errors.As(err, &goexitErr) && goexitErr.operation == leafMobilityRefreshCancelOp
			})
		})
	}
}

func TestLeafMobilityRefreshCancelBlockCannotHoldPathLockOrSpawnAnotherOrphan(t *testing.T) {
	var source *abnormalLeafMobilityRefreshPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			source = &abnormalLeafMobilityRefreshPath{
				PathConn: path, mode: "cancel-block",
				cancelEnter: make(chan struct{}), cancelBlock: make(chan struct{}),
			}
			return source
		}, nil, nil, nil,
	)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(source.cancelBlock) }) }
	t.Cleanup(release)

	retired := make(chan error, 1)
	go func() {
		retired <- fixture.client.RetirePath(fixture.clientRef, errors.New("retire blocked cancel source"))
	}()
	select {
	case err := <-retired:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("refresh cancellation blocked RetirePath while pathsMu was held")
	}
	select {
	case <-source.cancelEnter:
	case <-time.After(time.Second):
		t.Fatal("refresh cancellation stimulus did not enter")
	}
	eventuallyEngine(t, time.Second, func() bool {
		var deadlineErr *pathDispatchCallbackDeadlineError
		return errors.As(fixture.client.teardownError(), &deadlineErr) &&
			deadlineErr.operation == leafMobilityRefreshCancelOp
	})
	fixture.client.leafRefreshMu.Lock()
	_, pending := fixture.client.leafRefreshPending[fixture.clientRef]
	_, running := fixture.client.leafRefreshRunning[fixture.clientRef]
	_, workerCancel := fixture.client.leafRefreshCancel[fixture.clientRef]
	_, status := fixture.client.leafRefreshStatus[fixture.clientRef]
	fixture.client.leafRefreshMu.Unlock()
	if pending || running || workerCancel || status || source.cancelCalls.Load() != 1 {
		t.Fatalf("blocked cancel retained pending/running/cancel/status/calls=%t/%t/%t/%t/%d",
			pending, running, workerCancel, status, source.cancelCalls.Load())
	}

	owner := &externalPathCallbackOwner{}
	entered := make(chan struct{})
	blocked := make(chan struct{})
	var calls atomic.Int32
	ctx, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := invokeLeafMobilityRefreshCancel(ctx, owner, func() {
		calls.Add(1)
		close(entered)
		<-blocked
	})
	stop()
	select {
	case <-entered:
	default:
		t.Fatal("standalone blocked cancel did not enter")
	}
	var deadlineErr *pathDispatchCallbackDeadlineError
	if !errors.As(err, &deadlineErr) {
		t.Fatalf("blocked cancel error=%v want typed deadline", err)
	}
	secondCtx, stopSecond := context.WithTimeout(context.Background(), time.Second)
	secondErr := invokeLeafMobilityRefreshCancel(secondCtx, owner, func() { calls.Add(1) })
	stopSecond()
	var busyErr *pathDispatchCallbackBusyError
	if !errors.As(secondErr, &busyErr) || calls.Load() != 1 {
		t.Fatalf("second cancel error/calls=%v/%d want typed busy/1", secondErr, calls.Load())
	}
	close(blocked)
	eventuallyEngine(t, time.Second, func() bool {
		return !externalPathCallbackInFlight(leafMobilityRefreshCancelOp, owner)
	})
	release()
}

func TestLeafMobilityRefreshCancellationIsDurableAndTrackedByEngineClose(t *testing.T) {
	var source *abnormalLeafMobilityRefreshPath
	fixture := newLeafMobilityEngineFixtureWithAllWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			source = &abnormalLeafMobilityRefreshPath{
				PathConn: path, mode: "cancel-block",
				cancelEnter: make(chan struct{}), cancelBlock: make(chan struct{}),
				cancelExit: make(chan struct{}),
			}
			return source
		}, nil, nil, nil,
	)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(source.cancelBlock) }) }
	t.Cleanup(release)

	// An established subscription owns separate durable cancellation authority;
	// filling the ordinary lifecycle class cannot prevent teardown invocation.
	leases := make([]*externalPathCallbackLease, 0, externalPathCallbackClassLimit)
	defer func() {
		for _, lease := range leases {
			lease.release()
		}
	}()
	for index := 0; index < externalPathCallbackClassLimit; index++ {
		lease, err := acquireExternalPathCallbackLease(
			"PathConn.OnDeath", &externalPathCallbackOwner{marker: byte(index)},
		)
		if err != nil {
			t.Fatalf("lifecycle lease %d: %v", index, err)
		}
		leases = append(leases, lease)
	}

	closeResult := make(chan error, 1)
	go func() { closeResult <- fixture.client.Close() }()
	select {
	case <-source.cancelEnter:
	case <-time.After(time.Second):
		t.Fatal("established cancellation lost authority under lifecycle saturation")
	}
	select {
	case <-source.cancelExit:
		t.Fatal("blocked transport cancellation was falsely reported as drained")
	default:
	}
	select {
	case err := <-closeResult:
		var deadlineErr *pathDispatchCallbackDeadlineError
		if !errors.As(err, &deadlineErr) || deadlineErr.operation != leafMobilityRefreshCancelOp {
			t.Fatalf("Close error=%v want typed refresh cancellation deadline", err)
		}
		var teardownDeadline *engineTeardownDeadlineError
		if !errors.As(err, &teardownDeadline) {
			t.Fatalf("Close error=%v want typed engine teardown deadline", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Engine.Close did not complete after bounded cancellation result")
	}
	select {
	case <-fixture.client.Closed():
		t.Fatal("Closed was published while durable cancellation was still alive")
	default:
	}
	var observedDeadline *pathDispatchCallbackDeadlineError
	if err := fixture.client.CloseErr(); !errors.As(err, &observedDeadline) ||
		observedDeadline.operation != leafMobilityRefreshCancelOp {
		t.Fatalf("CloseErr=%v did not retain late cancellation failure", err)
	}
	externalPathDurableCallbacks.Lock()
	durableCancelRetained := false
	heldCancelCount := 0
	for _, reservation := range externalPathDurableCallbacks.owners {
		if reservation.operation == leafMobilityRefreshCancelOp && !reservation.released.Load() {
			durableCancelRetained = true
			heldCancelCount++
		}
	}
	externalPathDurableCallbacks.Unlock()
	if !durableCancelRetained {
		t.Fatal("blocked callback did not retain its process permit after bounded Close")
	}

	release()
	select {
	case <-source.cancelExit:
	case <-time.After(time.Second):
		t.Fatal("released cancellation callback did not exit")
	}
	select {
	case <-fixture.client.Closed():
	case <-time.After(time.Second):
		t.Fatal("engine did not publish quiescence after durable cancellation exited")
	}
	eventuallyEngine(t, time.Second, func() bool {
		externalPathDurableCallbacks.Lock()
		defer externalPathDurableCallbacks.Unlock()
		remaining := 0
		for _, reservation := range externalPathDurableCallbacks.owners {
			if reservation.operation == leafMobilityRefreshCancelOp && !reservation.released.Load() {
				remaining++
			}
		}
		return remaining < heldCancelCount
	})

	t.Run("production cancellation hooks bound more than one worker class", func(t *testing.T) {
		const cancellationCount = externalPathDurableCallbackWorkerLimit + 1
		engines := []*Engine{
			New(SideClient, NewClientFlowID(), Limits{}.Clamp()),
			New(SideClient, NewClientFlowID(), Limits{}.Clamp()),
		}
		baselineGoroutines := runtime.NumGoroutine()
		release := make(chan struct{})
		var releaseOnce sync.Once
		unblock := func() { releaseOnce.Do(func() { close(release) }) }
		t.Cleanup(func() {
			unblock()
			for _, engine := range engines {
				_ = engine.Close()
			}
		})
		var started, active, maxActive atomic.Int32
		calls := make([]atomic.Int32, cancellationCount)
		reservations := make([]*externalPathDurableCallbackReservation, cancellationCount)
		for index := 0; index < cancellationCount; index++ {
			owner := &externalPathCallbackOwner{marker: byte(index)}
			reservation, err := reserveExternalPathDurableCallback(leafMobilityRefreshCancelOp, owner)
			if err != nil {
				t.Fatalf("reserve cancellation %d: %v", index, err)
			}
			reservations[index] = reservation
			callbackIndex := index
			cancellation := &leafMobilityRefreshCancellation{
				owner:       newLeafMobilityRefreshSubscriptionOwner(nil, nil),
				cancelSetup: func(error) {},
				cancel: func() {
					calls[callbackIndex].Add(1)
					now := active.Add(1)
					for previous := maxActive.Load(); now > previous; previous = maxActive.Load() {
						if maxActive.CompareAndSwap(previous, now) {
							break
						}
					}
					started.Add(1)
					<-release
					active.Add(-1)
				},
				reservation: reservation,
			}
			engines[index%len(engines)].startLeafMobilityRefreshCancel(cancellation)
		}
		eventuallyEngine(t, time.Second, func() bool {
			return started.Load() == externalPathDurableCallbackWorkerLimit
		})
		if got := maxActive.Load(); got > externalPathDurableCallbackWorkerLimit {
			t.Fatalf("refresh cancellation active=%d limit=%d", got, externalPathDurableCallbackWorkerLimit)
		}
		if got := calls[cancellationCount-1].Load(); got != 0 {
			t.Fatalf("queued production cancellation calls=%d want=0", got)
		}
		if delta := runtime.NumGoroutine() - baselineGoroutines; delta > externalPathDurableCallbackWorkerLimit+4 {
			t.Fatalf("refresh cancellation goroutine delta=%d want<=%d",
				delta, externalPathDurableCallbackWorkerLimit+4)
		}
		unblock()
		eventuallyEngine(t, time.Second, func() bool {
			return started.Load() == cancellationCount && active.Load() == 0
		})
		for index, reservation := range reservations {
			select {
			case <-reservation.completion():
			case <-time.After(time.Second):
				t.Fatalf("production cancellation %d did not complete", index)
			}
			if got := calls[index].Load(); got != 1 {
				t.Fatalf("production cancellation %d calls=%d want=1", index, got)
			}
		}
		for index, engine := range engines {
			_ = engine.Close()
			select {
			case <-engine.Closed():
			case <-time.After(time.Second):
				t.Fatalf("refresh engine %d completion hooks did not quiesce", index)
			}
		}
	})
}

func TestPendingAndStagedAbortCancelRefreshAndReleaseReservationsOnce(t *testing.T) {
	for _, stage := range []bool{false, true} {
		name := "pending"
		if stage {
			name = "staged"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newLeafMobilityEngineFixtureWithAllWrappers(
				t, leafmobility.Resource{}, leafmobility.Resource{}, nil, nil, nil, nil,
			)
			base, peer := newMemoryPathPair()
			t.Cleanup(func() { _ = peer.Close() })
			source := &abnormalLeafMobilityRefreshPath{PathConn: base}
			facts := fixture.clientClaim.Snapshot()
			facts.Operations = 0
			facts.Scope = leafmobility.ScopeUnknown
			facts.ResourceID = leafmobility.ResourceID{}
			facts.Generation = leafmobility.NextGeneration()
			claim := leafmobility.MustNewDrivenClaimWithIncarnation(
				facts, fixture.clientExecutionDriver, fixture.clientResource,
				fixture.clientExecutionDriver.reporter,
			)
			source.setLeafMobilityTestClaim(claim)
			path := &claimedMemoryPath{PathConn: source, claim: claim}

			counts := func() [externalPathDurableCallbackClassCount]int {
				externalPathDurableCallbacks.Lock()
				defer externalPathDurableCallbacks.Unlock()
				return externalPathDurableCallbacks.classInflight
			}
			baseline := counts()
			id, err := fixture.client.PreparePathBound(
				path, transport.PathSpec{Transport: "refresh-abort"}, fixture.binding,
			)
			if err != nil {
				t.Fatal(err)
			}
			fixture.client.pathsMu.RLock()
			slot := fixture.client.pendingPaths[id]
			fixture.client.pathsMu.RUnlock()
			if slot == nil {
				t.Fatal("prepared path is not pending")
			}
			if stage {
				if err := fixture.client.StagePathAttach(id); err != nil {
					t.Fatal(err)
				}
				fixture.client.pathsMu.RLock()
				slot = fixture.client.stagedPaths[id]
				fixture.client.pathsMu.RUnlock()
				if slot == nil {
					t.Fatal("prepared path is not staged")
				}
			}
			admitted := counts()
			if admitted[externalPathDurableCleanup] != baseline[externalPathDurableCleanup]+1 ||
				admitted[externalPathDurableCancellation] != baseline[externalPathDurableCancellation]+1 ||
				admitted[externalPathDurableEvent] != baseline[externalPathDurableEvent]+1 {
				t.Fatalf("durable reservations after prepare=%v baseline=%v", admitted, baseline)
			}

			fixture.client.AbortPathAttach(id, errors.New("abort refresh registration"))
			fixture.client.AbortPathAttach(id, errors.New("duplicate abort"))
			select {
			case <-slot.cleanupReservation.completion():
			case <-time.After(time.Second):
				t.Fatal("path cleanup reservation did not complete")
			}
			eventuallyEngine(t, time.Second, func() bool {
				return source.cancelCalls.Load() == 1 && source.closeCalls.Load() == 1 && counts() == baseline
			})
			fixture.client.pathsMu.RLock()
			_, pending := fixture.client.pendingPaths[id]
			_, staged := fixture.client.stagedPaths[id]
			fixture.client.pathsMu.RUnlock()
			if pending || staged || !slot.retireTracked.Load() || source.cancelCalls.Load() != 1 ||
				source.closeCalls.Load() != 1 {
				t.Fatalf(
					"post-abort pending/staged/tracked/cancel/close=%t/%t/%t/%d/%d",
					pending, staged, slot.retireTracked.Load(), source.cancelCalls.Load(), source.closeCalls.Load(),
				)
			}
		})
	}
}

func assertLeafMobilityRefreshCallbackError(t *testing.T, err error, mode, operation string) {
	t.Helper()
	if mode == "subscribe-panic" || mode == "cancel-panic" {
		var panicErr *pathDispatchCallbackPanicError
		if !errors.As(err, &panicErr) || panicErr.operation != operation {
			t.Fatalf("callback error=%v want panic for %s", err, operation)
		}
		return
	}
	var goexitErr *pathDispatchCallbackGoexitError
	if !errors.As(err, &goexitErr) || goexitErr.operation != operation {
		t.Fatalf("callback error=%v want Goexit for %s", err, operation)
	}
}
