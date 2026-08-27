package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type panicErrorPayload struct{ calls *atomic.Int32 }

func (payload panicErrorPayload) Error() string {
	payload.calls.Add(1)
	panic("panic payload Error must not run")
}

type panicStringerPayload struct{ calls *atomic.Int32 }

func (payload panicStringerPayload) String() string {
	payload.calls.Add(1)
	panic("panic payload String must not run")
}

func TestTransportCallbackPanicDiagnosticNeverExecutesRecoveredPayload(t *testing.T) {
	tests := []struct {
		name    string
		payload func(*atomic.Int32) any
	}{
		{name: "error", payload: func(calls *atomic.Int32) any { return panicErrorPayload{calls: calls} }},
		{name: "stringer", payload: func(calls *atomic.Int32) any { return panicStringerPayload{calls: calls} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			payload := test.payload(&calls)
			_, err := invokeExternalPathValueCallback("hostile-panic-"+test.name, func() int {
				panic(payload)
			})
			var panicErr *pathDispatchCallbackPanicError
			if !errors.As(err, &panicErr) {
				t.Fatalf("callback error=%v want typed panic", err)
			}
			wantType := reflect.TypeOf(payload).String()
			if panicErr.recoveredType != wantType {
				t.Fatalf("panic type=%q want %q", panicErr.recoveredType, wantType)
			}
			_ = err.Error()
			if got := calls.Load(); got != 0 {
				t.Fatalf("panic payload formatter calls=%d want=0", got)
			}
		})
	}
}

func TestExternalValueCallbackDeadlineRetainsOneOrphanLease(t *testing.T) {
	const operation = "test.blocked-value-authority"
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	var calls atomic.Int32

	started := time.Now()
	_, err := invokeExternalPathValueCallback(operation, func() int {
		calls.Add(1)
		close(entered)
		<-release
		return 1
	})
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("blocked value callback returned after %s", elapsed)
	}
	select {
	case <-entered:
	default:
		t.Fatal("blocked value callback did not enter")
	}
	var deadlineErr *pathDispatchCallbackDeadlineError
	if !errors.As(err, &deadlineErr) || deadlineErr.operation != operation {
		t.Fatalf("blocked value error=%v want typed deadline", err)
	}

	started = time.Now()
	_, err = invokeExternalPathValueCallback(operation, func() int {
		calls.Add(1)
		return 2
	})
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("busy value callback returned after %s", elapsed)
	}
	var busyErr *pathDispatchCallbackBusyError
	if !errors.As(err, &busyErr) || calls.Load() != 1 {
		t.Fatalf("busy value error/calls=%v/%d want typed busy/1", err, calls.Load())
	}

	releaseOnce.Do(func() { close(release) })
	eventuallyEngine(t, time.Second, func() bool {
		return !externalPathCallbackInFlight(operation, nil)
	})
	value, err := invokeExternalPathValueCallback(operation, func() int {
		calls.Add(1)
		return 3
	})
	if err != nil || value != 3 || calls.Load() != 2 {
		t.Fatalf("reused value callback value/error/calls=%d/%v/%d", value, err, calls.Load())
	}
	t.Run("global capacity remains bounded", testExternalPathCallbackCapacity)
	t.Run("admission write remains single flight", testAdmissionWriteCallbackSingleFlight)
	t.Run("completed durable deadlines leave no scheduler residue", func(t *testing.T) {
		const callbackCount = 2 * externalPathDurableCallbackWorkerLimit
		eventuallyEngine(t, time.Second, func() bool {
			return externalPathDurableCallbackDeadlines.entryCount() == 0
		})
		owners := make([]externalPathCallbackOwner, callbackCount)
		reservations := make([]*externalPathDurableCallbackReservation, callbackCount)
		release := make(chan struct{})
		var releaseOnce sync.Once
		unblock := func() { releaseOnce.Do(func() { close(release) }) }
		t.Cleanup(unblock)
		var reports atomic.Int32

		for index := range reservations {
			owners[index].marker = byte(index)
			reservation, err := reserveExternalPathDurableCallback(
				leafMobilityRefreshCancelOp, &owners[index],
			)
			if err != nil {
				unblock()
				t.Fatalf("reserve scheduled callback %d: %v", index, err)
			}
			reservations[index] = reservation
			if err := reservation.start(func() error {
				<-release
				return nil
			}); err != nil {
				unblock()
				t.Fatalf("start scheduled callback %d: %v", index, err)
			}
			if err := externalPathDurableCallbackDeadlines.schedule(
				reservation, time.Hour, func(error) { reports.Add(1) },
			); err != nil {
				unblock()
				t.Fatalf("schedule callback %d: %v", index, err)
			}
		}
		if got := externalPathDurableCallbackDeadlines.entryCount(); got != callbackCount {
			t.Fatalf("scheduled deadline entries=%d want=%d", got, callbackCount)
		}

		unblock()
		for index, reservation := range reservations {
			select {
			case <-reservation.completion():
			case <-time.After(time.Second):
				t.Fatalf("scheduled callback %d did not complete", index)
			}
		}
		eventuallyEngine(t, time.Second, func() bool {
			return externalPathDurableCallbackDeadlines.entryCount() == 0
		})
		if got := reports.Load(); got != 0 {
			t.Fatalf("far-future completed callbacks reported %d deadlines", got)
		}
		eventuallyEngine(t, time.Second, durableCallbackInfrastructureIdle)

		for cycle := 0; cycle < 2; cycle++ {
			owner := &externalPathCallbackOwner{marker: byte(cycle + 1)}
			reservation, err := reserveExternalPathDurableCallback(
				leafMobilityRefreshCancelOp, owner,
			)
			if err != nil {
				t.Fatalf("cycle %d reserve deadline callback: %v", cycle, err)
			}
			releaseCycle := make(chan struct{})
			if err := reservation.start(func() error {
				<-releaseCycle
				return nil
			}); err != nil {
				t.Fatalf("cycle %d start deadline callback: %v", cycle, err)
			}
			if err := externalPathDurableCallbackDeadlines.schedule(
				reservation, time.Hour, func(error) { reports.Add(1) },
			); err != nil {
				close(releaseCycle)
				t.Fatalf("cycle %d schedule deadline callback: %v", cycle, err)
			}
			eventuallyEngine(t, time.Second, func() bool {
				externalPathDurableCallbackDeadlines.mu.Lock()
				defer externalPathDurableCallbackDeadlines.mu.Unlock()
				return externalPathDurableCallbackDeadlines.running &&
					len(externalPathDurableCallbackDeadlines.entries) == 1
			})
			close(releaseCycle)
			select {
			case <-reservation.completion():
			case <-time.After(time.Second):
				t.Fatalf("cycle %d deadline callback did not complete", cycle)
			}
			eventuallyEngine(t, time.Second, durableCallbackInfrastructureIdle)
		}
		if got := reports.Load(); got != 0 {
			t.Fatalf("restart cycles reported %d far-future deadlines", got)
		}
	})
	t.Run("durable dispatchers retire and restart", func(t *testing.T) {
		operations := []string{
			externalPathCloseOperation,
			leafMobilityRefreshCancelOp,
			leafMobilityRefreshEventOp,
		}
		for cycle := 0; cycle < 2; cycle++ {
			owners := make([]externalPathCallbackOwner, len(operations))
			for index, operation := range operations {
				owners[index].marker = byte(cycle*len(operations) + index + 1)
				reservation, err := reserveExternalPathDurableCallback(operation, &owners[index])
				if err != nil {
					t.Fatalf("cycle %d reserve %s: %v", cycle, operation, err)
				}
				if err := reservation.start(func() error { return nil }); err != nil {
					t.Fatalf("cycle %d start %s: %v", cycle, operation, err)
				}
				select {
				case <-reservation.completion():
				case <-time.After(time.Second):
					t.Fatalf("cycle %d callback %s did not complete", cycle, operation)
				}
			}
			eventuallyEngine(t, time.Second, durableCallbackInfrastructureIdle)
		}
	})
}

func durableCallbackInfrastructureIdle() bool {
	externalPathDurableCallbackDeadlines.mu.Lock()
	deadlineIdle := len(externalPathDurableCallbackDeadlines.entries) == 0 &&
		!externalPathDurableCallbackDeadlines.running
	externalPathDurableCallbackDeadlines.mu.Unlock()
	if !deadlineIdle {
		return false
	}
	for _, executor := range externalPathDurableCallbackExecutors {
		executor.mu.Lock()
		idle := executor.queued == 0 && !executor.running && len(executor.workerLimit) == 0
		executor.mu.Unlock()
		if !idle {
			return false
		}
	}
	return true
}

type blockingAdmissionWritePath struct {
	transport.PathConn
	entered chan struct{}
	release chan struct{}
	block   atomic.Bool
	calls   atomic.Int32
}

func (path *blockingAdmissionWritePath) Write(frame []byte) (int, error) {
	path.calls.Add(1)
	if path.block.Load() {
		select {
		case path.entered <- struct{}{}:
		default:
		}
		<-path.release
	}
	return len(frame), nil
}

func testAdmissionWriteCallbackSingleFlight(t *testing.T) {
	path := &blockingAdmissionWritePath{
		entered: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	path.block.Store(true)
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(path.release) }) })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := writeAdmissionCtrlContext(ctx, path, proto.CtrlHello, nil)
	cancel()
	var deadlineErr *pathDispatchCallbackDeadlineError
	if !errors.As(err, &deadlineErr) || deadlineErr.operation != externalPathWriteOperation {
		t.Fatalf("blocked admission write error=%v want typed deadline", err)
	}
	select {
	case <-path.entered:
	default:
		t.Fatal("blocked admission write did not enter the PathConn callback")
	}

	started := time.Now()
	err = writeAdmissionCtrlContext(context.Background(), path, proto.CtrlHello, nil)
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("duplicate admission write blocked for %s", elapsed)
	}
	var busyErr *pathDispatchCallbackBusyError
	if !errors.As(err, &busyErr) || busyErr.operation != externalPathWriteOperation {
		t.Fatalf("duplicate admission write error=%v want typed busy", err)
	}
	if calls := path.calls.Load(); calls != 1 {
		t.Fatalf("blocked admission write callbacks=%d want=1", calls)
	}

	releaseOnce.Do(func() { close(path.release) })
	eventuallyEngine(t, time.Second, func() bool {
		return !externalPathCallbackInFlight(externalPathWriteOperation, path)
	})
	path.block.Store(false)
	if err := writeAdmissionCtrlContext(context.Background(), path, proto.CtrlHello, nil); err != nil {
		t.Fatalf("admission write did not recover after callback completion: %v", err)
	}
	if calls := path.calls.Load(); calls != 2 {
		t.Fatalf("recovered admission write callbacks=%d want=2", calls)
	}
}

func testExternalPathCallbackCapacity(t *testing.T) {
	leases := make([]*externalPathCallbackLease, 0, 3*externalPathCallbackClassLimit+externalPathAdmissionCallbackClassLimit)
	defer func() {
		for _, lease := range leases {
			lease.release()
		}
	}()
	for index := 0; index < externalPathCallbackClassLimit; index++ {
		lease, err := acquireExternalPathCallbackLease("capacity", &externalPathCallbackOwner{marker: byte(index)})
		if err != nil {
			t.Fatalf("lease %d: %v", index, err)
		}
		leases = append(leases, lease)
	}
	_, err := acquireExternalPathCallbackLease("capacity-overflow", &externalPathCallbackOwner{})
	var capacityErr *pathDispatchCallbackCapacityError
	if !errors.As(err, &capacityErr) {
		t.Fatalf("overflow error=%v want typed capacity error", err)
	}
	for index := 0; index < externalPathCallbackClassLimit; index++ {
		lease, err := acquireExternalPathCallbackLease(
			"PathConn.Close",
			&externalPathCallbackOwner{marker: byte(index)},
		)
		if err != nil {
			t.Fatalf("reserved cleanup lease %d: %v", index, err)
		}
		leases = append(leases, lease)
	}
	_, err = acquireExternalPathCallbackLease("PathConn.Close", &externalPathCallbackOwner{})
	if !errors.As(err, &capacityErr) {
		t.Fatalf("cleanup-capacity overflow error=%v want typed capacity error", err)
	}
	for index := 0; index < externalPathAdmissionCallbackClassLimit; index++ {
		lease, err := acquireExternalPathCallbackLease(
			externalPathReadOperation,
			&externalPathCallbackOwner{marker: byte(index)},
		)
		if err != nil {
			t.Fatalf("admission lease %d: %v", index, err)
		}
		leases = append(leases, lease)
	}
	_, err = acquireExternalPathCallbackLease(externalPathWriteOperation, &externalPathCallbackOwner{})
	if !errors.As(err, &capacityErr) {
		t.Fatalf("admission-capacity overflow error=%v want typed capacity error", err)
	}
}

type cleanupCapacityPath struct {
	transport.PathConn
	closed atomic.Int32
}

type blockingCleanupAuthorityPath struct {
	transport.PathConn
	release   <-chan struct{}
	calls     atomic.Int32
	started   *atomic.Int32
	active    *atomic.Int32
	maxActive *atomic.Int32
}

func (path *blockingCleanupAuthorityPath) Close() error {
	path.calls.Add(1)
	now := path.active.Add(1)
	for previous := path.maxActive.Load(); now > previous; previous = path.maxActive.Load() {
		if path.maxActive.CompareAndSwap(previous, now) {
			break
		}
	}
	path.started.Add(1)
	<-path.release
	path.active.Add(-1)
	return nil
}

func (path *cleanupCapacityPath) Close() error {
	path.closed.Add(1)
	if path.PathConn != nil {
		return path.PathConn.Close()
	}
	return nil
}

func TestPathCloseExecutesWhileOptionalCallbackCapacityIsSaturated(t *testing.T) {
	leases := make([]*externalPathCallbackLease, 0, externalPathCallbackClassLimit)
	defer func() {
		for _, lease := range leases {
			lease.release()
		}
	}()
	for index := 0; index < externalPathCallbackClassLimit; index++ {
		lease, err := acquireExternalPathCallbackLease(
			"PathConn.Diagnostics",
			&externalPathCallbackOwner{marker: byte(index)},
		)
		if err != nil {
			t.Fatalf("optional lease %d: %v", index, err)
		}
		leases = append(leases, lease)
	}

	path := &cleanupCapacityPath{}
	if err := closeExternalPathConn(path); err != nil {
		t.Fatalf("PathConn.Close under optional saturation: %v", err)
	}
	if got := path.closed.Load(); got != 1 {
		t.Fatalf("PathConn.Close calls=%d want=1", got)
	}
	var canceled atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	err := invokeLeafMobilityRefreshCancel(ctx, &externalPathCallbackOwner{}, func() { canceled.Add(1) })
	cancel()
	if err != nil || canceled.Load() != 1 {
		t.Fatalf("refresh cleanup under optional saturation calls/error=%d/%v want 1/nil", canceled.Load(), err)
	}

	t.Run("pre-canceled context still starts durable cancellation", func(t *testing.T) {
		owner := &externalPathCallbackOwner{}
		started := make(chan struct{})
		release := make(chan struct{})
		var calls atomic.Int32
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := invokeLeafMobilityRefreshCancel(ctx, owner, func() {
			calls.Add(1)
			close(started)
			<-release
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("pre-canceled invocation error=%v want context.Canceled", err)
		}
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("durable cancellation did not start after pre-cancellation")
		}
		if err := invokeLeafMobilityRefreshCancel(context.Background(), owner, func() {
			calls.Add(1)
		}); err == nil {
			t.Fatal("second cancellation acquired authority while first was unresolved")
		} else {
			var busy *pathDispatchCallbackBusyError
			if !errors.As(err, &busy) {
				t.Fatalf("second cancellation error=%v want busy", err)
			}
		}

		close(release)
		eventuallyEngine(t, time.Second, func() bool {
			externalPathDurableCallbacks.Lock()
			defer externalPathDurableCallbacks.Unlock()
			_, exists := externalPathDurableCallbacks.owners[externalPathCallbackKey{
				operation:  leafMobilityRefreshCancelOp,
				targetType: reflect.TypeOf(owner),
				target:     owner,
			}]
			return !exists
		})
		if got := calls.Load(); got != 1 {
			t.Fatalf("pre-canceled durable cancellation calls=%d want=1", got)
		}
	})

	t.Run("durable execution is bounded and class isolated", func(t *testing.T) {
		const cleanupCount = externalPathDurableCallbackWorkerLimit + 1
		baselineGoroutines := runtime.NumGoroutine()
		reservations := make([]*externalPathDurableCallbackReservation, cleanupCount)
		owners := make([]externalPathCallbackOwner, cleanupCount)
		releases := make([]chan struct{}, cleanupCount)
		releaseOnce := make([]sync.Once, cleanupCount)
		calls := make([]atomic.Int32, cleanupCount)
		var started atomic.Int32
		var active atomic.Int32
		var maxActive atomic.Int32
		releaseCleanup := func(index int) {
			releaseOnce[index].Do(func() { close(releases[index]) })
		}
		t.Cleanup(func() {
			for index := range releases {
				releaseCleanup(index)
			}
		})

		for index := 0; index < cleanupCount; index++ {
			owners[index] = externalPathCallbackOwner{marker: byte(index)}
			releases[index] = make(chan struct{})
			reservation, err := reserveExternalPathDurableCallback(
				externalPathCloseOperation, &owners[index],
			)
			if err != nil {
				t.Fatalf("reserve cleanup %d: %v", index, err)
			}
			reservations[index] = reservation
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			callbackIndex := index
			err = reservation.invoke(ctx, func() error {
				calls[callbackIndex].Add(1)
				now := active.Add(1)
				for previous := maxActive.Load(); now > previous; previous = maxActive.Load() {
					if maxActive.CompareAndSwap(previous, now) {
						break
					}
				}
				started.Add(1)
				<-releases[callbackIndex]
				active.Add(-1)
				return nil
			})
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("pre-canceled cleanup %d error=%v want context.Canceled", index, err)
			}
		}

		eventuallyEngine(t, time.Second, func() bool {
			return started.Load() == externalPathDurableCallbackWorkerLimit
		})
		if got := maxActive.Load(); got > externalPathDurableCallbackWorkerLimit {
			t.Fatalf("concurrent cleanup callbacks=%d limit=%d", got, externalPathDurableCallbackWorkerLimit)
		}
		if got := calls[cleanupCount-1].Load(); got != 0 {
			t.Fatalf("queued cleanup calls=%d want=0 before a worker is released", got)
		}
		if delta := runtime.NumGoroutine() - baselineGoroutines; delta > externalPathDurableCallbackWorkerLimit+4 {
			t.Fatalf("blocked durable cleanup goroutine delta=%d want<=%d", delta, externalPathDurableCallbackWorkerLimit+4)
		}

		cancelOwner := &externalPathCallbackOwner{}
		cancelReservation, err := reserveExternalPathDurableCallback(
			leafMobilityRefreshCancelOp, cancelOwner,
		)
		if err != nil {
			t.Fatal(err)
		}
		cancelStarted := make(chan struct{})
		cancelRelease := make(chan struct{})
		var cancelReleaseOnce sync.Once
		releaseCancellation := func() { cancelReleaseOnce.Do(func() { close(cancelRelease) }) }
		t.Cleanup(releaseCancellation)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err = cancelReservation.invoke(ctx, func() error {
			close(cancelStarted)
			<-cancelRelease
			return nil
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("pre-canceled cancellation error=%v want context.Canceled", err)
		}
		select {
		case <-cancelStarted:
		case <-time.After(time.Second):
			t.Fatal("cancellation execution starved behind saturated cleanup execution")
		}

		releaseCleanup(0)
		eventuallyEngine(t, time.Second, func() bool { return started.Load() == cleanupCount })
		if got := calls[cleanupCount-1].Load(); got != 1 {
			t.Fatalf("queued cleanup calls after release=%d want=1", got)
		}
		for index := 1; index < cleanupCount; index++ {
			releaseCleanup(index)
		}
		releaseCancellation()
		for index, reservation := range reservations {
			select {
			case <-reservation.completion():
			case <-time.After(time.Second):
				t.Fatalf("cleanup reservation %d did not complete", index)
			}
			if got := calls[index].Load(); got != 1 {
				t.Fatalf("cleanup callback %d calls=%d want=1", index, got)
			}
		}
		select {
		case <-cancelReservation.completion():
		case <-time.After(time.Second):
			t.Fatal("cancellation reservation did not complete")
		}
		eventuallyEngine(t, time.Second, func() bool { return active.Load() == 0 })
	})

	t.Run("reservation lifecycle rejects released double and uncounted invoke", func(t *testing.T) {
		owner := &externalPathCallbackOwner{}
		reservation, err := reserveExternalPathDurableCallback(externalPathCloseOperation, owner)
		if err != nil {
			t.Fatal(err)
		}
		var hookCalls atomic.Int32
		if err := reservation.onCompletion(func(completion externalPathDurableCallbackCompletion) {
			hookCalls.Add(1)
			if completion.State != externalPathDurableCallbackReleased || completion.Terminal != nil {
				t.Errorf("released completion=%+v", completion)
			}
		}); err != nil {
			t.Fatal(err)
		}
		if err := reservation.releaseReservation(); err != nil {
			t.Fatal(err)
		}
		var callbackCalls atomic.Int32
		err = reservation.invoke(context.Background(), func() error {
			callbackCalls.Add(1)
			return nil
		})
		var stateErr *externalPathDurableCallbackStateError
		if !errors.As(err, &stateErr) || stateErr.state != externalPathDurableCallbackReleased {
			t.Fatalf("invoke-after-release error=%v want released state error", err)
		}
		if hookCalls.Load() != 1 || callbackCalls.Load() != 0 {
			t.Fatalf("released hook/callback calls=%d/%d want 1/0", hookCalls.Load(), callbackCalls.Load())
		}

		queuedOwner := &externalPathCallbackOwner{marker: 1}
		queued, err := reserveExternalPathDurableCallback(externalPathCloseOperation, queuedOwner)
		if err != nil {
			t.Fatal(err)
		}
		release := make(chan struct{})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := queued.invoke(ctx, func() error {
			callbackCalls.Add(1)
			<-release
			return nil
		}); !errors.Is(err, context.Canceled) {
			t.Fatalf("first queued invocation error=%v", err)
		}
		err = queued.invoke(context.Background(), func() error {
			callbackCalls.Add(1)
			return nil
		})
		if !errors.As(err, &stateErr) || stateErr.state != externalPathDurableCallbackQueued {
			t.Fatalf("double invocation error=%v want queued state error", err)
		}
		close(release)
		select {
		case <-queued.completion():
		case <-time.After(time.Second):
			t.Fatal("queued reservation did not complete")
		}
		if got := callbackCalls.Load(); got != 1 {
			t.Fatalf("double invocation callback calls=%d want=1", got)
		}

		uncounted := &externalPathDurableCallbackReservation{
			operation: externalPathCloseOperation,
			class:     externalPathDurableCleanup,
			done:      make(chan struct{}),
		}
		uncounted.state.Store(uint32(externalPathDurableCallbackQueued))
		err = externalPathDurableCallbackExecutors[externalPathDurableCleanup].enqueue(
			&externalPathDurableCallbackJob{
				reservation: uncounted,
				callback: func() error {
					callbackCalls.Add(1)
					return nil
				},
			},
		)
		if !errors.As(err, &stateErr) || stateErr.action != "enqueue without counted authority" {
			t.Fatalf("uncounted enqueue error=%v want state error", err)
		}
		time.Sleep(10 * time.Millisecond)
		if got := callbackCalls.Load(); got != 1 {
			t.Fatalf("uncounted callback executed: total calls=%d want=1", got)
		}
	})

	t.Run("production admission rejects are bounded without completion waiters", func(t *testing.T) {
		const pathCount = externalPathDurableCallbackWorkerLimit + 1
		engines := make([]*Engine, pathCount)
		for index := range engines {
			engines[index] = New(SideClient, NewClientFlowID(), Limits{}.Clamp())
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
		paths := make([]*blockingCleanupAuthorityPath, pathCount)
		results := make(chan error, pathCount)
		var callers sync.WaitGroup
		callers.Add(pathCount)
		for index := range paths {
			path := &blockingCleanupAuthorityPath{
				release: release, started: &started, active: &active, maxActive: &maxActive,
			}
			paths[index] = path
			engine := engines[index]
			go func() {
				defer callers.Done()
				_, adopted, err := engine.PreparePathBoundWithOwnership(
					path,
					transport.PathSpec{Transport: "invalid-admission"},
					PathBinding{LocalTXTargetID: proto.TargetID{1}},
				)
				if !adopted || err == nil {
					results <- fmt.Errorf("adopted/error=%t/%v want true/non-nil", adopted, err)
					return
				}
				results <- nil
			}()
		}
		eventuallyEngine(t, time.Second, func() bool {
			return started.Load() == externalPathDurableCallbackWorkerLimit
		})
		for index := 0; index < pathCount; index++ {
			select {
			case err := <-results:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("production admission reject did not return within callback budget")
			}
		}
		callers.Wait()
		if got := maxActive.Load(); got > externalPathDurableCallbackWorkerLimit {
			t.Fatalf("admission cleanup active=%d limit=%d", got, externalPathDurableCallbackWorkerLimit)
		}
		if delta := runtime.NumGoroutine() - baselineGoroutines; delta > externalPathDurableCallbackWorkerLimit+5 {
			t.Fatalf("admission reject goroutine delta=%d want<=%d", delta, externalPathDurableCallbackWorkerLimit+5)
		}
		unblock()
		eventuallyEngine(t, time.Second, func() bool { return started.Load() == pathCount && active.Load() == 0 })
		for index, path := range paths {
			if got := path.calls.Load(); got != 1 {
				t.Fatalf("admission path %d close calls=%d want=1", index, got)
			}
		}
		for index, engine := range engines {
			_ = engine.Close()
			select {
			case <-engine.Closed():
			case <-time.After(time.Second):
				t.Fatalf("admission engine %d cleanup hook did not release Close tracking", index)
			}
		}
	})
}

func TestOwnedPathCloseExecutesWhileOrdinaryCleanupCapacityIsSaturated(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	base, peer := newMemoryPathPair()
	defer func() {
		_ = e.Close()
		_ = peer.Close()
	}()
	path := &cleanupCapacityPath{PathConn: base}
	if _, err := e.AttachPath(path, transport.PathSpec{Transport: "memory"}); err != nil {
		_ = e.Close()
		_ = peer.Close()
		t.Fatal(err)
	}
	leases := make([]*externalPathCallbackLease, 0, externalPathCallbackClassLimit)
	defer func() {
		for _, lease := range leases {
			lease.release()
		}
	}()
	for index := 0; index < externalPathCallbackClassLimit; index++ {
		lease, err := acquireExternalPathCallbackLease(
			externalPathCloseOperation,
			&externalPathCallbackOwner{marker: byte(index)},
		)
		if err != nil {
			for _, held := range leases {
				held.release()
			}
			_ = e.Close()
			_ = peer.Close()
			t.Fatalf("ordinary cleanup lease %d: %v", index, err)
		}
		leases = append(leases, lease)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("reserved owned path close: %v", err)
	}
	if got := path.closed.Load(); got != 1 {
		t.Fatalf("reserved PathConn.Close calls=%d want=1", got)
	}
}

func TestPathCleanupReservationCapacityRejectsBeforeOwnership(t *testing.T) {
	externalPathDurableCallbacks.Lock()
	baseline := externalPathDurableCallbacks.classInflight[externalPathDurableCleanup]
	previousLimit := externalPathDurableCallbacks.classLimit[externalPathDurableCleanup]
	externalPathDurableCallbacks.classLimit[externalPathDurableCleanup] = baseline + 1
	externalPathDurableCallbacks.Unlock()
	defer func() {
		externalPathDurableCallbacks.Lock()
		externalPathDurableCallbacks.classLimit[externalPathDurableCleanup] = previousLimit
		externalPathDurableCallbacks.Unlock()
	}()

	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	first, firstPeer := newMemoryPathPair()
	defer func() {
		_ = e.Close()
		_ = firstPeer.Close()
	}()
	firstID, err := e.PreparePathBound(first, transport.PathSpec{Transport: "memory"}, PathBinding{})
	if err != nil {
		_ = e.Close()
		_ = firstPeer.Close()
		t.Fatal(err)
	}
	secondBase, secondPeer := newMemoryPathPair()
	second := &cleanupCapacityPath{PathConn: secondBase}
	defer func() {
		_ = secondPeer.Close()
	}()
	_, adopted, err := e.PreparePathBoundWithOwnership(second, transport.PathSpec{Transport: "memory"}, PathBinding{})
	var capacityErr *pathDispatchCallbackCapacityError
	if !errors.As(err, &capacityErr) || capacityErr.operation != externalPathCloseOperation {
		t.Fatalf("second admission error=%v want cleanup capacity", err)
	}
	if adopted {
		t.Fatal("capacity-rejected path reported engine ownership")
	}
	if got := second.closed.Load(); got != 0 {
		t.Fatalf("capacity-rejected path was adopted/closed %d times", got)
	}

	e.AbortPathAttach(firstID, errors.New("release cleanup reservation"))
	eventuallyEngine(t, time.Second, func() bool {
		externalPathDurableCallbacks.Lock()
		defer externalPathDurableCallbacks.Unlock()
		return externalPathDurableCallbacks.classInflight[externalPathDurableCleanup] == baseline
	})
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if got := second.closed.Load(); got != 1 {
		t.Fatalf("caller-owned PathConn.Close calls=%d want=1", got)
	}
	_ = firstPeer.Close()
	_ = secondPeer.Close()
}

func TestPathCleanupReservationsPreserveCrossEngineScaleAboveOrdinaryLimit(t *testing.T) {
	const pathsPerEngine = externalPathCallbackClassLimit/2 + 1
	engines := []*Engine{
		New(SideClient, NewClientFlowID(), Limits{}.Clamp()),
		New(SideClient, NewClientFlowID(), Limits{}.Clamp()),
	}
	peers := make([]transport.PathConn, 0, len(engines)*pathsPerEngine)
	defer func() {
		for _, engine := range engines {
			_ = engine.Close()
		}
		for _, peer := range peers {
			_ = peer.Close()
		}
	}()
	for engineIndex, engine := range engines {
		for pathIndex := 0; pathIndex < pathsPerEngine; pathIndex++ {
			path, peer := newMemoryPathPair()
			peers = append(peers, peer)
			if _, err := engine.AttachPathBound(
				path, transport.PathSpec{Transport: "memory"}, PathBinding{},
			); err != nil {
				for _, owned := range engines {
					_ = owned.Close()
				}
				for _, remote := range peers {
					_ = remote.Close()
				}
				t.Fatalf("engine %d path %d: %v", engineIndex, pathIndex, err)
			}
		}
	}
	if total := len(engines) * pathsPerEngine; total <= externalPathCallbackClassLimit {
		t.Fatalf("invalid cross-engine stimulus: total=%d", total)
	}
	for _, engine := range engines {
		if err := engine.Close(); err != nil {
			t.Fatalf("cross-engine close: %v", err)
		}
	}
	for _, peer := range peers {
		_ = peer.Close()
	}
}

func TestNonComparableExternalCallbackTargetsDoNotShareSingleFlight(t *testing.T) {
	const operation = "test.non-comparable-target"
	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	firstContext, cancelFirst := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelFirst()

	_, err := invokeExternalPathValueCallbackContext(
		firstContext,
		operation,
		[]byte("first"),
		func() int {
			close(entered)
			<-release
			return 1
		},
	)
	var deadlineErr *pathDispatchCallbackDeadlineError
	if !errors.As(err, &deadlineErr) {
		t.Fatalf("first callback error=%v want typed deadline", err)
	}
	select {
	case <-entered:
	default:
		t.Fatal("first non-comparable callback did not enter")
	}

	secondContext, cancelSecond := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelSecond()
	value, err := invokeExternalPathValueCallbackContext(
		secondContext,
		operation,
		[]byte("second"),
		func() int { return 2 },
	)
	if err != nil || value != 2 {
		t.Fatalf("independent non-comparable callback value/error=%d/%v want 2/nil", value, err)
	}

	t.Run("same path generation retains exact committer authority", func(t *testing.T) {
		state := &nonComparableRefreshCommitterState{
			entered: make(chan struct{}),
			release: make(chan struct{}),
		}
		path := nonComparableRefreshCommitter{state}
		authority := &externalPathCallbackOwner{}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		err := invokeLeafMobilityRefreshCommitter(ctx, authority, path, leafmobility.RefreshEvidence{})
		cancel()
		var deadlineErr *pathDispatchCallbackDeadlineError
		if !errors.As(err, &deadlineErr) {
			t.Fatalf("first committer error=%v want typed deadline", err)
		}
		select {
		case <-state.entered:
		default:
			t.Fatal("first non-comparable committer did not enter")
		}

		started := time.Now()
		err = invokeLeafMobilityRefreshCommitter(
			context.Background(), authority, path, leafmobility.RefreshEvidence{},
		)
		if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
			t.Fatalf("duplicate committer blocked for %s", elapsed)
		}
		var busyErr *pathDispatchCallbackBusyError
		if !errors.As(err, &busyErr) || state.calls.Load() != 1 {
			t.Fatalf("duplicate committer error/calls=%v/%d want busy/1", err, state.calls.Load())
		}

		close(state.release)
		eventuallyEngine(t, time.Second, func() bool {
			return !externalPathCallbackInFlight(leafMobilityRefreshCommitOp, authority)
		})
		if err := invokeLeafMobilityRefreshCommitter(
			context.Background(), authority, path, leafmobility.RefreshEvidence{},
		); err != nil {
			t.Fatalf("committer authority did not recover: %v", err)
		}
		if got := state.calls.Load(); got != 2 {
			t.Fatalf("committer calls=%d want=2", got)
		}
	})
}

type nonComparableRefreshCommitter []*nonComparableRefreshCommitterState

type nonComparableRefreshCommitterState struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	calls   atomic.Int32
}

func (path nonComparableRefreshCommitter) Read([]byte) (int, error) { return 0, io.EOF }
func (path nonComparableRefreshCommitter) Write(frame []byte) (int, error) {
	return len(frame), nil
}
func (path nonComparableRefreshCommitter) Close() error { return nil }
func (path nonComparableRefreshCommitter) Quality() transport.PathQuality {
	return transport.PathQuality{}
}
func (path nonComparableRefreshCommitter) LocalAddr() string                         { return "non-comparable-local" }
func (path nonComparableRefreshCommitter) RemoteAddr() string                        { return "non-comparable-remote" }
func (path nonComparableRefreshCommitter) OnDeath(func(transport.DeathCause, error)) {}
func (path nonComparableRefreshCommitter) CommitLeafMobilityRefresh(leafmobility.RefreshEvidence) error {
	state := path[0]
	state.calls.Add(1)
	state.once.Do(func() { close(state.entered) })
	<-state.release
	return nil
}

type blockingMaxFramePath struct {
	transport.PathConn
	entered    chan struct{}
	release    chan struct{}
	closeEnter chan struct{}
	once       sync.Once
	closeOnce  sync.Once
	calls      atomic.Int32
	closeCalls atomic.Int32
}

type fixedMaxFramePath struct {
	transport.PathConn
	limit int
}

func (path *fixedMaxFramePath) MaxFrameSize() int { return path.limit }

func (path *blockingMaxFramePath) MaxFrameSize() int {
	path.calls.Add(1)
	path.once.Do(func() { close(path.entered) })
	<-path.release
	return 1500
}

func (path *blockingMaxFramePath) Close() error {
	path.closeCalls.Add(1)
	if path.closeEnter != nil {
		path.closeOnce.Do(func() { close(path.closeEnter) })
	}
	if path.PathConn == nil {
		return nil
	}
	return path.PathConn.Close()
}

func TestMaxFrameSizeBlockIsBoundedAndSingleFlight(t *testing.T) {
	base, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = base.Close(); _ = peer.Close() })
	path := &blockingMaxFramePath{
		PathConn: base, entered: make(chan struct{}), release: make(chan struct{}),
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(path.release) }) }
	t.Cleanup(release)
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	e.SetPacketMode()
	t.Cleanup(func() { _ = e.Close() })

	type result struct {
		limit int
		set   bool
		err   error
	}
	authority := &externalPathCallbackOwner{}
	first := make(chan result, 1)
	go func() {
		limit, set, err := e.validatePacketPathFrameLimit(path, PathBinding{LocalReceiveFrameCapacity: 1500, PeerReceiveFrameCapacity: 1500}, authority)
		first <- result{limit: limit, set: set, err: err}
	}()
	select {
	case got := <-first:
		var deadlineErr *pathDispatchCallbackDeadlineError
		if !errors.As(got.err, &deadlineErr) || got.limit != 0 || got.set {
			t.Fatalf("blocked MaxFrameSize result=%+v want typed deadline", got)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("blocked MaxFrameSize held packet admission")
	}
	select {
	case <-path.entered:
	default:
		t.Fatal("MaxFrameSize callback did not enter")
	}
	_, _, err := e.validatePacketPathFrameLimit(path, PathBinding{LocalReceiveFrameCapacity: 1500, PeerReceiveFrameCapacity: 1500}, authority)
	var busyErr *pathDispatchCallbackBusyError
	if !errors.As(err, &busyErr) || path.calls.Load() != 1 {
		t.Fatalf("second MaxFrameSize error/calls=%v/%d want typed busy/1", err, path.calls.Load())
	}
	otherBase, otherPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = otherBase.Close(); _ = otherPeer.Close() })
	other := &fixedMaxFramePath{PathConn: otherBase, limit: 1500}
	limit, set, err := e.validatePacketPathFrameLimit(other, PathBinding{LocalReceiveFrameCapacity: 1500, PeerReceiveFrameCapacity: 1500}, &externalPathCallbackOwner{})
	if err != nil || !set || limit != 1500 {
		t.Fatalf("blocked path poisoned independent target: limit/set/error=%d/%t/%v", limit, set, err)
	}
	release()
	eventuallyEngine(t, time.Second, func() bool {
		return !externalPathCallbackInFlight("PathConn.MaxFrameSize", path)
	})

	t.Run("rejected admission retains exact-generation callback authority", func(t *testing.T) {
		base, peer := newMemoryPathPair()
		path := &blockingMaxFramePath{
			PathConn: base, entered: make(chan struct{}), release: make(chan struct{}),
			closeEnter: make(chan struct{}),
		}
		e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
		e.SetPacketMode()
		var releaseOnce sync.Once
		release := func() { releaseOnce.Do(func() { close(path.release) }) }
		var permits []*externalPathRetirementPermit
		t.Cleanup(func() {
			release()
			releaseExternalPathRetirementPermits(permits)
			_ = e.Close()
			_ = peer.Close()
		})

		type prepareResult struct {
			adopted bool
			err     error
		}
		prepared := make(chan prepareResult, 1)
		go func() {
			_, adopted, err := e.PreparePathBoundWithOwnership(
				path,
				transport.PathSpec{Transport: "blocked-frame-limit"},
				PathBinding{LocalReceiveFrameCapacity: 1500, PeerReceiveFrameCapacity: 1500},
			)
			prepared <- prepareResult{adopted: adopted, err: err}
		}()
		select {
		case <-path.entered:
		case <-time.After(time.Second):
			t.Fatal("admission MaxFrameSize callback did not enter")
		}
		if got := path.calls.Load(); got != 1 {
			t.Fatalf("MaxFrameSize stimulus calls=%d want 1", got)
		}
		permits = saturateExternalPathRetirementCapacity(t)
		var result prepareResult
		select {
		case result = <-prepared:
		case <-time.After(time.Second):
			t.Fatal("blocked MaxFrameSize admission did not return its bounded result")
		}
		var deadlineErr *pathDispatchCallbackDeadlineError
		if !result.adopted || !errors.As(result.err, &deadlineErr) || deadlineErr.operation != "PathConn.MaxFrameSize" {
			t.Fatalf("blocked admission adopted/error=%t/%v want true/MaxFrameSize deadline", result.adopted, result.err)
		}

		closed := make(chan error, 1)
		go func() { closed <- e.Close() }()
		select {
		case <-path.closeEnter:
			t.Fatal("rejected carrier closed while exact-generation MaxFrameSize was still running")
		case <-time.After(2 * externalPathValueCallbackTimeout):
		}
		select {
		case <-e.Closed():
			t.Fatal("Engine.Closed closed while exact-generation MaxFrameSize was still running")
		default:
		}
		assertExternalPathRetirementCapacityExhausted(t)

		release()
		select {
		case <-path.closeEnter:
		case <-time.After(time.Second):
			t.Fatal("rejected carrier close did not follow MaxFrameSize completion")
		}
		eventuallyEngine(t, time.Second, func() bool { return path.closeCalls.Load() == 1 })
		var permit *externalPathRetirementPermit
		eventuallyEngine(t, time.Second, func() bool {
			var err error
			permit, err = externalPathRetirements.reserve()
			return err == nil
		})
		permit.release()
		select {
		case <-e.Closed():
		case <-time.After(time.Second):
			t.Fatal("Engine.Closed did not close after MaxFrameSize cleanup")
		}
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("Engine.Close did not return after MaxFrameSize cleanup")
		}
		if got := path.closeCalls.Load(); got != 1 {
			t.Fatalf("rejected carrier close calls=%d want 1", got)
		}
		if got := path.calls.Load(); got != 1 {
			t.Fatalf("MaxFrameSize stimulus calls after cleanup=%d want 1", got)
		}
	})
}

type blockingDiagnosticPath struct {
	transport.PathConn
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	calls   atomic.Int32
}

func (path *blockingDiagnosticPath) LocalAddr() string {
	path.calls.Add(1)
	path.once.Do(func() { close(path.entered) })
	<-path.release
	return "late-local"
}

func TestPathDiagnosticsBlockKeepsCoreStatusAndBoundsOrphans(t *testing.T) {
	base, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = base.Close(); _ = peer.Close() })
	path := &blockingDiagnosticPath{
		PathConn: base, entered: make(chan struct{}), release: make(chan struct{}),
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(path.release) }) }
	t.Cleanup(release)
	slot := &pathSlot{id: 77, owner: 88, conn: path, attached: time.Unix(9, 0)}
	slot.dataWrites.Store(12)

	result := make(chan []transport.PathInfo, 1)
	go func() { result <- pathInfos([]*pathSlot{slot}, slot.id, time.Second) }()
	var infos []transport.PathInfo
	select {
	case infos = <-result:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("blocked diagnostics held PathInfo status")
	}
	if len(infos) != 1 || infos[0].ID != slot.id || !infos[0].Active || infos[0].DataWrites != 12 ||
		infos[0].LocalAddr != "" || infos[0].RemoteAddr != "" {
		t.Fatalf("bounded diagnostic fallback=%+v", infos)
	}
	select {
	case <-path.entered:
	default:
		t.Fatal("diagnostic callback did not enter")
	}
	infos = pathInfos([]*pathSlot{slot}, slot.id, time.Second)
	if len(infos) != 1 || path.calls.Load() != 1 {
		t.Fatalf("second diagnostic status/calls=%+v/%d", infos, path.calls.Load())
	}
	release()
	eventuallyEngine(t, time.Second, func() bool {
		return !externalPathCallbackInFlight("PathConn.Diagnostics", path)
	})
}

type abnormalByeMarkerPath struct {
	transport.PathConn
	mode    string
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	calls   atomic.Int32
	onEnter func()
}

type aggregateByeMarkerPath struct {
	transport.PathConn
	calls   *atomic.Int32
	release <-chan struct{}
}

func (path *aggregateByeMarkerPath) MarkByeSeen() {
	path.calls.Add(1)
	if path.release != nil {
		<-path.release
	}
}

func TestMarkPeerByeSeenSkipsGenerationRetiredAfterSnapshot(t *testing.T) {
	firstBase, firstPeer := newMemoryPathPair()
	secondBase, secondPeer := newMemoryPathPair()
	defer func() {
		_ = firstBase.Close()
		_ = firstPeer.Close()
		_ = secondBase.Close()
		_ = secondPeer.Close()
	}()
	var firstCalls, retiredCalls atomic.Int32
	first := &aggregateByeMarkerPath{PathConn: firstBase, calls: &firstCalls}
	retired := &aggregateByeMarkerPath{PathConn: secondBase, calls: &retiredCalls}
	e := &Engine{paths: map[uint32]*pathSlot{
		1: {id: 1, owner: 11, conn: first},
		2: {id: 2, owner: 22, conn: retired},
	}}
	e.markPeerByeSeenAfterSnapshot = func() {
		e.pathsMu.Lock()
		delete(e.paths, 2)
		e.pathsMu.Unlock()
	}
	e.markPeerByeSeen()
	if got := firstCalls.Load(); got != 1 {
		t.Fatalf("current generation calls=%d want=1", got)
	}
	if got := retiredCalls.Load(); got != 0 {
		t.Fatalf("retired generation calls=%d want=0", got)
	}
}

func TestMarkPeerByeSeenRejectsRetiredGenerationAuthority(t *testing.T) {
	base, peer := newMemoryPathPair()
	defer func() {
		_ = base.Close()
		_ = peer.Close()
	}()
	var calls atomic.Int32
	path := &aggregateByeMarkerPath{PathConn: base, calls: &calls}
	slot := &pathSlot{id: 1, owner: 11, conn: path}
	e := &Engine{paths: map[uint32]*pathSlot{slot.id: slot}}
	e.markPeerByeSeenAfterSnapshot = slot.retireByeCallbacks

	e.markPeerByeSeen()
	if got := calls.Load(); got != 0 {
		t.Fatalf("retired exact-generation callback calls=%d want=0", got)
	}
	if externalPathCallbackInFlight("PathConn.MarkByeSeen", path) {
		t.Fatal("rejected retired generation retained callback authority")
	}
}

func TestMarkPeerByeSeenUsesOneAggregateDeadline(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	var calls atomic.Int32
	e := &Engine{paths: make(map[uint32]*pathSlot, maxSessionPaths)}
	paths := make([]*aggregateByeMarkerPath, 0, maxSessionPaths)
	peers := make([]transport.PathConn, 0, maxSessionPaths)
	for index := 0; index < maxSessionPaths; index++ {
		base, peer := newMemoryPathPair()
		path := &aggregateByeMarkerPath{PathConn: base, calls: &calls, release: release}
		id := uint32(index + 1)
		e.paths[id] = &pathSlot{id: id, owner: uint64(index + 101), conn: path}
		paths = append(paths, path)
		peers = append(peers, peer)
	}
	defer func() {
		for _, path := range paths {
			_ = path.Close()
		}
		for _, peer := range peers {
			_ = peer.Close()
		}
	}()

	started := time.Now()
	e.markPeerByeSeen()
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("aggregate MarkByeSeen took %s", elapsed)
	}
	eventuallyEngine(t, time.Second, func() bool { return calls.Load() == maxSessionPaths })
	if !externalPathCallbackInFlight("PathConn.MarkByeSeen", paths[0]) {
		t.Fatal("blocked marker was falsely reported as drained after aggregate timeout")
	}
	unblock()
	eventuallyEngine(t, time.Second, func() bool {
		for _, path := range paths {
			if externalPathCallbackInFlight("PathConn.MarkByeSeen", path) {
				return false
			}
		}
		return true
	})
}

func TestBlockedMarkPeerByeSeenKeepsEngineUnquiesced(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: time.Hour}.Clamp())
	ids := configureLeafSelectorRuntime(t, e, "bye-blocked")
	base, peer := newMemoryPathPair()
	defer func() { _ = peer.Close() }()
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer func() {
		unblock()
		_ = e.Close()
	}()
	var calls atomic.Int32
	path := &aggregateByeMarkerPath{PathConn: base, calls: &calls, release: release}
	_ = attachFixturePath(
		t, e, path, transport.PathSpec{Transport: "blocked-bye"}, ids["bye-blocked"],
	)

	e.markPeerByeSeen()
	if calls.Load() != 1 || !externalPathCallbackInFlight("PathConn.MarkByeSeen", path) {
		t.Fatalf("blocked BYE stimulus calls/inflight=%d/%t want 1/true",
			calls.Load(), externalPathCallbackInFlight("PathConn.MarkByeSeen", path))
	}
	started := time.Now()
	err := e.Close()
	if elapsed := time.Since(started); elapsed > pathCloseTimeout+150*time.Millisecond {
		t.Fatalf("bounded Close took %s", elapsed)
	}
	var teardownDeadline *engineTeardownDeadlineError
	if !errors.As(err, &teardownDeadline) {
		t.Fatalf("Close error=%v want typed teardown deadline", err)
	}
	select {
	case <-e.Closed():
		t.Fatal("engine quiesced while exact-generation BYE callback was alive")
	default:
	}

	unblock()
	select {
	case <-e.Closed():
	case <-time.After(time.Second):
		t.Fatal("engine did not quiesce after BYE callback exited")
	}
}

func (path *abnormalByeMarkerPath) MarkByeSeen() {
	path.calls.Add(1)
	path.once.Do(func() { close(path.entered) })
	if path.onEnter != nil {
		path.onEnter()
	}
	switch path.mode {
	case "panic":
		panic("MarkByeSeen panic")
	case "goexit":
		runtime.Goexit()
	case "block":
		<-path.release
	}
}

func TestMarkByeSeenAbnormalExitRetiresExactGeneration(t *testing.T) {
	for _, mode := range []string{"panic", "goexit", "block"} {
		t.Run(mode, func(t *testing.T) {
			e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: time.Hour}.Clamp())
			t.Cleanup(func() { _ = e.Close() })
			ids := configureLeafSelectorRuntime(t, e, "bad-bye", "healthy-bye")
			badBase, badPeer := newMemoryPathPair()
			healthy, healthyPeer := newMemoryPathPair()
			t.Cleanup(func() { _ = badPeer.Close(); _ = healthyPeer.Close() })
			path := &abnormalByeMarkerPath{
				PathConn: badBase, mode: mode, entered: make(chan struct{}), release: make(chan struct{}),
			}
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(path.release) }) }
			t.Cleanup(release)
			badID := attachFixturePath(t, e, path, transport.PathSpec{Transport: "bad-bye"}, ids["bad-bye"])
			healthyID := attachFixturePath(t, e, healthy, transport.PathSpec{Transport: "healthy-bye"}, ids["healthy-bye"])
			e.pathsMu.RLock()
			badSlot := e.paths[badID]
			healthySlot := e.paths[healthyID]
			e.pathsMu.RUnlock()
			if badSlot == nil || healthySlot == nil {
				t.Fatal("missing BYE test paths")
			}
			death := make(chan PathDeathEvent, 1)
			cancelDeath := e.OnPathDeathSerial(func(event PathDeathEvent) {
				if event.ID == badID {
					death <- event
				}
			})
			defer cancelDeath()

			started := time.Now()
			e.markPathByeSeen(badSlot)
			if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
				t.Fatalf("MarkByeSeen %s returned after %s", mode, elapsed)
			}
			select {
			case <-path.entered:
			default:
				t.Fatal("MarkByeSeen callback did not enter")
			}
			var event PathDeathEvent
			select {
			case event = <-death:
			case <-time.After(time.Second):
				t.Fatal("abnormal MarkByeSeen did not retire its path")
			}
			if event.Owner != badSlot.owner || event.Cause != transport.CauseTransportError {
				t.Fatalf("BYE death owner/cause=%d/%v want %d/transport", event.Owner, event.Cause, badSlot.owner)
			}
			if mode == "panic" {
				var panicErr *pathDispatchCallbackPanicError
				if !errors.As(event.Err, &panicErr) || panicErr.operation != "PathConn.MarkByeSeen" {
					t.Fatalf("BYE panic error=%v", event.Err)
				}
			} else if mode == "goexit" {
				var goexitErr *pathDispatchCallbackGoexitError
				if !errors.As(event.Err, &goexitErr) || goexitErr.operation != "PathConn.MarkByeSeen" {
					t.Fatalf("BYE Goexit error=%v", event.Err)
				}
			} else {
				var deadlineErr *pathDispatchCallbackDeadlineError
				if !errors.As(event.Err, &deadlineErr) || deadlineErr.operation != "PathConn.MarkByeSeen" {
					t.Fatalf("BYE block error=%v", event.Err)
				}
			}
			e.pathsMu.RLock()
			_, badPresent := e.paths[badID]
			currentHealthy := e.paths[healthyID]
			e.pathsMu.RUnlock()
			if badPresent || currentHealthy != healthySlot || path.calls.Load() != 1 {
				t.Fatalf("post-BYE bad/healthy/calls=%t/%t/%d", badPresent, currentHealthy == healthySlot, path.calls.Load())
			}
			release()
		})
	}

	for _, mode := range []string{"panic", "block"} {
		t.Run("actual-ctrl-bye-"+mode, func(t *testing.T) {
			e := New(SideClient, NewClientFlowID(), Limits{
				ProbeInterval:       time.Hour,
				ZombieMaxMigrations: 2,
				ZombieCooldown:      time.Hour,
			}.Clamp())
			ids := configureLeafSelectorRuntime(t, e, "bye-carrier", "survivor")
			badBase, badPeer := newMemoryPathPair()
			healthy, healthyPeer := newMemoryPathPair()
			path := &abnormalByeMarkerPath{
				PathConn: badBase, mode: mode, entered: make(chan struct{}), release: make(chan struct{}),
			}
			var terminalPublishedBeforeCallback atomic.Bool
			var eofGateOpenedBeforeCallback atomic.Bool
			var (
				deathInjectedDuringCallback atomic.Bool
				ackSeenAtCallbackEntry      atomic.Bool
				eofSeenDuringCallback       atomic.Bool
			)
			callbackWindowObserved := make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(path.release) }) }
			t.Cleanup(func() {
				release()
				_ = badPeer.Close()
				_ = healthyPeer.Close()
				_ = e.Close()
			})
			badID := attachFixturePath(t, e, path, transport.PathSpec{Transport: "bye-carrier"}, ids["bye-carrier"])
			_ = attachFixturePath(t, e, healthy, transport.PathSpec{Transport: "survivor"}, ids["survivor"])
			readResult := make(chan error, 1)
			go func() {
				_, err := e.Recv(make([]byte, 1))
				readResult <- err
			}()
			path.onEnter = func() {
				terminalPublishedBeforeCallback.Store(e.policyTerminal.Load())
				eofGateOpenedBeforeCallback.Store(e.peerNormalBye.Load())
				if mode == "block" {
					injectedErr := errors.New("physical path death during MarkByeSeen")
					badBase.Fail(injectedErr)
					badBase.notifyFailure(injectedErr)
					deathInjectedDuringCallback.Store(true)
				}
				healthy.framesMu.Lock()
				for _, header := range healthy.frames {
					if header.Type == proto.FrameCtrl && proto.CtrlCodeFromFlags(header.Flags) == proto.CtrlPathProbeReply {
						ackSeenAtCallbackEntry.Store(true)
						break
					}
				}
				healthy.framesMu.Unlock()
				select {
				case <-readResult:
					eofSeenDuringCallback.Store(true)
				default:
				}
				close(callbackWindowObserved)
			}

			e.zombieMu.Lock()
			zombieLeftBefore := e.zombieLeft
			zombieGenerationBefore := e.zombieGeneration
			zombieLastMigrationBefore := e.zombieLastMig
			e.zombieMu.Unlock()

			death := make(chan PathDeathEvent, 1)
			cancelDeath := e.OnPathDeathSerial(func(event PathDeathEvent) { death <- event })
			defer cancelDeath()

			payload := proto.ByePayload{Reason: proto.ByeNormal}.Encode()
			frame := make([]byte, proto.HeaderSize+len(payload))
			if err := (proto.Header{
				Version: proto.Version,
				Type:    proto.FrameCtrl,
				Flags:   proto.FlagsForCtrl(proto.CtrlBye),
				Seq:     0,
			}).Encode(frame); err != nil {
				t.Fatal(err)
			}
			copy(frame[proto.HeaderSize:], payload)
			if n, err := badPeer.Write(frame); err != nil || n != len(frame) {
				t.Fatalf("write normal CtrlBye = (%d, %v), want (%d, nil)", n, err, len(frame))
			}

			select {
			case <-callbackWindowObserved:
			case <-time.After(time.Second):
				t.Fatal("actual CtrlBye did not invoke MarkByeSeen")
			}
			if !terminalPublishedBeforeCallback.Load() {
				t.Fatal("actual CtrlBye entered MarkByeSeen before publishing receive terminal state")
			}
			if eofGateOpenedBeforeCallback.Load() {
				t.Fatal("actual CtrlBye opened the application EOF gate before terminal ACK handoff")
			}
			if eofSeenDuringCallback.Load() {
				t.Fatal("Recv exposed EOF while MarkByeSeen was still executing")
			}
			if mode == "block" {
				if !deathInjectedDuringCallback.Load() {
					t.Fatal("test did not inject registered OnDeath during blocked MarkByeSeen")
				}
				if ackSeenAtCallbackEntry.Load() {
					t.Fatal("terminal ACK was emitted before MarkByeSeen callback entry")
				}
			}
			eventuallyEngine(t, time.Second, func() bool { return e.peerNormalBye.Load() })
			select {
			case err := <-readResult:
				if !errors.Is(err, io.EOF) {
					t.Fatalf("Recv after terminal ACK handoff = %v, want EOF", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Recv did not expose EOF after terminal ACK handoff")
			}
			if mode == "block" {
				eventuallyEngine(t, time.Second, func() bool {
					healthy.framesMu.Lock()
					defer healthy.framesMu.Unlock()
					for _, header := range healthy.frames {
						if header.Type == proto.FrameCtrl && proto.CtrlCodeFromFlags(header.Flags) == proto.CtrlPathProbeReply {
							return true
						}
					}
					return false
				})
			}

			if got := e.MigrationCount(); got != 0 {
				t.Fatalf("normal CtrlBye recorded %d automatic migrations, want 0", got)
			}
			e.zombieMu.Lock()
			zombieLeft := e.zombieLeft
			zombieGeneration := e.zombieGeneration
			zombieLastMigration := e.zombieLastMig
			e.zombieMu.Unlock()
			if zombieLeft != zombieLeftBefore || zombieGeneration != zombieGenerationBefore ||
				!zombieLastMigration.Equal(zombieLastMigrationBefore) {
				t.Fatalf("normal CtrlBye changed zombie state: left=%d/%d generation=%d/%d last=%v/%v",
					zombieLeft, zombieLeftBefore, zombieGeneration, zombieGenerationBefore,
					zombieLastMigration, zombieLastMigrationBefore)
			}
			if got := e.ActivePath(); got != badID {
				t.Fatalf("normal CtrlBye callback failure changed active path=%d, want %d", got, badID)
			}
			select {
			case event := <-death:
				t.Fatalf("normal CtrlBye callback failure emitted path death: %+v", event)
			case <-time.After(100 * time.Millisecond):
			}
			release()
		})
	}
}
