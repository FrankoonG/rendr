package rendr

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/transport"
)

func TestFactoryIgnoringContextIsBoundedAndLateResultClosedOnce(t *testing.T) {
	const (
		factoryID = "ignores-context"
		waiters   = 128
	)
	started := make(chan struct{})
	release := make(chan struct{})
	lateClosed := make(chan struct{})
	var calls atomic.Int32
	var closeCalls atomic.Int32
	late := &factoryBoundaryStreamConn{closeHook: func() {
		if closeCalls.Add(1) == 1 {
			close(lateClosed)
		}
	}}
	healthy := &factoryBoundaryStreamConn{}
	resolver := &pathFactoryResolver{stream: map[string]streamPathFactory{
		factoryID: func(context.Context, string) (net.Conn, error) {
			if calls.Add(1) == 1 {
				close(started)
				<-release
				return late, nil
			}
			return healthy, nil
		},
	}}
	spec := PathSpec{Transport: factoryID, Address: "unused"}
	gate := resolver.factoryCallGate(factoryID, FactoryKindStream)

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	firstResult := make(chan error, 1)
	go func() {
		_, err := resolver.dialPath(firstCtx, spec)
		firstResult <- err
	}()
	awaitFactorySignal(t, started, "first factory callback")
	cancelFirst()
	assertFactoryCanceledBoundedly(t, firstResult, "first factory callback")

	retriesStarted := time.Now()
	for range waiters {
		_, err := resolver.dialPath(context.Background(), spec)
		assertFactoryReason(t, err, factoryID, FactoryKindStream, FactoryReasonBusy)
	}
	if elapsed := time.Since(retriesStarted); elapsed > time.Second {
		t.Fatalf("%d gated retries took %s, want immediate typed busy failures", waiters, elapsed)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("factory calls after canceled retries=%d, want 1", got)
	}

	close(release)
	awaitFactorySignal(t, lateClosed, "late result cleanup")
	awaitFactoryGateIdle(t, gate)
	if got := closeCalls.Load(); got != 1 {
		t.Fatalf("late result Close calls=%d, want 1", got)
	}

	path, err := resolver.dialPath(context.Background(), spec)
	if err != nil {
		t.Fatalf("factory call after orphan cleanup: %v", err)
	}
	if path == nil || calls.Load() != 2 {
		t.Fatalf("factory reuse returned path=%T calls=%d, want non-nil and 2", path, calls.Load())
	}
	if err := path.Close(); err != nil {
		t.Fatalf("close reused path: %v", err)
	}
	if got := closeCalls.Load(); got != 1 {
		t.Fatalf("late result Close calls after reuse=%d, want 1", got)
	}
}

func TestFactoryConflictingResultCleanupIsBoundedAndEventuallyObservable(t *testing.T) {
	const factoryID = "blocked-conflicting-result"
	factoryErr := errors.New("factory returned a connection with an error")
	closeErr := errors.New("late connection cleanup failed")
	closeStarted := make(chan struct{})
	closeRelease := make(chan struct{})
	closeReturned := make(chan struct{})
	var factoryCalls atomic.Int32
	blocked := &factoryCleanupCountingConn{closeFn: func() error {
		close(closeStarted)
		<-closeRelease
		close(closeReturned)
		return closeErr
	}}
	healthy := &factoryCleanupCountingConn{}
	resolver := &pathFactoryResolver{stream: map[string]streamPathFactory{
		factoryID: func(context.Context, string) (net.Conn, error) {
			if factoryCalls.Add(1) == 1 {
				return blocked, factoryErr
			}
			return healthy, nil
		},
	}}
	spec := PathSpec{Transport: factoryID, Address: "unused"}
	gate := resolver.factoryCallGate(factoryID, FactoryKindStream)

	startedAt := time.Now()
	path, err := resolver.dialPath(context.Background(), spec)
	if path != nil {
		t.Fatalf("conflicting result returned path %T", path)
	}
	if !errors.Is(err, factoryErr) {
		t.Fatalf("dial error=%v, want original factory error %v", err, factoryErr)
	}
	assertFactoryReason(t, err, factoryID, FactoryKindStream, FactoryReasonCleanupTimeout)
	if elapsed := time.Since(startedAt); elapsed > time.Second {
		t.Fatalf("blocked cleanup held invokePathFactory for %s", elapsed)
	}
	awaitFactorySignal(t, closeStarted, "conflicting result cleanup")
	if got := blocked.closeCalls.Load(); got != 1 {
		t.Fatalf("blocked connection Close calls=%d, want exactly 1", got)
	}

	retriesStarted := time.Now()
	for range 128 {
		path, retryErr := resolver.dialPath(context.Background(), spec)
		if path != nil {
			t.Fatalf("busy retry returned path %T", path)
		}
		assertFactoryReason(t, retryErr, factoryID, FactoryKindStream, FactoryReasonBusy)
	}
	if elapsed := time.Since(retriesStarted); elapsed > time.Second {
		t.Fatalf("busy retries blocked for %s", elapsed)
	}
	if got := factoryCalls.Load(); got != 1 {
		t.Fatalf("factory calls while cleanup unresolved=%d, want 1", got)
	}

	close(closeRelease)
	awaitFactorySignal(t, closeReturned, "blocked cleanup return")
	awaitFactoryGateIdle(t, gate)
	path, err = resolver.dialPath(context.Background(), spec)
	if path != nil {
		t.Fatalf("late cleanup diagnostic returned path %T", path)
	}
	if !errors.Is(err, closeErr) {
		t.Fatalf("late cleanup diagnostic=%v, want %v", err, closeErr)
	}
	if got := factoryCalls.Load(); got != 1 {
		t.Fatalf("late diagnostic invoked factory: calls=%d want=1", got)
	}

	path, err = resolver.dialPath(context.Background(), spec)
	if err != nil || path == nil {
		t.Fatalf("healthy retry after cleanup path=%T err=%v", path, err)
	}
	if err := path.Close(); err != nil {
		t.Fatalf("close healthy result: %v", err)
	}
	if got := factoryCalls.Load(); got != 2 {
		t.Fatalf("factory calls after recovery=%d, want 2", got)
	}
	if got := blocked.closeCalls.Load(); got != 1 {
		t.Fatalf("blocked connection final Close calls=%d, want exactly 1", got)
	}
}

func TestFactoryLateCanceledResultHasSingleCleanupAuthority(t *testing.T) {
	const factoryID = "late-canceled-result"
	factoryErr := errors.New("late factory error")
	closeErr := errors.New("late cleanup error")
	factoryStarted := make(chan struct{})
	factoryRelease := make(chan struct{})
	closeStarted := make(chan struct{})
	closeRelease := make(chan struct{})
	var factoryCalls atomic.Int32
	late := &factoryCleanupCountingConn{closeFn: func() error {
		close(closeStarted)
		<-closeRelease
		return closeErr
	}}
	healthy := &factoryCleanupCountingConn{}
	resolver := &pathFactoryResolver{stream: map[string]streamPathFactory{
		factoryID: func(context.Context, string) (net.Conn, error) {
			if factoryCalls.Add(1) == 1 {
				close(factoryStarted)
				<-factoryRelease
				return late, factoryErr
			}
			return healthy, nil
		},
	}}
	spec := PathSpec{Transport: factoryID, Address: "unused"}
	gate := resolver.factoryCallGate(factoryID, FactoryKindStream)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := resolver.dialPath(ctx, spec)
		result <- err
	}()
	awaitFactorySignal(t, factoryStarted, "late factory callback")
	cancel()
	assertFactoryCanceledBoundedly(t, result, "late factory callback")

	close(factoryRelease)
	awaitFactorySignal(t, closeStarted, "late result cleanup")
	if got := late.closeCalls.Load(); got != 1 {
		t.Fatalf("late result Close calls=%d, want exactly 1", got)
	}
	_, err := resolver.dialPath(context.Background(), spec)
	assertFactoryReason(t, err, factoryID, FactoryKindStream, FactoryReasonBusy)
	if got := factoryCalls.Load(); got != 1 {
		t.Fatalf("factory calls while late cleanup blocked=%d, want 1", got)
	}

	close(closeRelease)
	awaitFactoryGateIdle(t, gate)
	_, err = resolver.dialPath(context.Background(), spec)
	if !errors.Is(err, factoryErr) || !errors.Is(err, closeErr) {
		t.Fatalf("late terminal error=%v, want factory=%v and cleanup=%v", err, factoryErr, closeErr)
	}
	path, err := resolver.dialPath(context.Background(), spec)
	if err != nil || path == nil {
		t.Fatalf("healthy retry after late cleanup path=%T err=%v", path, err)
	}
	if err := path.Close(); err != nil {
		t.Fatalf("close healthy retry: %v", err)
	}
	if got := late.closeCalls.Load(); got != 1 {
		t.Fatalf("late result final Close calls=%d, want exactly 1", got)
	}
}

func TestFactoryCleanupContainsPanicAndGoexitExactlyOnce(t *testing.T) {
	factoryErr := errors.New("factory conflict")
	panicValue := &factoryBoundaryPanicValue{}
	tests := []struct {
		name      string
		closeHook func()
		panic     any
	}{
		{name: "panic", closeHook: func() { panic(panicValue) }, panic: panicValue},
		{name: "goexit", closeHook: func() { runtime.Goexit() }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const factoryID = "abnormal-cleanup"
			conn := &factoryCleanupCountingConn{closeFn: func() error {
				test.closeHook()
				return nil
			}}
			resolver := &pathFactoryResolver{stream: map[string]streamPathFactory{
				factoryID: func(context.Context, string) (net.Conn, error) {
					return conn, factoryErr
				},
			}}
			path, err := resolver.dialPath(context.Background(), PathSpec{Transport: factoryID})
			if path != nil || !errors.Is(err, factoryErr) {
				t.Fatalf("conflicting result path=%T err=%v", path, err)
			}
			assertFactoryBoundaryError(t, err, factoryID, FactoryKindStream, FactoryReasonCleanup, test.panic)
			if got := conn.closeCalls.Load(); got != 1 {
				t.Fatalf("cleanup Close calls=%d, want exactly 1", got)
			}
		})
	}
}

func TestFactoryGateSupportsMoreThan64HealthySequentialUses(t *testing.T) {
	const (
		factoryID = "healthy-sequential"
		uses      = 128
	)
	var factoryCalls atomic.Int32
	var closeCalls atomic.Int32
	resolver := &pathFactoryResolver{stream: map[string]streamPathFactory{
		factoryID: func(context.Context, string) (net.Conn, error) {
			factoryCalls.Add(1)
			return &factoryCleanupCountingConn{closeFn: func() error {
				closeCalls.Add(1)
				return nil
			}}, nil
		},
	}}
	spec := PathSpec{Transport: factoryID}
	for index := range uses {
		path, err := resolver.dialPath(context.Background(), spec)
		if err != nil || path == nil {
			t.Fatalf("healthy use %d path=%T err=%v", index, path, err)
		}
		if err := path.Close(); err != nil {
			t.Fatalf("close healthy use %d: %v", index, err)
		}
	}
	if got := factoryCalls.Load(); got != uses {
		t.Fatalf("factory calls=%d, want %d", got, uses)
	}
	if got := closeCalls.Load(); got != uses {
		t.Fatalf("connection closes=%d, want %d", got, uses)
	}
}

func TestFactoryGateSupportsMoreThan64HealthyConcurrentUses(t *testing.T) {
	const (
		factoryID = "healthy-concurrent"
		uses      = 128
	)
	var entered atomic.Int32
	allEntered := make(chan struct{})
	release := make(chan struct{})
	resolver := &pathFactoryResolver{stream: map[string]streamPathFactory{
		factoryID: func(context.Context, string) (net.Conn, error) {
			if entered.Add(1) == uses {
				close(allEntered)
			}
			<-release
			return &factoryCleanupCountingConn{}, nil
		},
	}}
	spec := PathSpec{Transport: factoryID}
	type result struct {
		path transport.PathConn
		err  error
	}
	results := make(chan result, uses)
	var callers sync.WaitGroup
	callers.Add(uses)
	for range uses {
		go func() {
			defer callers.Done()
			path, err := resolver.dialPath(context.Background(), spec)
			results <- result{path: path, err: err}
		}()
	}
	awaitFactorySignal(t, allEntered, "all healthy concurrent factory callbacks")
	close(release)
	callers.Wait()
	close(results)
	for result := range results {
		if result.err != nil || result.path == nil {
			t.Fatalf("healthy concurrent result path=%T err=%v", result.path, result.err)
		}
		if err := result.path.Close(); err != nil {
			t.Fatalf("close healthy concurrent path: %v", err)
		}
	}
	if got := entered.Load(); got != uses {
		t.Fatalf("concurrent factory callbacks=%d, want %d", got, uses)
	}
}

func TestFactoryCallbackCapacityDoesNotSpawnAnUnboundedWorker(t *testing.T) {
	const factoryID = "callback-capacity"
	var entered atomic.Int32
	allEntered := make(chan struct{})
	release := make(chan struct{})
	resolver := &pathFactoryResolver{stream: map[string]streamPathFactory{
		factoryID: func(context.Context, string) (net.Conn, error) {
			if entered.Add(1) == maxOutstandingFactoryCallbacks {
				close(allEntered)
			}
			<-release
			return &factoryCleanupCountingConn{}, nil
		},
	}}
	spec := PathSpec{Transport: factoryID}
	type result struct {
		path transport.PathConn
		err  error
	}
	results := make(chan result, maxOutstandingFactoryCallbacks)
	for range maxOutstandingFactoryCallbacks {
		go func() {
			path, err := resolver.dialPath(context.Background(), spec)
			results <- result{path: path, err: err}
		}()
	}
	awaitFactorySignal(t, allEntered, "factory callback capacity")
	path, err := resolver.dialPath(context.Background(), spec)
	if path != nil {
		t.Fatalf("over-capacity callback returned path %T", path)
	}
	assertFactoryReason(t, err, factoryID, FactoryKindStream, FactoryReasonCapacity)
	if got := entered.Load(); got != maxOutstandingFactoryCallbacks {
		t.Fatalf("factory callbacks after capacity rejection=%d, want %d", got, maxOutstandingFactoryCallbacks)
	}
	close(release)
	for range maxOutstandingFactoryCallbacks {
		result := <-results
		if result.err != nil || result.path == nil {
			t.Fatalf("admitted callback path=%T err=%v", result.path, result.err)
		}
		if err := result.path.Close(); err != nil {
			t.Fatalf("close admitted callback path: %v", err)
		}
	}
}

func TestRuntimeFactoryBudgetIsSharedAcrossFreshResolverSnapshots(t *testing.T) {
	const factoryID = "runtime-shared-budget"
	var entered atomic.Int32
	allEntered := make(chan struct{})
	release := make(chan struct{})
	dialer := &sessionDialer{
		streamFactories: map[string]streamPathFactory{
			factoryID: func(context.Context, string) (net.Conn, error) {
				if entered.Add(1) == maxRuntimeFactoryCallbacks {
					close(allEntered)
				}
				<-release
				return &factoryCleanupCountingConn{}, nil
			},
		},
		factoryCallbackBudget: newFactoryCallbackBudget(maxRuntimeFactoryCallbacks),
	}
	spec := PathSpec{Transport: factoryID}
	type result struct {
		path transport.PathConn
		err  error
	}
	results := make(chan result, maxRuntimeFactoryCallbacks)
	for range maxRuntimeFactoryCallbacks {
		resolver := dialer.snapshotFactoryResolver()
		go func() {
			path, err := resolver.dialPath(context.Background(), spec)
			results <- result{path: path, err: err}
		}()
	}
	awaitFactorySignal(t, allEntered, "shared Runtime callback capacity")
	path, err := dialer.snapshotFactoryResolver().dialPath(context.Background(), spec)
	if path != nil {
		t.Fatalf("over-capacity Runtime callback returned path %T", path)
	}
	assertFactoryReason(t, err, factoryID, FactoryKindStream, FactoryReasonCapacity)
	if got := entered.Load(); got != maxRuntimeFactoryCallbacks {
		t.Fatalf("callbacks across fresh Runtime resolvers=%d, want %d", got, maxRuntimeFactoryCallbacks)
	}
	close(release)
	for range maxRuntimeFactoryCallbacks {
		result := <-results
		if result.err != nil || result.path == nil {
			t.Fatalf("admitted Runtime callback path=%T err=%v", result.path, result.err)
		}
		if err := result.path.Close(); err != nil {
			t.Fatalf("close Runtime-budget path: %v", err)
		}
	}
}

func TestProcessFactoryBudgetIsSharedAcrossFreshResolvers(t *testing.T) {
	const factoryID = "process-shared-budget"
	var entered atomic.Int32
	allEntered := make(chan struct{})
	release := make(chan struct{})
	factory := func(context.Context, string) (net.Conn, error) {
		if entered.Add(1) == maxProcessFactoryCallbacks {
			close(allEntered)
		}
		<-release
		return &factoryCleanupCountingConn{}, nil
	}
	spec := PathSpec{Transport: factoryID}
	type result struct {
		path transport.PathConn
		err  error
	}
	results := make(chan result, maxProcessFactoryCallbacks)
	for range maxProcessFactoryCallbacks {
		resolver := &pathFactoryResolver{stream: map[string]streamPathFactory{factoryID: factory}}
		go func() {
			path, err := resolver.dialPath(context.Background(), spec)
			results <- result{path: path, err: err}
		}()
	}
	awaitFactorySignal(t, allEntered, "process callback capacity")
	resolver := &pathFactoryResolver{stream: map[string]streamPathFactory{factoryID: factory}}
	path, err := resolver.dialPath(context.Background(), spec)
	if path != nil {
		t.Fatalf("over-capacity process callback returned path %T", path)
	}
	assertFactoryReason(t, err, factoryID, FactoryKindStream, FactoryReasonCapacity)
	if got := entered.Load(); got != maxProcessFactoryCallbacks {
		t.Fatalf("callbacks across fresh resolvers=%d, want %d", got, maxProcessFactoryCallbacks)
	}
	close(release)
	for range maxProcessFactoryCallbacks {
		result := <-results
		if result.err != nil || result.path == nil {
			t.Fatalf("admitted process callback path=%T err=%v", result.path, result.err)
		}
		if err := result.path.Close(); err != nil {
			t.Fatalf("close process-budget path: %v", err)
		}
	}
}

func TestPreAdoptionPathLeaseBoundsCleanupAndTransfersExactlyOnce(t *testing.T) {
	const factoryID = "pre-adoption"
	t.Run("bounded cleanup and late error", func(t *testing.T) {
		closeErr := errors.New("pre-adoption close failed")
		closeStarted := make(chan struct{})
		closeRelease := make(chan struct{})
		conn := &factoryCleanupCountingConn{closeFn: func() error {
			close(closeStarted)
			<-closeRelease
			return closeErr
		}}
		resolver := &pathFactoryResolver{stream: map[string]streamPathFactory{
			factoryID: func(context.Context, string) (net.Conn, error) { return conn, nil },
		}}
		lease, err := resolver.dialPathForAdoption(context.Background(), PathSpec{Transport: factoryID})
		if err != nil || lease == nil || lease.Path() == nil {
			t.Fatalf("pre-adoption lease=%v path=%T err=%v", lease, lease.Path(), err)
		}
		startedAt := time.Now()
		err = lease.Close()
		assertFactoryReason(t, err, factoryID, FactoryKindStream, FactoryReasonCleanupTimeout)
		if elapsed := time.Since(startedAt); elapsed > time.Second {
			t.Fatalf("pre-adoption cleanup blocked for %s", elapsed)
		}
		awaitFactorySignal(t, closeStarted, "pre-adoption cleanup")
		if got := conn.closeCalls.Load(); got != 1 {
			t.Fatalf("pre-adoption Close calls=%d, want exactly 1", got)
		}
		close(closeRelease)
		deadline := time.Now().Add(time.Second)
		for {
			err = lease.Close()
			if errors.Is(err, closeErr) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("late pre-adoption cleanup error=%v, want %v", err, closeErr)
			}
			time.Sleep(time.Millisecond)
		}
		if got := conn.closeCalls.Load(); got != 1 {
			t.Fatalf("pre-adoption final Close calls=%d, want exactly 1", got)
		}
	})

	t.Run("transfer releases cleanup authority", func(t *testing.T) {
		conn := &factoryCleanupCountingConn{}
		resolver := &pathFactoryResolver{stream: map[string]streamPathFactory{
			factoryID: func(context.Context, string) (net.Conn, error) { return conn, nil },
		}}
		lease, err := resolver.dialPathForAdoption(context.Background(), PathSpec{Transport: factoryID})
		if err != nil {
			t.Fatalf("create pre-adoption lease: %v", err)
		}
		path := lease.Path()
		if err := lease.ReleaseToEngine(); err != nil {
			t.Fatalf("release pre-adoption lease: %v", err)
		}
		if err := lease.Close(); err != nil {
			t.Fatalf("close released lease: %v", err)
		}
		if got := conn.closeCalls.Load(); got != 0 {
			t.Fatalf("released lease closed engine-owned path %d times", got)
		}
		if err := path.Close(); err != nil {
			t.Fatalf("engine-side close: %v", err)
		}
		if got := conn.closeCalls.Load(); got != 1 {
			t.Fatalf("engine-side Close calls=%d, want exactly 1", got)
		}
	})

	t.Run("runtime dial retains cleanup authority before engine adoption", func(t *testing.T) {
		closeStarted := make(chan struct{})
		closeRelease := make(chan struct{})
		path := &preAdoptionFactoryPathConn{
			closeStarted: closeStarted,
			closeRelease: closeRelease,
		}
		runtime, err := NewRuntime(RuntimeConfig{})
		if err != nil {
			t.Fatal(err)
		}
		if err := runtime.RegisterFramedFactory(factoryID, FramedFactory{
			Carrier: CarrierTCP,
			Factory: &factoryBoundaryFramedFactory{dial: func(context.Context, PathSpec) (transport.PathConn, error) {
				return path, nil
			}},
		}); err != nil {
			t.Fatal(err)
		}

		startedAt := time.Now()
		client, err := runtime.Dial(context.Background(), SessionConfig{
			Root: Path("pre-adoption", PathSpec{Transport: factoryID, Address: "unused"}),
		})
		if client != nil || err == nil {
			t.Fatalf("Runtime.Dial client=%T err=%v, want pre-adoption failure", client, err)
		}
		assertFactoryReason(t, err, factoryID, FactoryKindFramed, FactoryReasonCleanupTimeout)
		if elapsed := time.Since(startedAt); elapsed > time.Second {
			t.Fatalf("Runtime.Dial blocked for %s on pre-adoption cleanup", elapsed)
		}
		awaitFactorySignal(t, closeStarted, "Runtime.Dial pre-adoption cleanup")
		if got := path.closeCalls.Load(); got != 1 {
			t.Fatalf("Runtime.Dial pre-adoption Close calls=%d, want 1", got)
		}
		if got := len(runtime.factoryCallbackBudget.permits); got != 1 {
			t.Fatalf("Runtime callback permits=%d, want retained cleanup authority", got)
		}

		close(closeRelease)
		deadline := time.Now().Add(time.Second)
		for len(runtime.factoryCallbackBudget.permits) != 0 {
			if time.Now().After(deadline) {
				t.Fatal("Runtime cleanup authority was not released after Close completed")
			}
			time.Sleep(time.Millisecond)
		}
		if got := path.closeCalls.Load(); got != 1 {
			t.Fatalf("Runtime.Dial final Close calls=%d, want 1", got)
		}
	})
}

func TestPreAdoptionPathLeaseContainsPanicAndGoexitAndReleasesPermit(t *testing.T) {
	const factoryID = "pre-adoption-abnormal-close"
	panicValue := &factoryBoundaryPanicValue{}
	tests := []struct {
		name      string
		closeHook func()
		panic     any
	}{
		{name: "panic", closeHook: func() { panic(panicValue) }, panic: panicValue},
		{name: "goexit", closeHook: runtime.Goexit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			var first *factoryCleanupCountingConn
			var second *factoryCleanupCountingConn
			resolver := &pathFactoryResolver{
				runtimeBudget: newFactoryCallbackBudget(1),
				stream: map[string]streamPathFactory{
					factoryID: func(context.Context, string) (net.Conn, error) {
						if calls.Add(1) == 1 {
							first = &factoryCleanupCountingConn{closeFn: func() error {
								test.closeHook()
								return nil
							}}
							return first, nil
						}
						second = &factoryCleanupCountingConn{}
						return second, nil
					},
				},
			}
			lease, err := resolver.dialPathForAdoption(context.Background(), PathSpec{Transport: factoryID})
			if err != nil {
				t.Fatalf("create abnormal pre-adoption lease: %v", err)
			}
			err = lease.Close()
			assertFactoryBoundaryError(t, err, factoryID, FactoryKindStream, FactoryReasonCleanup, test.panic)
			if got := first.closeCalls.Load(); got != 1 {
				t.Fatalf("abnormal pre-adoption Close calls=%d, want 1", got)
			}
			next, err := resolver.dialPathForAdoption(context.Background(), PathSpec{Transport: factoryID})
			if err != nil || next == nil {
				t.Fatalf("permit not released after abnormal cleanup lease=%v err=%v", next, err)
			}
			if err := next.Close(); err != nil {
				t.Fatalf("close next pre-adoption lease: %v", err)
			}
			if got := second.closeCalls.Load(); got != 1 {
				t.Fatalf("next pre-adoption Close calls=%d, want 1", got)
			}
		})
	}
}

func TestPreAdoptionPathLeaseCloseTransferRaceHasOneOwner(t *testing.T) {
	const factoryID = "pre-adoption-race"
	for iteration := range 200 {
		conn := &factoryCleanupCountingConn{}
		resolver := &pathFactoryResolver{stream: map[string]streamPathFactory{
			factoryID: func(context.Context, string) (net.Conn, error) { return conn, nil },
		}}
		lease, err := resolver.dialPathForAdoption(context.Background(), PathSpec{Transport: factoryID})
		if err != nil {
			t.Fatalf("iteration %d create lease: %v", iteration, err)
		}
		path := lease.Path()
		start := make(chan struct{})
		closeResult := make(chan error, 1)
		transferResult := make(chan error, 1)
		go func() {
			<-start
			closeResult <- lease.Close()
		}()
		go func() {
			<-start
			transferResult <- lease.ReleaseToEngine()
		}()
		close(start)
		closeErr := <-closeResult
		transferErr := <-transferResult
		if closeErr != nil {
			t.Fatalf("iteration %d close error: %v", iteration, closeErr)
		}
		switch {
		case transferErr == nil:
			if got := conn.closeCalls.Load(); got != 0 {
				t.Fatalf("iteration %d transferred path was closed %d times", iteration, got)
			}
			if err := path.Close(); err != nil {
				t.Fatalf("iteration %d engine close: %v", iteration, err)
			}
		case transferErr != nil:
			if got := conn.closeCalls.Load(); got != 1 {
				t.Fatalf("iteration %d lease-owned path Close calls=%d, want 1", iteration, got)
			}
		}
		if got := conn.closeCalls.Load(); got != 1 {
			t.Fatalf("iteration %d final Close calls=%d, want exactly 1", iteration, got)
		}
	}
}

func TestPreAdoptionPathLeaseSupportsMoreThan64PendingPathsAndBoundsCapacity(t *testing.T) {
	const factoryID = "pre-adoption-capacity"
	baselineGoroutines := runtime.NumGoroutine()
	var calls atomic.Int32
	var closeStarted atomic.Int32
	allCloseStarted := make(chan struct{})
	closeRelease := make(chan struct{})
	connections := make([]*factoryCleanupCountingConn, 0, maxRuntimeFactoryCallbacks+1)
	dialer := &sessionDialer{
		factoryCallbackBudget: newFactoryCallbackBudget(maxRuntimeFactoryCallbacks),
		streamFactories: map[string]streamPathFactory{
			factoryID: func(context.Context, string) (net.Conn, error) {
				calls.Add(1)
				conn := &factoryCleanupCountingConn{closeFn: func() error {
					if closeStarted.Add(1) == maxRuntimeFactoryCallbacks {
						close(allCloseStarted)
					}
					<-closeRelease
					return nil
				}}
				connections = append(connections, conn)
				return conn, nil
			},
		}}
	leases := make([]*preAdoptionPathLease, 0, maxRuntimeFactoryCallbacks)
	for index := range maxRuntimeFactoryCallbacks {
		resolver := dialer.snapshotFactoryResolver()
		lease, err := resolver.dialPathForAdoption(context.Background(), PathSpec{Transport: factoryID})
		if err != nil {
			t.Fatalf("reserve pre-adoption path %d: %v", index, err)
		}
		leases = append(leases, lease)
	}
	if len(leases) <= 64 {
		t.Fatalf("pending path capacity=%d, want more than 64", len(leases))
	}
	excessResolver := dialer.snapshotFactoryResolver()
	excess, err := excessResolver.dialPathForAdoption(context.Background(), PathSpec{Transport: factoryID})
	if excess != nil {
		t.Fatalf("over-capacity admission returned lease %v", excess)
	}
	assertFactoryReason(t, err, factoryID, FactoryKindStream, FactoryReasonCapacity)
	if got := calls.Load(); got != maxRuntimeFactoryCallbacks {
		t.Fatalf("factory calls after excess admission=%d, want %d", got, maxRuntimeFactoryCallbacks)
	}
	if got := len(connections); got != maxRuntimeFactoryCallbacks {
		t.Fatalf("published connections=%d, want %d", got, maxRuntimeFactoryCallbacks)
	}

	closeResults := make(chan error, maxRuntimeFactoryCallbacks)
	for _, lease := range leases {
		go func() { closeResults <- lease.Close() }()
	}
	awaitFactorySignal(t, allCloseStarted, "pre-adoption cleanup runtime capacity")
	for range maxRuntimeFactoryCallbacks {
		err := <-closeResults
		assertFactoryReason(t, err, factoryID, FactoryKindStream, FactoryReasonCleanupTimeout)
	}

	if got := closeStarted.Load(); got != maxRuntimeFactoryCallbacks {
		t.Fatalf("blocked Close callbacks=%d, want bounded %d", got, maxRuntimeFactoryCallbacks)
	}

	close(closeRelease)
	for index, lease := range leases {
		deadline := time.Now().Add(time.Second)
		for {
			if err := lease.Close(); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("cleanup lease %d did not complete", index)
			}
			time.Sleep(time.Millisecond)
		}
		if got := connections[index].closeCalls.Load(); got != 1 {
			t.Fatalf("cleanup lease %d Close calls=%d, want 1", index, got)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > baselineGoroutines+8 {
		if time.Now().After(deadline) {
			t.Fatalf("factory cleanup goroutines did not return: baseline=%d current=%d", baselineGoroutines, runtime.NumGoroutine())
		}
		runtime.Gosched()
	}
}

func TestFailedFactoryResultCleanupAuthorityIsBoundedAcrossFreshResolvers(t *testing.T) {
	const factoryID = "failed-result-runtime-capacity"
	factoryErr := errors.New("factory returned connection and error")
	var calls atomic.Int32
	var closeStarted atomic.Int32
	allCloseStarted := make(chan struct{})
	closeRelease := make(chan struct{})
	var connectionsMu sync.Mutex
	connections := make([]*factoryCleanupCountingConn, 0, maxRuntimeFactoryCallbacks)
	dialer := &sessionDialer{
		factoryCallbackBudget: newFactoryCallbackBudget(maxRuntimeFactoryCallbacks),
		streamFactories: map[string]streamPathFactory{
			factoryID: func(context.Context, string) (net.Conn, error) {
				calls.Add(1)
				conn := &factoryCleanupCountingConn{closeFn: func() error {
					if closeStarted.Add(1) == maxRuntimeFactoryCallbacks {
						close(allCloseStarted)
					}
					<-closeRelease
					return nil
				}}
				connectionsMu.Lock()
				connections = append(connections, conn)
				connectionsMu.Unlock()
				return conn, factoryErr
			},
		},
	}
	type result struct {
		lease *preAdoptionPathLease
		err   error
	}
	results := make(chan result, maxRuntimeFactoryCallbacks)
	for range maxRuntimeFactoryCallbacks {
		resolver := dialer.snapshotFactoryResolver()
		go func() {
			lease, err := resolver.dialPathForAdoption(context.Background(), PathSpec{Transport: factoryID})
			results <- result{lease: lease, err: err}
		}()
	}
	awaitFactorySignal(t, allCloseStarted, "failed result cleanup runtime capacity")
	for range maxRuntimeFactoryCallbacks {
		result := <-results
		if result.lease != nil {
			t.Fatalf("conflicting result published lease %v", result.lease)
		}
		if !errors.Is(result.err, factoryErr) {
			t.Fatalf("conflicting result error=%v, want %v", result.err, factoryErr)
		}
		assertFactoryReason(t, result.err, factoryID, FactoryKindStream, FactoryReasonCleanupTimeout)
	}
	excess, err := dialer.snapshotFactoryResolver().dialPathForAdoption(context.Background(), PathSpec{Transport: factoryID})
	if excess != nil {
		t.Fatalf("over-capacity failed-result admission returned lease %v", excess)
	}
	assertFactoryReason(t, err, factoryID, FactoryKindStream, FactoryReasonCapacity)
	if got := calls.Load(); got != maxRuntimeFactoryCallbacks {
		t.Fatalf("factory calls after over-capacity failed result=%d, want %d", got, maxRuntimeFactoryCallbacks)
	}
	if got := closeStarted.Load(); got != maxRuntimeFactoryCallbacks {
		t.Fatalf("failed-result cleanup callbacks=%d, want bounded %d", got, maxRuntimeFactoryCallbacks)
	}

	close(closeRelease)
	deadline := time.Now().Add(3 * time.Second)
	for {
		connectionsMu.Lock()
		allClosed := len(connections) == maxRuntimeFactoryCallbacks
		for _, conn := range connections {
			allClosed = allClosed && conn.closeCalls.Load() == 1
		}
		connectionsMu.Unlock()
		if allClosed && len(dialer.factoryCallbackBudget.permits) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("failed-result cleanup authority did not quiesce: callbacks=%d permits=%d", closeStarted.Load(), len(dialer.factoryCallbackBudget.permits))
		}
		runtime.Gosched()
	}
}

func TestPacketFactorySpecFailurePrecedesExternalCallback(t *testing.T) {
	const factoryID = "packet-preflight"
	var calls atomic.Int32
	resolver := &pathFactoryResolver{packet: map[string]packetPathFactory{
		factoryID: func(context.Context, string) (PacketEndpoint, error) {
			calls.Add(1)
			return PacketEndpoint{
				Conn:            &factoryBoundaryPacketConn{closeHook: func() { select {} }},
				Peer:            factoryBoundaryAddr("peer"),
				MaxDatagramSize: testPacketMaxDatagramSize,
			}, nil
		},
	}}
	tests := []PathSpec{
		{Transport: factoryID, Address: "opaque", Opts: map[string]string{"flow_id_hex": "bad"}},
		{Transport: factoryID, Address: "opaque", Opts: map[string]string{"flow_id_hex": "zz112233445566"}},
	}
	for _, spec := range tests {
		startedAt := time.Now()
		path, err := resolver.dialPath(context.Background(), spec)
		if path != nil || err == nil {
			t.Fatalf("invalid packet spec=%+v path=%T err=%v", spec, path, err)
		}
		if elapsed := time.Since(startedAt); elapsed > time.Second {
			t.Fatalf("invalid packet spec blocked for %s", elapsed)
		}
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("invalid packet specs invoked external factory %d times", got)
	}
}

func TestBlockedRecoveryFactoryDoesNotBlockConnClose(t *testing.T) {
	const factoryID = "blocked-recovery"
	started := make(chan struct{})
	release := make(chan struct{})
	lateClosed := make(chan struct{})
	var closeCalls atomic.Int32
	late := &factoryBoundaryStreamConn{closeHook: func() {
		if closeCalls.Add(1) == 1 {
			close(lateClosed)
		}
	}}
	resolver := &pathFactoryResolver{
		stream: map[string]streamPathFactory{
			factoryID: func(context.Context, string) (net.Conn, error) {
				close(started)
				<-release
				return late, nil
			},
		},
		carrier: map[string]CarrierFamily{factoryID: CarrierTCP},
	}
	spec := PathSpec{Transport: factoryID, Address: "unused"}
	e := engine.New(engine.SideClient, engine.NewClientFlowID(), engine.Limits{}.Clamp())
	defer e.Close()
	supervisor := newPathRecoverySupervisor(
		e,
		resolver,
		func(ctx context.Context, candidate PathSpec) (uint32, error) {
			path, err := resolver.dialPath(ctx, candidate)
			if path != nil {
				_ = path.Close()
			}
			return 0, err
		},
		[]PathSpec{spec},
		newPathStatusTracker([]PathSpec{spec}, ""),
		retryPolicy{MinBackoff: time.Millisecond, MaxBackoff: time.Millisecond},
	)
	awaitFactorySignal(t, started, "recovery factory callback")
	conn := &engineBackedConn{e: e, conn: &engine.Conn{E: e}, recovery: supervisor}

	stopped := make(chan struct{})
	go func() {
		_ = conn.Close()
		close(stopped)
	}()
	awaitFactorySignal(t, stopped, "connection shutdown")

	close(release)
	awaitFactorySignal(t, lateClosed, "late recovery result cleanup")
	if got := closeCalls.Load(); got != 1 {
		t.Fatalf("late recovery result Close calls=%d, want 1", got)
	}
}

func assertFactoryCanceledBoundedly(t *testing.T, result <-chan error, operation string) {
	t.Helper()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("%s error=%v, want context cancellation", operation, err)
		}
	case <-time.After(time.Second):
		t.Fatalf("%s did not return after cancellation", operation)
	}
}

func awaitFactorySignal(t *testing.T, signal <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s", operation)
	}
}

func awaitFactoryGateIdle(t *testing.T, gate *factoryCallGate) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		gate.mu.Lock()
		active := gate.active
		gate.mu.Unlock()
		if active == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for factory gate cleanup completion")
		}
		time.Sleep(time.Millisecond)
	}
}

func assertFactoryReason(t *testing.T, err error, factoryID string, kind FactoryKind, reason FactoryErrorReason) {
	t.Helper()
	var factoryErr *FactoryError
	if !errors.As(err, &factoryErr) {
		t.Fatalf("factory error type=%T, want *FactoryError: %v", err, err)
	}
	if factoryErr.FactoryID != factoryID || factoryErr.Kind != kind || factoryErr.Reason != reason {
		t.Fatalf("factory error=%+v, want id=%q kind=%q reason=%q", factoryErr, factoryID, kind, reason)
	}
}

type factoryCleanupCountingConn struct {
	closeCalls atomic.Int32
	closeFn    func() error
}

func (*factoryCleanupCountingConn) Read([]byte) (int, error) { return 0, io.EOF }
func (*factoryCleanupCountingConn) Write(p []byte) (int, error) {
	return len(p), nil
}
func (c *factoryCleanupCountingConn) Close() error {
	c.closeCalls.Add(1)
	if c.closeFn != nil {
		return c.closeFn()
	}
	return nil
}
func (*factoryCleanupCountingConn) LocalAddr() net.Addr              { return factoryBoundaryAddr("local") }
func (*factoryCleanupCountingConn) RemoteAddr() net.Addr             { return factoryBoundaryAddr("remote") }
func (*factoryCleanupCountingConn) SetDeadline(time.Time) error      { return nil }
func (*factoryCleanupCountingConn) SetReadDeadline(time.Time) error  { return nil }
func (*factoryCleanupCountingConn) SetWriteDeadline(time.Time) error { return nil }

type preAdoptionFactoryPathConn struct {
	closeStarted chan struct{}
	closeRelease chan struct{}
	closeCalls   atomic.Int32
}

func (*preAdoptionFactoryPathConn) Read([]byte) (int, error)  { return 0, io.EOF }
func (*preAdoptionFactoryPathConn) Write([]byte) (int, error) { return 0, net.ErrClosed }
func (path *preAdoptionFactoryPathConn) Close() error {
	if path.closeCalls.Add(1) == 1 {
		close(path.closeStarted)
	}
	<-path.closeRelease
	return nil
}
func (*preAdoptionFactoryPathConn) Quality() transport.PathQuality            { return transport.PathQuality{} }
func (*preAdoptionFactoryPathConn) OnDeath(func(transport.DeathCause, error)) {}
func (*preAdoptionFactoryPathConn) LocalAddr() string                         { return "local" }
func (*preAdoptionFactoryPathConn) RemoteAddr() string                        { return "remote" }
