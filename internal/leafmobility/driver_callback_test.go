package leafmobility

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	goruntime "runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type hostilePanicPayload struct{}

func (hostilePanicPayload) Error() string { panic("panic payload must not be formatted") }

type preflightBoundaryDriver struct {
	operation Operation
	entered   chan struct{}
	release   chan struct{}
	enterOnce sync.Once
	calls     atomic.Int32
	active    atomic.Int32
	maximum   atomic.Int32
	goexit    bool
	panicWith any
}

func (driver *preflightBoundaryDriver) Operation() Operation { return driver.operation }

func (driver *preflightBoundaryDriver) Preflight(
	_ context.Context,
	request PreflightRequest,
) (DriverAttempt, PreflightResult, error) {
	driver.calls.Add(1)
	active := driver.active.Add(1)
	defer driver.active.Add(-1)
	for {
		maximum := driver.maximum.Load()
		if active <= maximum || driver.maximum.CompareAndSwap(maximum, active) {
			break
		}
	}
	if driver.entered != nil {
		driver.enterOnce.Do(func() { close(driver.entered) })
	}
	if driver.goexit {
		goruntime.Goexit()
	}
	if driver.panicWith != nil {
		panic(driver.panicWith)
	}
	if driver.release != nil {
		<-driver.release
	}
	references := testProbeReferencesForRequest(testProbeReferences(0xd1), request)
	evidence := EvidenceDigest{0xd1}
	attempt := &fakeDriverTransaction{evidence: AttemptEvidence{Digest: evidence, ProbeReferences: references}}
	return attempt, PreflightResult{
		Eligible: true, Stage: StagePreflightComplete,
		EvidenceDigest: evidence, ProbeReferences: references,
	}, nil
}

func TestDriverPreflightDeadlineRetainsOneOrphanAndDiscardsLateAttempt(t *testing.T) {
	driver := &preflightBoundaryDriver{
		operation: OperationTCPRepair,
		entered:   make(chan struct{}),
		release:   make(chan struct{}),
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(driver.release) }) }
	t.Cleanup(release)
	claim := MustNewDrivenClaim(testDrivenFacts(), driver, MustNewResource(ScopeEndpoint))
	binding := testBinding(0xd1)
	bindDrivenClaim(t, claim, binding)
	t.Cleanup(func() { _ = claim.Retire(binding) })

	request := fixedPlanRequest(binding)
	request.Deadline = canonicalTime(time.Now().Add(250 * time.Millisecond))
	type planResult struct {
		plan Plan
		err  error
	}
	first := make(chan planResult, 1)
	go func() {
		plan, err := PlanCandidate(context.Background(), claim, request)
		first <- planResult{plan: plan, err: err}
	}()
	select {
	case <-driver.entered:
	case outcome := <-first:
		t.Fatalf("preflight returned before driver entry: plan=%+v error=%v", outcome.plan, outcome.err)
	case <-time.After(time.Second):
		t.Fatal("preflight did not enter the driver")
	}
	select {
	case outcome := <-first:
		assertFallbackPlan(t, outcome.plan, outcome.err, StagePeerPlan, ReasonDeadlineExpired, false)
	case <-time.After(2 * time.Second):
		release()
		t.Fatal("preflight ignored its immutable deadline")
	}
	key, ok := driverPreflightIdentity(driver)
	if !ok {
		t.Fatal("driver has no stable preflight identity")
	}
	driverPreflightRegistry.Lock()
	orphan := driverPreflightRegistry.active[key]
	driverPreflightRegistry.Unlock()
	if orphan == nil {
		t.Fatal("timed-out preflight did not retain its callback slot")
	}

	for index := 0; index < 32; index++ {
		retry := fixedPlanRequest(binding)
		retry.Deadline = canonicalTime(time.Now().Add(time.Second))
		plan, err := PlanCandidate(context.Background(), claim, retry)
		assertFallbackPlan(t, plan, err, StagePreflight, ReasonPreflightFailed, false)
	}
	if calls, active, maximum := driver.calls.Load(), driver.active.Load(), driver.maximum.Load(); calls != 1 || active != 1 || maximum != 1 {
		t.Fatalf("preflight calls/active/max=%d/%d/%d want=1/1/1", calls, active, maximum)
	}
	driverPreflightRegistry.Lock()
	retained := driverPreflightRegistry.active[key]
	driverPreflightRegistry.Unlock()
	if retained != orphan {
		t.Fatal("preflight retries replaced the retained orphan")
	}

	release()
	select {
	case <-orphan.done:
	case <-time.After(time.Second):
		t.Fatal("late preflight did not complete its callback wrapper")
	}
	if driver.active.Load() != 0 {
		t.Fatalf("driver remained active after callback completion: %d", driver.active.Load())
	}
	if orphan.outcome.attempt == nil {
		t.Fatal("late preflight did not produce the expected discarded attempt")
	}
	lateAttemptPointer, ok := interfaceIdentity(orphan.outcome.attempt)
	if !ok {
		t.Fatal("late driver attempt has no stable identity")
	}
	lateAttemptKey := driverAttemptKey{typeOf: reflect.TypeOf(orphan.outcome.attempt), ptr: lateAttemptPointer}
	driverAttemptRegistry.Lock()
	_, lateAttemptRegistered := driverAttemptRegistry.active[lateAttemptKey]
	driverAttemptRegistry.Unlock()
	if lateAttemptRegistered {
		t.Fatal("attempt returned after the immutable deadline was registered for execution")
	}
	retry := fixedPlanRequest(binding)
	retry.Deadline = canonicalTime(time.Now().Add(time.Second))
	plan, err := PlanCandidate(context.Background(), claim, retry)
	if err != nil || plan.Operation != OperationTCPRepair || plan.Stage != StagePreflightComplete {
		t.Fatalf("preflight after orphan cleanup plan=%+v error=%v", plan, err)
	}
	if plan.attempt == nil || plan.attempt.attempt == orphan.outcome.attempt {
		t.Fatal("preflight after orphan cleanup reused the discarded late attempt")
	}
	if calls, maximum := driver.calls.Load(), driver.maximum.Load(); calls != 2 || maximum != 1 {
		t.Fatalf("preflight calls/max after retry=%d/%d want=2/1", calls, maximum)
	}
}

func TestDriverAttemptRegistryExpiresLastRecordWithoutAnotherRegistration(t *testing.T) {
	attempt := &fakeDriverTransaction{}
	ptr, ok := interfaceIdentity(attempt)
	if !ok {
		t.Fatal("driver attempt has no stable identity")
	}
	key := driverAttemptKey{typeOf: reflect.TypeOf(attempt), ptr: ptr}
	deadline, ok := registerDriverAttempt(attempt, time.Now().Add(20*time.Millisecond))
	if !ok {
		t.Fatal("driver attempt registration failed")
	}
	driverAttemptRegistry.Lock()
	_, registered := driverAttemptRegistry.active[key]
	driverAttemptRegistry.Unlock()
	if !registered {
		t.Fatal("driver attempt was not retained through its execution deadline")
	}

	limit := time.Now().Add(2 * time.Second)
	for {
		driverAttemptRegistry.Lock()
		_, registered = driverAttemptRegistry.active[key]
		driverAttemptRegistry.Unlock()
		if !registered {
			break
		}
		if time.Now().After(limit) {
			t.Fatalf("last driver attempt remained registered after deadline %v", deadline)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestDriverAttemptOldExpiryCannotDeleteNewRecord(t *testing.T) {
	attempt := &fakeDriverTransaction{}
	ptr, ok := interfaceIdentity(attempt)
	if !ok {
		t.Fatal("driver attempt has no stable identity")
	}
	key := driverAttemptKey{typeOf: reflect.TypeOf(attempt), ptr: ptr}
	_, ok = registerDriverAttempt(attempt, time.Now().Add(time.Second))
	if !ok {
		t.Fatal("driver attempt registration failed")
	}
	driverAttemptRegistry.Lock()
	old := driverAttemptRegistry.active[key]
	newer := old
	newer.id++
	if newer.id == 0 {
		newer.id++
	}
	newer.deadline = time.Now().Add(time.Second)
	driverAttemptRegistry.active[key] = newer
	driverAttemptRegistry.Unlock()
	t.Cleanup(func() {
		driverAttemptRegistry.Lock()
		delete(driverAttemptRegistry.active, key)
		driverAttemptRegistry.Unlock()
	})

	expireDriverAttemptRecord(key, old.id, time.Now().Add(-time.Second))
	driverAttemptRegistry.Lock()
	got, exists := driverAttemptRegistry.active[key]
	driverAttemptRegistry.Unlock()
	if !exists || got.id != newer.id {
		t.Fatalf("old expiry removed newer driver attempt record: exists=%t id=%d want=%d", exists, got.id, newer.id)
	}
}

func TestDriverPreflightGoexitAndHostilePanicAreContained(t *testing.T) {
	for _, test := range []struct {
		name   string
		driver *preflightBoundaryDriver
		want   error
	}{
		{
			name:   "goexit",
			driver: &preflightBoundaryDriver{operation: OperationTCPRepair, goexit: true},
			want:   ErrDriverPreflightGoexit,
		},
		{
			name:   "hostile panic payload",
			driver: &preflightBoundaryDriver{operation: OperationTCPRepair, panicWith: hostilePanicPayload{}},
			want:   ErrDriverPreflightPanic,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			binding := testBinding(byte(0xd2 + len(test.name)))
			request := fixedPlanRequest(binding)
			request.Deadline = canonicalTime(time.Now().Add(time.Second))
			ctx, cancel := context.WithDeadline(context.Background(), request.Deadline)
			defer cancel()
			_, _, _, err := invokeDriverPreflight(ctx, test.driver, request, testDrivenFacts())
			if !errors.Is(err, ErrInvalidDriver) || !errors.Is(err, test.want) {
				t.Fatalf("preflight error=%v want invalid-driver + %v", err, test.want)
			}
			if test.driver.active.Load() != 0 || test.driver.calls.Load() != 1 {
				t.Fatalf("preflight active/calls=%d/%d want=0/1", test.driver.active.Load(), test.driver.calls.Load())
			}
		})
	}
	t.Run("trusted timeout diagnostic does not format hostile causes", func(t *testing.T) {
		timeoutErr := newDriverCallbackError(
			ErrExecutionDriver, "stage", context.DeadlineExceeded,
		)
		const wantTimeout = "leafmobility: driver execution failed: stage: context deadline exceeded"
		if got := timeoutErr.Error(); got != wantTimeout {
			t.Fatalf("timeout diagnostic=%q want=%q", got, wantTimeout)
		}
		wrappedTimeoutErr := newDriverCallbackError(
			ErrExecutionDriver, "rollback",
			errors.Join(errors.New("opaque driver failure"), fmt.Errorf("internal boundary: %w", context.DeadlineExceeded)),
		)
		const wantWrapped = "leafmobility: driver execution failed: rollback: context deadline exceeded"
		if got := wrappedTimeoutErr.Error(); got != wantWrapped {
			t.Fatalf("wrapped timeout diagnostic=%q want=%q", got, wantWrapped)
		}
		hostileErr := newDriverCallbackError(ErrExecutionDriver, "stage", hostilePanicPayload{})
		const wantHostile = "leafmobility: driver execution failed: stage"
		if got := hostileErr.Error(); got != wantHostile {
			t.Fatalf("hostile diagnostic=%q want=%q", got, wantHostile)
		}
	})
	t.Run("global callback capacity", func(t *testing.T) {
		for index := 0; index < driverCallbackLimit; index++ {
			if !acquireDriverCallbackPermit() {
				t.Fatalf("permit %d was unavailable", index)
			}
		}
		defer func() {
			for index := 0; index < driverCallbackLimit; index++ {
				releaseDriverCallbackPermit()
			}
		}()
		driver := &preflightBoundaryDriver{operation: OperationTCPRepair}
		request := fixedPlanRequest(testBinding(0xf1))
		request.Deadline = canonicalTime(time.Now().Add(time.Second))
		_, _, _, err := invokeDriverPreflight(context.Background(), driver, request, testDrivenFacts())
		if !errors.Is(err, ErrDriverCallbackCapacity) || driver.calls.Load() != 0 {
			t.Fatalf("capacity error/calls=%v/%d", err, driver.calls.Load())
		}
	})
}
