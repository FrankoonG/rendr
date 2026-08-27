package leafmobility

import (
	"context"
	"errors"
	goruntime "runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type executionBoundaryDriver struct {
	attempt *executionBoundaryAttempt
}

func (*executionBoundaryDriver) Operation() Operation { return OperationTCPRepair }

func (driver *executionBoundaryDriver) Preflight(
	_ context.Context,
	request PreflightRequest,
) (DriverAttempt, PreflightResult, error) {
	references := testProbeReferencesForRequest(testProbeReferences(0xe1), request)
	evidence := AttemptEvidence{Digest: EvidenceDigest{0xe1}, ProbeReferences: references}
	driver.attempt.mu.Lock()
	driver.attempt.evidence = evidence
	driver.attempt.mu.Unlock()
	return driver.attempt, PreflightResult{
		Eligible: true, Stage: StagePreflightComplete,
		EvidenceDigest: evidence.Digest, ProbeReferences: references,
	}, nil
}

type executionBoundaryAttempt struct {
	mu              sync.Mutex
	evidence        AttemptEvidence
	blockStep       string
	panicStep       string
	panicValue      any
	goexitStep      string
	entered         chan struct{}
	release         chan struct{}
	enterOnce       sync.Once
	prepareErr      error
	rollbackErr     error
	failClosedErr   error
	rollbackOneShot bool
	failClosedOnce  bool
	endpointChanged bool
	publishHook     func()
	evidenceBlock   bool
	evidenceGoexit  bool
	evidencePanic   any
	evidenceEntered chan struct{}
	evidenceRelease chan struct{}
	evidenceOnce    sync.Once

	prepareCalls    atomic.Int32
	stageCalls      atomic.Int32
	publishCalls    atomic.Int32
	activateCalls   atomic.Int32
	rollbackCalls   atomic.Int32
	failClosedCalls atomic.Int32
}

func (attempt *executionBoundaryAttempt) Evidence() AttemptEvidence {
	attempt.mu.Lock()
	evidence := attempt.evidence
	block := attempt.evidenceBlock
	goexit := attempt.evidenceGoexit
	panicValue := attempt.evidencePanic
	entered := attempt.evidenceEntered
	release := attempt.evidenceRelease
	attempt.mu.Unlock()
	if block {
		attempt.evidenceOnce.Do(func() { close(entered) })
		<-release
	}
	if panicValue != nil {
		panic(panicValue)
	}
	if goexit {
		goruntime.Goexit()
	}
	return evidence
}

func (attempt *executionBoundaryAttempt) Prepare(context.Context, ExecutionRequest) error {
	attempt.prepareCalls.Add(1)
	attempt.before("prepare")
	return attempt.prepareErr
}

func (attempt *executionBoundaryAttempt) Stage(context.Context, ExecutionRequest) (PublicationEvidence, error) {
	attempt.stageCalls.Add(1)
	attempt.before("stage")
	return PublicationEvidence{Digest: EvidenceDigest{0xe2}}, nil
}

func (attempt *executionBoundaryAttempt) Publish(context.Context, ExecutionRequest) error {
	attempt.publishCalls.Add(1)
	attempt.before("publish")
	if attempt.publishHook != nil {
		attempt.publishHook()
	}
	return nil
}

func (attempt *executionBoundaryAttempt) Activate(context.Context, ExecutionRequest) error {
	attempt.activateCalls.Add(1)
	attempt.before("activate")
	return nil
}

func (attempt *executionBoundaryAttempt) Rollback(context.Context, ExecutionRequest) error {
	calls := attempt.rollbackCalls.Add(1)
	attempt.mu.Lock()
	err := attempt.rollbackErr
	oneShot := attempt.rollbackOneShot
	attempt.mu.Unlock()
	attempt.before("rollback")
	if oneShot && calls > 1 {
		return errors.New("rollback repeated after one-shot success")
	}
	return err
}

func (attempt *executionBoundaryAttempt) FailClosed(context.Context, ExecutionRequest) error {
	calls := attempt.failClosedCalls.Add(1)
	attempt.mu.Lock()
	err := attempt.failClosedErr
	oneShot := attempt.failClosedOnce
	attempt.mu.Unlock()
	attempt.before("fail-closed")
	if oneShot && calls > 1 {
		return errors.New("fail-closed repeated after one-shot success")
	}
	return err
}

func (attempt *executionBoundaryAttempt) EndpointGenerationChanged() bool {
	attempt.mu.Lock()
	defer attempt.mu.Unlock()
	return attempt.endpointChanged
}

func (attempt *executionBoundaryAttempt) before(step string) {
	attempt.mu.Lock()
	block := attempt.blockStep == step
	panicStep := attempt.panicStep == step
	panicValue := attempt.panicValue
	goexit := attempt.goexitStep == step
	attempt.mu.Unlock()
	if block {
		attempt.enterOnce.Do(func() { close(attempt.entered) })
		<-attempt.release
	}
	if panicStep {
		panic(panicValue)
	}
	if goexit {
		goruntime.Goexit()
	}
}

func (attempt *executionBoundaryAttempt) calls(step string) int32 {
	switch step {
	case "prepare":
		return attempt.prepareCalls.Load()
	case "stage":
		return attempt.stageCalls.Load()
	case "publish":
		return attempt.publishCalls.Load()
	case "activate":
		return attempt.activateCalls.Load()
	case "rollback":
		return attempt.rollbackCalls.Load()
	case "fail-closed":
		return attempt.failClosedCalls.Load()
	default:
		return 0
	}
}

func TestExecutionDriverCallbackDeadlineFencesLateCompletion(t *testing.T) {
	steps := []struct {
		name         string
		timeoutState ExecutionState
		lateState    ExecutionState
	}{
		{name: "prepare", timeoutState: ExecutionRollbackRequired, lateState: ExecutionRollbackRequired},
		{name: "stage", timeoutState: ExecutionRollbackRequired, lateState: ExecutionRollbackRequired},
		{name: "publish", timeoutState: ExecutionFailClosedRequired, lateState: ExecutionFailClosedRequired},
		{name: "activate", timeoutState: ExecutionActivationRequired, lateState: ExecutionActivationRequired},
		{name: "rollback", timeoutState: ExecutionRollbackRequired, lateState: ExecutionRolledBack},
		{name: "fail-closed", timeoutState: ExecutionFailClosedRequired, lateState: ExecutionFailedClosed},
	}
	for _, test := range steps {
		t.Run(test.name, func(t *testing.T) {
			reporter := newTestIncarnationReporter()
			attempt := &executionBoundaryAttempt{
				blockStep: test.name,
				entered:   make(chan struct{}),
				release:   make(chan struct{}),
			}
			if test.name == "rollback" {
				attempt.prepareErr = errors.New("force rollback")
			}
			if test.name == "publish" || test.name == "activate" {
				attempt.publishHook = func() { reporter.value.Add(1) }
			}
			driver := &executionBoundaryDriver{attempt: attempt}
			issuer, claim, plan, transaction := executableClaimFixtureWithDeadlineAndReporter(
				t, driver, canonicalTime(time.Now().Add(3*time.Second)), reporter,
			)
			execution, err := issuer.ConsumeExecution(claim, transaction, plan, testPeerAgreement(plan))
			if err != nil {
				t.Fatal(err)
			}
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(attempt.release) }) }
			t.Cleanup(func() {
				release()
				cleanupBoundaryExecution(execution)
			})

			switch test.name {
			case "stage", "publish", "activate", "fail-closed":
				if err := execution.Prepare(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			switch test.name {
			case "publish", "activate":
				if err := execution.Stage(context.Background()); err != nil {
					t.Fatal(err)
				}
				authorizeExecutionPublish(t, execution, transaction)
			}
			if test.name == "activate" {
				if err := execution.Publish(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if test.name == "rollback" {
				if err := execution.Prepare(context.Background()); !errors.Is(err, attempt.prepareErr) {
					t.Fatalf("prepare error=%v want=%v", err, attempt.prepareErr)
				}
			}

			generationBefore := claim.Snapshot().Generation
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			result := make(chan error, 1)
			go func() { result <- invokeBoundaryExecutionStep(execution, test.name, ctx) }()
			select {
			case <-attempt.entered:
			case <-time.After(time.Second):
				cancel()
				release()
				t.Fatalf("%s did not enter the driver", test.name)
			}
			select {
			case err := <-result:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("%s error=%v want deadline", test.name, err)
				}
			case <-time.After(time.Second):
				release()
				t.Fatalf("%s ignored the supplied deadline", test.name)
			}
			cancel()
			if execution.State() != test.timeoutState {
				t.Fatalf("%s timeout state=%d want=%d", test.name, execution.State(), test.timeoutState)
			}
			if test.name == "publish" && claim.Snapshot().Generation == generationBefore {
				t.Fatal("uncertain publish did not invalidate the endpoint generation")
			}

			for index := 0; index < 32; index++ {
				if err := invokeBoundaryCleanupStep(execution, test.name); err == nil {
					t.Fatalf("%s allowed concurrent cleanup attempt %d", test.name, index)
				}
			}
			if calls := attempt.calls(test.name); calls != 1 {
				t.Fatalf("%s callback calls while orphaned=%d want=1", test.name, calls)
			}

			release()
			waitExecutionDriverCall(t, execution)
			if execution.State() != test.lateState {
				t.Fatalf("%s late result changed state to %d want=%d", test.name, execution.State(), test.lateState)
			}
			if test.name == "stage" {
				execution.token.mu.Lock()
				publication := execution.token.publication
				execution.token.mu.Unlock()
				if publication != (PublicationEvidence{}) {
					t.Fatalf("late Stage published evidence %+v", publication)
				}
			}
			if test.name == "publish" && transaction.State() == ResourceTransactionPublished {
				t.Fatal("late Publish committed the resource transaction")
			}

			switch test.name {
			case "prepare", "stage":
				if err := execution.Rollback(context.Background()); err != nil {
					t.Fatal(err)
				}
				finalizeRolledBackExecution(t, execution)
			case "rollback":
				finalizeRolledBackExecution(t, execution)
			case "publish":
				if err := execution.FailClosed(context.Background()); err != nil {
					t.Fatal(err)
				}
			case "fail-closed":
				if err := execution.FailClosed(context.Background()); err != nil {
					t.Fatal(err)
				}
			case "activate":
				if err := execution.Activate(context.Background()); err != nil {
					t.Fatal(err)
				}
				if err := execution.FinalizePublished(); err != nil {
					t.Fatal(err)
				}
			}
			assertExecutionLeaseReleased(t, execution)
		})
	}

	t.Run("blocking evidence cannot retain final acceptance", func(t *testing.T) {
		attempt := &executionBoundaryAttempt{}
		issuer, claim, plan, transaction := executableClaimFixtureWithDeadline(
			t, &executionBoundaryDriver{attempt: attempt}, canonicalTime(time.Now().Add(3*time.Second)),
		)
		execution, err := issuer.ConsumeExecution(claim, transaction, plan, testPeerAgreement(plan))
		if err != nil {
			t.Fatal(err)
		}
		if err := execution.Prepare(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := execution.Stage(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := transaction.MarkCommitPublished(); err != nil {
			t.Fatal(err)
		}
		entered := make(chan struct{})
		release := make(chan struct{})
		var releaseOnce sync.Once
		unblock := func() { releaseOnce.Do(func() { close(release) }) }
		t.Cleanup(unblock)
		attempt.mu.Lock()
		attempt.evidenceBlock = true
		attempt.evidenceEntered = entered
		attempt.evidenceRelease = release
		attempt.mu.Unlock()

		type acceptanceResult struct {
			disposition FinalAcceptanceDisposition
			err         error
		}
		result := make(chan acceptanceResult, 1)
		go func() {
			disposition, resolveErr := execution.ResolveFinalAcceptance(true)
			result <- acceptanceResult{disposition: disposition, err: resolveErr}
		}()
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("final acceptance did not enter Evidence")
		}
		if _, evidenceErr := readAttemptEvidence(attempt); !errors.Is(evidenceErr, ErrDriverEvidenceBusy) {
			t.Fatalf("concurrent Evidence error=%v want=%v", evidenceErr, ErrDriverEvidenceBusy)
		}
		select {
		case outcome := <-result:
			if outcome.err != nil || outcome.disposition != FinalAcceptanceRollbackOnly {
				t.Fatalf("final acceptance outcome=%d error=%v want rollback-only", outcome.disposition, outcome.err)
			}
		case <-time.After(time.Second):
			t.Fatal("blocking Evidence retained final acceptance")
		}
		if execution.State() != ExecutionRollbackRequired {
			t.Fatalf("state=%d want rollback-required", execution.State())
		}
		if err := execution.Rollback(context.Background()); err != nil {
			t.Fatalf("cleanup reserve did not admit rollback: %v", err)
		}
		finalizeRolledBackExecution(t, execution)
		unblock()
	})

	for _, abnormal := range []struct {
		name      string
		configure func(*executionBoundaryAttempt)
		clear     func(*executionBoundaryAttempt)
	}{
		{
			name:      "evidence Goexit",
			configure: func(attempt *executionBoundaryAttempt) { attempt.evidenceGoexit = true },
			clear:     func(attempt *executionBoundaryAttempt) { attempt.evidenceGoexit = false },
		},
		{
			name:      "evidence hostile panic",
			configure: func(attempt *executionBoundaryAttempt) { attempt.evidencePanic = hostilePanicPayload{} },
			clear:     func(attempt *executionBoundaryAttempt) { attempt.evidencePanic = nil },
		},
	} {
		t.Run(abnormal.name, func(t *testing.T) {
			attempt := &executionBoundaryAttempt{}
			issuer, claim, plan, transaction := executableClaimFixture(
				t, &executionBoundaryDriver{attempt: attempt},
			)
			execution, err := issuer.ConsumeExecution(claim, transaction, plan, testPeerAgreement(plan))
			if err != nil {
				t.Fatal(err)
			}
			if err := execution.Prepare(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := execution.Stage(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := transaction.MarkCommitPublished(); err != nil {
				t.Fatal(err)
			}
			attempt.mu.Lock()
			abnormal.configure(attempt)
			attempt.mu.Unlock()
			disposition, resolveErr := execution.ResolveFinalAcceptance(true)
			if resolveErr != nil || disposition != FinalAcceptanceRollbackOnly {
				t.Fatalf("final acceptance outcome=%d error=%v want rollback-only", disposition, resolveErr)
			}
			attempt.mu.Lock()
			abnormal.clear(attempt)
			attempt.mu.Unlock()
			if err := execution.Rollback(context.Background()); err != nil {
				t.Fatal(err)
			}
			finalizeRolledBackExecution(t, execution)
		})
	}
}

func TestExecutionLateCleanupCompletionIsReconciledExactlyOnce(t *testing.T) {
	cleanupFailure := errors.New("late cleanup failed")

	t.Run("rollback late success is not repeated", func(t *testing.T) {
		attempt := &executionBoundaryAttempt{
			blockStep:       "rollback",
			entered:         make(chan struct{}),
			release:         make(chan struct{}),
			prepareErr:      errors.New("force rollback"),
			rollbackOneShot: true,
		}
		execution := consumeExecutableClaim(t, &executionBoundaryDriver{attempt: attempt})
		if err := execution.Prepare(context.Background()); !errors.Is(err, attempt.prepareErr) {
			t.Fatalf("Prepare error=%v want=%v", err, attempt.prepareErr)
		}

		invokeCleanupUntilTimeout(t, execution, attempt, "rollback")
		close(attempt.release)
		waitExecutionState(t, execution, ExecutionRolledBack)
		if err := execution.Rollback(context.Background()); err != nil {
			t.Fatalf("idempotent terminal Rollback: %v", err)
		}
		if calls := attempt.rollbackCalls.Load(); calls != 1 {
			t.Fatalf("rollback calls=%d want=1", calls)
		}
		finalizeRolledBackExecution(t, execution)
	})

	t.Run("rollback late error remains retryable", func(t *testing.T) {
		attempt := &executionBoundaryAttempt{
			blockStep:   "rollback",
			entered:     make(chan struct{}),
			release:     make(chan struct{}),
			prepareErr:  errors.New("force rollback"),
			rollbackErr: cleanupFailure,
		}
		execution := consumeExecutableClaim(t, &executionBoundaryDriver{attempt: attempt})
		if err := execution.Prepare(context.Background()); !errors.Is(err, attempt.prepareErr) {
			t.Fatalf("Prepare error=%v want=%v", err, attempt.prepareErr)
		}

		invokeCleanupUntilTimeout(t, execution, attempt, "rollback")
		close(attempt.release)
		waitExecutionState(t, execution, ExecutionRollbackRequired)
		attempt.mu.Lock()
		attempt.blockStep = ""
		attempt.rollbackErr = nil
		attempt.mu.Unlock()
		if err := execution.Rollback(context.Background()); err != nil {
			t.Fatalf("Rollback retry: %v", err)
		}
		if calls := attempt.rollbackCalls.Load(); calls != 2 {
			t.Fatalf("rollback calls=%d want=2", calls)
		}
		finalizeRolledBackExecution(t, execution)
	})

	t.Run("fail-closed late success releases concurrent retirement", func(t *testing.T) {
		attempt := &executionBoundaryAttempt{
			blockStep:      "fail-closed",
			entered:        make(chan struct{}),
			release:        make(chan struct{}),
			failClosedOnce: true,
		}
		issuer, claim, plan, transaction := executableClaimFixture(
			t, &executionBoundaryDriver{attempt: attempt},
		)
		execution, err := issuer.ConsumeExecution(claim, transaction, plan, testPeerAgreement(plan))
		if err != nil {
			t.Fatal(err)
		}
		if err := execution.Prepare(context.Background()); err != nil {
			t.Fatal(err)
		}

		invokeCleanupUntilTimeout(t, execution, attempt, "fail-closed")
		binding, ok := claim.Binding()
		if !ok {
			t.Fatal("claim is not bound")
		}
		retired := make(chan error, 1)
		go func() { retired <- claim.Retire(binding) }()
		select {
		case err := <-retired:
			t.Fatalf("retirement returned before late cleanup: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
		close(attempt.release)
		select {
		case err := <-retired:
			if err != nil {
				t.Fatalf("Retire: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("late successful FailClosed did not release retirement")
		}
		if execution.State() != ExecutionFailedClosed {
			t.Fatalf("state=%d want failed-closed", execution.State())
		}
		if err := execution.FailClosed(context.Background()); err != nil {
			t.Fatalf("idempotent terminal FailClosed: %v", err)
		}
		if calls := attempt.failClosedCalls.Load(); calls != 1 {
			t.Fatalf("fail-closed calls=%d want=1", calls)
		}
	})

	t.Run("fail-closed late error remains fail-closed retryable", func(t *testing.T) {
		attempt := &executionBoundaryAttempt{
			blockStep:     "fail-closed",
			entered:       make(chan struct{}),
			release:       make(chan struct{}),
			failClosedErr: cleanupFailure,
		}
		execution := consumeExecutableClaim(t, &executionBoundaryDriver{attempt: attempt})
		if err := execution.Prepare(context.Background()); err != nil {
			t.Fatal(err)
		}

		invokeCleanupUntilTimeout(t, execution, attempt, "fail-closed")
		close(attempt.release)
		waitExecutionState(t, execution, ExecutionFailClosedRequired)
		attempt.mu.Lock()
		attempt.blockStep = ""
		attempt.failClosedErr = nil
		attempt.mu.Unlock()
		if err := execution.FailClosed(context.Background()); err != nil {
			t.Fatalf("FailClosed retry: %v", err)
		}
		if calls := attempt.failClosedCalls.Load(); calls != 2 {
			t.Fatalf("fail-closed calls=%d want=2", calls)
		}
		assertExecutionLeaseReleased(t, execution)
	})
}

func invokeCleanupUntilTimeout(
	t testing.TB,
	execution *Execution,
	attempt *executionBoundaryAttempt,
	step string,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- invokeBoundaryExecutionStep(execution, step, ctx) }()
	select {
	case <-attempt.entered:
	case <-time.After(time.Second):
		t.Fatalf("%s did not enter the driver", step)
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("%s error=%v want deadline", step, err)
		}
	case <-time.After(time.Second):
		t.Fatalf("%s ignored the supplied deadline", step)
	}
}

func waitExecutionState(t testing.TB, execution *Execution, want ExecutionState) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		state := execution.State()
		execution.token.mu.Lock()
		busy := execution.token.busy
		execution.token.mu.Unlock()
		if state == want && !busy {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("state=%d want=%d", execution.State(), want)
}

func TestExecutionDriverHostilePanicPayloadIsNotFormatted(t *testing.T) {
	attempt := &executionBoundaryAttempt{
		panicStep:  "prepare",
		panicValue: hostilePanicPayload{},
	}
	execution := consumeExecutableClaim(t, &executionBoundaryDriver{attempt: attempt})
	if err := execution.Prepare(context.Background()); !errors.Is(err, ErrExecutionDriverPanic) {
		t.Fatalf("Prepare error=%v want=%v", err, ErrExecutionDriverPanic)
	}
	attempt.mu.Lock()
	attempt.panicStep = ""
	attempt.mu.Unlock()
	if err := execution.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	finalizeRolledBackExecution(t, execution)
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
		var calls atomic.Int32
		_, call, err := invokeDriverStep(
			context.Background(), "capacity", ContextDigest{}, ProbeReference{}, false, false, driverCallbackNormal, false,
			func() (PublicationEvidence, error) {
				calls.Add(1)
				return PublicationEvidence{}, nil
			},
		)
		if !errors.Is(err, ErrDriverCallbackCapacity) || call != nil {
			t.Fatalf("capacity error/call=%v/%v", err, call)
		}
		if got := calls.Load(); got != 0 {
			t.Fatalf("capacity-exhausted callback calls=%d want=0", got)
		}
	})
	t.Run("cleanup reserve survives normal callback saturation", func(t *testing.T) {
		failure := errors.New("force rollback")
		attempt := &executionBoundaryAttempt{prepareErr: failure}
		execution := consumeExecutableClaim(t, &executionBoundaryDriver{attempt: attempt})
		if err := execution.Prepare(context.Background()); !errors.Is(err, failure) {
			t.Fatalf("Prepare error=%v want=%v", err, failure)
		}
		for index := 0; index < driverCallbackLimit; index++ {
			if !acquireDriverCallbackPermit() {
				t.Fatalf("normal permit %d was unavailable", index)
			}
		}
		defer func() {
			for index := 0; index < driverCallbackLimit; index++ {
				releaseDriverCallbackPermit()
			}
		}()
		for index := 1; index < driverCleanupCallbackLimit; index++ {
			if !acquireDriverCleanupCallbackPermit() {
				t.Fatalf("cleanup reservation %d was unavailable", index)
			}
		}
		defer func() {
			for index := 1; index < driverCleanupCallbackLimit; index++ {
				releaseDriverCleanupCallbackPermit()
			}
		}()
		if err := execution.Rollback(context.Background()); err != nil {
			t.Fatalf("Rollback under normal and cleanup saturation: %v", err)
		}
		if calls := attempt.rollbackCalls.Load(); calls != 1 {
			t.Fatalf("rollback calls=%d want=1", calls)
		}
		finalizeRolledBackExecution(t, execution)
	})
	t.Run("cleanup capacity is reserved before destructive work", func(t *testing.T) {
		for index := 0; index < driverCleanupCallbackLimit; index++ {
			if !acquireDriverCleanupCallbackPermit() {
				t.Fatalf("cleanup permit %d was unavailable", index)
			}
		}
		defer func() {
			for index := 0; index < driverCleanupCallbackLimit; index++ {
				releaseDriverCleanupCallbackPermit()
			}
		}()
		attempt := &executionBoundaryAttempt{}
		execution := consumeExecutableClaim(t, &executionBoundaryDriver{attempt: attempt})
		if err := execution.Prepare(context.Background()); !errors.Is(err, ErrDriverCallbackCapacity) {
			t.Fatalf("Prepare without cleanup reservation=%v want=%v", err, ErrDriverCallbackCapacity)
		}
		if calls := attempt.prepareCalls.Load(); calls != 0 {
			t.Fatalf("capacity-exhausted Prepare calls=%d want=0", calls)
		}
		if execution.State() != ExecutionAuthorized {
			t.Fatalf("capacity-exhausted state=%d want authorized", execution.State())
		}
		if err := execution.Rollback(context.Background()); err != nil {
			t.Fatal(err)
		}
		finalizeRolledBackExecution(t, execution)
	})
}

func invokeBoundaryExecutionStep(execution *Execution, step string, ctx context.Context) error {
	switch step {
	case "prepare":
		return execution.Prepare(ctx)
	case "stage":
		return execution.Stage(ctx)
	case "publish":
		return execution.Publish(ctx)
	case "activate":
		return execution.Activate(ctx)
	case "rollback":
		return execution.Rollback(ctx)
	case "fail-closed":
		return execution.FailClosed(ctx)
	default:
		return ErrExecutionState
	}
}

func invokeBoundaryCleanupStep(execution *Execution, blockedStep string) error {
	switch blockedStep {
	case "publish", "fail-closed":
		return execution.FailClosed(context.Background())
	case "activate":
		return execution.Activate(context.Background())
	default:
		return execution.Rollback(context.Background())
	}
}

func waitExecutionDriverCall(t testing.TB, execution *Execution) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		_ = execution.State()
		execution.token.mu.Lock()
		busy := execution.token.busy
		execution.token.mu.Unlock()
		if !busy {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("late driver callback did not release its execution gate")
		}
		time.Sleep(time.Millisecond)
	}
}

func cleanupBoundaryExecution(execution *Execution) {
	if execution == nil {
		return
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		switch execution.State() {
		case ExecutionAuthorized:
			_ = execution.FailClosed(context.Background())
		case ExecutionPrepared, ExecutionStaged, ExecutionPublishAuthorized, ExecutionRollbackRequired:
			if err := execution.Rollback(context.Background()); err == nil {
				_ = execution.FinalizeRolledBack()
			}
		case ExecutionPublished, ExecutionActivationRequired, ExecutionFailClosedRequired:
			_ = execution.FailClosed(context.Background())
		case ExecutionActivated:
			_ = execution.FinalizePublished()
			return
		case ExecutionRolledBack:
			_ = execution.FinalizeRolledBack()
			return
		case ExecutionFailedClosed, ExecutionInvalid:
			return
		}
		time.Sleep(time.Millisecond)
	}
}

func assertExecutionLeaseReleased(t testing.TB, execution *Execution) {
	t.Helper()
	execution.token.mu.Lock()
	busy, leaseHeld := execution.token.busy, execution.token.leaseHeld
	execution.token.mu.Unlock()
	execution.token.claim.executionMu.Lock()
	claimActive := execution.token.claim.executionActive
	execution.token.claim.executionMu.Unlock()
	if busy || leaseHeld || claimActive {
		t.Fatalf("busy/token lease/claim lease=%v/%v/%v want false/false/false", busy, leaseHeld, claimActive)
	}
}
