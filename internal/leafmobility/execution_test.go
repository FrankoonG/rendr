package leafmobility

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
)

type transactionalTestDriver struct {
	operation Operation
	result    PreflightResult
	attempt   DriverAttempt
}

func (d *transactionalTestDriver) Operation() Operation { return d.operation }

func (d *transactionalTestDriver) Preflight(_ context.Context, request PreflightRequest) (DriverAttempt, PreflightResult, error) {
	result := d.result
	result.ProbeReferences = testProbeReferencesForRequest(result.ProbeReferences, request)
	if attempt, ok := d.attempt.(*transactionalTestAttempt); ok {
		attempt.mu.Lock()
		attempt.evidence = AttemptEvidence{Digest: result.EvidenceDigest, ProbeReferences: result.ProbeReferences}
		attempt.mu.Unlock()
	}
	return d.attempt, result, nil
}

type transactionalTestAttempt struct {
	prepareErr  error
	cutoverErr  error
	commitErr   error
	rollbackErr error

	prepareCalls   atomic.Int32
	cutoverCalls   atomic.Int32
	commitCalls    atomic.Int32
	rollbackCalls  atomic.Int32
	prepareEnter   chan struct{}
	prepareExit    chan struct{}
	commitEnter    chan struct{}
	commitExit     chan struct{}
	panicPrepare   bool
	mu             sync.Mutex
	request        ExecutionRequest
	evidence       AttemptEvidence
	rollbackCtxErr error
}

func (a *transactionalTestAttempt) Evidence() AttemptEvidence {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.evidence
}

func (a *transactionalTestAttempt) Prepare(ctx context.Context, request ExecutionRequest) error {
	a.prepareCalls.Add(1)
	a.mu.Lock()
	a.request = request
	a.mu.Unlock()
	if a.prepareEnter != nil {
		close(a.prepareEnter)
	}
	if a.prepareExit != nil {
		select {
		case <-a.prepareExit:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if a.panicPrepare {
		panic("forced prepare panic")
	}
	return a.prepareErr
}

func (a *transactionalTestAttempt) Cutover(context.Context, ExecutionRequest) error {
	a.cutoverCalls.Add(1)
	return a.cutoverErr
}

func (a *transactionalTestAttempt) Commit(context.Context, ExecutionRequest) error {
	a.commitCalls.Add(1)
	if a.commitEnter != nil {
		close(a.commitEnter)
	}
	if a.commitExit != nil {
		<-a.commitExit
	}
	return a.commitErr
}

func (a *transactionalTestAttempt) Rollback(ctx context.Context, _ ExecutionRequest) error {
	a.rollbackCalls.Add(1)
	a.mu.Lock()
	a.rollbackCtxErr = ctx.Err()
	a.mu.Unlock()
	return a.rollbackErr
}

func TestClaimConsumeExecutionBindsExactPlanAndDriver(t *testing.T) {
	attempt := &transactionalTestAttempt{}
	driver := &transactionalTestDriver{
		operation: OperationTCPRepair,
		result: PreflightResult{
			Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{0xa5}, ProbeReferences: testProbeReferences(0xa5),
		},
		attempt: attempt,
	}
	issuer, claim, plan, tx := executableClaimFixture(t, driver)

	forged := plan
	forged.TransactionID[0] ^= 0xff
	forgedAttempt := *plan.attempt
	forgedRequest := forgedAttempt.request
	forgedRequest.TransactionID = forged.TransactionID
	forgedAttempt.request = forgedRequest
	forged.attempt = &forgedAttempt
	forged.LocalDigest = digestPlan(forged)
	if _, err := issuer.ConsumeExecution(claim, tx, forged, testPeerAgreement(forged)); !errors.Is(err, ErrAuthorityStale) {
		t.Fatalf("forged plan consume=%v want=%v", err, ErrAuthorityStale)
	}
	if tx.State() != ResourceTransactionFinalAccepted {
		t.Fatalf("forged plan changed transaction state=%d", tx.State())
	}

	mutations := []func(*PeerAgreement){
		func(a *PeerAgreement) { a.Binding.RouteGeneration++ },
		func(a *PeerAgreement) { a.Generation++ },
		func(a *PeerAgreement) { a.ActorEndpointGeneration++ },
		func(a *PeerAgreement) { a.PeerEndpointGeneration++ },
		func(a *PeerAgreement) { a.ActorPlanDigest[0] ^= 0xff },
		func(a *PeerAgreement) { a.ProposalDigest[0] ^= 0xff },
		func(a *PeerAgreement) { a.PeerPlanDigest[0] ^= 0xff },
		func(a *PeerAgreement) { a.AgreementDigest[0] ^= 0xff },
		func(a *PeerAgreement) { a.ReservationID[0] ^= 0xff },
	}
	for index, mutate := range mutations {
		agreement := testPeerAgreement(plan)
		mutate(&agreement)
		if _, err := issuer.ConsumeExecution(claim, tx, plan, agreement); !errors.Is(err, ErrInvalidPeerAgreement) {
			t.Fatalf("mutated agreement %d consume=%v want=%v", index, err, ErrInvalidPeerAgreement)
		}
		if tx.State() != ResourceTransactionFinalAccepted {
			t.Fatalf("mutated agreement %d changed transaction state=%d", index, tx.State())
		}
	}
	attempt.mu.Lock()
	originalEvidence := attempt.evidence
	attempt.evidence.Digest[0] ^= 0xff
	attempt.mu.Unlock()
	if _, err := issuer.ConsumeExecution(claim, tx, plan, testPeerAgreement(plan)); !errors.Is(err, ErrAuthorityStale) {
		t.Fatalf("mutated attempt evidence consume=%v want=%v", err, ErrAuthorityStale)
	}
	if attempt.prepareCalls.Load() != 0 || tx.State() != ResourceTransactionFinalAccepted {
		t.Fatalf("mutated attempt invoked driver or changed transaction: calls=%d state=%d", attempt.prepareCalls.Load(), tx.State())
	}
	attempt.mu.Lock()
	attempt.evidence = originalEvidence
	attempt.mu.Unlock()

	wrongIssuer := NewAuthorityIssuer()
	if _, err := wrongIssuer.ConsumeExecution(claim, tx, plan, testPeerAgreement(plan)); !errors.Is(err, ErrAuthorityIssuerMismatch) {
		t.Fatalf("wrong issuer consume=%v want=%v", err, ErrAuthorityIssuerMismatch)
	}
	execution, err := issuer.ConsumeExecution(claim, tx, plan, testPeerAgreement(plan))
	if err != nil {
		t.Fatal(err)
	}
	if execution.State() != ExecutionAuthorized || tx.State() != ResourceTransactionConsumed {
		t.Fatalf("execution=%d transaction=%d", execution.State(), tx.State())
	}
	if _, err := issuer.ConsumeExecution(claim, tx, plan, testPeerAgreement(plan)); !errors.Is(err, ErrAuthorityConsumed) {
		t.Fatalf("second consume=%v want=%v", err, ErrAuthorityConsumed)
	}
	if attempt.prepareCalls.Load() != 0 {
		t.Fatal("consuming authority invoked driver before Prepare")
	}
	if err := execution.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	attempt.mu.Lock()
	request := attempt.request
	attempt.mu.Unlock()
	if request.Plan != plan || request.Facts != claim.Snapshot() || request.Agreement != testPeerAgreement(plan) {
		t.Fatalf("execution request=%+v", request)
	}
	if err := execution.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	finalizeRolledBackExecution(t, execution)
}

func TestExecutionEnforcesOrderAndTerminalState(t *testing.T) {
	attempt := &transactionalTestAttempt{}
	driver := &transactionalTestDriver{
		operation: OperationTCPRepair,
		result: PreflightResult{
			Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{1}, ProbeReferences: testProbeReferences(1),
		},
		attempt: attempt,
	}
	execution := consumeExecutableClaim(t, driver)
	if err := execution.Cutover(context.Background()); !errors.Is(err, ErrExecutionState) {
		t.Fatalf("cutover before prepare=%v", err)
	}
	if err := execution.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := execution.Prepare(context.Background()); !errors.Is(err, ErrExecutionState) {
		t.Fatalf("second prepare=%v", err)
	}
	if err := execution.Cutover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := execution.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if execution.State() != ExecutionCommitted {
		t.Fatalf("state=%d want committed", execution.State())
	}
	if err := execution.Rollback(context.Background()); !errors.Is(err, ErrExecutionState) {
		t.Fatalf("rollback after commit=%v", err)
	}
	if err := execution.FinalizeCommitted(); err != nil {
		t.Fatal(err)
	}
	if attempt.prepareCalls.Load() != 1 || attempt.cutoverCalls.Load() != 1 || attempt.commitCalls.Load() != 1 || attempt.rollbackCalls.Load() != 0 {
		t.Fatalf("calls prepare=%d cutover=%d commit=%d rollback=%d",
			attempt.prepareCalls.Load(), attempt.cutoverCalls.Load(), attempt.commitCalls.Load(), attempt.rollbackCalls.Load())
	}
}

func TestExecutionSuccessfulCommitIsIrreversibleAfterConcurrentCancellation(t *testing.T) {
	attempt := &transactionalTestAttempt{commitEnter: make(chan struct{}), commitExit: make(chan struct{})}
	driver := &transactionalTestDriver{
		operation: OperationTCPRepair,
		result: PreflightResult{
			Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{0x2c}, ProbeReferences: testProbeReferences(0x2c),
		},
		attempt: attempt,
	}
	execution := consumeExecutableClaim(t, driver)
	if err := execution.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := execution.Cutover(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- execution.Commit(ctx) }()
	select {
	case <-attempt.commitEnter:
	case <-time.After(time.Second):
		t.Fatal("Commit did not enter driver")
	}
	cancel()
	close(attempt.commitExit)
	if err := <-result; err != nil {
		t.Fatalf("successful driver commit was downgraded: %v", err)
	}
	if execution.State() != ExecutionCommitted {
		t.Fatalf("state=%d want committed", execution.State())
	}
	if err := execution.Rollback(context.Background()); !errors.Is(err, ErrExecutionState) {
		t.Fatalf("rollback after committed driver=%v", err)
	}
	if err := execution.FinalizeCommitted(); err != nil {
		t.Fatal(err)
	}
}

func TestExecutionFailureRequiresSuccessfulRollback(t *testing.T) {
	forced := errors.New("forced prepare failure")
	rollbackFailure := errors.New("forced rollback failure")
	attempt := &transactionalTestAttempt{prepareErr: forced, rollbackErr: rollbackFailure}
	driver := &transactionalTestDriver{
		operation: OperationTCPRepair,
		result: PreflightResult{
			Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{2}, ProbeReferences: testProbeReferences(2),
		},
		attempt: attempt,
	}
	execution := consumeExecutableClaim(t, driver)
	if err := execution.Prepare(context.Background()); !errors.Is(err, forced) {
		t.Fatalf("prepare error=%v want forced failure", err)
	}
	if execution.State() != ExecutionRollbackRequired {
		t.Fatalf("state=%d want rollback-required", execution.State())
	}
	if err := execution.Rollback(context.Background()); !errors.Is(err, rollbackFailure) {
		t.Fatalf("rollback error=%v want forced failure", err)
	}
	if execution.State() != ExecutionRollbackRequired {
		t.Fatalf("failed rollback state=%d", execution.State())
	}
	attempt.rollbackErr = nil
	if err := execution.Rollback(context.Background()); err != nil {
		t.Fatalf("rollback retry: %v", err)
	}
	finalizeRolledBackExecution(t, execution)
	if execution.State() != ExecutionRolledBack || attempt.rollbackCalls.Load() != 2 {
		t.Fatalf("state=%d rollback calls=%d", execution.State(), attempt.rollbackCalls.Load())
	}
}

func TestExecutionRollbackIgnoresCallerCancellation(t *testing.T) {
	forced := errors.New("forced prepare failure")
	attempt := &transactionalTestAttempt{prepareErr: forced}
	driver := &transactionalTestDriver{
		operation: OperationTCPRepair,
		result: PreflightResult{
			Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{0x2d}, ProbeReferences: testProbeReferences(0x2d),
		},
		attempt: attempt,
	}
	execution := consumeExecutableClaim(t, driver)
	if err := execution.Prepare(context.Background()); !errors.Is(err, forced) {
		t.Fatalf("prepare error=%v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := execution.Rollback(canceled); err != nil {
		t.Fatal(err)
	}
	finalizeRolledBackExecution(t, execution)
	attempt.mu.Lock()
	rollbackCtxErr := attempt.rollbackCtxErr
	attempt.mu.Unlock()
	if rollbackCtxErr != nil {
		t.Fatalf("driver inherited caller cancellation: %v", rollbackCtxErr)
	}
}

func TestExecutionAttemptPanicRequiresRollback(t *testing.T) {
	attempt := &transactionalTestAttempt{panicPrepare: true}
	driver := &transactionalTestDriver{
		operation: OperationTCPRepair,
		result: PreflightResult{
			Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{4}, ProbeReferences: testProbeReferences(4),
		},
		attempt: attempt,
	}
	execution := consumeExecutableClaim(t, driver)
	if err := execution.Prepare(context.Background()); !errors.Is(err, ErrExecutionDriverPanic) {
		t.Fatalf("panic error=%v", err)
	}
	if execution.State() != ExecutionRollbackRequired {
		t.Fatalf("panic state=%d want fail-closed", execution.State())
	}
	if err := execution.Rollback(context.Background()); err != nil {
		t.Fatalf("panic rollback=%v", err)
	}
	finalizeRolledBackExecution(t, execution)
	if execution.State() != ExecutionRolledBack {
		t.Fatalf("panic rollback state=%d", execution.State())
	}
}

func TestEligiblePreflightRequiresConcreteAttempt(t *testing.T) {
	driver := &transactionalTestDriver{
		operation: OperationTCPRepair,
		result: PreflightResult{
			Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{5}, ProbeReferences: testProbeReferences(5),
		},
	}
	resource := MustNewResource(ScopeEndpoint)
	claim := MustNewDrivenClaim(testDrivenFacts(), driver, resource)
	binding := testBinding(32)
	bindDrivenClaim(t, claim, binding)
	if _, err := PlanCandidate(context.Background(), claim, fixedPlanRequest(binding)); !errors.Is(err, ErrInvalidDriver) {
		t.Fatalf("nil attempt preflight=%v want=%v", err, ErrInvalidDriver)
	}
}

func TestExecutionSerializesDriverSteps(t *testing.T) {
	attempt := &transactionalTestAttempt{prepareEnter: make(chan struct{}), prepareExit: make(chan struct{})}
	driver := &transactionalTestDriver{
		operation: OperationTCPRepair,
		result: PreflightResult{
			Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{6}, ProbeReferences: testProbeReferences(6),
		},
		attempt: attempt,
	}
	execution := consumeExecutableClaim(t, driver)
	prepared := make(chan error, 1)
	go func() { prepared <- execution.Prepare(context.Background()) }()
	select {
	case <-attempt.prepareEnter:
	case <-time.After(time.Second):
		t.Fatal("Prepare did not enter driver")
	}
	if err := execution.Cutover(context.Background()); !errors.Is(err, ErrExecutionBusy) {
		t.Fatalf("concurrent cutover=%v want=%v", err, ErrExecutionBusy)
	}
	close(attempt.prepareExit)
	if err := <-prepared; err != nil {
		t.Fatal(err)
	}
	if err := execution.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	finalizeRolledBackExecution(t, execution)
}

func TestCopiedExecutionSharesSingleUseToken(t *testing.T) {
	attempt := &transactionalTestAttempt{}
	driver := &transactionalTestDriver{
		operation: OperationTCPRepair,
		result: PreflightResult{
			Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{9}, ProbeReferences: testProbeReferences(9),
		},
		attempt: attempt,
	}
	execution := consumeExecutableClaim(t, driver)
	copyOfExecution := *execution
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, candidate := range []*Execution{execution, &copyOfExecution} {
		go func(candidate *Execution) {
			<-start
			results <- candidate.Prepare(context.Background())
		}(candidate)
	}
	close(start)
	first, second := <-results, <-results
	if (first == nil) == (second == nil) {
		t.Fatalf("copied Prepare results=(%v,%v), want exactly one success", first, second)
	}
	loser := first
	if loser == nil {
		loser = second
	}
	if !errors.Is(loser, ErrExecutionBusy) && !errors.Is(loser, ErrExecutionState) {
		t.Fatalf("copied Prepare loser=%v", loser)
	}
	if attempt.prepareCalls.Load() != 1 || execution.State() != ExecutionPrepared || copyOfExecution.State() != ExecutionPrepared {
		t.Fatalf("calls=%d states=(%d,%d)", attempt.prepareCalls.Load(), execution.State(), copyOfExecution.State())
	}
	if err := execution.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	finalizeRolledBackExecution(t, execution)
}

func TestExecutionRevalidatesAuthorityAtEveryStage(t *testing.T) {
	t.Run("retired before prepare", func(t *testing.T) {
		attempt := &transactionalTestAttempt{}
		driver := &transactionalTestDriver{
			operation: OperationTCPRepair,
			result: PreflightResult{
				Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{7}, ProbeReferences: testProbeReferences(7),
			},
			attempt: attempt,
		}
		issuer, claim, plan, tx := executableClaimFixture(t, driver)
		execution, err := issuer.ConsumeExecution(claim, tx, plan, testPeerAgreement(plan))
		if err != nil {
			t.Fatal(err)
		}
		if err := claim.Retire(plan.Binding); err != nil {
			t.Fatal(err)
		}
		if err := execution.Prepare(context.Background()); !errors.Is(err, ErrAuthorityStale) {
			t.Fatalf("prepare after retirement=%v want=%v", err, ErrAuthorityStale)
		}
		if attempt.prepareCalls.Load() != 0 || execution.State() != ExecutionRolledBack {
			t.Fatalf("prepare calls=%d state=%d", attempt.prepareCalls.Load(), execution.State())
		}
	})

	t.Run("retired during prepare", func(t *testing.T) {
		attempt := &transactionalTestAttempt{prepareEnter: make(chan struct{}), prepareExit: make(chan struct{})}
		driver := &transactionalTestDriver{
			operation: OperationTCPRepair,
			result: PreflightResult{
				Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{8}, ProbeReferences: testProbeReferences(8),
			},
			attempt: attempt,
		}
		issuer, claim, plan, tx := executableClaimFixture(t, driver)
		execution, err := issuer.ConsumeExecution(claim, tx, plan, testPeerAgreement(plan))
		if err != nil {
			t.Fatal(err)
		}
		prepareCtx, cancelPrepare := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() { result <- execution.Prepare(prepareCtx) }()
		select {
		case <-attempt.prepareEnter:
		case <-time.After(time.Second):
			t.Fatal("Prepare did not enter driver")
		}
		retired := make(chan error, 1)
		go func() { retired <- claim.Retire(plan.Binding) }()
		select {
		case err := <-retired:
			t.Fatalf("retirement crossed active execution lease: %v", err)
		case <-time.After(25 * time.Millisecond):
		}
		if !claim.Retired() {
			t.Fatal("retirement request did not invalidate the claim immediately")
		}
		cancelPrepare()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("prepare retirement race=%v want cancellation", err)
		}
		if execution.State() != ExecutionRollbackRequired {
			t.Fatalf("state=%d want rollback-required", execution.State())
		}
		if err := execution.Rollback(context.Background()); err != nil {
			t.Fatal(err)
		}
		finalizeRolledBackExecution(t, execution)
		select {
		case err := <-retired:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("retirement did not complete after rollback released lease")
		}
	})
}

func TestExecutionForwardDeadlineLeavesRollbackWindow(t *testing.T) {
	attempt := &transactionalTestAttempt{prepareEnter: make(chan struct{}), prepareExit: make(chan struct{})}
	driver := &transactionalTestDriver{
		operation: OperationTCPRepair,
		result: PreflightResult{
			Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{0x3a}, ProbeReferences: testProbeReferences(0x3a),
		},
		attempt: attempt,
	}
	deadline := canonicalTime(time.Now().Add(400 * time.Millisecond))
	issuer, claim, plan, tx := executableClaimFixtureWithDeadline(t, driver, deadline)
	execution, err := issuer.ConsumeExecution(claim, tx, plan, testPeerAgreement(plan))
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- execution.Prepare(context.Background()) }()
	select {
	case <-attempt.prepareEnter:
	case <-time.After(time.Second):
		t.Fatal("Prepare did not enter driver")
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("prepare error=%v want deadline", err)
		}
	case <-time.After(time.Second):
		t.Fatal("forward stage ignored reserved deadline")
	}
	if execution.State() != ExecutionRollbackRequired {
		t.Fatalf("state=%d want rollback-required", execution.State())
	}
	if err := execution.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	finalizeRolledBackExecution(t, execution)
	if !time.Now().Before(plan.Deadline) {
		t.Fatalf("rollback completed after immutable deadline %v", plan.Deadline)
	}
	if remaining := time.Until(plan.Deadline); remaining < 25*time.Millisecond {
		t.Fatalf("rollback reserve collapsed to %v", remaining)
	}
}

func TestExecutionDoesNotInvokeRollbackAfterImmutableDeadline(t *testing.T) {
	attempt := &transactionalTestAttempt{}
	driver := &transactionalTestDriver{
		operation: OperationTCPRepair,
		result: PreflightResult{
			Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{0x3b}, ProbeReferences: testProbeReferences(0x3b),
		},
		attempt: attempt,
	}
	deadline := canonicalTime(time.Now().Add(80 * time.Millisecond))
	issuer, claim, plan, tx := executableClaimFixtureWithDeadline(t, driver, deadline)
	execution, err := issuer.ConsumeExecution(claim, tx, plan, testPeerAgreement(plan))
	if err != nil {
		t.Fatal(err)
	}
	if err := execution.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(execution.Deadline()) + 10*time.Millisecond)
	if err := execution.Rollback(context.Background()); !errors.Is(err, ErrPlanExpired) {
		t.Fatalf("rollback after deadline=%v want=%v", err, ErrPlanExpired)
	}
	if calls := attempt.rollbackCalls.Load(); calls != 0 {
		t.Fatalf("driver rollback calls after deadline=%d", calls)
	}
	if execution.State() != ExecutionFailedClosed {
		t.Fatalf("state=%d want failed-closed", execution.State())
	}
}

func executableClaimFixture(t testing.TB, driver Driver) (*AuthorityIssuer, *Claim, Plan, *ResourceTransaction) {
	return executableClaimFixtureWithDeadline(t, driver, canonicalTime(time.Now().Add(time.Minute)))
}

func finalizeRolledBackExecution(t testing.TB, execution *Execution) {
	t.Helper()
	if err := execution.FinalizeRolledBack(); err != nil {
		t.Fatal(err)
	}
}

func executableClaimFixtureWithDeadline(
	t testing.TB,
	driver Driver,
	deadline time.Time,
) (*AuthorityIssuer, *Claim, Plan, *ResourceTransaction) {
	t.Helper()
	resource := MustNewResource(ScopeEndpoint)
	binding := testBinding(31)
	claim := MustNewDrivenClaim(testDrivenFacts(), driver, resource)
	issuer := bindDrivenClaim(t, claim, binding)
	t.Cleanup(func() { _ = claim.Retire(binding) })
	plan, err := PlanCandidate(context.Background(), claim, PlanRequest{
		TransactionID: TransactionID{0xe1, 0xe2}, Binding: binding,
		Direction: protoDirectionForExecutionTest(), Session: SessionStream,
		Deadline: deadline, LocalSupport: OperationTCPRepair, PeerSupport: OperationTCPRepair,
	})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := claim.ReserveResourceTransaction(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.MarkPrepared(plan.BaseGeneration+1, plan.Deadline); err != nil {
		t.Fatal(err)
	}
	if err := tx.MarkCommitPublished(); err != nil {
		t.Fatal(err)
	}
	if err := tx.MarkFinalAccepted(); err != nil {
		t.Fatal(err)
	}
	return issuer, claim, plan, tx
}

func consumeExecutableClaim(t testing.TB, driver Driver) *Execution {
	t.Helper()
	issuer, claim, plan, tx := executableClaimFixture(t, driver)
	execution, err := issuer.ConsumeExecution(claim, tx, plan, testPeerAgreement(plan))
	if err != nil {
		t.Fatal(err)
	}
	return execution
}

func testPeerAgreement(plan Plan) PeerAgreement {
	binding := proto.LeafMobilityPeerPlanBinding{
		CoordinatorSide: proto.LeafMobilityActorClient,
		ActorSide:       proto.LeafMobilityActorClient,
		Direction:       plan.Direction,
		SessionKind:     protocolSession(plan.Session),
		Operation:       protocolOperation(plan.Operation),
		Fallback:        proto.LeafMobilityFallbackRedialAttach,
		LeaseMillis:     1_000,
		SessionEpoch:    proto.SessionEpoch(plan.Binding.FlowID),
		TransactionID:   [16]byte(plan.TransactionID),
		ClientGraph:     proto.GraphBinding{Revision: 1, Digest: proto.GraphDigest{1}},
		ServerGraph:     proto.GraphBinding{Revision: 1, Digest: proto.GraphDigest{2}},
		ClientTargetID:  proto.TargetID(plan.Binding.LocalTargetID),
		ServerTargetID:  proto.TargetID(plan.Binding.PeerTargetID),
		BaseGeneration:  plan.BaseGeneration,
		ResourceScope:   protocolScope(plan.Scope),
		ResourceID:      proto.LeafMobilityResourceID(plan.ResourceID),
		RouteGeneration: 9,
	}
	actorPlan := proto.LeafMobilityPlanDigest(plan.LocalDigest)
	prepare := proto.LeafMobilityPeerPlanPrepare{
		LeafMobilityPeerPlanBinding: binding,
		ActorEndpointGeneration:     plan.EndpointGeneration,
		ActorPlanDigest:             actorPlan,
	}
	proposal, err := prepare.ProposalDigest()
	if err != nil {
		panic(err)
	}
	peerDigest := proto.LeafMobilityPeerDigest{1}
	reservation := proto.LeafMobilityReservationID{3}
	peerEndpointGeneration := plan.EndpointGeneration + 1
	digest, err := proto.ComputeLeafMobilityAgreementDigest(
		binding, plan.BaseGeneration+1, plan.EndpointGeneration, peerEndpointGeneration,
		proposal, peerDigest, reservation,
	)
	if err != nil {
		panic(err)
	}
	return PeerAgreement{
		Binding: binding, Generation: plan.BaseGeneration + 1,
		ActorEndpointGeneration: plan.EndpointGeneration, PeerEndpointGeneration: peerEndpointGeneration,
		ActorPlanDigest: actorPlan, ProposalDigest: proposal, PeerPlanDigest: peerDigest,
		AgreementDigest: digest, ReservationID: reservation,
	}
}

func protoDirectionForExecutionTest() proto.SenderDirection {
	return proto.SenderDirectionClientToServer
}
