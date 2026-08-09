package leafmobility

import (
	"context"
	"errors"
	"fmt"
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
	prepareErr      error
	stageErr        error
	publishErr      error
	activateErr     error
	rollbackErr     error
	failClosedErr   error
	publication     PublicationEvidence
	zeroPublication bool

	prepareCalls    atomic.Int32
	stageCalls      atomic.Int32
	publishCalls    atomic.Int32
	activateCalls   atomic.Int32
	rollbackCalls   atomic.Int32
	failClosedCalls atomic.Int32
	prepareEnter    chan struct{}
	prepareExit     chan struct{}
	publishEnter    chan struct{}
	publishExit     chan struct{}
	panicPrepare    bool
	publishHook     func()
	activateHook    func()
	rollbackHook    func()
	mu              sync.Mutex
	request         ExecutionRequest
	evidence        AttemptEvidence
	rollbackCtxErr  error
	endpointChanged bool
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

func (a *transactionalTestAttempt) Stage(context.Context, ExecutionRequest) (PublicationEvidence, error) {
	a.stageCalls.Add(1)
	publication := a.publication
	if publication.Digest == (EvidenceDigest{}) && a.stageErr == nil && !a.zeroPublication {
		publication.Digest = EvidenceDigest{0x51}
	}
	return publication, a.stageErr
}

func (a *transactionalTestAttempt) Publish(context.Context, ExecutionRequest) error {
	a.publishCalls.Add(1)
	if a.publishEnter != nil {
		close(a.publishEnter)
	}
	if a.publishExit != nil {
		<-a.publishExit
	}
	if a.publishHook != nil {
		a.publishHook()
	}
	return a.publishErr
}

func (a *transactionalTestAttempt) Activate(context.Context, ExecutionRequest) error {
	a.activateCalls.Add(1)
	if a.activateHook != nil {
		a.activateHook()
	}
	return a.activateErr
}

func (a *transactionalTestAttempt) Rollback(ctx context.Context, _ ExecutionRequest) error {
	a.rollbackCalls.Add(1)
	if a.rollbackHook != nil {
		a.rollbackHook()
	}
	a.mu.Lock()
	a.rollbackCtxErr = ctx.Err()
	a.mu.Unlock()
	return a.rollbackErr
}

type testIncarnationReporter struct {
	value     atomic.Uint64
	panicRead atomic.Bool
}

func newTestIncarnationReporter() *testIncarnationReporter {
	reporter := &testIncarnationReporter{}
	reporter.value.Store(1)
	return reporter
}

func (reporter *testIncarnationReporter) LeafMobilityIncarnation() uint64 {
	if reporter.panicRead.Load() {
		panic("forced incarnation reporter failure")
	}
	return reporter.value.Load()
}

func (a *transactionalTestAttempt) FailClosed(context.Context, ExecutionRequest) error {
	a.failClosedCalls.Add(1)
	return a.failClosedErr
}

func (a *transactionalTestAttempt) EndpointGenerationChanged() bool {
	a.mu.Lock()
	changed := a.endpointChanged
	a.mu.Unlock()
	return changed
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
	if tx.State() != ResourceTransactionPrepared {
		t.Fatalf("forged plan changed transaction state=%d", tx.State())
	}

	mutations := []func(*PeerAgreement){
		func(a *PeerAgreement) { a.Binding.SubjectRouteGeneration++ },
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
		if tx.State() != ResourceTransactionPrepared {
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
	if attempt.prepareCalls.Load() != 0 || tx.State() != ResourceTransactionPrepared {
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
	if execution.State() != ExecutionAuthorized || tx.State() != ResourceTransactionExecutionStaged {
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
	reporter := newTestIncarnationReporter()
	attempt := &transactionalTestAttempt{publishHook: func() { reporter.value.Add(1) }}
	driver := &transactionalTestDriver{
		operation: OperationTCPRepair,
		result: PreflightResult{
			Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{1}, ProbeReferences: testProbeReferences(1),
		},
		attempt: attempt,
	}
	issuer, claim, plan, tx := executableClaimFixtureWithReporter(t, driver, reporter)
	execution, err := issuer.ConsumeExecution(claim, tx, plan, testPeerAgreement(plan))
	if err != nil {
		t.Fatal(err)
	}
	if err := execution.Stage(context.Background()); !errors.Is(err, ErrExecutionState) {
		t.Fatalf("stage before prepare=%v", err)
	}
	if err := execution.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := execution.Prepare(context.Background()); !errors.Is(err, ErrExecutionState) {
		t.Fatalf("second prepare=%v", err)
	}
	if err := execution.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := reporter.value.Load(); got != 1 {
		t.Fatalf("private Stage changed endpoint incarnation to %d", got)
	}
	if digest, err := execution.PublicationDigest(); err != nil || digest == (proto.LeafMobilityPublicationDigest{}) {
		t.Fatalf("publication digest=(%x, %v)", digest, err)
	}
	if err := execution.Publish(context.Background()); !errors.Is(err, ErrExecutionState) {
		t.Fatalf("publish before FINAL=%v", err)
	}
	if calls := attempt.publishCalls.Load(); calls != 0 {
		t.Fatalf("publish before FINAL invoked driver %d time(s)", calls)
	}
	authorizeExecutionPublish(t, execution, tx)
	if err := execution.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	if execution.State() != ExecutionPublished {
		t.Fatalf("state=%d want published", execution.State())
	}
	if err := execution.Rollback(context.Background()); !errors.Is(err, ErrExecutionState) {
		t.Fatalf("rollback after publish=%v", err)
	}
	if err := execution.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := execution.FinalizePublished(); err != nil {
		t.Fatal(err)
	}
	if attempt.prepareCalls.Load() != 1 || attempt.stageCalls.Load() != 1 || attempt.publishCalls.Load() != 1 ||
		attempt.activateCalls.Load() != 1 || attempt.rollbackCalls.Load() != 0 {
		t.Fatalf("calls prepare=%d stage=%d publish=%d activate=%d rollback=%d",
			attempt.prepareCalls.Load(), attempt.stageCalls.Load(), attempt.publishCalls.Load(),
			attempt.activateCalls.Load(), attempt.rollbackCalls.Load())
	}
}

func TestExecutionFinalAcceptanceLinearizesResourceAndDriverState(t *testing.T) {
	newStaged := func(t *testing.T, deadline time.Time) (*Execution, *ResourceTransaction, *transactionalTestAttempt) {
		t.Helper()
		attempt := &transactionalTestAttempt{}
		driver := &transactionalTestDriver{
			operation: OperationTCPRepair,
			result: PreflightResult{
				Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{0x6a}, ProbeReferences: testProbeReferences(0x6a),
			},
			attempt: attempt,
		}
		issuer, claim, plan, transaction := executableClaimFixtureWithDeadline(t, driver, deadline)
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
		return execution, transaction, attempt
	}

	t.Run("final wins", func(t *testing.T) {
		execution, transaction, _ := newStaged(t, canonicalTime(time.Now().Add(time.Second)))
		disposition, err := execution.ResolveFinalAcceptance(true)
		if err != nil || disposition != FinalAcceptancePublishAllowed {
			t.Fatalf("disposition/error=%d/%v", disposition, err)
		}
		if execution.State() != ExecutionPublishAuthorized || transaction.State() != ResourceTransactionPublishAuthorized {
			t.Fatalf("states=(%d,%d)", execution.State(), transaction.State())
		}
		if err := execution.Rollback(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := transaction.BeginResolution(ResolutionRolledBack); err != nil {
			t.Fatal(err)
		}
		if err := transaction.FinishResolution(ResolutionRolledBack); err != nil {
			t.Fatal(err)
		}
		finalizeRolledBackExecution(t, execution)
	})

	t.Run("recovery forbids publish", func(t *testing.T) {
		execution, transaction, attempt := newStaged(t, canonicalTime(time.Now().Add(time.Second)))
		disposition, err := execution.ResolveFinalAcceptance(false)
		if err != nil || disposition != FinalAcceptanceRollbackOnly {
			t.Fatalf("disposition/error=%d/%v", disposition, err)
		}
		snapshot := transaction.Snapshot()
		if execution.State() != ExecutionRollbackRequired || snapshot.State != ResourceTransactionOutcomeUnknown ||
			snapshot.UnknownFrom != ResourceTransactionPublishAuthorized {
			t.Fatalf("execution/transaction=%d/%+v", execution.State(), snapshot)
		}
		if err := execution.Publish(context.Background()); !errors.Is(err, ErrExecutionState) {
			t.Fatalf("recovery Publish=%v want state error", err)
		}
		if calls := attempt.publishCalls.Load(); calls != 0 {
			t.Fatalf("recovery invoked Publish %d time(s)", calls)
		}
		if err := execution.Rollback(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := transaction.BeginResolution(ResolutionRolledBack); err != nil {
			t.Fatal(err)
		}
		if err := transaction.FinishResolution(ResolutionRolledBack); err != nil {
			t.Fatal(err)
		}
		finalizeRolledBackExecution(t, execution)
	})

	t.Run("commit uncertainty forbids publish", func(t *testing.T) {
		execution, transaction, _ := newStaged(t, canonicalTime(time.Now().Add(time.Second)))
		if err := transaction.MarkOutcomeUnknown(); err != nil {
			t.Fatal(err)
		}
		disposition, err := execution.ResolveFinalAcceptance(true)
		if err != nil || disposition != FinalAcceptanceRollbackOnly {
			t.Fatalf("disposition/error=%d/%v", disposition, err)
		}
		snapshot := transaction.Snapshot()
		if execution.State() != ExecutionRollbackRequired || snapshot.State != ResourceTransactionOutcomeUnknown ||
			snapshot.UnknownFrom != ResourceTransactionPublishAuthorized {
			t.Fatalf("execution/transaction=%d/%+v", execution.State(), snapshot)
		}
		if err := execution.Rollback(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := transaction.BeginResolution(ResolutionRolledBack); err != nil {
			t.Fatal(err)
		}
		if err := transaction.FinishResolution(ResolutionRolledBack); err != nil {
			t.Fatal(err)
		}
		finalizeRolledBackExecution(t, execution)
	})

	t.Run("deadline wins", func(t *testing.T) {
		deadline := canonicalTime(time.Now().Add(150 * time.Millisecond))
		execution, transaction, attempt := newStaged(t, deadline)
		time.Sleep(max(time.Until(deadline), 0) + 5*time.Millisecond)
		disposition, err := execution.ResolveFinalAcceptance(true)
		if err != nil || disposition != FinalAcceptanceRollbackOnly {
			t.Fatalf("disposition/error=%d/%v", disposition, err)
		}
		snapshot := transaction.Snapshot()
		if execution.State() != ExecutionRollbackRequired || snapshot.State != ResourceTransactionOutcomeUnknown ||
			snapshot.UnknownFrom != ResourceTransactionPublishAuthorized {
			t.Fatalf("execution/transaction=%d/%+v", execution.State(), snapshot)
		}
		if calls := attempt.publishCalls.Load(); calls != 0 {
			t.Fatalf("deadline invoked Publish %d time(s)", calls)
		}
		if err := execution.FailClosed(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestExecutionStageRequiresPublicationEvidence(t *testing.T) {
	attempt := &transactionalTestAttempt{zeroPublication: true}
	driver := &transactionalTestDriver{
		operation: OperationTCPRepair,
		result: PreflightResult{
			Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{0x52}, ProbeReferences: testProbeReferences(0x52),
		},
		attempt: attempt,
	}
	execution := consumeExecutableClaim(t, driver)
	if err := execution.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := execution.Stage(context.Background()); !errors.Is(err, ErrExecutionDriver) {
		t.Fatalf("Stage with zero publication evidence=%v want=%v", err, ErrExecutionDriver)
	}
	if execution.State() != ExecutionRollbackRequired {
		t.Fatalf("state=%d want rollback-required", execution.State())
	}
	if _, err := execution.PublicationDigest(); !errors.Is(err, ErrExecutionState) {
		t.Fatalf("PublicationDigest after rejected Stage=%v want=%v", err, ErrExecutionState)
	}
	if err := execution.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	finalizeRolledBackExecution(t, execution)
}

func TestExecutionPublishErrorWithoutIncarnationChangeCanRollback(t *testing.T) {
	publishFailure := errors.New("publish failed before owner swap")
	reporter := newTestIncarnationReporter()
	attempt := &transactionalTestAttempt{publishErr: publishFailure}
	driver := &transactionalTestDriver{
		operation: OperationTCPRepair,
		result: PreflightResult{
			Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{0x53}, ProbeReferences: testProbeReferences(0x53),
		},
		attempt: attempt,
	}
	issuer, claim, plan, transaction := executableClaimFixtureWithReporter(t, driver, reporter)
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
	authorizeExecutionPublish(t, execution, transaction)
	if err := execution.Publish(context.Background()); !errors.Is(err, publishFailure) {
		t.Fatalf("Publish=%v want=%v", err, publishFailure)
	}
	if execution.State() != ExecutionRollbackRequired {
		t.Fatalf("state=%d want rollback-required", execution.State())
	}
	if err := execution.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	finalizeRolledBackExecution(t, execution)
	if attempt.rollbackCalls.Load() != 1 || reporter.value.Load() != 1 {
		t.Fatalf("rollback calls/incarnation=%d/%d want=1/1", attempt.rollbackCalls.Load(), reporter.value.Load())
	}
}

func TestExecutionPublishErrorWithUnprovenIncarnationRequiresFailClosed(t *testing.T) {
	publishFailure := errors.New("publish failed after an unknown owner boundary")
	reporter := newTestIncarnationReporter()
	attempt := &transactionalTestAttempt{
		publishErr: publishFailure,
		publishHook: func() {
			reporter.panicRead.Store(true)
		},
	}
	driver := &transactionalTestDriver{
		operation: OperationTCPRepair,
		result: PreflightResult{
			Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{0x55}, ProbeReferences: testProbeReferences(0x55),
		},
		attempt: attempt,
	}
	issuer, claim, plan, transaction := executableClaimFixtureWithReporter(t, driver, reporter)
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
	authorizeExecutionPublish(t, execution, transaction)
	if err := execution.Publish(context.Background()); !errors.Is(err, publishFailure) {
		t.Fatalf("Publish=%v want=%v", err, publishFailure)
	}
	if execution.State() != ExecutionFailClosedRequired {
		t.Fatalf("state=%d want fail-closed-required", execution.State())
	}
	if err := execution.Rollback(context.Background()); !errors.Is(err, ErrExecutionState) {
		t.Fatalf("Rollback after unproven Publish=%v want state rejection", err)
	}
	if attempt.rollbackCalls.Load() != 0 {
		t.Fatalf("unproven Publish invoked Rollback %d time(s)", attempt.rollbackCalls.Load())
	}
	reporter.panicRead.Store(false)
	if err := execution.FailClosed(context.Background()); err != nil {
		t.Fatal(err)
	}
	if execution.State() != ExecutionFailedClosed || attempt.failClosedCalls.Load() != 1 {
		t.Fatalf("state/fail-closed calls=%d/%d", execution.State(), attempt.failClosedCalls.Load())
	}
}

func TestExecutionActivateFailureCanOnlyRetryActivate(t *testing.T) {
	activateFailure := errors.New("activation still pending")
	reporter := newTestIncarnationReporter()
	attempt := &transactionalTestAttempt{
		publishHook: func() { reporter.value.Add(1) },
		activateErr: activateFailure,
	}
	driver := &transactionalTestDriver{
		operation: OperationTCPRepair,
		result: PreflightResult{
			Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{0x54}, ProbeReferences: testProbeReferences(0x54),
		},
		attempt: attempt,
	}
	issuer, claim, plan, transaction := executableClaimFixtureWithReporter(t, driver, reporter)
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
	authorizeExecutionPublish(t, execution, transaction)
	if err := execution.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := execution.Activate(context.Background()); !errors.Is(err, activateFailure) {
		t.Fatalf("Activate=%v want=%v", err, activateFailure)
	}
	if execution.State() != ExecutionActivationRequired {
		t.Fatalf("state=%d want activation-required", execution.State())
	}
	if err := execution.Rollback(context.Background()); !errors.Is(err, ErrExecutionState) {
		t.Fatalf("Rollback after Publish=%v want=%v", err, ErrExecutionState)
	}
	if attempt.rollbackCalls.Load() != 0 {
		t.Fatalf("post-Publish rollback calls=%d", attempt.rollbackCalls.Load())
	}
	attempt.activateErr = nil
	if err := execution.Activate(context.Background()); err != nil {
		t.Fatalf("Activate retry: %v", err)
	}
	if err := execution.FinalizePublished(); err != nil {
		t.Fatal(err)
	}
	if attempt.activateCalls.Load() != 2 {
		t.Fatalf("activate calls=%d want=2", attempt.activateCalls.Load())
	}
}

func TestExecutionPublishAdvancesOnlyFutureEndpointGeneration(t *testing.T) {
	reporter := newTestIncarnationReporter()
	attempt := &transactionalTestAttempt{publishHook: func() { reporter.value.Add(1) }}
	driver := &transactionalTestDriver{
		operation: OperationTCPRepair,
		result: PreflightResult{
			Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{0x7a}, ProbeReferences: testProbeReferences(0x7a),
		},
		attempt: attempt,
	}
	issuer, claim, plan, transaction := executableClaimFixtureWithReporter(t, driver, reporter)
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
	authorizeExecutionPublish(t, execution, transaction)
	if err := execution.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	current := claim.Snapshot().Generation
	if current == 0 || current == plan.EndpointGeneration {
		t.Fatalf("published endpoint generation=%d, old=%d", current, plan.EndpointGeneration)
	}
	if execution.token.request.Plan.EndpointGeneration != plan.EndpointGeneration ||
		execution.token.request.Agreement.ActorEndpointGeneration != plan.EndpointGeneration {
		t.Fatal("publish rewrote immutable transaction evidence")
	}
	if err := claim.ValidatePlanCurrent(plan); !errors.Is(err, ErrStalePlan) {
		t.Fatalf("old plan after publish=%v want=%v", err, ErrStalePlan)
	}
	if err := execution.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := execution.FinalizePublished(); err != nil {
		t.Fatal(err)
	}
}

func TestExecutionSuccessfulPublishIsIrreversibleAfterConcurrentCancellation(t *testing.T) {
	reporter := newTestIncarnationReporter()
	attempt := &transactionalTestAttempt{
		publishEnter: make(chan struct{}), publishExit: make(chan struct{}),
		publishHook: func() { reporter.value.Add(1) },
	}
	driver := &transactionalTestDriver{
		operation: OperationTCPRepair,
		result: PreflightResult{
			Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{0x2c}, ProbeReferences: testProbeReferences(0x2c),
		},
		attempt: attempt,
	}
	issuer, claim, plan, tx := executableClaimFixtureWithReporter(t, driver, reporter)
	execution, err := issuer.ConsumeExecution(claim, tx, plan, testPeerAgreement(plan))
	if err != nil {
		t.Fatal(err)
	}
	if err := execution.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := execution.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	authorizeExecutionPublish(t, execution, tx)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- execution.Publish(ctx) }()
	select {
	case <-attempt.publishEnter:
	case <-time.After(time.Second):
		t.Fatal("Publish did not enter driver")
	}
	cancel()
	close(attempt.publishExit)
	if err := <-result; err != nil {
		t.Fatalf("successful driver publish was downgraded: %v", err)
	}
	if execution.State() != ExecutionPublished {
		t.Fatalf("state=%d want published", execution.State())
	}
	if err := execution.Rollback(context.Background()); !errors.Is(err, ErrExecutionState) {
		t.Fatalf("rollback after published driver=%v", err)
	}
	if err := execution.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := execution.FinalizePublished(); err != nil {
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

func TestExecutionFailClosedCleanupFailureRetainsRetryableOwnership(t *testing.T) {
	cleanupFailure := errors.New("cleanup still pending")
	attempt := &transactionalTestAttempt{failClosedErr: cleanupFailure}
	driver := &transactionalTestDriver{
		operation: OperationTCPRepair,
		result: PreflightResult{
			Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{0xb4}, ProbeReferences: testProbeReferences(0xb4),
		},
		attempt: attempt,
	}
	issuer, claim, plan, tx := executableClaimFixture(t, driver)
	execution, err := issuer.ConsumeExecution(claim, tx, plan, testPeerAgreement(plan))
	if err != nil {
		t.Fatal(err)
	}
	if err := execution.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := execution.FailClosed(context.Background()); !errors.Is(err, cleanupFailure) {
		t.Fatalf("first FailClosed = %v, want cleanup failure", err)
	}
	if execution.State() != ExecutionFailClosedRequired {
		t.Fatalf("state=%d want cleanup ownership retained", execution.State())
	}
	if err := execution.Rollback(context.Background()); !errors.Is(err, ErrExecutionState) {
		t.Fatalf("Rollback after failed FailClosed=%v want state rejection", err)
	}
	if attempt.rollbackCalls.Load() != 0 {
		t.Fatalf("failed FailClosed reopened Rollback %d time(s)", attempt.rollbackCalls.Load())
	}
	retired := make(chan error, 1)
	go func() { retired <- claim.Retire(plan.Binding) }()
	select {
	case err := <-retired:
		t.Fatalf("failed cleanup released execution lease: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	attempt.failClosedErr = nil
	if err := execution.FailClosed(context.Background()); err != nil {
		t.Fatalf("retry FailClosed: %v", err)
	}
	if execution.State() != ExecutionFailedClosed || attempt.failClosedCalls.Load() != 2 {
		t.Fatalf("state/calls=%d/%d want failed-closed/2", execution.State(), attempt.failClosedCalls.Load())
	}
	select {
	case err := <-retired:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("successful cleanup did not release execution lease")
	}
}

func TestExecutionNilPublishWithoutIncarnationChangeRequiresFailClosed(t *testing.T) {
	cleanupFailure := errors.New("cleanup proof pending")
	reporter := newTestIncarnationReporter()
	attempt := &transactionalTestAttempt{failClosedErr: cleanupFailure}
	driver := &transactionalTestDriver{
		operation: OperationTCPRepair,
		result: PreflightResult{
			Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{0xb5}, ProbeReferences: testProbeReferences(0xb5),
		},
		attempt: attempt,
	}
	issuer, claim, plan, tx := executableClaimFixtureWithReporter(t, driver, reporter)
	execution, err := issuer.ConsumeExecution(claim, tx, plan, testPeerAgreement(plan))
	if err != nil {
		t.Fatal(err)
	}
	if err := execution.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := execution.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	authorizeExecutionPublish(t, execution, tx)
	before := claim.Snapshot().Generation
	if err := execution.Publish(context.Background()); !errors.Is(err, ErrIncarnationUnproven) {
		t.Fatalf("Publish = %v, want incarnation proof failure", err)
	}
	if execution.State() != ExecutionFailClosedRequired || claim.Snapshot().Generation != before {
		t.Fatalf("state/generation=%d/%d want fail-closed-required/%d", execution.State(), claim.Snapshot().Generation, before)
	}
	if err := execution.Rollback(context.Background()); !errors.Is(err, ErrExecutionState) {
		t.Fatalf("Rollback after unproven publish = %v, want state rejection", err)
	}
	if calls := attempt.rollbackCalls.Load(); calls != 0 {
		t.Fatalf("unproven publish invoked Rollback %d time(s)", calls)
	}
	retired := make(chan error, 1)
	go func() { retired <- claim.Retire(plan.Binding) }()
	select {
	case err := <-retired:
		t.Fatalf("unproven publish released execution lease: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	if err := execution.FailClosed(context.Background()); !errors.Is(err, cleanupFailure) {
		t.Fatalf("first FailClosed = %v, want cleanup proof failure", err)
	}
	if execution.State() != ExecutionFailClosedRequired {
		t.Fatalf("failed cleanup state=%d want fail-closed-required", execution.State())
	}
	select {
	case err := <-retired:
		t.Fatalf("failed cleanup released execution lease: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	attempt.failClosedErr = nil
	if err := execution.FailClosed(context.Background()); err != nil {
		t.Fatalf("FailClosed retry: %v", err)
	}
	select {
	case err := <-retired:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cleanup proof did not release execution lease")
	}
}

func TestExecutionPublishWithoutIncarnationReporterIsUnproven(t *testing.T) {
	attempt := &transactionalTestAttempt{}
	driver := &transactionalTestDriver{
		operation: OperationTCPRepair,
		result: PreflightResult{
			Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{0xb8}, ProbeReferences: testProbeReferences(0xb8),
		},
		attempt: attempt,
	}
	issuer, claim, plan, tx := executableClaimFixture(t, driver)
	execution, err := issuer.ConsumeExecution(claim, tx, plan, testPeerAgreement(plan))
	if err != nil {
		t.Fatal(err)
	}
	if err := execution.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := execution.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	authorizeExecutionPublish(t, execution, tx)
	if err := execution.Publish(context.Background()); !errors.Is(err, ErrIncarnationUnproven) {
		t.Fatalf("Publish = %v, want incarnation proof failure", err)
	}
	if execution.State() != ExecutionFailClosedRequired {
		t.Fatalf("state=%d want fail-closed-required", execution.State())
	}
	if err := execution.Rollback(context.Background()); !errors.Is(err, ErrExecutionState) {
		t.Fatalf("Rollback after unproven publish = %v, want state rejection", err)
	}
	if attempt.rollbackCalls.Load() != 0 {
		t.Fatal("missing incarnation reporter invoked Rollback")
	}
	if err := execution.FailClosed(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestExecutionUsesClaimIncarnationReporterForPublishAndRollback(t *testing.T) {
	t.Run("publish", func(t *testing.T) {
		reporter := newTestIncarnationReporter()
		attempt := &transactionalTestAttempt{publishHook: func() { reporter.value.Add(1) }}
		driver := &transactionalTestDriver{
			operation: OperationTCPRepair,
			result: PreflightResult{
				Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{0xb6}, ProbeReferences: testProbeReferences(0xb6),
			},
			attempt: attempt,
		}
		issuer, claim, plan, tx := executableClaimFixtureWithReporter(t, driver, reporter)
		execution, err := issuer.ConsumeExecution(claim, tx, plan, testPeerAgreement(plan))
		if err != nil {
			t.Fatal(err)
		}
		before := claim.Snapshot().Generation
		if err := execution.Prepare(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := execution.Stage(context.Background()); err != nil {
			t.Fatal(err)
		}
		authorizeExecutionPublish(t, execution, tx)
		if err := execution.Publish(context.Background()); err != nil {
			t.Fatal(err)
		}
		defer execution.FinalizePublished()
		if claim.Snapshot().Generation == before {
			t.Fatal("publish reporter change did not advance claim generation")
		}
		if err := execution.Activate(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := execution.FinalizePublished(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("rollback", func(t *testing.T) {
		reporter := newTestIncarnationReporter()
		stageFailure := errors.New("stage failed after reconstruction")
		attempt := &transactionalTestAttempt{
			stageErr:     stageFailure,
			rollbackHook: func() { reporter.value.Add(1) },
		}
		driver := &transactionalTestDriver{
			operation: OperationTCPRepair,
			result: PreflightResult{
				Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{0xb7}, ProbeReferences: testProbeReferences(0xb7),
			},
			attempt: attempt,
		}
		issuer, claim, plan, tx := executableClaimFixtureWithReporter(t, driver, reporter)
		execution, err := issuer.ConsumeExecution(claim, tx, plan, testPeerAgreement(plan))
		if err != nil {
			t.Fatal(err)
		}
		before := claim.Snapshot().Generation
		if err := execution.Prepare(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := execution.Stage(context.Background()); !errors.Is(err, stageFailure) {
			t.Fatalf("Stage = %v", err)
		}
		if err := execution.Rollback(context.Background()); err != nil {
			t.Fatal(err)
		}
		defer execution.FinalizeRolledBack()
		if claim.Snapshot().Generation == before {
			t.Fatal("rollback reporter change did not advance claim generation")
		}
		finalizeRolledBackExecution(t, execution)
	})
}

func TestExecutionRollbackAdvancesGenerationOnlyAfterReconstruction(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(fmt.Sprintf("changed_%t", changed), func(t *testing.T) {
			attempt := &transactionalTestAttempt{stageErr: errors.New("forced stage failure"), endpointChanged: changed}
			driver := &transactionalTestDriver{
				operation: OperationTCPRepair,
				result: PreflightResult{
					Eligible: true, Stage: StagePreflightComplete, EvidenceDigest: EvidenceDigest{0x5b}, ProbeReferences: testProbeReferences(0x5b),
				},
				attempt: attempt,
			}
			issuer, claim, plan, transaction := executableClaimFixture(t, driver)
			execution, err := issuer.ConsumeExecution(claim, transaction, plan, testPeerAgreement(plan))
			if err != nil {
				t.Fatal(err)
			}
			if err := execution.Prepare(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := execution.Stage(context.Background()); err == nil {
				t.Fatal("Stage unexpectedly succeeded")
			}
			if err := execution.Rollback(context.Background()); err != nil {
				t.Fatal(err)
			}
			generation := claim.Snapshot().Generation
			if changed && generation == plan.EndpointGeneration {
				t.Fatal("reconstructed rollback retained predecessor generation")
			}
			if !changed && generation != plan.EndpointGeneration {
				t.Fatalf("non-destructive rollback changed generation to %d", generation)
			}
			finalizeRolledBackExecution(t, execution)
		})
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
	if err := execution.Stage(context.Background()); !errors.Is(err, ErrExecutionBusy) {
		t.Fatalf("concurrent stage=%v want=%v", err, ErrExecutionBusy)
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
	if execution.State() != ExecutionRollbackRequired {
		t.Fatalf("state=%d want rollback-required with cleanup ownership retained", execution.State())
	}
	if err := execution.FailClosed(context.Background()); err != nil {
		t.Fatalf("fail-closed cleanup: %v", err)
	}
	if calls := attempt.failClosedCalls.Load(); calls != 1 {
		t.Fatalf("driver fail-closed calls=%d want=1", calls)
	}
	if execution.State() != ExecutionFailedClosed {
		t.Fatalf("state=%d want failed-closed after cleanup", execution.State())
	}
}

func executableClaimFixture(t testing.TB, driver Driver) (*AuthorityIssuer, *Claim, Plan, *ResourceTransaction) {
	return executableClaimFixtureWithDeadline(t, driver, canonicalTime(time.Now().Add(time.Minute)))
}

func executableClaimFixtureWithReporter(
	t testing.TB,
	driver Driver,
	reporter IncarnationReporter,
) (*AuthorityIssuer, *Claim, Plan, *ResourceTransaction) {
	return executableClaimFixtureWithDeadlineAndReporter(
		t, driver, canonicalTime(time.Now().Add(time.Minute)), reporter,
	)
}

func executableClaimFixtureWithDeadlineAndReporter(
	t testing.TB,
	driver Driver,
	deadline time.Time,
	reporter IncarnationReporter,
) (*AuthorityIssuer, *Claim, Plan, *ResourceTransaction) {
	t.Helper()
	resource := MustNewResource(ScopeEndpoint)
	binding := testBinding(31)
	claim := MustNewDrivenClaimWithIncarnation(testDrivenFacts(), driver, resource, reporter)
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
	return issuer, claim, plan, tx
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
	return issuer, claim, plan, tx
}

func authorizeExecutionPublish(t testing.TB, execution *Execution, transaction *ResourceTransaction) {
	t.Helper()
	digest, err := execution.PublicationDigest()
	if err != nil {
		t.Fatalf("PublicationDigest: %v", err)
	}
	if digest == (proto.LeafMobilityPublicationDigest{}) {
		t.Fatal("PublicationDigest returned zero digest")
	}
	if err := transaction.MarkCommitPublished(); err != nil {
		t.Fatalf("MarkCommitPublished: %v", err)
	}
	if state := transaction.State(); state != ResourceTransactionCommitPublished {
		t.Fatalf("transaction state=%d want commit-published", state)
	}
	disposition, err := execution.ResolveFinalAcceptance(true)
	if err != nil {
		t.Fatalf("ResolveFinalAcceptance: %v", err)
	}
	if disposition != FinalAcceptancePublishAllowed {
		t.Fatalf("FINAL disposition=%d want publish-allowed", disposition)
	}
	if state := transaction.State(); state != ResourceTransactionPublishAuthorized {
		t.Fatalf("transaction state=%d want publish-authorized", state)
	}
	if state := execution.State(); state != ExecutionPublishAuthorized {
		t.Fatalf("execution state=%d want publish-authorized", state)
	}
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
		CoordinatorSide:        proto.LeafMobilityActorClient,
		ActorSide:              proto.LeafMobilityActorClient,
		Direction:              plan.Direction,
		SessionKind:            protocolSession(plan.Session),
		Operation:              protocolOperation(plan.Operation),
		Fallback:               proto.LeafMobilityFallbackRedialAttach,
		LeaseMillis:            1_000,
		SessionEpoch:           proto.SessionEpoch(plan.Binding.FlowID),
		TransactionID:          [16]byte(plan.TransactionID),
		ClientGraph:            proto.GraphBinding{Revision: 1, Digest: proto.GraphDigest{1}},
		ServerGraph:            proto.GraphBinding{Revision: 1, Digest: proto.GraphDigest{2}},
		SubjectClientTargetID:  proto.TargetID(plan.Binding.LocalTargetID),
		SubjectServerTargetID:  proto.TargetID(plan.Binding.PeerTargetID),
		BaseGeneration:         plan.BaseGeneration,
		ResourceScope:          protocolScope(plan.Scope),
		ResourceID:             proto.LeafMobilityResourceID(plan.ResourceID),
		SubjectRouteGeneration: 9,
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
