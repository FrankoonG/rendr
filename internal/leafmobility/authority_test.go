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

func TestResourceTransactionTracksExecutionWithoutIssuingCapability(t *testing.T) {
	claim, plan := resourceTransactionFixture(t, time.Second)
	tx, err := claim.ReserveResourceTransaction(plan)
	if err != nil {
		t.Fatal(err)
	}
	if tx.State() != ResourceTransactionProposed {
		t.Fatalf("state=%d want proposed", tx.State())
	}
	if _, err := ReserveAdmissions(claim); !errors.Is(err, ErrAuthorityActive) {
		t.Fatalf("admission during proposal=%v want=%v", err, ErrAuthorityActive)
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

	copyOfTransaction := *tx
	if err := copyOfTransaction.Consume(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Consume(); !errors.Is(err, ErrAuthorityConsumed) {
		t.Fatalf("second consume=%v want=%v", err, ErrAuthorityConsumed)
	}
	if err := tx.BeginResolution(ResolutionComplete); err != nil {
		t.Fatal(err)
	}
	if err := copyOfTransaction.FinishResolution(ResolutionComplete); err != nil {
		t.Fatal(err)
	}
	if tx.State() != ResourceTransactionCompleted {
		t.Fatalf("state=%d want completed", tx.State())
	}
	if claim.ExecutionGeneration() != 1 {
		t.Fatalf("generation=%d want=1", claim.ExecutionGeneration())
	}
	admission, err := ReserveAdmissions(claim)
	if err != nil {
		t.Fatalf("released resource remained blocked: %v", err)
	}
	admission.Release()
}

func TestResourceTransactionFinalRejectConsumesGenerationAndReleases(t *testing.T) {
	claim, plan := resourceTransactionFixture(t, time.Second)
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
	if err := tx.MarkFinalRejected(); err != nil {
		t.Fatal(err)
	}
	if tx.State() != ResourceTransactionFinalRejected || claim.ExecutionGeneration() != 1 {
		t.Fatalf("state=%d generation=%d", tx.State(), claim.ExecutionGeneration())
	}
	next := authorityPlan(t, claim, plan.Binding, TransactionID{0xb3}, time.Now().Add(time.Second))
	if next.BaseGeneration != 1 {
		t.Fatalf("next base generation=%d want=1", next.BaseGeneration)
	}
}

func TestResourceTransactionPublishedAbortConsumesGeneration(t *testing.T) {
	claim, plan := resourceTransactionFixture(t, time.Second)
	tx, err := claim.ReserveResourceTransaction(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.MarkProposalPublished(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Abort(); err != nil {
		t.Fatal(err)
	}
	if tx.State() != ResourceTransactionAborted || claim.ExecutionGeneration() != 1 {
		t.Fatalf("state=%d generation=%d", tx.State(), claim.ExecutionGeneration())
	}
	next := authorityPlan(t, claim, plan.Binding, TransactionID{0xb5}, time.Now().Add(time.Second))
	if next.BaseGeneration != 1 {
		t.Fatalf("next base generation=%d want=1", next.BaseGeneration)
	}
}

func TestResourceTransactionPublishedExpiryConsumesGeneration(t *testing.T) {
	claim, plan := resourceTransactionFixture(t, 25*time.Millisecond)
	tx, err := claim.ReserveResourceTransaction(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.MarkProposalPublished(); err != nil {
		t.Fatal(err)
	}
	eventually(t, time.Second, func() bool { return tx.State() == ResourceTransactionExpired })
	if claim.ExecutionGeneration() != 1 {
		t.Fatalf("expired published generation=%d want=1", claim.ExecutionGeneration())
	}
}

func TestResourceTransactionLateFinalRejectedReconcilesUnknownOutcome(t *testing.T) {
	claim, plan := resourceTransactionFixture(t, time.Second)
	tx, err := claim.ReserveResourceTransaction(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.MarkPrepared(1, plan.Deadline); err != nil {
		t.Fatal(err)
	}
	if err := tx.MarkCommitPublished(); err != nil {
		t.Fatal(err)
	}
	if err := tx.MarkOutcomeUnknown(); err != nil {
		t.Fatal(err)
	}
	snapshot := tx.Snapshot()
	if snapshot.State != ResourceTransactionOutcomeUnknown || snapshot.UnknownFrom != ResourceTransactionCommitPublished {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	if !snapshot.Deadline.Equal(plan.Deadline) || !claimResource(claim).Snapshot().Poisoned {
		t.Fatalf("deadline=%v poisoned=%t", snapshot.Deadline, claimResource(claim).Snapshot().Poisoned)
	}
	if err := tx.ReconcileFinalRejected(); err != nil {
		t.Fatal(err)
	}
	if tx.State() != ResourceTransactionFinalRejected || claimResource(claim).Snapshot().Poisoned {
		t.Fatalf("state=%d resource=%+v", tx.State(), claimResource(claim).Snapshot())
	}
	nextPlan := authorityPlan(t, claim, plan.Binding, TransactionID{0xb4}, time.Now().Add(time.Second))
	next, err := claim.ReserveResourceTransaction(nextPlan)
	if err != nil {
		t.Fatalf("resource stayed blocked after deterministic rejection: %v", err)
	}
	if err := next.Abort(); err != nil {
		t.Fatal(err)
	}
}

func TestResourceTransactionLateFinalAcceptedRequiresNoExecutionRollback(t *testing.T) {
	claim, plan := resourceTransactionFixture(t, 25*time.Millisecond)
	tx, err := claim.ReserveResourceTransaction(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.MarkPrepared(1, plan.Deadline); err != nil {
		t.Fatal(err)
	}
	if err := tx.MarkCommitPublished(); err != nil {
		t.Fatal(err)
	}
	eventually(t, time.Second, func() bool { return tx.State() == ResourceTransactionOutcomeUnknown })
	if err := tx.ReconcileFinalAccepted(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Consume(); !errors.Is(err, ErrAuthorityExpired) {
		t.Fatalf("consume after immutable deadline=%v want=%v", err, ErrAuthorityExpired)
	}
	snapshot := tx.Snapshot()
	if snapshot.State != ResourceTransactionOutcomeUnknown || snapshot.UnknownFrom != ResourceTransactionFinalAccepted {
		t.Fatalf("snapshot after denied consume=%+v", snapshot)
	}
	if err := tx.BeginResolution(ResolutionComplete); !errors.Is(err, ErrTransactionOutcomeUnknown) {
		t.Fatalf("no-execution complete=%v want=%v", err, ErrTransactionOutcomeUnknown)
	}
	if err := tx.BeginResolution(ResolutionRolledBack); err != nil {
		t.Fatal(err)
	}
	if err := tx.FinishResolution(ResolutionRolledBack); err != nil {
		t.Fatal(err)
	}
	if tx.State() != ResourceTransactionRolledBack || claimResource(claim).Snapshot().Poisoned {
		t.Fatalf("state=%d resource=%+v", tx.State(), claimResource(claim).Snapshot())
	}
}

func TestResourceTransactionLateReleasedFinishesUncertainResolution(t *testing.T) {
	claim, plan := resourceTransactionFixture(t, time.Second)
	tx, err := claim.ReserveResourceTransaction(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, transition := range []func() error{
		func() error { return tx.MarkPrepared(1, plan.Deadline) },
		tx.MarkCommitPublished,
		tx.MarkFinalAccepted,
		tx.Consume,
		func() error { return tx.BeginResolution(ResolutionComplete) },
		tx.MarkOutcomeUnknown,
	} {
		if err := transition(); err != nil {
			t.Fatal(err)
		}
	}
	snapshot := tx.Snapshot()
	if snapshot.State != ResourceTransactionOutcomeUnknown || snapshot.UnknownFrom != ResourceTransactionResolving ||
		snapshot.Resolution != ResolutionComplete {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	if err := tx.FinishResolution(ResolutionComplete); err != nil {
		t.Fatal(err)
	}
	if tx.State() != ResourceTransactionCompleted {
		t.Fatalf("state=%d want completed", tx.State())
	}
}

func TestResourceTransactionRecoveryRejectsContradictoryEvidence(t *testing.T) {
	claim, plan := resourceTransactionFixture(t, time.Second)
	tx, err := claim.ReserveResourceTransaction(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, transition := range []func() error{
		func() error { return tx.MarkPrepared(1, plan.Deadline) },
		tx.MarkCommitPublished,
		tx.MarkFinalAccepted,
		tx.MarkOutcomeUnknown,
	} {
		if err := transition(); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.ReconcileFinalRejected(); !errors.Is(err, ErrResourceTransactionState) {
		t.Fatalf("contradictory late rejection=%v want=%v", err, ErrResourceTransactionState)
	}
	if err := tx.ReconcileFinalAccepted(); !errors.Is(err, ErrResourceTransactionState) {
		t.Fatalf("duplicate recovery acceptance=%v want=%v", err, ErrResourceTransactionState)
	}
	snapshot := tx.Snapshot()
	if snapshot.State != ResourceTransactionOutcomeUnknown || snapshot.UnknownFrom != ResourceTransactionFinalAccepted ||
		!claimResource(claim).Snapshot().Poisoned {
		t.Fatalf("contradictory evidence changed fail-closed state: transaction=%+v resource=%+v", snapshot, claimResource(claim).Snapshot())
	}
	if err := tx.BeginResolution(ResolutionRolledBack); err != nil {
		t.Fatal(err)
	}
	if err := tx.FinishResolution(ResolutionRolledBack); err != nil {
		t.Fatal(err)
	}
}

func TestResourceTransactionExpiryIsFailClosedAfterCommit(t *testing.T) {
	t.Run("proposal expiry is reversible", func(t *testing.T) {
		claim, plan := resourceTransactionFixture(t, 20*time.Millisecond)
		tx, err := claim.ReserveResourceTransaction(plan)
		if err != nil {
			t.Fatal(err)
		}
		eventually(t, time.Second, func() bool { return tx.State() == ResourceTransactionExpired })
		if claim.ExecutionGeneration() != 0 {
			t.Fatalf("proposal expiry consumed generation %d", claim.ExecutionGeneration())
		}
		admission, err := ReserveAdmissions(claim)
		if err != nil {
			t.Fatal(err)
		}
		admission.Release()
	})

	t.Run("published commit remains held", func(t *testing.T) {
		claim, plan := resourceTransactionFixture(t, 20*time.Millisecond)
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
		eventually(t, time.Second, func() bool { return tx.State() == ResourceTransactionOutcomeUnknown })
		if claim.ExecutionGeneration() != 1 {
			t.Fatalf("uncertain commit generation=%d want=1", claim.ExecutionGeneration())
		}
		if !claimResource(claim).Snapshot().Poisoned {
			t.Fatal("uncertain transaction was not reported fail-closed")
		}
		if _, err := ReserveAdmissions(claim); !errors.Is(err, ErrAuthorityActive) {
			t.Fatalf("admission over uncertain commit=%v", err)
		}
		if err := tx.Abort(); !errors.Is(err, ErrTransactionOutcomeUnknown) {
			t.Fatalf("abort uncertain transaction=%v", err)
		}
	})
}

func TestResourceTransactionCopiesConsumeExactlyOnce(t *testing.T) {
	claim, plan := resourceTransactionFixture(t, time.Second)
	tx, err := claim.ReserveResourceTransaction(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.MarkPrepared(1, plan.Deadline); err != nil {
		t.Fatal(err)
	}
	if err := tx.MarkCommitPublished(); err != nil {
		t.Fatal(err)
	}
	if err := tx.MarkFinalAccepted(); err != nil {
		t.Fatal(err)
	}

	const workers = 100
	start := make(chan struct{})
	var wg sync.WaitGroup
	var wins atomic.Int32
	var consumed atomic.Int32
	var unexpected atomic.Int32
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		copyOfTransaction := *tx
		go func(transaction ResourceTransaction) {
			defer wg.Done()
			<-start
			switch err := transaction.Consume(); {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, ErrAuthorityConsumed):
				consumed.Add(1)
			default:
				unexpected.Add(1)
			}
		}(copyOfTransaction)
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 || consumed.Load() != workers-1 || unexpected.Load() != 0 {
		t.Fatalf("wins=%d consumed=%d unexpected=%d", wins.Load(), consumed.Load(), unexpected.Load())
	}
	if err := tx.BeginResolution(ResolutionRolledBack); err != nil {
		t.Fatal(err)
	}
	if err := tx.FinishResolution(ResolutionRolledBack); err != nil {
		t.Fatal(err)
	}
}

func TestResourceTransactionStateAndSnapshotAreRaceSafe(t *testing.T) {
	claim, plan := resourceTransactionFixture(t, 2*time.Second)
	tx, err := claim.ReserveResourceTransaction(plan)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var readers sync.WaitGroup
	for i := 0; i < 16; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-done:
					return
				default:
					_ = tx.State()
					_ = tx.Snapshot()
					_ = claimResource(claim).Snapshot()
				}
			}
		}()
	}
	for _, transition := range []func() error{
		func() error { return tx.MarkPrepared(1, plan.Deadline.Add(-time.Millisecond)) },
		tx.MarkCommitPublished,
		tx.MarkFinalAccepted,
		tx.Consume,
		func() error { return tx.BeginResolution(ResolutionComplete) },
		func() error { return tx.FinishResolution(ResolutionComplete) },
	} {
		if err := transition(); err != nil {
			close(done)
			readers.Wait()
			t.Fatal(err)
		}
	}
	close(done)
	readers.Wait()
}

func TestAdmissionPoisonPersistsAcrossClaimReplacement(t *testing.T) {
	resource := MustNewResource(ScopeSharedLink)
	first := newTestDrivenClaim(t, resource, OperationGVisorLinkRebind, KindGVisor, testBinding(41))
	hold, err := ReserveAdmissions(first)
	if err != nil {
		t.Fatal(err)
	}
	hold.Poison()
	if !resource.Snapshot().Poisoned {
		t.Fatal("poisoned peer guard was not retained by the resource")
	}
	second := newTestDrivenClaim(t, resource, OperationGVisorLinkRebind, KindGVisor, testBinding(42))
	plan := authorityPlanForOperation(t, second, testBinding(42), TransactionID{0xd2}, time.Now().Add(time.Second), OperationGVisorLinkRebind)
	if _, err := second.ReserveResourceTransaction(plan); !errors.Is(err, ErrResourceOutcomeUnknown) {
		t.Fatalf("transaction on poisoned resource=%v want=%v", err, ErrResourceOutcomeUnknown)
	}
}

func TestAdmissionPoisonCanBeReconciledOnlyByOwningReservation(t *testing.T) {
	resource := MustNewResource(ScopeSharedLink)
	claim := newTestDrivenClaim(t, resource, OperationGVisorLinkRebind, KindGVisor, testBinding(43))
	hold, err := ReserveAdmissions(claim)
	if err != nil {
		t.Fatal(err)
	}
	hold.Poison()
	if !resource.Snapshot().Poisoned {
		t.Fatal("poisoned reservation did not isolate resource")
	}
	if !hold.ReconcilePoison() {
		t.Fatal("owning reservation could not reconcile its poison")
	}
	if resource.Snapshot().Poisoned {
		t.Fatal("correlated reconciliation left resource poisoned")
	}
	if hold.ReconcilePoison() {
		t.Fatal("repeated poison reconciliation succeeded")
	}
	if next, err := ReserveAdmissions(claim); err != nil {
		t.Fatalf("resource remained unavailable after reconciliation: %v", err)
	} else {
		next.Release()
	}
}

func TestResourceTransactionSerializesSharedHandleAcrossClaims(t *testing.T) {
	resource := MustNewResource(ScopeSharedLink)
	first := newTestDrivenClaim(t, resource, OperationGVisorLinkRebind, KindGVisor, testBinding(51))
	second := newTestDrivenClaim(t, resource, OperationGVisorLinkRebind, KindGVisor, testBinding(52))
	firstPlan := authorityPlanForOperation(t, first, testBinding(51), TransactionID{0xe1}, time.Now().Add(time.Second), OperationGVisorLinkRebind)
	secondPlan := authorityPlanForOperation(t, second, testBinding(52), TransactionID{0xe2}, time.Now().Add(time.Second), OperationGVisorLinkRebind)
	firstTx, err := first.ReserveResourceTransaction(firstPlan)
	if err != nil {
		t.Fatal(err)
	}
	defer firstTx.Abort()
	if _, err := second.ReserveResourceTransaction(secondPlan); !errors.Is(err, ErrAuthorityActive) {
		t.Fatalf("parallel shared transaction=%v want=%v", err, ErrAuthorityActive)
	}
}

func TestResourceHandlePreservesGenerationAcrossClaimReplacement(t *testing.T) {
	resource := MustNewResource(ScopeEndpoint)
	firstBinding := testBinding(61)
	first := newTestDrivenClaim(t, resource, OperationTCPRepair, KindRawTCP, firstBinding)
	firstPlan := authorityPlan(t, first, firstBinding, TransactionID{0xf1}, time.Now().Add(time.Second))
	tx, err := first.ReserveResourceTransaction(firstPlan)
	if err != nil {
		t.Fatal(err)
	}
	for _, transition := range []func() error{
		func() error { return tx.MarkPrepared(1, firstPlan.Deadline) },
		tx.MarkCommitPublished,
		tx.MarkFinalAccepted,
		func() error { return tx.BeginResolution(ResolutionRolledBack) },
		func() error { return tx.FinishResolution(ResolutionRolledBack) },
	} {
		if err := transition(); err != nil {
			t.Fatal(err)
		}
	}
	if err := first.Retire(firstBinding); err != nil {
		t.Fatal(err)
	}

	secondBinding := testBinding(62)
	second := newTestDrivenClaim(t, resource, OperationTCPRepair, KindRawTCP, secondBinding)
	next := authorityPlan(t, second, secondBinding, TransactionID{0xf2}, time.Now().Add(time.Second))
	if next.BaseGeneration != 1 || resource.Snapshot().Generation != 1 {
		t.Fatalf("replacement base=%d resource generation=%d", next.BaseGeneration, resource.Snapshot().Generation)
	}
}

func TestPublishedResourceTransactionRetirementConsumesGeneration(t *testing.T) {
	resource := MustNewResource(ScopeEndpoint)
	firstBinding := testBinding(63)
	first := newTestDrivenClaim(t, resource, OperationTCPRepair, KindRawTCP, firstBinding)
	plan := authorityPlan(t, first, firstBinding, TransactionID{0xf3}, time.Now().Add(time.Second))
	tx, err := first.ReserveResourceTransaction(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.MarkProposalPublished(); err != nil {
		t.Fatal(err)
	}
	if err := first.Retire(firstBinding); err != nil {
		t.Fatal(err)
	}
	if tx.State() != ResourceTransactionRevoked || resource.Snapshot().Generation != 1 {
		t.Fatalf("retired state=%d resource=%+v", tx.State(), resource.Snapshot())
	}

	secondBinding := testBinding(64)
	second := newTestDrivenClaim(t, resource, OperationTCPRepair, KindRawTCP, secondBinding)
	next := authorityPlan(t, second, secondBinding, TransactionID{0xf4}, time.Now().Add(time.Second))
	if next.BaseGeneration != 1 {
		t.Fatalf("replacement base=%d want=1", next.BaseGeneration)
	}
}

func TestResourceTransactionRetirementIsFailClosedAfterFinalAcceptance(t *testing.T) {
	claim, plan := resourceTransactionFixture(t, time.Second)
	tx, err := claim.ReserveResourceTransaction(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.MarkPrepared(1, plan.Deadline); err != nil {
		t.Fatal(err)
	}
	if err := tx.MarkCommitPublished(); err != nil {
		t.Fatal(err)
	}
	if err := tx.MarkFinalAccepted(); err != nil {
		t.Fatal(err)
	}
	if err := claim.Retire(plan.Binding); err != nil {
		t.Fatal(err)
	}
	snapshot := tx.Snapshot()
	if snapshot.State != ResourceTransactionOutcomeUnknown || snapshot.UnknownFrom != ResourceTransactionFinalAccepted {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	if err := tx.BeginResolution(ResolutionRolledBack); err != nil {
		t.Fatal(err)
	}
	if err := tx.FinishResolution(ResolutionRolledBack); err != nil {
		t.Fatal(err)
	}
}

func TestResourceTransactionConcurrentReservationHasOneWinner(t *testing.T) {
	claim, plan := resourceTransactionFixture(t, time.Second)
	const workers = 100
	start := make(chan struct{})
	var wg sync.WaitGroup
	var wins atomic.Int32
	var unexpected atomic.Int32
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			<-start
			tx, err := claim.ReserveResourceTransaction(plan)
			switch {
			case err == nil && tx != nil:
				wins.Add(1)
			case errors.Is(err, ErrAuthorityActive):
			default:
				unexpected.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 || unexpected.Load() != 0 {
		t.Fatalf("wins=%d unexpected=%d", wins.Load(), unexpected.Load())
	}
}

func resourceTransactionFixture(t testing.TB, lease time.Duration) (*Claim, Plan) {
	t.Helper()
	resource := MustNewResource(ScopeEndpoint)
	binding := testBinding(21)
	claim := newTestDrivenClaim(t, resource, OperationTCPRepair, KindRawTCP, binding)
	plan := authorityPlan(t, claim, binding, TransactionID{0xb1, 0xb2}, time.Now().Add(lease))
	return claim, plan
}

func newTestDrivenClaim(t testing.TB, resource Resource, operation Operation, kind Kind, binding Binding) *Claim {
	t.Helper()
	driver := &fakeDriver{operation: operation, result: PreflightResult{Eligible: true, EvidenceDigest: EvidenceDigest{0xa1}}}
	facts := testDrivenFacts()
	facts.Kind = kind
	facts.Generation = NextGeneration()
	claim := MustNewDrivenClaim(facts, driver, resource)
	if err := claim.Bind(binding); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = claim.Retire(binding) })
	return claim
}

func claimResource(claim *Claim) Resource {
	claim.mu.RLock()
	resource := Resource{state: claim.resource}
	claim.mu.RUnlock()
	return resource
}

func authorityPlan(t testing.TB, claim *Claim, binding Binding, transaction TransactionID, deadline time.Time) Plan {
	t.Helper()
	return authorityPlanForOperation(t, claim, binding, transaction, deadline, OperationTCPRepair)
}

func authorityPlanForOperation(t testing.TB, claim *Claim, binding Binding, transaction TransactionID, deadline time.Time, operation Operation) Plan {
	t.Helper()
	plan, err := PlanCandidate(context.Background(), claim, PlanRequest{
		TransactionID: transaction, Binding: binding, Direction: proto.SenderDirectionClientToServer,
		Session: SessionStream, Deadline: deadline, LocalSupport: operation, PeerSupport: operation,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Operation != operation {
		t.Fatalf("plan operation=%d want=%d reason=%s", plan.Operation, operation, plan.Reason)
	}
	return plan
}

func eventually(t testing.TB, timeout time.Duration, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition did not become true before deadline")
}
