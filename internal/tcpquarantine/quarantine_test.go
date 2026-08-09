package tcpquarantine

import (
	"context"
	"encoding/hex"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestReconcileContextIgnoresCancellationButPreservesEarlierDeadline(t *testing.T) {
	manager := &Manager{reconcileTimeout: time.Second}
	parent, cancelParent := context.WithDeadline(context.Background(), time.Now().Add(100*time.Millisecond))
	cancelParent()

	ctx, cancel := manager.reconcileContext(parent)
	defer cancel()
	if err := ctx.Err(); err != nil {
		t.Fatalf("reconcile context inherited cancellation: %v", err)
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("reconcile context has no deadline")
	}
	parentDeadline, _ := parent.Deadline()
	if deadline != parentDeadline {
		t.Fatalf("reconcile deadline = %v, want parent deadline %v", deadline, parentDeadline)
	}
}

func TestReconcileContextAppliesItsOwnShorterCap(t *testing.T) {
	manager := &Manager{reconcileTimeout: 25 * time.Millisecond}
	parent, cancelParent := context.WithTimeout(context.Background(), time.Second)
	defer cancelParent()

	started := time.Now()
	ctx, cancel := manager.reconcileContext(parent)
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("reconcile context has no deadline")
	}
	remaining := deadline.Sub(started)
	if remaining <= 0 || remaining > 100*time.Millisecond {
		t.Fatalf("reconcile cap = %s, want bounded by configured timeout", remaining)
	}
}

func TestReleaseRefusesToObserveOrDeleteOutsideInstalledNamespace(t *testing.T) {
	runner := newScriptedRunner(t)
	manager := mustManager(t, runner)
	scope, err := currentNamespaceScope()
	if err != nil {
		t.Fatal(err)
	}
	scope.inode++
	spec := newNFTSpec(manager.owner, testTransactionID(), testTuple())
	state, err := manager.reserveLease(testTransactionID(), spec, scope)
	if err != nil {
		t.Fatalf("reserveLease() error = %v", err)
	}
	err = (&Lease{state: state}).Release(context.Background())
	if !errors.Is(err, ErrExecutionScopeChanged) {
		t.Fatalf("release scope error = %v, want ErrExecutionScopeChanged", err)
	}
	runner.assertDone()
}

func TestPreflightUsesCheckBatchAndProvesAbsence(t *testing.T) {
	runner := newScriptedRunner(t)
	manager := mustManager(t, runner)
	spec := newNFTSpec(manager.owner, testTransactionID(), testTuple())
	runner.append(runnerStep{
		wantArgs:  []string{"-c", "-f", "-"},
		wantStdin: spec.installBatch(),
	})
	runner.append(absentObservationSteps(t, spec)...)

	if err := manager.Preflight(context.Background(), testTransactionID(), testTuple()); err != nil {
		t.Fatalf("Preflight() error = %v", err)
	}
	runner.assertDone()
}

func TestPreflightNeverDeletesUnexpectedTable(t *testing.T) {
	runner := newScriptedRunner(t)
	manager := mustManager(t, runner)
	spec := newNFTSpec(manager.owner, testTransactionID(), testTuple())
	runner.append(
		runnerStep{wantArgs: []string{"-c", "-f", "-"}, wantStdin: spec.installBatch(), err: errFakeCommand},
		runnerStep{wantArgs: spec.listTableArgs(), result: exactTableResult(t, spec, nil)},
	)

	err := manager.Preflight(context.Background(), testTransactionID(), testTuple())
	if !errors.Is(err, ErrPreflightStateChanged) {
		t.Fatalf("Preflight() error = %v, want ErrPreflightStateChanged", err)
	}
	runner.assertDone()
}

func TestInstallErrorAbsent(t *testing.T) {
	runner := newScriptedRunner(t)
	manager := mustManager(t, runner)
	spec := newNFTSpec(manager.owner, testTransactionID(), testTuple())
	runner.append(runnerStep{
		wantArgs:  []string{"-f", "-"},
		wantStdin: spec.installBatch(),
		err:       errFakeCommand,
	})
	runner.append(absentObservationSteps(t, spec)...)

	lease, err := manager.Install(context.Background(), testTransactionID(), testTuple())
	if lease != nil {
		t.Fatal("Install() returned a lease for an absent table")
	}
	if !errors.Is(err, ErrInstallNotApplied) || !errors.Is(err, errFakeCommand) {
		t.Fatalf("Install() error = %v, want install and command errors", err)
	}
	runner.assertDone()
}

func TestInstallErrorAbsentCanRetryWithNewIncarnation(t *testing.T) {
	runner := newScriptedRunner(t)
	manager := mustManager(t, runner)
	spec := newNFTSpec(manager.owner, testTransactionID(), testTuple())
	runner.append(runnerStep{
		wantArgs:  []string{"-f", "-"},
		wantStdin: spec.installBatch(),
		err:       errFakeCommand,
	})
	runner.append(absentObservationSteps(t, spec)...)

	failed, err := manager.Install(context.Background(), testTransactionID(), testTuple())
	if failed != nil || !errors.Is(err, ErrInstallNotApplied) {
		t.Fatalf("first Install() = (%v, %v), want proven-absent failure", failed, err)
	}

	runner.append(
		runnerStep{wantArgs: []string{"-f", "-"}, wantStdin: spec.installBatch()},
		runnerStep{wantArgs: spec.listTableArgs(), result: exactTableResult(t, spec, nil)},
	)
	lease, err := manager.Install(context.Background(), testTransactionID(), testTuple())
	if lease == nil || err != nil {
		t.Fatalf("retry Install() = (%v, %v), want lease", lease, err)
	}
	if lease.state.generation != 2 {
		t.Fatalf("retry generation = %d, want 2", lease.state.generation)
	}

	runner.append(runnerStep{wantArgs: []string{"-f", "-"}, wantStdin: spec.deleteBatch()})
	runner.append(absentObservationSteps(t, spec)...)
	if err := lease.Release(context.Background()); err != nil {
		t.Fatalf("Release() error = %v", err)
	}
	runner.assertDone()
}

func TestInstallErrorPresentIsReconciledAsSuccess(t *testing.T) {
	runner := newScriptedRunner(t)
	manager := mustManager(t, runner)
	spec := newNFTSpec(manager.owner, testTransactionID(), testTuple())
	runner.append(
		runnerStep{wantArgs: []string{"-f", "-"}, wantStdin: spec.installBatch(), err: errFakeCommand},
		runnerStep{wantArgs: spec.listTableArgs(), result: exactTableResult(t, spec, nil)},
	)

	lease, err := manager.Install(context.Background(), testTransactionID(), testTuple())
	if err != nil || lease == nil {
		t.Fatalf("Install() = (%v, %v), want verified lease and nil error", lease, err)
	}

	runner.append(runnerStep{wantArgs: []string{"-f", "-"}, wantStdin: spec.deleteBatch()})
	runner.append(absentObservationSteps(t, spec)...)
	if err := lease.Release(context.Background()); err != nil {
		t.Fatalf("Release() error = %v", err)
	}
	runner.assertDone()
}

func TestInstallErrorMalformedCleansUp(t *testing.T) {
	runner := newScriptedRunner(t)
	manager := mustManager(t, runner)
	spec := newNFTSpec(manager.owner, testTransactionID(), testTuple())
	runner.append(
		runnerStep{wantArgs: []string{"-f", "-"}, wantStdin: spec.installBatch(), err: errFakeCommand},
		runnerStep{wantArgs: spec.listTableArgs(), result: RunResult{Stdout: []byte(`{"nftables":[`)}},
		runnerStep{wantArgs: []string{"-f", "-"}, wantStdin: spec.deleteBatch(), check: requireBoundedLiveContext},
	)
	cleanupObservation := absentObservationSteps(t, spec)
	for index := range cleanupObservation {
		cleanupObservation[index].check = requireBoundedLiveContext
	}
	runner.append(cleanupObservation...)

	lease, err := manager.Install(context.Background(), testTransactionID(), testTuple())
	if lease != nil {
		t.Fatal("Install() retained lease after verified cleanup")
	}
	if !errors.Is(err, ErrVerificationFailed) || !errors.Is(err, errFakeCommand) {
		t.Fatalf("Install() error = %v, want verification and command errors", err)
	}
	runner.assertDone()
}

func TestInstallVerifyFailureCleansUpMutatedRule(t *testing.T) {
	runner := newScriptedRunner(t)
	manager := mustManager(t, runner)
	spec := newNFTSpec(manager.owner, testTransactionID(), testTuple())
	mutated := exactTableResult(t, spec, func(objects []any) {
		mutateRule(objects, outputChain, func(rule map[string]any) {
			expressions := rule["expr"].([]any)
			expressions[len(expressions)-1] = map[string]any{"accept": nil}
		})
	})
	runner.append(
		runnerStep{wantArgs: []string{"-f", "-"}, wantStdin: spec.installBatch()},
		runnerStep{wantArgs: spec.listTableArgs(), result: mutated},
		runnerStep{wantArgs: []string{"-f", "-"}, wantStdin: spec.deleteBatch()},
	)
	runner.append(absentObservationSteps(t, spec)...)

	lease, err := manager.Install(context.Background(), testTransactionID(), testTuple())
	if lease != nil || !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("Install() = (%v, %v), want cleaned verification failure", lease, err)
	}
	runner.assertDone()
}

func TestInstallUnknownCleanupReturnsRetryableLease(t *testing.T) {
	runner := newScriptedRunner(t)
	manager := mustManager(t, runner)
	spec := newNFTSpec(manager.owner, testTransactionID(), testTuple())
	runner.append(
		runnerStep{wantArgs: []string{"-f", "-"}, wantStdin: spec.installBatch()},
		runnerStep{wantArgs: spec.listTableArgs(), err: errFakeCommand},
		runnerStep{wantArgs: listTablesArgs(), err: errFakeCommand},
		runnerStep{wantArgs: []string{"-f", "-"}, wantStdin: spec.deleteBatch(), err: errFakeCommand},
		runnerStep{wantArgs: spec.listTableArgs(), err: errFakeCommand},
		runnerStep{wantArgs: listTablesArgs(), err: errFakeCommand},
	)

	lease, err := manager.Install(context.Background(), testTransactionID(), testTuple())
	if lease == nil || !errors.Is(err, ErrStateUnknown) || !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("Install() = (%v, %v), want retryable unknown lease", lease, err)
	}
	callCount := runner.callCount()
	duplicate, duplicateErr := manager.Install(context.Background(), testTransactionID(), testTuple())
	if duplicate != nil || !errors.Is(duplicateErr, ErrLeaseBusy) {
		t.Fatalf("Install() while cleanup ownership is retained = (%v, %v), want ErrLeaseBusy", duplicate, duplicateErr)
	}
	if got := runner.callCount(); got != callCount {
		t.Fatalf("retained-ownership Install() issued %d nft calls, want none", got-callCount)
	}

	runner.append(runnerStep{wantArgs: []string{"-f", "-"}, wantStdin: spec.deleteBatch()})
	runner.append(absentObservationSteps(t, spec)...)
	if err := lease.Release(context.Background()); err != nil {
		t.Fatalf("retry Release() error = %v", err)
	}
	runner.assertDone()
}

func TestReleaseErrorAbsentIsSuccessAndIdempotent(t *testing.T) {
	lease, runner, spec := installVerifiedLease(t)
	runner.append(runnerStep{wantArgs: []string{"-f", "-"}, wantStdin: spec.deleteBatch(), err: errFakeCommand})
	runner.append(absentObservationSteps(t, spec)...)

	if err := lease.Release(context.Background()); err != nil {
		t.Fatalf("Release() error = %v", err)
	}
	calls := runner.callCount()
	if err := lease.Release(context.Background()); err != nil {
		t.Fatalf("idempotent Release() error = %v", err)
	}
	if runner.callCount() != calls {
		t.Fatal("idempotent Release issued another nft command")
	}
	runner.assertDone()
}

func TestReleaseErrorPresentRemainsRetryable(t *testing.T) {
	lease, runner, spec := installVerifiedLease(t)
	runner.append(
		runnerStep{wantArgs: []string{"-f", "-"}, wantStdin: spec.deleteBatch(), err: errFakeCommand},
		runnerStep{wantArgs: spec.listTableArgs(), result: exactTableResult(t, spec, nil)},
	)

	if err := lease.Release(context.Background()); !errors.Is(err, ErrReleaseNotApplied) {
		t.Fatalf("first Release() error = %v, want ErrReleaseNotApplied", err)
	}
	runner.append(runnerStep{wantArgs: []string{"-f", "-"}, wantStdin: spec.deleteBatch()})
	runner.append(absentObservationSteps(t, spec)...)
	if err := lease.Release(context.Background()); err != nil {
		t.Fatalf("retry Release() error = %v", err)
	}
	runner.assertDone()
}

func TestReleaseUnknownIsNotSuccessAndRemainsRetryable(t *testing.T) {
	lease, runner, spec := installVerifiedLease(t)
	runner.append(
		runnerStep{wantArgs: []string{"-f", "-"}, wantStdin: spec.deleteBatch()},
		runnerStep{wantArgs: spec.listTableArgs(), err: errFakeCommand},
		runnerStep{wantArgs: listTablesArgs(), result: RunResult{Stdout: []byte(`{"nftables":[{"table":{"family":"inet"}}]}`)}},
	)

	if err := lease.Release(context.Background()); !errors.Is(err, ErrStateUnknown) {
		t.Fatalf("first Release() error = %v, want ErrStateUnknown", err)
	}
	runner.append(runnerStep{wantArgs: []string{"-f", "-"}, wantStdin: spec.deleteBatch()})
	runner.append(absentObservationSteps(t, spec)...)
	if err := lease.Release(context.Background()); err != nil {
		t.Fatalf("retry Release() error = %v", err)
	}
	runner.assertDone()
}

func TestConcurrentReleaseSharesOneAttempt(t *testing.T) {
	lease, runner, spec := installVerifiedLease(t)
	started := make(chan struct{})
	allow := make(chan struct{})
	runner.append(runnerStep{
		wantArgs:  []string{"-f", "-"},
		wantStdin: spec.deleteBatch(),
		run: func(context.Context) (RunResult, error) {
			close(started)
			<-allow
			return RunResult{}, nil
		},
	})
	runner.append(absentObservationSteps(t, spec)...)

	const callers = 16
	errorsSeen := make(chan error, callers)
	var wait sync.WaitGroup
	wait.Add(callers)
	for range callers {
		go func() {
			defer wait.Done()
			errorsSeen <- lease.Release(context.Background())
		}()
	}
	<-started
	close(allow)
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Errorf("concurrent Release() error = %v", err)
		}
	}
	if got := runner.callCount(); got != 5 {
		t.Fatalf("nft call count = %d, want install/list plus one delete/absence observation", got)
	}
	runner.assertDone()
}

func TestDuplicateSequentialInstallReturnsBusyWithoutNFTMutation(t *testing.T) {
	lease, runner, spec := installVerifiedLease(t)
	callCount := runner.callCount()

	duplicate, err := lease.state.manager.Install(context.Background(), testTransactionID(), testTuple())
	if duplicate != nil || !errors.Is(err, ErrLeaseBusy) {
		t.Fatalf("duplicate Install() = (%v, %v), want nil lease and ErrLeaseBusy", duplicate, err)
	}
	if got := runner.callCount(); got != callCount {
		t.Fatalf("duplicate Install() issued %d nft calls, want none", got-callCount)
	}

	runner.append(runnerStep{wantArgs: []string{"-f", "-"}, wantStdin: spec.deleteBatch()})
	runner.append(absentObservationSteps(t, spec)...)
	if err := lease.Release(context.Background()); err != nil {
		t.Fatalf("Release() error = %v", err)
	}
	runner.assertDone()
}

func TestDuplicateConcurrentInstallHasOneOwnershipToken(t *testing.T) {
	runner := newScriptedRunner(t)
	manager := mustManager(t, runner)
	spec := newNFTSpec(manager.owner, testTransactionID(), testTuple())
	started := make(chan struct{})
	allow := make(chan struct{})
	runner.append(
		runnerStep{
			wantArgs:  []string{"-f", "-"},
			wantStdin: spec.installBatch(),
			run: func(context.Context) (RunResult, error) {
				close(started)
				<-allow
				return RunResult{}, nil
			},
		},
		runnerStep{wantArgs: spec.listTableArgs(), result: exactTableResult(t, spec, nil)},
	)

	type installResult struct {
		lease *Lease
		err   error
	}
	firstResult := make(chan installResult, 1)
	go func() {
		lease, err := manager.Install(context.Background(), testTransactionID(), testTuple())
		firstResult <- installResult{lease: lease, err: err}
	}()
	<-started

	duplicate, err := manager.Install(context.Background(), testTransactionID(), testTuple())
	if duplicate != nil || !errors.Is(err, ErrLeaseBusy) {
		t.Fatalf("concurrent duplicate Install() = (%v, %v), want nil lease and ErrLeaseBusy", duplicate, err)
	}
	if got := runner.callCount(); got != 1 {
		t.Fatalf("nft call count while first Install is blocked = %d, want 1", got)
	}

	close(allow)
	first := <-firstResult
	if first.lease == nil || first.err != nil {
		t.Fatalf("first Install() = (%v, %v), want one lease", first.lease, first.err)
	}
	runner.append(runnerStep{wantArgs: []string{"-f", "-"}, wantStdin: spec.deleteBatch()})
	runner.append(absentObservationSteps(t, spec)...)
	if err := first.lease.Release(context.Background()); err != nil {
		t.Fatalf("Release() error = %v", err)
	}
	runner.assertDone()
}

func TestSameTransactionDifferentTupleCannotDeleteActiveLease(t *testing.T) {
	lease, runner, spec := installVerifiedLease(t)
	conflictingTuple := testTuple()
	conflictingTuple.Remote = netip.MustParseAddrPort("203.0.113.20:8443")
	callCount := runner.callCount()

	conflict, err := lease.state.manager.Install(context.Background(), testTransactionID(), conflictingTuple)
	if conflict != nil || !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("conflicting Install() = (%v, %v), want nil lease and ErrLeaseConflict", conflict, err)
	}
	if got := runner.callCount(); got != callCount {
		t.Fatalf("conflicting Install() issued %d nft calls, want none", got-callCount)
	}

	runner.append(runnerStep{wantArgs: []string{"-f", "-"}, wantStdin: spec.deleteBatch()})
	runner.append(absentObservationSteps(t, spec)...)
	if err := lease.Release(context.Background()); err != nil {
		t.Fatalf("active lease Release() error = %v", err)
	}
	runner.assertDone()
}

func TestFailedReleaseRetryAndReinstallRejectStaleLeaseABA(t *testing.T) {
	first, runner, spec := installVerifiedLease(t)
	manager := first.state.manager
	staleCopy := *first
	runner.append(
		runnerStep{wantArgs: []string{"-f", "-"}, wantStdin: spec.deleteBatch(), err: errFakeCommand},
		runnerStep{wantArgs: spec.listTableArgs(), result: exactTableResult(t, spec, nil)},
	)
	if err := first.Release(context.Background()); !errors.Is(err, ErrReleaseNotApplied) {
		t.Fatalf("first Release() error = %v, want ErrReleaseNotApplied", err)
	}

	callCount := runner.callCount()
	duplicate, err := manager.Install(context.Background(), testTransactionID(), testTuple())
	if duplicate != nil || !errors.Is(err, ErrLeaseBusy) {
		t.Fatalf("Install() after failed release = (%v, %v), want nil lease and ErrLeaseBusy", duplicate, err)
	}
	if got := runner.callCount(); got != callCount {
		t.Fatalf("Install() after failed release issued %d nft calls, want none", got-callCount)
	}

	runner.append(runnerStep{wantArgs: []string{"-f", "-"}, wantStdin: spec.deleteBatch()})
	runner.append(absentObservationSteps(t, spec)...)
	if err := first.Release(context.Background()); err != nil {
		t.Fatalf("retry Release() error = %v", err)
	}

	runner.append(
		runnerStep{wantArgs: []string{"-f", "-"}, wantStdin: spec.installBatch()},
		runnerStep{wantArgs: spec.listTableArgs(), result: exactTableResult(t, spec, nil)},
	)
	second, err := manager.Install(context.Background(), testTransactionID(), testTuple())
	if second == nil || err != nil {
		t.Fatalf("reinstall after verified release = (%v, %v), want new lease", second, err)
	}
	if second.state.generation == first.state.generation {
		t.Fatalf("reinstall generation = %d, want a new incarnation", second.state.generation)
	}

	callCount = runner.callCount()
	if err := staleCopy.Release(context.Background()); err != nil {
		t.Fatalf("stale copied lease Release() error = %v, want idempotent success", err)
	}
	if got := runner.callCount(); got != callCount {
		t.Fatalf("stale copied lease issued %d nft calls against the new incarnation", got-callCount)
	}

	runner.append(runnerStep{wantArgs: []string{"-f", "-"}, wantStdin: spec.deleteBatch()})
	runner.append(absentObservationSteps(t, spec)...)
	if err := second.Release(context.Background()); err != nil {
		t.Fatalf("new incarnation Release() error = %v", err)
	}
	runner.assertDone()
}

func TestCanceledInstallUsesDetachedBoundedCleanup(t *testing.T) {
	runner := newScriptedRunner(t)
	manager := mustManager(t, runner)
	spec := newNFTSpec(manager.owner, testTransactionID(), testTuple())
	started := make(chan struct{})
	runner.append(runnerStep{
		wantArgs:  []string{"-f", "-"},
		wantStdin: spec.installBatch(),
		run: func(ctx context.Context) (RunResult, error) {
			close(started)
			<-ctx.Done()
			return RunResult{}, context.Cause(ctx)
		},
	})
	runner.append(
		runnerStep{wantArgs: spec.listTableArgs(), result: exactTableResult(t, spec, nil), check: requireBoundedLiveContext},
		runnerStep{wantArgs: []string{"-f", "-"}, wantStdin: spec.deleteBatch(), check: requireBoundedLiveContext},
	)
	cleanupObservation := absentObservationSteps(t, spec)
	for index := range cleanupObservation {
		cleanupObservation[index].check = requireBoundedLiveContext
	}
	runner.append(cleanupObservation...)

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan struct {
		lease *Lease
		err   error
	}, 1)
	go func() {
		lease, err := manager.Install(ctx, testTransactionID(), testTuple())
		result <- struct {
			lease *Lease
			err   error
		}{lease: lease, err: err}
	}()
	<-started
	cancel()
	installed := <-result
	if installed.lease != nil || !errors.Is(installed.err, context.Canceled) {
		t.Fatalf("canceled Install() = (%v, %v), want cleaned context cancellation", installed.lease, installed.err)
	}
	runner.assertDone()
}

func TestBatchNamesUseOnlyOwnerAndTransactionHex(t *testing.T) {
	runner := newScriptedRunner(t)
	manager := mustManager(t, runner)
	spec := newNFTSpec(manager.owner, testTransactionID(), testTuple())
	expected := "rendr_q_" + hex.EncodeToString(manager.owner[:]) + "_" + strings.Repeat("22", tokenSize)
	if spec.table != expected || spec.comment != expected {
		t.Fatalf("derived names = (%q, %q), want %q", spec.table, spec.comment, expected)
	}
	if !regexp.MustCompile(`^rendr_q_[0-9a-f]{32}_[0-9a-f]{32}$`).MatchString(spec.table) {
		t.Fatalf("table name %q is not token/transaction hex", spec.table)
	}
	batch := string(spec.installBatch())
	if strings.Count(batch, "add table ") != 1 || strings.Count(batch, "add chain ") != 2 || strings.Count(batch, "add rule ") != 2 {
		t.Fatalf("install batch does not contain one table, two chains, and two rules:\n%s", batch)
	}
	if strings.Count(batch, `comment "`+expected+`"`) != 2 {
		t.Fatalf("rule comments are not the derived comment:\n%s", batch)
	}
	if got := string(spec.deleteBatch()); got != "delete table inet "+expected+"\n" {
		t.Fatalf("delete batch = %q", got)
	}
}

func TestInvalidIdentityAndNonIPv4TupleIssueNoCommands(t *testing.T) {
	runner := newScriptedRunner(t)
	manager := mustManager(t, runner)

	if lease, err := manager.Install(context.Background(), TransactionID{}, testTuple()); lease != nil || !errors.Is(err, ErrInvalidTransactionID) {
		t.Fatalf("Install(zero transaction) = (%v, %v)", lease, err)
	}
	ipv6Tuple := testTuple()
	ipv6Tuple.Remote = netip.MustParseAddrPort("[2001:db8::1]:443")
	if err := manager.Preflight(context.Background(), testTransactionID(), ipv6Tuple); !errors.Is(err, ErrInvalidTuple) {
		t.Fatalf("Preflight(IPv6 tuple) error = %v, want ErrInvalidTuple", err)
	}
	zeroPortTuple := testTuple()
	zeroPortTuple.Local = netip.AddrPortFrom(zeroPortTuple.Local.Addr(), 0)
	if lease, err := manager.Install(context.Background(), testTransactionID(), zeroPortTuple); lease != nil || !errors.Is(err, ErrInvalidTuple) {
		t.Fatalf("Install(zero port) = (%v, %v)", lease, err)
	}
	if got := runner.callCount(); got != 0 {
		t.Fatalf("invalid requests issued %d nft calls", got)
	}
	runner.assertDone()
}

func TestExecRunnerNeverFallsBackToPATH(t *testing.T) {
	result, err := (execRunner{}).Run(context.Background(), []string{"-j", "list", "tables"}, nil)
	if len(result.Stdout) != 0 || len(result.Stderr) != 0 || !errors.Is(err, ErrNFTExecutableUnavailable) {
		t.Fatalf("zero exec runner = (%+v, %v), want trusted executable error", result, err)
	}
}

func installVerifiedLease(t *testing.T) (*Lease, *scriptedRunner, nftSpec) {
	t.Helper()
	runner := newScriptedRunner(t)
	manager := mustManager(t, runner)
	spec := newNFTSpec(manager.owner, testTransactionID(), testTuple())
	runner.append(
		runnerStep{wantArgs: []string{"-f", "-"}, wantStdin: spec.installBatch()},
		runnerStep{wantArgs: spec.listTableArgs(), result: exactTableResult(t, spec, nil)},
	)
	lease, err := manager.Install(context.Background(), testTransactionID(), testTuple())
	if err != nil || lease == nil {
		t.Fatalf("Install() = (%v, %v), want lease", lease, err)
	}
	return lease, runner, spec
}
