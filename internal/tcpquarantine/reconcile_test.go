package tcpquarantine

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestReconcileDeletesOnlyExactTableFromProvenDeadProcess(t *testing.T) {
	manager, runner := newReconcileTestManager(t)
	stale := testProcessIdentity(0x90)
	spec := newNFTSpec(stale, testOwnerToken(0x91), testTransactionID(), testTuple())
	manager.processState = func(identity processIdentity) (processState, error) {
		if identity != stale {
			t.Fatalf("observed process = %+v, want %+v", identity, stale)
		}
		return processStateDead, nil
	}
	runner.append(
		runnerStep{wantArgs: listTablesArgs(), result: tableListResult(t, "foreign_table", spec.table)},
		runnerStep{wantArgs: spec.listTableArgs(), result: exactTableResult(t, spec, nil)},
		runnerStep{wantArgs: []string{"-f", "-"}, wantStdin: spec.deleteBatch()},
	)
	runner.append(absentObservationSteps(t, spec)...)

	report, err := manager.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if report != (ReconcileReport{Managed: 1, Removed: 1}) {
		t.Fatalf("Reconcile() report = %+v", report)
	}
	runner.assertDone()
}

func TestReconcilePreservesLiveOwnerAndCurrentProcessTables(t *testing.T) {
	manager, runner := newReconcileTestManager(t)
	live := testProcessIdentity(0x92)
	liveSpec := newNFTSpec(live, testOwnerToken(0x93), testTransactionID(), testTuple())
	currentSpec := manager.newSpec(testTransactionID(), testTuple())
	manager.processState = func(identity processIdentity) (processState, error) {
		if identity != live {
			t.Fatalf("observed process = %+v, want %+v", identity, live)
		}
		return processStateAlive, nil
	}
	runner.append(runnerStep{
		wantArgs: listTablesArgs(),
		result:   tableListResult(t, currentSpec.table, liveSpec.table),
	})

	report, err := manager.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if report != (ReconcileReport{Managed: 2, Live: 2}) {
		t.Fatalf("Reconcile() report = %+v", report)
	}
	runner.assertDone()
}

func TestReconcileUnknownOwnerFailsClosedAndRetries(t *testing.T) {
	manager, runner := newReconcileTestManager(t)
	stale := testProcessIdentity(0x94)
	spec := newNFTSpec(stale, testOwnerToken(0x95), testTransactionID(), testTuple())
	unknown := errors.New("hidden PID namespace")
	attempts := 0
	manager.processState = func(identity processIdentity) (processState, error) {
		attempts++
		if attempts == 1 {
			return processStateUnknown, unknown
		}
		return processStateDead, nil
	}
	runner.append(runnerStep{wantArgs: listTablesArgs(), result: tableListResult(t, spec.table)})
	report, err := manager.Reconcile(context.Background())
	if !errors.Is(err, ErrReconcileIncomplete) || !errors.Is(err, ErrProcessStateUnknown) {
		t.Fatalf("first Reconcile() error = %v", err)
	}
	if report != (ReconcileReport{Managed: 1, Unknown: 1}) {
		t.Fatalf("first Reconcile() report = %+v", report)
	}

	runner.append(
		runnerStep{wantArgs: listTablesArgs(), result: tableListResult(t, spec.table)},
		runnerStep{wantArgs: spec.listTableArgs(), result: exactTableResult(t, spec, nil)},
		runnerStep{wantArgs: []string{"-f", "-"}, wantStdin: spec.deleteBatch()},
	)
	runner.append(absentObservationSteps(t, spec)...)
	report, err = manager.Reconcile(context.Background())
	if err != nil || report != (ReconcileReport{Managed: 1, Removed: 1}) {
		t.Fatalf("retry Reconcile() = (%+v, %v)", report, err)
	}
	runner.assertDone()
}

func TestReconcileNeverDeletesMalformedOrMutatedManagedTable(t *testing.T) {
	t.Run("malformed identity", func(t *testing.T) {
		manager, runner := newReconcileTestManager(t)
		name := managedPrefix + "not-an-identity"
		runner.append(runnerStep{wantArgs: listTablesArgs(), result: tableListResult(t, name)})
		report, err := manager.Reconcile(context.Background())
		if !errors.Is(err, ErrReconcileIncomplete) || !errors.Is(err, ErrManagedTableMalformed) {
			t.Fatalf("Reconcile() error = %v", err)
		}
		if report != (ReconcileReport{}) {
			t.Fatalf("Reconcile() report = %+v", report)
		}
		runner.assertDone()
	})

	t.Run("legacy identity without process generation", func(t *testing.T) {
		manager, runner := newReconcileTestManager(t)
		name := legacyPrefix + strings.Repeat("a", tokenSize*2) + "_" + strings.Repeat("b", tokenSize*2)
		runner.append(runnerStep{wantArgs: listTablesArgs(), result: tableListResult(t, name)})
		report, err := manager.Reconcile(context.Background())
		if !errors.Is(err, ErrReconcileIncomplete) || !errors.Is(err, ErrManagedTableMalformed) {
			t.Fatalf("Reconcile() error = %v", err)
		}
		if report != (ReconcileReport{}) {
			t.Fatalf("Reconcile() report = %+v", report)
		}
		runner.assertDone()
	})

	t.Run("mutated exact schema", func(t *testing.T) {
		manager, runner := newReconcileTestManager(t)
		stale := testProcessIdentity(0x96)
		spec := newNFTSpec(stale, testOwnerToken(0x97), testTransactionID(), testTuple())
		manager.processState = func(processIdentity) (processState, error) { return processStateDead, nil }
		mutated := exactTableResult(t, spec, func(objects []any) {
			mutateRule(objects, outputChain, func(rule map[string]any) {
				rule["comment"] = "foreign-owner"
			})
		})
		runner.append(
			runnerStep{wantArgs: listTablesArgs(), result: tableListResult(t, spec.table)},
			runnerStep{wantArgs: spec.listTableArgs(), result: mutated},
		)
		report, err := manager.Reconcile(context.Background())
		if !errors.Is(err, ErrReconcileIncomplete) || !strings.Contains(err.Error(), ErrManagedTableMalformed.Error()) {
			t.Fatalf("Reconcile() error = %v", err)
		}
		if report != (ReconcileReport{Managed: 1, Unknown: 1}) {
			t.Fatalf("Reconcile() report = %+v", report)
		}
		runner.assertDone()
	})
}

func TestReconcileTreatsDeleteErrorWithProvenAbsenceAsSuccess(t *testing.T) {
	manager, runner := newReconcileTestManager(t)
	stale := testProcessIdentity(0x98)
	spec := newNFTSpec(stale, testOwnerToken(0x99), testTransactionID(), testTuple())
	manager.processState = func(processIdentity) (processState, error) { return processStateDead, nil }
	runner.append(
		runnerStep{wantArgs: listTablesArgs(), result: tableListResult(t, spec.table)},
		runnerStep{wantArgs: spec.listTableArgs(), result: exactTableResult(t, spec, nil)},
		runnerStep{wantArgs: []string{"-f", "-"}, wantStdin: spec.deleteBatch(), err: errFakeCommand},
	)
	runner.append(absentObservationSteps(t, spec)...)

	report, err := manager.Reconcile(context.Background())
	if err != nil || report != (ReconcileReport{Managed: 1, Removed: 1}) {
		t.Fatalf("Reconcile() = (%+v, %v)", report, err)
	}
	runner.assertDone()
}

func TestInstallCannotRunBeforeSuccessfulReconciliation(t *testing.T) {
	manager, runner := newReconcileTestManager(t)
	reconcileFailure := errors.New("cannot enumerate nft state")
	runner.append(runnerStep{wantArgs: listTablesArgs(), err: reconcileFailure})
	lease, err := manager.Install(context.Background(), testTransactionID(), testTuple())
	if lease != nil || !errors.Is(err, ErrReconcileIncomplete) || !errors.Is(err, reconcileFailure) {
		t.Fatalf("Install() = (%v, %v)", lease, err)
	}
	if len(manager.activeLeases) != 0 {
		t.Fatalf("failed reconciliation reserved %d lease(s)", len(manager.activeLeases))
	}
	runner.assertDone()
}

func TestCanceledReconcileIssuesNoCommands(t *testing.T) {
	manager, runner := newReconcileTestManager(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, err := manager.Reconcile(ctx)
	if report != (ReconcileReport{}) || !errors.Is(err, ErrReconcileIncomplete) || !errors.Is(err, context.Canceled) {
		t.Fatalf("Reconcile(canceled) = (%+v, %v)", report, err)
	}
	if runner.callCount() != 0 {
		t.Fatalf("canceled Reconcile issued %d command(s)", runner.callCount())
	}
	runner.assertDone()
}

func TestConcurrentReconcileDeletesStaleTableOnce(t *testing.T) {
	manager, runner := newReconcileTestManager(t)
	stale := testProcessIdentity(0x9a)
	spec := newNFTSpec(stale, testOwnerToken(0x9b), testTransactionID(), testTuple())
	manager.processState = func(processIdentity) (processState, error) { return processStateDead, nil }
	runner.append(
		runnerStep{wantArgs: listTablesArgs(), result: tableListResult(t, spec.table)},
		runnerStep{wantArgs: spec.listTableArgs(), result: exactTableResult(t, spec, nil)},
		runnerStep{wantArgs: []string{"-f", "-"}, wantStdin: spec.deleteBatch()},
	)
	runner.append(absentObservationSteps(t, spec)...)
	runner.append(runnerStep{wantArgs: listTablesArgs(), result: emptyTablesResult(t)})

	start := make(chan struct{})
	results := make(chan ReconcileReport, 2)
	errorsSeen := make(chan error, 2)
	var workers sync.WaitGroup
	workers.Add(2)
	for range 2 {
		go func() {
			defer workers.Done()
			<-start
			report, err := manager.Reconcile(context.Background())
			results <- report
			errorsSeen <- err
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	close(errorsSeen)
	removed := 0
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("concurrent Reconcile() error = %v", err)
		}
	}
	for report := range results {
		removed += report.Removed
	}
	if removed != 1 {
		t.Fatalf("concurrent Reconcile() removed %d tables, want 1", removed)
	}
	runner.assertDone()
}

func newReconcileTestManager(t *testing.T) (*Manager, *scriptedRunner) {
	t.Helper()
	runner := newScriptedRunner(t)
	manager := mustManager(t, runner)
	scope, err := currentNamespaceScope()
	if err != nil {
		t.Fatal(err)
	}
	delete(manager.reconciledScopes, scope)
	return manager, runner
}

func testProcessIdentity(seed uint64) processIdentity {
	return processIdentity{
		pidNamespaceDevice: seed,
		pidNamespaceInode:  seed + 1,
		pid:                seed + 2,
		startTime:          seed + 3,
	}
}

func testOwnerToken(seed byte) ownerToken {
	var owner ownerToken
	for index := range owner {
		owner[index] = seed
	}
	return owner
}
