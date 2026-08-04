package tunfull

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/caseexec"
	"github.com/FrankoonG/rendr/regress/internal/chaos"
	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/report"
)

func TestTUNFullCleanupCancellationSafety(t *testing.T) {
	originalJoinTimeout := tunCaseJoinTimeout
	tunCaseJoinTimeout = 200 * time.Millisecond
	t.Cleanup(func() { tunCaseJoinTimeout = originalJoinTimeout })

	t.Run("parent cancellation cleans before non-cooperative workload containment", func(t *testing.T) {
		originalApply := tunChaosApply
		t.Cleanup(func() { tunChaosApply = originalApply })
		cleanupStarted := make(chan struct{})
		var setupCalls atomic.Int32
		var cleanupCalls atomic.Int32
		tunChaosApply = func(chaos.Profile) (func() error, error) {
			setupCalls.Add(1)
			return func() error {
				if cleanupCalls.Add(1) == 1 {
					close(cleanupStarted)
				}
				return nil
			}, nil
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		workloadStarted := make(chan struct{})
		workloadDone := make(chan struct{})
		releaseWorkload := make(chan struct{})
		var releaseOnce sync.Once
		release := func() { releaseOnce.Do(func() { close(releaseWorkload) }) }
		t.Cleanup(func() {
			release()
			waitTUNCleanupSignal(t, workloadDone, "non-cooperative workload exit")
		})

		def := cleanupTUNCase("cleanup.cancel", 2*time.Second, func(cctx context.Context) report.Case {
			return runT4WithBudget(cctx, "cleanup.cancel", 2*time.Second, chaos.Profile{}, func(context.Context) report.Case {
				close(workloadStarted)
				defer close(workloadDone)
				<-releaseWorkload
				return report.Case{}
			})
		})
		returned := make(chan caseexec.Outcome, 1)
		go func() { returned <- runManifestCaseOutcome(ctx, "", def) }()

		waitTUNCleanupSignal(t, workloadStarted, "workload start")
		cancel()
		waitTUNCleanupSignal(t, cleanupStarted, "cleanup start")
		outcome := waitTUNCleanupOutcome(t, returned)
		if !outcome.MustStop || !strings.Contains(outcome.Case.InvalidReason, "Go cannot terminate") {
			t.Fatalf("non-cooperative outcome = %+v", outcome)
		}
		if setupCalls.Load() != 1 || cleanupCalls.Load() != 1 || outcome.Case.Evidence[tunCleanupStateEvidence] != tunCleanupStateComplete {
			t.Fatalf("setup=%d cleanup=%d evidence=%v", setupCalls.Load(), cleanupCalls.Load(), outcome.Case.Evidence)
		}
		release()
	})

	t.Run("workload panic is reported after exactly one cleanup", func(t *testing.T) {
		originalApply := tunChaosApply
		t.Cleanup(func() { tunChaosApply = originalApply })
		var setupCalls atomic.Int32
		var cleanupCalls atomic.Int32
		tunChaosApply = func(chaos.Profile) (func() error, error) {
			setupCalls.Add(1)
			return func() error {
				cleanupCalls.Add(1)
				return nil
			}, nil
		}

		rc := runT4WithBudget(context.Background(), "cleanup.panic", time.Second, chaos.Profile{},
			func(context.Context) report.Case { panic("synthetic workload panic") })
		if !strings.Contains(rc.Failure, "runner panic: synthetic workload panic") || rc.InvalidReason != "" {
			t.Fatalf("panic result = %+v", rc)
		}
		if setupCalls.Load() != 1 || cleanupCalls.Load() != 1 {
			t.Fatalf("setup=%d cleanup=%d, want 1 each", setupCalls.Load(), cleanupCalls.Load())
		}
	})

	t.Run("blocking cleanup is bounded and stops the suite", func(t *testing.T) {
		originalApply := tunChaosApply
		t.Cleanup(func() { tunChaosApply = originalApply })
		cleanupStarted := make(chan struct{})
		cleanupDone := make(chan struct{})
		releaseCleanup := make(chan struct{})
		var releaseOnce sync.Once
		release := func() { releaseOnce.Do(func() { close(releaseCleanup) }) }
		t.Cleanup(func() {
			release()
			waitTUNCleanupSignal(t, cleanupDone, "blocking cleanup exit")
		})
		var cleanupCalls atomic.Int32
		tunChaosApply = func(chaos.Profile) (func() error, error) {
			return func() error {
				defer close(cleanupDone)
				if cleanupCalls.Add(1) == 1 {
					close(cleanupStarted)
				}
				<-releaseCleanup
				return nil
			}, nil
		}

		def := cleanupTUNCase("cleanup.blocked", time.Second, func(ctx context.Context) report.Case {
			return runT4WithBudget(ctx, "cleanup.blocked", time.Second, chaos.Profile{}, func(context.Context) report.Case {
				return report.Case{}
			})
		})
		started := time.Now()
		outcome := runManifestCaseOutcome(context.Background(), "", def)
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("blocking cleanup was not bounded: %s", elapsed)
		}
		waitTUNCleanupSignal(t, cleanupStarted, "blocking cleanup start")
		if !outcome.MustStop || !strings.Contains(outcome.Case.InvalidReason, "chaos cleanup did not return") ||
			outcome.Case.Evidence[tunCleanupStateEvidence] != tunCleanupStateUnjoined {
			t.Fatalf("blocking cleanup outcome = %+v", outcome)
		}
		if cleanupCalls.Load() != 1 {
			t.Fatalf("cleanup calls = %d, want 1", cleanupCalls.Load())
		}
		release()
	})
}

func cleanupTUNCase(id string, budget time.Duration, run func(context.Context) report.Case) caseDef {
	return caseDef{
		spec: manifest.RequiredWithBudget(id, "T7", budget),
		run: func(ctx context.Context, _ string, _ manifest.Spec) report.Case {
			return run(ctx)
		},
	}
}

func waitTUNCleanupSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func waitTUNCleanupOutcome(t *testing.T, result <-chan caseexec.Outcome) caseexec.Outcome {
	t.Helper()
	select {
	case outcome := <-result:
		return outcome
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for bounded tunfull outcome")
		return caseexec.Outcome{}
	}
}
