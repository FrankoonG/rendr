package tier4

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/caseexec"
	"github.com/FrankoonG/rendr/regress/internal/chaos"
	"github.com/FrankoonG/rendr/regress/internal/smoke"
)

func TestTier4CleanupCancellationSafety(t *testing.T) {
	originalJoinTimeout := tier4CaseJoinTimeout
	tier4CaseJoinTimeout = 200 * time.Millisecond
	t.Cleanup(func() { tier4CaseJoinTimeout = originalJoinTimeout })

	t.Run("parent cancellation cleans before non-cooperative workload containment", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		workloadStarted := make(chan struct{})
		workloadDone := make(chan struct{})
		releaseWorkload := make(chan struct{})
		var releaseOnce sync.Once
		release := func() { releaseOnce.Do(func() { close(releaseWorkload) }) }
		t.Cleanup(func() {
			release()
			waitTier4CleanupSignal(t, workloadDone, "non-cooperative workload exit")
		})

		cleanupStarted := make(chan struct{})
		var setupCalls atomic.Int32
		var cleanupCalls atomic.Int32
		returned := make(chan caseexec.Outcome, 1)
		go func() {
			returned <- runCaseWithChaosOutcomeInterval(ctx, "cleanup.cancel", 2*time.Second, chaos.Profile{},
				func(context.Context) smoke.Result {
					close(workloadStarted)
					defer close(workloadDone)
					<-releaseWorkload
					return smoke.Result{}
				},
				func(chaos.Profile) (chaos.Fixture, error) {
					setupCalls.Add(1)
					return &tier4CleanupFixture{cleanup: func() error {
						if cleanupCalls.Add(1) == 1 {
							close(cleanupStarted)
						}
						return nil
					}}, nil
				}, time.Hour)
		}()

		waitTier4CleanupSignal(t, workloadStarted, "workload start")
		cancel()
		waitTier4CleanupSignal(t, cleanupStarted, "cleanup start")
		outcome := waitTier4CleanupOutcome(t, returned)
		if !outcome.MustStop || !strings.Contains(outcome.Case.InvalidReason, "Go cannot terminate") {
			t.Fatalf("non-cooperative outcome = %+v", outcome)
		}
		if setupCalls.Load() != 1 || cleanupCalls.Load() != 1 || outcome.Case.Evidence[chaosCleanupStateEvidence] != chaosCleanupStateComplete {
			t.Fatalf("setup=%d cleanup=%d evidence=%v", setupCalls.Load(), cleanupCalls.Load(), outcome.Case.Evidence)
		}
		release()
	})

	t.Run("non-cooperative monitor cannot hold cleanup hostage", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		verifyStarted := make(chan struct{})
		verifyDone := make(chan struct{})
		releaseVerify := make(chan struct{})
		var releaseOnce sync.Once
		release := func() { releaseOnce.Do(func() { close(releaseVerify) }) }
		t.Cleanup(func() {
			release()
			waitTier4CleanupSignal(t, verifyDone, "monitor verification exit")
		})

		cleanupStarted := make(chan struct{})
		var verifyCalls atomic.Int32
		var cleanupCalls atomic.Int32
		fixture := &tier4CleanupFixture{
			verify: func() error {
				if verifyCalls.Add(1) == 1 {
					close(verifyStarted)
					defer close(verifyDone)
					<-releaseVerify
				}
				return nil
			},
			cleanup: func() error {
				if cleanupCalls.Add(1) == 1 {
					close(cleanupStarted)
				}
				return nil
			},
		}
		returned := make(chan caseexec.Outcome, 1)
		go func() {
			returned <- runCaseWithChaosOutcomeInterval(ctx, "cleanup.monitor", 2*time.Second, chaos.Profile{},
				func(ctx context.Context) smoke.Result {
					<-ctx.Done()
					return smoke.Result{}
				},
				func(chaos.Profile) (chaos.Fixture, error) { return fixture, nil }, time.Millisecond)
		}()

		waitTier4CleanupSignal(t, verifyStarted, "monitor verification start")
		cancel()
		waitTier4CleanupSignal(t, cleanupStarted, "cleanup start")
		outcome := waitTier4CleanupOutcome(t, returned)
		if !outcome.MustStop || !strings.Contains(outcome.Case.InvalidReason, "chaos monitor did not return") {
			t.Fatalf("non-cooperative monitor outcome = %+v", outcome)
		}
		if cleanupCalls.Load() != 1 {
			t.Fatalf("cleanup calls = %d, want 1", cleanupCalls.Load())
		}
		release()
	})

	t.Run("workload panic is reported after exactly one cleanup", func(t *testing.T) {
		var setupCalls atomic.Int32
		var cleanupCalls atomic.Int32
		outcome := runCaseWithChaosOutcomeInterval(context.Background(), "cleanup.panic", time.Second, chaos.Profile{},
			func(context.Context) smoke.Result { panic("synthetic workload panic") },
			func(chaos.Profile) (chaos.Fixture, error) {
				setupCalls.Add(1)
				return &tier4CleanupFixture{cleanup: func() error {
					cleanupCalls.Add(1)
					return nil
				}}, nil
			}, time.Hour)
		if outcome.MustStop || !strings.Contains(outcome.Case.Failure, "runner panic: synthetic workload panic") {
			t.Fatalf("panic outcome = %+v", outcome)
		}
		if setupCalls.Load() != 1 || cleanupCalls.Load() != 1 {
			t.Fatalf("setup=%d cleanup=%d, want 1 each", setupCalls.Load(), cleanupCalls.Load())
		}
	})

	t.Run("blocking cleanup is bounded and stops the tier", func(t *testing.T) {
		cleanupStarted := make(chan struct{})
		cleanupDone := make(chan struct{})
		releaseCleanup := make(chan struct{})
		var releaseOnce sync.Once
		release := func() { releaseOnce.Do(func() { close(releaseCleanup) }) }
		t.Cleanup(func() {
			release()
			waitTier4CleanupSignal(t, cleanupDone, "blocking cleanup exit")
		})
		var cleanupCalls atomic.Int32
		started := time.Now()
		outcome := runCaseWithChaosOutcomeInterval(context.Background(), "cleanup.blocked", time.Second, chaos.Profile{},
			func(context.Context) smoke.Result { return smoke.Result{} },
			func(chaos.Profile) (chaos.Fixture, error) {
				return &tier4CleanupFixture{cleanup: func() error {
					defer close(cleanupDone)
					if cleanupCalls.Add(1) == 1 {
						close(cleanupStarted)
					}
					<-releaseCleanup
					return nil
				}}, nil
			}, time.Hour)
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("blocking cleanup was not bounded: %s", elapsed)
		}
		waitTier4CleanupSignal(t, cleanupStarted, "blocking cleanup start")
		if !outcome.MustStop || !strings.Contains(outcome.Case.InvalidReason, "chaos cleanup did not return") ||
			outcome.Case.Evidence[chaosCleanupStateEvidence] != chaosCleanupStateUnjoined {
			t.Fatalf("blocking cleanup outcome = %+v", outcome)
		}
		if cleanupCalls.Load() != 1 {
			t.Fatalf("cleanup calls = %d, want 1", cleanupCalls.Load())
		}
		release()
	})
}

type tier4CleanupFixture struct {
	verify  func() error
	cleanup func() error
}

func (*tier4CleanupFixture) Changes() <-chan error { return nil }

func (f *tier4CleanupFixture) Verify() error {
	if f.verify == nil {
		return nil
	}
	return f.verify()
}

func (f *tier4CleanupFixture) Cleanup() error {
	if f.cleanup == nil {
		return nil
	}
	return f.cleanup()
}

func waitTier4CleanupSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func waitTier4CleanupOutcome(t *testing.T, result <-chan caseexec.Outcome) caseexec.Outcome {
	t.Helper()
	select {
	case outcome := <-result:
		return outcome
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for bounded tier4 outcome")
		return caseexec.Outcome{}
	}
}
