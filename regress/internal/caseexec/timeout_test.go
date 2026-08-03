package caseexec

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/report"
)

func TestRunTimeoutCancelsAndJoinsCooperativeCleanup(t *testing.T) {
	cleanupStarted := make(chan struct{})
	allowCleanup := make(chan struct{})
	returned := make(chan Outcome, 1)
	var cleanupFinished atomic.Bool
	var cleanupOnce sync.Once
	releaseCleanup := func() { cleanupOnce.Do(func() { close(allowCleanup) }) }
	t.Cleanup(releaseCleanup)

	go func() {
		returned <- Run(context.Background(), Config{
			Name:        "cooperative",
			Tier:        "TX",
			Budget:      20 * time.Millisecond,
			JoinTimeout: time.Second,
		}, func(ctx context.Context) report.Case {
			<-ctx.Done()
			close(cleanupStarted)
			<-allowCleanup
			cleanupFinished.Store(true)
			return report.Case{Evidence: map[string]string{"worker_cleanup": "complete"}}
		})
	}()

	select {
	case <-cleanupStarted:
	case <-time.After(time.Second):
		t.Fatal("case did not observe cancellation")
	}
	select {
	case outcome := <-returned:
		t.Fatalf("Run returned before cooperative cleanup was joined: %+v", outcome)
	default:
	}
	releaseCleanup()

	var outcome Outcome
	select {
	case outcome = <-returned:
	case <-time.After(time.Second):
		t.Fatal("Run did not return after cleanup completed")
	}
	if outcome.MustStop {
		t.Fatal("cooperative timeout requested a hard tier stop")
	}
	if !cleanupFinished.Load() {
		t.Fatal("cleanup was not complete when Run returned")
	}
	if !strings.Contains(outcome.Case.Failure, "case exceeded TX budget") || outcome.Case.InvalidReason != "" {
		t.Fatalf("timeout result = %+v, want joined budget failure", outcome.Case)
	}
	if got := outcome.Case.Evidence[evidenceCleanup]; got != "joined" {
		t.Fatalf("timeout cleanup evidence = %q, want joined", got)
	}
	if got := outcome.Case.Evidence["worker_cleanup"]; got != "complete" {
		t.Fatalf("worker evidence = %q, want complete", got)
	}

	t.Run("completion before deadline survives late observation", func(t *testing.T) {
		deadline := time.Now()
		if err := completionStopError(context.DeadlineExceeded, deadline, deadline.Add(-time.Nanosecond)); err != nil {
			t.Fatalf("completion before deadline = %v, want nil", err)
		}
		if err := completionStopError(nil, deadline, deadline.Add(time.Nanosecond)); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("completion after deadline = %v, want deadline exceeded", err)
		}
	})
}

func TestRunTimeoutMarksNoncooperativeWorkUnsafeToContinue(t *testing.T) {
	release := make(chan struct{})
	workerDone := make(chan struct{})
	var releaseOnce sync.Once
	releaseWorker := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseWorker)
	start := time.Now()
	outcome := Run(context.Background(), Config{
		Name:        "noncooperative",
		Tier:        "TX",
		Budget:      20 * time.Millisecond,
		JoinTimeout: 30 * time.Millisecond,
	}, func(context.Context) report.Case {
		defer close(workerDone)
		<-release
		return report.Case{}
	})

	if !outcome.MustStop {
		t.Fatal("noncooperative timeout did not request a hard tier stop")
	}
	if outcome.Case.Failure != "" || !strings.Contains(outcome.Case.InvalidReason, "Go cannot terminate") {
		t.Fatalf("noncooperative result = %+v, want explicit process-level INVALID", outcome.Case)
	}
	if got := outcome.Case.Evidence[evidenceCleanup]; got != "unjoined" {
		t.Fatalf("timeout cleanup evidence = %q, want unjoined", got)
	}
	if elapsed := time.Since(start); elapsed < 45*time.Millisecond || elapsed > time.Second {
		t.Fatalf("bounded timeout elapsed = %s, want budget plus join grace", elapsed)
	}

	releaseWorker()
	select {
	case <-workerDone:
	case <-time.After(time.Second):
		t.Fatal("released worker did not exit")
	}
}

func TestRunDoesNotStartWithCanceledParent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	outcome := Run(ctx, Config{Name: "canceled", Tier: "TX", Budget: time.Second}, func(context.Context) report.Case {
		called = true
		return report.Case{}
	})
	if called {
		t.Fatal("case started with an already canceled parent")
	}
	if outcome.Case.Failure == "" || outcome.MustStop {
		t.Fatalf("canceled-parent result = %+v", outcome)
	}
}
