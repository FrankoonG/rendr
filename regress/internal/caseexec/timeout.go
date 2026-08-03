// Package caseexec enforces per-case cancellation and teardown isolation.
package caseexec

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/report"
)

// DefaultJoinTimeout bounds cleanup after a case budget or parent context
// expires. It leaves room for command-backed cases' bounded process wait plus
// fixture cleanup. The case budget itself is unchanged; this is teardown-only
// grace.
const DefaultJoinTimeout = 10 * time.Second

const (
	evidenceBudget       = "timeout_budget"
	evidenceCause        = "timeout_cause"
	evidenceCleanup      = "timeout_cleanup"
	evidenceJoinLimit    = "timeout_join_limit"
	evidenceProcessLimit = "timeout_process_limit"
)

// Config identifies one bounded case execution.
type Config struct {
	Name        string
	Tier        string
	Budget      time.Duration
	JoinTimeout time.Duration
}

// Outcome contains the report row and whether continuing in this process is
// unsafe. MustStop is set when cancellation did not stop the case entrypoint.
type Outcome struct {
	Case     report.Case
	MustStop bool
}

type completion struct {
	caseResult report.Case
	finishedAt time.Time
}

// Run starts fn with the configured budget. On cancellation it waits for fn to
// return before reporting, up to JoinTimeout. A returned fn is responsible for
// joining its own child goroutines and processes before it returns.
//
// Go cannot terminate a noncooperative goroutine. If the join limit expires,
// Run marks the case INVALID and sets MustStop. Callers must stop the tier and
// let the regress process exit before starting more cases; process isolation is
// the only hard containment boundary for detached or noncooperative work.
func Run(ctx context.Context, cfg Config, fn func(context.Context) report.Case) Outcome {
	start := time.Now()
	if ctx == nil {
		return invalidConfig(cfg, start, "case context is nil")
	}
	if cfg.Budget <= 0 {
		return invalidConfig(cfg, start, "case has no bounded execution budget")
	}
	if fn == nil {
		return invalidConfig(cfg, start, "case function is nil")
	}
	joinTimeout := cfg.JoinTimeout
	if joinTimeout == 0 {
		joinTimeout = DefaultJoinTimeout
	}
	if joinTimeout < 0 {
		return invalidConfig(cfg, start, "case cleanup join timeout is negative")
	}
	if err := ctx.Err(); err != nil {
		return Outcome{Case: report.Case{
			Name:     cfg.Name,
			Tier:     cfg.Tier,
			Duration: time.Since(start),
			Failure:  fmt.Sprintf("case canceled before %s execution: %v", cfg.Tier, err),
		}}
	}

	cctx, cancel := context.WithTimeout(ctx, cfg.Budget)
	deadline, _ := cctx.Deadline()
	completed := make(chan completion, 1)
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		completed <- completion{caseResult: fn(cctx), finishedAt: time.Now()}
	}()

	select {
	case finished := <-completed:
		stopErr := completionStopError(cctx.Err(), deadline, finished.finishedAt)
		cancel()
		<-workerDone
		if stopErr != nil {
			return joinedTimeout(cfg, start, joinTimeout, stopErr, finished.caseResult)
		}
		rc := finished.caseResult
		if rc.Duration == 0 {
			rc.Duration = time.Since(start)
		}
		return Outcome{Case: rc}

	case <-cctx.Done():
		stopErr := cctx.Err()
		cancel()
		if waitFor(workerDone, joinTimeout) {
			finished := <-completed
			return joinedTimeout(cfg, start, joinTimeout, stopErr, finished.caseResult)
		}
		return unjoinedTimeout(cfg, start, joinTimeout, stopErr)
	}
}

func completionStopError(contextErr error, deadline, finishedAt time.Time) error {
	if !deadline.IsZero() && finishedAt.After(deadline) {
		return context.DeadlineExceeded
	}
	// A result that completed before the deadline remains valid even if the
	// scheduler didn't receive it until after the deadline timer fired.
	if errors.Is(contextErr, context.DeadlineExceeded) {
		return nil
	}
	return contextErr
}

func invalidConfig(cfg Config, start time.Time, reason string) Outcome {
	return Outcome{Case: report.Case{
		Name:     cfg.Name,
		Tier:     cfg.Tier,
		Duration: time.Since(start),
		Failure:  reason,
	}}
}

func joinedTimeout(cfg Config, start time.Time, joinTimeout time.Duration, stopErr error, late report.Case) Outcome {
	evidence := timeoutEvidence(late.Evidence, cfg.Budget, joinTimeout, stopErr, "joined")
	return Outcome{Case: report.Case{
		Name:     cfg.Name,
		Tier:     cfg.Tier,
		Duration: time.Since(start),
		Failure:  stopFailure(cfg.Tier, stopErr),
		Evidence: evidence,
	}}
}

func unjoinedTimeout(cfg Config, start time.Time, joinTimeout time.Duration, stopErr error) Outcome {
	const processLimit = "Go cannot terminate the running case goroutine; the regress process must exit before any later case can run"
	evidence := timeoutEvidence(nil, cfg.Budget, joinTimeout, stopErr, "unjoined")
	evidence[evidenceProcessLimit] = processLimit
	return Outcome{
		Case: report.Case{
			Name:          cfg.Name,
			Tier:          cfg.Tier,
			Duration:      time.Since(start),
			InvalidReason: fmt.Sprintf("%s; canceled workload did not return within cleanup join limit %s. Tier stopped. %s", stopFailure(cfg.Tier, stopErr), joinTimeout, processLimit),
			Evidence:      evidence,
		},
		MustStop: true,
	}
}

func stopFailure(tier string, err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Sprintf("case exceeded %s budget: %v", tier, err)
	}
	return fmt.Sprintf("case canceled during %s execution: %v", tier, err)
}

func timeoutEvidence(existing map[string]string, budget, joinTimeout time.Duration, stopErr error, cleanup string) map[string]string {
	evidence := make(map[string]string, len(existing)+4)
	for key, value := range existing {
		evidence[key] = value
	}
	evidence[evidenceBudget] = budget.String()
	evidence[evidenceCause] = stopErr.Error()
	evidence[evidenceCleanup] = cleanup
	evidence[evidenceJoinLimit] = joinTimeout.String()
	return evidence
}

func waitFor(done <-chan struct{}, limit time.Duration) bool {
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}
