// Package tier4 implements the long-run regression tier — the
// release-tag verification path. T4 is opt-in via --tier=4.
package tier4

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/report"
	"github.com/FrankoonG/rendr/regress/internal/smoke"
)

// Run executes T4 cases with per-case budgets enforced by select.
func Run(ctx context.Context, suite *report.Suite, _ string) {
	runCase(ctx, suite, "G1-T4", 5*time.Minute, func(c context.Context) smoke.Result {
		return smoke.RunG1(c, smoke.G1Opts{
			Size:       1 << 30,
			Migrations: 10,
			Paths:      2,
			Transport:  "tcp",
		})
	})
	runCase(ctx, suite, "G1-T4-quic", 5*time.Minute, func(c context.Context) smoke.Result {
		return smoke.RunG1(c, smoke.G1Opts{
			Size:       1 << 30,
			Migrations: 10,
			Paths:      2,
			Transport:  "quic",
		})
	})

	runCase(ctx, suite, "G2-T4", 33*time.Minute, func(c context.Context) smoke.Result {
		return smoke.RunG2(c, smoke.G2Opts{
			Duration:     30 * time.Minute,
			Migrations:   30,
			Paths:        2,
			Transport:    "tcp",
			Interval:     100 * time.Millisecond,
			P99CeilingMs: 50,
		})
	})

	if runtime.GOOS == "linux" {
		runCase(ctx, suite, "G3-T4", 3*time.Minute, func(c context.Context) smoke.Result {
			return smoke.RunG3(c, smoke.G3Opts{
				Duration:     30 * time.Second,
				PPS:          100_000,
				PayloadLen:   1024,
				Migrations:   10,
				Paths:        4,
				P95CeilingMs: 20,
				LossPct:      0,
			})
		})
	} else {
		suite.Add(report.Case{
			Name:       "G3-T4",
			Tier:       "T4",
			SkipReason: "Linux only (100k pps QUIC DATAGRAM needs net.core.rmem_max=8MiB)",
		})
	}
}

// runCase enforces the per-case budget via select-on-Done. Smoke.RunG1
// /G2/G3 only honor ctx at Accept() and path-attach; the hot loop
// blocks on rendr.Conn which won't unblock from ctx if the engine
// deadlocks. select guarantees forward progress: smoke goroutine
// leaks but container teardown bounds the leak. Also prints
// per-case start/end so a stuck case is visible in real-time stdout.
func runCase(ctx context.Context, suite *report.Suite, name string, budget time.Duration, fn func(context.Context) smoke.Result) {
	fmt.Printf("  > T4/%s (budget %s) — start\n", name, budget)
	cctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	start := time.Now()
	done := make(chan smoke.Result, 1)
	go func() {
		done <- fn(cctx)
	}()
	rc := report.Case{Name: name, Tier: "T4"}
	select {
	case r := <-done:
		rc.Duration = r.Duration
		rc.Failure = r.Failure
		if rc.Duration == 0 {
			rc.Duration = time.Since(start)
		}
	case <-cctx.Done():
		rc.Duration = time.Since(start)
		rc.Failure = "case exceeded T4 budget (" + budget.String() + "): " + cctx.Err().Error()
	}
	if rc.Failure != "" {
		fmt.Printf("  > T4/%s (took %s) — FAIL: %s\n", name, rc.Duration, rc.Failure)
	} else {
		fmt.Printf("  > T4/%s (took %s) — OK\n", name, rc.Duration)
	}
	suite.Add(rc)
}
