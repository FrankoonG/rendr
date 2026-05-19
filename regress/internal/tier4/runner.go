// Package tier4 implements the long-run regression tier — the
// release-tag verification path. T4 re-uses the smoke G1/G2/G3
// implementations with the contract-literal values from
// docs/success-criteria.md §G1-§G3:
//
//   - G1-T4: 1 GiB stream, 10 forced migrations, SHA-256 verify
//   - G2-T4: 30-min sustained echo with periodic migrations
//   - G3-T4: 30 s × 100 000 pps QUIC DATAGRAM under bond, 10 migrations
//
// Smoke (T2) provides headline coverage; T4 proves the same contracts
// at production scale. T4 is opt-in via `--tier=4` — the default
// regress run does not pay the ~35-minute cost.
//
// All cases are Linux-only (G3 needs sysctl net.core.rmem_max=8MiB
// at host level; the regress driver already refuses non-Linux at
// boot unless --allow-non-linux is passed).
package tier4

import (
	"context"
	"runtime"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/report"
	"github.com/FrankoonG/rendr/regress/internal/smoke"
)

// Run executes T4 cases with per-case context budgets. Without
// the per-case timeout, a deadlocked engine path (e.g. writer
// blocked on a full buffer mid-migration) would hang the whole T4
// run indefinitely — observed on commit 13b5464.
func Run(ctx context.Context, suite *report.Suite, _ string) {
	runCase(ctx, suite, "G1-T4", 5*time.Minute, func(c context.Context) smoke.Result {
		return smoke.RunG1(c, smoke.G1Opts{
			Size:       1 << 30, // 1 GiB
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

// runCase wraps a smoke.Run* with a per-case context.WithTimeout and
// promotes a budget-exceeded ctx to a regress failure (the smoke fn
// itself only sees Err() through reads/writes; without the wrap, a
// deadlock would return Result{Failure: ""} and look like a pass).
func runCase(ctx context.Context, suite *report.Suite, name string, budget time.Duration, fn func(context.Context) smoke.Result) {
	cctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	start := time.Now()
	r := fn(cctx)
	rc := report.Case{
		Name:     name,
		Tier:     "T4",
		Duration: r.Duration,
		Failure:  r.Failure,
	}
	if rc.Duration == 0 {
		rc.Duration = time.Since(start)
	}
	if rc.Failure == "" && cctx.Err() != nil {
		rc.Failure = "case exceeded T4 budget (" + budget.String() + "): " + cctx.Err().Error()
	}
	suite.Add(rc)
}
