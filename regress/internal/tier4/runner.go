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

// Run executes all T4 cases and records them on suite.
func Run(ctx context.Context, suite *report.Suite, _ string) {
	addRun(suite, "G1-T4", func() smoke.Result {
		return smoke.RunG1(ctx, smoke.G1Opts{
			Size:       1 << 30, // 1 GiB
			Migrations: 10,
			Paths:      2,
			Transport:  "tcp",
		})
	})
	addRun(suite, "G1-T4-quic", func() smoke.Result {
		return smoke.RunG1(ctx, smoke.G1Opts{
			Size:       1 << 30,
			Migrations: 10,
			Paths:      2,
			Transport:  "quic",
		})
	})

	addRun(suite, "G2-T4", func() smoke.Result {
		return smoke.RunG2(ctx, smoke.G2Opts{
			Duration:     30 * time.Minute,
			Migrations:   30,
			Paths:        2,
			Transport:    "tcp",
			Interval:     100 * time.Millisecond,
			P99CeilingMs: 50, // T4 tightens vs smoke's 200ms
		})
	})

	if runtime.GOOS == "linux" {
		addRun(suite, "G3-T4", func() smoke.Result {
			return smoke.RunG3(ctx, smoke.G3Opts{
				Duration:     30 * time.Second,
				PPS:          100_000,
				PayloadLen:   1024,
				Migrations:   10,
				Paths:        4,
				P95CeilingMs: 20, // tighter than smoke's 50ms
				LossPct:      0,  // T4 strict; smoke tolerates 0.5%
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

func addRun(suite *report.Suite, name string, fn func() smoke.Result) {
	r := fn()
	suite.Add(report.Case{
		Name:     name,
		Tier:     "T4",
		Duration: r.Duration,
		Failure:  r.Failure,
	})
}
