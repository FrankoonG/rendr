// Package tier2 runs phase-1 rendr-self-check G-mini cases. T2 is
// the rendr engine's own G1-G5 contract at smoke scale: small enough
// to fit in <8 min, large enough to catch engine-layer regressions
// before phase 2 burns CI time.
//
// Status:
//   - G1-smoke: cross-platform, implemented.
//   - G2-smoke: cross-platform, implemented.
//   - G3-smoke: Linux-only (needs net.core.rmem_max=8MiB for QUIC
//     DATAGRAM at 30k pps), pending.
//   - G4 / G5: Linux-only (iptables -j DROP for forced path death),
//     pending.
//
// Linux-only cases SKIP on non-Linux runners with a clear reason so
// the gap is visible in reports.
package tier2

import (
	"context"
	"runtime"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/report"
	"github.com/FrankoonG/rendr/regress/internal/smoke"
)

// Run executes all T2 cases and records them on suite.
func Run(ctx context.Context, suite *report.Suite, _ string) {
	addRun(suite, "G1-smoke", "T2", func() smoke.Result {
		return smoke.RunG1(ctx, smoke.G1Opts{})
	})
	addRun(suite, "G2-smoke", "T2", func() smoke.Result {
		return smoke.RunG2(ctx, smoke.G2Opts{})
	})

	linuxPending := []string{"G3-smoke", "G4", "G5"}
	for _, name := range linuxPending {
		c := report.Case{Name: name, Tier: "T2"}
		if runtime.GOOS != "linux" {
			c.SkipReason = "Linux only (iptables / sysctl rmem_max)"
		} else {
			c.SkipReason = "T2 implementation pending (regression-suite §14 step 3)"
		}
		suite.Add(c)
	}
}

func addRun(suite *report.Suite, name, tier string, fn func() smoke.Result) {
	start := time.Now()
	r := fn()
	suite.Add(report.Case{
		Name:     name,
		Tier:     tier,
		Duration: r.Duration,
		Failure:  r.Failure,
	})
	_ = start // start is captured inside fn via smoke; kept for symmetry if fn ignores time
}
