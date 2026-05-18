// Package tier2 runs phase-1 rendr-self-check G-mini cases. T2 is
// the rendr engine's own G1-G5 contract at smoke scale: small enough
// to fit in <8 min, large enough to catch engine-layer regressions
// before phase 2 burns CI time.
//
// Status:
//   - G1-smoke / G2-smoke / G4 / G5: cross-platform via the
//     ForceKillPathForTest engine backdoor and AddPath. Implemented.
//   - G3-smoke: Linux-only (QUIC DATAGRAM at 30k pps needs
//     sysctl net.core.rmem_max=8MiB; Windows / macOS UDP loopback
//     does not have a comparable knob). Skipped elsewhere.
package tier2

import (
	"context"
	"runtime"

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

	// G3-smoke: QUIC DATAGRAM 30k pps + ConnID migration. Pending
	// implementation. On Linux the future call site will be
	// smoke.RunG3(...); for now SKIP so phase 1 isn't gated on it.
	g3Skip := "implementation pending (regression-suite §14 step 7 equivalent for smoke; validate on Linux test host)"
	if runtime.GOOS != "linux" {
		g3Skip = "Linux only (sysctl net.core.rmem_max for 30k pps QUIC DATAGRAM) — " + g3Skip
	}
	suite.Add(report.Case{Name: "G3-smoke", Tier: "T2", SkipReason: g3Skip})
	_ = smoke.G3Opts{} // keep the type referenced for the next commit

	addRun(suite, "G4", "T2", func() smoke.Result {
		return smoke.RunG4(ctx, smoke.G4Opts{})
	})
	addRun(suite, "G5", "T2", func() smoke.Result {
		return smoke.RunG5(ctx, smoke.G5Opts{})
	})
}

func addRun(suite *report.Suite, name, tier string, fn func() smoke.Result) {
	r := fn()
	suite.Add(report.Case{
		Name:     name,
		Tier:     tier,
		Duration: r.Duration,
		Failure:  r.Failure,
	})
}
