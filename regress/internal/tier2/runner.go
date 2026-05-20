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

	"github.com/FrankoonG/rendr"
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
	// Matrix coverage at smoke scale: race + bond modes on TCP.
	// Race mode dispatches each frame to every path, so migrations
	// are semantically moot — set Migrations=0 to skip the
	// "migrations actually fired" assertion. Bond keeps the
	// default migration cadence to exercise active-path swap.
	addRun(suite, "G2-race-tcp-smoke", "T2", func() smoke.Result {
		return smoke.RunG2(ctx, smoke.G2Opts{
			Mode:       rendr.ModeRace,
			Migrations: 0,
		})
	})
	addRun(suite, "G2-bond-tcp-smoke", "T2", func() smoke.Result {
		return smoke.RunG2(ctx, smoke.G2Opts{Mode: rendr.ModeBond})
	})

	if runtime.GOOS == "linux" {
		addRun(suite, "G3-smoke", "T2", func() smoke.Result {
			return smoke.RunG3(ctx, smoke.G3Opts{})
		})
	} else {
		suite.Add(report.Case{
			Name:       "G3-smoke",
			Tier:       "T2",
			SkipReason: "Linux only (sysctl net.core.rmem_max=8MiB for 30k pps QUIC DATAGRAM)",
		})
	}

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
