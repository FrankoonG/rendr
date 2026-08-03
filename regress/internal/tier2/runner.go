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
	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/report"
	"github.com/FrankoonG/rendr/regress/internal/smoke"
)

// Options filters the tier2 smoke cases.
type Options struct {
	Case     string
	FromCase string
}

type caseDef struct {
	spec       manifest.Spec
	onlyOn     string
	skipReason string
	run        func(context.Context) smoke.Result
}

var caseDefs = []caseDef{
	{spec: manifest.Required("G1-smoke", "T2"), run: func(ctx context.Context) smoke.Result {
		return smoke.RunG1(ctx, smoke.G1Opts{})
	}},
	{spec: manifest.Required("G1-mixed-tcp-quic-smoke", "T2"), run: func(ctx context.Context) smoke.Result {
		return smoke.RunG1(ctx, smoke.G1Opts{
			Size:       8 << 20,
			Migrations: 1,
			Transports: []string{
				"tcp",
				"quic",
			},
		})
	}},
	{spec: manifest.Required("G2-smoke", "T2"), run: func(ctx context.Context) smoke.Result {
		return smoke.RunG2(ctx, smoke.G2Opts{})
	}},
	// Matrix coverage at smoke scale: race + bond modes on TCP.
	// Race mode dispatches each frame to every path, so migrations
	// are semantically moot — set Migrations=0 to skip the
	// "migrations actually fired" assertion. Bond keeps the
	// default migration cadence to exercise active-path swap.
	{spec: manifest.Required("G2-race-tcp-smoke", "T2"), run: func(ctx context.Context) smoke.Result {
		return smoke.RunG2(ctx, smoke.G2Opts{
			Mode:       rendr.ModeRace,
			Migrations: 0,
		})
	}},
	{spec: manifest.Required("G2-bond-tcp-smoke", "T2"), run: func(ctx context.Context) smoke.Result {
		return smoke.RunG2(ctx, smoke.G2Opts{Mode: rendr.ModeBond})
	}},
	{
		spec:       manifest.Required("G3-smoke", "T2"),
		onlyOn:     "linux",
		skipReason: "Linux only (sysctl net.core.rmem_max=8MiB for 30k pps QUIC DATAGRAM)",
		run: func(ctx context.Context) smoke.Result {
			return smoke.RunG3(ctx, smoke.G3Opts{})
		},
	},
	{spec: manifest.Required("G4", "T2"), run: func(ctx context.Context) smoke.Result {
		return smoke.RunG4(ctx, smoke.G4Opts{})
	}},
	{spec: manifest.Required("G5", "T2"), run: func(ctx context.Context) smoke.Result {
		return smoke.RunG5(ctx, smoke.G5Opts{})
	}},
	{spec: manifest.Required("M11-udp-relay-smoke", "T2"), run: func(ctx context.Context) smoke.Result {
		return smoke.RunUDPRelay(ctx, smoke.UDPRelayOpts{})
	}},
	{spec: manifest.Required("M11-udp-relay-porthop-smoke", "T2"), run: func(ctx context.Context) smoke.Result {
		return smoke.RunUDPRelayPortHop(ctx, smoke.UDPRelayOpts{
			Packets:    128,
			Paths:      2,
			Migrations: 2,
			PortHops:   3,
		})
	}},
}

// Specs returns the ordered T2 case manifest.
func Specs() []manifest.Spec {
	specs := make([]manifest.Spec, len(caseDefs))
	for i, def := range caseDefs {
		specs[i] = def.spec
	}
	return specs
}

func selectCaseDefs(opts Options) ([]caseDef, error) {
	selected, err := manifest.Select(Specs(), opts.Case, opts.FromCase)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]caseDef, len(caseDefs))
	for _, def := range caseDefs {
		byID[def.spec.ID] = def
	}
	defs := make([]caseDef, 0, len(selected))
	for _, spec := range selected {
		defs = append(defs, byID[spec.ID])
	}
	return defs, nil
}

// Run executes all T2 cases and records them on suite.
func Run(ctx context.Context, suite *report.Suite, rendrRoot string) {
	RunWithOptions(ctx, suite, rendrRoot, Options{})
}

// RunWithOptions executes the selected T2 cases and records them on suite.
func RunWithOptions(ctx context.Context, suite *report.Suite, _ string, opts Options) {
	defs, err := selectCaseDefs(opts)
	if err != nil {
		suite.Add(report.Case{Name: "T2-case-filter", Tier: "T2", Failure: err.Error()})
		return
	}
	for _, def := range defs {
		if def.onlyOn != "" && def.onlyOn != runtime.GOOS {
			suite.Add(report.Case{Name: def.spec.ID, Tier: "T2", SkipReason: def.skipReason})
			continue
		}
		addRun(suite, def.spec.ID, "T2", func() smoke.Result { return def.run(ctx) })
	}
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
