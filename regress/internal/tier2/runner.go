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
	"fmt"
	"runtime"
	"time"

	"github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/regress/internal/caseexec"
	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/report"
	"github.com/FrankoonG/rendr/regress/internal/smoke"
)

const (
	streamSmokeBudget = time.Minute
	g2SmokeBudget     = time.Minute
	g3SmokeBudget     = time.Minute
	g4G5SmokeBudget   = 30 * time.Second
	relaySmokeBudget  = 30 * time.Second

	g1SmokeMigrations     = 3
	g2SmokeMigrations     = 5
	g2RaceSmokeMigrations = -1
	g3SmokeLossPct        = 0.5
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
	{spec: manifest.RequiredWithBudget("G1-smoke", "T2", streamSmokeBudget), run: func(ctx context.Context) smoke.Result {
		return smoke.RunG1(ctx, smoke.G1Opts{Migrations: g1SmokeMigrations})
	}},
	{spec: manifest.RequiredWithBudget("G1-mixed-tcp-quic-smoke", "T2", streamSmokeBudget), run: func(ctx context.Context) smoke.Result {
		return smoke.RunG1(ctx, smoke.G1Opts{
			Size:       8 << 20,
			Migrations: 1,
			Transports: []string{
				"tcp",
				"quic",
			},
		})
	}},
	{spec: manifest.RequiredWithBudget("G2-smoke", "T2", g2SmokeBudget), run: func(ctx context.Context) smoke.Result {
		return smoke.RunG2(ctx, smoke.G2Opts{Migrations: g2SmokeMigrations})
	}},
	// Matrix coverage at smoke scale: race + bond modes on TCP.
	// Race mode dispatches each frame to every path, so migrations
	// are semantically moot — set Migrations=-1 to skip the
	// "migrations actually fired" assertion. Bond keeps the
	// default migration cadence to exercise active-path swap.
	{spec: manifest.RequiredWithBudget("G2-race-tcp-smoke", "T2", g2SmokeBudget), run: func(ctx context.Context) smoke.Result {
		return smoke.RunG2(ctx, smoke.G2Opts{
			Mode:       rendr.ModeRace,
			Migrations: g2RaceSmokeMigrations,
		})
	}},
	{spec: manifest.RequiredWithBudget("G2-bond-tcp-smoke", "T2", g2SmokeBudget), run: func(ctx context.Context) smoke.Result {
		return smoke.RunG2(ctx, smoke.G2Opts{Mode: rendr.ModeBond, Migrations: g2SmokeMigrations})
	}},
	{
		// This preserves the historical CaseID as a QUIC DATAGRAM smoke.
		// It is not RFC 9000 CID/NAT-rebinding Gold evidence; V1-M1 still
		// requires a replacement case with an external CID migration oracle.
		spec:       manifest.RequiredWithBudget("G3-smoke", "T2", g3SmokeBudget),
		onlyOn:     "linux",
		skipReason: "Linux only (sysctl net.core.rmem_max=8MiB for 30k pps QUIC DATAGRAM)",
		run: func(ctx context.Context) smoke.Result {
			// Phase 1 keeps its historical sub-1% smoke budget explicit.
			// A zero value now means strict zero loss and is used by T4.
			return smoke.RunG3(ctx, smoke.G3Opts{LossPct: g3SmokeLossPct})
		},
	},
	{spec: manifest.RequiredWithBudget("G4", "T2", g4G5SmokeBudget), run: func(ctx context.Context) smoke.Result {
		return smoke.RunG4(ctx, smoke.G4Opts{})
	}},
	{spec: manifest.RequiredWithBudget("G5", "T2", g4G5SmokeBudget), run: func(ctx context.Context) smoke.Result {
		return smoke.RunG5(ctx, smoke.G5Opts{})
	}},
	{spec: manifest.RequiredWithBudget("M11-udp-relay-smoke", "T2", relaySmokeBudget), run: func(ctx context.Context) smoke.Result {
		return smoke.RunUDPRelay(ctx, smoke.UDPRelayOpts{})
	}},
	{spec: manifest.RequiredWithBudget("M11-udp-relay-porthop-smoke", "T2", relaySmokeBudget), run: func(ctx context.Context) smoke.Result {
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
		specs[i] = manifest.CloneSpec(def.spec)
	}
	return specs
}

func selectCaseDefs(opts Options) ([]caseDef, error) {
	return selectCaseDefsFrom(caseDefs, opts)
}

func selectCaseDefsFrom(registry []caseDef, opts Options) ([]caseDef, error) {
	specs := make([]manifest.Spec, len(registry))
	for i, def := range registry {
		specs[i] = manifest.CloneSpec(def.spec)
	}
	selected, err := manifest.SelectWithPrerequisites(specs, opts.Case, opts.FromCase)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]caseDef, len(registry))
	for _, def := range registry {
		byID[def.spec.ID] = def
	}
	defs := make([]caseDef, 0, len(selected))
	for _, spec := range selected {
		def := byID[spec.ID]
		def.spec = spec
		defs = append(defs, def)
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
	runSelectedCases(ctx, suite, defs, executeCase)
}

type caseExecutor func(context.Context, caseDef) caseexec.Outcome

func runSelectedCases(ctx context.Context, suite *report.Suite, defs []caseDef, execute caseExecutor) {
	failedCaseID := ""
	for _, def := range defs {
		if failedCaseID != "" {
			suite.Add(notRunCase(def.spec, failedCaseID))
			continue
		}
		outcome := execute(ctx, def)
		rc := outcome.Case
		suite.Add(rc)
		if outcome.MustStop || mandatoryCaseFailed(def.spec, rc) {
			failedCaseID = def.spec.ID
		}
	}
}

func executeCase(ctx context.Context, def caseDef) caseexec.Outcome {
	if def.onlyOn != "" && def.onlyOn != runtime.GOOS {
		return caseexec.Outcome{Case: report.Case{Name: def.spec.ID, Tier: def.spec.Tier, SkipReason: def.skipReason}}
	}
	return runSmokeCase(ctx, def.spec.ID, def.spec.Tier, def.spec.Budget, def.run)
}

func addRun(ctx context.Context, suite *report.Suite, name, tier string, budget time.Duration, fn func(context.Context) smoke.Result) caseexec.Outcome {
	outcome := runSmokeCase(ctx, name, tier, budget, fn)
	suite.Add(outcome.Case)
	return outcome
}

func runSmokeCase(ctx context.Context, name, tier string, budget time.Duration, fn func(context.Context) smoke.Result) caseexec.Outcome {
	return runSmokeCaseWithJoinTimeout(ctx, name, tier, budget, caseexec.DefaultJoinTimeout, fn)
}

func runSmokeCaseWithJoinTimeout(ctx context.Context, name, tier string, budget, joinTimeout time.Duration, fn func(context.Context) smoke.Result) caseexec.Outcome {
	var workload func(context.Context) report.Case
	if fn != nil {
		workload = func(ctx context.Context) report.Case {
			smokeResult := fn(ctx)
			return report.Case{
				Name:          name,
				Tier:          tier,
				Duration:      smokeResult.Duration,
				Failure:       smokeResult.Failure,
				InvalidReason: smokeResult.InvalidReason,
				Evidence:      detailEvidence(smokeResult.Detail),
			}
		}
	}
	return caseexec.Run(ctx, caseexec.Config{
		Name:        name,
		Tier:        tier,
		Budget:      budget,
		JoinTimeout: joinTimeout,
	}, workload)
}

func mandatoryCaseFailed(spec manifest.Spec, rc report.Case) bool {
	return spec.Mandatory && (rc.Failure != "" || rc.InvalidReason != "" || rc.SkipReason != "")
}

func notRunCase(spec manifest.Spec, failedCaseID string) report.Case {
	return report.Case{
		Name:          spec.ID,
		Tier:          spec.Tier,
		InvalidReason: fmt.Sprintf("not run after %s failed", failedCaseID),
	}
}

func detailEvidence(detail map[string]any) map[string]string {
	if len(detail) == 0 {
		return nil
	}
	evidence := make(map[string]string, len(detail))
	for key, value := range detail {
		evidence[key] = fmt.Sprint(value)
	}
	return evidence
}
