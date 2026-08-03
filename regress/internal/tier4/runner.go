// Package tier4 implements the long-run regression tier — the
// release-tag verification path. T4 is opt-in via --tier=4.
package tier4

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/regress/internal/chaos"
	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/report"
	"github.com/FrankoonG/rendr/regress/internal/smoke"
)

// Options filters the long-run matrix for targeted debug runs.
type Options struct {
	Case     string
	FromCase string
}

type caseDef struct {
	spec       manifest.Spec
	profile    chaos.Profile
	run        func(context.Context) smoke.Result
	skipReason func() string
}

var caseDefs = []caseDef{
	{
		spec:    manifest.RequiredWithBudget("G1-T4", "T4", 7*time.Minute),
		profile: chaos.Realistic50M,
		run: func(ctx context.Context) smoke.Result {
			return smoke.RunG1(ctx, smoke.G1Opts{Size: 1 << 30, Migrations: 10, Paths: 2, Transport: "tcp"})
		},
	},
	{
		spec:    manifest.RequiredWithBudget("G1-T4-quic", "T4", 7*time.Minute),
		profile: chaos.Realistic50M,
		run: func(ctx context.Context) smoke.Result {
			return smoke.RunG1(ctx, smoke.G1Opts{Size: 1 << 30, Migrations: 10, Paths: 2, Transport: "quic"})
		},
	},
	{
		spec:    manifest.RequiredWithBudget("G2-T4", "T4", 33*time.Minute),
		profile: chaos.Realistic50M,
		run: func(ctx context.Context) smoke.Result {
			return smoke.RunG2(ctx, smoke.G2Opts{
				Duration:     30 * time.Minute,
				Migrations:   30,
				Paths:        2,
				Transport:    "tcp",
				Mode:         rendr.ModePrime,
				Interval:     100 * time.Millisecond,
				P99CeilingMs: 200,
			})
		},
	},
	{
		spec:    manifest.RequiredWithBudget("G2-T4-race-tcp", "T4", 33*time.Minute),
		profile: chaos.Realistic50M,
		run: func(ctx context.Context) smoke.Result {
			return smoke.RunG2(ctx, smoke.G2Opts{
				Duration:     30 * time.Minute,
				Migrations:   -1,
				Paths:        2,
				Transport:    "tcp",
				Mode:         rendr.ModeRace,
				Interval:     100 * time.Millisecond,
				P99CeilingMs: 200,
			})
		},
	},
	{
		spec:    manifest.RequiredWithBudget("G2-T4-bond-tcp", "T4", 33*time.Minute),
		profile: chaos.Realistic50M,
		run: func(ctx context.Context) smoke.Result {
			return smoke.RunG2(ctx, smoke.G2Opts{
				Duration:     30 * time.Minute,
				Migrations:   30,
				Paths:        2,
				Transport:    "tcp",
				Mode:         rendr.ModeBond,
				Interval:     100 * time.Millisecond,
				P99CeilingMs: 200,
			})
		},
	},
	{
		spec: manifest.RequiredWithBudget("M11-udp-relay-T4", "T4", 5*time.Minute),
		run: func(ctx context.Context) smoke.Result {
			return smoke.RunUDPRelay(ctx, smoke.UDPRelayOpts{Packets: 10_000, Paths: 2, Migrations: 3, Server: true})
		},
	},
	{
		spec: manifest.RequiredWithBudget("M11-udp-relay-porthop-T4", "T4", 5*time.Minute),
		run: func(ctx context.Context) smoke.Result {
			return smoke.RunUDPRelayPortHop(ctx, smoke.UDPRelayOpts{Packets: 10_000, Paths: 2, Migrations: 3, PortHops: 8})
		},
	},
	{
		spec: manifest.RequiredWithBudget("M11-wireguard-relay-T4", "T4", 5*time.Minute),
		run: func(ctx context.Context) smoke.Result {
			return smoke.RunWireGuardRelay(ctx, smoke.WireGuardRelayOpts{Messages: 512, MessageSize: 512, Paths: 2, Migrations: 3})
		},
		skipReason: func() string {
			if runtime.GOOS != "linux" {
				return "Linux only (wireguard-go UDP endpoint smoke is validated on Linux regress hosts)"
			}
			return ""
		},
	},
	{
		spec: manifest.RequiredWithBudget("M11-hysteria2-relay-T4", "T4", 5*time.Minute),
		run: func(ctx context.Context) smoke.Result {
			return smoke.RunHysteriaRelay(ctx, smoke.HysteriaRelayOpts{Paths: 2, Migrations: 3, DataSize: 8 << 20})
		},
		skipReason: func() string {
			if runtime.GOOS != "linux" {
				return "Linux only (Hysteria 2 relay smoke is validated on Linux regress hosts)"
			}
			if !smoke.HysteriaAvailable() {
				return "hysteria binary not found"
			}
			return ""
		},
	},
	{
		spec: manifest.RequiredWithBudget("G3-T4", "T4", 8*time.Minute),
		run: func(ctx context.Context) smoke.Result {
			return smoke.RunG3(ctx, smoke.G3Opts{
				Duration:     5 * time.Minute,
				PPS:          100_000,
				PayloadLen:   1024,
				Migrations:   10,
				Paths:        8,
				P95CeilingMs: 20,
				LossPct:      0,
			})
		},
		skipReason: func() string {
			if runtime.GOOS != "linux" {
				return "Linux only (100k pps QUIC DATAGRAM needs net.core.rmem_max=8MiB)"
			}
			return ""
		},
	},
}

// Specs returns the ordered T4 case manifest.
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

// Run executes T4 cases with their per-case budgets and chaos profiles.
func Run(ctx context.Context, suite *report.Suite, _ string, opts Options) {
	defs, err := selectCaseDefs(opts)
	if err != nil {
		suite.Add(report.Case{
			Name:    "T4-case-filter",
			Tier:    "T4",
			Failure: fmt.Sprintf("T4 case selection failed for case=%q from-case=%q: %v", opts.Case, opts.FromCase, err),
		})
		return
	}
	runSelectedCases(ctx, suite, defs, executeCase)
}

type caseExecutor func(context.Context, caseDef) report.Case

func runSelectedCases(ctx context.Context, suite *report.Suite, defs []caseDef, execute caseExecutor) {
	failedCaseID := ""
	for _, def := range defs {
		if failedCaseID != "" {
			suite.Add(notRunCase(def.spec, failedCaseID))
			continue
		}
		rc := execute(ctx, def)
		suite.Add(rc)
		if mandatoryCaseFailed(def.spec, rc) {
			failedCaseID = def.spec.ID
		}
	}
}

func executeCase(ctx context.Context, def caseDef) report.Case {
	if def.skipReason != nil {
		if reason := def.skipReason(); reason != "" {
			return report.Case{Name: def.spec.ID, Tier: def.spec.Tier, SkipReason: reason}
		}
	}
	return runCase(ctx, def.spec.ID, def.spec.Budget, def.profile, def.run)
}

// runCase enforces the per-case budget via select-on-Done. It returns only
// after chaos cleanup so the selected-case loop can stop before launching any
// later case, even when the smoke goroutine is still unwinding cancellation.
func runCase(ctx context.Context, name string, budget time.Duration, prof chaos.Profile, fn func(context.Context) smoke.Result) report.Case {
	return runCaseWithChaos(ctx, name, budget, prof, fn, chaos.Apply)
}

func runCaseWithChaos(ctx context.Context, name string, budget time.Duration, prof chaos.Profile, fn func(context.Context) smoke.Result, apply func(chaos.Profile) (func() error, error)) report.Case {
	fmt.Printf("  > T4/%s (budget %s, chaos %s) — start\n", name, budget, profDesc(prof))
	rc := report.Case{Name: name, Tier: "T4"}
	cleanup, err := apply(prof)
	if err != nil {
		rc.Failure = "chaos.Apply failed: " + err.Error()
		fmt.Printf("  > T4/%s — FAIL: %s\n", name, rc.Failure)
		return rc
	}
	cctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	start := time.Now()
	done := make(chan smoke.Result, 1)
	go func() {
		done <- fn(cctx)
	}()
	select {
	case r := <-done:
		rc.Duration = r.Duration
		rc.Failure = r.Failure
		rc.InvalidReason = r.InvalidReason
		rc.Evidence = evidenceFromDetail(r.Detail)
		if rc.Duration == 0 {
			rc.Duration = time.Since(start)
		}
	case <-cctx.Done():
		rc.Duration = time.Since(start)
		rc.Failure = "case exceeded T4 budget (" + budget.String() + "): " + cctx.Err().Error()
	}
	applyCleanupResult(&rc, cleanup)
	if rc.Failure != "" {
		fmt.Printf("  > T4/%s (took %s) — FAIL: %s\n", name, rc.Duration, rc.Failure)
	} else if rc.InvalidReason != "" {
		fmt.Printf("  > T4/%s (took %s) — INVALID: %s\n", name, rc.Duration, rc.InvalidReason)
	} else {
		fmt.Printf("  > T4/%s (took %s) — OK\n", name, rc.Duration)
	}
	return rc
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

func evidenceFromDetail(detail map[string]any) map[string]string {
	if len(detail) == 0 {
		return nil
	}
	evidence := make(map[string]string, len(detail))
	for key, value := range detail {
		evidence[key] = fmt.Sprint(value)
	}
	return evidence
}

func applyCleanupResult(rc *report.Case, cleanup func() error) {
	if rc == nil || cleanup == nil {
		return
	}
	if err := cleanup(); err != nil {
		message := "chaos cleanup failed: " + err.Error()
		if rc.Failure != "" {
			rc.Failure += "; " + message
			return
		}
		rc.InvalidReason = message
	}
}

func profDesc(p chaos.Profile) string {
	if p.Bandwidth == 0 && p.LossPct == 0 && p.Delay == 0 {
		return "clean"
	}
	return fmt.Sprintf("%dMbit/loss%.1f%%/delay%dms", p.Bandwidth/1_000_000, p.LossPct, p.Delay.Milliseconds())
}
