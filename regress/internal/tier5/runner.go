// Package tier5 implements the TCP fallback / adapter verification tier.
package tier5

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/report"
	"github.com/FrankoonG/rendr/regress/internal/smoke"
	"github.com/FrankoonG/rendr/transport/gvisor"
	"github.com/FrankoonG/rendr/transport/tcprepair"
)

// Options filters the tier5 adapter matrix.
type Options struct {
	Case     string
	FromCase string
}

type caseDef struct {
	spec manifest.Spec
	run  func(context.Context, string) report.Case
}

var caseDefs = []caseDef{
	{
		spec: manifest.RequiredWithBudget("T5.1-tcprepair-privileged", "T5", 3*time.Minute),
		run: func(ctx context.Context, _ string) report.Case {
			const name = "T5.1-tcprepair-privileged"
			if err := tcprepair.Available(); err != nil {
				return report.Case{Name: name, Tier: "T5", Failure: err.Error()}
			}
			r := smoke.RunG1TCPRepairSameTuple(ctx, smoke.G1TCPRepairOpts{Size: 100 << 20, Migrations: 3})
			return report.Case{Name: name, Tier: "T5", Duration: r.Duration, Failure: r.Failure}
		},
	},
	{
		spec: manifest.RequiredWithBudget("T5.2-gvisor-privileged", "T5", 2*time.Minute),
		run: func(ctx context.Context, _ string) report.Case {
			const name = "T5.2-gvisor-privileged"
			if err := gvisor.Available(); err != nil {
				return report.Case{Name: name, Tier: "T5", Failure: err.Error()}
			}
			r := smoke.RunG1(ctx, smoke.G1Opts{Size: 30 << 20, Migrations: 3, Paths: 2, Transport: "gvisor"})
			return report.Case{Name: name, Tier: "T5", Duration: r.Duration, Failure: r.Failure}
		},
	},
	{spec: manifest.RequiredWithBudget("T5.3-tcprepair-unprivileged", "T5", 2*time.Minute), run: probeUnprivileged},
	{spec: manifest.RequiredWithBudget("T5.4-gvisor-unprivileged", "T5", 2*time.Minute), run: probeGVisorUnprivileged},
	{spec: manifest.RequiredWithBudget("T5.5-tcprepair-gvisor-fallback-unprivileged", "T5", 2*time.Minute), run: probeTCPRepairGVisorFallbackUnprivileged},
	{spec: manifest.RequiredWithBudget("T5.6-gvisor-packet-carrier-unprivileged", "T5", 2*time.Minute), run: probeGVisorPacketCarrierUnprivileged},
}

// Specs returns the ordered T5 case manifest.
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

func Run(ctx context.Context, suite *report.Suite, rendrRoot string, opts Options) {
	defs, err := selectCaseDefs(opts)
	if err != nil {
		suite.Add(report.Case{
			Name:    "T5-case-filter",
			Tier:    "T5",
			Failure: fmt.Sprintf("T5 case selection failed for case=%q from-case=%q: %v", opts.Case, opts.FromCase, err),
		})
		return
	}

	for _, def := range defs {
		if runtime.GOOS != "linux" {
			addLinuxOnlySkip(suite, def)
			continue
		}
		def := def
		runCase(ctx, suite, def.spec.ID, def.spec.Budget, func(c context.Context) report.Case {
			return def.run(c, rendrRoot)
		})
	}
}

func addLinuxOnlySkip(suite *report.Suite, def caseDef) {
	suite.Add(report.Case{Name: def.spec.ID, Tier: def.spec.Tier, SkipReason: "Linux only"})
}

func runCase(ctx context.Context, suite *report.Suite, name string, budget time.Duration, fn func(context.Context) report.Case) {
	fmt.Printf("  > T5/%s (budget %s) — start\n", name, budget)
	cctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	start := time.Now()
	done := make(chan report.Case, 1)
	go func() { done <- fn(cctx) }()
	var rc report.Case
	select {
	case rc = <-done:
		if rc.Duration == 0 {
			rc.Duration = time.Since(start)
		}
	case <-cctx.Done():
		rc = report.Case{
			Name:     name,
			Tier:     "T5",
			Duration: time.Since(start),
			Failure:  "case exceeded T5 budget: " + cctx.Err().Error(),
		}
	}
	if rc.Failure != "" {
		fmt.Printf("  > T5/%s (took %s) — FAIL: %s\n", name, rc.Duration, rc.Failure)
	} else if rc.SkipReason != "" {
		fmt.Printf("  > T5/%s — SKIP: %s\n", name, rc.SkipReason)
	} else {
		fmt.Printf("  > T5/%s (took %s) — OK\n", name, rc.Duration)
	}
	suite.Add(rc)
}

func probeUnprivileged(ctx context.Context, rendrRoot string) report.Case {
	const name = "T5.3-tcprepair-unprivileged"
	if _, err := exec.LookPath("setpriv"); err != nil {
		return report.Case{Name: name, Tier: "T5", SkipReason: "setpriv unavailable"}
	}
	if _, err := os.Stat(rendrRoot); err != nil {
		return report.Case{Name: name, Tier: "T5", Failure: "bad rendr root: " + err.Error()}
	}
	cmd := exec.CommandContext(
		ctx,
		"setpriv",
		"--bounding-set=-net_admin",
		"--inh-caps=-net_admin",
		"--ambient-caps=-net_admin",
		"bash", "-lc",
		fmt.Sprintf("cd %s && /usr/local/go/bin/go test ./transport/tcprepair -run TestAvailableExpectation -count=1", rendrRoot),
	)
	cmd.Env = append(os.Environ(),
		"RENDR_EXPECT_TCPREPAIR=unavailable",
		"GOCACHE=/tmp/go-build-nocap",
		"GOMODCACHE=/tmp/go-mod-nocap",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return report.Case{Name: name, Tier: "T5", Failure: fmt.Sprintf("%v (%s)", err, strings.TrimSpace(string(out)))}
	}
	return report.Case{Name: name, Tier: "T5"}
}

func probeGVisorUnprivileged(ctx context.Context, rendrRoot string) report.Case {
	const name = "T5.4-gvisor-unprivileged"
	if _, err := exec.LookPath("setpriv"); err != nil {
		return report.Case{Name: name, Tier: "T5", SkipReason: "setpriv unavailable"}
	}
	if _, err := os.Stat(rendrRoot); err != nil {
		return report.Case{Name: name, Tier: "T5", Failure: "bad rendr root: " + err.Error()}
	}
	cmd := exec.CommandContext(
		ctx,
		"setpriv",
		"--bounding-set=-net_admin",
		"--inh-caps=-net_admin",
		"--ambient-caps=-net_admin",
		"bash", "-lc",
		fmt.Sprintf("cd %s/regress && /usr/local/go/bin/go test ./internal/smoke -run TestRunG1GVisor -count=1", rendrRoot),
	)
	cmd.Env = append(os.Environ(),
		"GOCACHE=/tmp/go-build-gvisor-nocap",
		"GOMODCACHE=/tmp/go-mod-gvisor-nocap",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return report.Case{Name: name, Tier: "T5", Failure: fmt.Sprintf("%v (%s)", err, strings.TrimSpace(string(out)))}
	}
	return report.Case{Name: name, Tier: "T5"}
}

func probeTCPRepairGVisorFallbackUnprivileged(ctx context.Context, rendrRoot string) report.Case {
	const name = "T5.5-tcprepair-gvisor-fallback-unprivileged"
	if _, err := exec.LookPath("setpriv"); err != nil {
		return report.Case{Name: name, Tier: "T5", SkipReason: "setpriv unavailable"}
	}
	if _, err := os.Stat(rendrRoot); err != nil {
		return report.Case{Name: name, Tier: "T5", Failure: "bad rendr root: " + err.Error()}
	}
	cmd := exec.CommandContext(
		ctx,
		"setpriv",
		"--bounding-set=-net_admin",
		"--inh-caps=-net_admin",
		"--ambient-caps=-net_admin",
		"bash", "-lc",
		fmt.Sprintf("cd %s/regress && /usr/local/go/bin/go test ./internal/smoke -run TestTCPRepairUnavailableFallsBackToGVisor -count=1", rendrRoot),
	)
	cmd.Env = append(os.Environ(),
		"GOCACHE=/tmp/go-build-tcprepair-gvisor-fallback-nocap",
		"GOMODCACHE=/tmp/go-mod-tcprepair-gvisor-fallback-nocap",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return report.Case{Name: name, Tier: "T5", Failure: fmt.Sprintf("%v (%s)", err, strings.TrimSpace(string(out)))}
	}
	return report.Case{Name: name, Tier: "T5"}
}

func probeGVisorPacketCarrierUnprivileged(ctx context.Context, rendrRoot string) report.Case {
	const name = "T5.6-gvisor-packet-carrier-unprivileged"
	if _, err := exec.LookPath("setpriv"); err != nil {
		return report.Case{Name: name, Tier: "T5", SkipReason: "setpriv unavailable"}
	}
	if _, err := os.Stat(rendrRoot); err != nil {
		return report.Case{Name: name, Tier: "T5", Failure: "bad rendr root: " + err.Error()}
	}
	cmd := exec.CommandContext(
		ctx,
		"setpriv",
		"--bounding-set=-net_admin",
		"--inh-caps=-net_admin",
		"--ambient-caps=-net_admin",
		"bash", "-lc",
		fmt.Sprintf("cd %s/regress && /usr/local/go/bin/go test ./internal/smoke -run TestRunG1GVisorPacketCarrier -count=1", rendrRoot),
	)
	cmd.Env = append(os.Environ(),
		"GOCACHE=/tmp/go-build-gvisor-packet-nocap",
		"GOMODCACHE=/tmp/go-mod-gvisor-packet-nocap",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return report.Case{Name: name, Tier: "T5", Failure: fmt.Sprintf("%v (%s)", err, strings.TrimSpace(string(out)))}
	}
	return report.Case{Name: name, Tier: "T5"}
}
