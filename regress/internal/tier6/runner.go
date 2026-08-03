// Package tier6 implements selector target graph regression gates.
package tier6

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/report"
)

// Options filters the tier6 selector graph matrix.
type Options struct {
	Case     string
	FromCase string
}

type caseDef struct {
	spec    manifest.Spec
	pattern string
}

var caseDefs = []caseDef{
	{manifest.RequiredWithBudget("T6.graph.compat-mode", "T6", 2*time.Minute), "TestTargetConstructors|TestLegacy|TestDialerCompile|TestDialerRoot"},
	{manifest.RequiredWithBudget("T6.peak.A-to-bulk-bond", "T6", 2*time.Minute), "^TestSelectorPeakTransferRuntimePromotesToBond$"},
	{manifest.RequiredWithBudget("T6.peak.nested-normal-to-C", "T6", 2*time.Minute), "^TestSelectorPeakTransferNormalSelectorUsesQuality$"},
	{manifest.RequiredWithBudget("T6.failover.hot-standby", "T6", 2*time.Minute), "^TestSelectorHotStandbyFailover$"},
	{manifest.RequiredWithBudget("T6.peak.composite-normal", "T6", 2*time.Minute), "^TestSelectorPeakTransferCompositeNormalDeathStaysNormal$"},
	{manifest.RequiredWithBudget("T6.peak.bad-speed", "T6", 2*time.Minute), "^TestSelectorPeakTransferBadSpeedQualityGate$"},
	{manifest.RequiredWithBudget("T6.peak.stale-speed", "T6", 2*time.Minute), "^TestSelectorPeakTransferStaleSpeedEvidence$"},
	{manifest.RequiredWithBudget("T6.peak.probe-budget", "T6", 2*time.Minute), "^TestSelectorPeakTransferProbeBudgetUsesSinglePeakCandidate$"},
	{manifest.RequiredWithBudget("T6.peak.slow-peak-revert", "T6", 2*time.Minute), "^TestSelectorPeakTransferSlowPeakRevertsAndSuppresses$"},
	{manifest.RequiredWithBudget("T6.peak.rx-peer-policy", "T6", 2*time.Minute), "^TestSelectorPeakTransferRxPromotesPeerSenderOnly$"},
}

// Specs returns the ordered T6 case manifest.
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
		failure := fmt.Sprintf("no T6 case matched case=%q from-case=%q", opts.Case, opts.FromCase)
		if opts.FromCase == "" {
			failure = fmt.Sprintf("no T6 case matched %q", opts.Case)
		}
		suite.Add(report.Case{Name: "T6-case-filter", Tier: "T6", Failure: failure})
		return
	}
	for _, def := range defs {
		def := def
		runCase(ctx, suite, def.spec.ID, def.spec.Budget, func(c context.Context) report.Case {
			return runRootTargetGraphTests(c, rendrRoot, def.spec.ID, def.pattern)
		})
	}
}

func runCase(ctx context.Context, suite *report.Suite, name string, budget time.Duration, fn func(context.Context) report.Case) {
	fmt.Printf("  > T6/%s (budget %s) - start\n", name, budget)
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
			Tier:     "T6",
			Duration: time.Since(start),
			Failure:  "case exceeded T6 budget: " + cctx.Err().Error(),
		}
	}
	if rc.Failure != "" {
		fmt.Printf("  > T6/%s (took %s) - FAIL: %s\n", name, rc.Duration, rc.Failure)
	} else if rc.SkipReason != "" {
		fmt.Printf("  > T6/%s - SKIP: %s\n", name, rc.SkipReason)
	} else {
		fmt.Printf("  > T6/%s (took %s) - OK\n", name, rc.Duration)
	}
	suite.Add(rc)
}

func runRootTargetGraphTests(ctx context.Context, rendrRoot, name, pattern string) report.Case {
	if _, err := os.Stat(rendrRoot); err != nil {
		return report.Case{Name: name, Tier: "T6", Failure: "bad rendr root: " + err.Error()}
	}
	cmd := exec.CommandContext(
		ctx,
		"/usr/local/go/bin/go",
		"test",
		".",
		"-run",
		pattern,
		"-count=1",
	)
	cmd.Dir = rendrRoot
	cmd.Env = append(os.Environ(), "GOCACHE=/tmp/go-build-rendr-t6")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return report.Case{Name: name, Tier: "T6", Failure: fmt.Sprintf("%v (%s)", err, strings.TrimSpace(string(out)))}
	}
	return report.Case{Name: name, Tier: "T6"}
}
