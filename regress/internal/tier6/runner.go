// Package tier6 implements selector target graph regression gates.
package tier6

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/gotestjson"
	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/report"
)

// Options filters the tier6 selector graph matrix.
type Options struct {
	Case     string
	FromCase string
}

type caseDef struct {
	spec     manifest.Spec
	expected []string
}

var caseDefs = []caseDef{
	{
		spec: manifest.RequiredWithBudget("T6.graph.compat-mode", "T6", 2*time.Minute),
		expected: []string{
			"TestLegacyRootTargetCompilesModes",
			"TestTargetConstructorsExposeGroupKinds",
			"TestDialerCompileDialPlanUsesRoot",
			"TestDialerRootSelectorDialSmoke",
		},
	},
	{manifest.RequiredWithBudget("T6.peak.A-to-bulk-bond", "T6", 2*time.Minute), []string{"TestSelectorPeakTransferRuntimePromotesToBond"}},
	{manifest.RequiredWithBudget("T6.peak.nested-normal-to-C", "T6", 2*time.Minute), []string{"TestSelectorPeakTransferNormalSelectorUsesQuality"}},
	{manifest.RequiredWithBudget("T6.failover.hot-standby", "T6", 2*time.Minute), []string{"TestSelectorHotStandbyFailover"}},
	{manifest.RequiredWithBudget("T6.peak.composite-normal", "T6", 2*time.Minute), []string{"TestSelectorPeakTransferCompositeNormalDeathStaysNormal"}},
	{manifest.RequiredWithBudget("T6.peak.bad-speed", "T6", 2*time.Minute), []string{"TestSelectorPeakTransferBadSpeedQualityGate"}},
	{manifest.RequiredWithBudget("T6.peak.stale-speed", "T6", 2*time.Minute), []string{"TestSelectorPeakTransferStaleSpeedEvidence"}},
	{manifest.RequiredWithBudget("T6.peak.probe-budget", "T6", 2*time.Minute), []string{"TestSelectorPeakTransferProbeBudgetUsesSinglePeakCandidate"}},
	{manifest.RequiredWithBudget("T6.peak.slow-peak-revert", "T6", 2*time.Minute), []string{"TestSelectorPeakTransferSlowPeakRevertsAndSuppresses"}},
	{manifest.RequiredWithBudget("T6.peak.rx-peer-policy", "T6", 2*time.Minute), []string{"TestSelectorPeakTransferRxPromotesPeerSenderOnly"}},
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
	runCaseDefs(ctx, suite, rendrRoot, defs, func(ctx context.Context, rendrRoot string, def caseDef) report.Case {
		return runCase(ctx, def.spec.ID, def.spec.Budget, func(c context.Context) report.Case {
			return runRootTargetGraphTests(c, rendrRoot, def)
		})
	})
}

type caseExecutor func(context.Context, string, caseDef) report.Case

func runCaseDefs(ctx context.Context, suite *report.Suite, rendrRoot string, defs []caseDef, execute caseExecutor) {
	failedCaseID := ""
	for _, def := range defs {
		if failedCaseID != "" {
			suite.Add(notRunCase(def.spec, failedCaseID))
			continue
		}
		rc := execute(ctx, rendrRoot, def)
		suite.Add(rc)
		if mandatoryCaseFailed(def.spec, rc) {
			failedCaseID = def.spec.ID
		}
	}
}

func runCase(ctx context.Context, name string, budget time.Duration, fn func(context.Context) report.Case) report.Case {
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
	if rc.InvalidReason != "" {
		fmt.Printf("  > T6/%s (took %s) - INVALID: %s\n", name, rc.Duration, rc.InvalidReason)
	} else if rc.Failure != "" {
		fmt.Printf("  > T6/%s (took %s) - FAIL: %s\n", name, rc.Duration, rc.Failure)
	} else if rc.SkipReason != "" {
		fmt.Printf("  > T6/%s - SKIP: %s\n", name, rc.SkipReason)
	} else {
		fmt.Printf("  > T6/%s (took %s) - OK\n", name, rc.Duration)
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

func runRootTargetGraphTests(ctx context.Context, rendrRoot string, def caseDef) report.Case {
	if _, err := os.Stat(rendrRoot); err != nil {
		return report.Case{Name: def.spec.ID, Tier: "T6", InvalidReason: "bad rendr root: " + err.Error()}
	}
	result, err := tier6GoTestExecutor.Run(ctx, gotestjson.Request{
		Dir:      rendrRoot,
		Package:  ".",
		Pattern:  exactTestPattern(def.expected),
		Expected: testExpectations(def.expected),
		Env:      []string{"GOCACHE=" + filepath.Join(os.TempDir(), "go-build-rendr-t6")},
	})
	if err != nil && result.Passed() {
		result.Issues = append(result.Issues, gotestjson.Issue{Code: gotestjson.IssueCommandFailed, Detail: err.Error()})
	}
	return goTestReportCase(def.spec.ID, "T6", def.expected, result)
}
