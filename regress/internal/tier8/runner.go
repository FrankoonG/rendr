// Package tier8 implements runtime status / identity / recovery gates.
package tier8

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

// Options filters tier8 runtime status cases.
type Options struct {
	Case     string
	FromCase string
}

type caseDef struct {
	spec    manifest.Spec
	pattern string
}

var caseDefs = []caseDef{
	{manifest.RequiredWithBudget("T8.status.local-default", "T8", time.Minute), "^TestProbeLocalDefault$"},
	{manifest.RequiredWithBudget("T8.status.peer-rendr", "T8", 2*time.Minute), "^TestDialerStatusPeerRendr$"},
	{manifest.RequiredWithBudget("T8.primary.default-first-leaf", "T8", 2*time.Minute), "^TestDialerRootSelectorDialSmoke$"},
	{manifest.RequiredWithBudget("T8.primary.explicit-path", "T8", time.Minute), "^TestDialerPrimaryExplicitPathReordersPlan$"},
	{manifest.RequiredWithBudget("T8.primary.explicit-group-resolve", "T8", time.Minute), "^TestDialerPrimaryExplicitGroupResolvesLeaf$"},
	{manifest.RequiredWithBudget("T8.primary.prefer-fallback", "T8", 2*time.Minute), "^TestDialerPrimaryPreferFallbackStatus$"},
	{manifest.RequiredWithBudget("T8.primary.require-fails", "T8", 2*time.Minute), "^TestDialerPrimaryRequireFails$"},
	{manifest.RequiredWithBudget("T8.retry.forwarding-fixed", "T8", 2*time.Minute), "^TestDialerOptionalPathRetryAttachesAfterForwardingFix$"},
	{manifest.RequiredWithBudget("T8.retry.no-app-error", "T8", 2*time.Minute), "^TestDialerOptionalPathFailureDoesNotSurfaceToApp$"},
}

// Specs returns the ordered T8 case manifest.
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
			Name:    "T8-case-filter",
			Tier:    "T8",
			Failure: fmt.Sprintf("no T8 case matched case=%q from-case=%q", opts.Case, opts.FromCase),
		})
		return
	}
	for _, def := range defs {
		def := def
		runCase(ctx, suite, def.spec.ID, def.spec.Budget, func(c context.Context) report.Case {
			return runGoTest(c, rendrRoot, def.spec.ID, def.pattern)
		})
	}
}

func runCase(ctx context.Context, suite *report.Suite, name string, budget time.Duration, fn func(context.Context) report.Case) {
	fmt.Printf("  > T8/%s (budget %s) - start\n", name, budget)
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
			Tier:     "T8",
			Duration: time.Since(start),
			Failure:  "case exceeded T8 budget: " + cctx.Err().Error(),
		}
	}
	if rc.Failure != "" {
		fmt.Printf("  > T8/%s (took %s) - FAIL: %s\n", name, rc.Duration, rc.Failure)
	} else if rc.SkipReason != "" {
		fmt.Printf("  > T8/%s - SKIP: %s\n", name, rc.SkipReason)
	} else {
		fmt.Printf("  > T8/%s (took %s) - OK\n", name, rc.Duration)
	}
	suite.Add(rc)
}

func runGoTest(ctx context.Context, rendrRoot, name, pattern string) report.Case {
	if _, err := os.Stat(rendrRoot); err != nil {
		return report.Case{Name: name, Tier: "T8", Failure: "bad rendr root: " + err.Error()}
	}
	cmd := exec.CommandContext(ctx, "go", "test", ".", "-run", pattern, "-count=1")
	cmd.Dir = rendrRoot
	cmd.Env = append(os.Environ(), "GOCACHE=/tmp/go-build-rendr-t8")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return report.Case{Name: name, Tier: "T8", Failure: fmt.Sprintf("%v (%s)", err, strings.TrimSpace(string(out)))}
	}
	return report.Case{Name: name, Tier: "T8"}
}
