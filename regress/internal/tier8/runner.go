// Package tier8 implements runtime status / identity / recovery gates.
package tier8

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/caseexec"
	"github.com/FrankoonG/rendr/regress/internal/gotestjson"
	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/report"
)

// Options filters tier8 runtime status cases.
type Options struct {
	Case     string
	FromCase string
}

type caseDef struct {
	spec     manifest.Spec
	expected []string
}

var caseDefs = []caseDef{
	{mustCaseSpec("T8.status.local-default", time.Minute), []string{"TestProbeLocalDefault"}},
	{mustCaseSpec("T8.status.peer-rendr", 2*time.Minute), []string{"TestDialerStatusPeerRendr"}},
	{mustCaseSpec("T8.primary.default-first-leaf", 2*time.Minute), []string{"TestDialerRootSelectorDialSmoke"}},
	{mustCaseSpec("T8.primary.explicit-path", time.Minute), []string{"TestDialerPrimaryExplicitPathReordersPlan"}},
	{mustCaseSpec("T8.primary.explicit-group-resolve", time.Minute), []string{"TestDialerPrimaryExplicitGroupResolvesLeaf"}},
	{mustCaseSpec("T8.primary.prefer-fallback", 2*time.Minute), []string{"TestDialerPrimaryPreferFallbackStatus"}},
	{mustCaseSpec("T8.primary.require-fails", 2*time.Minute), []string{"TestDialerPrimaryRequireFails"}},
	{mustCaseSpec("T8.retry.forwarding-fixed", 2*time.Minute), []string{"TestDialerOptionalPathRetryAttachesAfterForwardingFix"}},
	{mustCaseSpec("T8.retry.no-app-error", 2*time.Minute), []string{"TestDialerOptionalPathFailureDoesNotSurfaceToApp"}},
}

// Specs returns the ordered T8 case manifest.
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
	runCaseDefs(ctx, suite, rendrRoot, defs, func(ctx context.Context, rendrRoot string, def caseDef) caseexec.Outcome {
		return runCase(ctx, def.spec.ID, def.spec.Budget, func(c context.Context) report.Case {
			return runGoTest(c, rendrRoot, def)
		})
	})
}

type caseExecutor func(context.Context, string, caseDef) caseexec.Outcome

func runCaseDefs(ctx context.Context, suite *report.Suite, rendrRoot string, defs []caseDef, execute caseExecutor) {
	failedCaseID := ""
	for _, def := range defs {
		if failedCaseID != "" {
			suite.Add(notRunCase(def.spec, failedCaseID))
			continue
		}
		outcome := execute(ctx, rendrRoot, def)
		rc := outcome.Case
		suite.Add(rc)
		if outcome.MustStop || mandatoryCaseFailed(def.spec, rc) {
			failedCaseID = def.spec.ID
		}
	}
}

func runCase(ctx context.Context, name string, budget time.Duration, fn func(context.Context) report.Case) caseexec.Outcome {
	fmt.Printf("  > T8/%s (budget %s) - start\n", name, budget)
	outcome := caseexec.Run(ctx, caseexec.Config{
		Name:        name,
		Tier:        "T8",
		Budget:      budget,
		JoinTimeout: caseexec.DefaultJoinTimeout,
	}, fn)
	rc := outcome.Case
	if rc.InvalidReason != "" {
		fmt.Printf("  > T8/%s (took %s) - INVALID: %s\n", name, rc.Duration, rc.InvalidReason)
	} else if rc.Failure != "" {
		fmt.Printf("  > T8/%s (took %s) - FAIL: %s\n", name, rc.Duration, rc.Failure)
	} else if rc.SkipReason != "" {
		fmt.Printf("  > T8/%s - SKIP: %s\n", name, rc.SkipReason)
	} else {
		fmt.Printf("  > T8/%s (took %s) - OK\n", name, rc.Duration)
	}
	return outcome
}

func mandatoryCaseFailed(spec manifest.Spec, rc report.Case) bool {
	return spec.Mandatory && (rc.Failure != "" || rc.InvalidReason != "" || rc.SkipReason != "")
}

func notRunCase(spec manifest.Spec, failedCaseID string) report.Case {
	return report.Case{
		Name:            spec.ID,
		Tier:            spec.Tier,
		ExecutionState:  report.ExecutionStateNotRun,
		BlockerKind:     report.BlockerKindCase,
		BlockedByCaseID: failedCaseID,
		InvalidReason:   fmt.Sprintf("not run after %s failed", failedCaseID),
	}
}

func runGoTest(ctx context.Context, rendrRoot string, def caseDef) report.Case {
	if _, err := os.Stat(rendrRoot); err != nil {
		return report.Case{Name: def.spec.ID, Tier: "T8", InvalidReason: "bad rendr root: " + err.Error()}
	}
	result, err := tier8GoTestExecutor.Run(ctx, gotestjson.Request{
		Dir:      rendrRoot,
		Package:  ".",
		Pattern:  exactTestPattern(def.expected),
		Expected: testExpectations(def.expected),
		Env:      []string{"GOCACHE=" + filepath.Join(os.TempDir(), "go-build-rendr-t8")},
	})
	if err != nil && result.Passed() {
		result.Issues = append(result.Issues, gotestjson.Issue{Code: gotestjson.IssueCommandFailed, Detail: err.Error()})
	}
	return goTestReportCase(def.spec.ID, "T8", def.expected, result)
}
