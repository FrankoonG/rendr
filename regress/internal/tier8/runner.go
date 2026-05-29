// Package tier8 implements runtime status / identity / recovery gates.
package tier8

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/report"
)

// Options filters tier8 runtime status cases.
type Options struct {
	Case     string
	FromCase string
}

func Run(ctx context.Context, suite *report.Suite, rendrRoot string, opts Options) {
	matched := false
	run := func(name string, budget time.Duration, pattern string) {
		if !caseMatches(opts.Case, opts.FromCase, name, matched) {
			return
		}
		matched = true
		runCase(ctx, suite, name, budget, func(c context.Context) report.Case {
			return runGoTest(c, rendrRoot, name, pattern)
		})
	}
	defer func() {
		if (opts.Case != "" || opts.FromCase != "") && !matched {
			suite.Add(report.Case{
				Name:    "T8-case-filter",
				Tier:    "T8",
				Failure: fmt.Sprintf("no T8 case matched case=%q from-case=%q", opts.Case, opts.FromCase),
			})
		}
	}()

	run("T8.status.local-default", time.Minute, "^TestProbeLocalDefault$")
	run("T8.status.peer-rendr", 2*time.Minute, "^TestDialerStatusPeerRendr$")
	run("T8.primary.default-first-leaf", 2*time.Minute, "^TestDialerRootSelectorDialSmoke$")
	run("T8.primary.explicit-path", time.Minute, "^TestDialerPrimaryExplicitPathReordersPlan$")
	run("T8.primary.explicit-group-resolve", time.Minute, "^TestDialerPrimaryExplicitGroupResolvesLeaf$")
	run("T8.primary.prefer-fallback", 2*time.Minute, "^TestDialerPrimaryPreferFallbackStatus$")
	run("T8.primary.require-fails", 2*time.Minute, "^TestDialerPrimaryRequireFails$")
	run("T8.retry.forwarding-fixed", 2*time.Minute, "^TestDialerOptionalPathRetryAttachesAfterForwardingFix$")
	run("T8.retry.no-app-error", 2*time.Minute, "^TestDialerOptionalPathFailureDoesNotSurfaceToApp$")
}

func caseMatches(filter, fromCase, name string, alreadyStarted bool) bool {
	if filter != "" {
		return filter == name
	}
	if fromCase == "" {
		return true
	}
	return alreadyStarted || fromCase == name
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
	cmd := exec.CommandContext(ctx, "/usr/local/go/bin/go", "test", ".", "-run", pattern, "-count=1")
	cmd.Dir = rendrRoot
	cmd.Env = append(os.Environ(), "GOCACHE=/tmp/go-build-rendr-t8")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return report.Case{Name: name, Tier: "T8", Failure: fmt.Sprintf("%v (%s)", err, strings.TrimSpace(string(out)))}
	}
	return report.Case{Name: name, Tier: "T8"}
}
