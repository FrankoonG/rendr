// Package tier6 implements selector target graph regression gates.
package tier6

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/report"
)

// Options filters the tier6 selector graph matrix.
type Options struct {
	Case string
}

func Run(ctx context.Context, suite *report.Suite, rendrRoot string, opts Options) {
	matched := false
	run := func(name string, budget time.Duration, fn func(context.Context) report.Case) {
		if !caseMatches(opts.Case, name) {
			return
		}
		matched = true
		runCase(ctx, suite, name, budget, fn)
	}
	defer func() {
		if opts.Case != "" && !matched {
			suite.Add(report.Case{
				Name:    "T6-case-filter",
				Tier:    "T6",
				Failure: fmt.Sprintf("no T6 case matched %q", opts.Case),
			})
		}
	}()

	run("T6.graph.compat-mode", 2*time.Minute, func(c context.Context) report.Case {
		return runRootTargetGraphTests(c, rendrRoot, "T6.graph.compat-mode", "TestTargetConstructors|TestLegacy|TestDialerCompile|TestDialerRoot")
	})
	run("T6.peak.A-to-bulk-bond", 2*time.Minute, func(c context.Context) report.Case {
		return runRootTargetGraphTests(c, rendrRoot, "T6.peak.A-to-bulk-bond", "^TestSelectorPeakTransferRuntimePromotesToBond$")
	})
	run("T6.peak.nested-normal-to-C", 2*time.Minute, func(c context.Context) report.Case {
		return runRootTargetGraphTests(c, rendrRoot, "T6.peak.nested-normal-to-C", "^TestSelectorPeakTransferNormalSelectorUsesQuality$")
	})
	run("T6.failover.hot-standby", 2*time.Minute, func(c context.Context) report.Case {
		return runRootTargetGraphTests(c, rendrRoot, "T6.failover.hot-standby", "^TestSelectorHotStandbyFailover$")
	})
	run("T6.peak.composite-normal", 2*time.Minute, func(c context.Context) report.Case {
		return runRootTargetGraphTests(c, rendrRoot, "T6.peak.composite-normal", "^TestSelectorPeakTransferCompositeNormalDeathStaysNormal$")
	})
	run("T6.peak.bad-speed", 2*time.Minute, func(c context.Context) report.Case {
		return runRootTargetGraphTests(c, rendrRoot, "T6.peak.bad-speed", "^TestSelectorPeakTransferBadSpeedQualityGate$")
	})
	run("T6.peak.stale-speed", 2*time.Minute, func(c context.Context) report.Case {
		return runRootTargetGraphTests(c, rendrRoot, "T6.peak.stale-speed", "^TestSelectorPeakTransferStaleSpeedEvidence$")
	})
	run("T6.peak.probe-budget", 2*time.Minute, func(c context.Context) report.Case {
		return runRootTargetGraphTests(c, rendrRoot, "T6.peak.probe-budget", "^TestSelectorPeakTransferProbeBudgetUsesSinglePeakCandidate$")
	})
	run("T6.peak.slow-peak-revert", 2*time.Minute, func(c context.Context) report.Case {
		return runRootTargetGraphTests(c, rendrRoot, "T6.peak.slow-peak-revert", "^TestSelectorPeakTransferSlowPeakRevertsAndSuppresses$")
	})
	run("T6.peak.rx-peer-policy", 2*time.Minute, func(c context.Context) report.Case {
		return runRootTargetGraphTests(c, rendrRoot, "T6.peak.rx-peer-policy", "^TestSelectorPeakTransferRxPromotesPeerSenderOnly$")
	})
}

func caseMatches(filter, name string) bool {
	return filter == "" || filter == name
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
