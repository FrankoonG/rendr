// Package tier5 implements the TCP fallback / adapter verification
// tier. With tcprepair available but gvisor still absent, the current
// matrix is:
//   - T5.1 privileged tcprepair same-tuple rebuild smoke
//   - T5.2 skipped (gvisor unavailable)
//   - T5.3 unprivileged tcprepair capability probe must fail clearly
//   - T5.4 skipped (gvisor unavailable)
package tier5

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/report"
	"github.com/FrankoonG/rendr/regress/internal/smoke"
	"github.com/FrankoonG/rendr/transport/tcprepair"
)

// Options filters the tier5 adapter matrix.
type Options struct {
	Case string
}

func Run(ctx context.Context, suite *report.Suite, rendrRoot string, opts Options) {
	matched := false
	add := func(c report.Case) {
		if !caseMatches(opts.Case, c.Name) {
			return
		}
		matched = true
		suite.Add(c)
	}
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
				Name:    "T5-case-filter",
				Tier:    "T5",
				Failure: fmt.Sprintf("no T5 case matched %q", opts.Case),
			})
		}
	}()

	if runtime.GOOS != "linux" {
		add(report.Case{
			Name:       "T5.1-tcprepair-privileged",
			Tier:       "T5",
			SkipReason: "Linux only",
		})
		return
	}

	run("T5.1-tcprepair-privileged", 3*time.Minute, func(c context.Context) report.Case {
		if err := tcprepair.Available(); err != nil {
			return report.Case{Name: "T5.1-tcprepair-privileged", Tier: "T5", Failure: err.Error()}
		}
		r := smoke.RunG1TCPRepairSameTuple(c, smoke.G1TCPRepairOpts{
			Size:       30 << 20,
			Migrations: 3,
		})
		return report.Case{Name: "T5.1-tcprepair-privileged", Tier: "T5", Duration: r.Duration, Failure: r.Failure}
	})

	add(report.Case{
		Name:       "T5.2-gvisor-privileged",
		Tier:       "T5",
		SkipReason: "gvisor adapter unavailable",
	})

	run("T5.3-tcprepair-unprivileged", 2*time.Minute, func(context.Context) report.Case {
		return probeUnprivileged(rendrRoot)
	})

	add(report.Case{
		Name:       "T5.4-gvisor-unprivileged",
		Tier:       "T5",
		SkipReason: "gvisor adapter unavailable",
	})
}

func caseMatches(filter, name string) bool {
	return filter == "" || filter == name
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

func probeUnprivileged(rendrRoot string) report.Case {
	const name = "T5.3-tcprepair-unprivileged"
	if _, err := exec.LookPath("setpriv"); err != nil {
		return report.Case{Name: name, Tier: "T5", SkipReason: "setpriv unavailable"}
	}
	if _, err := os.Stat(rendrRoot); err != nil {
		return report.Case{Name: name, Tier: "T5", Failure: "bad rendr root: " + err.Error()}
	}
	cmd := exec.Command(
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
