// Package tier3 runs the path-factory × xray outbound matrix from
// docs/regression-suite.md §7. Implementation strategy:
// rather than re-implement test discovery, tier3 shells out to
// `go test -v -json ./internal/matrix/...` inside the regress
// submodule and translates each top-level Go test result into one
// report.Case entry.
//
// This keeps the matrix tests authored as plain Go test files (so
// `go test` from the regress dir works for ad-hoc debugging) while
// still surfacing them through the regress driver's phase-gate +
// JUnit reporter.
package tier3

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/report"
)

// Options filters the tier3 matrix execution.
type Options struct {
	Case string
}

// Run shells out to `go test -json ./internal/matrix/...` under the
// regress submodule and translates each top-level test outcome into
// a tier3 report.Case. rendrRoot is the rendr repo root; the
// regress submodule lives at <rendrRoot>/regress.
func Run(ctx context.Context, suite *report.Suite, rendrRoot string, opts Options) {
	regressDir := filepath.Join(rendrRoot, "regress")
	start := time.Now()

	// 8-minute hard cap on the whole matrix; individual matrix
	// tests have their own t.Context budgets too.
	cctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(cctx, "go", buildGoTestArgs(opts)...)
	cmd.Dir = regressDir
	cmd.WaitDelay = 15 * time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		suite.Add(report.Case{
			Name:     "T3-setup",
			Tier:     "T3",
			Duration: time.Since(start),
			Failure:  "stdout pipe: " + err.Error(),
		})
		return
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		suite.Add(report.Case{
			Name:     "T3-setup",
			Tier:     "T3",
			Duration: time.Since(start),
			Failure:  "go test start: " + err.Error(),
		})
		return
	}

	// Parse the JSON test event stream. We only track top-level
	// Go-test names (no subtests) so each TestXxx in the matrix
	// package = one regress.Case.
	tests := map[string]*testRec{}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1<<20), 1<<22)
	for scanner.Scan() {
		var ev event
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			continue
		}
		if ev.Test == "" || strings.Contains(ev.Test, "/") {
			continue // skip subtests + suite-level events
		}
		t, ok := tests[ev.Test]
		if !ok {
			t = &testRec{name: ev.Test}
			tests[ev.Test] = t
		}
		switch ev.Action {
		case "run":
			t.started = ev.Time
		case "output":
			// Capture last few hundred lines of output for failure
			// context; cap memory at 16 KiB per test.
			if len(t.output)+len(ev.Output) > 16<<10 {
				continue
			}
			t.output += ev.Output
		case "pass", "fail", "skip":
			t.result = ev.Action
			t.finished = ev.Time
			t.elapsed = time.Duration(ev.Elapsed * float64(time.Second))
		}
	}
	waitErr := cmd.Wait()
	if waitErr != nil && !errors.Is(waitErr, io.EOF) {
		// Wait can fail because of test failures; that's expected
		// and handled per-test below. Only treat exec-level errors
		// (e.g. binary missing) as a setup failure.
		var exitErr *exec.ExitError
		if !errors.As(waitErr, &exitErr) {
			suite.Add(report.Case{
				Name:     "T3-setup",
				Tier:     "T3",
				Duration: time.Since(start),
				Failure:  "go test wait: " + waitErr.Error(),
			})
			return
		}
	}

	if len(tests) == 0 {
		suite.Add(report.Case{
			Name:       "T3-matrix",
			Tier:       "T3",
			Duration:   time.Since(start),
			SkipReason: "no matrix tests found (regress/internal/matrix/...)",
		})
		return
	}

	for _, t := range tests {
		c := report.Case{
			Name:     t.name,
			Tier:     "T3",
			Duration: t.elapsed,
		}
		switch t.result {
		case "fail":
			c.Failure = fmt.Sprintf("matrix test failed:\n%s", strings.TrimSpace(t.output))
		case "skip":
			c.SkipReason = "matrix test skipped"
		}
		suite.Add(c)
	}
}

func buildGoTestArgs(opts Options) []string {
	args := []string{
		"test",
		"-json",
		"-count=1",
		"-timeout",
		"6m",
	}
	if opts.Case != "" {
		args = append(args, "-run", "^"+regexp.QuoteMeta(opts.Case)+"$")
	}
	args = append(args, "./internal/matrix/...")
	return args
}

type event struct {
	Time    time.Time `json:"Time"`
	Action  string    `json:"Action"`
	Package string    `json:"Package"`
	Test    string    `json:"Test"`
	Elapsed float64   `json:"Elapsed"`
	Output  string    `json:"Output"`
}

type testRec struct {
	name     string
	started  time.Time
	finished time.Time
	elapsed  time.Duration
	result   string // "pass" | "fail" | "skip" | ""
	output   string
}
