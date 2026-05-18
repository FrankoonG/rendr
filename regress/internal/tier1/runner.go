// Package tier1 runs phase-1 contract tests: go test ./..., go vet,
// go test -race, bench smoke, plus a const grep that catches silent
// drift in load-bearing constants (proto versions, migration budget,
// mode table). The constants tested here are wire-protocol or
// release-blocking; changing them MUST happen in a separate commit
// with a wire-protocol version bump.
package tier1

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/report"
)

// Run executes all T1 cases and writes results to suite. rendrRoot
// is the path to the rendr repo root (where go.mod lives).
//
// Caller decides what to do with failures; this function does not exit.
func Run(ctx context.Context, suite *report.Suite, rendrRoot string) {
	cases := []struct {
		name string
		fn   func(context.Context, string) error
		// onlyOn is empty for "any OS"; "linux" restricts to Linux runners.
		onlyOn string
	}{
		{"go-vet", goVet, ""},
		{"go-test", goTest, ""},
		{"go-test-race", goTestRace, "linux"},
		{"go-bench-smoke", goBenchSmoke, "linux"},
		{"const-proto-version", constProtoVersion, ""},
		{"const-udpflow-version", constUDPFlowVersion, ""},
		{"const-migration-budget-90s", constMigrationBudget, ""},
		{"const-mode-values", constModeValues, ""},
		{"const-mode-transition-table", constModeTransitionTable, ""},
	}

	for _, c := range cases {
		if c.onlyOn != "" && c.onlyOn != runtime.GOOS {
			suite.Add(report.Case{
				Name:       c.name,
				Tier:       "T1",
				SkipReason: fmt.Sprintf("only runs on %s", c.onlyOn),
			})
			continue
		}
		start := time.Now()
		err := c.fn(ctx, rendrRoot)
		rc := report.Case{
			Name:     c.name,
			Tier:     "T1",
			Duration: time.Since(start),
		}
		if err != nil {
			rc.Failure = err.Error()
		}
		suite.Add(rc)
	}
}

func runGo(ctx context.Context, rendrRoot string, args ...string) error {
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = rendrRoot
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stderr
	if err := cmd.Run(); err != nil {
		excerpt := strings.TrimSpace(stderr.String())
		if len(excerpt) > 4000 {
			excerpt = excerpt[len(excerpt)-4000:]
		}
		return fmt.Errorf("go %s: %v\n%s", strings.Join(args, " "), err, excerpt)
	}
	return nil
}

func goVet(ctx context.Context, root string) error {
	return runGo(ctx, root, "vet", "./...")
}

func goTest(ctx context.Context, root string) error {
	return runGo(ctx, root, "test", "./...", "-count=1", "-timeout", "240s")
}

func goTestRace(ctx context.Context, root string) error {
	return runGo(ctx, root, "test", "./...", "-count=1", "-race", "-timeout", "360s")
}

func goBenchSmoke(ctx context.Context, root string) error {
	return runGo(ctx, root, "test", "-run=^$", "-bench=.", "-benchtime=1x", "-timeout", "60s", "./...")
}

// Const grep cases — each reads one file and asserts an exact regex
// match. The grep is intentionally cheap (<1s total) and lives in
// T1 to catch silent constant drift before phase 2 burns 15 minutes
// just to discover the same.

func grepFile(root, rel string, want *regexp.Regexp, label string) error {
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		return fmt.Errorf("read %s: %w", rel, err)
	}
	if !want.Match(b) {
		return fmt.Errorf("%s: %s does not match expected pattern /%s/", label, rel, want)
	}
	return nil
}

var (
	rxProtoVersion       = regexp.MustCompile(`const\s+Version\s+uint8\s*=\s*0\b`)
	rxUDPFlowVersion     = regexp.MustCompile(`const\s+UDPFlowVersion\s+uint8\s*=\s*0\b`)
	rxMigrationBudget    = regexp.MustCompile(`MigrationBudget:\s*90\s*\*\s*time\.Second`)
	rxModeValues         = regexp.MustCompile(`(?s)ModePrime\s+Mode\s*=\s*1.*?ModeBond\s+Mode\s*=\s*2.*?ModeRace\s+Mode\s*=\s*3`)
	rxModeTransitionTable = regexp.MustCompile(`(?s)cur\s*==\s*ModeRace\s*&&\s*m\s*==\s*ModeBond.*?cur\s*==\s*ModeBond\s*&&\s*m\s*==\s*ModeRace`)
)

func constProtoVersion(_ context.Context, root string) error {
	return grepFile(root, "proto/frame.go", rxProtoVersion, "proto.Version must be 0 (wire protocol v0)")
}

func constUDPFlowVersion(_ context.Context, root string) error {
	return grepFile(root, "proto/udpflow.go", rxUDPFlowVersion, "proto.UDPFlowVersion must be 0")
}

func constMigrationBudget(_ context.Context, root string) error {
	return grepFile(root, "internal/engine/state.go", rxMigrationBudget,
		"MigrationBudget default must be 90s (CLAUDE.md hard rule #4)")
}

func constModeValues(_ context.Context, root string) error {
	return grepFile(root, "mode.go", rxModeValues,
		"Mode constant values must remain ModePrime=1 ModeBond=2 ModeRace=3 (wire-stable)")
}

func constModeTransitionTable(_ context.Context, root string) error {
	return grepFile(root, "conn_impl.go", rxModeTransitionTable,
		"Mode transition table must forbid race↔bond (CLAUDE.md modes spec)")
}

// VerifyRoot checks the path looks like the rendr repo root.
func VerifyRoot(root string) error {
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return fmt.Errorf("rendr-root=%s: %w", root, err)
	}
	b, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return err
	}
	if !bytes.Contains(b, []byte("github.com/FrankoonG/rendr")) {
		return errors.New("rendr-root go.mod is not the rendr root module")
	}
	return nil
}
