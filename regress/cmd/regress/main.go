// Command regress is the one-button rendr regression suite entry
// point. It enforces the two-phase contract from
// docs/regression-suite.md §4: phase 1 (T1+T2 rendr self-check)
// must be green before phase 2 (T3+T4+T5 integration) is allowed
// to run. Default invocation runs phase 1 then phase 2 T3; phase 1
// failure exits without touching phase 2.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/gate"
	"github.com/FrankoonG/rendr/regress/internal/report"
	"github.com/FrankoonG/rendr/regress/internal/tier1"
	"github.com/FrankoonG/rendr/regress/internal/tier2"
	"github.com/FrankoonG/rendr/regress/internal/tier3"
	"github.com/FrankoonG/rendr/regress/internal/tier4"
	"github.com/FrankoonG/rendr/regress/internal/tier5"
)

// Exit codes match docs/regression-suite.md §10.
const (
	exitOK          = 0
	exitT1Fail      = 10
	exitT2Fail      = 11
	exitT3Fail      = 20
	exitT4Fail      = 21
	exitT5Fail      = 22
	exitEnvError    = 50
	exitPhase1Stale = 51
)

type runFlags struct {
	phase         string
	tier          string
	full          bool
	forcePhase2   bool
	allowNonLinux bool
	profile       string
	caseID        string
	reportDir     string
	rendrRoot     string
}

func parseFlags() runFlags {
	var f runFlags
	flag.StringVar(&f.phase, "phase", "", "phase to run: 1 | 2 (default: 1 then 2-T3)")
	flag.StringVar(&f.tier, "tier", "", "specific tier inside phase 2: 3 | 4 | 5")
	flag.BoolVar(&f.full, "full", false, "run phase 1 and all phase-2 tiers (T3+T4+T5)")
	flag.BoolVar(&f.forcePhase2, "force-phase2", false, "skip phase-1 gate (local debug only; CI MUST NOT pass this)")
	flag.BoolVar(&f.allowNonLinux, "allow-non-linux", false, "bypass the linux-only safety check (dev iteration only)")
	flag.StringVar(&f.profile, "profile", "", "comma-separated path-profile filter (T3)")
	flag.StringVar(&f.caseID, "case", "", "specific case id to run")
	flag.StringVar(&f.reportDir, "report-dir", "reports", "directory to write JUnit + Markdown summary into")
	flag.StringVar(&f.rendrRoot, "rendr-root", "..", "path to the rendr repo root (where the parent go.mod lives)")
	flag.Parse()
	return f
}

func main() {
	cfg := parseFlags()
	// Linux-only safety check. docs/regression-suite.md §3 specifies
	// the suite runs in a Linux container (iptables / tc / netns /
	// -race). Running on Windows / macOS hosts can mask real
	// regressions that only surface under Linux scheduling.
	if runtime.GOOS != "linux" && !cfg.allowNonLinux {
		fmt.Fprintf(os.Stderr,
			"regress: refusing to run on %s — the suite is designed for Linux.\n", runtime.GOOS)
		fmt.Fprintln(os.Stderr, "  Use scripts/regress.sh to run inside the docker container.")
		fmt.Fprintln(os.Stderr, "  For dev iteration only, pass --allow-non-linux to bypass.")
		os.Exit(exitEnvError)
	}
	if err := tier1.VerifyRoot(cfg.rendrRoot); err != nil {
		fmt.Fprintln(os.Stderr, "regress: rendr-root invalid:", err)
		os.Exit(exitEnvError)
	}
	absRoot, err := filepath.Abs(cfg.rendrRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, "regress: cannot resolve rendr-root:", err)
		os.Exit(exitEnvError)
	}
	cfg.rendrRoot = absRoot

	suite := report.New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runP1, runP2 := decidePhases(cfg)

	if runP1 {
		fmt.Println("== phase 1: rendr self-check (T1+T2) ==")
		tier1.Run(ctx, suite, cfg.rendrRoot)
		tier2.Run(ctx, suite, cfg.rendrRoot)
		writeReports(suite, cfg.reportDir)
		state := gate.State{
			CommitSHA: gate.HeadCommit(),
			Status:    "green",
			At:        time.Now(),
		}
		if suite.AnyFailedAt("T1") {
			state.Status = "red"
			_ = gate.Write(cfg.reportDir, state)
			fmt.Fprintln(os.Stderr, "phase 1: T1 FAILED — phase 2 NOT entered")
			os.Exit(exitT1Fail)
		}
		if suite.AnyFailedAt("T2") {
			state.Status = "red"
			_ = gate.Write(cfg.reportDir, state)
			fmt.Fprintln(os.Stderr, "phase 1: T2 FAILED — phase 2 NOT entered")
			os.Exit(exitT2Fail)
		}
		if err := gate.Write(cfg.reportDir, state); err != nil {
			fmt.Fprintln(os.Stderr, "regress: cannot persist phase 1 state:", err)
			os.Exit(exitEnvError)
		}
		fmt.Println("phase 1: GREEN")
	}

	if runP2 {
		if !runP1 && !cfg.forcePhase2 {
			if err := gate.CheckPhase2Allowed(cfg.reportDir); err != nil {
				fmt.Fprintln(os.Stderr, "regress: phase 2 not allowed:", err)
				fmt.Fprintln(os.Stderr, "  → run `regress --phase=1` first, or pass --force-phase2 (local debug only)")
				os.Exit(exitPhase1Stale)
			}
		}
		// Default phase-2 invocation runs T3 (path-factory matrix).
		// T4 long-run and T5 fallback are opt-in via --tier=4/5
		// or included together via --full.
		runT3, runT4, runT5 := selectedTiers(cfg)
		if !runT3 && !runT4 && !runT5 {
			fmt.Fprintln(os.Stderr, "regress: invalid tier; use --tier=3, --tier=4, --tier=5, or --full")
			os.Exit(exitEnvError)
		}
		if runT3 {
			fmt.Println("== phase 2 / T3: PathFactory × xray outbound matrix ==")
			tier3.Run(ctx, suite, cfg.rendrRoot, tier3.Options{Case: cfg.caseID})
			writeReports(suite, cfg.reportDir)
			if suite.AnyFailedAt("T3") {
				fmt.Fprintln(os.Stderr, "phase 2 / T3: FAILED")
				os.Exit(exitT3Fail)
			}
			fmt.Println("phase 2 / T3: GREEN")
		}
		if runT4 {
			fmt.Println("== phase 2 / T4: long-run (1 GiB / 30 min / 100k pps) ==")
			tier4.Run(ctx, suite, cfg.rendrRoot, tier4.Options{Case: cfg.caseID})
			writeReports(suite, cfg.reportDir)
			if suite.AnyFailedAt("T4") {
				fmt.Fprintln(os.Stderr, "phase 2 / T4: FAILED")
				os.Exit(exitT4Fail)
			}
			fmt.Println("phase 2 / T4: GREEN")
		}
		if runT5 {
			fmt.Println("== phase 2 / T5: TCP fallback / adapter verification ==")
			tier5.Run(ctx, suite, cfg.rendrRoot, tier5.Options{Case: cfg.caseID})
			writeReports(suite, cfg.reportDir)
			if suite.AnyFailedAt("T5") {
				fmt.Fprintln(os.Stderr, "phase 2 / T5: FAILED")
				os.Exit(exitT5Fail)
			}
			fmt.Println("phase 2 / T5: GREEN")
		}
	}

	if !runP1 && !runP2 {
		fmt.Fprintln(os.Stderr, "regress: no phase selected; use --phase=1 or --phase=2")
		os.Exit(exitEnvError)
	}

	if suite.AnyFailed() {
		os.Exit(exitT1Fail) // shouldn't reach here because P1 fails exit earlier; safeguard
	}
	os.Exit(exitOK)
}

// decidePhases interprets --phase / --tier / default to pick which
// phases run. See docs/regression-suite.md §10.
func decidePhases(cfg runFlags) (runP1, runP2 bool) {
	switch {
	case cfg.full:
		return true, true
	case cfg.phase == "1":
		return true, false
	case cfg.phase == "2":
		return false, true
	case cfg.tier != "":
		return false, true
	default:
		return true, true
	}
}

func selectedTiers(cfg runFlags) (runT3, runT4, runT5 bool) {
	if cfg.full {
		return true, true, true
	}
	switch cfg.tier {
	case "", "3":
		return true, false, false
	case "4":
		return false, true, false
	case "5":
		return false, false, true
	default:
		return false, false, false
	}
}

func writeReports(suite *report.Suite, dir string) {
	junit := filepath.Join(dir, "junit.xml")
	md := filepath.Join(dir, "SUMMARY.md")
	if err := suite.WriteJUnit(junit); err != nil && !errors.Is(err, os.ErrPermission) {
		fmt.Fprintln(os.Stderr, "regress: cannot write JUnit:", err)
	}
	if err := suite.WriteMarkdown(md); err != nil && !errors.Is(err, os.ErrPermission) {
		fmt.Fprintln(os.Stderr, "regress: cannot write SUMMARY.md:", err)
	}
}
