// Command regress is the one-button rendr regression suite entry point.
// It validates a registry-backed execution plan before starting any tier and
// enforces the phase-1 gate before entering phase 2.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/catalog"
	"github.com/FrankoonG/rendr/regress/internal/environment"
	"github.com/FrankoonG/rendr/regress/internal/gate"
	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/report"
	"github.com/FrankoonG/rendr/regress/internal/runplan"
	"github.com/FrankoonG/rendr/regress/internal/tier1"
	"github.com/FrankoonG/rendr/regress/internal/tier2"
	"github.com/FrankoonG/rendr/regress/internal/tier3"
	"github.com/FrankoonG/rendr/regress/internal/tier4"
	"github.com/FrankoonG/rendr/regress/internal/tier5"
	"github.com/FrankoonG/rendr/regress/internal/tier6"
	"github.com/FrankoonG/rendr/regress/internal/tier7"
	"github.com/FrankoonG/rendr/regress/internal/tier8"
	"github.com/FrankoonG/rendr/regress/internal/tunfull"
)

// Exit codes match docs/regression-suite.md section 10.
const (
	exitOK          = 0
	exitT1Fail      = 10
	exitT2Fail      = 11
	exitT3Fail      = 20
	exitT4Fail      = 21
	exitT5Fail      = 22
	exitT6Fail      = 23
	exitT7Fail      = 24
	exitT8Fail      = 25
	exitEnvError    = 50
	exitPhase1Stale = 51
)

const (
	listSchemaVersion       = 6
	invocationSchemaVersion = report.InvocationSchemaVersion
	junitReportFileName     = report.JUnitReportFileName
	markdownReportFileName  = report.MarkdownReportFileName
	jsonReportFileName      = report.JSONReportFileName
)

type runFlags struct {
	phase                  string
	tier                   string
	full                   bool
	tunFull                bool
	list                   bool
	forcePhase2            bool
	allowNonLinux          bool
	allowUnprovenContracts bool
	profile                string
	caseID                 string
	fromCaseID             string
	selectorID             string
	requestedCaseIDs       []string
	phase1Authorization    *report.Phase1Authorization
	reportDir              string
	rendrRoot              string
}

func parseFlags(args []string, stderr io.Writer) (runFlags, error) {
	var cfg runFlags
	fs := flag.NewFlagSet("regress", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.phase, "phase", "", "phase to run: 1 | 2 (default: 1 then T3)")
	fs.StringVar(&cfg.tier, "tier", "", "specific phase-2 tier: 3 | 4 | 5 | 6 | 7 | 8")
	fs.BoolVar(&cfg.full, "full", false, "run the normal T1-T8 full suite")
	fs.BoolVar(&cfg.tunFull, "tun-full", false, "run the synthetic TUN/L3-session suite (not kernel-TUN Gold)")
	fs.BoolVar(&cfg.list, "list", false, "write the selected case manifests as JSON and exit")
	fs.BoolVar(&cfg.forcePhase2, "force-phase2", false, "skip the phase-1 gate (local debug only)")
	fs.BoolVar(&cfg.allowNonLinux, "allow-non-linux", false, "bypass the Linux-only execution check")
	fs.BoolVar(&cfg.allowUnprovenContracts, "allow-unproven-contracts", false, "allow audited legacy cases with blocked manifest contracts (baseline only)")
	fs.StringVar(&cfg.profile, "profile", "", "legacy T3 profile filter (unsupported; use --case)")
	fs.StringVar(&cfg.caseID, "case", "", "run exactly one globally registered case")
	fs.StringVar(&cfg.fromCaseID, "from-case", "", "resume inclusively from a registered case")
	fs.StringVar(&cfg.selectorID, "selector", "", "expand one registered compatibility selector")
	fs.StringVar(&cfg.reportDir, "report-dir", "reports", "directory for JUnit, summary, and gate state")
	fs.StringVar(&cfg.rendrRoot, "rendr-root", "..", "path to the rendr repository root")
	if err := fs.Parse(args); err != nil {
		return runFlags{}, err
	}
	if fs.NArg() != 0 {
		return runFlags{}, fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}
	return cfg, nil
}

type preparedCommand struct {
	normal *runplan.Plan
	tun    *tunSelection
	list   *listDocument
}

type invocationReportStore struct {
	invalidate func(context.Context) error
	publish    func(context.Context, *report.Suite) error
	verify     func(context.Context) (report.VerifiedSet, error)
}

func reportStoreForLease(lease *report.ReportSetLease) invocationReportStore {
	return invocationReportStore{
		invalidate: lease.Invalidate,
		publish:    lease.Publish,
		verify:     lease.Verify,
	}
}

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr))
}

func runCLI(args []string, stdout, stderr io.Writer) int {
	cfg, err := parseFlags(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		fmt.Fprintln(stderr, "regress:", err)
		return exitEnvError
	}

	prepared, err := prepareCommand(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "regress:", err)
		return exitEnvError
	}
	if prepared.list != nil {
		if err := writeList(stdout, *prepared.list); err != nil {
			fmt.Fprintln(stderr, "regress: cannot write case manifest:", err)
			return exitEnvError
		}
		return exitOK
	}

	if runtime.GOOS != "linux" && !cfg.allowNonLinux {
		fmt.Fprintf(stderr, "regress: refusing to run on %s; the suite is designed for Linux.\n", runtime.GOOS)
		fmt.Fprintln(stderr, "  Use the Linux regression host, or pass --allow-non-linux for local iteration.")
		return exitEnvError
	}
	root, err := resolveRendrRoot(cfg.rendrRoot)
	if err != nil {
		fmt.Fprintln(stderr, "regress: rendr-root invalid:", err)
		return exitEnvError
	}
	cfg.rendrRoot = root

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		// Restore default signal handling after the first signal so a second
		// signal can force termination even if cleanup is blocked.
		stop()
	}()
	if prepared.tun != nil {
		return executeTUN(ctx, cfg, *prepared.tun, stdout, stderr)
	}
	return executeNormal(ctx, cfg, *prepared.normal, stdout, stderr)
}

func prepareCommand(cfg runFlags) (preparedCommand, error) {
	if err := validateFlagCombinations(cfg); err != nil {
		return preparedCommand{}, err
	}
	normalSpecs, tunCatalog, err := loadCatalogs()
	if err != nil {
		return preparedCommand{}, err
	}
	suiteName, err := resolveCommandSuite(cfg, normalSpecs, tunCatalog)
	if err != nil {
		return preparedCommand{}, err
	}

	if cfg.list {
		doc, err := buildListDocument(cfg, suiteName, normalSpecs, tunCatalog)
		if err != nil {
			return preparedCommand{}, err
		}
		return preparedCommand{list: &doc}, nil
	}
	if suiteName == manifest.SuiteTUN {
		selection, err := tunCatalog.selectCases(cfg.caseID, cfg.fromCaseID, cfg.selectorID)
		if err != nil {
			return preparedCommand{}, fmt.Errorf("TUN run plan: %w", err)
		}
		return preparedCommand{tun: &selection}, nil
	}

	plan, err := runplan.Build(runplan.Request{
		Phase:    cfg.phase,
		Tier:     cfg.tier,
		Full:     cfg.full,
		Case:     cfg.caseID,
		FromCase: cfg.fromCaseID,
	})
	if err != nil {
		return preparedCommand{}, err
	}
	if cfg.forcePhase2 && !plan.HasPhase2() {
		return preparedCommand{}, errors.New("--force-phase2 requires a plan that enters phase 2")
	}
	return preparedCommand{normal: &plan}, nil
}

func validateFlagCombinations(cfg runFlags) error {
	filters := 0
	for _, value := range []string{cfg.caseID, cfg.fromCaseID, cfg.selectorID} {
		if value != "" {
			filters++
		}
	}
	if filters > 1 {
		return errors.New("--case, --from-case, and --selector are mutually exclusive")
	}
	if cfg.full && cfg.tunFull {
		return errors.New("--full and --tun-full are mutually exclusive")
	}
	if cfg.full && filters != 0 {
		return errors.New("--full cannot be combined with --case, --from-case, or --selector; use a standalone filter for targeted execution")
	}
	if cfg.tunFull && cfg.phase != "" {
		return errors.New("--tun-full cannot be combined with --phase")
	}
	if cfg.tunFull && cfg.tier != "" {
		return errors.New("--tun-full cannot be combined with --tier")
	}
	if cfg.phase == "1" && cfg.forcePhase2 {
		return errors.New("--force-phase2 cannot be combined with --phase=1")
	}
	if cfg.list && cfg.forcePhase2 {
		return errors.New("--force-phase2 cannot be combined with --list")
	}
	if cfg.list && cfg.allowUnprovenContracts {
		return errors.New("--allow-unproven-contracts cannot be combined with --list")
	}
	if cfg.profile != "" {
		return errors.New("--profile is not supported by the registered case runners; use --case")
	}
	return nil
}

func loadCatalogs() ([]manifest.Spec, tunCatalog, error) {
	if err := catalog.Validate(); err != nil {
		return nil, tunCatalog{}, fmt.Errorf("normal catalog validation failed: %w", err)
	}
	normalSpecs := catalog.NormalFull()
	if len(normalSpecs) == 0 {
		return nil, tunCatalog{}, errors.New("normal catalog is empty")
	}
	tunCases, err := buildTUNCatalog(tunfull.Specs(), tunfull.Aliases())
	if err != nil {
		return nil, tunCatalog{}, err
	}
	if err := validateGlobalCatalogNames(normalSpecs, tunCases); err != nil {
		return nil, tunCatalog{}, err
	}
	return normalSpecs, tunCases, nil
}

func validateGlobalCatalogNames(normalSpecs []manifest.Spec, tunCases tunCatalog) error {
	all := append(append([]manifest.Spec(nil), normalSpecs...), tunCases.specs...)
	if err := manifest.ValidateCensus(all); err != nil {
		return fmt.Errorf("global catalog validation failed: %w", err)
	}
	normalIDs := make(map[string]bool, len(normalSpecs))
	for _, spec := range normalSpecs {
		normalIDs[spec.ID] = true
	}
	for _, alias := range tunCases.aliases {
		if normalIDs[alias.ID] {
			return fmt.Errorf("global catalog validation failed: TUN selector %q collides with a normal executable case", alias.ID)
		}
	}
	return nil
}

func resolveCommandSuite(cfg runFlags, normalSpecs []manifest.Spec, tunCatalog tunCatalog) (string, error) {
	if cfg.selectorID != "" {
		if cfg.phase != "" || cfg.tier != "" {
			return "", errors.New("--selector cannot be combined with --phase or --tier")
		}
		if !tunCatalog.hasSelector(cfg.selectorID) {
			if _, ok := findManifestSpec(normalSpecs, cfg.selectorID); ok || tunCatalog.hasCase(cfg.selectorID) {
				return "", fmt.Errorf("--selector=%q names an executable CaseID, not a compatibility selector; use --case", cfg.selectorID)
			}
			return "", fmt.Errorf("no compatibility selector matched --selector=%q", cfg.selectorID)
		}
		return manifest.SuiteTUN, nil
	}

	filterName, filterID := "", ""
	if cfg.caseID != "" {
		filterName, filterID = "--case", cfg.caseID
	} else if cfg.fromCaseID != "" {
		filterName, filterID = "--from-case", cfg.fromCaseID
	}
	if filterID == "" {
		if cfg.tunFull {
			return manifest.SuiteTUN, nil
		}
		return manifest.SuiteNormal, nil
	}
	if tunCatalog.hasSelector(filterID) {
		return "", fmt.Errorf("%s=%q is a compatibility selector, not an executable CaseID; use --selector", filterName, filterID)
	}
	_, normal := findManifestSpec(normalSpecs, filterID)
	tun := tunCatalog.hasCase(filterID)
	if normal == tun {
		if normal {
			return "", fmt.Errorf("globally ambiguous executable CaseID %q", filterID)
		}
		return "", fmt.Errorf("manifest: no case matched %s=%q", filterName, filterID)
	}
	if normal {
		if cfg.tunFull {
			return "", fmt.Errorf("%s=%q belongs to the normal suite, not --tun-full", filterName, filterID)
		}
		return manifest.SuiteNormal, nil
	}
	if cfg.phase != "" || cfg.tier != "" {
		return "", fmt.Errorf("%s=%q belongs to the TUN suite and cannot be combined with --phase or --tier", filterName, filterID)
	}
	return manifest.SuiteTUN, nil
}

func findManifestSpec(specs []manifest.Spec, id string) (manifest.Spec, bool) {
	for _, spec := range specs {
		if spec.ID == id {
			return spec, true
		}
	}
	return manifest.Spec{}, false
}

func resolveRendrRoot(root string) (string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve %q: %w", root, err)
	}
	absRoot = filepath.Clean(absRoot)
	if err := tier1.VerifyRoot(absRoot); err != nil {
		return "", err
	}
	return absRoot, nil
}

type tierSelection struct {
	Case     string
	FromCase string
}

type tierCommand struct {
	tier     string
	title    string
	exitCode int
	run      func(context.Context, *report.Suite, string, tierSelection)
}

var tierCommands = map[string]tierCommand{
	"T1": {
		tier: "T1", title: "phase 1 / T1: contracts, unit, race, and static gates", exitCode: exitT1Fail,
		run: func(ctx context.Context, suite *report.Suite, root string, selection tierSelection) {
			tier1.RunWithOptions(ctx, suite, root, tier1.Options{Case: selection.Case, FromCase: selection.FromCase})
		},
	},
	"T2": {
		tier: "T2", title: "phase 1 / T2: rendr smoke contracts", exitCode: exitT2Fail,
		run: func(ctx context.Context, suite *report.Suite, root string, selection tierSelection) {
			tier2.RunWithOptions(ctx, suite, root, tier2.Options{Case: selection.Case, FromCase: selection.FromCase})
		},
	},
	"T3": {
		tier: "T3", title: "phase 2 / T3: PathFactory x xray outbound matrix", exitCode: exitT3Fail,
		run: func(ctx context.Context, suite *report.Suite, root string, selection tierSelection) {
			tier3.Run(ctx, suite, root, tier3.Options{Case: selection.Case, FromCase: selection.FromCase})
		},
	},
	"T4": {
		tier: "T4", title: "phase 2 / T4: long-run and release loads", exitCode: exitT4Fail,
		run: func(ctx context.Context, suite *report.Suite, root string, selection tierSelection) {
			tier4.Run(ctx, suite, root, tier4.Options{Case: selection.Case, FromCase: selection.FromCase})
		},
	},
	"T5": {
		tier: "T5", title: "phase 2 / T5: TCP fallback and adapters", exitCode: exitT5Fail,
		run: func(ctx context.Context, suite *report.Suite, root string, selection tierSelection) {
			tier5.Run(ctx, suite, root, tier5.Options{Case: selection.Case, FromCase: selection.FromCase})
		},
	},
	"T6": {
		tier: "T6", title: "phase 2 / T6: selector target graph", exitCode: exitT6Fail,
		run: func(ctx context.Context, suite *report.Suite, root string, selection tierSelection) {
			tier6.Run(ctx, suite, root, tier6.Options{Case: selection.Case, FromCase: selection.FromCase})
		},
	},
	"T7": {
		tier: "T7", title: "phase 2 / T7: TUN ingress and L3 identity", exitCode: exitT7Fail,
		run: func(ctx context.Context, suite *report.Suite, root string, selection tierSelection) {
			tier7.Run(ctx, suite, root, tier7.Options{Case: selection.Case, FromCase: selection.FromCase})
		},
	},
	"T8": {
		tier: "T8", title: "phase 2 / T8: runtime status, identity, and recovery", exitCode: exitT8Fail,
		run: func(ctx context.Context, suite *report.Suite, root string, selection tierSelection) {
			tier8.Run(ctx, suite, root, tier8.Options{Case: selection.Case, FromCase: selection.FromCase})
		},
	},
}

var phase1SpecsProvider = loadCanonicalPhase1Specs

func executeNormal(ctx context.Context, cfg runFlags, plan runplan.Plan, stdout, stderr io.Writer) (exitCode int) {
	if plan.CompletePhase1 && plan.HasPhase2() && cfg.allowUnprovenContracts && !cfg.forcePhase2 {
		fmt.Fprintln(stderr, "regress: a combined unproven baseline cannot authorize its own phase 2; rerun with --force-phase2 for audited baseline collection")
		return exitPhase1Stale
	}
	selected, err := specsForPlan(plan, catalog.ByTier)
	if err != nil {
		fmt.Fprintln(stderr, "regress: cannot resolve selected manifest:", err)
		return exitEnvError
	}
	if err := requireContractProofOptIn(selected, cfg.allowUnprovenContracts); err != nil {
		fmt.Fprintln(stderr, "regress:", err)
		return exitEnvError
	}
	lease, err := report.AcquireReportSetLease(ctx, cfg.reportDir)
	if err != nil {
		fmt.Fprintln(stderr, "regress: cannot acquire report invocation lease:", err)
		return exitEnvError
	}
	defer func() {
		if err := lease.Close(); err != nil {
			fmt.Fprintln(stderr, "regress: cannot release report invocation lease:", err)
			exitCode = exitEnvError
		}
	}()
	reportStore := reportStoreForLease(lease)
	if requiresExistingPhase1Gate(plan) && !cfg.forcePhase2 {
		authorization, err := verifyPhase1Gate(ctx, cfg.reportDir, cfg.rendrRoot)
		if err != nil {
			fmt.Fprintln(stderr, "regress: phase 2 not allowed:", err)
			fmt.Fprintln(stderr, "  Run a complete phase 1 first, or pass --force-phase2 for local debugging.")
			return exitPhase1Stale
		}
		cfg.phase1Authorization = &authorization
	}
	suite, revisionStart, err := beginInvocation(
		ctx,
		cfg,
		manifest.SuiteNormal,
		selected,
		gate.CurrentRevision,
		environment.Capture,
		reportStore,
	)
	if err != nil {
		fmt.Fprintln(stderr, "regress: cannot initialize invocation report:", err)
		return exitEnvError
	}

	if plan.CompletePhase1 {
		if err := writeKnownPhase1Gate(cfg.reportDir, revisionStart, "running", time.Now()); err != nil {
			persistInvocationFailure(ctx, suite, cfg, revisionStart, selected, "cannot invalidate prior phase 1 gate: "+err.Error(), gate.CurrentRevision, environment.Capture, reportStore, stderr)
			fmt.Fprintln(stderr, "regress: cannot invalidate prior phase 1 gate:", err)
			return exitEnvError
		}
	}

	for i, run := range plan.Runs {
		command, ok := tierCommands[run.Tier]
		if !ok {
			persistInvocationFailure(ctx, suite, cfg, revisionStart, selected, "execution plan contains unknown tier "+run.Tier, gate.CurrentRevision, environment.Capture, reportStore, stderr)
			fmt.Fprintf(stderr, "regress: execution plan contains unknown tier %q\n", run.Tier)
			return exitEnvError
		}
		fmt.Fprintf(stdout, "== %s ==\n", command.title)
		expected, err := specsForTierRun(run)
		if err != nil {
			persistInvocationFailure(ctx, suite, cfg, revisionStart, selected, "cannot resolve planned cases: "+err.Error(), gate.CurrentRevision, environment.Capture, reportStore, stderr)
			fmt.Fprintln(stderr, "regress: cannot resolve planned cases:", err)
			return exitEnvError
		}
		before := len(suite.Cases)
		command.run(ctx, suite, cfg.rendrRoot, tierSelection{Case: run.Case, FromCase: run.FromCase})
		reconcileErr := reconcileReportRows(expected, suite.Cases[before:])
		if reconcileErr != nil {
			suite.FailRun(run.Tier + " manifest reconciliation failed: " + reconcileErr.Error())
		}
		environmentErr := updateInvocationEnvironment(ctx, suite, environment.Capture)
		if environmentErr != nil {
			suite.FailRun(environmentErr.Error())
		}
		revisionErr := updateInvocationRevision(suite, cfg.rendrRoot, revisionStart, gate.CurrentRevision)
		if revisionErr != nil {
			suite.FailRun(revisionErr.Error())
		}
		blocker, aborted := invocationAbortBlocker(ctx, suite, reconcileErr, environmentErr, revisionErr)
		if aborted {
			if finalErr := finalizeAbortedInvocation(selected, suite, blocker); finalErr != nil {
				suite.FailRun("cannot project aborted invocation: " + finalErr.Error())
			}
		} else {
			suite.Complete = i == len(plan.Runs)-1
		}
		publishCtx, cancelPublish := reportPublicationContext(ctx)
		publishErr := reportStore.publish(publishCtx, suite)
		cancelPublish()
		if publishErr != nil {
			fmt.Fprintf(stderr, "regress: cannot write %s reports: %v\n", run.Tier, publishErr)
			return exitEnvError
		}
		if ctx.Err() != nil {
			if isPhase1Tier(run.Tier) {
				writeRedPhase1Gate(cfg, stderr)
			}
			fmt.Fprintln(stderr, "regress: invocation canceled:", ctx.Err())
			return exitEnvError
		}
		if revisionErr != nil {
			if isPhase1Tier(run.Tier) {
				writeRedPhase1Gate(cfg, stderr)
			}
			fmt.Fprintln(stderr, "regress: invocation revision changed:", revisionErr)
			return exitPhase1Stale
		}
		if environmentErr != nil {
			if isPhase1Tier(run.Tier) {
				writeRedPhase1Gate(cfg, stderr)
			}
			fmt.Fprintln(stderr, "regress: invocation environment invalid:", environmentErr)
			return exitEnvError
		}
		if reconcileErr != nil || suite.AnyFailed() {
			if isPhase1Tier(run.Tier) {
				writeRedPhase1Gate(cfg, stderr)
			}
			fmt.Fprintf(stderr, "%s: FAILED\n", run.Tier)
			return command.exitCode
		}
		fmt.Fprintf(stdout, "%s: %s\n", run.Tier, contractResultLabel(suite))

		if isLastPhase1Run(plan.Runs, i) {
			if shouldWriteGreenPhase1Gate(plan) && !cfg.allowUnprovenContracts && !cfg.allowNonLinux {
				phase1Specs, err := phase1SpecsProvider()
				if err != nil {
					writeRedPhase1Gate(cfg, stderr)
					fmt.Fprintln(stderr, "regress: phase 1 manifest resolution failed:", err)
					return exitEnvError
				}
				proofSuite, err := buildPhase1ProofSuite(suite, phase1Specs)
				if err != nil {
					writeRedPhase1Gate(cfg, stderr)
					fmt.Fprintln(stderr, "regress: phase 1 proof projection failed:", err)
					return exitEnvError
				}
				verified, err := publishPhase1Proof(ctx, cfg.reportDir, proofSuite, phase1Specs)
				if err != nil {
					writeRedPhase1Gate(cfg, stderr)
					fmt.Fprintln(stderr, "regress: phase 1 proof publication failed:", err)
					return exitEnvError
				}
				if err := writeKnownPhase1Gate(cfg.reportDir, revisionStart, "green", time.Now(), verified.Manifest); err != nil {
					suite.Complete = false
					suite.FailRun("cannot persist phase 1 state: " + err.Error())
					if reportErr := reportStore.publish(ctx, suite); reportErr != nil {
						fmt.Fprintln(stderr, "regress: cannot persist invocation failure report:", reportErr)
					}
					fmt.Fprintln(stderr, "regress: cannot persist phase 1 state:", err)
					return exitEnvError
				}
				if plan.HasPhase2() {
					authorization := phase1Authorization(revisionStart, verified.Manifest)
					suite.Invocation.Phase1Authorization = &authorization
				}
				fmt.Fprintln(stdout, "phase 1: GREEN")
			} else if shouldWriteGreenPhase1Gate(plan) {
				writeRedPhase1Gate(cfg, stderr)
				fmt.Fprintln(stdout, "phase 1: UNPROVEN (green gate not written)")
			} else {
				fmt.Fprintln(stdout, "phase 1: PARTIAL (green gate unchanged)")
			}
		}
	}
	if requiresPhase1Authorization(selected) && !cfg.forcePhase2 {
		if err := verifyFinalPhase1Authorization(ctx, cfg, suite); err != nil {
			persistInvocationFailure(ctx, suite, cfg, revisionStart, selected, "final phase 1 authorization verification failed: "+err.Error(), gate.CurrentRevision, environment.Capture, reportStore, stderr)
			fmt.Fprintln(stderr, "regress: final phase 1 authorization verification failed:", err)
			return exitPhase1Stale
		}
	}
	if err := requirePassingFinalReportStore(ctx, reportStore, suite, selected); err != nil {
		persistInvocationFailure(ctx, suite, cfg, revisionStart, selected, "final report verification failed: "+err.Error(), gate.CurrentRevision, environment.Capture, reportStore, stderr)
		fmt.Fprintln(stderr, "regress:", err)
		return exitEnvError
	}
	if err := ctx.Err(); err != nil {
		persistInvocationFailure(ctx, suite, cfg, revisionStart, selected, "invocation canceled before successful return: "+err.Error(), gate.CurrentRevision, environment.Capture, reportStore, stderr)
		fmt.Fprintln(stderr, "regress: invocation canceled before successful return:", err)
		return exitEnvError
	}
	return exitOK
}

func executeTUN(ctx context.Context, cfg runFlags, selection tunSelection, stdout, stderr io.Writer) (exitCode int) {
	planned, err := tunfull.PlanCases(selection.runOrder)
	if err != nil {
		fmt.Fprintln(stderr, "regress: invalid prepared TUN plan:", err)
		return exitEnvError
	}
	expected := make([]manifest.Spec, len(planned))
	for i, plannedCase := range planned {
		expected[i] = plannedCase.Spec()
	}
	if err := requireContractProofOptIn(expected, cfg.allowUnprovenContracts); err != nil {
		fmt.Fprintln(stderr, "regress:", err)
		return exitEnvError
	}
	lease, err := report.AcquireReportSetLease(ctx, cfg.reportDir)
	if err != nil {
		fmt.Fprintln(stderr, "regress: cannot acquire report invocation lease:", err)
		return exitEnvError
	}
	defer func() {
		if err := lease.Close(); err != nil {
			fmt.Fprintln(stderr, "regress: cannot release report invocation lease:", err)
			exitCode = exitEnvError
		}
	}()
	reportStore := reportStoreForLease(lease)
	if !cfg.forcePhase2 {
		authorization, err := verifyPhase1Gate(ctx, cfg.reportDir, cfg.rendrRoot)
		if err != nil {
			fmt.Fprintln(stderr, "regress: phase 2 not allowed:", err)
			fmt.Fprintln(stderr, "  Run a complete phase 1 first, or pass --force-phase2 for local debugging.")
			return exitPhase1Stale
		}
		cfg.phase1Authorization = &authorization
	}
	cfg.requestedCaseIDs = append([]string(nil), selection.requestedOrder...)
	suite, revisionStart, err := beginInvocation(
		ctx,
		cfg,
		tunInvocationSuite,
		expected,
		gate.CurrentRevision,
		environment.Capture,
		reportStore,
	)
	if err != nil {
		fmt.Fprintln(stderr, "regress: cannot initialize TUN invocation report:", err)
		return exitEnvError
	}
	for i, plannedCase := range planned {
		spec := plannedCase.Spec()
		fmt.Fprintf(stdout, "== phase 2 / TUN synthetic L3/session: %s ==\n", spec.ID)
		before := len(suite.Cases)
		runTUNCase(ctx, suite, cfg.rendrRoot, plannedCase)
		reconcileErr := reconcileReportRows([]manifest.Spec{spec}, suite.Cases[before:])
		if reconcileErr != nil {
			suite.FailRun("TUN manifest reconciliation failed: " + reconcileErr.Error())
		}
		environmentErr := updateInvocationEnvironment(ctx, suite, environment.Capture)
		if environmentErr != nil {
			suite.FailRun(environmentErr.Error())
		}
		revisionErr := updateInvocationRevision(suite, cfg.rendrRoot, revisionStart, gate.CurrentRevision)
		if revisionErr != nil {
			suite.FailRun(revisionErr.Error())
		}
		blocker, aborted := invocationAbortBlocker(ctx, suite, reconcileErr, environmentErr, revisionErr)
		if aborted {
			if finalErr := finalizeAbortedInvocation(expected, suite, blocker); finalErr != nil {
				suite.FailRun("TUN final manifest reconciliation failed: " + finalErr.Error())
			}
		} else {
			suite.Complete = i == len(expected)-1
		}
		publishCtx, cancelPublish := reportPublicationContext(ctx)
		publishErr := reportStore.publish(publishCtx, suite)
		cancelPublish()
		if publishErr != nil {
			fmt.Fprintln(stderr, "regress: cannot write TUN reports:", publishErr)
			return exitEnvError
		}
		if ctx.Err() != nil {
			fmt.Fprintln(stderr, "regress: TUN invocation canceled:", ctx.Err())
			return exitEnvError
		}
		if revisionErr != nil {
			fmt.Fprintln(stderr, "regress: TUN invocation revision changed:", revisionErr)
			return exitPhase1Stale
		}
		if environmentErr != nil {
			fmt.Fprintln(stderr, "regress: TUN invocation environment invalid:", environmentErr)
			return exitEnvError
		}
		if aborted {
			fmt.Fprintln(stderr, "phase 2 / TUN synthetic L3/session: FAILED")
			return exitT7Fail
		}
	}
	if !cfg.forcePhase2 {
		if err := verifyFinalPhase1Authorization(ctx, cfg, suite); err != nil {
			persistInvocationFailure(ctx, suite, cfg, revisionStart, expected, "final phase 1 authorization verification failed: "+err.Error(), gate.CurrentRevision, environment.Capture, reportStore, stderr)
			fmt.Fprintln(stderr, "regress: final phase 1 authorization verification failed:", err)
			return exitPhase1Stale
		}
	}
	if err := requirePassingFinalReportStore(ctx, reportStore, suite, expected); err != nil {
		persistInvocationFailure(ctx, suite, cfg, revisionStart, expected, "final report verification failed: "+err.Error(), gate.CurrentRevision, environment.Capture, reportStore, stderr)
		fmt.Fprintln(stderr, "regress:", err)
		return exitEnvError
	}
	if err := ctx.Err(); err != nil {
		persistInvocationFailure(ctx, suite, cfg, revisionStart, expected, "TUN invocation canceled before successful return: "+err.Error(), gate.CurrentRevision, environment.Capture, reportStore, stderr)
		fmt.Fprintln(stderr, "regress: TUN invocation canceled before successful return:", err)
		return exitEnvError
	}
	fmt.Fprintf(stdout, "phase 2 / TUN synthetic L3/session: %s (kernel TUN Gold remains separate)\n", contractResultLabel(suite))
	return exitOK
}

func isPhase1Tier(tier string) bool {
	return tier == "T1" || tier == "T2"
}

func isLastPhase1Run(runs []runplan.TierRun, index int) bool {
	if index < 0 || index >= len(runs) || !isPhase1Tier(runs[index].Tier) {
		return false
	}
	return index+1 == len(runs) || !isPhase1Tier(runs[index+1].Tier)
}

func shouldWriteGreenPhase1Gate(plan runplan.Plan) bool {
	return plan.CompletePhase1
}

func containsSelectedPhase1(plan runplan.Plan) bool {
	for _, run := range plan.Runs {
		if isPhase1Tier(run.Tier) {
			return true
		}
	}
	return false
}

func requiresExistingPhase1Gate(plan runplan.Plan) bool {
	return plan.HasPhase2() && !plan.CompletePhase1
}

func writeRedPhase1Gate(cfg runFlags, stderr io.Writer) {
	if err := writePhase1Gate(cfg.reportDir, cfg.rendrRoot, "red"); err != nil {
		// Preserve the tier-specific failure code after the report was written.
		fmt.Fprintln(stderr, "regress: warning: cannot persist red phase 1 state:", err)
	}
}

func writePhase1Gate(reportDir, rendrRoot, status string) error {
	state, err := buildPhase1State(rendrRoot, status, time.Now(), gate.CurrentRevision)
	if err != nil {
		return err
	}
	return gate.Write(reportDir, state)
}

func verifyPhase1Gate(ctx context.Context, reportDir, rendrRoot string) (report.Phase1Authorization, error) {
	if err := gate.CheckPhase2Allowed(reportDir, rendrRoot); err != nil {
		return report.Phase1Authorization{}, err
	}
	state, err := gate.Read(reportDir)
	if err != nil {
		return report.Phase1Authorization{}, fmt.Errorf("read phase 1 state: %w", err)
	}
	verified, err := report.Verify(ctx, phase1ProofDir(reportDir, state.ReportSetGeneration))
	if err != nil {
		return report.Phase1Authorization{}, fmt.Errorf("verify phase 1 report set: %w", err)
	}
	phase1Specs, err := phase1SpecsProvider()
	if err != nil {
		return report.Phase1Authorization{}, fmt.Errorf("resolve canonical phase 1 manifest: %w", err)
	}
	if err := validatePhase1Proof(*state, verified, phase1Specs); err != nil {
		return report.Phase1Authorization{}, err
	}
	return phase1Authorization(gate.Revision{CommitSHA: state.CommitSHA, WorktreeSHA: state.WorktreeSHA}, verified.Manifest), nil
}

func phase1Authorization(revision gate.Revision, proof report.SetManifest) report.Phase1Authorization {
	return report.Phase1Authorization{
		CommitSHA: revision.CommitSHA, WorktreeSHA: revision.WorktreeSHA,
		ReportSetGeneration: proof.Generation, CanonicalReportDigest: proof.CanonicalReportDigest,
	}
}

func verifyFinalPhase1Authorization(ctx context.Context, cfg runFlags, suite *report.Suite) error {
	authorization, err := verifyPhase1Gate(ctx, cfg.reportDir, cfg.rendrRoot)
	if err != nil {
		return err
	}
	if suite == nil || suite.Invocation.Phase1Authorization == nil {
		return errors.New("final report is missing phase-1 authorization")
	}
	if *suite.Invocation.Phase1Authorization != authorization {
		return errors.New("final report phase-1 authorization does not match the current gate proof")
	}
	return nil
}

func loadCanonicalPhase1Specs() ([]manifest.Spec, error) {
	plan, err := runplan.Build(runplan.Request{Phase: "1"})
	if err != nil {
		return nil, err
	}
	return specsForPlan(plan, catalog.ByTier)
}

func buildPhase1ProofSuite(source *report.Suite, expected []manifest.Spec) (*report.Suite, error) {
	if source == nil {
		return nil, errors.New("cannot project phase 1 proof from a nil suite")
	}
	if source.RunFailure != "" {
		return nil, errors.New("cannot project phase 1 proof from a failed invocation")
	}
	if len(source.Cases) != len(expected) {
		return nil, fmt.Errorf("phase 1 proof row count is %d, want %d", len(source.Cases), len(expected))
	}
	identity, err := buildInvocationIdentity(runFlags{phase: "1"}, manifest.SuiteNormal, expected)
	if err != nil {
		return nil, fmt.Errorf("build canonical phase 1 identity: %w", err)
	}
	identity.EnvironmentStart = source.Invocation.EnvironmentStart
	identity.EnvironmentEnd = source.Invocation.EnvironmentEnd
	identity.RevisionStart = source.Invocation.RevisionStart
	identity.RevisionEnd = source.Invocation.RevisionEnd
	proof := &report.Suite{
		Started:    source.Started,
		Invocation: identity,
		Cases:      cloneReportCases(source.Cases),
		Complete:   true,
	}
	if err := reconcileReportRows(expected, proof.Cases); err != nil {
		return nil, fmt.Errorf("reconcile canonical phase 1 rows: %w", err)
	}
	if proof.AnyFailed() {
		return nil, errors.New("canonical phase 1 projection contains a failing row")
	}
	if _, err := proof.ReportDigest(); err != nil {
		return nil, fmt.Errorf("seal canonical phase 1 proof: %w", err)
	}
	return proof, nil
}

func validatePhase1Proof(state gate.State, verified report.VerifiedSet, expected []manifest.Spec) error {
	if state.ReportSetGeneration != verified.Manifest.Generation {
		return fmt.Errorf("phase 1 report generation mismatch: gate=%s report=%s", state.ReportSetGeneration, verified.Manifest.Generation)
	}
	if state.CanonicalReportDigest != verified.Manifest.CanonicalReportDigest {
		return fmt.Errorf("phase 1 report digest mismatch: gate=%s report=%s", state.CanonicalReportDigest, verified.Manifest.CanonicalReportDigest)
	}
	if !verified.Report.Complete || verified.Report.State != "pass" {
		return fmt.Errorf("phase 1 report is not proven passing evidence: state=%s complete=%t", verified.Report.State, verified.Report.Complete)
	}
	invocation := verified.Report.Invocation
	if invocation.SchemaVersion != invocationSchemaVersion {
		return fmt.Errorf("phase 1 invocation schema is %d, want %d", invocation.SchemaVersion, invocationSchemaVersion)
	}
	if invocation.Suite != manifest.SuiteNormal || invocation.Scope != "phase-1" || invocation.Phase != "1" {
		return fmt.Errorf("phase 1 proof has wrong identity: suite=%q scope=%q phase=%q", invocation.Suite, invocation.Scope, invocation.Phase)
	}
	if invocation.Full || invocation.TUNFull || invocation.Forced || invocation.AllowNonLinux || invocation.AllowUnprovenContracts || invocation.ReleaseManifest {
		return fmt.Errorf("phase 1 proof contains forbidden bypass flags: full=%t tun_full=%t forced=%t non_linux=%t unproven=%t release=%t",
			invocation.Full, invocation.TUNFull, invocation.Forced, invocation.AllowNonLinux, invocation.AllowUnprovenContracts, invocation.ReleaseManifest)
	}
	if !invocation.ContractProofRequired {
		return errors.New("phase 1 proof does not require contract evidence")
	}
	if invocation.Case != "" || invocation.Selector != "" || invocation.FromCase != "" || invocation.Tier != "" {
		return errors.New("phase 1 proof contains a scoped or filtered request identity")
	}
	if invocation.RevisionStart.CommitSHA != state.CommitSHA || invocation.RevisionStart.WorktreeSHA != state.WorktreeSHA ||
		invocation.RevisionEnd != invocation.RevisionStart {
		return errors.New("phase 1 proof revision does not match the gate revision")
	}
	if invocation.EnvironmentStart.Runtime.GOOS != "linux" || invocation.EnvironmentEnd.Runtime.GOOS != "linux" {
		return errors.New("phase 1 proof was not captured on Linux")
	}
	wantManifestDigest, err := selectedManifestDigest(expected)
	if err != nil {
		return fmt.Errorf("digest canonical phase 1 manifest: %w", err)
	}
	wantCatalogDigest, err := suiteRegistryDigest(manifest.SuiteNormal)
	if err != nil {
		return fmt.Errorf("digest canonical normal catalog: %w", err)
	}
	wantIDs := manifestIDs(expected)
	if invocation.ManifestDigest != wantManifestDigest || invocation.CatalogDigest != wantCatalogDigest ||
		invocation.SelectedCases != len(wantIDs) || !equalStrings(invocation.SelectedCaseIDs, wantIDs) {
		return errors.New("phase 1 proof does not match the canonical T1+T2 manifest")
	}
	if len(wantIDs) == 0 || invocation.ResumeCaseID != wantIDs[0] || invocation.RequestAnchor != wantIDs[0] ||
		!equalStrings(invocation.RequestedCaseIDs, wantIDs) {
		return errors.New("phase 1 proof has an invalid resume identity")
	}
	rows := cloneReportCases(verified.Report.Cases)
	for i, spec := range expected {
		if spec.Contract == nil || spec.Contract.State != manifest.ContractStateEnforced {
			return fmt.Errorf("canonical phase 1 contract %q is not enforced", spec.ID)
		}
		digest, err := spec.CanonicalDigest()
		if err != nil {
			return fmt.Errorf("digest canonical phase 1 case %q: %w", spec.ID, err)
		}
		if rows[i].CaseDigest != digest {
			return fmt.Errorf("phase 1 case %q digest mismatch", spec.ID)
		}
		if rows[i].Evidence[report.EvidenceContractStateKey] != string(manifest.ContractStateEnforced) {
			return fmt.Errorf("phase 1 case %q lacks enforced contract evidence", spec.ID)
		}
	}
	if err := reconcileReportRows(expected, rows); err != nil {
		return fmt.Errorf("revalidate persisted phase 1 contract evidence: %w", err)
	}
	return nil
}

func cloneReportCases(source []report.Case) []report.Case {
	cloned := make([]report.Case, len(source))
	for i, row := range source {
		cloned[i] = row
		if row.Evidence != nil {
			cloned[i].Evidence = make(map[string]string, len(row.Evidence))
			for key, value := range row.Evidence {
				cloned[i].Evidence[key] = value
			}
		}
	}
	return cloned
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func writeKnownPhase1Gate(reportDir string, revision gate.Revision, status string, at time.Time, manifest ...report.SetManifest) error {
	if revision.CommitSHA == "" || revision.WorktreeSHA == "" {
		return errors.New("phase 1 revision identity is incomplete")
	}
	state := gate.State{
		SchemaVersion: gate.StateSchemaVersion,
		CommitSHA:     revision.CommitSHA,
		WorktreeSHA:   revision.WorktreeSHA,
		Status:        status,
		At:            at,
	}
	if len(manifest) > 1 {
		return errors.New("phase 1 state received multiple report-set manifests")
	}
	if len(manifest) == 1 {
		state.ReportSetGeneration = manifest[0].Generation
		state.CanonicalReportDigest = manifest[0].CanonicalReportDigest
	}
	return gate.Write(reportDir, state)
}

func beginInvocation(
	ctx context.Context,
	cfg runFlags,
	suiteName string,
	selected []manifest.Spec,
	currentRevision func(string) (gate.Revision, error),
	captureEnvironment func(context.Context) (environment.Snapshot, error),
	reports invocationReportStore,
) (*report.Suite, gate.Revision, error) {
	identity, err := buildInvocationIdentity(cfg, suiteName, selected)
	if err != nil {
		return nil, gate.Revision{}, err
	}
	suite := report.New()
	suite.Invocation = identity
	if err := reports.invalidate(ctx); err != nil {
		suite.FailRun("cannot invalidate stale reports: " + err.Error())
		if finalErr := finalizeAbortedInvocation(selected, suite, reasonInvocationBlocker(report.BlockerKindHarness, "report-set invalidation failed")); finalErr != nil {
			suite.FailRun("cannot project aborted invocation: " + finalErr.Error())
		}
		if writeErr := reports.publish(ctx, suite); writeErr != nil {
			return suite, gate.Revision{}, fmt.Errorf("invalidate stale reports: %v; write failure report: %w", err, writeErr)
		}
		return suite, gate.Revision{}, fmt.Errorf("invalidate stale reports: %w", err)
	}

	snapshot, captureErr := captureEnvironment(ctx)
	if captureErr != nil {
		suite.FailRun("cannot capture invocation start environment: " + captureErr.Error())
		if finalErr := finalizeAbortedInvocation(selected, suite, reasonInvocationBlocker(report.BlockerKindEnvironment, "start environment capture failed")); finalErr != nil {
			suite.FailRun("cannot project aborted invocation: " + finalErr.Error())
		}
		if writeErr := reports.publish(ctx, suite); writeErr != nil {
			return suite, gate.Revision{}, fmt.Errorf("capture invocation start environment: %v; write failure report: %w", captureErr, writeErr)
		}
		return suite, gate.Revision{}, fmt.Errorf("capture invocation start environment: %w", captureErr)
	}
	suite.Invocation.EnvironmentStart = snapshot

	revision, revisionErr := currentRevision(cfg.rendrRoot)
	if revisionErr != nil {
		suite.FailRun("cannot fingerprint invocation start: " + revisionErr.Error())
		if finalErr := finalizeAbortedInvocation(selected, suite, reasonInvocationBlocker(report.BlockerKindRevision, "start revision fingerprint failed")); finalErr != nil {
			suite.FailRun("cannot project aborted invocation: " + finalErr.Error())
		}
		if writeErr := reports.publish(ctx, suite); writeErr != nil {
			return suite, gate.Revision{}, fmt.Errorf("fingerprint invocation start: %v; invalidate stale reports: %w", revisionErr, writeErr)
		}
		return suite, gate.Revision{}, fmt.Errorf("fingerprint invocation start: %w", revisionErr)
	}
	suite.Invocation.RevisionStart = reportRevision(revision)
	publishCtx, cancelPublish := reportPublicationContext(ctx)
	defer cancelPublish()
	if err := reports.publish(publishCtx, suite); err != nil {
		return suite, gate.Revision{}, fmt.Errorf("invalidate stale reports: %w", err)
	}
	return suite, revision, nil
}

func invalidateFixedReports(dir string) error {
	return report.InvalidateSet(dir)
}

func buildInvocationIdentity(cfg runFlags, suiteName string, selected []manifest.Spec) (report.Invocation, error) {
	digest, err := selectedManifestDigest(selected)
	if err != nil {
		return report.Invocation{}, err
	}
	catalogDigest, err := suiteRegistryDigest(suiteName)
	if err != nil {
		return report.Invocation{}, err
	}
	selectedIDs := make([]string, len(selected))
	for i, spec := range selected {
		selectedIDs[i] = spec.ID
	}
	requestedIDs, requestAnchor, err := requestedInvocationIdentity(cfg, selectedIDs)
	if err != nil {
		return report.Invocation{}, err
	}
	invocation := report.Invocation{
		SchemaVersion:          invocationSchemaVersion,
		Suite:                  suiteName,
		Scope:                  invocationScope(cfg),
		Phase:                  cfg.phase,
		Tier:                   cfg.tier,
		Full:                   cfg.full,
		TUNFull:                cfg.tunFull,
		Case:                   cfg.caseID,
		Selector:               cfg.selectorID,
		FromCase:               cfg.fromCaseID,
		ResumeCaseID:           selectedIDs[0],
		Forced:                 cfg.forcePhase2,
		AllowNonLinux:          cfg.allowNonLinux,
		AllowUnprovenContracts: cfg.allowUnprovenContracts,
		ManifestDigest:         digest,
		CatalogDigest:          catalogDigest,
		SelectedCases:          len(selected),
		SelectedCaseIDs:        selectedIDs,
		RequestedCaseIDs:       requestedIDs,
		RequestAnchor:          requestAnchor,
		EvidenceClass:          invocationEvidenceClass(suiteName),
		ReleaseManifest:        false,
		ContractProofRequired:  true,
	}
	if cfg.phase1Authorization != nil {
		authorization := *cfg.phase1Authorization
		invocation.Phase1Authorization = &authorization
	}
	return invocation, nil
}

func requestedInvocationIdentity(cfg runFlags, selectedIDs []string) ([]string, string, error) {
	if len(selectedIDs) == 0 {
		return nil, "", errors.New("selected manifest is empty")
	}
	indexByID := make(map[string]int, len(selectedIDs))
	for i, id := range selectedIDs {
		indexByID[id] = i
	}
	requested := append([]string(nil), cfg.requestedCaseIDs...)
	anchor := ""
	switch {
	case cfg.selectorID != "":
		anchor = cfg.selectorID
		if len(requested) == 0 {
			requested = append([]string(nil), selectedIDs...)
		}
	case cfg.caseID != "":
		anchor = cfg.caseID
		requested = []string{cfg.caseID}
	case cfg.fromCaseID != "":
		anchor = cfg.fromCaseID
		start, ok := indexByID[cfg.fromCaseID]
		if !ok {
			return nil, "", fmt.Errorf("requested --from-case=%q is not in execution plan %v", cfg.fromCaseID, selectedIDs)
		}
		requested = append([]string(nil), selectedIDs[start:]...)
	default:
		requested = append([]string(nil), selectedIDs...)
		anchor = requested[0]
	}
	seen := make(map[string]bool, len(requested))
	lastIndex := -1
	for _, id := range requested {
		index, ok := indexByID[id]
		if !ok {
			return nil, "", fmt.Errorf("requested case %q is not in execution plan %v", id, selectedIDs)
		}
		if seen[id] || index <= lastIndex {
			return nil, "", fmt.Errorf("requested cases are duplicate or out of execution order: %v", requested)
		}
		seen[id] = true
		lastIndex = index
	}
	return requested, anchor, nil
}

func manifestIDs(specs []manifest.Spec) []string {
	ids := make([]string, len(specs))
	for i, spec := range specs {
		ids[i] = spec.ID
	}
	return ids
}

func invocationEvidenceClass(suiteName string) string {
	if suiteName == manifest.SuiteTUN || suiteName == tunInvocationSuite {
		return tunSyntheticEvidenceClass
	}
	return normalComponentEvidenceClass
}

func requireContractProofOptIn(specs []manifest.Spec, allowUnproven bool) error {
	if len(specs) == 0 {
		return errors.New("cannot evaluate contract proof policy for an empty manifest")
	}
	var blocked []string
	for _, spec := range specs {
		if spec.Contract == nil || spec.Contract.State != manifest.ContractStateEnforced {
			blocked = append(blocked, spec.ID)
		}
	}
	if len(blocked) == 0 {
		if allowUnproven {
			return errors.New("--allow-unproven-contracts is unnecessary because every selected contract is enforced")
		}
		return nil
	}
	if allowUnproven {
		suiteName := specs[0].Suite
		digest, err := suiteRegistryDigest(suiteName)
		if err != nil {
			return fmt.Errorf("verify frozen V1-M1 catalog: %w", err)
		}
		want := v1M1UnprovenCatalogDigests[suiteName]
		if want == "" || digest != want {
			return fmt.Errorf("--allow-unproven-contracts is restricted to the frozen V1-M1 catalog: suite=%s digest=%s want=%s", suiteName, digest, want)
		}
		return nil
	}
	const previewLimit = 5
	preview := blocked
	if len(preview) > previewLimit {
		preview = preview[:previewLimit]
	}
	detail := strings.Join(preview, ", ")
	if len(blocked) > len(preview) {
		detail += fmt.Sprintf(" (+%d more)", len(blocked)-len(preview))
	}
	return fmt.Errorf(
		"selected manifest contains %d unproven contract(s): %s; use --allow-unproven-contracts only for the audited V1-M1 legacy baseline",
		len(blocked), detail,
	)
}

func contractResultLabel(suite *report.Suite) string {
	proof, err := report.ContractProofState(suite)
	if err != nil {
		return "INVALID CONTRACT PROOF"
	}
	if proof == report.ContractProofUnproven {
		return "PASS (UNPROVEN CONTRACTS)"
	}
	return "GREEN"
}

func invocationScope(cfg runFlags) string {
	switch {
	case cfg.selectorID != "":
		return "selector"
	case cfg.caseID != "":
		return "exact"
	case cfg.fromCaseID != "":
		return "from-case"
	case cfg.full || cfg.tunFull:
		return "full"
	case cfg.tier != "":
		return "tier-" + cfg.tier
	case cfg.phase != "":
		return "phase-" + cfg.phase
	default:
		return "default"
	}
}

func selectedManifestDigest(selected []manifest.Spec) (string, error) {
	if err := validateSelectedManifest(selected); err != nil {
		return "", fmt.Errorf("selected manifest is invalid: %w", err)
	}
	return digestJSON("selected manifest", selected)
}

// validateSelectedManifest validates reportable rows without requiring the
// selected subset to contain prerequisite rows outside its requested scope.
func validateSelectedManifest(selected []manifest.Spec) error {
	if len(selected) == 0 {
		return errors.New("selected manifest is empty")
	}
	wantSuite := selected[0].Suite
	seen := make(map[string]bool, len(selected))
	for i, spec := range selected {
		if spec.ID == "" {
			return fmt.Errorf("case %d has empty ID", i)
		}
		if seen[spec.ID] {
			return fmt.Errorf("duplicate case ID %q", spec.ID)
		}
		seen[spec.ID] = true
		if spec.Tier == "" {
			return fmt.Errorf("case %q has empty tier", spec.ID)
		}
		if spec.Suite != manifest.SuiteNormal && spec.Suite != manifest.SuiteTUN {
			return fmt.Errorf("case %q has unsupported suite %q", spec.ID, spec.Suite)
		}
		if spec.Suite != wantSuite {
			return fmt.Errorf("case %q has suite %q, want %q", spec.ID, spec.Suite, wantSuite)
		}
		if !spec.Mandatory {
			return fmt.Errorf("case %q is not mandatory", spec.ID)
		}
		if spec.Budget <= 0 {
			return fmt.Errorf("case %q has non-positive budget %s", spec.ID, spec.Budget)
		}
		required := make(map[string]bool, len(spec.Requires))
		for _, requiredID := range spec.Requires {
			if requiredID == "" {
				return fmt.Errorf("case %q has an empty prerequisite", spec.ID)
			}
			if required[requiredID] {
				return fmt.Errorf("case %q has duplicate prerequisite %q", spec.ID, requiredID)
			}
			required[requiredID] = true
		}
		if _, err := spec.CanonicalDigest(); err != nil {
			return fmt.Errorf("case %q is not canonically digestible: %w", spec.ID, err)
		}
	}
	return nil
}

func suiteRegistryDigest(suiteName string) (string, error) {
	normalSpecs, tunCatalog, err := loadCatalogs()
	if err != nil {
		return "", err
	}
	payload := struct {
		Suite                 string          `json:"suite"`
		ContractSchemaVersion int             `json:"contract_schema_version"`
		Specs                 []manifest.Spec `json:"specs"`
		Aliases               []tunfull.Alias `json:"aliases,omitempty"`
	}{Suite: suiteName, ContractSchemaVersion: manifest.ContractSchemaVersion}
	switch suiteName {
	case manifest.SuiteNormal:
		payload.Specs = normalSpecs
	case manifest.SuiteTUN:
		payload.Specs = tunCatalog.specs
		payload.Aliases = tunCatalog.aliases
	default:
		return "", fmt.Errorf("unknown invocation suite %q", suiteName)
	}
	return digestJSON(suiteName+" registry", payload)
}

func digestJSON(label string, value any) (string, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode %s: %w", label, err)
	}
	digest := sha256.Sum256(b)
	return fmt.Sprintf("sha256:%x", digest[:]), nil
}

func reportRevision(revision gate.Revision) report.Revision {
	return report.Revision{CommitSHA: revision.CommitSHA, WorktreeSHA: revision.WorktreeSHA}
}

func updateInvocationEnvironment(
	ctx context.Context,
	suite *report.Suite,
	captureEnvironment func(context.Context) (environment.Snapshot, error),
) error {
	suite.Invocation.EnvironmentEnd = environment.Snapshot{}
	snapshot, err := captureEnvironment(ctx)
	if err != nil {
		return fmt.Errorf("capture invocation end environment: %w", err)
	}
	suite.Invocation.EnvironmentEnd = snapshot
	if err := environment.ValidatePair(suite.Invocation.EnvironmentStart, snapshot); err != nil {
		return fmt.Errorf("validate invocation environment: %w", err)
	}
	return nil
}

func updateInvocationRevision(
	suite *report.Suite,
	rendrRoot string,
	before gate.Revision,
	currentRevision func(string) (gate.Revision, error),
) error {
	after, err := currentRevision(rendrRoot)
	if err != nil {
		return fmt.Errorf("fingerprint regression invocation: %w", err)
	}
	suite.Invocation.RevisionEnd = reportRevision(after)
	if before != after {
		return fmt.Errorf(
			"worktree changed during regression invocation: before commit=%s worktree=%s, after commit=%s worktree=%s",
			before.CommitSHA, before.WorktreeSHA, after.CommitSHA, after.WorktreeSHA,
		)
	}
	return nil
}

func persistInvocationFailure(
	ctx context.Context,
	suite *report.Suite,
	cfg runFlags,
	revisionStart gate.Revision,
	expected []manifest.Spec,
	reason string,
	currentRevision func(string) (gate.Revision, error),
	captureEnvironment func(context.Context) (environment.Snapshot, error),
	reports invocationReportStore,
	stderr io.Writer,
) {
	suite.Complete = false
	suite.FailRun(reason)
	if err := finalizeAbortedInvocation(expected, suite, reasonInvocationBlocker(report.BlockerKindHarness, reason)); err != nil {
		suite.FailRun("cannot project aborted invocation: " + err.Error())
	}
	if err := updateInvocationEnvironment(ctx, suite, captureEnvironment); err != nil {
		suite.FailRun(err.Error())
	}
	if err := updateInvocationRevision(suite, cfg.rendrRoot, revisionStart, currentRevision); err != nil {
		suite.FailRun(err.Error())
	}
	publishCtx, cancelPublish := reportPublicationContext(ctx)
	defer cancelPublish()
	if err := reports.publish(publishCtx, suite); err != nil {
		fmt.Fprintln(stderr, "regress: warning: cannot persist invocation failure report:", err)
	}
}

func buildPhase1State(
	rendrRoot string,
	status string,
	at time.Time,
	currentRevision func(string) (gate.Revision, error),
) (gate.State, error) {
	revision, err := currentRevision(rendrRoot)
	if err != nil {
		return gate.State{}, fmt.Errorf("bind phase 1 revision: %w", err)
	}
	return gate.State{
		SchemaVersion: gate.StateSchemaVersion,
		CommitSHA:     revision.CommitSHA,
		WorktreeSHA:   revision.WorktreeSHA,
		Status:        status,
		At:            at,
	}, nil
}

const (
	tunKindCase                  = "case"
	tunKindCompatibilityAlias    = "compatibility_alias"
	tunKindCompatibilitySelector = "compatibility_selector"
	tunSyntheticEvidenceClass    = "synthetic_l3_session_not_kernel_tun_gold"
	normalComponentEvidenceClass = "legacy_regression_component_not_v1_release_manifest"
	tunInvocationSuite           = manifest.SuiteTUN
)

var v1M1UnprovenCatalogDigests = map[string]string{
	manifest.SuiteNormal: "sha256:134f7d28c282ab8a08f7eeaf17863cdea086b797c6e3adca4a265f748c4d9111",
	manifest.SuiteTUN:    "sha256:2c1bb1a20b0d4260e6f1e6984fdb20f453d2ddb92fc97f2ef75a66dbb92485f0",
}

type tunCatalog struct {
	specs   []manifest.Spec
	aliases []tunfull.Alias
}

type tunSelection struct {
	cases          []listedCase
	runOrder       []string
	requestedOrder []string
}

var runTUNCase = tunfull.RunPlannedCase

type tunCatalogEntry struct {
	listed        listedCase
	runIDs        []string
	retiredReason string
}

func buildTUNCatalog(specs []manifest.Spec, aliases []tunfull.Alias) (tunCatalog, error) {
	if err := manifest.ValidateCensus(specs); err != nil {
		return tunCatalog{}, fmt.Errorf("TUN catalog validation failed: %w", err)
	}
	byID := make(map[string]manifest.Spec, len(specs))
	indexByID := make(map[string]int, len(specs))
	for i, spec := range specs {
		if spec.Suite != manifest.SuiteTUN || spec.Tier != "T7" || !spec.Mandatory || spec.Budget <= 0 {
			return tunCatalog{}, fmt.Errorf("TUN registry/full mismatch: invalid executable case %+v", spec)
		}
		byID[spec.ID] = spec
		indexByID[spec.ID] = i
	}
	seenAliases := make(map[string]bool, len(aliases))
	for _, alias := range aliases {
		if alias.ID == "" || alias.Before == "" || len(alias.ExpandsTo) == 0 {
			return tunCatalog{}, fmt.Errorf("TUN registry/full mismatch: incomplete alias %+v", alias)
		}
		if _, collision := byID[alias.ID]; collision {
			return tunCatalog{}, fmt.Errorf("TUN registry/full mismatch: alias %q collides with executable case", alias.ID)
		}
		if seenAliases[alias.ID] {
			return tunCatalog{}, fmt.Errorf("TUN registry/full mismatch: duplicate alias %q", alias.ID)
		}
		seenAliases[alias.ID] = true
		if _, ok := byID[alias.Before]; !ok {
			return tunCatalog{}, fmt.Errorf("TUN registry/full mismatch: alias %q has unknown continuation %q", alias.ID, alias.Before)
		}
		if alias.ExpandsTo[0] != alias.Before {
			return tunCatalog{}, fmt.Errorf("TUN registry/full mismatch: alias %q first expansion %q must equal continuation %q", alias.ID, alias.ExpandsTo[0], alias.Before)
		}
		seenMembers := make(map[string]bool, len(alias.ExpandsTo))
		continuationIndex := indexByID[alias.Before]
		for i, member := range alias.ExpandsTo {
			_, ok := byID[member]
			if !ok {
				return tunCatalog{}, fmt.Errorf("TUN registry/full mismatch: alias %q references unknown case %q", alias.ID, member)
			}
			if seenMembers[member] {
				return tunCatalog{}, fmt.Errorf("TUN registry/full mismatch: alias %q repeats case %q", alias.ID, member)
			}
			seenMembers[member] = true
			if indexByID[member] != continuationIndex+i {
				return tunCatalog{}, fmt.Errorf("TUN registry/full mismatch: alias %q expansion is not a contiguous canonical suffix", alias.ID)
			}
		}
	}
	return tunCatalog{
		specs:   cloneManifestSpecs(specs),
		aliases: cloneTUNAliases(aliases),
	}, nil
}

func cloneManifestSpecs(specs []manifest.Spec) []manifest.Spec {
	return manifest.CloneSpecs(specs)
}

func cloneTUNAliases(aliases []tunfull.Alias) []tunfull.Alias {
	cloned := make([]tunfull.Alias, len(aliases))
	for i, alias := range aliases {
		cloned[i] = alias
		cloned[i].ExpandsTo = append([]string(nil), alias.ExpandsTo...)
	}
	return cloned
}

func (catalog tunCatalog) hasCase(id string) bool {
	_, ok := findManifestSpec(catalog.specs, id)
	return ok
}

func (catalog tunCatalog) hasSelector(id string) bool {
	for _, alias := range catalog.aliases {
		if alias.ID == id {
			return true
		}
	}
	return false
}

func (catalog tunCatalog) entries() ([]tunCatalogEntry, error) {
	aliasesBefore := make(map[string][]tunfull.Alias, len(catalog.aliases))
	for _, alias := range catalog.aliases {
		aliasesBefore[alias.Before] = append(aliasesBefore[alias.Before], alias)
	}
	byID := make(map[string]manifest.Spec, len(catalog.specs))
	for _, spec := range catalog.specs {
		byID[spec.ID] = spec
	}
	entries := make([]tunCatalogEntry, 0, len(catalog.specs)+len(catalog.aliases))
	for _, spec := range catalog.specs {
		for _, alias := range aliasesBefore[spec.ID] {
			long := false
			for _, member := range alias.ExpandsTo {
				long = long || byID[member].Long
			}
			kind := tunKindCompatibilityAlias
			if len(alias.ExpandsTo) > 1 {
				kind = tunKindCompatibilitySelector
			}
			entries = append(entries, tunCatalogEntry{
				listed: listedCase{
					ID: alias.ID, Tier: "T7", Suite: manifest.SuiteTUN, Phase: 2,
					Mandatory: false, Long: long, InDefaultCommand: false, InSuiteFull: false, Kind: kind,
					ExpandsTo:     append([]string(nil), alias.ExpandsTo...),
					RetiredReason: alias.RetiredReason,
				},
				runIDs:        append([]string(nil), alias.ExpandsTo...),
				retiredReason: alias.RetiredReason,
			})
		}
		listed, err := listedCaseFrom(spec, 2, false, true, tunKindCase, nil)
		if err != nil {
			return nil, err
		}
		entries = append(entries, tunCatalogEntry{
			listed: listed,
			runIDs: []string{spec.ID},
		})
	}
	return entries, nil
}

func (catalog tunCatalog) selectCases(caseID, fromCaseID, selectorID string) (tunSelection, error) {
	filters := 0
	for _, value := range []string{caseID, fromCaseID, selectorID} {
		if value != "" {
			filters++
		}
	}
	if filters > 1 {
		return tunSelection{}, errors.New("manifest: --case, --from-case, and --selector are mutually exclusive")
	}
	entries, err := catalog.entries()
	if err != nil {
		return tunSelection{}, err
	}
	if filters == 0 {
		result := tunSelection{
			cases: make([]listedCase, len(entries)), runOrder: make([]string, len(catalog.specs)),
			requestedOrder: make([]string, len(catalog.specs)),
		}
		for i, entry := range entries {
			result.cases[i] = entry.listed
		}
		for i, spec := range catalog.specs {
			result.runOrder[i] = spec.ID
			result.requestedOrder[i] = spec.ID
		}
		return catalog.withPrerequisites(result)
	}

	if selectorID != "" {
		for _, entry := range entries {
			if entry.listed.ID != selectorID || entry.listed.Kind == tunKindCase {
				continue
			}
			if entry.retiredReason != "" {
				return tunSelection{}, fmt.Errorf("manifest: compatibility selector %q is retired: %s", selectorID, entry.retiredReason)
			}
			return catalog.withPrerequisites(tunSelection{
				cases:          []listedCase{entry.listed},
				runOrder:       append([]string(nil), entry.runIDs...),
				requestedOrder: append([]string(nil), entry.runIDs...),
			})
		}
		return tunSelection{}, fmt.Errorf("manifest: no compatibility selector matched --selector=%q", selectorID)
	}

	want := caseID
	if want == "" {
		want = fromCaseID
	}
	start := -1
	for i, spec := range catalog.specs {
		if spec.ID == want {
			start = i
			break
		}
	}
	if start < 0 {
		if catalog.hasSelector(want) {
			return tunSelection{}, fmt.Errorf("manifest: %q is a compatibility selector; use --selector", want)
		}
		if caseID != "" {
			return tunSelection{}, fmt.Errorf("manifest: no case matched --case=%q", caseID)
		}
		return tunSelection{}, fmt.Errorf("manifest: no case matched --from-case=%q", fromCaseID)
	}
	end := len(catalog.specs)
	if caseID != "" {
		end = start + 1
	}
	selectedSpecs := catalog.specs[start:end]
	result := tunSelection{
		cases:          make([]listedCase, len(selectedSpecs)),
		runOrder:       make([]string, len(selectedSpecs)),
		requestedOrder: make([]string, len(selectedSpecs)),
	}
	for i, spec := range selectedSpecs {
		listed, err := listedCaseFrom(spec, 2, false, true, tunKindCase, nil)
		if err != nil {
			return tunSelection{}, err
		}
		result.cases[i] = listed
		result.runOrder[i] = spec.ID
		result.requestedOrder[i] = spec.ID
	}
	return catalog.withPrerequisites(result)
}

func (catalog tunCatalog) withPrerequisites(selection tunSelection) (tunSelection, error) {
	selected, err := tunSpecsForRunOrder(catalog.specs, selection.runOrder)
	if err != nil {
		return tunSelection{}, err
	}
	expanded, err := manifest.WithPrerequisites(catalog.specs, selected)
	if err != nil {
		return tunSelection{}, fmt.Errorf("expand TUN prerequisites: %w", err)
	}
	selection.runOrder = make([]string, len(expanded))
	for i, spec := range expanded {
		selection.runOrder[i] = spec.ID
	}
	return selection, nil
}

type listDocument struct {
	SchemaVersion int           `json:"schema_version"`
	Catalogs      []listCatalog `json:"catalogs"`
}

type listCatalog struct {
	Suite                  string       `json:"suite"`
	EvidenceClass          string       `json:"evidence_class,omitempty"`
	CatalogDigest          string       `json:"catalog_digest"`
	Cases                  []listedCase `json:"cases"`
	Selectors              []listedCase `json:"selectors,omitempty"`
	CatalogOrder           []string     `json:"catalog_order"`
	DefaultCommandRunOrder []string     `json:"default_command_run_order"`
	SuiteFullRunOrder      []string     `json:"suite_full_run_order"`
	SelectedRunOrder       []string     `json:"selected_run_order,omitempty"`
	RequestedCaseIDs       []string     `json:"requested_case_ids,omitempty"`
	RequestAnchor          string       `json:"request_anchor,omitempty"`
}

type listedCase struct {
	ID               string             `json:"id"`
	Tier             string             `json:"tier"`
	Suite            string             `json:"suite"`
	Phase            int                `json:"phase"`
	Mandatory        bool               `json:"mandatory"`
	Requires         []string           `json:"requires,omitempty"`
	Long             bool               `json:"long,omitempty"`
	Budget           time.Duration      `json:"budget_ns,omitempty"`
	InDefaultCommand bool               `json:"in_default_command"`
	InSuiteFull      bool               `json:"in_suite_full"`
	Kind             string             `json:"kind"`
	ExpandsTo        []string           `json:"expands_to,omitempty"`
	RetiredReason    string             `json:"retired_reason,omitempty"`
	CaseDigest       string             `json:"case_digest,omitempty"`
	Contract         *manifest.Contract `json:"contract,omitempty"`
}

func buildListDocument(cfg runFlags, suiteName string, normalSpecs []manifest.Spec, tunCatalog tunCatalog) (listDocument, error) {
	doc := listDocument{SchemaVersion: listSchemaVersion}
	if hasListScope(cfg) && suiteName == manifest.SuiteTUN {
		selection, err := tunCatalog.selectCases(cfg.caseID, cfg.fromCaseID, cfg.selectorID)
		if err != nil {
			return listDocument{}, fmt.Errorf("TUN list selection: %w", err)
		}
		listed, err := tunCatalog.listSelection(selection)
		if err != nil {
			return listDocument{}, fmt.Errorf("TUN list projection: %w", err)
		}
		cases, selectors, err := splitListedCases(listed)
		if err != nil {
			return listDocument{}, fmt.Errorf("TUN list projection: %w", err)
		}
		_, requestAnchor, err := requestedInvocationIdentity(runFlags{
			caseID: cfg.caseID, fromCaseID: cfg.fromCaseID, selectorID: cfg.selectorID,
			requestedCaseIDs: selection.requestedOrder,
		}, selection.runOrder)
		if err != nil {
			return listDocument{}, fmt.Errorf("TUN list request identity: %w", err)
		}
		catalogDigest, err := suiteRegistryDigest(manifest.SuiteTUN)
		if err != nil {
			return listDocument{}, err
		}
		doc.Catalogs = append(doc.Catalogs, listCatalog{
			Suite: manifest.SuiteTUN, EvidenceClass: tunSyntheticEvidenceClass,
			CatalogDigest: catalogDigest,
			Cases:         cases, Selectors: selectors, CatalogOrder: manifestIDs(tunCatalog.specs),
			DefaultCommandRunOrder: []string{}, SuiteFullRunOrder: manifestIDs(tunCatalog.specs), SelectedRunOrder: selection.runOrder,
			RequestedCaseIDs: append([]string(nil), selection.requestedOrder...), RequestAnchor: requestAnchor,
		})
		return doc, nil
	}

	if hasListScope(cfg) {
		plan, err := runplan.Build(runplan.Request{
			Phase: cfg.phase, Tier: cfg.tier, Full: cfg.full,
			Case: cfg.caseID, FromCase: cfg.fromCaseID,
		})
		if err != nil {
			return listDocument{}, err
		}
		selected, err := specsForPlan(plan, catalog.ByTier)
		if err != nil {
			return listDocument{}, err
		}
		normal, err := normalListCatalog(selected)
		if err != nil {
			return listDocument{}, err
		}
		requestedIDs, requestAnchor, err := requestedInvocationIdentity(cfg, manifestIDs(selected))
		if err != nil {
			return listDocument{}, fmt.Errorf("normal list request identity: %w", err)
		}
		normal.RequestedCaseIDs = requestedIDs
		normal.RequestAnchor = requestAnchor
		normal.SelectedRunOrder = manifestIDs(selected)
		doc.Catalogs = append(doc.Catalogs, normal)
		return doc, nil
	}

	normal, err := normalListCatalog(normalSpecs)
	if err != nil {
		return listDocument{}, err
	}
	tunSelection, err := tunCatalog.selectCases("", "", "")
	if err != nil {
		return listDocument{}, err
	}
	tunCases, tunSelectors, err := splitListedCases(tunSelection.cases)
	if err != nil {
		return listDocument{}, fmt.Errorf("TUN list projection: %w", err)
	}
	tunCatalogDigest, err := suiteRegistryDigest(manifest.SuiteTUN)
	if err != nil {
		return listDocument{}, err
	}
	doc.Catalogs = append(doc.Catalogs, normal, listCatalog{
		Suite: manifest.SuiteTUN, EvidenceClass: tunSyntheticEvidenceClass,
		CatalogDigest: tunCatalogDigest,
		Cases:         tunCases, Selectors: tunSelectors, CatalogOrder: manifestIDs(tunCatalog.specs),
		DefaultCommandRunOrder: []string{}, SuiteFullRunOrder: tunSelection.runOrder,
	})
	return doc, nil
}

func splitListedCases(entries []listedCase) ([]listedCase, []listedCase, error) {
	cases := make([]listedCase, 0, len(entries))
	selectors := make([]listedCase, 0)
	for _, entry := range entries {
		switch entry.Kind {
		case tunKindCase:
			cases = append(cases, entry)
		case tunKindCompatibilityAlias, tunKindCompatibilitySelector:
			selectors = append(selectors, entry)
		default:
			return nil, nil, fmt.Errorf("listed entry %q has unsupported kind %q", entry.ID, entry.Kind)
		}
	}
	return cases, selectors, nil
}

func (catalog tunCatalog) listSelection(selection tunSelection) ([]listedCase, error) {
	entries, err := catalog.entries()
	if err != nil {
		return nil, err
	}
	byID := make(map[string]listedCase, len(entries))
	for _, entry := range entries {
		byID[entry.listed.ID] = entry.listed
	}
	listed := make([]listedCase, 0, len(selection.runOrder)+len(selection.cases))
	seen := make(map[string]bool, cap(listed))
	for _, id := range selection.runOrder {
		entry, ok := byID[id]
		if !ok || entry.Kind != tunKindCase {
			return nil, fmt.Errorf("execution CaseID %q has no executable catalog entry", id)
		}
		listed = append(listed, entry)
		seen[id] = true
	}
	for _, requested := range selection.cases {
		if !seen[requested.ID] {
			listed = append(listed, requested)
			seen[requested.ID] = true
		}
	}
	return listed, nil
}

func hasListScope(cfg runFlags) bool {
	return cfg.phase != "" || cfg.tier != "" || cfg.full || cfg.tunFull || cfg.caseID != "" || cfg.fromCaseID != "" || cfg.selectorID != ""
}

func specsForPlan(plan runplan.Plan, byTier func(string) []manifest.Spec) ([]manifest.Spec, error) {
	var selected []manifest.Spec
	for _, run := range plan.Runs {
		tierSpecs := byTier(run.Tier)
		if len(tierSpecs) == 0 {
			return nil, fmt.Errorf("list plan references unknown or empty tier %q", run.Tier)
		}
		specs, err := manifest.SelectWithPrerequisites(tierSpecs, run.Case, run.FromCase)
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", run.Tier, err)
		}
		selected = append(selected, specs...)
	}
	if err := validateSelectedManifest(selected); err != nil {
		return nil, fmt.Errorf("selected list validation failed: %w", err)
	}
	return selected, nil
}

func specsForTierRun(run runplan.TierRun) ([]manifest.Spec, error) {
	specs := catalog.ByTier(run.Tier)
	if len(specs) == 0 {
		return nil, fmt.Errorf("unknown or empty tier %q", run.Tier)
	}
	selected, err := manifest.SelectWithPrerequisites(specs, run.Case, run.FromCase)
	if err != nil {
		return nil, fmt.Errorf("select %s: %w", run.Tier, err)
	}
	return selected, nil
}

func tunSpecsForRunOrder(specs []manifest.Spec, ids []string) ([]manifest.Spec, error) {
	byID := make(map[string]manifest.Spec, len(specs))
	for _, spec := range specs {
		byID[spec.ID] = spec
	}
	selected := make([]manifest.Spec, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if seen[id] {
			return nil, fmt.Errorf("duplicate TUN run ID %q", id)
		}
		spec, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("unknown TUN run ID %q", id)
		}
		seen[id] = true
		selected = append(selected, spec)
	}
	if len(selected) == 0 {
		return nil, errors.New("prepared TUN plan contains no executable cases")
	}
	return selected, nil
}

func reconcileReportRows(expected []manifest.Spec, actual []report.Case) error {
	if len(actual) != len(expected) {
		return fmt.Errorf("manifest/report row count mismatch: got %d, want %d", len(actual), len(expected))
	}
	seen := make(map[string]bool, len(actual))
	for i, want := range expected {
		got := actual[i]
		if seen[got.Name] {
			return fmt.Errorf("manifest/report duplicate case %q at row %d", got.Name, i)
		}
		seen[got.Name] = true
		if got.Name != want.ID {
			return fmt.Errorf("manifest/report ID mismatch at row %d: got %q, want %q", i, got.Name, want.ID)
		}
		if got.Tier != want.Tier {
			return fmt.Errorf("manifest/report tier mismatch for %q: got %q, want %q", want.ID, got.Tier, want.Tier)
		}
		if want.Mandatory && got.Optional {
			return fmt.Errorf("manifest/report mandatory case %q was downgraded to optional", want.ID)
		}
		digest, err := want.CanonicalDigest()
		if err != nil {
			return fmt.Errorf("manifest/report cannot digest case %q: %w", want.ID, err)
		}
		if got.CaseDigest != "" && got.CaseDigest != digest {
			return fmt.Errorf("manifest/report case %q digest mismatch: got %q, want %q", want.ID, got.CaseDigest, digest)
		}
		// This is the selected manifest identity, not proof that the runner
		// exercised its declared stimulus. Contract evidence facts and their
		// independent oracle remain responsible for execution truth.
		actual[i].CaseDigest = digest
		if err := reconcileContractEvidence(want, &actual[i]); err != nil {
			return fmt.Errorf("manifest/report case %q contract evidence: %w", want.ID, err)
		}
	}
	return nil
}

func reconcileContractEvidence(spec manifest.Spec, row *report.Case) error {
	if spec.Contract == nil {
		return nil
	}
	if row.Evidence == nil {
		row.Evidence = make(map[string]string)
	}
	missing, err := json.Marshal(spec.Contract.MissingDimensions)
	if err != nil {
		return fmt.Errorf("encode missing dimensions: %w", err)
	}
	row.Evidence[report.EvidenceContractStateKey] = string(spec.Contract.State)
	row.Evidence["manifest_contract_missing"] = string(missing)
	if row.ExecutionState == report.ExecutionStateNotRun || row.InvalidReason != "" || row.SkipReason != "" {
		return nil
	}
	claimAssertions, err := spec.Contract.RuntimeClaimAssertions()
	if err != nil {
		return fmt.Errorf("load structured claim bindings: %w", err)
	}
	for _, claim := range claimAssertions {
		if err := manifest.EvaluateEvidenceAssertion(claim.Assertion, row.Evidence[claim.Assertion.Fact]); err != nil {
			return fmt.Errorf("%s claim %q: %w", claim.Dimension, claim.ClaimKey, err)
		}
	}
	if row.Failure != "" {
		if err := validateEvidenceProfile("stimulus", spec.Contract.Stimulus, row.Evidence, spec.Contract.State == manifest.ContractStateEnforced); err != nil {
			row.Evidence["manifest_reported_failure"] = row.Failure
			row.Failure = ""
			row.InvalidReason = "product failure lacks valid stimulus evidence: " + err.Error()
		}
		return nil
	}
	for _, item := range []struct {
		label   string
		profile manifest.EvidenceProfile
	}{
		{label: "stimulus", profile: spec.Contract.Stimulus},
		{label: "oracle", profile: spec.Contract.Oracle},
	} {
		if item.profile.Name == "" {
			continue
		}
		if err := validateEvidenceProfile(item.label, item.profile, row.Evidence, spec.Contract.State == manifest.ContractStateEnforced); err != nil {
			return err
		}
	}
	return nil
}

func validateEvidenceProfile(label string, profile manifest.EvidenceProfile, evidence map[string]string, requireIdentity bool) error {
	if profile.Name == "" {
		return fmt.Errorf("%s evidence is not declared by this blocked contract", label)
	}
	if requireIdentity {
		nameFact := "manifest_" + label + "_profile_name"
		versionFact := "manifest_" + label + "_profile_version"
		if evidence[nameFact] != profile.Name {
			return fmt.Errorf("%s profile identity is %q, want %q", label, evidence[nameFact], profile.Name)
		}
		if evidence[versionFact] != fmt.Sprintf("%d", profile.Version) {
			return fmt.Errorf("%s profile version is %q, want %d", label, evidence[versionFact], profile.Version)
		}
	}
	for _, fact := range profile.RequiredFacts {
		if strings.TrimSpace(evidence[fact]) == "" {
			return fmt.Errorf("%s profile %q is missing required fact %q", label, profile.Name, fact)
		}
	}
	for _, assertion := range profile.Assertions {
		if err := manifest.EvaluateEvidenceAssertion(assertion, evidence[assertion.Fact]); err != nil {
			return fmt.Errorf("%s profile %q assertion: %w", label, profile.Name, err)
		}
	}
	return nil
}

type invocationBlocker struct {
	kind   report.BlockerKind
	caseID string
	reason string
}

func caseInvocationBlocker(caseID string) invocationBlocker {
	return invocationBlocker{kind: report.BlockerKindCase, caseID: caseID}
}

func reasonInvocationBlocker(kind report.BlockerKind, reason string) invocationBlocker {
	return invocationBlocker{kind: kind, reason: strings.TrimSpace(reason)}
}

func finalizeAbortedInvocation(expected []manifest.Spec, suite *report.Suite, blocker invocationBlocker) error {
	if suite == nil {
		return errors.New("cannot finalize a nil invocation")
	}
	if blocker.kind == "" {
		return errors.New("cannot finalize invocation without blocker kind")
	}
	if len(suite.Cases) > len(expected) {
		return fmt.Errorf("report has %d rows for %d selected cases", len(suite.Cases), len(expected))
	}
	for i, row := range suite.Cases {
		if row.Name != expected[i].ID {
			return fmt.Errorf("existing report row %d is %q, want %q", i, row.Name, expected[i].ID)
		}
		if row.ExecutionState == report.ExecutionStateNotRun {
			applyInvocationBlocker(&suite.Cases[i], blocker)
		}
	}
	for _, spec := range expected[len(suite.Cases):] {
		row := report.Case{
			Name:           spec.ID,
			Tier:           spec.Tier,
			ExecutionState: report.ExecutionStateNotRun,
		}
		applyInvocationBlocker(&row, blocker)
		suite.Add(row)
	}
	suite.Complete = false
	return reconcileReportRows(expected, suite.Cases)
}

func applyInvocationBlocker(row *report.Case, blocker invocationBlocker) {
	row.BlockerKind = blocker.kind
	row.BlockedByCaseID = ""
	row.BlockerReason = ""
	if blocker.kind == report.BlockerKindCase {
		row.BlockedByCaseID = blocker.caseID
		row.InvalidReason = fmt.Sprintf("not run after %s failed", blocker.caseID)
		return
	}
	row.BlockerReason = blocker.reason
	row.InvalidReason = fmt.Sprintf("not run: %s blocker: %s", blocker.kind, blocker.reason)
}

func firstFailedExecutedCaseID(cases []report.Case) string {
	for _, row := range cases {
		if row.ExecutionState == report.ExecutionStateNotRun {
			continue
		}
		if row.Failure != "" || row.InvalidReason != "" || (row.SkipReason != "" && !row.Optional) {
			return row.Name
		}
	}
	return ""
}

func invocationAbortBlocker(ctx context.Context, suite *report.Suite, reconcileErr, environmentErr, revisionErr error) (invocationBlocker, bool) {
	if err := ctx.Err(); err != nil {
		return reasonInvocationBlocker(report.BlockerKindSignal, err.Error()), true
	}
	if revisionErr != nil {
		return reasonInvocationBlocker(report.BlockerKindRevision, revisionErr.Error()), true
	}
	if environmentErr != nil {
		return reasonInvocationBlocker(report.BlockerKindEnvironment, environmentErr.Error()), true
	}
	if reconcileErr != nil {
		return reasonInvocationBlocker(report.BlockerKindHarness, reconcileErr.Error()), true
	}
	if caseID := firstFailedExecutedCaseID(suite.Cases); caseID != "" {
		return caseInvocationBlocker(caseID), true
	}
	if suite.RunFailure != "" {
		return reasonInvocationBlocker(report.BlockerKindHarness, suite.RunFailure), true
	}
	return invocationBlocker{}, false
}

func reportPublicationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
}

func normalListCatalog(specs []manifest.Spec) (listCatalog, error) {
	if len(specs) == 0 {
		return listCatalog{}, errors.New("normal list contains no cases")
	}
	if err := validateSelectedManifest(specs); err != nil {
		return listCatalog{}, err
	}
	defaultOrder, err := normalDefaultCommandRunOrder()
	if err != nil {
		return listCatalog{}, err
	}
	defaultIDs := make(map[string]bool, len(defaultOrder))
	for _, id := range defaultOrder {
		defaultIDs[id] = true
	}
	catalogDigest, err := suiteRegistryDigest(manifest.SuiteNormal)
	if err != nil {
		return listCatalog{}, err
	}
	result := listCatalog{
		Suite: manifest.SuiteNormal, Cases: make([]listedCase, 0, len(specs)), CatalogOrder: manifestIDs(catalog.NormalFull()),
		CatalogDigest: catalogDigest, DefaultCommandRunOrder: defaultOrder, SuiteFullRunOrder: manifestIDs(catalog.NormalFull()),
	}
	for _, spec := range specs {
		if spec.Suite != manifest.SuiteNormal {
			return listCatalog{}, fmt.Errorf("normal list case %q has suite %q", spec.ID, spec.Suite)
		}
		phase, err := phaseForTier(spec.Tier)
		if err != nil {
			return listCatalog{}, err
		}
		listed, err := listedCaseFrom(spec, phase, defaultIDs[spec.ID], true, tunKindCase, nil)
		if err != nil {
			return listCatalog{}, err
		}
		result.Cases = append(result.Cases, listed)
	}
	return result, nil
}

func normalDefaultCommandRunOrder() ([]string, error) {
	plan, err := runplan.Build(runplan.Request{})
	if err != nil {
		return nil, fmt.Errorf("build default command projection: %w", err)
	}
	specs, err := specsForPlan(plan, catalog.ByTier)
	if err != nil {
		return nil, fmt.Errorf("resolve default command projection: %w", err)
	}
	return manifestIDs(specs), nil
}

func phaseForTier(tier string) (int, error) {
	switch tier {
	case "T1", "T2":
		return 1, nil
	case "T3", "T4", "T5", "T6", "T7", "T8":
		return 2, nil
	default:
		return 0, fmt.Errorf("case registry contains unknown tier %q", tier)
	}
}

func requiresPhase1Authorization(specs []manifest.Spec) bool {
	for _, spec := range specs {
		phase, err := phaseForTier(spec.Tier)
		if err == nil && phase == 2 {
			return true
		}
	}
	return false
}

func listedCaseFrom(spec manifest.Spec, phase int, inDefaultCommand, inSuiteFull bool, kind string, expandsTo []string) (listedCase, error) {
	digest, err := spec.CanonicalDigest()
	if err != nil {
		return listedCase{}, fmt.Errorf("list case %q: %w", spec.ID, err)
	}
	var contract *manifest.Contract
	if spec.Contract != nil {
		normalized, err := spec.Contract.Normalize()
		if err != nil {
			return listedCase{}, fmt.Errorf("list case %q contract: %w", spec.ID, err)
		}
		contract = &normalized
	}
	return listedCase{
		ID:               spec.ID,
		Tier:             spec.Tier,
		Suite:            spec.Suite,
		Phase:            phase,
		Mandatory:        spec.Mandatory,
		Requires:         append([]string(nil), spec.Requires...),
		Long:             spec.Long,
		Budget:           spec.Budget,
		InDefaultCommand: inDefaultCommand,
		InSuiteFull:      inSuiteFull,
		Kind:             kind,
		ExpandsTo:        append([]string(nil), expandsTo...),
		CaseDigest:       digest,
		Contract:         contract,
	}, nil
}

func writeList(w io.Writer, doc listDocument) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(doc)
}

func tunFullUnimplementedCase() report.Case {
	return tunfull.UnimplementedCase("")
}
