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
	"path/filepath"
	"runtime"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/catalog"
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
	listSchemaVersion       = 2
	invocationSchemaVersion = 2
	junitReportFileName     = "junit.xml"
	markdownReportFileName  = "SUMMARY.md"
)

type runFlags struct {
	phase         string
	tier          string
	full          bool
	tunFull       bool
	list          bool
	forcePhase2   bool
	allowNonLinux bool
	profile       string
	caseID        string
	fromCaseID    string
	reportDir     string
	rendrRoot     string
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
	fs.StringVar(&cfg.profile, "profile", "", "legacy T3 profile filter (unsupported; use --case)")
	fs.StringVar(&cfg.caseID, "case", "", "run exactly one globally registered case")
	fs.StringVar(&cfg.fromCaseID, "from-case", "", "resume inclusively from a registered case")
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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

	if cfg.list {
		doc, err := buildListDocument(cfg, normalSpecs, tunCatalog)
		if err != nil {
			return preparedCommand{}, err
		}
		return preparedCommand{list: &doc}, nil
	}
	if cfg.tunFull {
		selection, err := tunCatalog.selectCases(cfg.caseID, cfg.fromCaseID)
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
	if cfg.caseID != "" && cfg.fromCaseID != "" {
		return errors.New("--case and --from-case are mutually exclusive")
	}
	if cfg.full && cfg.tunFull {
		return errors.New("--full and --tun-full are mutually exclusive")
	}
	if cfg.full && (cfg.caseID != "" || cfg.fromCaseID != "") {
		return errors.New("--full cannot be combined with --case or --from-case; use a standalone filter for resumable execution")
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
	all := append(append([]manifest.Spec(nil), normalSpecs...), tunCases.specs...)
	if err := manifest.Validate(all); err != nil {
		return nil, tunCatalog{}, fmt.Errorf("global catalog validation failed: %w", err)
	}
	return normalSpecs, tunCases, nil
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

func executeNormal(ctx context.Context, cfg runFlags, plan runplan.Plan, stdout, stderr io.Writer) int {
	selected, err := specsForPlan(plan, catalog.ByTier)
	if err != nil {
		fmt.Fprintln(stderr, "regress: cannot resolve selected manifest:", err)
		return exitEnvError
	}
	suite, revisionStart, err := beginInvocation(
		cfg,
		manifest.SuiteNormal,
		selected,
		gate.CurrentRevision,
		writeReports,
	)
	if err != nil {
		fmt.Fprintln(stderr, "regress: cannot initialize invocation report:", err)
		return exitEnvError
	}

	if requiresExistingPhase1Gate(plan) && !cfg.forcePhase2 {
		if err := gate.CheckPhase2Allowed(cfg.reportDir, cfg.rendrRoot); err != nil {
			persistInvocationFailure(suite, cfg, revisionStart, "phase 2 gate rejected invocation: "+err.Error(), gate.CurrentRevision, stderr)
			fmt.Fprintln(stderr, "regress: phase 2 not allowed:", err)
			fmt.Fprintln(stderr, "  Run a complete phase 1 first, or pass --force-phase2 for local debugging.")
			return exitPhase1Stale
		}
	}

	if plan.CompletePhase1 {
		if err := writeKnownPhase1Gate(cfg.reportDir, revisionStart, "running", time.Now()); err != nil {
			persistInvocationFailure(suite, cfg, revisionStart, "cannot invalidate prior phase 1 gate: "+err.Error(), gate.CurrentRevision, stderr)
			fmt.Fprintln(stderr, "regress: cannot invalidate prior phase 1 gate:", err)
			return exitEnvError
		}
	}

	for i, run := range plan.Runs {
		command, ok := tierCommands[run.Tier]
		if !ok {
			fmt.Fprintf(stderr, "regress: execution plan contains unknown tier %q\n", run.Tier)
			return exitEnvError
		}
		fmt.Fprintf(stdout, "== %s ==\n", command.title)
		expected, err := specsForTierRun(run)
		if err != nil {
			fmt.Fprintln(stderr, "regress: cannot resolve planned cases:", err)
			return exitEnvError
		}
		before := len(suite.Cases)
		command.run(ctx, suite, cfg.rendrRoot, tierSelection{Case: run.Case, FromCase: run.FromCase})
		reconcileErr := reconcileReportRows(expected, suite.Cases[before:])
		if reconcileErr != nil {
			suite.FailRun(run.Tier + " manifest reconciliation failed: " + reconcileErr.Error())
		}
		revisionErr := updateInvocationRevision(suite, cfg.rendrRoot, revisionStart, gate.CurrentRevision)
		if revisionErr != nil {
			suite.FailRun(revisionErr.Error())
		}
		suite.Complete = i == len(plan.Runs)-1 && reconcileErr == nil && revisionErr == nil
		if err := writeReports(suite, cfg.reportDir); err != nil {
			fmt.Fprintf(stderr, "regress: cannot write %s reports: %v\n", run.Tier, err)
			return exitEnvError
		}
		if revisionErr != nil {
			if isPhase1Tier(run.Tier) {
				writeRedPhase1Gate(cfg, stderr)
			}
			fmt.Fprintln(stderr, "regress: invocation revision changed:", revisionErr)
			return exitPhase1Stale
		}
		if reconcileErr != nil || suite.AnyFailedAt(run.Tier) {
			if isPhase1Tier(run.Tier) {
				writeRedPhase1Gate(cfg, stderr)
			}
			fmt.Fprintf(stderr, "%s: FAILED\n", run.Tier)
			return command.exitCode
		}
		fmt.Fprintf(stdout, "%s: GREEN\n", run.Tier)

		if isLastPhase1Run(plan.Runs, i) {
			if shouldWriteGreenPhase1Gate(plan) {
				if err := writeKnownPhase1Gate(cfg.reportDir, revisionStart, "green", time.Now()); err != nil {
					suite.Complete = false
					suite.FailRun("cannot persist phase 1 state: " + err.Error())
					if reportErr := writeReports(suite, cfg.reportDir); reportErr != nil {
						fmt.Fprintln(stderr, "regress: cannot persist invocation failure report:", reportErr)
					}
					fmt.Fprintln(stderr, "regress: cannot persist phase 1 state:", err)
					return exitEnvError
				}
				fmt.Fprintln(stdout, "phase 1: GREEN")
			} else {
				fmt.Fprintln(stdout, "phase 1: PARTIAL (green gate unchanged)")
			}
		}
	}
	return exitOK
}

func executeTUN(ctx context.Context, cfg runFlags, selection tunSelection, stdout, stderr io.Writer) int {
	expected, err := tunSpecsForRunOrder(tunfull.Specs(), selection.runOrder)
	if err != nil {
		fmt.Fprintln(stderr, "regress: invalid prepared TUN plan:", err)
		return exitEnvError
	}
	suite, revisionStart, err := beginInvocation(
		cfg,
		tunInvocationSuite,
		expected,
		gate.CurrentRevision,
		writeReports,
	)
	if err != nil {
		fmt.Fprintln(stderr, "regress: cannot initialize TUN invocation report:", err)
		return exitEnvError
	}
	if !cfg.forcePhase2 {
		if err := gate.CheckPhase2Allowed(cfg.reportDir, cfg.rendrRoot); err != nil {
			persistInvocationFailure(suite, cfg, revisionStart, "phase 2 gate rejected invocation: "+err.Error(), gate.CurrentRevision, stderr)
			fmt.Fprintln(stderr, "regress: phase 2 not allowed:", err)
			fmt.Fprintln(stderr, "  Run a complete phase 1 first, or pass --force-phase2 for local debugging.")
			return exitPhase1Stale
		}
	}

	for i, spec := range expected {
		fmt.Fprintf(stdout, "== phase 2 / TUN synthetic L3/session: %s ==\n", spec.ID)
		before := len(suite.Cases)
		runTUNCase(ctx, suite, cfg.rendrRoot, tunfull.Options{Case: spec.ID})
		reconcileErr := reconcileReportRows([]manifest.Spec{spec}, suite.Cases[before:])
		if reconcileErr != nil {
			suite.FailRun("TUN manifest reconciliation failed: " + reconcileErr.Error())
		}
		revisionErr := updateInvocationRevision(suite, cfg.rendrRoot, revisionStart, gate.CurrentRevision)
		if revisionErr != nil {
			suite.FailRun(revisionErr.Error())
		}
		caseFailed := reconcileErr != nil || suite.AnyFailedAt("T7")
		if caseFailed {
			for _, remaining := range expected[i+1:] {
				suite.Add(tunfull.NotRunCase(remaining, spec.ID))
			}
			if finalErr := reconcileReportRows(expected, suite.Cases); finalErr != nil {
				suite.FailRun("TUN final manifest reconciliation failed: " + finalErr.Error())
				suite.Complete = false
			} else {
				suite.Complete = revisionErr == nil
			}
		} else {
			suite.Complete = i == len(expected)-1 && revisionErr == nil
		}
		if err := writeReports(suite, cfg.reportDir); err != nil {
			fmt.Fprintln(stderr, "regress: cannot write TUN reports:", err)
			return exitEnvError
		}
		if revisionErr != nil {
			fmt.Fprintln(stderr, "regress: TUN invocation revision changed:", revisionErr)
			return exitPhase1Stale
		}
		if caseFailed {
			fmt.Fprintln(stderr, "phase 2 / TUN synthetic L3/session: FAILED")
			return exitT7Fail
		}
	}
	fmt.Fprintln(stdout, "phase 2 / TUN synthetic L3/session: GREEN (kernel TUN Gold remains separate)")
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

func writeKnownPhase1Gate(reportDir string, revision gate.Revision, status string, at time.Time) error {
	if revision.CommitSHA == "" || revision.WorktreeSHA == "" {
		return errors.New("phase 1 revision identity is incomplete")
	}
	return gate.Write(reportDir, gate.State{
		CommitSHA:   revision.CommitSHA,
		WorktreeSHA: revision.WorktreeSHA,
		Status:      status,
		At:          at,
	})
}

func beginInvocation(
	cfg runFlags,
	suiteName string,
	selected []manifest.Spec,
	currentRevision func(string) (gate.Revision, error),
	writer func(*report.Suite, string) error,
) (*report.Suite, gate.Revision, error) {
	identity, err := buildInvocationIdentity(cfg, suiteName, selected)
	if err != nil {
		return nil, gate.Revision{}, err
	}
	suite := report.New()
	suite.Invocation = identity
	if err := invalidateFixedReports(cfg.reportDir); err != nil {
		suite.FailRun("cannot invalidate stale reports: " + err.Error())
		if writeErr := writer(suite, cfg.reportDir); writeErr != nil {
			return suite, gate.Revision{}, fmt.Errorf("invalidate stale reports: %v; write failure report: %w", err, writeErr)
		}
		return suite, gate.Revision{}, fmt.Errorf("invalidate stale reports: %w", err)
	}

	revision, revisionErr := currentRevision(cfg.rendrRoot)
	if revisionErr != nil {
		suite.FailRun("cannot fingerprint invocation start: " + revisionErr.Error())
		if writeErr := writer(suite, cfg.reportDir); writeErr != nil {
			return suite, gate.Revision{}, fmt.Errorf("fingerprint invocation start: %v; invalidate stale reports: %w", revisionErr, writeErr)
		}
		return suite, gate.Revision{}, fmt.Errorf("fingerprint invocation start: %w", revisionErr)
	}
	suite.Invocation.RevisionStart = reportRevision(revision)
	if err := writer(suite, cfg.reportDir); err != nil {
		return suite, gate.Revision{}, fmt.Errorf("invalidate stale reports: %w", err)
	}
	return suite, revision, nil
}

func invalidateFixedReports(dir string) error {
	var removeErrors []error
	for _, name := range []string{junitReportFileName, markdownReportFileName} {
		path := filepath.Join(dir, name)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			removeErrors = append(removeErrors, fmt.Errorf("remove %s: %w", path, err))
		}
	}
	return errors.Join(removeErrors...)
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
	return report.Invocation{
		SchemaVersion:   invocationSchemaVersion,
		Suite:           suiteName,
		Scope:           invocationScope(cfg, selected),
		Phase:           cfg.phase,
		Tier:            cfg.tier,
		Full:            cfg.full,
		TUNFull:         cfg.tunFull,
		Case:            cfg.caseID,
		FromCase:        cfg.fromCaseID,
		ResumeCaseID:    selectedIDs[0],
		Forced:          cfg.forcePhase2,
		ManifestDigest:  digest,
		CatalogDigest:   catalogDigest,
		SelectedCases:   len(selected),
		SelectedCaseIDs: selectedIDs,
	}, nil
}

func invocationScope(cfg runFlags, selected []manifest.Spec) string {
	switch {
	case cfg.caseID != "":
		for _, spec := range selected {
			if spec.ID == cfg.caseID {
				return "exact"
			}
		}
		return "selector"
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
	if len(selected) == 0 {
		return "", errors.New("selected manifest is empty")
	}
	if err := manifest.Validate(selected); err != nil {
		return "", fmt.Errorf("selected manifest is invalid: %w", err)
	}
	return digestJSON("selected manifest", selected)
}

func suiteRegistryDigest(suiteName string) (string, error) {
	registrySuite := suiteName
	if suiteName == tunInvocationSuite {
		registrySuite = manifest.SuiteTUN
	}
	normalSpecs, tunCatalog, err := loadCatalogs()
	if err != nil {
		return "", err
	}
	doc, err := buildListDocument(runFlags{}, normalSpecs, tunCatalog)
	if err != nil {
		return "", fmt.Errorf("build full registry document: %w", err)
	}
	for _, registry := range doc.Catalogs {
		if registry.Suite == registrySuite {
			return digestJSON(registrySuite+" registry", registry)
		}
	}
	return "", fmt.Errorf("unknown invocation suite %q", suiteName)
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
	suite *report.Suite,
	cfg runFlags,
	revisionStart gate.Revision,
	reason string,
	currentRevision func(string) (gate.Revision, error),
	stderr io.Writer,
) {
	suite.Complete = false
	suite.FailRun(reason)
	if err := updateInvocationRevision(suite, cfg.rendrRoot, revisionStart, currentRevision); err != nil {
		suite.FailRun(err.Error())
	}
	if err := writeReports(suite, cfg.reportDir); err != nil {
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
		CommitSHA:   revision.CommitSHA,
		WorktreeSHA: revision.WorktreeSHA,
		Status:      status,
		At:          at,
	}, nil
}

const (
	tunKindCase                  = "case"
	tunKindCompatibilityAlias    = "compatibility_alias"
	tunKindCompatibilitySelector = "compatibility_selector"
	tunSyntheticEvidenceClass    = "synthetic_l3_session_not_kernel_tun_gold"
	tunInvocationSuite           = "tun-full/synthetic-l3-session"
)

type tunCatalog struct {
	specs   []manifest.Spec
	aliases []tunfull.Alias
}

type tunSelection struct {
	cases    []listedCase
	runOrder []string
}

var runTUNCase = func(ctx context.Context, suite *report.Suite, rendrRoot string, opts tunfull.Options) {
	tunfull.RunCanonicalCase(ctx, suite, rendrRoot, opts.Case)
}

type tunCatalogEntry struct {
	listed listedCase
	runIDs []string
}

func buildTUNCatalog(specs []manifest.Spec, aliases []tunfull.Alias) (tunCatalog, error) {
	if err := manifest.Validate(specs); err != nil {
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
	cloned := make([]manifest.Spec, len(specs))
	for i, spec := range specs {
		cloned[i] = spec
		cloned[i].Requires = append([]string(nil), spec.Requires...)
	}
	return cloned
}

func cloneTUNAliases(aliases []tunfull.Alias) []tunfull.Alias {
	cloned := make([]tunfull.Alias, len(aliases))
	for i, alias := range aliases {
		cloned[i] = alias
		cloned[i].ExpandsTo = append([]string(nil), alias.ExpandsTo...)
	}
	return cloned
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
					Mandatory: false, Long: long, DefaultRun: false, Kind: kind,
					ExpandsTo: append([]string(nil), alias.ExpandsTo...),
				},
				runIDs: append([]string(nil), alias.ExpandsTo...),
			})
		}
		entries = append(entries, tunCatalogEntry{
			listed: listedCaseFrom(spec, 2, true, tunKindCase, nil),
			runIDs: []string{spec.ID},
		})
	}
	return entries, nil
}

func (catalog tunCatalog) selectCases(caseID, fromCaseID string) (tunSelection, error) {
	if caseID != "" && fromCaseID != "" {
		return tunSelection{}, errors.New("manifest: --case and --from-case are mutually exclusive")
	}
	entries, err := catalog.entries()
	if err != nil {
		return tunSelection{}, err
	}
	if caseID == "" && fromCaseID == "" {
		result := tunSelection{cases: make([]listedCase, len(entries)), runOrder: make([]string, len(catalog.specs))}
		for i, entry := range entries {
			result.cases[i] = entry.listed
		}
		for i, spec := range catalog.specs {
			result.runOrder[i] = spec.ID
		}
		return catalog.withPrerequisites(result)
	}

	want := caseID
	if want == "" {
		want = fromCaseID
	}
	start := -1
	for i, entry := range entries {
		if entry.listed.ID == want {
			start = i
			break
		}
	}
	if start < 0 {
		if caseID != "" {
			return tunSelection{}, fmt.Errorf("manifest: no case matched --case=%q", caseID)
		}
		return tunSelection{}, fmt.Errorf("manifest: no case matched --from-case=%q", fromCaseID)
	}
	if caseID != "" {
		entry := entries[start]
		return catalog.withPrerequisites(tunSelection{
			cases:    []listedCase{entry.listed},
			runOrder: append([]string(nil), entry.runIDs...),
		})
	}

	selectedEntries := entries[start:]
	result := tunSelection{cases: make([]listedCase, len(selectedEntries))}
	for i, entry := range selectedEntries {
		result.cases[i] = entry.listed
	}
	emitted := make(map[string]bool)
	add := func(ids ...string) {
		for _, id := range ids {
			if !emitted[id] {
				result.runOrder = append(result.runOrder, id)
				emitted[id] = true
			}
		}
	}
	if selectedEntries[0].listed.Kind != tunKindCase {
		add(selectedEntries[0].runIDs...)
	}
	for _, entry := range selectedEntries {
		if entry.listed.Kind == tunKindCase {
			add(entry.runIDs...)
		}
	}
	if len(result.runOrder) == 0 {
		return tunSelection{}, errors.New("selected TUN scope contains no executable cases")
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
	Suite         string       `json:"suite"`
	EvidenceClass string       `json:"evidence_class,omitempty"`
	Cases         []listedCase `json:"cases"`
	RunOrder      []string     `json:"run_order"`
}

type listedCase struct {
	ID         string        `json:"id"`
	Tier       string        `json:"tier"`
	Suite      string        `json:"suite"`
	Phase      int           `json:"phase"`
	Mandatory  bool          `json:"mandatory"`
	Requires   []string      `json:"requires,omitempty"`
	Long       bool          `json:"long,omitempty"`
	Budget     time.Duration `json:"budget_ns,omitempty"`
	DefaultRun bool          `json:"default_run"`
	Kind       string        `json:"kind"`
	ExpandsTo  []string      `json:"expands_to,omitempty"`
}

func buildListDocument(cfg runFlags, normalSpecs []manifest.Spec, tunCatalog tunCatalog) (listDocument, error) {
	doc := listDocument{SchemaVersion: listSchemaVersion}
	if cfg.tunFull {
		selection, err := tunCatalog.selectCases(cfg.caseID, cfg.fromCaseID)
		if err != nil {
			return listDocument{}, fmt.Errorf("TUN list selection: %w", err)
		}
		doc.Catalogs = append(doc.Catalogs, listCatalog{
			Suite: manifest.SuiteTUN, EvidenceClass: tunSyntheticEvidenceClass,
			Cases: selection.cases, RunOrder: selection.runOrder,
		})
		return doc, nil
	}

	if hasNormalListScope(cfg) {
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
		doc.Catalogs = append(doc.Catalogs, normal)
		return doc, nil
	}

	normal, err := normalListCatalog(normalSpecs)
	if err != nil {
		return listDocument{}, err
	}
	tunSelection, err := tunCatalog.selectCases("", "")
	if err != nil {
		return listDocument{}, err
	}
	doc.Catalogs = append(doc.Catalogs, normal, listCatalog{
		Suite: manifest.SuiteTUN, EvidenceClass: tunSyntheticEvidenceClass,
		Cases: tunSelection.cases, RunOrder: tunSelection.runOrder,
	})
	return doc, nil
}

func hasNormalListScope(cfg runFlags) bool {
	return cfg.phase != "" || cfg.tier != "" || cfg.full || cfg.caseID != "" || cfg.fromCaseID != ""
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
	if err := manifest.Validate(selected); err != nil {
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
	}
	return nil
}

func normalListCatalog(specs []manifest.Spec) (listCatalog, error) {
	if len(specs) == 0 {
		return listCatalog{}, errors.New("normal list contains no cases")
	}
	if err := manifest.Validate(specs); err != nil {
		return listCatalog{}, err
	}
	result := listCatalog{Suite: manifest.SuiteNormal, Cases: make([]listedCase, 0, len(specs)), RunOrder: make([]string, 0, len(specs))}
	for _, spec := range specs {
		if spec.Suite != manifest.SuiteNormal {
			return listCatalog{}, fmt.Errorf("normal list case %q has suite %q", spec.ID, spec.Suite)
		}
		phase, err := phaseForTier(spec.Tier)
		if err != nil {
			return listCatalog{}, err
		}
		result.Cases = append(result.Cases, listedCaseFrom(spec, phase, true, tunKindCase, nil))
		result.RunOrder = append(result.RunOrder, spec.ID)
	}
	return result, nil
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

func listedCaseFrom(spec manifest.Spec, phase int, defaultRun bool, kind string, expandsTo []string) listedCase {
	return listedCase{
		ID:         spec.ID,
		Tier:       spec.Tier,
		Suite:      spec.Suite,
		Phase:      phase,
		Mandatory:  spec.Mandatory,
		Requires:   append([]string(nil), spec.Requires...),
		Long:       spec.Long,
		Budget:     spec.Budget,
		DefaultRun: defaultRun,
		Kind:       kind,
		ExpandsTo:  append([]string(nil), expandsTo...),
	}
}

func writeList(w io.Writer, doc listDocument) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(doc)
}

func tunFullUnimplementedCase() report.Case {
	return tunfull.UnimplementedCase("")
}

func writeReports(suite *report.Suite, dir string) error {
	junit := filepath.Join(dir, junitReportFileName)
	md := filepath.Join(dir, markdownReportFileName)
	if err := suite.WriteJUnit(junit); err != nil {
		return fmt.Errorf("write JUnit: %w", err)
	}
	if err := suite.WriteMarkdown(md); err != nil {
		return fmt.Errorf("write summary: %w", err)
	}
	return nil
}
