package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/catalog"
	"github.com/FrankoonG/rendr/regress/internal/gate"
	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/report"
	"github.com/FrankoonG/rendr/regress/internal/runplan"
	"github.com/FrankoonG/rendr/regress/internal/tunfull"
)

func TestPrepareCommandNormalScopes(t *testing.T) {
	tests := []struct {
		name       string
		cfg        runFlags
		wantRuns   []runplan.TierRun
		completeP1 bool
	}{
		{
			name: "exact case resolves owning tier",
			cfg:  runFlags{phase: "2", caseID: "T5.4-gvisor-unprivileged"},
			wantRuns: []runplan.TierRun{
				{Tier: "T5", Case: "T5.4-gvisor-unprivileged"},
			},
		},
		{
			name: "standalone resume crosses tiers",
			cfg:  runFlags{fromCaseID: "T5.4-gvisor-unprivileged"},
			wantRuns: []runplan.TierRun{
				{Tier: "T5", FromCase: "T5.4-gvisor-unprivileged"},
				{Tier: "T6"},
				{Tier: "T7"},
				{Tier: "T8"},
			},
		},
		{
			name: "explicit tier resume stays in tier",
			cfg:  runFlags{tier: "8", fromCaseID: "T8.primary.explicit-path"},
			wantRuns: []runplan.TierRun{
				{Tier: "T8", FromCase: "T8.primary.explicit-path"},
			},
		},
		{
			name: "full includes T1 through T8",
			cfg:  runFlags{full: true},
			wantRuns: []runplan.TierRun{
				{Tier: "T1"}, {Tier: "T2"}, {Tier: "T3"}, {Tier: "T4"},
				{Tier: "T5"}, {Tier: "T6"}, {Tier: "T7"}, {Tier: "T8"},
			},
			completeP1: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prepared, err := prepareCommand(tt.cfg)
			if err != nil {
				t.Fatal(err)
			}
			if prepared.normal == nil || prepared.tun != nil || prepared.list != nil {
				t.Fatalf("unexpected prepared command: %+v", prepared)
			}
			if !reflect.DeepEqual(prepared.normal.Runs, tt.wantRuns) {
				t.Fatalf("runs=%+v want %+v", prepared.normal.Runs, tt.wantRuns)
			}
			if prepared.normal.CompletePhase1 != tt.completeP1 {
				t.Fatalf("CompletePhase1=%v want %v", prepared.normal.CompletePhase1, tt.completeP1)
			}
		})
	}
}

func TestPrepareCommandRejectsConflictsAndOutOfScopeFilters(t *testing.T) {
	tests := []struct {
		name string
		cfg  runFlags
		want string
	}{
		{name: "both filters", cfg: runFlags{caseID: "go-vet", fromCaseID: "go-test"}, want: "mutually exclusive"},
		{name: "both full suites", cfg: runFlags{full: true, tunFull: true}, want: "mutually exclusive"},
		{name: "tun and phase", cfg: runFlags{tunFull: true, phase: "2"}, want: "cannot be combined"},
		{name: "tun and tier", cfg: runFlags{tunFull: true, tier: "7"}, want: "cannot be combined"},
		{name: "phase one force", cfg: runFlags{phase: "1", forcePhase2: true}, want: "cannot be combined"},
		{name: "list force", cfg: runFlags{list: true, forcePhase2: true}, want: "cannot be combined"},
		{name: "legacy profile", cfg: runFlags{profile: "PYS-D-1"}, want: "not supported"},
		{name: "full and tier", cfg: runFlags{full: true, tier: "4"}, want: "cannot be combined"},
		{name: "full and exact case", cfg: runFlags{full: true, caseID: "go-test"}, want: "--full cannot be combined"},
		{name: "full and resume", cfg: runFlags{full: true, fromCaseID: "go-test"}, want: "--full cannot be combined"},
		{name: "invalid phase", cfg: runFlags{phase: "3"}, want: "invalid --phase"},
		{name: "invalid tier", cfg: runFlags{tier: "9"}, want: "invalid --tier"},
		{name: "case outside phase", cfg: runFlags{phase: "1", caseID: "T8.status.local-default"}, want: "no case matched"},
		{name: "case outside tier", cfg: runFlags{tier: "6", caseID: "G5"}, want: "no case matched"},
		{name: "unknown normal case", cfg: runFlags{caseID: "missing"}, want: "no case matched"},
		{name: "unknown TUN case", cfg: runFlags{tunFull: true, caseID: "missing"}, want: "no case matched"},
		{name: "force without phase two", cfg: runFlags{caseID: "go-vet", forcePhase2: true}, want: "requires a plan"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := prepareCommand(tt.cfg)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err=%v want substring %q", err, tt.want)
			}
		})
	}
}

func TestEveryTierAdapterForwardsBothFilters(t *testing.T) {
	wantExitCodes := map[string]int{
		"T1": exitT1Fail,
		"T2": exitT2Fail,
		"T3": exitT3Fail,
		"T4": exitT4Fail,
		"T5": exitT5Fail,
		"T6": exitT6Fail,
		"T7": exitT7Fail,
		"T8": exitT8Fail,
	}
	for tier, wantExitCode := range wantExitCodes {
		t.Run(tier, func(t *testing.T) {
			command, ok := tierCommands[tier]
			if !ok || command.run == nil || command.tier != tier || command.exitCode != wantExitCode {
				t.Fatalf("bad tier command: %+v", command)
			}
			suite := report.New()
			command.run(context.Background(), suite, "unused", tierSelection{
				Case: "synthetic-missing-case", FromCase: "synthetic-missing-resume",
			})
			if len(suite.Cases) != 1 {
				t.Fatalf("filter produced %d reports, want one: %+v", len(suite.Cases), suite.Cases)
			}
			failure := suite.Cases[0].Failure
			containsBothValues := strings.Contains(failure, "synthetic-missing-case") && strings.Contains(failure, "synthetic-missing-resume")
			if !strings.Contains(failure, "mutually exclusive") && !containsBothValues {
				t.Fatalf("both filters were not forwarded: %+v", suite.Cases[0])
			}
		})
	}
}

func TestPartialPhaseOneCannotMintGreenGate(t *testing.T) {
	partial, err := runplan.Build(runplan.Request{Phase: "1", FromCase: "go-test"})
	if err != nil {
		t.Fatal(err)
	}
	if shouldWriteGreenPhase1Gate(partial) {
		t.Fatal("partial T1/T2 plan can mint a green gate")
	}

	complete, err := runplan.Build(runplan.Request{Phase: "1"})
	if err != nil {
		t.Fatal(err)
	}
	if !shouldWriteGreenPhase1Gate(complete) {
		t.Fatal("complete T1/T2 plan cannot mint its green gate")
	}
}

func TestBuildPhase1StateUsesExactRendrRoot(t *testing.T) {
	wantRoot := `E:\exact\rendr-root`
	wantTime := time.Unix(123, 456)
	state, err := buildPhase1State(wantRoot, "green", wantTime, func(gotRoot string) (gate.Revision, error) {
		if gotRoot != wantRoot {
			t.Fatalf("CurrentRevision root=%q want %q", gotRoot, wantRoot)
		}
		return gate.Revision{CommitSHA: "commit", WorktreeSHA: "worktree"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := gate.State{CommitSHA: "commit", WorktreeSHA: "worktree", Status: "green", At: wantTime}
	if !reflect.DeepEqual(state, want) {
		t.Fatalf("state=%+v want %+v", state, want)
	}

	_, err = buildPhase1State(wantRoot, "green", wantTime, func(string) (gate.Revision, error) {
		return gate.Revision{}, errors.New("revision failed")
	})
	if err == nil || !strings.Contains(err.Error(), "revision failed") {
		t.Fatalf("revision error=%v", err)
	}
}

func TestUpdateInvocationRevisionRejectsConcurrentChanges(t *testing.T) {
	wantRoot := "/exact/root"
	before := gate.Revision{CommitSHA: "commit", WorktreeSHA: "before"}
	suite := report.New()
	if err := updateInvocationRevision(suite, wantRoot, before, func(root string) (gate.Revision, error) {
		if root != wantRoot {
			t.Fatalf("root=%q want %q", root, wantRoot)
		}
		return before, nil
	}); err != nil {
		t.Fatalf("stable revision: %v", err)
	}
	if suite.Invocation.RevisionEnd != (report.Revision{CommitSHA: "commit", WorktreeSHA: "before"}) {
		t.Fatalf("revision end=%+v", suite.Invocation.RevisionEnd)
	}

	err := updateInvocationRevision(suite, wantRoot, before, func(string) (gate.Revision, error) {
		return gate.Revision{CommitSHA: "commit", WorktreeSHA: "after"}, nil
	})
	if err == nil || !strings.Contains(err.Error(), "changed during regression invocation") {
		t.Fatalf("changed revision err=%v", err)
	}
	if suite.Invocation.RevisionEnd.WorktreeSHA != "after" {
		t.Fatalf("drifted revision was not recorded: %+v", suite.Invocation.RevisionEnd)
	}

	err = updateInvocationRevision(suite, wantRoot, before, func(string) (gate.Revision, error) {
		return gate.Revision{}, errors.New("git failed")
	})
	if err == nil || !strings.Contains(err.Error(), "git failed") {
		t.Fatalf("fingerprint err=%v", err)
	}
}

func TestBeginInvocationInvalidatesStaleFixedPassReports(t *testing.T) {
	dir := t.TempDir()
	junitPath := filepath.Join(dir, "junit.xml")
	markdownPath := filepath.Join(dir, "SUMMARY.md")
	if err := os.WriteFile(junitPath, []byte(`<testsuites state="pass" failures="0">STALE-FULL-PASS</testsuites>`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(markdownPath, []byte("**OVERALL: PASS**\nSTALE-FULL-PASS\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	spec := manifest.RequiredWithBudget("synthetic.one", "T1", time.Second)
	cfg := runFlags{caseID: spec.ID, reportDir: dir, rendrRoot: "/exact/root"}
	suite, revision, err := beginInvocation(
		cfg,
		manifest.SuiteNormal,
		[]manifest.Spec{spec},
		func(root string) (gate.Revision, error) {
			if root != cfg.rendrRoot {
				t.Fatalf("root=%q want %q", root, cfg.rendrRoot)
			}
			return gate.Revision{CommitSHA: "commit", WorktreeSHA: "tree"}, nil
		},
		writeReports,
	)
	if err != nil {
		t.Fatal(err)
	}
	if revision.CommitSHA != "commit" || suite.Complete {
		t.Fatalf("suite=%+v revision=%+v", suite, revision)
	}
	junit, err := os.ReadFile(junitPath)
	if err != nil {
		t.Fatal(err)
	}
	markdown, err := os.ReadFile(markdownPath)
	if err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{"JUnit": string(junit), "Markdown": string(markdown)} {
		if strings.Contains(contents, "STALE-FULL-PASS") {
			t.Fatalf("%s retained stale PASS:\n%s", name, contents)
		}
	}
	for _, want := range []string{`state="partial"`, `failures="1"`, `invocation_scope="exact"`, `invocation_case="synthetic.one"`} {
		if !strings.Contains(string(junit), want) {
			t.Fatalf("invalidated JUnit missing %q:\n%s", want, junit)
		}
	}
	if strings.Contains(string(markdown), "**OVERALL: PASS**") || !strings.Contains(string(markdown), "**OVERALL: PARTIAL**") {
		t.Fatalf("invalidated Markdown is green:\n%s", markdown)
	}
}

func TestBeginInvocationRemovesStalePassBeforeWritingReplacement(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{junitReportFileName, markdownReportFileName} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("STALE-PASS"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writerCalled := false
	_, _, err := beginInvocation(
		runFlags{reportDir: dir, rendrRoot: "/exact/root"},
		manifest.SuiteNormal,
		[]manifest.Spec{manifest.RequiredWithBudget("one", "T1", time.Second)},
		func(string) (gate.Revision, error) {
			return gate.Revision{CommitSHA: "commit", WorktreeSHA: "tree"}, nil
		},
		func(*report.Suite, string) error {
			writerCalled = true
			for _, name := range []string{junitReportFileName, markdownReportFileName} {
				if _, statErr := os.Stat(filepath.Join(dir, name)); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("stale %s still exists before replacement write: %v", name, statErr)
				}
			}
			return errors.New("synthetic writer failure")
		},
	)
	if !writerCalled || err == nil || !strings.Contains(err.Error(), "synthetic writer failure") {
		t.Fatalf("writerCalled=%v err=%v", writerCalled, err)
	}
}

func TestInvocationScopeAndManifestDigestSeparateFullFromExact(t *testing.T) {
	all := []manifest.Spec{
		manifest.RequiredWithBudget("one", "T1", time.Second),
		manifest.RequiredWithBudget("two", "T1", time.Second),
	}
	full, err := buildInvocationIdentity(runFlags{full: true}, manifest.SuiteNormal, all)
	if err != nil {
		t.Fatal(err)
	}
	exact, err := buildInvocationIdentity(runFlags{caseID: "two", forcePhase2: true}, manifest.SuiteNormal, all[1:])
	if err != nil {
		t.Fatal(err)
	}
	if full.Scope != "full" || full.Forced || full.SelectedCases != 2 || !full.Full || full.TUNFull {
		t.Fatalf("full identity=%+v", full)
	}
	if exact.Scope != "exact" || exact.Case != "two" || !exact.Forced || exact.SelectedCases != 1 ||
		exact.ResumeCaseID != "two" || !reflect.DeepEqual(exact.SelectedCaseIDs, []string{"two"}) {
		t.Fatalf("exact identity=%+v", exact)
	}
	exactWithPrerequisite, err := buildInvocationIdentity(
		runFlags{caseID: "two"},
		manifest.SuiteNormal,
		all,
	)
	if err != nil {
		t.Fatal(err)
	}
	if exactWithPrerequisite.Scope != "exact" || exactWithPrerequisite.ResumeCaseID != "one" {
		t.Fatalf("exact identity with prerequisite=%+v", exactWithPrerequisite)
	}
	if full.ManifestDigest == exact.ManifestDigest {
		t.Fatalf("full and exact manifests share digest %q", full.ManifestDigest)
	}
	if full.ManifestDigest == "" || !strings.HasPrefix(full.ManifestDigest, "sha256:") {
		t.Fatalf("invalid full manifest digest %q", full.ManifestDigest)
	}
	if full.CatalogDigest == "" || full.CatalogDigest != exact.CatalogDigest {
		t.Fatalf("normal catalog digests full=%q exact=%q", full.CatalogDigest, exact.CatalogDigest)
	}
	if !reflect.DeepEqual(full.SelectedCaseIDs, []string{"one", "two"}) || full.ResumeCaseID != "one" {
		t.Fatalf("full selected identity=%+v", full)
	}
	reversed, err := selectedManifestDigest([]manifest.Spec{all[1], all[0]})
	if err != nil {
		t.Fatal(err)
	}
	if reversed == full.ManifestDigest {
		t.Fatal("manifest digest does not bind exact execution order")
	}
	tun, err := buildInvocationIdentity(runFlags{tunFull: true, forcePhase2: true}, manifest.SuiteTUN, all[:1])
	if err != nil {
		t.Fatal(err)
	}
	if tun.Suite != manifest.SuiteTUN || tun.Scope != "full" || !tun.Forced || !tun.TUNFull || tun.CatalogDigest == "" {
		t.Fatalf("TUN/forced identity=%+v", tun)
	}
	selector, err := buildInvocationIdentity(runFlags{tunFull: true, caseID: "legacy-selector"}, manifest.SuiteTUN, all[:1])
	if err != nil {
		t.Fatal(err)
	}
	if selector.Scope != "selector" || selector.Case != "legacy-selector" || selector.ResumeCaseID != "one" {
		t.Fatalf("selector identity=%+v", selector)
	}
}

func TestPhaseOneResumeCanRepairRedGateWithoutMintingGreen(t *testing.T) {
	resumed, err := runplan.Build(runplan.Request{FromCase: "go-test"})
	if err != nil {
		t.Fatal(err)
	}
	if !resumed.HasPhase2() || !containsSelectedPhase1(resumed) {
		t.Fatalf("resume plan does not bridge phase 1 to phase 2: %+v", resumed)
	}
	if !requiresExistingPhase1Gate(resumed) {
		t.Fatal("partial phase-1 resume bypasses the current green gate")
	}
	if shouldWriteGreenPhase1Gate(resumed) {
		t.Fatal("partial phase-1 resume can mint a complete green gate")
	}

	phase2Only, err := runplan.Build(runplan.Request{FromCase: "T5.4-gvisor-unprivileged"})
	if err != nil {
		t.Fatal(err)
	}
	if !requiresExistingPhase1Gate(phase2Only) {
		t.Fatal("phase-2-only resume bypasses the phase-1 gate")
	}

	complete, err := runplan.Build(runplan.Request{FromCase: "go-vet"})
	if err != nil {
		t.Fatal(err)
	}
	if requiresExistingPhase1Gate(complete) || !shouldWriteGreenPhase1Gate(complete) {
		t.Fatalf("complete phase-1 resume gate policy is wrong: %+v", complete)
	}
}

func TestExecuteNormalPhaseOneResumeBypassesRedGateButLeavesItRed(t *testing.T) {
	root := newMainTestRepo(t)
	reportDir := t.TempDir()

	restore := installSyntheticTierCommands(t)
	defer restore()
	plan, err := runplan.Build(runplan.Request{FromCase: "go-test"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := runFlags{fromCaseID: "go-test", reportDir: reportDir, rendrRoot: root}
	var stdout, stderr bytes.Buffer
	if code := executeNormal(context.Background(), cfg, plan, &stdout, &stderr); code != exitPhase1Stale {
		t.Fatalf("code=%d want %d stderr=%s stdout=%s", code, exitPhase1Stale, stderr.String(), stdout.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("tiers ran before gate rejection:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "phase 2 not allowed") {
		t.Fatalf("missing gate diagnostic:\n%s", stderr.String())
	}
	junit, err := os.ReadFile(filepath.Join(reportDir, junitReportFileName))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`state="fail"`, `complete="false"`, `invocation_scope="from-case"`, `invocation_from_case="go-test"`, "phase 2 gate rejected invocation"} {
		if !strings.Contains(string(junit), want) {
			t.Fatalf("resume JUnit missing %q:\n%s", want, junit)
		}
	}

	greenDir := t.TempDir()
	greenState, err := buildPhase1State(root, "green", time.Now(), gate.CurrentRevision)
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.Write(greenDir, greenState); err != nil {
		t.Fatal(err)
	}
	greenCfg := cfg
	greenCfg.reportDir = greenDir
	stdout.Reset()
	stderr.Reset()
	if code := executeNormal(context.Background(), greenCfg, plan, &stdout, &stderr); code != exitOK {
		t.Fatalf("green-gated code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}

	forcedDir := t.TempDir()
	forcedCfg := cfg
	forcedCfg.reportDir = forcedDir
	forcedCfg.forcePhase2 = true
	stdout.Reset()
	stderr.Reset()
	if code := executeNormal(context.Background(), forcedCfg, plan, &stdout, &stderr); code != exitOK {
		t.Fatalf("forced code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
}

func TestExecuteNormalRevisionDriftFailsAndPersistsEvidence(t *testing.T) {
	root := newMainTestRepo(t)
	reportDir := t.TempDir()
	original := tierCommands["T1"]
	command := original
	command.run = func(_ context.Context, suite *report.Suite, _ string, _ tierSelection) {
		suite.Add(report.Case{Name: "go-vet", Tier: "T1"})
		if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("changed\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tierCommands["T1"] = command
	defer func() { tierCommands["T1"] = original }()

	plan, err := runplan.Build(runplan.Request{Case: "go-vet"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := runFlags{caseID: "go-vet", reportDir: reportDir, rendrRoot: root}
	var stdout, stderr bytes.Buffer
	if code := executeNormal(context.Background(), cfg, plan, &stdout, &stderr); code != exitPhase1Stale {
		t.Fatalf("code=%d want %d stderr=%s", code, exitPhase1Stale, stderr.String())
	}
	junit, err := os.ReadFile(filepath.Join(reportDir, junitReportFileName))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`state="fail"`,
		`complete="false"`,
		`name="invocation-complete"`,
		"worktree changed during regression invocation",
	} {
		if !strings.Contains(string(junit), want) {
			t.Fatalf("drift JUnit missing %q:\n%s", want, junit)
		}
	}
}

func TestWriteKnownPhase1GateRejectsMissingIdentity(t *testing.T) {
	err := writeKnownPhase1Gate(t.TempDir(), gate.Revision{}, "running", time.Now())
	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("err=%v", err)
	}
}

func TestTUNCatalogMakesCompatibilitySelectorsExplicit(t *testing.T) {
	tunCatalog, err := buildTUNCatalog(tunfull.Specs(), tunfull.Aliases())
	if err != nil {
		t.Fatal(err)
	}
	selection, err := tunCatalog.selectCases("", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(selection.cases) != len(tunfull.Specs())+len(tunfull.Aliases()) {
		t.Fatalf("listed cases=%d want executable+alias count %d", len(selection.cases), len(tunfull.Specs())+len(tunfull.Aliases()))
	}
	wantDefault := []string{
		"TUN-full.preflight-kernel-tun",
		"TUN-full.G1-smoke",
		"TUN-full.G2-smoke",
		"TUN-full.G3-smoke",
		"TUN-full.G4-path-death",
		"TUN-full.G5-path-recovery",
		"TUN-full.T3-xray-matrix",
		"TUN-full.T4-G1-1GiB-tcp",
		"TUN-full.T4-G2-30m-selector",
		"TUN-full.T4-G3-100k-pps",
		"TUN-full.T5-adapter-matrix",
		"TUN-full.T6-selector",
	}
	if !reflect.DeepEqual(selection.runOrder, wantDefault) {
		t.Fatalf("default run=%v want %v", selection.runOrder, wantDefault)
	}

	streamCompat := findListedCase(t, selection.cases, "TUN-full.T3-xray-stream-smoke")
	if streamCompat.DefaultRun || streamCompat.Mandatory || streamCompat.Kind != tunKindCompatibilityAlias || !reflect.DeepEqual(streamCompat.ExpandsTo, []string{"TUN-full.T3-xray-matrix"}) {
		t.Fatalf("stream compatibility entry=%+v", streamCompat)
	}
	longCompat := findListedCase(t, selection.cases, "TUN-full.T4-long-run")
	if longCompat.DefaultRun || longCompat.Kind != tunKindCompatibilitySelector || len(longCompat.ExpandsTo) != 3 {
		t.Fatalf("long-run compatibility entry=%+v", longCompat)
	}

	exact, err := tunCatalog.selectCases("TUN-full.T4-long-run", "")
	if err != nil {
		t.Fatal(err)
	}
	wantLongRun := append([]string{"TUN-full.preflight-kernel-tun"}, longCompat.ExpandsTo...)
	if !reflect.DeepEqual(exact.runOrder, wantLongRun) {
		t.Fatalf("selector run=%v want preflight+expansion %v", exact.runOrder, wantLongRun)
	}
	primeCompat := findListedCase(t, selection.cases, "TUN-full.T4-G2-30m-prime")
	if primeCompat.Kind != tunKindCompatibilityAlias || !reflect.DeepEqual(primeCompat.ExpandsTo, []string{"TUN-full.T4-G2-30m-selector"}) {
		t.Fatalf("prime compatibility entry=%+v", primeCompat)
	}
	exact, err = tunCatalog.selectCases("TUN-full.T4-G2-30m-prime", "")
	if err != nil || !reflect.DeepEqual(exact.runOrder, []string{"TUN-full.preflight-kernel-tun", "TUN-full.T4-G2-30m-selector"}) {
		t.Fatalf("prime alias selection=%+v err=%v", exact, err)
	}
	fallbackCompat := findListedCase(t, selection.cases, "TUN-full.T5-fallback")
	if fallbackCompat.Kind != tunKindCompatibilityAlias || !reflect.DeepEqual(fallbackCompat.ExpandsTo, []string{"TUN-full.T5-adapter-matrix"}) {
		t.Fatalf("fallback compatibility entry=%+v", fallbackCompat)
	}
	resumed, err := tunCatalog.selectCases("", "TUN-full.T3-xray-stream-smoke")
	if err != nil {
		t.Fatal(err)
	}
	if len(resumed.runOrder) < 2 || resumed.runOrder[0] != "TUN-full.preflight-kernel-tun" || resumed.runOrder[1] != "TUN-full.T3-xray-matrix" {
		t.Fatalf("compatibility resume is not inclusive: %v", resumed.runOrder)
	}
	for _, spec := range tunfull.Specs() {
		if !spec.Mandatory {
			t.Fatalf("executable spec is not mandatory: %+v", spec)
		}
	}
}

func TestTUNCatalogMismatchFailsClosed(t *testing.T) {
	specs := tunfull.Specs()
	badSpecs := cloneManifestSpecs(specs)
	badSpecs[0].Tier = "T6"
	if _, err := buildTUNCatalog(badSpecs, tunfull.Aliases()); err == nil || !strings.Contains(err.Error(), "registry/full mismatch") {
		t.Fatalf("metadata mismatch err=%v", err)
	}

	aliases := cloneTUNAliases(tunfull.Aliases())
	aliases[0].Before = "TUN-full.missing"
	if _, err := buildTUNCatalog(specs, aliases); err == nil || !strings.Contains(err.Error(), "unknown continuation") {
		t.Fatalf("continuation mismatch err=%v", err)
	}
	aliases = cloneTUNAliases(tunfull.Aliases())
	aliases[0].ID = specs[0].ID
	if _, err := buildTUNCatalog(specs, aliases); err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("alias collision err=%v", err)
	}
	aliases = cloneTUNAliases(tunfull.Aliases())
	aliases[0].ExpandsTo = []string{"TUN-full.missing"}
	if _, err := buildTUNCatalog(specs, aliases); err == nil || !strings.Contains(err.Error(), "first expansion") {
		t.Fatalf("alias expansion err=%v", err)
	}
	aliases = cloneTUNAliases(tunfull.Aliases())
	aliases[1].ExpandsTo = []string{"TUN-full.T4-G1-1GiB-tcp", "TUN-full.T4-G3-100k-pps"}
	if _, err := buildTUNCatalog(specs, aliases); err == nil || !strings.Contains(err.Error(), "contiguous canonical suffix") {
		t.Fatalf("non-contiguous alias err=%v", err)
	}
	t.Run("expanded failure keeps canonical rows", testExecuteTUNFailurePreservesOneRowPerExpandedCanonicalCase)
}

func testExecuteTUNFailurePreservesOneRowPerExpandedCanonicalCase(t *testing.T) {
	catalog, err := buildTUNCatalog(tunfull.Specs(), tunfull.Aliases())
	if err != nil {
		t.Fatal(err)
	}
	selection, err := catalog.selectCases("TUN-full.T4-long-run", "")
	if err != nil {
		t.Fatal(err)
	}

	original := runTUNCase
	t.Cleanup(func() { runTUNCase = original })
	var called []string
	runTUNCase = func(_ context.Context, suite *report.Suite, _ string, opts tunfull.Options) {
		called = append(called, opts.Case)
		rc := report.Case{Name: opts.Case, Tier: "T7"}
		if opts.Case != "TUN-full.preflight-kernel-tun" {
			rc.Failure = "synthetic failure"
		}
		suite.Add(rc)
	}

	root := newMainTestRepo(t)
	reportDir := t.TempDir()
	cfg := runFlags{
		tunFull: true, caseID: "TUN-full.T4-long-run", forcePhase2: true,
		rendrRoot: root, reportDir: reportDir,
	}
	var stdout, stderr bytes.Buffer
	if code := executeTUN(context.Background(), cfg, selection, &stdout, &stderr); code != exitT7Fail {
		t.Fatalf("code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if !reflect.DeepEqual(called, []string{"TUN-full.preflight-kernel-tun", "TUN-full.T4-G1-1GiB-tcp"}) {
		t.Fatalf("executed=%v", called)
	}
	junit, err := os.ReadFile(filepath.Join(reportDir, junitReportFileName))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`complete="true"`, `selected_cases="4"`, `invocation_suite="tun-full/synthetic-l3-session"`,
		`name="TUN-full.preflight-kernel-tun"`,
		`name="TUN-full.T4-G1-1GiB-tcp"`, `name="TUN-full.T4-G2-30m-selector"`,
		`name="TUN-full.T4-G3-100k-pps"`, "not run after TUN-full.T4-G1-1GiB-tcp failed",
	} {
		if !strings.Contains(string(junit), want) {
			t.Fatalf("JUnit missing %q:\n%s", want, junit)
		}
	}
}

func TestListIsMachineReadableAndDoesNotRequireExecutionEnvironment(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runCLI([]string{"--list"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("runCLI code=%d stderr=%s", code, stderr.String())
	}
	var doc listDocument
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout.String())
	}
	if doc.SchemaVersion != listSchemaVersion || len(doc.Catalogs) != 2 {
		t.Fatalf("list document=%+v", doc)
	}
	if doc.Catalogs[0].Suite != manifest.SuiteNormal || len(doc.Catalogs[0].Cases) != len(catalog.NormalFull()) {
		t.Fatalf("normal catalog summary=%+v", doc.Catalogs[0])
	}
	if doc.Catalogs[1].Suite != manifest.SuiteTUN || doc.Catalogs[1].EvidenceClass != tunSyntheticEvidenceClass || len(doc.Catalogs[1].Cases) != len(tunfull.Specs())+len(tunfull.Aliases()) {
		t.Fatalf("TUN catalog summary=%+v", doc.Catalogs[1])
	}
	if !strings.Contains(stdout.String(), `"default_run": false`) {
		t.Fatal("JSON hides non-default compatibility entries")
	}
	if !strings.Contains(stdout.String(), `"requires":`) {
		t.Fatal("JSON hides executable prerequisite metadata")
	}
}

func TestScopedListUsesExecutionPlan(t *testing.T) {
	prepared, err := prepareCommand(runFlags{list: true, caseID: "T5.4-gvisor-unprivileged"})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.list == nil || len(prepared.list.Catalogs) != 1 {
		t.Fatalf("prepared=%+v", prepared)
	}
	got := prepared.list.Catalogs[0]
	if len(got.Cases) != 1 || got.Cases[0].Tier != "T5" || !reflect.DeepEqual(got.RunOrder, []string{"T5.4-gvisor-unprivileged"}) {
		t.Fatalf("scoped normal list=%+v", got)
	}

	prepared, err = prepareCommand(runFlags{list: true, tunFull: true, caseID: "TUN-full.T4-long-run"})
	if err != nil {
		t.Fatal(err)
	}
	got = prepared.list.Catalogs[0]
	if len(got.Cases) != 1 || got.Cases[0].Kind != tunKindCompatibilitySelector || !reflect.DeepEqual(got.RunOrder, []string{
		"TUN-full.preflight-kernel-tun",
		"TUN-full.T4-G1-1GiB-tcp",
		"TUN-full.T4-G2-30m-selector",
		"TUN-full.T4-G3-100k-pps",
	}) {
		t.Fatalf("scoped TUN list=%+v", got)
	}
}

func TestSpecsForPlanSupportsSyntheticRegistries(t *testing.T) {
	registries := map[string][]manifest.Spec{
		"T1": {
			manifest.RequiredWithBudget("synthetic.one", "T1", time.Second),
			manifest.RequiredWithBudget("synthetic.two", "T1", time.Second),
		},
		"T2": {
			manifest.RequiredWithBudget("synthetic.three", "T2", time.Second),
		},
	}
	plan := runplan.Plan{Runs: []runplan.TierRun{
		{Tier: "T1", FromCase: "synthetic.two"},
		{Tier: "T2"},
	}}
	got, err := specsForPlan(plan, func(tier string) []manifest.Spec {
		return append([]manifest.Spec(nil), registries[tier]...)
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"synthetic.two", "synthetic.three"}
	if !reflect.DeepEqual(specIDs(got), want) {
		t.Fatalf("selected IDs=%v want %v", specIDs(got), want)
	}
}

func TestReconcileReportRowsFailsClosed(t *testing.T) {
	expected := []manifest.Spec{
		manifest.RequiredWithBudget("one", "T1", time.Second),
		manifest.RequiredWithBudget("two", "T1", time.Second),
	}
	tests := []struct {
		name   string
		actual []report.Case
		want   string
	}{
		{name: "valid", actual: []report.Case{{Name: "one", Tier: "T1"}, {Name: "two", Tier: "T1"}}},
		{name: "zero rows", want: "row count mismatch"},
		{name: "missing row", actual: []report.Case{{Name: "one", Tier: "T1"}}, want: "row count mismatch"},
		{name: "extra row", actual: []report.Case{{Name: "one", Tier: "T1"}, {Name: "two", Tier: "T1"}, {Name: "extra", Tier: "T1"}}, want: "row count mismatch"},
		{name: "duplicate", actual: []report.Case{{Name: "one", Tier: "T1"}, {Name: "one", Tier: "T1"}}, want: "duplicate"},
		{name: "wrong order", actual: []report.Case{{Name: "two", Tier: "T1"}, {Name: "one", Tier: "T1"}}, want: "ID mismatch"},
		{name: "wrong tier", actual: []report.Case{{Name: "one", Tier: "T2"}, {Name: "two", Tier: "T1"}}, want: "tier mismatch"},
		{name: "mandatory downgraded", actual: []report.Case{{Name: "one", Tier: "T1", Optional: true}, {Name: "two", Tier: "T1"}}, want: "downgraded to optional"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := reconcileReportRows(expected, tt.actual)
			if tt.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err=%v want substring %q", err, tt.want)
			}
		})
	}
}

func TestTUNRunOrderResolvesExactUniqueSpecs(t *testing.T) {
	specs := tunfull.Specs()
	selected, err := tunSpecsForRunOrder(specs, []string{"TUN-full.G4-path-death", "TUN-full.G5-path-recovery"})
	if err != nil {
		t.Fatal(err)
	}
	if got := specIDs(selected); !reflect.DeepEqual(got, []string{"TUN-full.G4-path-death", "TUN-full.G5-path-recovery"}) {
		t.Fatalf("selected=%v", got)
	}
	if _, err := tunSpecsForRunOrder(specs, []string{"missing"}); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown err=%v", err)
	}
	if _, err := tunSpecsForRunOrder(specs, []string{"TUN-full.G4-path-death", "TUN-full.G4-path-death"}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate err=%v", err)
	}

	catalog, err := buildTUNCatalog(specs, tunfull.Aliases())
	if err != nil {
		t.Fatal(err)
	}
	exact, err := catalog.selectCases("TUN-full.G4-path-death", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := exact.runOrder; !reflect.DeepEqual(got, []string{"TUN-full.preflight-kernel-tun", "TUN-full.G4-path-death"}) {
		t.Fatalf("exact run order=%v", got)
	}
	resumed, err := catalog.selectCases("", "TUN-full.G4-path-death")
	if err != nil {
		t.Fatal(err)
	}
	if got := resumed.runOrder; len(got) < 2 || got[0] != "TUN-full.preflight-kernel-tun" || got[1] != "TUN-full.G4-path-death" {
		t.Fatalf("resume run order=%v", got)
	}
}

func TestTunFullUnimplementedCaseFails(t *testing.T) {
	c := tunFullUnimplementedCase()
	if c.Name != "TUN-full-not-implemented" || c.Tier != "T7" || c.Failure == "" {
		t.Fatalf("bad tun-full guard case: %+v", c)
	}
}

func findListedCase(t *testing.T, cases []listedCase, id string) listedCase {
	t.Helper()
	for _, c := range cases {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("case %q not listed", id)
	return listedCase{}
}

func specIDs(specs []manifest.Spec) []string {
	ids := make([]string, len(specs))
	for i, spec := range specs {
		ids[i] = spec.ID
	}
	return ids
}

func installSyntheticTierCommands(t *testing.T) func() {
	t.Helper()
	originals := make(map[string]tierCommand, len(tierCommands))
	for tier, original := range tierCommands {
		originals[tier] = original
		tier := tier
		command := original
		command.run = func(_ context.Context, suite *report.Suite, _ string, selection tierSelection) {
			selected, err := manifest.Select(catalog.ByTier(tier), selection.Case, selection.FromCase)
			if err != nil {
				t.Fatal(err)
			}
			for _, spec := range selected {
				suite.Add(report.Case{Name: spec.ID, Tier: spec.Tier})
			}
		}
		tierCommands[tier] = command
	}
	return func() {
		for tier, original := range originals {
			tierCommands[tier] = original
		}
	}
}

func newMainTestRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	runMainTestGit(t, root, "init", "--quiet")
	runMainTestGit(t, root, "config", "user.name", "rendr regression test")
	runMainTestGit(t, root, "config", "user.email", "regress@example.invalid")
	if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("initial\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runMainTestGit(t, root, "add", "tracked.txt")
	runMainTestGit(t, root, "commit", "--quiet", "-m", "initial")
	return root
}

func runMainTestGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v (%s)", args, err, strings.TrimSpace(string(out)))
	}
}
