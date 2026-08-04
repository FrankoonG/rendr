package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/catalog"
	"github.com/FrankoonG/rendr/regress/internal/environment"
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

func TestPrepareCommandResolvesCanonicalCaseSuite(t *testing.T) {
	exactID := "TUN-full.G4-path-death"
	prepared, err := prepareCommand(runFlags{caseID: exactID})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.tun == nil || prepared.normal != nil || !reflect.DeepEqual(prepared.tun.runOrder, []string{"TUN-full.preflight-kernel-tun", exactID}) {
		t.Fatalf("globally resolved exact TUN command=%+v", prepared)
	}
	if len(prepared.tun.cases) != 1 || prepared.tun.cases[0].ID != exactID || prepared.tun.cases[0].Kind != tunKindCase {
		t.Fatalf("exact TUN selection=%+v", prepared.tun)
	}

	resumeID := "TUN-full.T3-xray-matrix"
	prepared, err = prepareCommand(runFlags{fromCaseID: resumeID})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.tun == nil || len(prepared.tun.runOrder) < 2 || prepared.tun.runOrder[0] != "TUN-full.preflight-kernel-tun" || prepared.tun.runOrder[1] != resumeID {
		t.Fatalf("globally resolved TUN resume=%+v", prepared)
	}

	prepared, err = prepareCommand(runFlags{selectorID: "TUN-full.T4-long-run"})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.tun == nil || len(prepared.tun.runOrder) != 4 || prepared.tun.runOrder[0] != "TUN-full.preflight-kernel-tun" {
		t.Fatalf("explicit TUN selector=%+v", prepared)
	}

	if _, err := prepareCommand(runFlags{tunFull: true, caseID: "go-vet"}); err == nil || !strings.Contains(err.Error(), "normal suite") {
		t.Fatalf("cross-suite exact case err=%v", err)
	}

	tunCases, err := buildTUNCatalog(tunfull.Specs(), tunfull.Aliases())
	if err != nil {
		t.Fatal(err)
	}
	ambiguous := []manifest.Spec{manifest.RequiredWithBudget(exactID, "T1", time.Second)}
	if _, err := resolveCommandSuite(runFlags{caseID: exactID}, ambiguous, tunCases); err == nil || !strings.Contains(err.Error(), "globally ambiguous") {
		t.Fatalf("ambiguous executable CaseID err=%v", err)
	}
	selectorCollision := catalog.NormalFull()[:1]
	selectorCollision[0].ID = "TUN-full.T4-long-run"
	if err := validateGlobalCatalogNames(selectorCollision, tunCases); err == nil || !strings.Contains(err.Error(), "TUN selector") {
		t.Fatalf("selector/executable collision err=%v", err)
	}
}

func TestPrepareCommandRejectsConflictsAndOutOfScopeFilters(t *testing.T) {
	tests := []struct {
		name string
		cfg  runFlags
		want string
	}{
		{name: "both filters", cfg: runFlags{caseID: "go-vet", fromCaseID: "go-test"}, want: "mutually exclusive"},
		{name: "case and selector", cfg: runFlags{caseID: "go-vet", selectorID: "TUN-full.T4-long-run"}, want: "mutually exclusive"},
		{name: "both full suites", cfg: runFlags{full: true, tunFull: true}, want: "mutually exclusive"},
		{name: "tun and phase", cfg: runFlags{tunFull: true, phase: "2"}, want: "cannot be combined"},
		{name: "tun and tier", cfg: runFlags{tunFull: true, tier: "7"}, want: "cannot be combined"},
		{name: "phase one force", cfg: runFlags{phase: "1", forcePhase2: true}, want: "cannot be combined"},
		{name: "list force", cfg: runFlags{list: true, forcePhase2: true}, want: "cannot be combined"},
		{name: "list unproven", cfg: runFlags{list: true, allowUnprovenContracts: true}, want: "cannot be combined"},
		{name: "legacy profile", cfg: runFlags{profile: "PYS-D-1"}, want: "not supported"},
		{name: "full and tier", cfg: runFlags{full: true, tier: "4"}, want: "cannot be combined"},
		{name: "full and exact case", cfg: runFlags{full: true, caseID: "go-test"}, want: "--full cannot be combined"},
		{name: "full and resume", cfg: runFlags{full: true, fromCaseID: "go-test"}, want: "--full cannot be combined"},
		{name: "full and selector", cfg: runFlags{full: true, selectorID: "TUN-full.T4-long-run"}, want: "--full cannot be combined"},
		{name: "invalid phase", cfg: runFlags{phase: "3"}, want: "invalid --phase"},
		{name: "invalid tier", cfg: runFlags{tier: "9"}, want: "invalid --tier"},
		{name: "case outside phase", cfg: runFlags{phase: "1", caseID: "T8.status.local-default"}, want: "no case matched"},
		{name: "case outside tier", cfg: runFlags{tier: "6", caseID: "G5"}, want: "no case matched"},
		{name: "unknown normal case", cfg: runFlags{caseID: "missing"}, want: "no case matched"},
		{name: "unknown TUN case", cfg: runFlags{tunFull: true, caseID: "missing"}, want: "no case matched"},
		{name: "compatibility ID as case", cfg: runFlags{caseID: "TUN-full.T4-long-run"}, want: "use --selector"},
		{name: "compatibility ID as resume", cfg: runFlags{fromCaseID: "TUN-full.T4-long-run"}, want: "use --selector"},
		{name: "selector with tier", cfg: runFlags{tier: "7", selectorID: "TUN-full.T4-long-run"}, want: "cannot be combined"},
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
	state, err := buildPhase1State(wantRoot, "red", wantTime, func(gotRoot string) (gate.Revision, error) {
		if gotRoot != wantRoot {
			t.Fatalf("CurrentRevision root=%q want %q", gotRoot, wantRoot)
		}
		return gate.Revision{CommitSHA: "commit", WorktreeSHA: "worktree"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := gate.State{SchemaVersion: gate.StateSchemaVersion, CommitSHA: "commit", WorktreeSHA: "worktree", Status: "red", At: wantTime}
	if !reflect.DeepEqual(state, want) {
		t.Fatalf("state=%+v want %+v", state, want)
	}

	_, err = buildPhase1State(wantRoot, "red", wantTime, func(string) (gate.Revision, error) {
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

func TestUpdateInvocationEnvironmentRequiresStableIdentityAndRestoredQDisc(t *testing.T) {
	start := testEnvironmentWithQDisc(t, `[{"dev":"test0","kind":"fq_codel"}]`)
	suite := report.New()
	suite.Invocation.EnvironmentStart = start
	if err := updateInvocationEnvironment(context.Background(), suite, func(context.Context) (environment.Snapshot, error) {
		return start, nil
	}); err != nil {
		t.Fatalf("stable environment: %v", err)
	}

	leaked := testEnvironmentWithQDisc(t, `[{"dev":"test0","kind":"netem"}]`)
	err := updateInvocationEnvironment(context.Background(), suite, func(context.Context) (environment.Snapshot, error) {
		return leaked, nil
	})
	if err == nil || !strings.Contains(err.Error(), "qdisc state was not restored") {
		t.Fatalf("qdisc leak error = %v", err)
	}
	if suite.Invocation.EnvironmentEnd.QDisc.Digest != leaked.QDisc.Digest {
		t.Fatalf("leaked end snapshot was not retained: %+v", suite.Invocation.EnvironmentEnd.QDisc)
	}

	drifted := start
	drifted.Hostname = "other-host"
	drifted, sealErr := environment.Seal(drifted)
	if sealErr != nil {
		t.Fatal(sealErr)
	}
	err = updateInvocationEnvironment(context.Background(), suite, func(context.Context) (environment.Snapshot, error) {
		return drifted, nil
	})
	if err == nil || !strings.Contains(err.Error(), "stable environment identity changed") {
		t.Fatalf("identity drift error = %v", err)
	}
}

func TestBeginInvocationFailsClosedWhenEnvironmentCaptureFails(t *testing.T) {
	dir := t.TempDir()
	spec := manifest.RequiredWithBudget("synthetic.one", "T1", time.Second)
	revisionCalled := false
	_, _, err := beginInvocation(
		context.Background(),
		runFlags{caseID: spec.ID, reportDir: dir, rendrRoot: "/exact/root"},
		manifest.SuiteNormal,
		[]manifest.Spec{spec},
		func(string) (gate.Revision, error) {
			revisionCalled = true
			return gate.Revision{CommitSHA: "commit", WorktreeSHA: "tree"}, nil
		},
		func(context.Context) (environment.Snapshot, error) {
			return environment.Snapshot{}, errors.New("mandatory source unavailable")
		},
		newTestReportStore(t, dir),
	)
	if err == nil || !strings.Contains(err.Error(), "mandatory source unavailable") {
		t.Fatalf("begin invocation error = %v", err)
	}
	if revisionCalled {
		t.Fatal("revision fingerprint ran after mandatory environment capture failed")
	}
	junit, readErr := os.ReadFile(filepath.Join(dir, junitReportFileName))
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, want := range []string{`state="fail"`, "cannot capture invocation start environment", "start environment snapshot is missing"} {
		if !strings.Contains(string(junit), want) {
			t.Fatalf("failure JUnit missing %q:\n%s", want, junit)
		}
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
	cfg := runFlags{caseID: spec.ID, reportDir: dir, rendrRoot: "/exact/root", allowNonLinux: true}
	suite, revision, err := beginInvocation(
		context.Background(),
		cfg,
		manifest.SuiteNormal,
		[]manifest.Spec{spec},
		func(root string) (gate.Revision, error) {
			if root != cfg.rendrRoot {
				t.Fatalf("root=%q want %q", root, cfg.rendrRoot)
			}
			return gate.Revision{CommitSHA: "commit", WorktreeSHA: "tree"}, nil
		},
		captureTestEnvironment,
		newTestReportStore(t, dir),
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
	for _, name := range []string{junitReportFileName, markdownReportFileName, jsonReportFileName} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("STALE-PASS"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writerCalled := false
	_, _, err := beginInvocation(
		context.Background(),
		runFlags{reportDir: dir, rendrRoot: "/exact/root", allowNonLinux: true},
		manifest.SuiteNormal,
		[]manifest.Spec{manifest.RequiredWithBudget("one", "T1", time.Second)},
		func(string) (gate.Revision, error) {
			return gate.Revision{CommitSHA: "commit", WorktreeSHA: "tree"}, nil
		},
		captureTestEnvironment,
		invocationReportStore{
			invalidate: newTestReportStore(t, dir).invalidate,
			publish: func(context.Context, *report.Suite) error {
				writerCalled = true
				for _, name := range []string{junitReportFileName, markdownReportFileName, jsonReportFileName} {
					if _, statErr := os.Stat(filepath.Join(dir, name)); !errors.Is(statErr, os.ErrNotExist) {
						t.Fatalf("stale %s still exists before replacement write: %v", name, statErr)
					}
				}
				return errors.New("synthetic writer failure")
			},
		},
	)
	if !writerCalled || err == nil || !strings.Contains(err.Error(), "synthetic writer failure") {
		t.Fatalf("writerCalled=%v err=%v", writerCalled, err)
	}

	blockedDir := t.TempDir()
	blockedSummary := filepath.Join(blockedDir, markdownReportFileName)
	if err := os.Mkdir(blockedSummary, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blockedSummary, "keep"), []byte("block replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeReports(report.New(), blockedDir); err == nil {
		t.Fatalf("companion report failure=%v", err)
	}
	if _, err := os.Stat(filepath.Join(blockedDir, jsonReportFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canonical report was committed before companion reports: %v", err)
	}
	if _, err := os.Stat(filepath.Join(blockedDir, junitReportFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("green JUnit survived an incomplete report set: %v", err)
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
	exact, err := buildInvocationIdentity(runFlags{caseID: "two", forcePhase2: true, allowNonLinux: true}, manifest.SuiteNormal, all[1:])
	if err != nil {
		t.Fatal(err)
	}
	if full.Scope != "full" || full.Forced || full.SelectedCases != 2 || !full.Full || full.TUNFull ||
		full.SchemaVersion != invocationSchemaVersion || full.EvidenceClass != normalComponentEvidenceClass || full.ReleaseManifest ||
		!reflect.DeepEqual(full.RequestedCaseIDs, []string{"one", "two"}) || full.RequestAnchor != "one" {
		t.Fatalf("full identity=%+v", full)
	}
	if exact.Scope != "exact" || exact.Case != "two" || !exact.Forced || exact.SelectedCases != 1 ||
		!exact.AllowNonLinux || exact.ResumeCaseID != "two" || !reflect.DeepEqual(exact.SelectedCaseIDs, []string{"two"}) ||
		!reflect.DeepEqual(exact.RequestedCaseIDs, []string{"two"}) || exact.RequestAnchor != "two" {
		t.Fatalf("exact identity=%+v", exact)
	}
	exactWithPrerequisite, err := buildInvocationIdentity(
		runFlags{caseID: "two"},
		manifest.SuiteNormal,
		all,
	)
	if err != nil || exactWithPrerequisite.Scope != "exact" || exactWithPrerequisite.Case != "two" ||
		!reflect.DeepEqual(exactWithPrerequisite.SelectedCaseIDs, []string{"one", "two"}) ||
		!reflect.DeepEqual(exactWithPrerequisite.RequestedCaseIDs, []string{"two"}) ||
		exactWithPrerequisite.RequestAnchor != "two" || exactWithPrerequisite.ResumeCaseID != "one" {
		t.Fatalf("exact identity with prerequisite=%+v err=%v", exactWithPrerequisite, err)
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
	if tun.Suite != manifest.SuiteTUN || tun.Scope != "full" || !tun.Forced || !tun.TUNFull || tun.CatalogDigest == "" ||
		tun.EvidenceClass != tunSyntheticEvidenceClass || tun.ReleaseManifest {
		t.Fatalf("TUN/forced identity=%+v", tun)
	}
	selector, err := buildInvocationIdentity(runFlags{tunFull: true, selectorID: "legacy-selector"}, manifest.SuiteTUN, all[:1])
	if err != nil {
		t.Fatal(err)
	}
	if selector.Scope != "selector" || selector.Case != "" || selector.Selector != "legacy-selector" || selector.ResumeCaseID != "one" ||
		selector.RequestAnchor != "legacy-selector" || !reflect.DeepEqual(selector.RequestedCaseIDs, []string{"one"}) {
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
	cfg := runFlags{fromCaseID: "go-test", allowNonLinux: true, allowUnprovenContracts: true, reportDir: reportDir, rendrRoot: root}
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
	if _, err := os.Stat(filepath.Join(reportDir, junitReportFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("gate rejection overwrote phase-1 evidence: %v", err)
	}

	greenDir := t.TempDir()
	writeSyntheticGreenPhase1Gate(t, greenDir, root)
	greenCfg := cfg
	greenCfg.reportDir = greenDir
	stdout.Reset()
	stderr.Reset()
	if code := executeNormal(context.Background(), greenCfg, plan, &stdout, &stderr); code != exitOK {
		t.Fatalf("green-gated code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := executeNormal(context.Background(), greenCfg, plan, &stdout, &stderr); code != exitOK {
		t.Fatalf("second green-gated resume code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	verifiedResume, err := report.Verify(context.Background(), greenDir)
	if err != nil {
		t.Fatal(err)
	}
	gateState, err := gate.Read(greenDir)
	if err != nil {
		t.Fatal(err)
	}
	authorization := verifiedResume.Report.Invocation.Phase1Authorization
	if authorization == nil || authorization.ReportSetGeneration != gateState.ReportSetGeneration ||
		authorization.CanonicalReportDigest != gateState.CanonicalReportDigest {
		t.Fatalf("phase-2 report authorization=%+v gate=%+v", authorization, gateState)
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

func TestBuildPhase1ProofSuiteProjectsCombinedInvocation(t *testing.T) {
	first, firstEvidence := syntheticEnforcedSpec(t, "phase1.one", "T1")
	second, secondEvidence := syntheticEnforcedSpec(t, "phase1.two", "T2")
	phase2, _ := syntheticEnforcedSpec(t, "phase2.one", "T3")
	phase1Specs := []manifest.Spec{first, second}
	combinedSpecs := append(manifest.CloneSpecs(phase1Specs), phase2)
	identity, err := buildInvocationIdentity(runFlags{full: true}, manifest.SuiteNormal, combinedSpecs)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := captureTestLinuxEnvironment(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	revision := gate.Revision{CommitSHA: "phase1-commit", WorktreeSHA: strings.Repeat("a", 64)}
	identity.EnvironmentStart = snapshot
	identity.EnvironmentEnd = snapshot
	identity.RevisionStart = reportRevision(revision)
	identity.RevisionEnd = reportRevision(revision)
	source := report.New()
	source.Invocation = identity
	source.Add(report.Case{Name: first.ID, Tier: first.Tier, Evidence: firstEvidence})
	source.Add(report.Case{Name: second.ID, Tier: second.Tier, Evidence: secondEvidence})

	proof, err := buildPhase1ProofSuite(source, phase1Specs)
	if err != nil {
		t.Fatal(err)
	}
	if source.Complete || proof == source || !proof.Complete || proof.Invocation.Scope != "phase-1" || proof.Invocation.Full || len(proof.Cases) != 2 {
		t.Fatalf("source/proof projection source_complete=%t proof=%+v", source.Complete, proof.Invocation)
	}
	document, err := proof.Document()
	if err != nil {
		t.Fatal(err)
	}
	if document.State != "pass" {
		t.Fatalf("phase 1 proof state=%q", document.State)
	}

	dir := t.TempDir()
	firstGeneration, err := publishPhase1Proof(context.Background(), dir, proof, phase1Specs)
	if err != nil {
		t.Fatal(err)
	}
	secondGeneration, err := publishPhase1Proof(context.Background(), dir, proof, phase1Specs)
	if err != nil {
		t.Fatal(err)
	}
	if firstGeneration.Manifest.Generation == secondGeneration.Manifest.Generation {
		t.Fatal("phase 1 proof generations collided")
	}
	for _, generation := range []string{firstGeneration.Manifest.Generation, secondGeneration.Manifest.Generation} {
		if _, err := report.Verify(context.Background(), phase1ProofDir(dir, generation)); err != nil {
			t.Fatalf("immutable phase 1 generation %s: %v", generation, err)
		}
	}
	state := gate.State{
		SchemaVersion: gate.StateSchemaVersion, CommitSHA: revision.CommitSHA, WorktreeSHA: revision.WorktreeSHA,
		ReportSetGeneration: secondGeneration.Manifest.Generation, CanonicalReportDigest: secondGeneration.Manifest.CanonicalReportDigest,
		Status: "green", At: time.Now(),
	}
	if err := validatePhase1Proof(state, secondGeneration, phase1Specs); err != nil {
		t.Fatalf("canonical phase 1 proof rejected: %v", err)
	}
}

func TestValidatePhase1ProofRejectsWrongIdentity(t *testing.T) {
	dir := t.TempDir()
	root := newMainTestRepo(t)
	writeSyntheticGreenPhase1Gate(t, dir, root)
	state, err := gate.Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := phase1SpecsProvider()
	if err != nil {
		t.Fatal(err)
	}
	readProof := func(t *testing.T) report.VerifiedSet {
		t.Helper()
		verified, err := report.Verify(context.Background(), phase1ProofDir(dir, state.ReportSetGeneration))
		if err != nil {
			t.Fatal(err)
		}
		verified.Report.Cases = cloneReportCases(verified.Report.Cases)
		verified.Report.Invocation.SelectedCaseIDs = append([]string(nil), verified.Report.Invocation.SelectedCaseIDs...)
		verified.Report.Invocation.RequestedCaseIDs = append([]string(nil), verified.Report.Invocation.RequestedCaseIDs...)
		return verified
	}
	if err := validatePhase1Proof(*state, readProof(t), expected); err != nil {
		t.Fatalf("valid proof rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*report.VerifiedSet)
	}{
		{name: "schema downgrade", mutate: func(v *report.VerifiedSet) { v.Report.Invocation.SchemaVersion-- }},
		{name: "wrong scope", mutate: func(v *report.VerifiedSet) { v.Report.Invocation.Scope = "exact" }},
		{name: "forced", mutate: func(v *report.VerifiedSet) { v.Report.Invocation.Forced = true }},
		{name: "wrong catalog", mutate: func(v *report.VerifiedSet) { v.Report.Invocation.CatalogDigest = "sha256:" + strings.Repeat("f", 64) }},
		{name: "wrong revision", mutate: func(v *report.VerifiedSet) { v.Report.Invocation.RevisionEnd.CommitSHA = "other" }},
		{name: "partial selected IDs", mutate: func(v *report.VerifiedSet) {
			v.Report.Invocation.SelectedCaseIDs = v.Report.Invocation.SelectedCaseIDs[:1]
		}},
		{name: "wrong case digest", mutate: func(v *report.VerifiedSet) { v.Report.Cases[0].CaseDigest = "sha256:" + strings.Repeat("e", 64) }},
		{name: "self-attested blocked contract", mutate: func(v *report.VerifiedSet) {
			v.Report.Cases[0].Evidence[report.EvidenceContractStateKey] = string(manifest.ContractStateBlocked)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verified := readProof(t)
			tt.mutate(&verified)
			if err := validatePhase1Proof(*state, verified, expected); err == nil {
				t.Fatal("malformed phase 1 proof was accepted")
			}
		})
	}
}

func TestVerifyFinalPhase1AuthorizationRejectsMissingOrWrongLineage(t *testing.T) {
	dir := t.TempDir()
	root := newMainTestRepo(t)
	writeSyntheticGreenPhase1Gate(t, dir, root)
	authorization, err := verifyPhase1Gate(context.Background(), dir, root)
	if err != nil {
		t.Fatal(err)
	}
	cfg := runFlags{reportDir: dir, rendrRoot: root}
	suite := report.New()
	suite.Invocation.Phase1Authorization = &authorization
	if err := verifyFinalPhase1Authorization(context.Background(), cfg, suite); err != nil {
		t.Fatalf("valid lineage rejected: %v", err)
	}
	suite.Invocation.Phase1Authorization = nil
	if err := verifyFinalPhase1Authorization(context.Background(), cfg, suite); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing lineage error=%v", err)
	}
	wrong := authorization
	wrong.ReportSetGeneration = strings.Repeat("f", 32)
	suite.Invocation.Phase1Authorization = &wrong
	if err := verifyFinalPhase1Authorization(context.Background(), cfg, suite); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("wrong lineage error=%v", err)
	}
}

func TestExecuteNormalFinalAuthorizationFailureReplacesPassingReport(t *testing.T) {
	dir := t.TempDir()
	root := newMainTestRepo(t)
	writeSyntheticGreenPhase1Gate(t, dir, root)
	plan, err := runplan.Build(runplan.Request{Case: "T5.4-gvisor-unprivileged"})
	if err != nil {
		t.Fatal(err)
	}
	original := tierCommands["T5"]
	command := original
	command.run = func(_ context.Context, suite *report.Suite, _ string, _ tierSelection) {
		spec, ok := findManifestSpec(catalog.ByTier("T5"), "T5.4-gvisor-unprivileged")
		if !ok {
			t.Fatal("T5.4 spec is missing")
		}
		suite.Add(report.Case{Name: spec.ID, Tier: spec.Tier, Evidence: syntheticContractEvidence(spec)})
		state, err := gate.Read(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(phase1ProofDir(dir, state.ReportSetGeneration)); err != nil {
			t.Fatal(err)
		}
	}
	tierCommands["T5"] = command
	t.Cleanup(func() { tierCommands["T5"] = original })
	cfg := runFlags{
		caseID: "T5.4-gvisor-unprivileged", allowNonLinux: true, allowUnprovenContracts: true,
		rendrRoot: root, reportDir: dir,
	}
	var stdout, stderr bytes.Buffer
	if code := executeNormal(context.Background(), cfg, plan, &stdout, &stderr); code != exitPhase1Stale {
		t.Fatalf("code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	verified, err := report.Verify(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Report.State != "fail" || verified.Report.Complete || !strings.Contains(verified.Report.RunFailure, "final phase 1 authorization") {
		t.Fatalf("persisted final authorization failure=%+v", verified.Report)
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
	cfg := runFlags{caseID: "go-vet", allowUnprovenContracts: true, reportDir: reportDir, rendrRoot: root}
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

func TestExecuteNormalExitFollowsFinalizedReportValidity(t *testing.T) {
	root := newMainTestRepo(t)
	reportDir := t.TempDir()
	original := tierCommands["T1"]
	command := original
	command.run = func(_ context.Context, suite *report.Suite, _ string, _ tierSelection) {
		suite.Add(report.Case{Name: "go-vet", Tier: "T1"})
		suite.FailRun("synthetic finalized-report failure")
	}
	tierCommands["T1"] = command
	t.Cleanup(func() { tierCommands["T1"] = original })

	plan, err := runplan.Build(runplan.Request{Case: "go-vet"})
	if err != nil {
		t.Fatal(err)
	}
	var preflightOut, preflightErr bytes.Buffer
	if code := executeNormal(context.Background(), runFlags{
		caseID: "go-vet", allowNonLinux: true,
		reportDir: t.TempDir(), rendrRoot: root,
	}, plan, &preflightOut, &preflightErr); code != exitEnvError || !strings.Contains(preflightErr.String(), "--allow-unproven-contracts") {
		t.Fatalf("unproven preflight code=%d stderr=%s stdout=%s", code, preflightErr.String(), preflightOut.String())
	}
	cfg := runFlags{
		caseID: "go-vet", allowNonLinux: true, allowUnprovenContracts: true,
		reportDir: reportDir, rendrRoot: root,
	}
	var stdout, stderr bytes.Buffer
	if code := executeNormal(context.Background(), cfg, plan, &stdout, &stderr); code != exitT1Fail {
		t.Fatalf("code=%d want %d stderr=%s stdout=%s", code, exitT1Fail, stderr.String(), stdout.String())
	}
	if !strings.Contains(stderr.String(), `T1: FAILED`) {
		t.Fatalf("missing harness-failure diagnostic: %s", stderr.String())
	}
	junit, err := os.ReadFile(filepath.Join(reportDir, junitReportFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(junit), `state="fail"`) || !strings.Contains(string(junit), "synthetic finalized-report failure") {
		t.Fatalf("unexpected finalized report:\n%s", junit)
	}

	partialSpec := catalog.NormalFull()[0]
	partialIdentity, err := buildInvocationIdentity(runFlags{caseID: partialSpec.ID, allowNonLinux: true}, manifest.SuiteNormal, []manifest.Spec{partialSpec})
	if err != nil {
		t.Fatal(err)
	}
	partialIdentity.EnvironmentStart, err = captureTestEnvironment(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	partialIdentity.RevisionStart = report.Revision{CommitSHA: "partial-commit", WorktreeSHA: "partial-tree"}
	partial := report.New()
	partial.Invocation = partialIdentity
	partialDir := t.TempDir()
	if err := writeReports(partial, partialDir); err != nil {
		t.Fatal(err)
	}
	if err := requirePassingFinalReport(partialDir, partial, []manifest.Spec{partialSpec}); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("partial final report err=%v", err)
	}
}

func TestWriteKnownPhase1GateRejectsMissingIdentity(t *testing.T) {
	err := writeKnownPhase1Gate(t.TempDir(), gate.Revision{}, "running", time.Now())
	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("err=%v", err)
	}
	err = writeKnownPhase1Gate(t.TempDir(), gate.Revision{CommitSHA: "commit", WorktreeSHA: "tree"}, "green", time.Now())
	if err == nil || !strings.Contains(err.Error(), "report-set generation") {
		t.Fatalf("green gate without report binding err=%v", err)
	}
}

func TestTUNCatalogMakesCompatibilitySelectorsExplicit(t *testing.T) {
	tunCatalog, err := buildTUNCatalog(tunfull.Specs(), tunfull.Aliases())
	if err != nil {
		t.Fatal(err)
	}
	selection, err := tunCatalog.selectCases("", "", "")
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
	if streamCompat.InDefaultCommand || streamCompat.InSuiteFull || streamCompat.Mandatory || streamCompat.Kind != tunKindCompatibilityAlias || !reflect.DeepEqual(streamCompat.ExpandsTo, []string{"TUN-full.T3-xray-matrix"}) {
		t.Fatalf("stream compatibility entry=%+v", streamCompat)
	}
	longCompat := findListedCase(t, selection.cases, "TUN-full.T4-long-run")
	if longCompat.InDefaultCommand || longCompat.InSuiteFull || longCompat.Kind != tunKindCompatibilitySelector || len(longCompat.ExpandsTo) != 3 {
		t.Fatalf("long-run compatibility entry=%+v", longCompat)
	}

	if _, err := tunCatalog.selectCases("TUN-full.T4-long-run", "", ""); err == nil || !strings.Contains(err.Error(), "use --selector") {
		t.Fatalf("compatibility selector was accepted as --case: %v", err)
	}
	exact, err := tunCatalog.selectCases("", "", "TUN-full.T4-long-run")
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
	exact, err = tunCatalog.selectCases("", "", "TUN-full.T4-G2-30m-prime")
	if err != nil || !reflect.DeepEqual(exact.runOrder, []string{"TUN-full.preflight-kernel-tun", "TUN-full.T4-G2-30m-selector"}) {
		t.Fatalf("prime alias selection=%+v err=%v", exact, err)
	}
	fallbackCompat := findListedCase(t, selection.cases, "TUN-full.T5-fallback")
	if fallbackCompat.Kind != tunKindCompatibilityAlias || !reflect.DeepEqual(fallbackCompat.ExpandsTo, []string{"TUN-full.T5-adapter-matrix"}) || fallbackCompat.RetiredReason == "" {
		t.Fatalf("fallback compatibility entry=%+v", fallbackCompat)
	}
	if _, err := tunCatalog.selectCases("", "", "TUN-full.T5-fallback"); err == nil || !strings.Contains(err.Error(), "is retired") {
		t.Fatalf("retired fallback alias was executable: %v", err)
	}
	if _, err := tunCatalog.selectCases("", "TUN-full.T3-xray-stream-smoke", ""); err == nil || !strings.Contains(err.Error(), "use --selector") {
		t.Fatalf("compatibility selector was accepted as --from-case: %v", err)
	}
	resumed, err := tunCatalog.selectCases("", "TUN-full.T3-xray-matrix", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(resumed.runOrder) < 2 || resumed.runOrder[0] != "TUN-full.preflight-kernel-tun" || resumed.runOrder[1] != "TUN-full.T3-xray-matrix" {
		t.Fatalf("canonical resume is not inclusive: %v", resumed.runOrder)
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
	for i := range badSpecs {
		badSpecs[i].Tier = "T6"
	}
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
	selection, err := catalog.selectCases("", "", "TUN-full.T4-long-run")
	if err != nil {
		t.Fatal(err)
	}

	original := runTUNCase
	t.Cleanup(func() { runTUNCase = original })
	var called []string
	runTUNCase = func(_ context.Context, suite *report.Suite, _ string, planned tunfull.PlannedCase) {
		spec := planned.Spec()
		caseID := spec.ID
		called = append(called, caseID)
		rc := report.Case{Name: caseID, Tier: "T7", Evidence: syntheticContractEvidence(spec)}
		if caseID != "TUN-full.preflight-kernel-tun" {
			rc.Failure = "synthetic failure"
		}
		suite.Add(rc)
	}

	root := newMainTestRepo(t)
	reportDir := t.TempDir()
	cfg := runFlags{
		tunFull: true, selectorID: "TUN-full.T4-long-run", forcePhase2: true,
		allowNonLinux: true, allowUnprovenContracts: true, rendrRoot: root, reportDir: reportDir,
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
		`complete="false"`, `selected_cases="4"`, `invocation_suite="tun-full"`,
		`name="TUN-full.preflight-kernel-tun"`,
		`name="TUN-full.T4-G1-1GiB-tcp"`, `name="TUN-full.T4-G2-30m-selector"`,
		`name="TUN-full.T4-G3-100k-pps"`, `execution_state="not_run"`,
		`blocked_by_case_id="TUN-full.T4-G1-1GiB-tcp"`, "blocked by case TUN-full.T4-G1-1GiB-tcp",
	} {
		if !strings.Contains(string(junit), want) {
			t.Fatalf("JUnit missing %q:\n%s", want, junit)
		}
	}
}

func TestExecuteTUNCanonicalResumeProducesMatchingPassingReport(t *testing.T) {
	catalog, err := buildTUNCatalog(tunfull.Specs(), tunfull.Aliases())
	if err != nil {
		t.Fatal(err)
	}
	resumeID := "TUN-full.G4-path-death"
	selection, err := catalog.selectCases("", resumeID, "")
	if err != nil {
		t.Fatal(err)
	}

	original := runTUNCase
	t.Cleanup(func() { runTUNCase = original })
	runTUNCase = func(_ context.Context, suite *report.Suite, _ string, planned tunfull.PlannedCase) {
		spec := planned.Spec()
		suite.Add(report.Case{Name: spec.ID, Tier: spec.Tier, Evidence: syntheticContractEvidence(spec)})
	}

	reportDir := t.TempDir()
	cfg := runFlags{
		fromCaseID: resumeID, forcePhase2: true, allowNonLinux: true, allowUnprovenContracts: true,
		rendrRoot: newMainTestRepo(t), reportDir: reportDir,
	}
	var stdout, stderr bytes.Buffer
	if code := executeTUN(context.Background(), cfg, selection, &stdout, &stderr); code != exitOK {
		t.Fatalf("code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	junit, err := os.ReadFile(filepath.Join(reportDir, junitReportFileName))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`state="unproven"`, `invocation_scope="from-case"`,
		`invocation_from_case="` + resumeID + `"`,
		`invocation_resume_case_id="TUN-full.preflight-kernel-tun"`,
		`request_anchor="` + resumeID + `"`,
		`evidence_class="` + tunSyntheticEvidenceClass + `"`,
	} {
		if !strings.Contains(string(junit), want) {
			t.Fatalf("canonical resume JUnit missing %q:\n%s", want, junit)
		}
	}
}

func TestExecuteTUNCompatibilitySelectorProducesCanonicalPassingRows(t *testing.T) {
	catalog, err := buildTUNCatalog(tunfull.Specs(), tunfull.Aliases())
	if err != nil {
		t.Fatal(err)
	}
	selectorID := "TUN-full.T3-xray-stream-smoke"
	selection, err := catalog.selectCases("", "", selectorID)
	if err != nil {
		t.Fatal(err)
	}
	wantRows := []string{"TUN-full.preflight-kernel-tun", "TUN-full.T3-xray-matrix"}
	if !reflect.DeepEqual(selection.runOrder, wantRows) {
		t.Fatalf("selector run order=%v want %v", selection.runOrder, wantRows)
	}

	original := runTUNCase
	t.Cleanup(func() { runTUNCase = original })
	runTUNCase = func(_ context.Context, suite *report.Suite, _ string, planned tunfull.PlannedCase) {
		spec := planned.Spec()
		suite.Add(report.Case{Name: spec.ID, Tier: spec.Tier, Evidence: syntheticContractEvidence(spec)})
	}

	reportDir := t.TempDir()
	cfg := runFlags{
		selectorID: selectorID, forcePhase2: true, allowNonLinux: true, allowUnprovenContracts: true,
		rendrRoot: newMainTestRepo(t), reportDir: reportDir,
	}
	var stdout, stderr bytes.Buffer
	if code := executeTUN(context.Background(), cfg, selection, &stdout, &stderr); code != exitOK {
		t.Fatalf("code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	junit, err := os.ReadFile(filepath.Join(reportDir, junitReportFileName))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`state="unproven"`, `invocation_scope="selector"`,
		`invocation_selector="` + selectorID + `"`,
		`request_anchor="` + selectorID + `"`,
		`selected_case_ids="[&#34;` + wantRows[0] + `&#34;,&#34;` + wantRows[1] + `&#34;]"`,
	} {
		if !strings.Contains(string(junit), want) {
			t.Fatalf("selector JUnit missing %q:\n%s", want, junit)
		}
	}
	if strings.Contains(string(junit), `invocation_case="`+selectorID+`"`) {
		t.Fatalf("selector was overloaded into executable case identity:\n%s", junit)
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
	if doc.Catalogs[1].Suite != manifest.SuiteTUN || doc.Catalogs[1].EvidenceClass != tunSyntheticEvidenceClass ||
		len(doc.Catalogs[1].Cases) != len(tunfull.Specs()) || len(doc.Catalogs[1].Selectors) != len(tunfull.Aliases()) {
		t.Fatalf("TUN catalog summary=%+v", doc.Catalogs[1])
	}
	wantDefault, err := normalDefaultCommandRunOrder()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(doc.Catalogs[0].CatalogOrder, manifestIDs(catalog.NormalFull())) ||
		!reflect.DeepEqual(doc.Catalogs[0].DefaultCommandRunOrder, wantDefault) ||
		!reflect.DeepEqual(doc.Catalogs[0].SuiteFullRunOrder, manifestIDs(catalog.NormalFull())) ||
		len(doc.Catalogs[0].SelectedRunOrder) != 0 {
		t.Fatalf("normal projections=%+v", doc.Catalogs[0])
	}
	if len(doc.Catalogs[1].DefaultCommandRunOrder) != 0 ||
		!reflect.DeepEqual(doc.Catalogs[1].SuiteFullRunOrder, manifestIDs(tunfull.Specs())) ||
		len(doc.Catalogs[1].SelectedRunOrder) != 0 {
		t.Fatalf("TUN projections=%+v", doc.Catalogs[1])
	}
	if strings.Contains(stdout.String(), `"default_run"`) || !strings.Contains(stdout.String(), `"in_default_command": false`) {
		t.Fatal("JSON did not replace ambiguous default_run semantics")
	}
	if !strings.Contains(stdout.String(), `"requires":`) {
		t.Fatal("JSON hides executable prerequisite metadata")
	}
	specByID := make(map[string]manifest.Spec)
	for _, spec := range append(catalog.NormalFull(), tunfull.Specs()...) {
		specByID[spec.ID] = spec
	}
	for _, listedCatalog := range doc.Catalogs {
		defaultIDs := make(map[string]bool, len(listedCatalog.DefaultCommandRunOrder))
		for _, id := range listedCatalog.DefaultCommandRunOrder {
			defaultIDs[id] = true
		}
		for _, listed := range listedCatalog.Cases {
			if listed.Kind != tunKindCase {
				t.Fatalf("catalog cases contains non-executable entry: %+v", listed)
			}
			spec, ok := specByID[listed.ID]
			if !ok {
				t.Fatalf("listed executable case %q has no registry spec", listed.ID)
			}
			wantDigest, err := spec.CanonicalDigest()
			if err != nil {
				t.Fatal(err)
			}
			if listed.CaseDigest != wantDigest {
				t.Fatalf("listed case %q digest=%q want %q", listed.ID, listed.CaseDigest, wantDigest)
			}
			if !listed.InSuiteFull || listed.InDefaultCommand != defaultIDs[listed.ID] {
				t.Fatalf("listed case %q projection flags=%+v default IDs=%v", listed.ID, listed, listedCatalog.DefaultCommandRunOrder)
			}
		}
		for _, selector := range listedCatalog.Selectors {
			if selector.Kind != tunKindCompatibilityAlias && selector.Kind != tunKindCompatibilitySelector {
				t.Fatalf("catalog selectors contains executable entry: %+v", selector)
			}
			if selector.CaseDigest != "" || selector.Contract != nil {
				t.Fatalf("non-executable selector %q exposes an executable contract: %+v", selector.ID, selector)
			}
		}
	}
	if _, _, err := splitListedCases([]listedCase{{ID: "invalid", Kind: "unknown"}}); err == nil || !strings.Contains(err.Error(), "unsupported kind") {
		t.Fatalf("unknown listed kind err=%v", err)
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
	if len(got.Cases) != 1 || got.Cases[0].Tier != "T5" || !reflect.DeepEqual(got.SelectedRunOrder, []string{"T5.4-gvisor-unprivileged"}) ||
		!reflect.DeepEqual(got.RequestedCaseIDs, []string{"T5.4-gvisor-unprivileged"}) || got.RequestAnchor != "T5.4-gvisor-unprivileged" ||
		!reflect.DeepEqual(got.CatalogOrder, manifestIDs(catalog.NormalFull())) {
		t.Fatalf("scoped normal list=%+v", got)
	}

	prepared, err = prepareCommand(runFlags{list: true, tunFull: true, selectorID: "TUN-full.T4-long-run"})
	if err != nil {
		t.Fatal(err)
	}
	got = prepared.list.Catalogs[0]
	if len(got.Cases) != 4 || len(got.Selectors) != 1 || findListedCase(t, got.Selectors, "TUN-full.T4-long-run").Kind != tunKindCompatibilitySelector || !reflect.DeepEqual(got.SelectedRunOrder, []string{
		"TUN-full.preflight-kernel-tun",
		"TUN-full.T4-G1-1GiB-tcp",
		"TUN-full.T4-G2-30m-selector",
		"TUN-full.T4-G3-100k-pps",
	}) || !reflect.DeepEqual(got.RequestedCaseIDs, []string{
		"TUN-full.T4-G1-1GiB-tcp",
		"TUN-full.T4-G2-30m-selector",
		"TUN-full.T4-G3-100k-pps",
	}) || got.RequestAnchor != "TUN-full.T4-long-run" {
		t.Fatalf("scoped TUN list=%+v", got)
	}
}

func TestSpecsForPlanSupportsSyntheticRegistries(t *testing.T) {
	prerequisite := manifest.RequiredWithBudget("synthetic.one", "T1", time.Second)
	dependent := manifest.RequiredWithBudget("synthetic.two", "T1", time.Second)
	dependent.Requires = []string{prerequisite.ID}
	registries := map[string][]manifest.Spec{
		"T1": {
			prerequisite,
			dependent,
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
	want := []string{"synthetic.one", "synthetic.two", "synthetic.three"}
	if !reflect.DeepEqual(specIDs(got), want) {
		t.Fatalf("selected IDs=%v want %v", specIDs(got), want)
	}
	invalidContract := manifest.RequiredWithBudget("invalid-contract", "T1", time.Second)
	invalidContract.Contract = &manifest.Contract{SchemaVersion: manifest.ContractSchemaVersion}
	if err := validateSelectedManifest([]manifest.Spec{invalidContract}); err == nil || !strings.Contains(err.Error(), "contract:") {
		t.Fatalf("selected subset accepted invalid contract: %v", err)
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
	validRows := []report.Case{{Name: "one", Tier: "T1"}, {Name: "two", Tier: "T1"}}
	if err := reconcileReportRows(expected, validRows); err != nil {
		t.Fatal(err)
	}
	wantDigest, err := expected[0].CanonicalDigest()
	if err != nil {
		t.Fatal(err)
	}
	if validRows[0].CaseDigest != wantDigest {
		t.Fatalf("reconciled case digest=%q want %q", validRows[0].CaseDigest, wantDigest)
	}
	validRows[1].CaseDigest = "sha256:" + strings.Repeat("f", 64)
	if err := reconcileReportRows(expected, validRows); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("pre-filled wrong case digest err=%v", err)
	}

	contractedBase := manifest.RequiredWithBudget("contracted", "T1", time.Second)
	contracted, err := manifest.NewCompleteSpec(contractedBase, manifest.Contract{
		SchemaVersion: manifest.ContractSchemaVersion,
		State:         manifest.ContractStateBlocked,
		MissingDimensions: []manifest.MissingDimension{{
			Dimension: manifest.ContractDimensionResources,
			Reason:    "minimum isolated allocation is not calibrated",
		}},
		Purpose:          "exercise contract evidence reconciliation",
		Entrypoint:       "cmd/regress.TestReconcileReportRowsFailsClosed",
		Topology:         manifest.Topology{Profile: "in-process", Roles: []string{"runner"}, Isolation: "process", PathCount: 0},
		RoleCapabilities: map[string][]string{"runner": {}},
		Payload:          manifest.Profile{Applicability: manifest.ApplicabilityNotApplicable},
		Load:             manifest.Profile{Applicability: manifest.ApplicabilityNotApplicable},
		Seed:             manifest.SeedPolicy{Mode: manifest.SeedModeNone},
		Stimulus: manifest.EvidenceProfile{Name: "synthetic-stimulus", Version: 1, Assertions: []manifest.EvidenceAssertion{{
			Fact: "stimulus_seen", Predicate: manifest.EvidenceEquals, Expected: "true",
		}}},
		Oracle: manifest.EvidenceProfile{Name: "synthetic-oracle", Version: 1, Assertions: []manifest.EvidenceAssertion{{
			Fact: "oracle_passed", Predicate: manifest.EvidenceEquals, Expected: "true",
		}}},
		NegativeControl: manifest.NegativeControl{Kind: manifest.NegativeControlEmbedded, EmbeddedID: "missing-evidence"},
		Resources:       manifest.ResourceBudget{State: manifest.ResourceStateUnfrozen},
	})
	if err != nil {
		t.Fatal(err)
	}
	boundContract := *contracted.Contract
	requirements, err := boundContract.ClaimEvidenceRequirements()
	if err != nil {
		t.Fatal(err)
	}
	for _, requirement := range requirements {
		if requirement.ClaimKey == "/topology/path_count" {
			boundContract.ClaimBindings = []manifest.ClaimEvidenceBinding{requirement.Bind("observed_path_count")}
			break
		}
	}
	if len(boundContract.ClaimBindings) != 1 {
		t.Fatal("topology path-count claim requirement was not found")
	}
	contracted, err = manifest.NewCompleteSpec(contractedBase, boundContract)
	if err != nil {
		t.Fatal(err)
	}
	contractRows := []report.Case{{
		Name: contracted.ID, Tier: contracted.Tier,
		Evidence: map[string]string{"stimulus_seen": "true", "oracle_passed": "true", "observed_path_count": "0"},
	}}
	if err := reconcileReportRows([]manifest.Spec{contracted}, contractRows); err != nil {
		t.Fatal(err)
	}
	if contractRows[0].Evidence["manifest_contract_state"] != string(manifest.ContractStateBlocked) ||
		!strings.Contains(contractRows[0].Evidence["manifest_contract_missing"], string(manifest.ContractDimensionResources)) {
		t.Fatalf("contract annotations=%v", contractRows[0].Evidence)
	}
	delete(contractRows[0].Evidence, "oracle_passed")
	if err := reconcileReportRows([]manifest.Spec{contracted}, contractRows); err == nil || !strings.Contains(err.Error(), "oracle_passed") {
		t.Fatalf("missing required oracle fact err=%v", err)
	}
	contractRows[0].Evidence["oracle_passed"] = "false"
	if err := reconcileReportRows([]manifest.Spec{contracted}, contractRows); err == nil || !strings.Contains(err.Error(), `want "true"`) {
		t.Fatalf("false oracle fact err=%v", err)
	}
	contractRows[0].Evidence["oracle_passed"] = "true"
	delete(contractRows[0].Evidence, "observed_path_count")
	if err := reconcileReportRows([]manifest.Spec{contracted}, contractRows); err == nil || !strings.Contains(err.Error(), "/topology/path_count") {
		t.Fatalf("missing structured claim evidence err=%v", err)
	}

	trustedFailure := []report.Case{{
		Name: contracted.ID, Tier: contracted.Tier, Failure: "product failed",
		Evidence: map[string]string{"stimulus_seen": "true", "observed_path_count": "0"},
	}}
	if err := reconcileReportRows([]manifest.Spec{contracted}, trustedFailure); err != nil || trustedFailure[0].Failure == "" || trustedFailure[0].InvalidReason != "" {
		t.Fatalf("trusted product failure row=%+v err=%v", trustedFailure[0], err)
	}
	untrustedFailure := []report.Case{{
		Name: contracted.ID, Tier: contracted.Tier, Failure: "product failed",
		Evidence: map[string]string{"stimulus_seen": "false", "observed_path_count": "0"},
	}}
	if err := reconcileReportRows([]manifest.Spec{contracted}, untrustedFailure); err != nil || untrustedFailure[0].Failure != "" ||
		!strings.Contains(untrustedFailure[0].InvalidReason, "lacks valid stimulus evidence") || untrustedFailure[0].Evidence["manifest_reported_failure"] != "product failed" {
		t.Fatalf("untrusted product failure row=%+v err=%v", untrustedFailure[0], err)
	}
	notRun := []report.Case{{
		Name: contracted.ID, Tier: contracted.Tier, ExecutionState: report.ExecutionStateNotRun,
		BlockerKind: report.BlockerKindCase, BlockedByCaseID: "previous", InvalidReason: "not run after previous failed",
	}}
	if err := reconcileReportRows([]manifest.Spec{contracted}, notRun); err != nil {
		t.Fatalf("not-run row reconciliation: %v", err)
	}

	abortSpecs := []manifest.Spec{
		manifest.RequiredWithBudget("abort.one", "T1", time.Second),
		manifest.RequiredWithBudget("abort.two", "T1", time.Second),
		manifest.RequiredWithBudget("abort.three", "T2", time.Second),
	}
	aborted := report.New()
	aborted.Add(report.Case{Name: "abort.one", Tier: "T1", Failure: "synthetic failure"})
	if err := finalizeAbortedInvocation(abortSpecs, aborted, caseInvocationBlocker("abort.one")); err != nil {
		t.Fatal(err)
	}
	if aborted.Complete || len(aborted.Cases) != len(abortSpecs) {
		t.Fatalf("aborted projection=%+v", aborted)
	}
	for _, row := range aborted.Cases[1:] {
		if row.ExecutionState != report.ExecutionStateNotRun || row.BlockerKind != report.BlockerKindCase || row.BlockedByCaseID != "abort.one" || row.CaseDigest == "" {
			t.Fatalf("case-blocked projection row=%+v", row)
		}
	}

	signaled := report.New()
	signaled.Add(report.Case{Name: "abort.one", Tier: "T1", Failure: "interrupted"})
	signaled.Add(report.Case{
		Name: "abort.two", Tier: "T1", ExecutionState: report.ExecutionStateNotRun,
		BlockerKind: report.BlockerKindCase, BlockedByCaseID: "abort.one", InvalidReason: "not run after abort.one failed",
	})
	if err := finalizeAbortedInvocation(abortSpecs, signaled, reasonInvocationBlocker(report.BlockerKindSignal, "interrupt")); err != nil {
		t.Fatal(err)
	}
	for _, row := range signaled.Cases[1:] {
		if row.ExecutionState != report.ExecutionStateNotRun || row.BlockerKind != report.BlockerKindSignal || row.BlockerReason != "interrupt" || row.BlockedByCaseID != "" {
			t.Fatalf("signal-blocked projection row=%+v", row)
		}
	}
}

func TestFirstFailedExecutedCaseIDIgnoresOptionalSkip(t *testing.T) {
	cases := []report.Case{
		{Name: "optional", SkipReason: "not selected", Optional: true},
		{Name: "passing"},
		{Name: "mandatory", SkipReason: "dependency unavailable"},
	}
	if got := firstFailedExecutedCaseID(cases); got != "mandatory" {
		t.Fatalf("first failed case=%q want mandatory", got)
	}
	cases[2].Optional = true
	if got := firstFailedExecutedCaseID(cases); got != "" {
		t.Fatalf("all-optional skips produced blocker %q", got)
	}
}

func TestReconcileContractEvidenceRequiresCollectorIdentity(t *testing.T) {
	spec, evidence := syntheticEnforcedSpec(t, "collector.identity", "T1")
	valid := []report.Case{{Name: spec.ID, Tier: spec.Tier, Evidence: evidence}}
	if err := reconcileReportRows([]manifest.Spec{spec}, valid); err != nil {
		t.Fatalf("valid collector identity: %v", err)
	}

	missingVersion := []report.Case{{Name: spec.ID, Tier: spec.Tier, Evidence: cloneReportCases(valid)[0].Evidence}}
	delete(missingVersion[0].Evidence, "manifest_stimulus_profile_version")
	if err := reconcileReportRows([]manifest.Spec{spec}, missingVersion); err == nil || !strings.Contains(err.Error(), "profile version") {
		t.Fatalf("missing collector version error=%v", err)
	}

	staleName := []report.Case{{Name: spec.ID, Tier: spec.Tier, Evidence: cloneReportCases(valid)[0].Evidence}}
	staleName[0].Evidence["manifest_oracle_profile_name"] = "stale-oracle"
	if err := reconcileReportRows([]manifest.Spec{spec}, staleName); err == nil || !strings.Contains(err.Error(), "profile identity") {
		t.Fatalf("stale collector name error=%v", err)
	}
}

func TestReportPublicationContextSurvivesInvocationCancellation(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	publication, cancelPublication := reportPublicationContext(parent)
	defer cancelPublication()
	cancelParent()
	if err := publication.Err(); err != nil {
		t.Fatalf("publication inherited invocation cancellation: %v", err)
	}
	deadline, ok := publication.Deadline()
	if !ok {
		t.Fatal("publication context has no bounded deadline")
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > 10*time.Second {
		t.Fatalf("publication deadline remaining=%s", remaining)
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
	exact, err := catalog.selectCases("TUN-full.G4-path-death", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := exact.runOrder; !reflect.DeepEqual(got, []string{"TUN-full.preflight-kernel-tun", "TUN-full.G4-path-death"}) {
		t.Fatalf("exact run order=%v", got)
	}
	resumed, err := catalog.selectCases("", "TUN-full.G4-path-death", "")
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
				suite.Add(report.Case{Name: spec.ID, Tier: spec.Tier, Evidence: syntheticContractEvidence(spec)})
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

func syntheticContractEvidence(spec manifest.Spec) map[string]string {
	if spec.Contract == nil {
		return nil
	}
	evidence := make(map[string]string)
	for _, fact := range spec.Contract.Stimulus.RequiredFacts {
		evidence[fact] = "synthetic-test-fixture"
	}
	for _, fact := range spec.Contract.Oracle.RequiredFacts {
		evidence[fact] = "synthetic-test-fixture"
	}
	for _, assertion := range spec.Contract.Stimulus.Assertions {
		evidence[assertion.Fact] = assertion.Expected
	}
	for _, assertion := range spec.Contract.Oracle.Assertions {
		evidence[assertion.Fact] = assertion.Expected
	}
	if len(evidence) == 0 {
		return nil
	}
	return evidence
}

func newTestReportStore(t *testing.T, dir string) invocationReportStore {
	t.Helper()
	lease, err := report.AcquireReportSetLease(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := lease.Close(); err != nil {
			t.Errorf("close report lease: %v", err)
		}
	})
	return reportStoreForLease(lease)
}

func writeSyntheticGreenPhase1Gate(t *testing.T, dir, root string) {
	t.Helper()
	canonical, err := loadCanonicalPhase1Specs()
	if err != nil {
		t.Fatal(err)
	}
	specs := make([]manifest.Spec, len(canonical))
	evidence := make(map[string]map[string]string, len(canonical))
	for i, original := range canonical {
		specs[i], evidence[original.ID] = syntheticEnforcedSpec(t, original.ID, original.Tier)
	}
	previousProvider := phase1SpecsProvider
	phase1SpecsProvider = func() ([]manifest.Spec, error) {
		return manifest.CloneSpecs(specs), nil
	}
	t.Cleanup(func() { phase1SpecsProvider = previousProvider })

	identity, err := buildInvocationIdentity(runFlags{phase: "1"}, manifest.SuiteNormal, specs)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := captureTestLinuxEnvironment(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	revision, err := gate.CurrentRevision(root)
	if err != nil {
		t.Fatal(err)
	}
	identity.EnvironmentStart = snapshot
	identity.EnvironmentEnd = snapshot
	identity.RevisionStart = reportRevision(revision)
	identity.RevisionEnd = reportRevision(revision)
	suite := report.New()
	suite.Invocation = identity
	suite.Complete = true
	for _, spec := range specs {
		digest, err := spec.CanonicalDigest()
		if err != nil {
			t.Fatal(err)
		}
		suite.Add(report.Case{
			Name: spec.ID, Tier: spec.Tier, CaseDigest: digest,
			Evidence: evidence[spec.ID],
		})
	}
	verified, err := publishPhase1Proof(context.Background(), dir, suite, specs)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeKnownPhase1Gate(dir, revision, "green", time.Now(), verified.Manifest); err != nil {
		t.Fatal(err)
	}
}

func syntheticEnforcedSpec(t *testing.T, id, tier string) (manifest.Spec, map[string]string) {
	t.Helper()
	base := manifest.RequiredWithBudget(id, tier, time.Second)
	contract := manifest.Contract{
		SchemaVersion:    manifest.ContractSchemaVersion,
		State:            manifest.ContractStateEnforced,
		Purpose:          "exercise canonical phase 1 proof validation",
		Entrypoint:       "cmd/regress synthetic phase 1 fixture",
		Topology:         manifest.Topology{Profile: "in-process", Roles: []string{"runner"}, Isolation: "process", PathCount: 0},
		RoleCapabilities: map[string][]string{"runner": {}},
		Payload:          manifest.Profile{Applicability: manifest.ApplicabilityNotApplicable},
		Load:             manifest.Profile{Applicability: manifest.ApplicabilityNotApplicable},
		Seed:             manifest.SeedPolicy{Mode: manifest.SeedModeNone},
		Stimulus: manifest.EvidenceProfile{Name: "synthetic-stimulus", Version: 1, Assertions: []manifest.EvidenceAssertion{{
			Fact: "stimulus_seen", Predicate: manifest.EvidenceEquals, Expected: "true",
		}}},
		Oracle: manifest.EvidenceProfile{Name: "synthetic-oracle", Version: 1, Assertions: []manifest.EvidenceAssertion{{
			Fact: "oracle_passed", Predicate: manifest.EvidenceEquals, Expected: "true",
		}}},
		NegativeControl: manifest.NegativeControl{Kind: manifest.NegativeControlNotApplicable, Reason: "synthetic validator fixture"},
		Resources: manifest.ResourceBudget{
			State: manifest.ResourceStateDefined, Timeout: time.Second, Exclusivity: manifest.ExclusivityShared,
			Roles: map[string]manifest.RoleResourceBudget{"runner": {VCPUs: 1, RAMBytes: 1, DiskBytes: 1}},
		},
	}
	requirements, err := contract.ClaimEvidenceRequirements()
	if err != nil {
		t.Fatal(err)
	}
	evidence := map[string]string{
		"stimulus_seen":                     "true",
		"oracle_passed":                     "true",
		"manifest_stimulus_profile_name":    "synthetic-stimulus",
		"manifest_stimulus_profile_version": "1",
		"manifest_oracle_profile_name":      "synthetic-oracle",
		"manifest_oracle_profile_version":   "1",
	}
	for i, requirement := range requirements {
		fact := fmt.Sprintf("claim_%03d", i)
		contract.ClaimBindings = append(contract.ClaimBindings, requirement.Bind(fact))
		value := requirement.Expected
		if requirement.Predicate == manifest.EvidenceInt {
			value = "1"
		}
		evidence[fact] = value
	}
	spec, err := manifest.NewCompleteSpec(base, contract)
	if err != nil {
		t.Fatal(err)
	}
	evidence[report.EvidenceContractStateKey] = string(manifest.ContractStateEnforced)
	return spec, evidence
}

func captureTestLinuxEnvironment(context.Context) (environment.Snapshot, error) {
	sysctlNames := []string{
		"net.core.rmem_default",
		"net.core.rmem_max",
		"net.core.wmem_default",
		"net.core.wmem_max",
		"net.ipv4.tcp_congestion_control",
		"net.ipv4.tcp_mtu_probing",
		"net.ipv4.tcp_rmem",
		"net.ipv4.tcp_wmem",
		"net.ipv4.udp_rmem_min",
		"net.ipv4.udp_wmem_min",
	}
	sysctls := make([]environment.Sysctl, len(sysctlNames))
	for i, name := range sysctlNames {
		sysctls[i] = environment.Sysctl{Name: name, Value: "synthetic"}
	}
	return environment.Seal(environment.Snapshot{
		SchemaVersion: environment.SnapshotSchemaVersion,
		Runtime: environment.Runtime{
			GoVersion: "go-test",
			GOOS:      "linux",
			GOARCH:    "amd64",
		},
		Hostname:      "synthetic-host",
		KernelRelease: "6.8.0-test",
		BootID:        "00000000-0000-4000-8000-000000000001",
		NumCPU:        4,
		CPU: environment.CPU{
			Models:         []string{"Synthetic CPU"},
			OnlineSet:      "0-3",
			ProcessAllowed: "0-3",
		},
		TotalMemoryBytes: 4 << 30,
		Clocksource:      "tsc",
		Interfaces:       []environment.Interface{{Name: "test0", MTU: 1500}},
		SocketSysctls:    sysctls,
		QDisc:            environment.QDisc{Supported: true, State: []byte("[]")},
	})
}

func captureTestEnvironment(context.Context) (environment.Snapshot, error) {
	return environment.Seal(environment.Snapshot{
		SchemaVersion: environment.SnapshotSchemaVersion,
		Runtime: environment.Runtime{
			GoVersion: "go-test",
			GOOS:      "windows",
			GOARCH:    "amd64",
		},
		Hostname:   "synthetic-host",
		NumCPU:     4,
		Interfaces: []environment.Interface{{Name: "test0", MTU: 1500}},
	})
}

func testEnvironmentWithQDisc(t *testing.T, qdisc string) environment.Snapshot {
	t.Helper()
	snapshot, err := captureTestEnvironment(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	snapshot.QDisc = environment.QDisc{Supported: true, State: []byte(qdisc)}
	sealed, err := environment.Seal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
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
