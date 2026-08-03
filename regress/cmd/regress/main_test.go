package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
			name: "full resume crosses tiers",
			cfg:  runFlags{full: true, fromCaseID: "T5.4-gvisor-unprivileged"},
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

func TestVerifyPhase1RevisionRejectsConcurrentChanges(t *testing.T) {
	wantRoot := "/exact/root"
	before := gate.Revision{CommitSHA: "commit", WorktreeSHA: "before"}
	if err := verifyPhase1Revision(wantRoot, before, func(root string) (gate.Revision, error) {
		if root != wantRoot {
			t.Fatalf("root=%q want %q", root, wantRoot)
		}
		return before, nil
	}); err != nil {
		t.Fatalf("stable revision: %v", err)
	}

	err := verifyPhase1Revision(wantRoot, before, func(string) (gate.Revision, error) {
		return gate.Revision{CommitSHA: "commit", WorktreeSHA: "after"}, nil
	})
	if err == nil || !strings.Contains(err.Error(), "changed during phase 1") {
		t.Fatalf("changed revision err=%v", err)
	}

	err = verifyPhase1Revision(wantRoot, before, func(string) (gate.Revision, error) {
		return gate.Revision{}, errors.New("git failed")
	})
	if err == nil || !strings.Contains(err.Error(), "git failed") {
		t.Fatalf("fingerprint err=%v", err)
	}
}

func TestWriteKnownPhase1GateRejectsMissingIdentity(t *testing.T) {
	err := writeKnownPhase1Gate(t.TempDir(), gate.Revision{}, "running", time.Now())
	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("err=%v", err)
	}
}

func TestTUNCatalogMakesCompatibilitySelectorsExplicit(t *testing.T) {
	tunCatalog, err := buildTUNCatalog(tunfull.Specs(), tunCaseRoles)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := tunCatalog.selectCases("", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(selection.cases) != len(tunfull.Specs()) {
		t.Fatalf("listed cases=%d want registry count %d", len(selection.cases), len(tunfull.Specs()))
	}
	wantDefault := []string{
		"TUN-full.G1-smoke",
		"TUN-full.G2-smoke",
		"TUN-full.G3-smoke",
		"TUN-full.G4-path-death",
		"TUN-full.G5-path-recovery",
		"TUN-full.T3-xray-matrix",
		"TUN-full.T4-G1-1GiB-tcp",
		"TUN-full.T4-G2-30m-prime",
		"TUN-full.T4-G3-100k-pps",
		"TUN-full.T5-fallback",
		"TUN-full.T6-selector",
	}
	if !reflect.DeepEqual(selection.runOrder, wantDefault) {
		t.Fatalf("default run=%v want %v", selection.runOrder, wantDefault)
	}

	streamCompat := findListedCase(t, selection.cases, "TUN-full.T3-xray-stream-smoke")
	if streamCompat.DefaultRun || streamCompat.Kind != tunKindCompatibilityCase {
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
	if !reflect.DeepEqual(exact.runOrder, longCompat.ExpandsTo) {
		t.Fatalf("selector run=%v want expansion %v", exact.runOrder, longCompat.ExpandsTo)
	}
	resumed, err := tunCatalog.selectCases("", "TUN-full.T3-xray-stream-smoke")
	if err != nil {
		t.Fatal(err)
	}
	if len(resumed.runOrder) == 0 || resumed.runOrder[0] != "TUN-full.T3-xray-stream-smoke" {
		t.Fatalf("compatibility resume is not inclusive: %v", resumed.runOrder)
	}
}

func TestTUNCatalogMismatchFailsClosed(t *testing.T) {
	specs := tunfull.Specs()
	roles := cloneTUNRoles(tunCaseRoles)
	roles[0].ID = "TUN-full.changed"
	if _, err := buildTUNCatalog(specs, roles); err == nil || !strings.Contains(err.Error(), "registry/full mismatch") {
		t.Fatalf("identity mismatch err=%v", err)
	}

	roles = cloneTUNRoles(tunCaseRoles[:len(tunCaseRoles)-1])
	if _, err := buildTUNCatalog(specs, roles); err == nil || !strings.Contains(err.Error(), "registry/full mismatch") {
		t.Fatalf("count mismatch err=%v", err)
	}

	badSpecs := append([]manifest.Spec(nil), specs...)
	badSpecs[0].Mandatory = false
	if _, err := buildTUNCatalog(badSpecs, tunCaseRoles); err == nil || !strings.Contains(err.Error(), "registry/full mismatch") {
		t.Fatalf("metadata mismatch err=%v", err)
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
	if doc.Catalogs[1].Suite != manifest.SuiteTUN || len(doc.Catalogs[1].Cases) != len(tunfull.Specs()) {
		t.Fatalf("TUN catalog summary=%+v", doc.Catalogs[1])
	}
	if !strings.Contains(stdout.String(), `"default_run": false`) {
		t.Fatal("JSON hides non-default compatibility entries")
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
	if len(got.Cases) != 1 || got.Cases[0].Kind != tunKindCompatibilitySelector || len(got.RunOrder) != 3 {
		t.Fatalf("scoped TUN list=%+v", got)
	}
}

func TestSpecsForPlanSupportsSyntheticRegistries(t *testing.T) {
	registries := map[string][]manifest.Spec{
		"T1": {
			manifest.Required("synthetic.one", "T1"),
			manifest.Required("synthetic.two", "T1"),
		},
		"T2": {
			manifest.Required("synthetic.three", "T2"),
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
		manifest.Required("one", "T1"),
		manifest.Required("two", "T1"),
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
