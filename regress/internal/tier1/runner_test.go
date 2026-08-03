package tier1

import (
	"context"
	"errors"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/report"
)

var orderedCaseIDs = []string{
	"go-vet",
	"go-test",
	"regress-unit",
	"go-test-race",
	"go-bench-smoke",
	"const-proto-version",
	"const-udpflow-version",
	"const-migration-budget-90s",
	"const-mode-values",
	"const-mode-transition-table",
}

func TestSpecsOrder(t *testing.T) {
	specs := Specs()
	got := make([]string, len(specs))
	for i, spec := range specs {
		got[i] = spec.ID
		if spec.Budget <= 0 {
			t.Errorf("spec %q has unbounded budget %s", spec.ID, spec.Budget)
		}
	}
	if !reflect.DeepEqual(got, orderedCaseIDs) {
		t.Fatalf("Specs IDs = %v, want %v", got, orderedCaseIDs)
	}

	originalRequires := caseDefs[1].spec.Requires
	caseDefs[1].spec.Requires = []string{caseDefs[0].spec.ID}
	t.Cleanup(func() { caseDefs[1].spec.Requires = originalRequires })
	copied := Specs()
	copied[1].Requires[0] = "mutated"
	if got, want := caseDefs[1].spec.Requires[0], caseDefs[0].spec.ID; got != want {
		t.Fatalf("Specs result mutated caseDefs prerequisite to %q, want %q", got, want)
	}
}

func TestSelectCaseDefsExact(t *testing.T) {
	defs, err := selectCaseDefs(Options{Case: orderedCaseIDs[2]})
	if err != nil {
		t.Fatal(err)
	}
	if got := caseDefIDs(defs); !reflect.DeepEqual(got, orderedCaseIDs[2:3]) {
		t.Fatalf("selected IDs = %v, want %v", got, orderedCaseIDs[2:3])
	}

	prerequisite := manifest.RequiredWithBudget("synthetic-prerequisite", "T1", time.Second)
	target := manifest.RequiredWithBudget("synthetic-target", "T1", time.Second)
	target.Requires = []string{prerequisite.ID}
	defs, err = selectCaseDefsFrom([]caseDef{{spec: prerequisite}, {spec: target}}, Options{Case: target.ID})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := caseDefIDs(defs), []string{prerequisite.ID, target.ID}; !reflect.DeepEqual(got, want) {
		t.Fatalf("selected IDs = %v, want %v", got, want)
	}
}

func TestSelectCaseDefsInclusiveResume(t *testing.T) {
	defs, err := selectCaseDefs(Options{FromCase: orderedCaseIDs[6]})
	if err != nil {
		t.Fatal(err)
	}
	if got := caseDefIDs(defs); !reflect.DeepEqual(got, orderedCaseIDs[6:]) {
		t.Fatalf("selected IDs = %v, want %v", got, orderedCaseIDs[6:])
	}

	prerequisite := manifest.RequiredWithBudget("synthetic-prerequisite", "T1", time.Second)
	resume := manifest.RequiredWithBudget("synthetic-resume", "T1", time.Second)
	resume.Requires = []string{prerequisite.ID}
	target := manifest.RequiredWithBudget("synthetic-target", "T1", time.Second)
	target.Requires = []string{prerequisite.ID}
	defs, err = selectCaseDefsFrom([]caseDef{{spec: prerequisite}, {spec: resume}, {spec: target}}, Options{FromCase: resume.ID})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := caseDefIDs(defs), []string{prerequisite.ID, resume.ID, target.ID}; !reflect.DeepEqual(got, want) {
		t.Fatalf("selected IDs = %v, want %v", got, want)
	}
}

func TestRunWithOptionsMissingFilter(t *testing.T) {
	suite := report.New()
	RunWithOptions(context.Background(), suite, "", Options{Case: "missing"})
	if len(suite.Cases) != 1 {
		t.Fatalf("cases = %d, want 1", len(suite.Cases))
	}
	got := suite.Cases[0]
	if got.Name != "T1-case-filter" || got.Tier != "T1" || got.Failure != `manifest: no case matched --case="missing"` {
		t.Fatalf("failure row = %+v", got)
	}
}

func TestRunCaseDefPreservesRecoveredFailure(t *testing.T) {
	attempts := 0
	def := caseDef{
		spec:    manifest.RequiredWithBudget("flaky", "T1", time.Second),
		retries: 2,
		fn: func(context.Context, string) error {
			attempts++
			if attempts == 1 {
				return errors.New("first failure")
			}
			return nil
		},
	}
	rc := runCaseDef(context.Background(), "", def)
	if rc.Failure != "" || !strings.Contains(rc.InvalidReason, "first failure") || attempts != 2 {
		t.Fatalf("case=%+v attempts=%d", rc, attempts)
	}
	suite := report.New()
	suite.Add(rc)
	if !suite.AnyFailed() {
		t.Fatal("a retry-recovered case must still fail the release gate")
	}
}

func TestRunCaseDefUsesOneBudgetAcrossRetries(t *testing.T) {
	attempts := 0
	def := caseDef{
		spec:    manifest.RequiredWithBudget("timeout", "T1", 10*time.Millisecond),
		retries: 3,
		fn: func(ctx context.Context, _ string) error {
			attempts++
			<-ctx.Done()
			return ctx.Err()
		},
	}
	rc := runCaseDef(context.Background(), "", def)
	if rc.Failure == "" || attempts != 1 {
		t.Fatalf("case=%+v attempts=%d, want one budget-bounded attempt", rc, attempts)
	}
}

func TestRunCaseDefCleanFirstPass(t *testing.T) {
	def := caseDef{
		spec:    manifest.RequiredWithBudget("clean", "T1", time.Second),
		retries: 2,
		fn:      func(context.Context, string) error { return nil },
	}
	rc := runCaseDef(context.Background(), "", def)
	if rc.Failure != "" || rc.InvalidReason != "" || rc.SkipReason != "" {
		t.Fatalf("clean first pass = %+v", rc)
	}
}

func TestRunCaseDefsFailFastKeepsManifestRows(t *testing.T) {
	tests := []struct {
		name       string
		first      caseDef
		assertStop func(*testing.T, report.Case)
	}{
		{
			name: "failure",
			first: caseDef{
				spec: manifest.RequiredWithBudget("first", "T1", time.Second),
				fn:   func(context.Context, string) error { return errors.New("boom") },
			},
			assertStop: func(t *testing.T, rc report.Case) {
				if !strings.Contains(rc.Failure, "boom") {
					t.Fatalf("failure row = %+v", rc)
				}
			},
		},
		{
			name: "invalid retry recovery",
			first: func() caseDef {
				attempt := 0
				return caseDef{
					spec:    manifest.RequiredWithBudget("first", "T1", time.Second),
					retries: 1,
					fn: func(context.Context, string) error {
						attempt++
						if attempt == 1 {
							return errors.New("flaky")
						}
						return nil
					},
				}
			}(),
			assertStop: func(t *testing.T, rc report.Case) {
				if !strings.Contains(rc.InvalidReason, "flaky") {
					t.Fatalf("invalid row = %+v", rc)
				}
			},
		},
		{
			name: "mandatory skip",
			first: caseDef{
				spec:   manifest.RequiredWithBudget("first", "T1", time.Second),
				onlyOn: "not-" + runtime.GOOS,
				fn: func(context.Context, string) error {
					t.Fatal("skipped case executor was invoked")
					return nil
				},
			},
			assertStop: func(t *testing.T, rc report.Case) {
				if rc.SkipReason == "" {
					t.Fatalf("skip row = %+v", rc)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			laterCalls := 0
			defs := []caseDef{
				tc.first,
				{spec: manifest.RequiredWithBudget("second", "T1", time.Second), fn: func(context.Context, string) error { laterCalls++; return nil }},
				{spec: manifest.RequiredWithBudget("third", "T1", time.Second), fn: func(context.Context, string) error { laterCalls++; return nil }},
			}
			suite := report.New()
			runCaseDefs(context.Background(), suite, "", defs)

			if laterCalls != 0 {
				t.Fatalf("later executor calls = %d, want 0", laterCalls)
			}
			if got := reportCaseNames(suite.Cases); !reflect.DeepEqual(got, []string{"first", "second", "third"}) {
				t.Fatalf("report rows = %v", got)
			}
			tc.assertStop(t, suite.Cases[0])
			for _, rc := range suite.Cases[1:] {
				if rc.Tier != "T1" || rc.InvalidReason != "not run after first failed" || rc.Failure != "" || rc.SkipReason != "" {
					t.Fatalf("not-run row = %+v", rc)
				}
			}
		})
	}
}

func TestFilterRegressUnitPackages(t *testing.T) {
	input := []string{
		"example/regress/cmd/regress",
		"example/regress/internal/matrix",
		"example/regress/internal/matrix/driver",
		"example/regress/internal/smoke",
		"example/regress/internal/xrayglue",
		"example/regress/internal/report",
	}
	want := []string{
		"example/regress/cmd/regress",
		"example/regress/internal/smoke",
		"example/regress/internal/report",
	}
	if got := filterRegressUnitPackages(input); !reflect.DeepEqual(got, want) {
		t.Fatalf("packages=%v want %v", got, want)
	}
}

func caseDefIDs(defs []caseDef) []string {
	ids := make([]string, len(defs))
	for i, def := range defs {
		ids[i] = def.spec.ID
	}
	return ids
}

func reportCaseNames(cases []report.Case) []string {
	names := make([]string, len(cases))
	for i, rc := range cases {
		names[i] = rc.Name
	}
	return names
}
