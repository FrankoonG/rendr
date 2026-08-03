package tier6

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/caseexec"
	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/report"
)

var orderedCaseIDs = []string{
	"T6.graph.compat-mode",
	"T6.peak.A-to-bulk-bond",
	"T6.peak.nested-normal-to-C",
	"T6.failover.hot-standby",
	"T6.peak.composite-normal",
	"T6.peak.bad-speed",
	"T6.peak.stale-speed",
	"T6.peak.probe-budget",
	"T6.peak.slow-peak-revert",
	"T6.peak.rx-peer-policy",
}

func TestSpecsOrdered(t *testing.T) {
	specs := Specs()
	assertRequiredSpecs(t, specs)
	if got := specIDs(specs); !reflect.DeepEqual(got, orderedCaseIDs) {
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

func TestSelectCaseDefs(t *testing.T) {
	t.Run("exact", func(t *testing.T) {
		defs, err := selectCaseDefs(Options{Case: orderedCaseIDs[3]})
		if err != nil {
			t.Fatal(err)
		}
		if got := defIDs(defs); !reflect.DeepEqual(got, orderedCaseIDs[3:4]) {
			t.Fatalf("selected IDs = %v, want %v", got, orderedCaseIDs[3:4])
		}
	})

	t.Run("inclusive resume", func(t *testing.T) {
		defs, err := selectCaseDefs(Options{FromCase: orderedCaseIDs[7]})
		if err != nil {
			t.Fatal(err)
		}
		if got := defIDs(defs); !reflect.DeepEqual(got, orderedCaseIDs[7:]) {
			t.Fatalf("selected IDs = %v, want %v", got, orderedCaseIDs[7:])
		}
	})

	t.Run("missing", func(t *testing.T) {
		if _, err := selectCaseDefs(Options{Case: "T6.missing"}); err == nil {
			t.Fatal("missing exact filter succeeded")
		}
		if _, err := selectCaseDefs(Options{FromCase: "T6.missing"}); err == nil {
			t.Fatal("missing resume filter succeeded")
		}
	})

	t.Run("prerequisite expansion", func(t *testing.T) {
		prerequisite := manifest.RequiredWithBudget("synthetic-prerequisite", "T6", time.Second)
		resume := manifest.RequiredWithBudget("synthetic-resume", "T6", time.Second)
		resume.Requires = []string{prerequisite.ID}
		target := manifest.RequiredWithBudget("synthetic-target", "T6", time.Second)
		target.Requires = []string{prerequisite.ID}
		registry := []caseDef{{spec: prerequisite}, {spec: resume}, {spec: target}}

		defs, err := selectCaseDefsFrom(registry, Options{Case: target.ID})
		if err != nil {
			t.Fatal(err)
		}
		if got, want := defIDs(defs), []string{prerequisite.ID, target.ID}; !reflect.DeepEqual(got, want) {
			t.Fatalf("exact IDs = %v, want %v", got, want)
		}

		defs, err = selectCaseDefsFrom(registry, Options{FromCase: resume.ID})
		if err != nil {
			t.Fatal(err)
		}
		if got, want := defIDs(defs), []string{prerequisite.ID, resume.ID, target.ID}; !reflect.DeepEqual(got, want) {
			t.Fatalf("resume IDs = %v, want %v", got, want)
		}
	})
}

func TestRunCaseDefsFailFastKeepsManifestRows(t *testing.T) {
	defs := []caseDef{
		{spec: manifest.RequiredWithBudget("first", "T6", time.Second)},
		{spec: manifest.RequiredWithBudget("second", "T6", time.Second)},
		{spec: manifest.RequiredWithBudget("third", "T6", time.Second)},
	}
	tests := []struct {
		name string
		row  report.Case
	}{
		{name: "failure", row: report.Case{Failure: "boom"}},
		{name: "invalid", row: report.Case{InvalidReason: "bad evidence"}},
		{name: "mandatory skip", row: report.Case{SkipReason: "missing capability"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			suite := report.New()
			runCaseDefs(context.Background(), suite, "", defs, func(_ context.Context, _ string, def caseDef) caseexec.Outcome {
				calls++
				if calls > 1 {
					t.Fatal("later executor was invoked")
				}
				rc := tc.row
				rc.Name = def.spec.ID
				rc.Tier = def.spec.Tier
				rc.Evidence = map[string]string{"cleanup": "preserved"}
				return caseexec.Outcome{Case: rc}
			})

			if calls != 1 {
				t.Fatalf("executor calls = %d, want 1", calls)
			}
			if got := reportCaseNames(suite.Cases); !reflect.DeepEqual(got, []string{"first", "second", "third"}) {
				t.Fatalf("report rows = %v", got)
			}
			if suite.Cases[0].Evidence["cleanup"] != "preserved" {
				t.Fatalf("failing row lost evidence: %+v", suite.Cases[0])
			}
			for _, rc := range suite.Cases[1:] {
				if rc.Tier != "T6" || rc.InvalidReason != "not run after first failed" || rc.Failure != "" || rc.SkipReason != "" {
					t.Fatalf("not-run row = %+v", rc)
				}
			}
		})
	}
}

func TestRunCaseDefsStopsAfterUnsafeOutcome(t *testing.T) {
	defs := []caseDef{
		{spec: manifest.Spec{ID: "first", Tier: "T6"}},
		{spec: manifest.RequiredWithBudget("second", "T6", time.Second)},
	}
	calls := 0
	suite := report.New()
	runCaseDefs(context.Background(), suite, "", defs, func(_ context.Context, _ string, def caseDef) caseexec.Outcome {
		calls++
		return caseexec.Outcome{
			Case:     report.Case{Name: def.spec.ID, Tier: def.spec.Tier, InvalidReason: "process exit required"},
			MustStop: true,
		}
	})
	if calls != 1 {
		t.Fatalf("executor calls = %d, want 1", calls)
	}
	if got := suite.Cases[1].InvalidReason; got != "not run after first failed" {
		t.Fatalf("next case result = %q", got)
	}
}

func specIDs(specs []manifest.Spec) []string {
	ids := make([]string, len(specs))
	for i, spec := range specs {
		ids[i] = spec.ID
	}
	return ids
}

func assertRequiredSpecs(t *testing.T, specs []manifest.Spec) {
	t.Helper()
	if err := manifest.Validate(specs); err != nil {
		t.Fatal(err)
	}
	for _, spec := range specs {
		if !spec.Mandatory || spec.Suite != manifest.SuiteNormal || spec.Budget <= 0 {
			t.Fatalf("invalid required spec: %+v", spec)
		}
	}
}

func defIDs(defs []caseDef) []string {
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
