package tier8

import (
	"context"
	"reflect"
	"testing"

	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/report"
)

var orderedCaseIDs = []string{
	"T8.status.local-default",
	"T8.status.peer-rendr",
	"T8.primary.default-first-leaf",
	"T8.primary.explicit-path",
	"T8.primary.explicit-group-resolve",
	"T8.primary.prefer-fallback",
	"T8.primary.require-fails",
	"T8.retry.forwarding-fixed",
	"T8.retry.no-app-error",
}

func TestSpecsOrdered(t *testing.T) {
	specs := Specs()
	assertRequiredSpecs(t, specs)
	if got := specIDs(specs); !reflect.DeepEqual(got, orderedCaseIDs) {
		t.Fatalf("Specs IDs = %v, want %v", got, orderedCaseIDs)
	}
}

func TestSelectCaseDefs(t *testing.T) {
	t.Run("exact", func(t *testing.T) {
		defs, err := selectCaseDefs(Options{Case: orderedCaseIDs[2]})
		if err != nil {
			t.Fatal(err)
		}
		if got := defIDs(defs); !reflect.DeepEqual(got, orderedCaseIDs[2:3]) {
			t.Fatalf("selected IDs = %v, want %v", got, orderedCaseIDs[2:3])
		}
	})

	t.Run("inclusive resume", func(t *testing.T) {
		defs, err := selectCaseDefs(Options{FromCase: orderedCaseIDs[6]})
		if err != nil {
			t.Fatal(err)
		}
		if got := defIDs(defs); !reflect.DeepEqual(got, orderedCaseIDs[6:]) {
			t.Fatalf("selected IDs = %v, want %v", got, orderedCaseIDs[6:])
		}
	})

	t.Run("missing", func(t *testing.T) {
		if _, err := selectCaseDefs(Options{Case: "T8.missing"}); err == nil {
			t.Fatal("missing exact filter succeeded")
		}
		if _, err := selectCaseDefs(Options{FromCase: "T8.missing"}); err == nil {
			t.Fatal("missing resume filter succeeded")
		}
	})
}

func TestRunCaseDefsFailFastKeepsManifestRows(t *testing.T) {
	defs := []caseDef{
		{spec: manifest.Required("first", "T8")},
		{spec: manifest.Required("second", "T8")},
		{spec: manifest.Required("third", "T8")},
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
			runCaseDefs(context.Background(), suite, "", defs, func(_ context.Context, _ string, def caseDef) report.Case {
				calls++
				if calls > 1 {
					t.Fatal("later executor was invoked")
				}
				rc := tc.row
				rc.Name = def.spec.ID
				rc.Tier = def.spec.Tier
				rc.Evidence = map[string]string{"cleanup": "preserved"}
				return rc
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
				if rc.Tier != "T8" || rc.InvalidReason != "not run after first failed" || rc.Failure != "" || rc.SkipReason != "" {
					t.Fatalf("not-run row = %+v", rc)
				}
			}
		})
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
