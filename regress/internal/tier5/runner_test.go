package tier5

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/report"
	"github.com/FrankoonG/rendr/regress/internal/smoke"
)

var orderedCaseIDs = []string{
	"T5.1-tcprepair-privileged",
	"T5.2-gvisor-privileged",
	"T5.3-tcprepair-unprivileged",
	"T5.4-gvisor-unprivileged",
	"T5.5-tcprepair-gvisor-fallback-unprivileged",
	"T5.6-gvisor-packet-carrier-unprivileged",
}

func TestRunReportsSelectionFailures(t *testing.T) {
	tests := []struct {
		name string
		opts Options
		want string
	}{
		{
			name: "missing",
			opts: Options{Case: "T5.missing"},
			want: `T5 case selection failed for case="T5.missing" from-case="": manifest: no case matched --case="T5.missing"`,
		},
		{
			name: "ambiguous",
			opts: Options{Case: orderedCaseIDs[0], FromCase: orderedCaseIDs[1]},
			want: `T5 case selection failed for case="T5.1-tcprepair-privileged" from-case="T5.2-gvisor-privileged": manifest: --case and --from-case are mutually exclusive`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := report.New()
			Run(context.Background(), suite, "", tt.opts)
			if len(suite.Cases) != 1 {
				t.Fatalf("reported cases = %v, want one selection failure", suite.Cases)
			}
			got := suite.Cases[0]
			if got.Name != "T5-case-filter" || got.Tier != "T5" || got.Failure != tt.want {
				t.Fatalf("selection failure = %+v, want T5-case-filter failure %q", got, tt.want)
			}
		})
	}
}

func TestAddLinuxOnlySkipPreservesSelectedCases(t *testing.T) {
	defs, err := selectCaseDefs(Options{FromCase: orderedCaseIDs[3]})
	if err != nil {
		t.Fatal(err)
	}
	suite := report.New()
	for _, def := range defs {
		addLinuxOnlySkip(suite, def)
	}
	got := make([]string, len(suite.Cases))
	for i, rc := range suite.Cases {
		got[i] = rc.Name
		if rc.SkipReason != "Linux only" || rc.Failure != "" {
			t.Fatalf("case %s = %+v, want Linux-only skip", rc.Name, rc)
		}
	}
	if want := orderedCaseIDs[3:]; !reflect.DeepEqual(got, want) {
		t.Fatalf("reported IDs = %v, want %v", got, want)
	}
}

func TestSpecsOrdered(t *testing.T) {
	specs := Specs()
	if got := specIDs(specs); !reflect.DeepEqual(got, orderedCaseIDs) {
		t.Fatalf("Specs IDs = %v, want %v", got, orderedCaseIDs)
	}
	if err := manifest.Validate(specs); err != nil {
		t.Fatalf("Specs validation failed: %v", err)
	}
	wantBudgets := []time.Duration{3 * time.Minute, 2 * time.Minute, 2 * time.Minute, 2 * time.Minute, 2 * time.Minute, 2 * time.Minute}
	for i, spec := range specs {
		if !spec.Mandatory || spec.Suite != manifest.SuiteNormal || spec.Budget != wantBudgets[i] {
			t.Errorf("Specs()[%d] = %+v, want mandatory normal-suite budget %s", i, spec, wantBudgets[i])
		}
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
	tests := []struct {
		name    string
		opts    Options
		want    []string
		wantErr bool
	}{
		{name: "exact", opts: Options{Case: orderedCaseIDs[2]}, want: orderedCaseIDs[2:3]},
		{name: "inclusive resume", opts: Options{FromCase: orderedCaseIDs[4]}, want: orderedCaseIDs[4:]},
		{name: "missing exact", opts: Options{Case: "T5.missing"}, wantErr: true},
		{name: "missing resume", opts: Options{FromCase: "T5.missing"}, wantErr: true},
		{name: "ambiguous", opts: Options{Case: orderedCaseIDs[0], FromCase: orderedCaseIDs[1]}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defs, err := selectCaseDefs(tt.opts)
			if tt.wantErr {
				if err == nil {
					t.Fatal("selection succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := defIDs(defs); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("selected IDs = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("prerequisite expansion", func(t *testing.T) {
		prerequisite := manifest.RequiredWithBudget("synthetic-prerequisite", "T5", time.Second)
		resume := manifest.RequiredWithBudget("synthetic-resume", "T5", time.Second)
		resume.Requires = []string{prerequisite.ID}
		target := manifest.RequiredWithBudget("synthetic-target", "T5", time.Second)
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

func TestSmokeReportCasePreservesInvalidAndEvidence(t *testing.T) {
	rc := smokeReportCase("T5.synthetic", smoke.Result{
		Duration:      time.Second,
		InvalidReason: "stimulus missing",
		Detail:        map[string]any{"migrations": 0, "sha256_match": false},
	})
	if rc.InvalidReason != "stimulus missing" || rc.Failure != "" {
		t.Fatalf("outcome=%+v want invalid-only", rc)
	}
	want := map[string]string{"migrations": "0", "sha256_match": "false"}
	if !reflect.DeepEqual(rc.Evidence, want) {
		t.Fatalf("evidence=%v want=%v", rc.Evidence, want)
	}
}

func TestRunSelectedCasesStopsAfterMandatoryOutcome(t *testing.T) {
	tests := []struct {
		name    string
		outcome report.Case
	}{
		{name: "failure", outcome: report.Case{Failure: "boom"}},
		{name: "invalid", outcome: report.Case{InvalidReason: "stimulus missing"}},
		{name: "mandatory skip", outcome: report.Case{SkipReason: "dependency unavailable"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defs := syntheticCaseDefs("T5")
			var called []string
			suite := report.New()
			runSelectedCases(context.Background(), suite, defs, func(_ context.Context, def caseDef) report.Case {
				called = append(called, def.spec.ID)
				rc := report.Case{Name: def.spec.ID, Tier: def.spec.Tier}
				if def.spec.ID == "synthetic.blocker" {
					rc.Failure = tt.outcome.Failure
					rc.InvalidReason = tt.outcome.InvalidReason
					rc.SkipReason = tt.outcome.SkipReason
				}
				return rc
			})

			if want := []string{"synthetic.first", "synthetic.blocker"}; !reflect.DeepEqual(called, want) {
				t.Fatalf("executed cases = %v, want %v", called, want)
			}
			assertFailFastRows(t, suite.Cases, "T5")
		})
	}
}

func syntheticCaseDefs(tier string) []caseDef {
	ids := []string{"synthetic.first", "synthetic.blocker", "synthetic.after"}
	defs := make([]caseDef, len(ids))
	for i, id := range ids {
		defs[i].spec = manifest.RequiredWithBudget(id, tier, time.Second)
	}
	return defs
}

func assertFailFastRows(t *testing.T, cases []report.Case, tier string) {
	t.Helper()
	wantIDs := []string{"synthetic.first", "synthetic.blocker", "synthetic.after"}
	gotIDs := make([]string, len(cases))
	for i, rc := range cases {
		gotIDs[i] = rc.Name
		if rc.Tier != tier {
			t.Fatalf("row %d tier = %q, want %q", i, rc.Tier, tier)
		}
	}
	if !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Fatalf("report IDs = %v, want %v", gotIDs, wantIDs)
	}
	if got := cases[2].InvalidReason; got != "not run after synthetic.blocker failed" {
		t.Fatalf("trailing row invalid reason = %q", got)
	}
}

func specIDs(specs []manifest.Spec) []string {
	ids := make([]string, len(specs))
	for i, spec := range specs {
		ids[i] = spec.ID
	}
	return ids
}

func defIDs(defs []caseDef) []string {
	ids := make([]string, len(defs))
	for i, def := range defs {
		ids[i] = def.spec.ID
	}
	return ids
}
