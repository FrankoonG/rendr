package tunfull

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/report"
)

var orderedCaseIDs = []string{
	caseG1Smoke,
	caseG2Smoke,
	caseG3Smoke,
	caseG4PathDeath,
	caseG5PathRecovery,
	caseT3XrayStreamSmoke,
	caseT3XrayMatrix,
	caseT4LongRun,
	caseT4G1,
	caseT4G2,
	caseT4G3,
	caseT5Fallback,
	caseT6Selector,
}

var defaultCaseIDs = []string{
	caseG1Smoke,
	caseG2Smoke,
	caseG3Smoke,
	caseG4PathDeath,
	caseG5PathRecovery,
	caseT3XrayMatrix,
	caseT4G1,
	caseT4G2,
	caseT4G3,
	caseT5Fallback,
	caseT6Selector,
}

func TestSpecsOrderedAndBudgeted(t *testing.T) {
	specs := Specs()
	if got := specIDs(specs); !reflect.DeepEqual(got, orderedCaseIDs) {
		t.Fatalf("Specs IDs = %v, want %v", got, orderedCaseIDs)
	}
	if err := manifest.Validate(specs); err != nil {
		t.Fatalf("Specs validation failed: %v", err)
	}
	wantBudgets := []time.Duration{
		2 * time.Minute,
		2 * time.Minute,
		2 * time.Minute,
		30 * time.Second,
		time.Minute,
		8 * time.Minute,
		12 * time.Minute,
		48 * time.Minute,
		7 * time.Minute,
		33 * time.Minute,
		8 * time.Minute,
		5 * time.Minute,
		2 * time.Minute,
	}
	for i, spec := range specs {
		if !spec.Mandatory || spec.Suite != manifest.SuiteTUN || spec.Tier != "T7" || spec.Budget != wantBudgets[i] {
			t.Errorf("Specs()[%d] = %+v, want mandatory TUN/T7 budget %s", i, spec, wantBudgets[i])
		}
	}

	specs[0].ID = "mutated"
	if got := Specs()[0].ID; got != caseG1Smoke {
		t.Fatalf("Specs returned shared storage: first ID = %q", got)
	}
}

func TestSelectCaseDefs(t *testing.T) {
	tests := []struct {
		name    string
		opts    Options
		want    []string
		wantErr bool
	}{
		{name: "default canonical order", want: defaultCaseIDs},
		{name: "exact visible", opts: Options{Case: caseG3Smoke}, want: []string{caseG3Smoke}},
		{name: "exact hidden xray smoke", opts: Options{Case: caseT3XrayStreamSmoke}, want: []string{caseT3XrayStreamSmoke}},
		{name: "exact hidden long-run selector", opts: Options{Case: caseT4LongRun}, want: []string{caseT4G1, caseT4G2, caseT4G3}},
		{
			name: "inclusive resume",
			opts: Options{FromCase: caseG5PathRecovery},
			want: []string{caseG5PathRecovery, caseT3XrayMatrix, caseT4G1, caseT4G2, caseT4G3, caseT5Fallback, caseT6Selector},
		},
		{
			name: "resume from hidden xray smoke",
			opts: Options{FromCase: caseT3XrayStreamSmoke},
			want: []string{caseT3XrayStreamSmoke, caseT3XrayMatrix, caseT4G1, caseT4G2, caseT4G3, caseT5Fallback, caseT6Selector},
		},
		{
			name: "resume from hidden long-run selector",
			opts: Options{FromCase: caseT4LongRun},
			want: []string{caseT4G1, caseT4G2, caseT4G3, caseT5Fallback, caseT6Selector},
		},
		{name: "missing exact", opts: Options{Case: "TUN-full.missing"}, wantErr: true},
		{name: "missing resume", opts: Options{FromCase: "TUN-full.missing"}, wantErr: true},
		{name: "ambiguous", opts: Options{Case: caseG1Smoke, FromCase: caseG2Smoke}, wantErr: true},
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
}

func TestRunReportsSelectionFailuresWithoutExecutingCases(t *testing.T) {
	tests := []struct {
		name string
		opts Options
		want string
	}{
		{
			name: "unknown exact",
			opts: Options{Case: "missing"},
			want: `TUN full case selection failed for case="missing" from-case="": manifest: no case matched --case="missing"`,
		},
		{
			name: "unknown resume",
			opts: Options{FromCase: "missing"},
			want: `TUN full case selection failed for case="" from-case="missing": manifest: no case matched --from-case="missing"`,
		},
		{
			name: "ambiguous",
			opts: Options{Case: caseG1Smoke, FromCase: caseG2Smoke},
			want: `TUN full case selection failed for case="TUN-full.G1-smoke" from-case="TUN-full.G2-smoke": manifest: --case and --from-case are mutually exclusive`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := report.New()
			Run(context.Background(), suite, "unused", tt.opts)
			if len(suite.Cases) != 1 {
				t.Fatalf("reported cases = %v, want one selection failure", suite.Cases)
			}
			got := suite.Cases[0]
			if got.Name != "TUN-full-case-filter" || got.Tier != "T7" || got.Failure != tt.want {
				t.Fatalf("selection failure = %+v, want failure %q", got, tt.want)
			}
		})
	}
}

func TestRunCaseDefsUsesDeterministicManifestOrder(t *testing.T) {
	var ran []string
	defs := []caseDef{
		syntheticCase("synthetic.first", time.Second, func(_ context.Context, root string, spec manifest.Spec) report.Case {
			if root != "synthetic-root" {
				t.Errorf("root = %q, want synthetic-root", root)
			}
			ran = append(ran, spec.ID)
			return report.Case{}
		}),
		syntheticCase("synthetic.second", time.Second, func(_ context.Context, _ string, spec manifest.Spec) report.Case {
			ran = append(ran, spec.ID)
			return report.Case{}
		}),
	}
	suite := report.New()
	runCaseDefs(context.Background(), suite, "synthetic-root", defs)

	want := []string{"synthetic.first", "synthetic.second"}
	if !reflect.DeepEqual(ran, want) {
		t.Fatalf("runner order = %v, want %v", ran, want)
	}
	if got := reportIDs(suite.Cases); !reflect.DeepEqual(got, want) {
		t.Fatalf("report order = %v, want %v", got, want)
	}
	for _, rc := range suite.Cases {
		if rc.Tier != "T7" || rc.Failure != "" {
			t.Fatalf("normalized report = %+v", rc)
		}
	}
}

func TestRunManifestCaseEnforcesBudget(t *testing.T) {
	finished := make(chan struct{})
	def := syntheticCase("synthetic.timeout", 10*time.Millisecond, func(ctx context.Context, _ string, _ manifest.Spec) report.Case {
		<-ctx.Done()
		close(finished)
		return report.Case{}
	})
	rc := runManifestCase(context.Background(), "", def)
	if rc.Name != def.spec.ID || rc.Tier != def.spec.Tier || !strings.Contains(rc.Failure, "exceeded TUN full budget") {
		t.Fatalf("timeout report = %+v", rc)
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("synthetic timeout runner did not exit after cancellation")
	}
}

func TestRunManifestCaseFailsClosedOnWrongIdentity(t *testing.T) {
	def := syntheticCase("synthetic.expected", time.Second, func(context.Context, string, manifest.Spec) report.Case {
		return report.Case{Name: "synthetic.wrong", Tier: "wrong-tier"}
	})
	rc := runManifestCase(context.Background(), "", def)
	if rc.Name != def.spec.ID || rc.Tier != def.spec.Tier {
		t.Fatalf("report identity = %+v", rc)
	}
	if !strings.Contains(rc.Failure, `runner reported case "synthetic.wrong"`) || !strings.Contains(rc.Failure, `runner reported tier "wrong-tier"`) {
		t.Fatalf("identity mismatch did not fail closed: %+v", rc)
	}
}

func TestValidateCaseDefsRejectsMissingBudgetAndSelectorMember(t *testing.T) {
	noBudget := syntheticCase("synthetic.no-budget", 0, func(context.Context, string, manifest.Spec) report.Case {
		return report.Case{}
	})
	if err := validateCaseDefs([]caseDef{noBudget}); err == nil || !strings.Contains(err.Error(), "no execution budget") {
		t.Fatalf("missing budget err = %v", err)
	}

	selector := caseDef{
		spec:    tunSpec("synthetic.selector", time.Second, false),
		members: []string{"synthetic.missing"},
	}
	if err := validateCaseDefs([]caseDef{selector}); err == nil || !strings.Contains(err.Error(), "unknown case") {
		t.Fatalf("missing selector member err = %v", err)
	}
}

func TestUnimplementedCaseFails(t *testing.T) {
	c := UnimplementedCase("")
	if c.Name != "TUN-full-not-implemented" || c.Tier != "T7" || c.Failure == "" {
		t.Fatalf("bad unimplemented case: %+v", c)
	}
}

func syntheticCase(id string, budget time.Duration, run caseRun) caseDef {
	return caseDef{spec: tunSpec(id, budget, false), defaultRun: true, run: run}
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

func reportIDs(cases []report.Case) []string {
	ids := make([]string, len(cases))
	for i, rc := range cases {
		ids[i] = rc.Name
	}
	return ids
}
