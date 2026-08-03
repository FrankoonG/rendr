package tunfull

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/chaos"
	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/report"
	"github.com/FrankoonG/rendr/virtualif"
)

var orderedCaseIDs = []string{
	caseKernelTUNPreflight,
	caseG1Smoke,
	caseG2Smoke,
	caseG3Smoke,
	caseG4PathDeath,
	caseG5PathRecovery,
	caseT3XrayMatrix,
	caseT4G1,
	caseT4G2,
	caseT4G3,
	caseT5AdapterMatrix,
	caseT6Selector,
}

var defaultCaseIDs = []string{
	caseKernelTUNPreflight,
	caseG1Smoke,
	caseG2Smoke,
	caseG3Smoke,
	caseG4PathDeath,
	caseG5PathRecovery,
	caseT3XrayMatrix,
	caseT4G1,
	caseT4G2,
	caseT4G3,
	caseT5AdapterMatrix,
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
		30 * time.Second,
		2 * time.Minute,
		2 * time.Minute,
		2 * time.Minute,
		30 * time.Second,
		time.Minute,
		12 * time.Minute,
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
		wantRequires := []string(nil)
		if spec.ID != caseKernelTUNPreflight {
			wantRequires = []string{caseKernelTUNPreflight}
		}
		if !reflect.DeepEqual(spec.Requires, wantRequires) {
			t.Errorf("Specs()[%d].Requires = %v, want %v", i, spec.Requires, wantRequires)
		}
	}

	specs[0].ID = "mutated"
	specs[1].Requires[0] = "mutated"
	if got := Specs()[0].ID; got != caseKernelTUNPreflight {
		t.Fatalf("Specs returned shared storage: first ID = %q", got)
	}
	if got := Specs()[1].Requires[0]; got != caseKernelTUNPreflight {
		t.Fatalf("Specs returned shared prerequisite storage: %q", got)
	}
}

func testAliasesAreSeparateImmutableMetadata(t *testing.T) {
	got := Aliases()
	want := []Alias{
		{ID: caseT3XrayStreamSmoke, Before: caseT3XrayMatrix, ExpandsTo: []string{caseT3XrayMatrix}},
		{ID: caseT4LongRun, Before: caseT4G1, ExpandsTo: []string{caseT4G1, caseT4G2, caseT4G3}},
		{ID: caseT4G2Prime, Before: caseT4G2, ExpandsTo: []string{caseT4G2}},
		{ID: caseT5Fallback, Before: caseT5AdapterMatrix, ExpandsTo: []string{caseT5AdapterMatrix}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Aliases()=%+v want %+v", got, want)
	}
	got[0].ExpandsTo[0] = "mutated"
	if Aliases()[0].ExpandsTo[0] != caseT3XrayMatrix {
		t.Fatal("Aliases returned shared expansion storage")
	}
	for _, spec := range Specs() {
		for _, alias := range got {
			if spec.ID == alias.ID {
				t.Fatalf("compatibility alias %q entered executable Specs", alias.ID)
			}
		}
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
		{name: "exact visible", opts: Options{Case: caseG3Smoke}, want: []string{caseKernelTUNPreflight, caseG3Smoke}},
		{
			name: "inclusive resume",
			opts: Options{FromCase: caseG5PathRecovery},
			want: []string{caseKernelTUNPreflight, caseG5PathRecovery, caseT3XrayMatrix, caseT4G1, caseT4G2, caseT4G3, caseT5AdapterMatrix, caseT6Selector},
		},
		{name: "alias is not executable", opts: Options{Case: caseT4LongRun}, wantErr: true},
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

	if _, err := PlanCases([]string{caseG3Smoke}); err == nil || !strings.Contains(err.Error(), "not prerequisite-closed") {
		t.Fatalf("unclosed plan err=%v", err)
	}
	planned, err := PlanCases([]string{caseKernelTUNPreflight, caseG3Smoke})
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{planned[0].Spec().ID, planned[1].Spec().ID}; !reflect.DeepEqual(got, []string{caseKernelTUNPreflight, caseG3Smoke}) {
		t.Fatalf("planned IDs=%v", got)
	}
	spec := planned[1].Spec()
	spec.Requires[0] = "mutated"
	if got := planned[1].Spec().Requires[0]; got != caseKernelTUNPreflight {
		t.Fatalf("planned Spec exposed prerequisite alias: %q", got)
	}
	invalidSuite := report.New()
	RunPlannedCase(context.Background(), invalidSuite, "unused", PlannedCase{})
	if len(invalidSuite.Cases) != 1 || invalidSuite.Cases[0].Failure == "" {
		t.Fatalf("unsealed plan report=%+v", invalidSuite.Cases)
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
			want: `TUN synthetic L3/session case selection failed for case="missing" from-case="": manifest: no case matched --case="missing"`,
		},
		{
			name: "unknown resume",
			opts: Options{FromCase: "missing"},
			want: `TUN synthetic L3/session case selection failed for case="" from-case="missing": manifest: no case matched --from-case="missing"`,
		},
		{
			name: "ambiguous",
			opts: Options{Case: caseG1Smoke, FromCase: caseG2Smoke},
			want: `TUN synthetic L3/session case selection failed for case="TUN-full.G1-smoke" from-case="TUN-full.G2-smoke": manifest: --case and --from-case are mutually exclusive`,
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

func TestRunCaseDefsStopsAfterMandatoryOutcome(t *testing.T) {
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
			var called []string
			defs := []caseDef{
				syntheticCase("synthetic.first", time.Second, func(_ context.Context, _ string, spec manifest.Spec) report.Case {
					called = append(called, spec.ID)
					return report.Case{}
				}),
				syntheticCase("synthetic.blocker", time.Second, func(_ context.Context, _ string, spec manifest.Spec) report.Case {
					called = append(called, spec.ID)
					return tt.outcome
				}),
				syntheticCase("synthetic.after", time.Second, func(_ context.Context, _ string, spec manifest.Spec) report.Case {
					called = append(called, spec.ID)
					return report.Case{}
				}),
			}
			suite := report.New()
			runCaseDefs(context.Background(), suite, "", defs)

			if want := []string{"synthetic.first", "synthetic.blocker"}; !reflect.DeepEqual(called, want) {
				t.Fatalf("executed cases = %v, want %v", called, want)
			}
			wantIDs := []string{"synthetic.first", "synthetic.blocker", "synthetic.after"}
			if got := reportIDs(suite.Cases); !reflect.DeepEqual(got, wantIDs) {
				t.Fatalf("report IDs = %v, want %v", got, wantIDs)
			}
			if got := suite.Cases[2].InvalidReason; got != "not run after synthetic.blocker failed" {
				t.Fatalf("trailing row invalid reason = %q", got)
			}
		})
	}
}

func TestRunManifestCaseEnforcesBudget(t *testing.T) {
	cancelSeen := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	def := syntheticCase("synthetic.timeout", 10*time.Millisecond, func(ctx context.Context, _ string, _ manifest.Spec) report.Case {
		<-ctx.Done()
		close(cancelSeen)
		<-release
		close(finished)
		return report.Case{}
	})
	returned := make(chan report.Case, 1)
	go func() { returned <- runManifestCase(context.Background(), "", def) }()
	<-cancelSeen
	select {
	case rc := <-returned:
		t.Fatalf("runManifestCase returned before workload quiesced: %+v", rc)
	default:
	}
	close(release)
	rc := <-returned
	if rc.Name != def.spec.ID || rc.Tier != def.spec.Tier || !strings.Contains(rc.Failure, "exceeded TUN synthetic-suite budget") {
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
	if err := validateCaseDefs([]caseDef{noBudget}); err == nil || !strings.Contains(err.Error(), "non-positive budget") {
		t.Fatalf("missing budget err = %v", err)
	}

	missingRunner := caseDef{spec: tunSpec("synthetic.missing-runner", time.Second, false)}
	if err := validateCaseDefs([]caseDef{missingRunner}); err == nil || !strings.Contains(err.Error(), "no runner") {
		t.Fatalf("missing runner err = %v", err)
	}
}

func testKernelTUNPreflightFailsClosedAndRecordsSyntheticScope(t *testing.T) {
	original := probeKernelTUN
	t.Cleanup(func() { probeKernelTUN = original })

	probeKernelTUN = func() virtualif.Capability {
		return virtualif.Capability{Available: false, Reason: virtualif.ReasonTUNUnavailable, Err: errors.New("missing device")}
	}
	rc := runManifestCase(context.Background(), "", caseDefs[0])
	if !strings.Contains(rc.InvalidReason, "cannot count as TUN release evidence") {
		t.Fatalf("unavailable preflight=%+v", rc)
	}
	if rc.Evidence["kernel_tun_available"] != "false" || rc.Evidence["evidence_class"] != syntheticEvidenceClass || rc.Evidence["kernel_tun_gold"] != "false" {
		t.Fatalf("unavailable evidence=%v", rc.Evidence)
	}

	probeKernelTUN = func() virtualif.Capability { return virtualif.Capability{Available: true} }
	rc = runManifestCase(context.Background(), "", caseDefs[0])
	if rc.Failure != "" || rc.InvalidReason != "" || rc.SkipReason != "" {
		t.Fatalf("available preflight=%+v", rc)
	}
	if rc.Evidence["kernel_tun_available"] != "true" || rc.Evidence["required_gold_fixture"] != realTUNGoldFixture {
		t.Fatalf("available evidence=%v", rc.Evidence)
	}
}

func TestLongRunAliasReportsEachSelectedExecutableMemberExactlyOnce(t *testing.T) {
	t.Run("aliases are separate immutable metadata", testAliasesAreSeparateImmutableMetadata)
	t.Run("kernel TUN preflight fails closed", testKernelTUNPreflightFailsClosedAndRecordsSyntheticScope)
	t.Run("G3 measurements fail closed", testValidateTUNG3MeasurementsFailsClosed)
	t.Run("G3 explicit loss budget", testValidateTUNG3MeasurementsHonorsOnlyExplicitLossBudget)
	t.Run("G3 path evidence is deterministic", testFormatTUNG3PathWritesIsDeterministic)
	t.Run("xray uses exact strict JSON contract", testRunT3XrayMatrixUsesExactStrictGoTestContract)
	t.Run("xray rejects false-green streams", testTUNGoTestReportRejectsFalseGreenStreams)
}

func TestUnimplementedCaseFails(t *testing.T) {
	c := UnimplementedCase("")
	if c.Name != "TUN-full-not-implemented" || c.Tier != "T7" || c.Failure == "" {
		t.Fatalf("bad unimplemented case: %+v", c)
	}
}

func TestApplyT4CleanupResultFailsClosed(t *testing.T) {
	rc := report.Case{Name: "case", Tier: "T7"}
	applyT4CleanupResult(&rc, func() error { return errors.New("cleanup boom") })
	if rc.Failure != "" || rc.InvalidReason != "chaos cleanup failed: cleanup boom" {
		t.Fatalf("case=%+v", rc)
	}

	rc = report.Case{Name: "case", Tier: "T7", Failure: "case boom"}
	applyT4CleanupResult(&rc, func() error { return errors.New("cleanup boom") })
	if rc.Failure != "" || rc.InvalidReason != "chaos cleanup failed: cleanup boom" || rc.Evidence["untrusted_case_failure"] != "case boom" {
		t.Fatalf("failed case=%+v", rc)
	}

	rc = report.Case{Name: "case", Tier: "T7", InvalidReason: "stimulus missing"}
	applyT4CleanupResult(&rc, func() error { return errors.New("cleanup boom") })
	if rc.Failure != "" || rc.InvalidReason != "stimulus missing; chaos cleanup failed: cleanup boom" {
		t.Fatalf("invalid case=%+v", rc)
	}

	t.Run("budget joins workload before cleanup", func(t *testing.T) {
		original := tunChaosApply
		t.Cleanup(func() { tunChaosApply = original })
		cancelSeen := make(chan struct{})
		release := make(chan struct{})
		finished := make(chan struct{})
		cleanupCalled := make(chan struct{})
		tunChaosApply = func(chaos.Profile) (func() error, error) {
			return func() error {
				select {
				case <-finished:
				default:
					t.Error("cleanup ran before workload quiesced")
				}
				close(cleanupCalled)
				return nil
			}, nil
		}
		returned := make(chan report.Case, 1)
		go func() {
			returned <- runT4WithBudget(context.Background(), "synthetic.t4", 10*time.Millisecond, chaos.Profile{}, func(ctx context.Context) report.Case {
				<-ctx.Done()
				close(cancelSeen)
				<-release
				close(finished)
				return report.Case{Name: "synthetic.t4", Tier: "T7"}
			})
		}()
		<-cancelSeen
		select {
		case got := <-returned:
			t.Fatalf("runT4WithBudget returned before workload quiesced: %+v", got)
		default:
		}
		close(release)
		got := <-returned
		if !strings.Contains(got.Failure, "exceeded T4 budget") {
			t.Fatalf("timeout report = %+v", got)
		}
		select {
		case <-cleanupCalled:
		default:
			t.Fatal("cleanup was not called before return")
		}
	})
}

func syntheticCase(id string, budget time.Duration, run caseRun) caseDef {
	return caseDef{spec: tunSpec(id, budget, false), run: run}
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
