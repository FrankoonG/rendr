package tier5

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/caseexec"
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
	if err := manifest.ValidateCensus(specs); err != nil {
		t.Fatalf("closed T5 census validation failed: %v", err)
	}
	wantBudgets := []time.Duration{3 * time.Minute, 2 * time.Minute, 2 * time.Minute, 2 * time.Minute, 2 * time.Minute, 2 * time.Minute}
	for i, spec := range specs {
		if !spec.Mandatory || spec.Suite != manifest.SuiteNormal || spec.Budget != wantBudgets[i] {
			t.Errorf("Specs()[%d] = %+v, want mandatory normal-suite budget %s", i, spec, wantBudgets[i])
		}
		if spec.Contract == nil {
			t.Fatalf("case %q has no schema-v3 contract", spec.ID)
		}
		if err := spec.Contract.Validate(); err != nil {
			t.Fatalf("case %q contract validation failed: %v", spec.ID, err)
		}
		if spec.Contract.State != manifest.ContractStateBlocked {
			t.Errorf("case %q contract state=%q, want blocked while resource minima and negative controls are unfrozen", spec.ID, spec.Contract.State)
		}
		if tier5MissingReason(spec.Contract, manifest.ContractDimensionResources) == "" {
			t.Errorf("case %q does not mark per-role resources unfrozen", spec.ID)
		}
		for _, item := range []struct {
			dimension manifest.ContractDimension
			profile   manifest.EvidenceProfile
		}{
			{manifest.ContractDimensionStimulus, spec.Contract.Stimulus},
			{manifest.ContractDimensionOracle, spec.Contract.Oracle},
		} {
			if tier5MissingReason(spec.Contract, item.dimension) == "" && len(item.profile.Assertions) == 0 {
				t.Errorf("case %q %s profile has no typed assertion", spec.ID, item.dimension)
			}
		}
	}

	fallback := specs[4].Contract
	if reason := tier5MissingReason(fallback, manifest.ContractDimensionOracle); !strings.Contains(reason, "AdminConn.AddPath") {
		t.Fatalf("T5.5 oracle block reason=%q, want explicit regression-orchestrated redial/attach limitation", reason)
	}
	if fallback.Oracle.Name != "" || len(fallback.Oracle.RequiredFacts) != 0 || len(fallback.Oracle.Assertions) != 0 {
		t.Fatalf("T5.5 claims a completed fallback oracle: %+v", fallback.Oracle)
	}
	if !strings.Contains(fallback.Purpose, "regression-orchestrated same-session redial/attach") {
		t.Fatalf("T5.5 purpose=%q, want current explicit redial/attach behavior", fallback.Purpose)
	}
	if reason := tier5MissingReason(fallback, manifest.ContractDimensionPayload); !strings.Contains(reason, "different byte lengths") ||
		fallback.Payload.Applicability != manifest.ApplicabilityUnfrozen {
		t.Fatalf("T5.5 payload dimension does not record its variable round-trip strings: payload=%+v reason=%q", fallback.Payload, reason)
	}
	if got, ok := tier5ProfileParam(fallback.Load, "bidirectional_round_trips"); !ok || got != 4 {
		t.Fatalf("T5.5 load bidirectional_round_trips = %d, present=%t, want 4", got, ok)
	}

	for _, index := range []int{3, 5} {
		contract := specs[index].Contract
		if containsTier5String(contract.Oracle.RequiredFacts, "gvisor_packet_link_rebind_observed") ||
			!containsTier5String(contract.Stimulus.RequiredFacts, "gvisor_packet_link_rebind_observed") ||
			!tier5HasAssertion(contract.Stimulus, "gvisor_packet_link_rebind_observed", manifest.EvidenceEquals, "false") {
			t.Errorf("case %q treats absent packet-link rebind observation as a successful oracle: stimulus=%+v oracle=%+v", specs[index].ID, contract.Stimulus, contract.Oracle)
		}
		if !tier5HasAssertion(contract.Oracle, "sha256_match", manifest.EvidenceEquals, "true") ||
			!tier5HasAssertion(contract.Oracle, "workload_result", manifest.EvidenceEquals, "pass") {
			t.Errorf("case %q lacks typed workload pass predicates: %+v", specs[index].ID, contract.Oracle)
		}
	}

	contractCopy := Specs()
	contractCopy[0].Contract.Purpose = "mutated"
	contractCopy[0].Contract.MissingDimensions[0].Reason = "mutated"
	contractCopy[0].Contract.RoleCapabilities["test-process"][0] = "mutated"
	contractCopy[0].Contract.Oracle.Assertions[0].Expected = "mutated"
	if got := caseDefs[0].spec.Contract.Purpose; got == "mutated" {
		t.Fatal("Specs exposed mutable contract text")
	}
	if got := caseDefs[0].spec.Contract.MissingDimensions[0].Reason; got == "mutated" {
		t.Fatal("Specs exposed mutable nested contract metadata")
	}
	if got := caseDefs[0].spec.Contract.RoleCapabilities["test-process"][0]; got == "mutated" {
		t.Fatal("Specs exposed mutable role capabilities")
	}
	if got := caseDefs[0].spec.Contract.Oracle.Assertions[0].Expected; got == "mutated" {
		t.Fatal("Specs exposed mutable evidence assertions")
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

func tier5MissingReason(contract *manifest.Contract, dimension manifest.ContractDimension) string {
	if contract == nil {
		return ""
	}
	for _, missing := range contract.MissingDimensions {
		if missing.Dimension == dimension {
			return missing.Reason
		}
	}
	return ""
}

func tier5ProfileParam(profile manifest.Profile, name string) (uint64, bool) {
	for _, parameter := range profile.Params {
		if parameter.Name == name {
			return parameter.Value, true
		}
	}
	return 0, false
}

func tier5HasAssertion(profile manifest.EvidenceProfile, fact string, predicate manifest.EvidencePredicate, expected string) bool {
	for _, assertion := range profile.Assertions {
		if assertion.Fact == fact && assertion.Predicate == predicate && assertion.Expected == expected {
			return true
		}
	}
	return false
}

func containsTier5String(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
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
			runSelectedCases(context.Background(), suite, defs, func(_ context.Context, def caseDef) caseexec.Outcome {
				called = append(called, def.spec.ID)
				rc := report.Case{Name: def.spec.ID, Tier: def.spec.Tier}
				if def.spec.ID == "synthetic.blocker" {
					rc.Failure = tt.outcome.Failure
					rc.InvalidReason = tt.outcome.InvalidReason
					rc.SkipReason = tt.outcome.SkipReason
				}
				return caseexec.Outcome{Case: rc}
			})

			if want := []string{"synthetic.first", "synthetic.blocker"}; !reflect.DeepEqual(called, want) {
				t.Fatalf("executed cases = %v, want %v", called, want)
			}
			assertFailFastRows(t, suite.Cases, "T5")
		})
	}
}

func TestRunSelectedCasesStopsAfterUnsafeOutcome(t *testing.T) {
	defs := syntheticCaseDefs("T5")
	defs[0].spec.Mandatory = false
	calls := 0
	suite := report.New()
	runSelectedCases(context.Background(), suite, defs, func(_ context.Context, def caseDef) caseexec.Outcome {
		calls++
		return caseexec.Outcome{
			Case: report.Case{
				Name:          def.spec.ID,
				Tier:          def.spec.Tier,
				InvalidReason: "workload did not join; process exit required",
			},
			MustStop: true,
		}
	})

	if calls != 1 {
		t.Fatalf("executor calls = %d, want 1", calls)
	}
	if got := len(suite.Cases); got != len(defs) {
		t.Fatalf("report rows = %d, want %d", got, len(defs))
	}
	if got := suite.Cases[0]; got.ExecutionState != report.ExecutionStateExecuted || got.BlockedByCaseID != "" {
		t.Fatalf("executed stopping row state = %q blocked by %q", got.ExecutionState, got.BlockedByCaseID)
	}
	for _, got := range suite.Cases[1:] {
		if got.ExecutionState != report.ExecutionStateNotRun || got.BlockedByCaseID != "synthetic.first" ||
			got.InvalidReason != "not run after synthetic.first failed" {
			t.Fatalf("downstream not-run row = %+v", got)
		}
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
	for i, rc := range cases[:2] {
		if rc.ExecutionState != report.ExecutionStateExecuted || rc.BlockedByCaseID != "" {
			t.Fatalf("executed row %d state = %q blocked by %q", i, rc.ExecutionState, rc.BlockedByCaseID)
		}
	}
	trailing := cases[2]
	if trailing.ExecutionState != report.ExecutionStateNotRun || trailing.BlockedByCaseID != "synthetic.blocker" {
		t.Fatalf("trailing row state = %q blocked by %q", trailing.ExecutionState, trailing.BlockedByCaseID)
	}
	if got := trailing.InvalidReason; got != "not run after synthetic.blocker failed" {
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
