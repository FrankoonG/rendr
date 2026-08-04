package tunfull

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/FrankoonG/rendr"
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

type teardownSensitiveTUNG3Stats struct {
	closed             bool
	statsCalls         int
	observedAfterClose bool
}

func (a *teardownSensitiveTUNG3Stats) Stats() rendr.ConnStats {
	a.statsCalls++
	if a.closed {
		a.observedAfterClose = true
		return rendr.ConnStats{}
	}
	return rendr.ConnStats{
		MigrationCount: 7,
		Paths: []rendr.PathInfo{
			{ID: 1, Writes: 110},
			{ID: 2, Writes: 220},
		},
	}
}

func TestTUNG3CapturesPathEvidenceBeforeTeardown(t *testing.T) {
	admin := &teardownSensitiveTUNG3Stats{}
	evidence, err := finalizeTUNG3Evidence(admin, map[uint32]uint64{1: 10, 2: 20}, 4, func() error {
		if admin.statsCalls != 1 {
			t.Fatalf("Stats calls before teardown=%d, want exactly 1", admin.statsCalls)
		}
		admin.closed = true
		return nil
	})
	if err != nil {
		t.Fatalf("finalize evidence: %v", err)
	}
	if !admin.closed || admin.observedAfterClose {
		t.Fatalf("teardown ordering: closed=%t observed_after_close=%t", admin.closed, admin.observedAfterClose)
	}
	if evidence.initialPathCount != 2 || evidence.finalPathCount != 2 {
		t.Fatalf("path counts=(%d,%d), want (2,2)", evidence.initialPathCount, evidence.finalPathCount)
	}
	if evidence.migrationsObserved != 3 {
		t.Fatalf("migrations=%d, want 3", evidence.migrationsObserved)
	}
	if !reflect.DeepEqual(evidence.perPathWrites, map[uint32]uint64{1: 100, 2: 200}) || evidence.wireWrites != 300 {
		t.Fatalf("path evidence=%v total=%d", evidence.perPathWrites, evidence.wireWrites)
	}
}

func TestTUNG3FinalEvidenceRejectsPathCountChange(t *testing.T) {
	evidence := tunG3FinalEvidence{initialPathCount: 2, finalPathCount: 1}
	if got := evidence.invalidReason(); !strings.Contains(got, "final pre-teardown path count=1 differs from initial=2") {
		t.Fatalf("invalid reason=%q", got)
	}
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
		if spec.Contract == nil {
			t.Errorf("Specs()[%d] has no schema-v3 contract", i)
			continue
		}
		for _, item := range []struct {
			dimension manifest.ContractDimension
			profile   manifest.EvidenceProfile
		}{
			{manifest.ContractDimensionStimulus, spec.Contract.Stimulus},
			{manifest.ContractDimensionOracle, spec.Contract.Oracle},
		} {
			if !hasTUNMissing(spec.Contract, item.dimension) && len(item.profile.Assertions) == 0 {
				t.Errorf("Specs()[%d] %s profile has no typed assertion", i, item.dimension)
			}
		}
	}
	if err := manifest.ValidateCensus(specs); err != nil {
		t.Fatalf("TUN census validation failed: %v", err)
	}

	specs[0].ID = "mutated"
	specs[1].Requires[0] = "mutated"
	if got := Specs()[0].ID; got != caseKernelTUNPreflight {
		t.Fatalf("Specs returned shared storage: first ID = %q", got)
	}
	if got := Specs()[1].Requires[0]; got != caseKernelTUNPreflight {
		t.Fatalf("Specs returned shared prerequisite storage: %q", got)
	}

	t.Run("contracts are defensive copies", func(t *testing.T) {
		first := Specs()
		first[0].Contract.MissingDimensions[0].Reason = "mutated"
		first[0].Contract.Topology.Roles[0] = "mutated"
		first[0].Contract.Payload.Params[0].Name = "mutated"
		first[0].Contract.Stimulus.RequiredFacts[0] = "mutated"
		first[0].Contract.Oracle.Assertions[0].Expected = "mutated"
		fresh := Specs()[0].Contract
		if fresh.MissingDimensions[0].Reason == "mutated" || fresh.Topology.Roles[0] == "mutated" ||
			fresh.Payload.Params[0].Name == "mutated" || fresh.Stimulus.RequiredFacts[0] == "mutated" ||
			fresh.Oracle.Assertions[0].Expected == "mutated" {
			t.Fatal("mutating a returned contract changed the closed TUN registry")
		}
	})

	t.Run("kernel and synthetic claims stay distinct", func(t *testing.T) {
		registrySpecs := Specs()
		byID := make(map[string]manifest.Spec, len(registrySpecs))
		for _, spec := range registrySpecs {
			byID[spec.ID] = spec
		}
		preflight := byID[caseKernelTUNPreflight].Contract
		if preflight.NegativeControl.Kind != manifest.NegativeControlEmbedded ||
			preflight.NegativeControl.EmbeddedID != "CAP_NET_ADMIN-denied kernel TUN helper probe" ||
			!containsTUNString(preflight.Stimulus.RequiredFacts, "kernel_tun_fd_read_from_kernel") ||
			!containsTUNString(preflight.Oracle.RequiredFacts, "kernel_tun_negative_control_pass") ||
			containsTUNString(preflight.Oracle.RequiredFacts, "kernel_tun_gold") ||
			!hasTUNAssertion(preflight.Stimulus, "kernel_tun_gold", manifest.EvidenceEquals, "false") ||
			!hasTUNAssertion(preflight.Oracle, "kernel_tun_environment_gate_pass", manifest.EvidenceEquals, "true") {
			t.Fatalf("kernel preflight contract does not match emitted positive/negative evidence: %+v", preflight)
		}
		for _, id := range []string{caseG1Smoke, caseG2Smoke, caseG5PathRecovery, caseT4G1, caseT4G2, caseT6Selector} {
			contract := byID[id].Contract
			if contract.State != manifest.ContractStateBlocked || !hasTUNMissing(contract, manifest.ContractDimensionStimulus) ||
				!hasTUNMissing(contract, manifest.ContractDimensionOracle) || contract.Stimulus.Name != "" || contract.Oracle.Name != "" {
				t.Errorf("synthetic case %s does not remain blocked on absent emitted evidence: %+v", id, contract)
			}
		}
		adapter := byID[caseT5AdapterMatrix].Contract
		if hasTUNMissing(adapter, manifest.ContractDimensionStimulus) || !hasTUNMissing(adapter, manifest.ContractDimensionOracle) ||
			adapter.Oracle.Name != "" || !hasTUNAssertion(adapter.Stimulus, "gvisor_exercised", manifest.EvidenceEquals, "true") {
			t.Errorf("synthetic adapter matrix does not separate observations from its missing oracle: %+v", adapter)
		}
		for _, id := range []string{caseG3Smoke, caseT4G3} {
			contract := byID[id].Contract
			if !strings.Contains(contract.Purpose, "does not prove RFC 9000 CID rebinding") ||
				containsTUNString(contract.Oracle.RequiredFacts, "g3_semantics") ||
				!containsTUNString(contract.Stimulus.RequiredFacts, "g3_semantics") ||
				!hasTUNAssertion(contract.Stimulus, "g3_semantics", manifest.EvidenceEquals, "synthetic_l3session_quic_datagram_not_rfc9000_cid_gold") {
				t.Errorf("synthetic G3 contract %s overstates kernel TUN or CID semantics: %+v", id, contract)
			}
			if got, ok := tunProfileParam(contract.Payload, "application_record_bytes"); !ok || got != 1024 {
				t.Errorf("synthetic G3 %s application_record_bytes = %d, present=%t, want 1024", id, got, ok)
			}
			if got, ok := tunProfileParam(contract.Payload, "body_bytes"); !ok || got != 1016 {
				t.Errorf("synthetic G3 %s body_bytes = %d, present=%t, want 1016", id, got, ok)
			}
			if got, ok := tunProfileParam(contract.Payload, "sequence_prefix_bytes"); !ok || got != 8 {
				t.Errorf("synthetic G3 %s sequence_prefix_bytes = %d, present=%t, want 8", id, got, ok)
			}
		}
		g3Smoke := byID[caseG3Smoke].Contract
		if _, ok := tunProfileParam(g3Smoke.Load, "offered_pps"); ok {
			t.Errorf("synthetic G3 smoke labels its configured target as offered_pps: %+v", g3Smoke.Load)
		}
		if got, ok := tunProfileParam(g3Smoke.Load, "target_pps"); !ok || got != 5000 {
			t.Errorf("synthetic G3 smoke target_pps = %d, present=%t, want 5000", got, ok)
		}
		g3Long := byID[caseT4G3].Contract
		if !hasTUNMissing(g3Long, manifest.ContractDimensionLoad) || g3Long.Load.Applicability != manifest.ApplicabilityUnfrozen ||
			!strings.Contains(g3Long.Purpose, "at or above 95,000 pps") ||
			!hasTUNAssertion(g3Long.Stimulus, "offered_pps", manifest.EvidenceFloatAtLeast, "95000") {
			t.Errorf("synthetic 100k G3 does not record its factual 95%% load floor: %+v", g3Long)
		}
		if got := len(Aliases()); got != 4 {
			t.Fatalf("Aliases count = %d, want 4 non-executable aliases", got)
		}
	})
}

func hasTUNMissing(contract *manifest.Contract, dimension manifest.ContractDimension) bool {
	if contract == nil {
		return false
	}
	for _, missing := range contract.MissingDimensions {
		if missing.Dimension == dimension {
			return true
		}
	}
	return false
}

func containsTUNString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func tunProfileParam(profile manifest.Profile, name string) (uint64, bool) {
	for _, parameter := range profile.Params {
		if parameter.Name == name {
			return parameter.Value, true
		}
	}
	return 0, false
}

func hasTUNAssertion(profile manifest.EvidenceProfile, fact string, predicate manifest.EvidencePredicate, expected string) bool {
	for _, assertion := range profile.Assertions {
		if assertion.Fact == fact && assertion.Predicate == predicate && assertion.Expected == expected {
			return true
		}
	}
	return false
}

func testAliasesAreSeparateImmutableMetadata(t *testing.T) {
	got := Aliases()
	want := []Alias{
		{ID: caseT3XrayStreamSmoke, Before: caseT3XrayMatrix, ExpandsTo: []string{caseT3XrayMatrix}},
		{ID: caseT4LongRun, Before: caseT4G1, ExpandsTo: []string{caseT4G1, caseT4G2, caseT4G3}},
		{ID: caseT4G2Prime, Before: caseT4G2, ExpandsTo: []string{caseT4G2}},
		{
			ID:            caseT5Fallback,
			Before:        caseT5AdapterMatrix,
			ExpandsTo:     []string{caseT5AdapterMatrix},
			RetiredReason: "historical name claimed fallback coverage, but the replacement adapter matrix does not exercise fallback",
		},
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
		{name: "exact preflight", opts: Options{Case: caseKernelTUNPreflight}, want: []string{caseKernelTUNPreflight}},
		{name: "exact visible", opts: Options{Case: caseG3Smoke}, want: []string{caseKernelTUNPreflight, caseG3Smoke}},
		{name: "resume from preflight", opts: Options{FromCase: caseKernelTUNPreflight}, want: defaultCaseIDs},
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
			for i, rc := range suite.Cases[:2] {
				if rc.ExecutionState != report.ExecutionStateExecuted || rc.BlockedByCaseID != "" {
					t.Fatalf("executed row %d state = %q blocked by %q", i, rc.ExecutionState, rc.BlockedByCaseID)
				}
			}
			if got := suite.Cases[2]; got.ExecutionState != report.ExecutionStateNotRun || got.BlockedByCaseID != "synthetic.blocker" {
				t.Fatalf("trailing row state = %q blocked by %q", got.ExecutionState, got.BlockedByCaseID)
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
	if rc.Name != def.spec.ID || rc.Tier != def.spec.Tier || !strings.Contains(rc.Failure, "case exceeded T7 budget") ||
		rc.Evidence["timeout_cleanup"] != "joined" || rc.Evidence["timeout_budget"] != def.spec.Budget.String() {
		t.Fatalf("timeout report = %+v", rc)
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("synthetic timeout runner did not exit after cancellation")
	}
}

func TestRunCaseDefsStopsAfterUnjoinedTimeout(t *testing.T) {
	originalJoinTimeout := tunCaseJoinTimeout
	tunCaseJoinTimeout = 20 * time.Millisecond
	t.Cleanup(func() { tunCaseJoinTimeout = originalJoinTimeout })

	release := make(chan struct{})
	workerDone := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
		select {
		case <-workerDone:
		case <-time.After(time.Second):
			t.Error("noncooperative test worker did not exit after release")
		}
	})
	secondCalled := false
	defs := []caseDef{
		syntheticCase("synthetic.unjoined", 20*time.Millisecond, func(context.Context, string, manifest.Spec) report.Case {
			defer close(workerDone)
			<-release
			return report.Case{}
		}),
		syntheticCase("synthetic.after-unjoined", time.Second, func(context.Context, string, manifest.Spec) report.Case {
			secondCalled = true
			return report.Case{}
		}),
	}
	suite := report.New()
	runCaseDefs(context.Background(), suite, "", defs)
	if secondCalled {
		t.Fatal("runner started a later case after an unjoined timeout")
	}
	if len(suite.Cases) != 2 || !strings.Contains(suite.Cases[0].InvalidReason, "Go cannot terminate") ||
		!strings.Contains(suite.Cases[1].InvalidReason, "not run after synthetic.unjoined failed") {
		t.Fatalf("unjoined timeout rows = %+v", suite.Cases)
	}
	if got := suite.Cases[0]; got.ExecutionState != report.ExecutionStateExecuted || got.BlockedByCaseID != "" {
		t.Fatalf("unjoined executed row state = %q blocked by %q", got.ExecutionState, got.BlockedByCaseID)
	}
	if got := suite.Cases[1]; got.ExecutionState != report.ExecutionStateNotRun || got.BlockedByCaseID != "synthetic.unjoined" {
		t.Fatalf("unjoined downstream row state = %q blocked by %q", got.ExecutionState, got.BlockedByCaseID)
	}
}

func TestExecuteG4PathKillFailsClosedWithoutStimulus(t *testing.T) {
	tests := []struct {
		name       string
		activePath uint32
		kill       func(uint32) error
		paths      func() []rendr.PathInfo
		wantError  string
	}{
		{name: "no active path", wantError: "no active path"},
		{
			name: "kill error", activePath: 7,
			kill:      func(uint32) error { return errors.New("synthetic kill rejected") },
			paths:     func() []rendr.PathInfo { return []rendr.PathInfo{{ID: 7}, {ID: 8}} },
			wantError: "synthetic kill rejected",
		},
		{
			name: "path remains", activePath: 7,
			kill:      func(uint32) error { return nil },
			paths:     func() []rendr.PathInfo { return []rendr.PathInfo{{ID: 7}, {ID: 8}} },
			wantError: "remains attached",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outcome := executeG4PathKill(tt.activePath, tt.kill, tt.paths)
			if outcome.Err == nil || !strings.Contains(outcome.Err.Error(), tt.wantError) || outcome.PathRemoved {
				t.Fatalf("kill outcome = %+v, want error containing %q", outcome, tt.wantError)
			}
		})
	}

	outcome := executeG4PathKill(7, func(uint32) error { return nil }, func() []rendr.PathInfo {
		return []rendr.PathInfo{{ID: 8}}
	})
	if outcome.Err != nil || !outcome.Attempted || !outcome.PathRemoved || outcome.PathID != 7 || outcome.At.IsZero() {
		t.Fatalf("successful kill outcome = %+v", outcome)
	}
}

func TestT5AdapterMatrixRejectsPartialCoverage(t *testing.T) {
	original := tunTCPRepairAvailable
	tunTCPRepairAvailable = func() error { return errors.New("TCP_REPAIR unavailable") }
	t.Cleanup(func() { tunTCPRepairAvailable = original })

	rc := runT5AdapterMatrix(context.Background(), t5AdapterMatrixOptions{name: caseT5AdapterMatrix})
	if !strings.Contains(rc.InvalidReason, "mandatory tcprepair adapter unavailable") || rc.Failure != "" {
		t.Fatalf("partial adapter matrix = %+v", rc)
	}
	for _, key := range []string{"tcprepair_exercised", "gvisor_exercised", "gvisor_packet_exercised"} {
		if rc.Evidence[key] != "false" {
			t.Fatalf("partial adapter evidence %s=%q", key, rc.Evidence[key])
		}
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

	missingRunner := caseDef{spec: Specs()[0]}
	missingRunner.spec.ID = "synthetic.missing-runner"
	if err := validateCaseDefs([]caseDef{missingRunner}); err == nil || !strings.Contains(err.Error(), "no runner") {
		t.Fatalf("missing runner err = %v", err)
	}
}

func testKernelTUNPreflightFailsClosedAndRecordsEvidenceScope(t *testing.T) {
	original := probeKernelTUN
	t.Cleanup(func() { probeKernelTUN = original })

	probeKernelTUN = func(context.Context) kernelTUNGateResult {
		result := passingKernelTUNGateResult()
		result.Positive.Available = false
		result.Positive.Reason = string(virtualif.ReasonTUNPermissionDenied)
		result.Positive.Stage = "tun open"
		result.Positive.Detail = "permission denied"
		result.Positive.DeviceOpened = false
		result.Positive.InterfaceCreated = false
		result.Positive.KernelPacketRead = false
		result.Positive.KernelPacketWrite = false
		result.Positive.PacketIntegrity = false
		result.Positive.ReadBytes = 0
		result.Positive.WriteBytes = 0
		return result
	}
	rc := runManifestCase(context.Background(), "", caseDefs[0])
	if !strings.Contains(rc.InvalidReason, "cannot count as TUN release evidence") {
		t.Fatalf("unavailable preflight=%+v", rc)
	}
	if !strings.Contains(rc.InvalidReason, string(virtualif.ReasonTUNPermissionDenied)) {
		t.Fatalf("permission denial was not preserved: %+v", rc)
	}
	if rc.Evidence["kernel_tun_available"] != "false" || rc.Evidence["evidence_class"] != realKernelTUNPreflightClass ||
		rc.Evidence["kernel_tun_packet_io"] != "false" || rc.Evidence["kernel_tun_environment_gate_pass"] != "false" ||
		rc.Evidence["kernel_tun_gold"] != "false" {
		t.Fatalf("unavailable evidence=%v", rc.Evidence)
	}

	probeKernelTUN = func(context.Context) kernelTUNGateResult { return passingKernelTUNGateResult() }
	rc = runManifestCase(context.Background(), "", caseDefs[0])
	if rc.Failure != "" || rc.InvalidReason != "" || rc.SkipReason != "" {
		t.Fatalf("available preflight=%+v", rc)
	}
	if rc.Evidence["kernel_tun_available"] != "true" || rc.Evidence["kernel_tun_packet_io"] != "true" ||
		rc.Evidence["kernel_tun_environment_gate_pass"] != "true" || rc.Evidence["kernel_tun_negative_control_pass"] != "true" ||
		rc.Evidence["kernel_tun_fd_read_from_kernel"] != "true" || rc.Evidence["kernel_tun_fd_write_to_kernel"] != "true" ||
		rc.Evidence["kernel_tun_cleanup_verified"] != "true" ||
		rc.Evidence["required_gold_fixture"] != realTUNGoldFixture ||
		rc.Evidence["case_payload_via_kernel_tun"] != "false" || rc.Evidence["evidence_scope"] != "kernel_environment_only" {
		t.Fatalf("available evidence=%v", rc.Evidence)
	}
}

func TestKernelTUNGateRejectsMissingStimulusAndFalseGreenControls(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*kernelTUNGateResult)
		contains string
	}{
		{
			name: "missing kernel read",
			mutate: func(result *kernelTUNGateResult) {
				result.Positive.KernelPacketRead = false
			},
			contains: "kernel-emitted packet",
		},
		{
			name: "missing kernel write",
			mutate: func(result *kernelTUNGateResult) {
				result.Positive.KernelPacketWrite = false
			},
			contains: "kernel UDP socket",
		},
		{
			name: "cleanup not observed",
			mutate: func(result *kernelTUNGateResult) {
				result.Positive.CleanupVerified = false
			},
			contains: "deterministic interface cleanup",
		},
		{
			name: "negative control timed out",
			mutate: func(result *kernelTUNGateResult) {
				result.Negative.TimedOut = true
			},
			contains: "negative kernel TUN capability control exceeded",
		},
		{
			name: "capability drop not proved",
			mutate: func(result *kernelTUNGateResult) {
				result.Negative.CapabilitiesDropped = false
			},
			contains: "CAP_NET_ADMIN was absent",
		},
		{
			name: "negative control false green",
			mutate: func(result *kernelTUNGateResult) {
				result.Negative.Available = true
				result.Negative.Reason = ""
			},
			contains: "false-green",
		},
		{
			name: "generic unavailability is not permission denial",
			mutate: func(result *kernelTUNGateResult) {
				result.Negative.Reason = string(virtualif.ReasonTUNUnavailable)
			},
			contains: "did not observe permission denial",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := passingKernelTUNGateResult()
			tt.mutate(&result)
			if got := validateKernelTUNGate(result); !strings.Contains(got, tt.contains) {
				t.Fatalf("validateKernelTUNGate()=%q, want %q", got, tt.contains)
			}
		})
	}

	falseGreen := passingKernelTUNGateResult()
	falseGreen.Negative.Available = true
	falseGreen.Negative.Reason = ""
	evidence := kernelTUNGateEvidence(falseGreen)
	if evidence["kernel_tun_packet_io"] != "true" || evidence["kernel_tun_negative_control_pass"] != "false" ||
		evidence["kernel_tun_environment_gate_pass"] != "false" {
		t.Fatalf("false-green evidence=%v", evidence)
	}
}

func TestRunKernelTUNGateBoundsPositiveAndNegativeHelpers(t *testing.T) {
	original := executeKernelTUNProbe
	t.Cleanup(func() { executeKernelTUNProbe = original })

	var modes []string
	executeKernelTUNProbe = func(ctx context.Context, mode string) kernelTUNProbeResult {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Errorf("mode %q had no deadline", mode)
		}
		remaining := time.Until(deadline)
		limit := kernelTUNPositiveLimit
		if mode == kernelTUNProbeNegative {
			limit = kernelTUNNegativeLimit
		}
		if remaining <= 0 || remaining > limit {
			t.Errorf("mode %q remaining bound=%s, want (0,%s]", mode, remaining, limit)
		}
		modes = append(modes, mode)
		result := passingKernelTUNGateResult()
		if mode == kernelTUNProbePositive {
			return result.Positive
		}
		return result.Negative
	}

	result := runKernelTUNGate(context.Background())
	if want := []string{kernelTUNProbePositive, kernelTUNProbeNegative}; !reflect.DeepEqual(modes, want) {
		t.Fatalf("probe modes=%v, want %v", modes, want)
	}
	if invalid := validateKernelTUNGate(result); invalid != "" {
		t.Fatalf("bounded gate rejected: %s", invalid)
	}
}

func TestSyntheticRowsCannotClaimRealKernelTUNEvidence(t *testing.T) {
	def := syntheticCase("synthetic.evidence", time.Second, func(context.Context, string, manifest.Spec) report.Case {
		return report.Case{Evidence: map[string]string{
			"evidence_class":                   realKernelTUNPreflightClass,
			"kernel_tun_packet_io":             "true",
			"kernel_tun_fd_read_from_kernel":   "true",
			"kernel_tun_environment_gate_pass": "true",
			"kernel_tun_gold":                  "true",
			"case_payload_via_kernel_tun":      "true",
		}}
	})
	rc := runManifestCase(context.Background(), "", def)
	if rc.Evidence["evidence_class"] != syntheticEvidenceClass || rc.Evidence["kernel_tun_packet_io"] != "false" ||
		rc.Evidence["kernel_tun_gold"] != "false" || rc.Evidence["case_payload_via_kernel_tun"] != "false" ||
		rc.Evidence["evidence_scope"] != "synthetic_payload" {
		t.Fatalf("synthetic evidence escaped normalization: %v", rc.Evidence)
	}
	if _, ok := rc.Evidence["kernel_tun_fd_read_from_kernel"]; ok {
		t.Fatalf("synthetic evidence retained kernel packet claim: %v", rc.Evidence)
	}
	if _, ok := rc.Evidence["kernel_tun_environment_gate_pass"]; ok {
		t.Fatalf("synthetic evidence retained environment gate claim: %v", rc.Evidence)
	}
}

func TestKernelTUNHelperOutputRequiresMatchingStructuredIdentity(t *testing.T) {
	result := passingKernelTUNGateResult().Positive
	result.Schema = kernelTUNProbeSchema
	result.Mode = kernelTUNProbePositive
	result.Nonce = "expected"
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	output := []byte("unrelated output\n" + kernelTUNHelperLinePrefix + string(encoded) + "\n")
	if _, err := parseKernelTUNHelperOutput(output, kernelTUNProbePositive, "expected"); err != nil {
		t.Fatalf("valid structured output rejected: %v", err)
	}
	if _, err := parseKernelTUNHelperOutput(output, kernelTUNProbePositive, "wrong"); err == nil || !strings.Contains(err.Error(), "nonce mismatch") {
		t.Fatalf("nonce mismatch err=%v", err)
	}
	if _, err := parseKernelTUNHelperOutput(append(output, output...), kernelTUNProbePositive, "expected"); err == nil ||
		!strings.Contains(err.Error(), "multiple structured") {
		t.Fatalf("duplicate result err=%v", err)
	}
}

func TestKernelTUNHelperInvocationRequiresExactNonceAndMode(t *testing.T) {
	environment := map[string]string{
		kernelTUNHelperModeEnv:  kernelTUNProbeNegative,
		kernelTUNHelperNonceEnv: "expected",
	}
	getenv := func(key string) string { return environment[key] }
	mode, nonce, ok := kernelTUNHelperInvocation(
		[]string{"regress", kernelTUNHelperArgPrefix + "expected"},
		getenv,
	)
	if !ok || mode != kernelTUNProbeNegative || nonce != "expected" {
		t.Fatalf("valid helper invocation=(%q,%q,%t)", mode, nonce, ok)
	}
	for _, args := range [][]string{
		{"regress"},
		{"regress", kernelTUNHelperArgPrefix + "wrong"},
		{"regress", kernelTUNHelperArgPrefix + "expected", "extra"},
	} {
		if _, _, ok := kernelTUNHelperInvocation(args, getenv); ok {
			t.Fatalf("helper invocation accepted args=%v", args)
		}
	}
	environment[kernelTUNHelperModeEnv] = "unknown"
	if _, _, ok := kernelTUNHelperInvocation([]string{"regress", kernelTUNHelperArgPrefix + "expected"}, getenv); ok {
		t.Fatal("helper invocation accepted unknown mode")
	}
}

func TestLongRunAliasReportsEachSelectedExecutableMemberExactlyOnce(t *testing.T) {
	t.Run("aliases are separate immutable metadata", testAliasesAreSeparateImmutableMetadata)
	t.Run("kernel TUN preflight fails closed", testKernelTUNPreflightFailsClosedAndRecordsEvidenceScope)
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

func passingKernelTUNGateResult() kernelTUNGateResult {
	return kernelTUNGateResult{
		Positive: kernelTUNProbeResult{
			Completed:         true,
			Bounded:           true,
			Available:         true,
			Stage:             "complete",
			DeviceOpened:      true,
			InterfaceCreated:  true,
			InterfaceName:     "rendrg0",
			KernelPacketRead:  true,
			KernelPacketWrite: true,
			PacketIntegrity:   true,
			ReadBytes:         64,
			WriteBytes:        64,
			CleanupAttempted:  true,
			CleanupCloseOK:    true,
			CleanupVerified:   true,
		},
		Negative: kernelTUNProbeResult{
			Completed:           true,
			Bounded:             true,
			Available:           false,
			Reason:              string(virtualif.ReasonTUNPermissionDenied),
			Stage:               "probe-without-cap-net-admin",
			CapabilitiesDropped: true,
			CAPNetAdminPresent:  false,
		},
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

func reportIDs(cases []report.Case) []string {
	ids := make([]string, len(cases))
	for i, rc := range cases {
		ids[i] = rc.Name
	}
	return ids
}
