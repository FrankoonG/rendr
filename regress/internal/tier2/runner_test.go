package tier2

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/caseexec"
	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/report"
	"github.com/FrankoonG/rendr/regress/internal/smoke"
)

var orderedCaseIDs = []string{
	"G1-smoke",
	"G1-mixed-tcp-quic-smoke",
	"G2-smoke",
	"G2-race-tcp-smoke",
	"G2-bond-tcp-smoke",
	"G3-smoke",
	"G4",
	"G5",
	"M11-udp-relay-smoke",
	"M11-udp-relay-porthop-smoke",
}

func TestSpecsOrder(t *testing.T) {
	specs := Specs()
	got := make([]string, len(specs))
	for i, spec := range specs {
		got[i] = spec.ID
		if spec.Contract == nil {
			t.Errorf("spec %q has no schema-v3 contract", spec.ID)
			continue
		}
		if err := spec.Contract.Validate(); err != nil {
			t.Errorf("spec %q contract: %v", spec.ID, err)
		}
		for _, item := range []struct {
			dimension manifest.ContractDimension
			profile   manifest.EvidenceProfile
		}{
			{manifest.ContractDimensionStimulus, spec.Contract.Stimulus},
			{manifest.ContractDimensionOracle, spec.Contract.Oracle},
		} {
			if !contractMissing(spec, item.dimension) && len(item.profile.Assertions) == 0 {
				t.Errorf("spec %q %s profile has no typed assertion", spec.ID, item.dimension)
			}
		}
	}
	if !reflect.DeepEqual(got, orderedCaseIDs) {
		t.Fatalf("Specs IDs = %v, want %v", got, orderedCaseIDs)
	}
	if err := manifest.ValidateCensus(specs); err != nil {
		t.Fatalf("ValidateCensus(Specs()) = %v", err)
	}

	originalRequires := caseDefs[1].spec.Requires
	caseDefs[1].spec.Requires = []string{caseDefs[0].spec.ID}
	t.Cleanup(func() { caseDefs[1].spec.Requires = originalRequires })
	copied := Specs()
	copied[1].Requires[0] = "mutated"
	if got, want := caseDefs[1].spec.Requires[0], caseDefs[0].spec.ID; got != want {
		t.Fatalf("Specs result mutated caseDefs prerequisite to %q, want %q", got, want)
	}

	contractCopy := Specs()
	contractCopy[0].Contract.Purpose = "mutated"
	contractCopy[0].Contract.MissingDimensions[0].Reason = "mutated"
	contractCopy[0].Contract.Topology.Roles[0] = "mutated"
	contractCopy[0].Contract.RoleCapabilities["client"] = append(contractCopy[0].Contract.RoleCapabilities["client"], "mutated")
	contractCopy[0].Contract.Payload.Params[0].Value++
	contractCopy[0].Contract.Stimulus.RequiredFacts[0] = "mutated"
	contractCopy[0].Contract.Oracle.Assertions[0].Expected = "mutated"
	fresh := Specs()[0].Contract
	if fresh.Purpose == "mutated" || fresh.MissingDimensions[0].Reason == "mutated" || fresh.Topology.Roles[0] == "mutated" || len(fresh.RoleCapabilities["client"]) != 0 || fresh.Payload.Params[0].Value != 30<<20 || fresh.Stimulus.RequiredFacts[0] == "mutated" || fresh.Oracle.Assertions[0].Expected == "mutated" {
		t.Fatalf("Specs returned aliased T2 contract: %+v", fresh)
	}

	t.Run("weak cases remain truthfully blocked", func(t *testing.T) {
		byID := specsByID(specs)
		for _, id := range orderedCaseIDs {
			spec := byID[id]
			if spec.Contract.State != manifest.ContractStateBlocked {
				t.Errorf("spec %q state = %q, want blocked", id, spec.Contract.State)
			}
			if !contractMissing(spec, manifest.ContractDimensionNegativeControl) || !contractMissing(spec, manifest.ContractDimensionResources) {
				t.Errorf("spec %q must remain blocked on negative control and resources", id)
			}
		}
		g3 := byID["G3-smoke"]
		if !strings.Contains(g3.Contract.Purpose, "does not prove RFC 9000 CID or NAT rebinding") {
			t.Errorf("G3 purpose overclaims CID semantics: %q", g3.Contract.Purpose)
		}
		if got, ok := contractParam(g3.Contract.Payload, "body_bytes"); !ok || got != 1024 {
			t.Errorf("G3 body_bytes = %d, present=%t, want 1024", got, ok)
		}
		if got, ok := contractParam(g3.Contract.Payload, "application_record_bytes"); !ok || got != 1032 {
			t.Errorf("G3 application_record_bytes = %d, present=%t, want 1032", got, ok)
		}
		if _, ok := contractParam(g3.Contract.Load, "offered_pps"); ok {
			t.Errorf("G3 load still labels its configured target as offered_pps: %+v", g3.Contract.Load)
		}
		if got, ok := contractParam(g3.Contract.Load, "target_pps"); !ok || got != 5000 {
			t.Errorf("G3 target_pps = %d, present=%t, want 5000", got, ok)
		}
		wantG3Capabilities := []string{"Linux", "net.core.rmem_max >= 8388608 bytes"}
		for _, role := range []string{"client", "server"} {
			if got := g3.Contract.RoleCapabilities[role]; !reflect.DeepEqual(got, wantG3Capabilities) {
				t.Errorf("G3 %s capabilities = %v, want %v", role, got, wantG3Capabilities)
			}
		}
		if !hasContractAssertion(g3.Contract.Stimulus, "pps_sent", manifest.EvidenceFloatAtLeast, "4750") ||
			!hasContractAssertion(g3.Contract.Oracle, "loss_pct", manifest.EvidenceFloatAtMost, "0.5") ||
			!hasContractAssertion(g3.Contract.Oracle, "udp_snmp_status", manifest.EvidenceEquals, "ok") {
			t.Errorf("G3 typed load/oracle assertions are incomplete: stimulus=%+v oracle=%+v", g3.Contract.Stimulus, g3.Contract.Oracle)
		}
		for _, id := range []string{"G2-smoke", "G2-race-tcp-smoke", "G2-bond-tcp-smoke"} {
			g2 := byID[id]
			if _, ok := contractParam(g2.Contract.Load, "p99_ceiling_ns"); ok {
				t.Errorf("%s freezes a P99 ceiling despite an under-qualified sample population", id)
			}
			if !strings.Contains(g2.Contract.Purpose, "1,000-sample P99 qualification minimum") ||
				!hasContractAssertion(g2.Contract.Stimulus, "p99_qualified", manifest.EvidenceEquals, "false") ||
				containsContractString(g2.Contract.Oracle.RequiredFacts, "p99_qualified") ||
				!hasContractAssertion(g2.Contract.Oracle, "transport_lost_echoes", manifest.EvidenceEquals, "0") {
				t.Errorf("%s does not separate diagnostic P99 evidence from continuity predicates: %+v", id, g2.Contract)
			}
		}
		g4 := byID["G4"]
		if !strings.Contains(g4.Contract.Purpose, "ForceKillPathForTest") {
			t.Errorf("G4 purpose hides synthetic kill hook: %q", g4.Contract.Purpose)
		}
		porthop := byID["M11-udp-relay-porthop-smoke"]
		if !contractMissing(porthop, manifest.ContractDimensionPayload) || !contractMissing(porthop, manifest.ContractDimensionSeed) {
			t.Errorf("port-hop contract froze OS-assigned address payload or seed")
		}
	})
}

func specsByID(specs []manifest.Spec) map[string]manifest.Spec {
	byID := make(map[string]manifest.Spec, len(specs))
	for _, spec := range specs {
		byID[spec.ID] = spec
	}
	return byID
}

func contractMissing(spec manifest.Spec, dimension manifest.ContractDimension) bool {
	if spec.Contract == nil {
		return false
	}
	for _, missing := range spec.Contract.MissingDimensions {
		if missing.Dimension == dimension {
			return true
		}
	}
	return false
}

func contractParam(profile manifest.Profile, name string) (uint64, bool) {
	for _, parameter := range profile.Params {
		if parameter.Name == name {
			return parameter.Value, true
		}
	}
	return 0, false
}

func hasContractAssertion(profile manifest.EvidenceProfile, fact string, predicate manifest.EvidencePredicate, expected string) bool {
	for _, assertion := range profile.Assertions {
		if assertion.Fact == fact && assertion.Predicate == predicate && assertion.Expected == expected {
			return true
		}
	}
	return false
}

func containsContractString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func TestSpecsHaveBoundedBudgets(t *testing.T) {
	for _, spec := range Specs() {
		if spec.Budget <= 0 {
			t.Errorf("spec %q budget = %s, want > 0", spec.ID, spec.Budget)
		}
	}
}

func TestCriticalSmokeMigrationRequests(t *testing.T) {
	if g1SmokeMigrations <= 0 {
		t.Fatalf("G1-smoke migrations = %d, want > 0", g1SmokeMigrations)
	}
	if g2SmokeMigrations <= 0 {
		t.Fatalf("G2/G2-bond smoke migrations = %d, want > 0", g2SmokeMigrations)
	}
	if g2RaceSmokeMigrations != -1 {
		t.Fatalf("G2-race smoke migrations = %d, want explicit disable sentinel", g2RaceSmokeMigrations)
	}
}

func TestSelectCaseDefsExact(t *testing.T) {
	defs, err := selectCaseDefs(Options{Case: orderedCaseIDs[3]})
	if err != nil {
		t.Fatal(err)
	}
	if got := caseDefIDs(defs); !reflect.DeepEqual(got, orderedCaseIDs[3:4]) {
		t.Fatalf("selected IDs = %v, want %v", got, orderedCaseIDs[3:4])
	}

	prerequisite := manifest.RequiredWithBudget("synthetic-prerequisite", "T2", time.Second)
	target := manifest.RequiredWithBudget("synthetic-target", "T2", time.Second)
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
	defs, err := selectCaseDefs(Options{FromCase: orderedCaseIDs[7]})
	if err != nil {
		t.Fatal(err)
	}
	if got := caseDefIDs(defs); !reflect.DeepEqual(got, orderedCaseIDs[7:]) {
		t.Fatalf("selected IDs = %v, want %v", got, orderedCaseIDs[7:])
	}

	prerequisite := manifest.RequiredWithBudget("synthetic-prerequisite", "T2", time.Second)
	resume := manifest.RequiredWithBudget("synthetic-resume", "T2", time.Second)
	resume.Requires = []string{prerequisite.ID}
	target := manifest.RequiredWithBudget("synthetic-target", "T2", time.Second)
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
	RunWithOptions(context.Background(), suite, "", Options{FromCase: "missing"})
	if len(suite.Cases) != 1 {
		t.Fatalf("cases = %d, want 1", len(suite.Cases))
	}
	got := suite.Cases[0]
	if got.Name != "T2-case-filter" || got.Tier != "T2" || got.Failure != `manifest: no case matched --from-case="missing"` {
		t.Fatalf("failure row = %+v", got)
	}
}

func TestAddRunPreservesSmokeEvidence(t *testing.T) {
	suite := report.New()
	addRun(context.Background(), suite, "evidence", "T2", time.Second, func(context.Context) smoke.Result {
		return smoke.Result{
			Detail: map[string]any{
				"requested_migrations": 3,
				"migrations_done":      uint64(3),
				"sha256_match":         true,
			},
		}
	})
	want := map[string]string{
		"requested_migrations": "3",
		"migrations_done":      "3",
		"sha256_match":         "true",
	}
	if got := suite.Cases[0].Evidence; !reflect.DeepEqual(got, want) {
		t.Fatalf("evidence = %#v, want %#v", got, want)
	}
}

func TestAddRunPreservesInvalidSmokeOutcome(t *testing.T) {
	suite := report.New()
	addRun(context.Background(), suite, "invalid", "T2", time.Second, func(context.Context) smoke.Result {
		return smoke.Result{InvalidReason: "offered load below target"}
	})
	if got := suite.Cases[0]; got.InvalidReason != "offered load below target" || got.Failure != "" {
		t.Fatalf("case=%+v want invalid-only outcome", got)
	}
}

func TestAddRunCancelsAndJoinsWorkloadBeforeReporting(t *testing.T) {
	tests := []struct {
		name        string
		budget      time.Duration
		withCancel  bool
		wantFailure string
	}{
		{name: "deadline", budget: 5 * time.Millisecond, wantFailure: "exceeded T2 budget"},
		{name: "parent cancel", budget: time.Second, withCancel: true, wantFailure: "case canceled during T2 execution: context canceled"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			trigger := func() {}
			if tt.withCancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				trigger = cancel
				defer cancel()
			}

			suite := report.New()
			started := make(chan struct{})
			unwindStarted := make(chan struct{})
			allowUnwind := make(chan struct{})
			unwound := make(chan struct{})
			returned := make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(allowUnwind) }) }
			defer release()

			go func() {
				addRun(ctx, suite, "quiescence", "T2", tt.budget, func(ctx context.Context) smoke.Result {
					close(started)
					<-ctx.Done()
					close(unwindStarted)
					<-allowUnwind
					close(unwound)
					return smoke.Result{Detail: map[string]any{"late_success": true}}
				})
				close(returned)
			}()

			waitForSignal(t, started, "workload start")
			trigger()
			waitForSignal(t, unwindStarted, "cancellation")
			select {
			case <-returned:
				t.Fatal("addRun returned before the canceled workload unwound")
			case <-time.After(20 * time.Millisecond):
			}

			release()
			waitForSignal(t, returned, "addRun return after workload unwind")
			select {
			case <-unwound:
			default:
				t.Fatal("addRun returned without joining the workload")
			}
			if len(suite.Cases) != 1 {
				t.Fatalf("cases = %d, want 1", len(suite.Cases))
			}
			if got := suite.Cases[0].Failure; !strings.Contains(got, tt.wantFailure) {
				t.Fatalf("failure = %q, want %q despite late success", got, tt.wantFailure)
			}
		})
	}
}

func waitForSignal(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", name)
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
			defs := syntheticCaseDefs("T2")
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
			assertFailFastRows(t, suite.Cases, "T2")
		})
	}
}

func TestRunSelectedCasesBoundsUnjoinedWorkloadAndStopsTier(t *testing.T) {
	const (
		budget      = 20 * time.Millisecond
		joinTimeout = 30 * time.Millisecond
	)

	release := make(chan struct{})
	workerDone := make(chan struct{})
	var releaseOnce sync.Once
	releaseWorker := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseWorker)

	defs := syntheticCaseDefs("T2")
	defs[1].spec.Mandatory = false // MustStop, not mandatory failure, must halt the tier.
	var called []string
	suite := report.New()
	start := time.Now()
	runSelectedCases(context.Background(), suite, defs, func(ctx context.Context, def caseDef) caseexec.Outcome {
		called = append(called, def.spec.ID)
		if def.spec.ID != "synthetic.blocker" {
			return caseexec.Outcome{Case: report.Case{Name: def.spec.ID, Tier: def.spec.Tier}}
		}
		return runSmokeCaseWithJoinTimeout(ctx, def.spec.ID, def.spec.Tier, budget, joinTimeout, func(context.Context) smoke.Result {
			defer close(workerDone)
			<-release
			return smoke.Result{Detail: map[string]any{"late_success": true}}
		})
	})
	elapsed := time.Since(start)

	if want := []string{"synthetic.first", "synthetic.blocker"}; !reflect.DeepEqual(called, want) {
		t.Fatalf("executed cases = %v, want %v", called, want)
	}
	if elapsed > budget+joinTimeout+500*time.Millisecond {
		t.Fatalf("unjoined workload returned after %s, want budget %s plus join limit %s", elapsed, budget, joinTimeout)
	}
	if got := suite.Cases[1]; got.Failure != "" || !strings.Contains(got.InvalidReason, "did not return within cleanup join limit") {
		t.Fatalf("unjoined workload result = %+v, want INVALID-only outcome", got)
	}
	if got := suite.Cases[1].Evidence["timeout_cleanup"]; got != "unjoined" {
		t.Fatalf("timeout cleanup evidence = %q, want unjoined", got)
	}
	if got := suite.Cases[1].Evidence["timeout_join_limit"]; got != joinTimeout.String() {
		t.Fatalf("timeout join limit evidence = %q, want %q", got, joinTimeout)
	}
	assertFailFastRows(t, suite.Cases, "T2")

	releaseWorker()
	waitForSignal(t, workerDone, "released workload exit")
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

func caseDefIDs(defs []caseDef) []string {
	ids := make([]string, len(defs))
	for i, def := range defs {
		ids[i] = def.spec.ID
	}
	return ids
}
