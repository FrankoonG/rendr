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

	missingRunner := caseDef{spec: tunSpec("synthetic.missing-runner", time.Second, false)}
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
