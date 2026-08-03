package tier5

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/FrankoonG/rendr/regress/internal/gotestjson"
	"github.com/FrankoonG/rendr/regress/internal/report"
)

func TestUnprivilegedProbeRequestsAreExactAndMandatory(t *testing.T) {
	wantIDs := []string{
		"T5.3-tcprepair-unprivileged",
		"T5.4-gvisor-unprivileged",
		"T5.5-tcprepair-gvisor-fallback-unprivileged",
		"T5.6-gvisor-packet-carrier-unprivileged",
	}
	if len(unprivilegedProbeDefs) != len(wantIDs) {
		t.Fatalf("probe definition count = %d, want %d", len(unprivilegedProbeDefs), len(wantIDs))
	}
	gotIDs := make([]string, 0, len(unprivilegedProbeDefs))
	for _, id := range wantIDs {
		probe, ok := unprivilegedProbeDefs[id]
		if !ok {
			t.Fatalf("missing probe definition for %q", id)
		}
		gotIDs = append(gotIDs, probe.caseID)
		request := probeGoTestRequest(filepath.Join("testdata", "rendr"), probe)
		if request.Package != probe.packageName {
			t.Errorf("%s package = %q, want %q", id, request.Package, probe.packageName)
		}
		pattern, err := regexp.Compile(request.Pattern)
		if err != nil {
			t.Fatalf("%s pattern is invalid: %v", id, err)
		}
		if !pattern.MatchString(probe.testName) {
			t.Errorf("%s pattern %q does not match %q", id, request.Pattern, probe.testName)
		}
		if pattern.MatchString(probe.testName+"Extra") || pattern.MatchString(probe.testName+"/subtest") {
			t.Errorf("%s pattern %q is not exact", id, request.Pattern)
		}
		if len(request.Expected) != 1 || request.Expected[0].Name != probe.testName || request.Expected[0].AllowSkip {
			t.Errorf("%s expectations = %+v, want one mandatory exact test", id, request.Expected)
		}
		if got, want := request.CommandPrefix, setprivCommandPrefix(); !reflect.DeepEqual(got, want) {
			t.Errorf("%s command prefix = %#v, want %#v", id, got, want)
		}
	}
	if !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Fatalf("probe IDs = %v, want %v", gotIDs, wantIDs)
	}
}

func TestUnprivilegedProbeContractsAreFactualAndTruthful(t *testing.T) {
	for caseID, probe := range unprivilegedProbeDefs {
		t.Run(caseID, func(t *testing.T) {
			evidence := validProbeEvidence(t, probe)
			if invalids := validateProbeEvidence(probe, evidence); len(invalids) != 0 {
				t.Fatalf("valid probe evidence rejected: %v", invalids)
			}
		})
	}

	fallback := unprivilegedProbeDefs["T5.5-tcprepair-gvisor-fallback-unprivileged"]
	if fallback.testName != "TestTier5TCPRepairFailureRequiresNegotiatedFallback" {
		t.Fatalf("T5.5 test name=%q does not describe the v1 fallback contract", fallback.testName)
	}
	if got := fallback.required["gvisor_involved"]; got != "false" {
		t.Fatalf("T5.5 gvisor_involved=%q, want false", got)
	}
	if got := fallback.required["kernel_tcp_to_gvisor_conversion"]; got != "false" {
		t.Fatalf("T5.5 kernel conversion evidence=%q, want false", got)
	}
}

func TestRunUnprivilegedGoTestMissingSetprivIsInvalid(t *testing.T) {
	original := tier5LookPath
	tier5LookPath = func(string) (string, error) { return "", errors.New("not found") }
	t.Cleanup(func() { tier5LookPath = original })

	probe := unprivilegedProbeDefs["T5.3-tcprepair-unprivileged"]
	rc := runUnprivilegedGoTest(context.Background(), "unused", probe)
	if rc.InvalidReason == "" || rc.SkipReason != "" || rc.Failure != "" {
		t.Fatalf("missing setpriv outcome=%+v, want invalid-only", rc)
	}
	if rc.Evidence["setpriv_available"] != "false" || rc.Evidence["prerequisite_valid"] != "false" {
		t.Fatalf("missing setpriv evidence=%v", rc.Evidence)
	}
}

func TestApplyProbeEvidenceRequiresStructuredFacts(t *testing.T) {
	probe := unprivilegedProbeDefs["T5.3-tcprepair-unprivileged"]
	tests := []struct {
		name        string
		result      gotestjson.Result
		wantInvalid string
	}{
		{
			name: "missing evidence",
			result: gotestjson.Result{Tests: []gotestjson.TestResult{{
				Name: probe.testName, Status: gotestjson.StatusPassed,
			}}},
			wantInvalid: "structured probe evidence is missing",
		},
		{
			name: "malformed evidence",
			result: gotestjson.Result{Tests: []gotestjson.TestResult{{
				Name: probe.testName, Status: gotestjson.StatusPassed,
				Output: tier5EvidenceMarker + "{not-json}\n",
			}}},
			wantInvalid: "malformed JSON",
		},
		{
			name: "duplicate evidence",
			result: gotestjson.Result{Tests: []gotestjson.TestResult{{
				Name: probe.testName, Status: gotestjson.StatusPassed,
				Output: tier5EvidenceMarker + "{}\n" + tier5EvidenceMarker + "{}\n",
			}}},
			wantInvalid: "count=2",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rc := goTestReportCase(probe.caseID, []string{probe.testName}, test.result)
			applyProbeEvidence(&rc, probe, test.result)
			if !strings.Contains(rc.InvalidReason, test.wantInvalid) || rc.SkipReason != "" {
				t.Fatalf("outcome=%+v, want invalid containing %q", rc, test.wantInvalid)
			}
		})
	}
}

func TestApplyProbeEvidenceMergesValidatedFacts(t *testing.T) {
	probe := unprivilegedProbeDefs["T5.3-tcprepair-unprivileged"]
	evidence := validProbeEvidence(t, probe)
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	result := gotestjson.Result{Tests: []gotestjson.TestResult{{
		Name:   probe.testName,
		Status: gotestjson.StatusPassed,
		Output: "    probe_test.go:1: " + tier5EvidenceMarker + string(encoded) + "\n",
	}}}
	rc := goTestReportCase(probe.caseID, []string{probe.testName}, result)
	applyProbeEvidence(&rc, probe, result)
	if rc.Failure != "" || rc.InvalidReason != "" || rc.SkipReason != "" {
		t.Fatalf("valid structured evidence failed: %+v", rc)
	}
	if rc.Evidence["cap_eff"] != "0x0000000000000000" || rc.Evidence["setpriv_requested"] != "true" {
		t.Fatalf("merged evidence=%v", rc.Evidence)
	}
}

func TestProbeEvidenceRejectsInvalidCapabilityAndFallbackClaims(t *testing.T) {
	t.Run("CAP_NET_ADMIN retained", func(t *testing.T) {
		probe := unprivilegedProbeDefs["T5.3-tcprepair-unprivileged"]
		evidence := validProbeEvidence(t, probe)
		evidence["cap_eff"] = "0x0000000000001000"
		invalids := strings.Join(validateProbeEvidence(probe, evidence), "\n")
		if !strings.Contains(invalids, "retains CAP_NET_ADMIN") {
			t.Fatalf("invalids=%q, want retained capability", invalids)
		}
	})

	t.Run("capability prerequisite missing", func(t *testing.T) {
		probe := unprivilegedProbeDefs["T5.4-gvisor-unprivileged"]
		evidence := validProbeEvidence(t, probe)
		evidence["prerequisite_valid"] = "false"
		evidence["prerequisite_error"] = "capability status unavailable"
		invalids := strings.Join(validateProbeEvidence(probe, evidence), "\n")
		if !strings.Contains(invalids, "mandatory capability prerequisite invalid") {
			t.Fatalf("invalids=%q, want prerequisite invalid", invalids)
		}
	})

	t.Run("kernel TCP to gVisor claim", func(t *testing.T) {
		probe := unprivilegedProbeDefs["T5.5-tcprepair-gvisor-fallback-unprivileged"]
		evidence := validProbeEvidence(t, probe)
		evidence["gvisor_involved"] = "true"
		evidence["kernel_tcp_to_gvisor_conversion"] = "true"
		invalids := strings.Join(validateProbeEvidence(probe, evidence), "\n")
		if !strings.Contains(invalids, "gvisor_involved") || !strings.Contains(invalids, "kernel_tcp_to_gvisor_conversion") {
			t.Fatalf("invalids=%q, want conversion claim rejected", invalids)
		}
	})

	t.Run("unproven fallback", func(t *testing.T) {
		probe := unprivilegedProbeDefs["T5.5-tcprepair-gvisor-fallback-unprivileged"]
		evidence := validProbeEvidence(t, probe)
		evidence["fallback_outcome"] = "not_attempted"
		invalids := strings.Join(validateProbeEvidence(probe, evidence), "\n")
		if !strings.Contains(invalids, "neither factual redial/attach nor a typed planning failure") {
			t.Fatalf("invalids=%q, want unproven fallback rejected", invalids)
		}
	})
}

func TestProbeEvidenceAcceptsPreciseTypedFallbackFailure(t *testing.T) {
	probe := unprivilegedProbeDefs["T5.5-tcprepair-gvisor-fallback-unprivileged"]
	evidence := validProbeEvidence(t, probe)
	evidence["fallback_outcome"] = "typed_failure"
	evidence["attach_negotiation"] = "typed_failure"
	evidence["fallback_selection"] = "product_typed_planning_failure"
	evidence["leaf_mobility"] = "not_selected"
	evidence["original_socket_usable_after_typed_failure"] = "true"
	evidence["product_mobility_plan_observable"] = "true"
	evidence["typed_failure_stage"] = "mobility_planning"
	evidence["typed_failure_observed"] = "true"
	evidence["typed_failure_code"] = "peer_fallback_unsupported"
	if invalids := validateProbeEvidence(probe, evidence); len(invalids) != 0 {
		t.Fatalf("precise typed failure rejected: %v", invalids)
	}

	delete(evidence, "typed_failure_code")
	invalids := strings.Join(validateProbeEvidence(probe, evidence), "\n")
	if !strings.Contains(invalids, "typed_failure_code") {
		t.Fatalf("untyped failure invalids=%q, want missing code", invalids)
	}
}

func TestManualRedialAttachEvidenceFailsProductContract(t *testing.T) {
	probe := unprivilegedProbeDefs["T5.5-tcprepair-gvisor-fallback-unprivileged"]
	evidence := validProbeEvidence(t, probe)
	evidence["fallback_outcome"] = "manual_same_session_redial_attach"
	evidence["fallback_selection"] = "regression_orchestrated_after_failure"
	evidence["product_mobility_plan_observable"] = "false"
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	result := gotestjson.Result{Tests: []gotestjson.TestResult{{
		Name:   probe.testName,
		Status: gotestjson.StatusPassed,
		Output: tier5EvidenceMarker + string(encoded) + "\n",
	}}}
	rc := goTestReportCase(probe.caseID, []string{probe.testName}, result)
	applyProbeEvidence(&rc, probe, result)
	if rc.InvalidReason != "" || rc.SkipReason != "" {
		t.Fatalf("manual fallback evidence should be factual, got %+v", rc)
	}
	if !strings.Contains(rc.Failure, "product exposes no negotiated mobility plan") {
		t.Fatalf("manual fallback outcome=%+v, want product contract failure", rc)
	}
}

func TestMandatoryProbeSkipBecomesInvalid(t *testing.T) {
	probe := unprivilegedProbeDefs["T5.3-tcprepair-unprivileged"]
	evidence := validProbeEvidence(t, probe)
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	result := gotestjson.Result{Tests: []gotestjson.TestResult{{
		Name:   probe.testName,
		Status: gotestjson.StatusSkipped,
		Output: tier5EvidenceMarker + string(encoded) + "\n",
	}}}
	rc := goTestReportCase(probe.caseID, []string{probe.testName}, result)
	applyProbeEvidence(&rc, probe, result)
	if rc.InvalidReason == "" || rc.SkipReason != "" {
		t.Fatalf("mandatory probe skip outcome=%+v, want invalid", rc)
	}
}

func TestT5JSONContractRejectsZeroAndSkippedTests(t *testing.T) {
	const name = "TestExpected"
	tests := []struct {
		name   string
		stream string
	}{
		{name: "zero tests", stream: ""},
		{
			name: "mandatory skip",
			stream: "{\"Action\":\"run\",\"Test\":\"TestExpected\"}\n" +
				"{\"Action\":\"skip\",\"Test\":\"TestExpected\"}\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := gotestjson.Parse(
				strings.NewReader(test.stream),
				[]gotestjson.Expectation{{Name: name}},
			)
			if err == nil {
				t.Fatal("invalid go test stream passed JSON validation")
			}
			suite := report.New()
			suite.Add(goTestReportCase("T5.synthetic", []string{name}, result))
			if !suite.AnyFailed() {
				t.Fatalf("invalid go test stream passed T5 report gate: %+v", suite.Cases)
			}
		})
	}
}

func TestGoTestReportCaseFailsClosed(t *testing.T) {
	const name = "TestExpected"
	tests := []struct {
		name      string
		result    gotestjson.Result
		wantField string
		wantText  string
	}{
		{
			name: "zero tests",
			result: gotestjson.Result{
				Tests:  []gotestjson.TestResult{{Name: name, Status: gotestjson.StatusNotRun}},
				Issues: []gotestjson.Issue{{Code: gotestjson.IssueZeroTests, Detail: "no top-level tests ran"}},
			},
			wantField: "invalid",
			wantText:  string(gotestjson.IssueZeroTests),
		},
		{
			name: "mandatory skip",
			result: gotestjson.Result{
				Tests:  []gotestjson.TestResult{{Name: name, Status: gotestjson.StatusSkipped, Output: "missing privilege\n"}},
				Issues: []gotestjson.Issue{{Code: gotestjson.IssueMandatorySkip, Test: name}},
			},
			wantField: "skip",
			wantText:  "mandatory top-level test",
		},
		{
			name: "malformed JSON",
			result: gotestjson.Result{
				Tests:  []gotestjson.TestResult{{Name: name, Status: gotestjson.StatusNotRun}},
				Issues: []gotestjson.Issue{{Code: gotestjson.IssueMalformedJSON, Detail: "truncated object"}},
			},
			wantField: "invalid",
			wantText:  string(gotestjson.IssueMalformedJSON),
		},
		{
			name: "missing terminal event",
			result: gotestjson.Result{
				Tests:  []gotestjson.TestResult{{Name: name, Status: gotestjson.StatusIncomplete}},
				Issues: []gotestjson.Issue{{Code: gotestjson.IssueNoTerminal, Test: name}},
			},
			wantField: "invalid",
			wantText:  string(gotestjson.IssueNoTerminal),
		},
		{
			name: "unexpected top-level test",
			result: gotestjson.Result{
				Tests:  []gotestjson.TestResult{{Name: name, Status: gotestjson.StatusPassed}},
				Issues: []gotestjson.Issue{{Code: gotestjson.IssueUnexpectedTest, Test: "TestOther"}},
			},
			wantField: "invalid",
			wantText:  string(gotestjson.IssueUnexpectedTest),
		},
		{
			name: "bounded capture truncated",
			result: gotestjson.Result{
				Tests:            []gotestjson.TestResult{{Name: name, Status: gotestjson.StatusIncomplete}},
				CaptureTruncated: true,
				Issues:           []gotestjson.Issue{{Code: gotestjson.IssueCaptureLimit}},
			},
			wantField: "invalid",
			wantText:  string(gotestjson.IssueCaptureLimit),
		},
		{
			name: "test failure",
			result: gotestjson.Result{
				Tests:  []gotestjson.TestResult{{Name: name, Status: gotestjson.StatusFailed, Output: "assertion failed\n"}},
				Issues: []gotestjson.Issue{{Code: gotestjson.IssueTestFailed, Test: name}},
			},
			wantField: "failure",
			wantText:  "assertion failed",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rc := goTestReportCase("T5.synthetic", []string{name}, test.result)
			if rc.Failure == "" && rc.InvalidReason == "" && rc.SkipReason == "" {
				t.Fatalf("invalid go test result passed: %+v", rc)
			}
			var got string
			switch test.wantField {
			case "failure":
				got = rc.Failure
			case "invalid":
				got = rc.InvalidReason
			case "skip":
				got = rc.SkipReason
			default:
				t.Fatalf("unknown field %q", test.wantField)
			}
			if !strings.Contains(got, test.wantText) {
				t.Fatalf("%s diagnostic = %q, want substring %q", test.wantField, got, test.wantText)
			}
		})
	}
}

func TestGoTestReportCaseRecordsPassEvidence(t *testing.T) {
	const name = "TestExpected"
	result := gotestjson.Result{
		Tests:   []gotestjson.TestResult{{Name: name, Status: gotestjson.StatusPassed}},
		Command: []string{"setpriv", "go", "test", "-json"},
	}
	rc := goTestReportCase("T5.synthetic", []string{name}, result)
	if rc.Failure != "" || rc.InvalidReason != "" || rc.SkipReason != "" {
		t.Fatalf("passing result failed: %+v", rc)
	}
	want := map[string]string{
		"command":            `"setpriv" "go" "test" "-json"`,
		"expected_tests":     name,
		"observed_tests":     name + "=pass",
		"issue_codes":        "none",
		"capture_truncated":  "false",
		"json_validation_ok": "true",
	}
	if !reflect.DeepEqual(rc.Evidence, want) {
		t.Fatalf("evidence = %#v, want %#v", rc.Evidence, want)
	}
}

func TestGoTestReportDiagnosticIsBounded(t *testing.T) {
	const name = "TestExpected"
	result := gotestjson.Result{
		Tests: []gotestjson.TestResult{{
			Name:   name,
			Status: gotestjson.StatusIncomplete,
			Output: strings.Repeat("x", 2*maxReportDiagnosticBytes),
		}},
		Issues: []gotestjson.Issue{{Code: gotestjson.IssueNoTerminal, Test: name}},
	}
	rc := goTestReportCase("T5.synthetic", []string{name}, result)
	if len(rc.InvalidReason) > maxReportDiagnosticBytes {
		t.Fatalf("invalid diagnostic length = %d, max %d", len(rc.InvalidReason), maxReportDiagnosticBytes)
	}
	if !strings.Contains(rc.InvalidReason, "diagnostic truncated") {
		t.Fatalf("bounded diagnostic lacks truncation marker: %q", rc.InvalidReason)
	}
}

func validProbeEvidence(t *testing.T, probe goTestProbe) map[string]string {
	t.Helper()
	evidence := map[string]string{
		"schema":                           tier5EvidenceSchema,
		"case_id":                          probe.caseID,
		"goos":                             "linux",
		"euid":                             "65534",
		"capability_source":                "proc_self_status",
		"prerequisite_valid":               "true",
		"cap_net_admin_absent":             "true",
		"setpriv_capability_drop_observed": "true",
		"cap_inh":                          "0x0000000000000000",
		"cap_prm":                          "0x0000000000000000",
		"cap_eff":                          "0x0000000000000000",
		"cap_bnd":                          "0x0000000000000000",
		"cap_amb":                          "0x0000000000000000",
		"preflight_error_mentions_gvisor":  "true",
		"preflight_error_typed_eperm":      "false",
		"prepare_error_typed_eperm":        "true",
		"requested_migrations":             "2",
		"migration_calls_fired":            "2",
		"migrations_observed":              "2",
		"fallback_outcome":                 "negotiated_same_session_redial_attach",
		"attach_negotiation":               "bridge_tag_existing_flow",
		"fallback_selection":               "product_negotiated_before_data",
		"leaf_mobility":                    "redial_attach",
		"post_fallback_payload_ok":         "true",
		"product_mobility_plan_observable": "true",
		"same_session_flow_id_stable":      "true",
		"typed_failure_observed":           "false",
		"factory_dials":                    "2",
		"client_path_count":                "2",
		"server_path_count":                "2",
		"listener_flow_count":              "1",
		"migration_count_delta":            "1",
	}
	for key, value := range probe.required {
		evidence[key] = value
	}
	for _, key := range probe.requiredKeys {
		if evidence[key] == "" {
			evidence[key] = "present"
		}
	}
	return evidence
}
