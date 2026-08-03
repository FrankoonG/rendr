package tier5

import (
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
