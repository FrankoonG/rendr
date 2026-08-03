package tier6

import (
	"regexp"
	"strings"
	"testing"

	"github.com/FrankoonG/rendr/regress/internal/gotestjson"
)

func TestCaseDefinitionsUseExactExpectedTests(t *testing.T) {
	for _, def := range caseDefs {
		if len(def.expected) == 0 {
			t.Fatalf("case %q has no expected tests", def.spec.ID)
		}
		pattern := regexp.MustCompile(exactTestPattern(def.expected))
		expectations := testExpectations(def.expected)
		for i, name := range def.expected {
			if !pattern.MatchString(name) {
				t.Errorf("case %q pattern does not match %q", def.spec.ID, name)
			}
			if pattern.MatchString(name+"Extra") || pattern.MatchString(name+"/subtest") {
				t.Errorf("case %q pattern is not exact for %q", def.spec.ID, name)
			}
			if expectations[i].Name != name || expectations[i].AllowSkip {
				t.Errorf("case %q expectation[%d]=%+v, want mandatory %q", def.spec.ID, i, expectations[i], name)
			}
		}
	}

	quoted := regexp.MustCompile(exactTestPattern([]string{"TestMeta[1]+"}))
	if !quoted.MatchString("TestMeta[1]+") || quoted.MatchString("TestMeta1") {
		t.Fatalf("metacharacter test name was not quoted: %q", quoted.String())
	}
}

func TestGoTestReportCaseFailsClosed(t *testing.T) {
	const name = "TestExpected"
	tests := []struct {
		name      string
		result    gotestjson.Result
		wantField string
	}{
		{
			name: "zero tests",
			result: gotestjson.Result{
				Tests:  []gotestjson.TestResult{{Name: name, Status: gotestjson.StatusNotRun}},
				Issues: []gotestjson.Issue{{Code: gotestjson.IssueZeroTests}},
			},
			wantField: "invalid",
		},
		{
			name: "malformed JSON",
			result: gotestjson.Result{
				Tests:  []gotestjson.TestResult{{Name: name, Status: gotestjson.StatusNotRun}},
				Issues: []gotestjson.Issue{{Code: gotestjson.IssueMalformedJSON}},
			},
			wantField: "invalid",
		},
		{
			name: "truncated capture",
			result: gotestjson.Result{
				Tests:            []gotestjson.TestResult{{Name: name, Status: gotestjson.StatusIncomplete}},
				CaptureTruncated: true,
				Issues:           []gotestjson.Issue{{Code: gotestjson.IssueCaptureLimit}},
			},
			wantField: "invalid",
		},
		{
			name: "missing terminal",
			result: gotestjson.Result{
				Tests:  []gotestjson.TestResult{{Name: name, Status: gotestjson.StatusIncomplete}},
				Issues: []gotestjson.Issue{{Code: gotestjson.IssueNoTerminal, Test: name}},
			},
			wantField: "invalid",
		},
		{
			name: "mandatory skip",
			result: gotestjson.Result{
				Tests:  []gotestjson.TestResult{{Name: name, Status: gotestjson.StatusSkipped}},
				Issues: []gotestjson.Issue{{Code: gotestjson.IssueMandatorySkip, Test: name}},
			},
			wantField: "skip",
		},
		{
			name: "unexpected test",
			result: gotestjson.Result{
				Tests:  []gotestjson.TestResult{{Name: name, Status: gotestjson.StatusPassed}},
				Issues: []gotestjson.Issue{{Code: gotestjson.IssueUnexpectedTest, Test: "TestOther"}},
			},
			wantField: "invalid",
		},
		{
			name: "command failure",
			result: gotestjson.Result{
				Tests:  []gotestjson.TestResult{{Name: name, Status: gotestjson.StatusNotRun}},
				Issues: []gotestjson.Issue{{Code: gotestjson.IssueCommandFailed}},
			},
			wantField: "invalid",
		},
		{
			name: "test failure",
			result: gotestjson.Result{
				Tests:  []gotestjson.TestResult{{Name: name, Status: gotestjson.StatusFailed}},
				Issues: []gotestjson.Issue{{Code: gotestjson.IssueTestFailed, Test: name}},
			},
			wantField: "failure",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testCase := goTestReportCase("T6.synthetic", "T6", []string{name}, tc.result)
			if testCase.Failure == "" && testCase.InvalidReason == "" && testCase.SkipReason == "" {
				t.Fatalf("case unexpectedly passed: %+v", testCase)
			}
			switch tc.wantField {
			case "failure":
				if testCase.Failure == "" {
					t.Fatalf("case has no failure: %+v", testCase)
				}
			case "invalid":
				if testCase.InvalidReason == "" {
					t.Fatalf("case has no invalid reason: %+v", testCase)
				}
			case "skip":
				if testCase.SkipReason == "" {
					t.Fatalf("case has no mandatory skip: %+v", testCase)
				}
			}
		})
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
	testCase := goTestReportCase("T6.synthetic", "T6", []string{name}, result)
	if len(testCase.InvalidReason) > maxReportDiagnosticBytes {
		t.Fatalf("invalid diagnostic length=%d, max=%d", len(testCase.InvalidReason), maxReportDiagnosticBytes)
	}
	if !strings.Contains(testCase.InvalidReason, "diagnostic truncated") {
		t.Fatalf("bounded diagnostic lacks truncation marker")
	}
}
