package tier8

import (
	"regexp"
	"testing"

	"github.com/FrankoonG/rendr/regress/internal/gotestjson"
)

func TestCaseDefinitionsUseExactExpectedTests(t *testing.T) {
	for _, def := range caseDefs {
		if len(def.expected) == 0 {
			t.Fatalf("case %q has no expected tests", def.spec.ID)
		}
		pattern := regexp.MustCompile(exactTestPattern(def.expected))
		for i, name := range def.expected {
			if !pattern.MatchString(name) || pattern.MatchString(name+"Extra") || pattern.MatchString(name+"/subtest") {
				t.Errorf("case %q pattern is not exact for %q", def.spec.ID, name)
			}
			expectation := testExpectations(def.expected)[i]
			if expectation.Name != name || expectation.AllowSkip {
				t.Errorf("case %q expectation[%d]=%+v, want mandatory %q", def.spec.ID, i, expectation, name)
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
		status    gotestjson.Status
		issue     gotestjson.Issue
		truncated bool
		wantField string
	}{
		{"zero tests", gotestjson.StatusNotRun, gotestjson.Issue{Code: gotestjson.IssueZeroTests}, false, "invalid"},
		{"malformed JSON", gotestjson.StatusNotRun, gotestjson.Issue{Code: gotestjson.IssueMalformedJSON}, false, "invalid"},
		{"truncated capture", gotestjson.StatusIncomplete, gotestjson.Issue{Code: gotestjson.IssueCaptureLimit}, true, "invalid"},
		{"missing terminal", gotestjson.StatusIncomplete, gotestjson.Issue{Code: gotestjson.IssueNoTerminal, Test: name}, false, "invalid"},
		{"mandatory skip", gotestjson.StatusSkipped, gotestjson.Issue{Code: gotestjson.IssueMandatorySkip, Test: name}, false, "skip"},
		{"unexpected test", gotestjson.StatusPassed, gotestjson.Issue{Code: gotestjson.IssueUnexpectedTest, Test: "TestOther"}, false, "invalid"},
		{"command failure", gotestjson.StatusNotRun, gotestjson.Issue{Code: gotestjson.IssueCommandFailed}, false, "invalid"},
		{"test failure", gotestjson.StatusFailed, gotestjson.Issue{Code: gotestjson.IssueTestFailed, Test: name}, false, "failure"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := gotestjson.Result{
				Tests:            []gotestjson.TestResult{{Name: name, Status: tc.status}},
				Issues:           []gotestjson.Issue{tc.issue},
				CaptureTruncated: tc.truncated,
			}
			testCase := goTestReportCase("T8.synthetic", "T8", []string{name}, result)
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
