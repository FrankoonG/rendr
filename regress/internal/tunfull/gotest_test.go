package tunfull

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/gotestjson"
)

func testRunT3XrayMatrixUsesExactStrictGoTestContract(t *testing.T) {
	original := executeTUNGoTest
	t.Cleanup(func() { executeTUNGoTest = original })
	executeTUNGoTest = func(_ context.Context, request gotestjson.Request) (gotestjson.Result, error) {
		if request.Package != "./internal/matrix" || request.TestTimeout != 10*time.Minute {
			t.Fatalf("request=%+v", request)
		}
		if len(request.Expected) != len(tunXrayExpectedTests) {
			t.Fatalf("expectations=%d want %d", len(request.Expected), len(tunXrayExpectedTests))
		}
		pattern, err := regexp.Compile(request.Pattern)
		if err != nil {
			t.Fatal(err)
		}
		for i, want := range tunXrayExpectedTests {
			if request.Expected[i].Name != want || request.Expected[i].AllowSkip || !pattern.MatchString(want) {
				t.Fatalf("expectation[%d]=%+v pattern=%q", i, request.Expected[i], request.Pattern)
			}
		}
		if pattern.MatchString("TestTUNT3Unexpected") || pattern.MatchString("TestTUNT3FreedomStreamOverTUN/subtest") {
			t.Fatalf("pattern %q is not exact", request.Pattern)
		}
		return passingTUNGoTestResult(), nil
	}

	rc := runT3XrayMatrix(context.Background(), t.TempDir(), caseT3XrayMatrix)
	if rc.Failure != "" || rc.InvalidReason != "" || rc.SkipReason != "" {
		t.Fatalf("strict matrix result=%+v", rc)
	}
	if rc.Evidence["expected_top_level_tests"] != "14" || rc.Evidence["passed_top_level_tests"] != "14" {
		t.Fatalf("evidence=%v", rc.Evidence)
	}
}

func testTUNGoTestReportRejectsFalseGreenStreams(t *testing.T) {
	tests := []struct {
		name     string
		result   gotestjson.Result
		runErr   error
		field    func(gotestjsonResultCase) string
		contains string
	}{
		{
			name:   "zero tests",
			result: gotestjson.Result{Tests: notRunTUNGoTests(), Issues: []gotestjson.Issue{{Code: gotestjson.IssueZeroTests, Detail: "none ran"}}},
			field:  func(c gotestjsonResultCase) string { return c.invalid }, contains: "zero_tests",
		},
		{
			name:   "mandatory skip",
			result: skippedTUNGoTestResult(),
			field:  func(c gotestjsonResultCase) string { return c.skip }, contains: "mandatory",
		},
		{
			name:   "malformed json",
			result: resultWithIssue(gotestjson.IssueMalformedJSON),
			field:  func(c gotestjsonResultCase) string { return c.invalid }, contains: "malformed_json",
		},
		{
			name:   "truncated stream",
			result: func() gotestjson.Result { r := passingTUNGoTestResult(); r.CaptureTruncated = true; return r }(),
			field:  func(c gotestjsonResultCase) string { return c.invalid }, contains: "capture was truncated",
		},
		{
			name:   "test failure",
			result: failedTUNGoTestResult(),
			field:  func(c gotestjsonResultCase) string { return c.failure }, contains: "test_failed",
		},
		{
			name:   "unclassified executor error",
			result: passingTUNGoTestResult(), runErr: errors.New("executor boom"),
			field: func(c gotestjsonResultCase) string { return c.invalid }, contains: "unclassified error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := tunGoTestReportCase(caseT3XrayMatrix, tunXrayExpectedTests, tt.result, tt.runErr, time.Second)
			got := tt.field(gotestjsonResultCase{failure: rc.Failure, invalid: rc.InvalidReason, skip: rc.SkipReason})
			if !strings.Contains(got, tt.contains) {
				t.Fatalf("result=%+v want %q in %q", rc, tt.contains, got)
			}
		})
	}
}

type gotestjsonResultCase struct {
	failure string
	invalid string
	skip    string
}

func passingTUNGoTestResult() gotestjson.Result {
	results := make([]gotestjson.TestResult, len(tunXrayExpectedTests))
	for i, name := range tunXrayExpectedTests {
		results[i] = gotestjson.TestResult{Name: name, Status: gotestjson.StatusPassed, Duration: time.Millisecond}
	}
	return gotestjson.Result{Tests: results, Duration: time.Duration(len(results)) * time.Millisecond}
}

func notRunTUNGoTests() []gotestjson.TestResult {
	results := make([]gotestjson.TestResult, len(tunXrayExpectedTests))
	for i, name := range tunXrayExpectedTests {
		results[i] = gotestjson.TestResult{Name: name, Status: gotestjson.StatusNotRun}
	}
	return results
}

func skippedTUNGoTestResult() gotestjson.Result {
	result := passingTUNGoTestResult()
	result.Tests[0].Status = gotestjson.StatusSkipped
	result.Issues = []gotestjson.Issue{{Code: gotestjson.IssueMandatorySkip, Test: result.Tests[0].Name, Detail: "mandatory top-level test skipped"}}
	return result
}

func failedTUNGoTestResult() gotestjson.Result {
	result := passingTUNGoTestResult()
	result.Tests[0].Status = gotestjson.StatusFailed
	result.Issues = []gotestjson.Issue{{Code: gotestjson.IssueTestFailed, Test: result.Tests[0].Name, Detail: "top-level test failed"}}
	return result
}

func resultWithIssue(code gotestjson.IssueCode) gotestjson.Result {
	result := passingTUNGoTestResult()
	result.Issues = []gotestjson.Issue{{Code: code, Detail: "synthetic parser failure"}}
	return result
}
