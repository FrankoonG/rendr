package tier7

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/FrankoonG/rendr/regress/internal/gotestjson"
	"github.com/FrankoonG/rendr/regress/internal/report"
)

const maxReportDiagnosticBytes = 16 << 10

var tier7GoTestExecutor = gotestjson.Executor{
	Parser: gotestjson.Parser{MaxOutputBytes: maxReportDiagnosticBytes},
}

func exactTestPattern(names []string) string {
	quoted := make([]string, len(names))
	for i, name := range names {
		quoted[i] = regexp.QuoteMeta(name)
	}
	return "^(?:" + strings.Join(quoted, "|") + ")$"
}

func testExpectations(names []string) []gotestjson.Expectation {
	expected := make([]gotestjson.Expectation, len(names))
	for i, name := range names {
		expected[i] = gotestjson.Expectation{Name: name}
	}
	return expected
}

func goTestReportCase(caseName, tier string, expected []string, result gotestjson.Result) report.Case {
	rc := report.Case{Name: caseName, Tier: tier, Duration: result.Duration}
	results := make(map[string]gotestjson.TestResult, len(result.Tests))
	expectedSet := make(map[string]bool, len(expected))
	for _, name := range expected {
		expectedSet[name] = true
	}

	var failures, skips, invalids []string
	for _, testResult := range result.Tests {
		if !expectedSet[testResult.Name] {
			invalids = append(invalids, fmt.Sprintf("unexpected parsed test result %q", testResult.Name))
			continue
		}
		if _, exists := results[testResult.Name]; exists {
			invalids = append(invalids, fmt.Sprintf("duplicate parsed test result %q", testResult.Name))
			continue
		}
		results[testResult.Name] = testResult
	}

	issues := append([]gotestjson.Issue(nil), result.Issues...)
	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].Code != issues[j].Code {
			return issues[i].Code < issues[j].Code
		}
		if issues[i].Test != issues[j].Test {
			return issues[i].Test < issues[j].Test
		}
		return issues[i].Detail < issues[j].Detail
	})
	for _, issue := range issues {
		testResult, known := results[issue.Test]
		switch issue.Code {
		case gotestjson.IssueTestFailed:
			if !known || testResult.Status != gotestjson.StatusFailed {
				failures = append(failures, issue.String())
			}
		case gotestjson.IssueMandatorySkip:
			if !known || testResult.Status != gotestjson.StatusSkipped {
				skips = append(skips, issue.String())
			}
		default:
			invalids = append(invalids, issue.String())
		}
	}

	for _, name := range expected {
		testResult, ok := results[name]
		if !ok {
			invalids = append(invalids, fmt.Sprintf("expected top-level test %q has no parsed result", name))
			continue
		}
		switch testResult.Status {
		case gotestjson.StatusPassed:
		case gotestjson.StatusFailed:
			failures = append(failures, testOutputDiagnostic("top-level test "+name+" failed", testResult))
		case gotestjson.StatusSkipped:
			skips = append(skips, testOutputDiagnostic("mandatory top-level test "+name+" skipped", testResult))
		case gotestjson.StatusNotRun:
			invalids = append(invalids, fmt.Sprintf("expected top-level test %q did not run", name))
		case gotestjson.StatusIncomplete:
			invalids = append(invalids, testOutputDiagnostic("top-level test "+name+" has no terminal event", testResult))
		default:
			invalids = append(invalids, fmt.Sprintf("top-level test %q has unknown status %q", name, testResult.Status))
		}
	}

	if result.CaptureTruncated && !result.HasIssue(gotestjson.IssueCaptureLimit) {
		invalids = append(invalids, "go test JSON capture was truncated")
	}
	if len(invalids) != 0 && strings.TrimSpace(result.CommandOutput) != "" {
		invalids = append(invalids, outputDiagnostic("go test command output", result.CommandOutput, result.CommandOutputTruncated))
	}
	rc.Failure = boundedDiagnostic(failures)
	rc.SkipReason = boundedDiagnostic(skips)
	rc.InvalidReason = boundedDiagnostic(invalids)
	return rc
}

func testOutputDiagnostic(prefix string, result gotestjson.TestResult) string {
	return outputDiagnostic(prefix, result.Output, result.OutputTruncated)
}

func outputDiagnostic(prefix, output string, truncated bool) string {
	output = strings.TrimSpace(output)
	if output != "" {
		prefix += ":\n" + output
	}
	if truncated {
		prefix += "\n[output truncated]"
	}
	return prefix
}

func boundedDiagnostic(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	value := strings.ToValidUTF8(strings.Join(parts, "\n"), "?")
	if len(value) <= maxReportDiagnosticBytes {
		return value
	}
	const suffix = "\n...[diagnostic truncated]"
	limit := maxReportDiagnosticBytes - len(suffix)
	return strings.ToValidUTF8(value[:limit], "?") + suffix
}
