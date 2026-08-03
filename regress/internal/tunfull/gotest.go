package tunfull

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/gotestjson"
	"github.com/FrankoonG/rendr/regress/internal/report"
)

const maxGoTestDiagnosticBytes = 16 << 10

var tunXrayExpectedTests = []string{
	"TestTUNT3FreedomStreamOverTUN",
	"TestTUNT3SS2022StreamOverTUN",
	"TestTUNT3VMessStreamOverTUN",
	"TestTUNT3TrojanTLSStreamOverTUN",
	"TestTUNT3VLESSVisionTLSStreamOverTUN",
	"TestTUNT3VLESSVisionTLSMLKEMStreamOverTUN",
	"TestTUNT3VLESSVisionRealityStreamOverTUN",
	"TestTUNT3VLESSHysteria2TransportStreamOverTUN",
	"TestTUNT3MixedSS2022VMessStreamOverTUN",
	"TestTUNT3ThreePathSSVMessVLESSStreamOverTUN",
	"TestTUNT3DirectRelayStreamOverTUN",
	"TestTUNT3NestedTwoLayerStreamOverTUN",
	"TestTUNT3PacketXrayFreedomUDPxUDPFlowOverTUN",
	"TestTUNT3PacketXrayBalancerUDPxUDPFlowOverTUN",
}

var tunGoTestExecutor = gotestjson.Executor{
	WaitDelay: 15 * time.Second,
	Parser:    gotestjson.Parser{MaxOutputBytes: maxGoTestDiagnosticBytes},
}

var executeTUNGoTest = func(ctx context.Context, request gotestjson.Request) (gotestjson.Result, error) {
	return tunGoTestExecutor.Run(ctx, request)
}

func runT3XrayMatrix(ctx context.Context, rendrRoot, name string) report.Case {
	started := time.Now()
	if name == "" {
		name = caseT3XrayMatrix
	}
	if _, err := os.Stat(rendrRoot); err != nil {
		return failedCase(name, started, fmt.Errorf("bad rendr root: %w", err))
	}

	expected := make([]gotestjson.Expectation, len(tunXrayExpectedTests))
	quoted := make([]string, len(tunXrayExpectedTests))
	for i, testName := range tunXrayExpectedTests {
		expected[i] = gotestjson.Expectation{Name: testName}
		quoted[i] = regexp.QuoteMeta(testName)
	}
	cctx, cancel := context.WithTimeout(ctx, 12*time.Minute)
	defer cancel()
	result, runErr := executeTUNGoTest(cctx, gotestjson.Request{
		Dir:         filepath.Join(rendrRoot, "regress"),
		Package:     "./internal/matrix",
		Pattern:     "^(?:" + strings.Join(quoted, "|") + ")$",
		Expected:    expected,
		TestTimeout: 10 * time.Minute,
	})
	return tunGoTestReportCase(name, tunXrayExpectedTests, result, runErr, time.Since(started))
}

func tunGoTestReportCase(name string, expected []string, result gotestjson.Result, runErr error, elapsed time.Duration) report.Case {
	rc := report.Case{
		Name:     name,
		Tier:     "T7",
		Duration: elapsed,
		Evidence: map[string]string{
			"expected_top_level_tests": fmt.Sprintf("%d", len(expected)),
			"go_test_json":             "strict",
		},
	}
	if result.Duration > 0 {
		rc.Duration = result.Duration
	}

	expectedSet := make(map[string]bool, len(expected))
	for _, testName := range expected {
		expectedSet[testName] = true
	}
	results := make(map[string]gotestjson.TestResult, len(result.Tests))
	var failures, skips, invalids []string
	passed := 0
	for _, testResult := range result.Tests {
		if !expectedSet[testResult.Name] {
			invalids = append(invalids, fmt.Sprintf("unexpected parsed test result %q", testResult.Name))
			continue
		}
		if _, duplicate := results[testResult.Name]; duplicate {
			invalids = append(invalids, fmt.Sprintf("duplicate parsed test result %q", testResult.Name))
			continue
		}
		results[testResult.Name] = testResult
		if testResult.Status == gotestjson.StatusPassed {
			passed++
		}
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
		switch issue.Code {
		case gotestjson.IssueTestFailed:
			failures = append(failures, issue.String())
		case gotestjson.IssueMandatorySkip:
			skips = append(skips, issue.String())
		default:
			invalids = append(invalids, issue.String())
		}
	}
	if runErr != nil && len(result.Issues) == 0 {
		invalids = append(invalids, "go test executor returned an unclassified error: "+runErr.Error())
	}

	for _, testName := range expected {
		testResult, ok := results[testName]
		if !ok {
			invalids = append(invalids, fmt.Sprintf("expected top-level test %q has no parsed result", testName))
			continue
		}
		switch testResult.Status {
		case gotestjson.StatusPassed:
		case gotestjson.StatusFailed:
			failures = append(failures, tunTestOutput("top-level test "+testName+" failed", testResult))
		case gotestjson.StatusSkipped:
			skips = append(skips, tunTestOutput("mandatory top-level test "+testName+" skipped", testResult))
		case gotestjson.StatusNotRun:
			invalids = append(invalids, fmt.Sprintf("expected top-level test %q did not run", testName))
		case gotestjson.StatusIncomplete:
			invalids = append(invalids, tunTestOutput("top-level test "+testName+" has no terminal event", testResult))
		default:
			invalids = append(invalids, fmt.Sprintf("top-level test %q has unknown status %q", testName, testResult.Status))
		}
	}
	if result.CaptureTruncated && !result.HasIssue(gotestjson.IssueCaptureLimit) {
		invalids = append(invalids, "go test JSON capture was truncated")
	}
	if len(invalids) != 0 && strings.TrimSpace(result.CommandOutput) != "" {
		invalids = append(invalids, tunOutputDiagnostic("go test command output", result.CommandOutput, result.CommandOutputTruncated))
	}
	rc.Evidence["passed_top_level_tests"] = fmt.Sprintf("%d", passed)
	rc.Failure = boundedTUNDiagnostic(failures)
	rc.SkipReason = boundedTUNDiagnostic(skips)
	rc.InvalidReason = boundedTUNDiagnostic(invalids)
	return rc
}

func tunTestOutput(prefix string, result gotestjson.TestResult) string {
	return tunOutputDiagnostic(prefix, result.Output, result.OutputTruncated)
}

func tunOutputDiagnostic(prefix, output string, truncated bool) string {
	if output = strings.TrimSpace(output); output != "" {
		prefix += ":\n" + output
	}
	if truncated {
		prefix += "\n[output truncated]"
	}
	return prefix
}

func boundedTUNDiagnostic(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	value := strings.ToValidUTF8(strings.Join(parts, "\n"), "?")
	if len(value) <= maxGoTestDiagnosticBytes {
		return value
	}
	const suffix = "\n...[diagnostic truncated]"
	limit := maxGoTestDiagnosticBytes - len(suffix)
	return strings.ToValidUTF8(value[:limit], "?") + suffix
}
