package tier5

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/FrankoonG/rendr/regress/internal/gotestjson"
	"github.com/FrankoonG/rendr/regress/internal/report"
)

const maxReportDiagnosticBytes = 16 << 10

var tier5GoTestExecutor = gotestjson.Executor{
	Parser: gotestjson.Parser{MaxOutputBytes: maxReportDiagnosticBytes},
}

type goTestProbe struct {
	caseID       string
	workDir      string
	packageName  string
	testName     string
	cacheName    string
	modCacheName string
	env          []string
}

var unprivilegedProbeDefs = map[string]goTestProbe{
	"T5.3-tcprepair-unprivileged": {
		caseID:       "T5.3-tcprepair-unprivileged",
		packageName:  "./transport/tcprepair",
		testName:     "TestAvailableExpectation",
		cacheName:    "go-build-nocap",
		modCacheName: "go-mod-nocap",
		env:          []string{"RENDR_EXPECT_TCPREPAIR=unavailable"},
	},
	"T5.4-gvisor-unprivileged": {
		caseID:       "T5.4-gvisor-unprivileged",
		workDir:      "regress",
		packageName:  "./internal/smoke",
		testName:     "TestRunG1GVisor",
		cacheName:    "go-build-gvisor-nocap",
		modCacheName: "go-mod-gvisor-nocap",
	},
	"T5.5-tcprepair-gvisor-fallback-unprivileged": {
		caseID:       "T5.5-tcprepair-gvisor-fallback-unprivileged",
		workDir:      "regress",
		packageName:  "./internal/smoke",
		testName:     "TestTCPRepairUnavailableFallsBackToGVisor",
		cacheName:    "go-build-tcprepair-gvisor-fallback-nocap",
		modCacheName: "go-mod-tcprepair-gvisor-fallback-nocap",
	},
	"T5.6-gvisor-packet-carrier-unprivileged": {
		caseID:       "T5.6-gvisor-packet-carrier-unprivileged",
		workDir:      "regress",
		packageName:  "./internal/smoke",
		testName:     "TestRunG1GVisorPacketCarrier",
		cacheName:    "go-build-gvisor-packet-nocap",
		modCacheName: "go-mod-gvisor-packet-nocap",
	},
}

func probeUnprivileged(ctx context.Context, rendrRoot string) report.Case {
	return runUnprivilegedGoTest(ctx, rendrRoot, unprivilegedProbeDefs["T5.3-tcprepair-unprivileged"])
}

func probeGVisorUnprivileged(ctx context.Context, rendrRoot string) report.Case {
	return runUnprivilegedGoTest(ctx, rendrRoot, unprivilegedProbeDefs["T5.4-gvisor-unprivileged"])
}

func probeTCPRepairGVisorFallbackUnprivileged(ctx context.Context, rendrRoot string) report.Case {
	return runUnprivilegedGoTest(ctx, rendrRoot, unprivilegedProbeDefs["T5.5-tcprepair-gvisor-fallback-unprivileged"])
}

func probeGVisorPacketCarrierUnprivileged(ctx context.Context, rendrRoot string) report.Case {
	return runUnprivilegedGoTest(ctx, rendrRoot, unprivilegedProbeDefs["T5.6-gvisor-packet-carrier-unprivileged"])
}

func runUnprivilegedGoTest(ctx context.Context, rendrRoot string, probe goTestProbe) report.Case {
	if _, err := exec.LookPath("setpriv"); err != nil {
		return report.Case{Name: probe.caseID, Tier: "T5", SkipReason: "setpriv unavailable"}
	}
	request := probeGoTestRequest(rendrRoot, probe)
	if _, err := os.Stat(request.Dir); err != nil {
		return report.Case{Name: probe.caseID, Tier: "T5", InvalidReason: "bad go test working directory: " + err.Error()}
	}
	result, err := tier5GoTestExecutor.Run(ctx, request)
	if err != nil && result.Passed() {
		result.Issues = append(result.Issues, gotestjson.Issue{Code: gotestjson.IssueCommandFailed, Detail: err.Error()})
	}
	return goTestReportCase(probe.caseID, []string{probe.testName}, result)
}

func probeGoTestRequest(rendrRoot string, probe goTestProbe) gotestjson.Request {
	dir := rendrRoot
	if probe.workDir != "" {
		dir = filepath.Join(rendrRoot, probe.workDir)
	}
	env := append([]string(nil), probe.env...)
	env = append(env,
		"GOCACHE="+filepath.Join(os.TempDir(), probe.cacheName),
		"GOMODCACHE="+filepath.Join(os.TempDir(), probe.modCacheName),
	)
	return gotestjson.Request{
		Dir:           dir,
		Package:       probe.packageName,
		Pattern:       "^" + regexp.QuoteMeta(probe.testName) + "$",
		Expected:      []gotestjson.Expectation{{Name: probe.testName}},
		Env:           env,
		CommandPrefix: setprivCommandPrefix(),
	}
}

func setprivCommandPrefix() []string {
	return []string{
		"setpriv",
		"--bounding-set=-net_admin",
		"--inh-caps=-net_admin",
		"--ambient-caps=-net_admin",
	}
}

func goTestReportCase(caseName string, expected []string, result gotestjson.Result) report.Case {
	rc := report.Case{
		Name:     caseName,
		Tier:     "T5",
		Duration: result.Duration,
		Evidence: goTestEvidence(expected, result),
	}
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

func goTestEvidence(expected []string, result gotestjson.Result) map[string]string {
	observed := make([]string, 0, len(result.Tests))
	for _, testResult := range result.Tests {
		observed = append(observed, testResult.Name+"="+string(testResult.Status))
	}
	issueCodes := make([]string, 0, len(result.Issues))
	for _, issue := range result.Issues {
		issueCodes = append(issueCodes, string(issue.Code))
	}
	sort.Strings(issueCodes)
	if len(issueCodes) == 0 {
		issueCodes = append(issueCodes, "none")
	}
	return map[string]string{
		"command":            quotedCommand(result.Command),
		"expected_tests":     strings.Join(expected, ","),
		"observed_tests":     strings.Join(observed, ","),
		"issue_codes":        strings.Join(issueCodes, ","),
		"capture_truncated":  strconv.FormatBool(result.CaptureTruncated),
		"json_validation_ok": strconv.FormatBool(result.Passed()),
	}
}

func quotedCommand(command []string) string {
	quoted := make([]string, len(command))
	for i, arg := range command {
		quoted[i] = strconv.Quote(arg)
	}
	return strings.Join(quoted, " ")
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
