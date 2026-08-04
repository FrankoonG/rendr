package gotestjson

import (
	"fmt"
	"strings"
	"time"
)

// Expectation describes one expected top-level Go test. Tests are mandatory
// by default; set AllowSkip only for a deliberately optional test.
type Expectation struct {
	Name      string
	AllowSkip bool
}

// Status is the terminal state observed for an expected top-level test.
type Status string

const (
	StatusNotRun     Status = "not_run"
	StatusIncomplete Status = "incomplete"
	StatusPassed     Status = "pass"
	StatusFailed     Status = "fail"
	StatusSkipped    Status = "skip"
)

// TestResult contains the deterministic result for one expectation. Results
// are always returned in expectation order, independent of event order.
type TestResult struct {
	Name            string
	Package         string
	Status          Status
	Duration        time.Duration
	Output          string
	OutputTruncated bool
}

// IssueCode identifies a condition that makes a run invalid or failed.
type IssueCode string

const (
	IssueInvalidConfig      IssueCode = "invalid_config"
	IssueMalformedJSON      IssueCode = "malformed_json"
	IssueReadFailure        IssueCode = "read_failure"
	IssueEventTooLarge      IssueCode = "event_too_large"
	IssueCaptureLimit       IssueCode = "capture_limit"
	IssueZeroTests          IssueCode = "zero_tests"
	IssueTestNotRun         IssueCode = "test_not_run"
	IssueNoTerminal         IssueCode = "no_terminal_event"
	IssueMandatorySkip      IssueCode = "mandatory_skip"
	IssueTestFailed         IssueCode = "test_failed"
	IssueUnexpectedTest     IssueCode = "unexpected_test"
	IssueInvalidEvent       IssueCode = "invalid_event"
	IssueInvalidSequence    IssueCode = "invalid_event_sequence"
	IssueCommandCanceled    IssueCode = "command_canceled"
	IssueCommandFailed      IssueCode = "command_failed"
	IssueProcessContainment IssueCode = "process_containment_failed"
	IssueProcessLeak        IssueCode = "process_leak"
	IssueProcessCleanup     IssueCode = "process_cleanup_failed"
)

// ProcessContainmentMethod identifies the Linux command boundary used for an
// invocation. Other platforms report ProcessContainmentNone.
type ProcessContainmentMethod string

const (
	ProcessContainmentNone      ProcessContainmentMethod = "none"
	ProcessContainmentCgroupV2  ProcessContainmentMethod = "cgroup_v2"
	ProcessContainmentSubreaper ProcessContainmentMethod = "subreaper_proc"
)

// ProcessCleanupEvidence records the independently observable outcome of
// post-command descendant detection and teardown.
type ProcessCleanupEvidence struct {
	Method               ProcessContainmentMethod
	LeakDetected         bool
	DescendantCount      int
	TerminationConfirmed bool
}

// Issue describes one fail-closed validation finding.
type Issue struct {
	Code   IssueCode
	Test   string
	Detail string
}

func (i Issue) String() string {
	where := ""
	if i.Test != "" {
		where = " " + i.Test
	}
	if i.Detail == "" {
		return string(i.Code) + where
	}
	return fmt.Sprintf("%s%s: %s", i.Code, where, i.Detail)
}

// Result is the parsed and validated outcome of one go test invocation.
type Result struct {
	Tests                  []TestResult
	Command                []string
	Duration               time.Duration
	CommandOutput          string
	CommandOutputTruncated bool
	CaptureTruncated       bool
	ProcessCleanup         ProcessCleanupEvidence
	Issues                 []Issue
}

// Passed reports whether parsing, test outcomes, and command execution all
// satisfied the requested expectations.
func (r Result) Passed() bool {
	return len(r.Issues) == 0
}

// HasIssue reports whether the result contains an issue with code.
func (r Result) HasIssue(code IssueCode) bool {
	for _, issue := range r.Issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}

// Error is returned whenever a Result contains one or more issues. The result
// remains usable for deterministic per-test diagnostics.
type Error struct {
	Issues []Issue
}

func (e *Error) Error() string {
	if e == nil || len(e.Issues) == 0 {
		return "go test JSON validation failed"
	}
	parts := make([]string, len(e.Issues))
	for i, issue := range e.Issues {
		parts[i] = issue.String()
	}
	return "go test JSON validation failed: " + strings.Join(parts, "; ")
}

func resultError(issues []Issue) error {
	if len(issues) == 0 {
		return nil
	}
	return &Error{Issues: append([]Issue(nil), issues...)}
}
