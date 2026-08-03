package gotestjson

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"time"
	"unicode"
)

const (
	// DefaultMaxEventBytes bounds one encoded go test JSON event.
	DefaultMaxEventBytes = 4 << 20
	// DefaultMaxOutputBytes bounds retained output for each test and for
	// unattributed command output. Parsing continues after this limit.
	DefaultMaxOutputBytes = 64 << 10
)

var errEventTooLarge = errors.New("go test JSON event exceeds configured limit")

// Parser controls resource limits while parsing a go test -json stream. Zero
// values select the package defaults.
type Parser struct {
	MaxEventBytes  int
	MaxOutputBytes int
}

// Parse validates a go test -json stream with default parser limits.
func Parse(r io.Reader, expected []Expectation) (Result, error) {
	return Parser{}.Parse(r, expected)
}

// Parse validates a go test -json stream. It returns one TestResult for every
// expectation even when validation fails.
func (p Parser) Parse(r io.Reader, expected []Expectation) (Result, error) {
	result, states := initialResult(expected)
	issues := validateParserInput(r, expected, p)
	if len(issues) != 0 {
		result.Issues = issues
		return result, resultError(issues)
	}

	eventLimit := valueOrDefault(p.MaxEventBytes, DefaultMaxEventBytes)
	outputLimit := valueOrDefault(p.MaxOutputBytes, DefaultMaxOutputBytes)
	for i := range states {
		states[i].output.limit = outputLimit
	}
	commandOutput := outputCollector{limit: outputLimit}

	byName := make(map[string]int, len(expected))
	for i, expectation := range expected {
		byName[expectation.Name] = i
	}

	readerSize := eventLimit
	if readerSize > 64<<10 {
		readerSize = 64 << 10
	}
	br := bufio.NewReaderSize(r, readerSize)
	lineNumber := 0
	ranCount := 0
	unexpected := make(map[string]bool)

	for {
		line, readErr := readEventLine(br, eventLimit)
		if len(line) != 0 {
			lineNumber++
			line = trimLineEnding(line)
			var event testEvent
			if err := json.Unmarshal(line, &event); err != nil {
				issues = append(issues, Issue{
					Code:   IssueMalformedJSON,
					Detail: fmt.Sprintf("line %d: %v (%s)", lineNumber, err, excerpt(line)),
				})
			} else if event.Action == "" {
				issues = append(issues, Issue{
					Code:   IssueInvalidEvent,
					Detail: fmt.Sprintf("line %d has no Action", lineNumber),
				})
			} else {
				processEvent(event, byName, states, &commandOutput, unexpected, &issues, &ranCount)
			}
		}

		if readErr == nil {
			continue
		}
		switch {
		case errors.Is(readErr, io.EOF):
		case errors.Is(readErr, errEventTooLarge):
			issues = append(issues, Issue{
				Code:   IssueEventTooLarge,
				Detail: fmt.Sprintf("line %d exceeds %d bytes", lineNumber+1, eventLimit),
			})
		default:
			issues = append(issues, Issue{Code: IssueReadFailure, Detail: readErr.Error()})
		}
		break
	}

	if ranCount == 0 {
		issues = append(issues, Issue{
			Code:   IssueZeroTests,
			Detail: "go test JSON contained no run event for an expected top-level test",
		})
	}

	for i := range states {
		state := &states[i]
		result.Tests[i].Package = state.pkg
		result.Tests[i].Output = state.output.String()
		result.Tests[i].OutputTruncated = state.output.truncated
		issues = append(issues, state.issues...)

		switch {
		case !state.ran:
			result.Tests[i].Status = StatusNotRun
			if ranCount != 0 {
				issues = append(issues, Issue{
					Code:   IssueTestNotRun,
					Test:   state.expectation.Name,
					Detail: "expected top-level test had no run event",
				})
			}
		case !state.terminal:
			result.Tests[i].Status = StatusIncomplete
			issues = append(issues, Issue{
				Code:   IssueNoTerminal,
				Test:   state.expectation.Name,
				Detail: "test ran but produced no terminal pass, fail, or skip event",
			})
		default:
			result.Tests[i].Status = state.status
			result.Tests[i].Duration = state.duration
			switch state.status {
			case StatusFailed:
				issues = append(issues, Issue{
					Code:   IssueTestFailed,
					Test:   state.expectation.Name,
					Detail: "top-level test failed",
				})
			case StatusSkipped:
				if !state.expectation.AllowSkip {
					issues = append(issues, Issue{
						Code:   IssueMandatorySkip,
						Test:   state.expectation.Name,
						Detail: "mandatory top-level test skipped",
					})
				}
			}
		}
	}

	result.CommandOutput = commandOutput.String()
	result.CommandOutputTruncated = commandOutput.truncated
	result.Issues = issues
	return result, resultError(issues)
}

func initialResult(expected []Expectation) (Result, []testState) {
	result := Result{Tests: make([]TestResult, len(expected))}
	states := make([]testState, len(expected))
	for i, expectation := range expected {
		result.Tests[i] = TestResult{Name: expectation.Name, Status: StatusNotRun}
		states[i].expectation = expectation
	}
	return result, states
}

func validateParserInput(r io.Reader, expected []Expectation, p Parser) []Issue {
	var issues []Issue
	if r == nil {
		issues = append(issues, Issue{Code: IssueInvalidConfig, Detail: "nil JSON reader"})
	}
	if p.MaxEventBytes < 0 {
		issues = append(issues, Issue{Code: IssueInvalidConfig, Detail: "MaxEventBytes must not be negative"})
	}
	if p.MaxOutputBytes < 0 {
		issues = append(issues, Issue{Code: IssueInvalidConfig, Detail: "MaxOutputBytes must not be negative"})
	}
	issues = append(issues, validateExpectations(expected)...)
	return issues
}

func validateExpectations(expected []Expectation) []Issue {
	if len(expected) == 0 {
		return []Issue{{Code: IssueInvalidConfig, Detail: "at least one expected top-level test is required"}}
	}
	seen := make(map[string]bool, len(expected))
	var issues []Issue
	for _, expectation := range expected {
		name := expectation.Name
		switch {
		case name == "":
			issues = append(issues, Issue{Code: IssueInvalidConfig, Detail: "expected test name must not be empty"})
		case strings.ContainsRune(name, '/'):
			issues = append(issues, Issue{Code: IssueInvalidConfig, Test: name, Detail: "expected test must be top-level"})
		case strings.IndexFunc(name, unicode.IsSpace) >= 0:
			issues = append(issues, Issue{Code: IssueInvalidConfig, Test: name, Detail: "expected test name must not contain whitespace"})
		case seen[name]:
			issues = append(issues, Issue{Code: IssueInvalidConfig, Test: name, Detail: "duplicate expected test"})
		default:
			seen[name] = true
		}
	}
	return issues
}

func processEvent(
	event testEvent,
	byName map[string]int,
	states []testState,
	commandOutput *outputCollector,
	unexpected map[string]bool,
	issues *[]Issue,
	ranCount *int,
) {
	if event.Test == "" {
		commandOutput.Append(event.Output)
		return
	}

	root, child := topLevelName(event.Test)
	index, selected := byName[root]
	if !selected {
		commandOutput.Append(event.Output)
		if !unexpected[root] {
			unexpected[root] = true
			*issues = append(*issues, Issue{
				Code:   IssueUnexpectedTest,
				Test:   root,
				Detail: "go test JSON contained an unrequested top-level test",
			})
		}
		return
	}

	state := &states[index]
	state.output.Append(event.Output)
	state.observePackage(event.Package)
	if child {
		return
	}

	switch event.Action {
	case "run":
		if state.ran {
			state.addSequenceIssue("duplicate run event")
			return
		}
		if state.terminal {
			state.addSequenceIssue("run event followed a terminal event")
		}
		state.ran = true
		*ranCount++
	case "pass", "fail", "skip":
		if !state.ran {
			state.addSequenceIssue("terminal event preceded the run event")
		}
		if state.terminal {
			state.addSequenceIssue("duplicate terminal event")
			return
		}
		state.terminal = true
		state.status = statusForAction(event.Action)
		duration, ok := eventDuration(event.Elapsed)
		if !ok {
			state.issues = append(state.issues, Issue{
				Code:   IssueInvalidEvent,
				Test:   state.expectation.Name,
				Detail: fmt.Sprintf("invalid terminal elapsed value %v", event.Elapsed),
			})
			return
		}
		state.duration = duration
	}
}

func (s *testState) observePackage(pkg string) {
	if pkg == "" {
		return
	}
	if s.pkg == "" {
		s.pkg = pkg
		return
	}
	if s.pkg != pkg && !s.packageMismatch {
		s.packageMismatch = true
		s.addSequenceIssue(fmt.Sprintf("events came from multiple packages %q and %q", s.pkg, pkg))
	}
}

func (s *testState) addSequenceIssue(detail string) {
	s.issues = append(s.issues, Issue{
		Code:   IssueInvalidSequence,
		Test:   s.expectation.Name,
		Detail: detail,
	})
}

func statusForAction(action string) Status {
	switch action {
	case "pass":
		return StatusPassed
	case "fail":
		return StatusFailed
	case "skip":
		return StatusSkipped
	default:
		return StatusIncomplete
	}
}

func eventDuration(seconds float64) (time.Duration, bool) {
	if math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 0 {
		return 0, false
	}
	maxSeconds := float64(math.MaxInt64) / float64(time.Second)
	if seconds > maxSeconds {
		return 0, false
	}
	return time.Duration(seconds * float64(time.Second)), true
}

func topLevelName(name string) (string, bool) {
	if slash := strings.IndexByte(name, '/'); slash >= 0 {
		return name[:slash], true
	}
	return name, false
}

func readEventLine(r *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	for {
		fragment, err := r.ReadSlice('\n')
		if len(line)+len(fragment) > max {
			return nil, errEventTooLarge
		}
		line = append(line, fragment...)
		if err == nil {
			return line, nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return line, err
	}
}

func trimLineEnding(line []byte) []byte {
	line = bytes.TrimSuffix(line, []byte{'\n'})
	line = bytes.TrimSuffix(line, []byte{'\r'})
	return line
}

func excerpt(line []byte) string {
	const max = 160
	if len(line) > max {
		line = line[:max]
		return fmt.Sprintf("%q...", line)
	}
	return fmt.Sprintf("%q", line)
}

func valueOrDefault(value, fallback int) int {
	if value == 0 {
		return fallback
	}
	return value
}

type testEvent struct {
	Action  string  `json:"Action"`
	Package string  `json:"Package"`
	Test    string  `json:"Test"`
	Elapsed float64 `json:"Elapsed"`
	Output  string  `json:"Output"`
}

type testState struct {
	expectation     Expectation
	pkg             string
	ran             bool
	terminal        bool
	status          Status
	duration        time.Duration
	output          outputCollector
	issues          []Issue
	packageMismatch bool
}

type outputCollector struct {
	limit     int
	value     strings.Builder
	truncated bool
}

func (c *outputCollector) Append(output string) {
	if output == "" {
		return
	}
	remaining := c.limit - c.value.Len()
	if remaining <= 0 {
		c.truncated = true
		return
	}
	if len(output) > remaining {
		_, _ = c.value.WriteString(output[:remaining])
		c.truncated = true
		return
	}
	_, _ = c.value.WriteString(output)
}

func (c *outputCollector) String() string {
	return c.value.String()
}
