package gotestjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseReturnsExpectationOrderAndDeterministicDetails(t *testing.T) {
	stream := encodeEvents(t,
		testEvent{Action: "start", Package: "example/pkg", Output: "package setup\n"},
		testEvent{Action: "run", Package: "example/pkg", Test: "TestSecond"},
		testEvent{Action: "output", Package: "example/pkg", Test: "TestSecond", Output: "second top\n"},
		testEvent{Action: "run", Package: "example/pkg", Test: "TestSecond/child"},
		testEvent{Action: "output", Package: "example/pkg", Test: "TestSecond/child", Output: "second child\n"},
		testEvent{Action: "pass", Package: "example/pkg", Test: "TestSecond/child", Elapsed: 0.01},
		testEvent{Action: "pass", Package: "example/pkg", Test: "TestSecond", Elapsed: 0.25},
		testEvent{Action: "run", Package: "example/pkg", Test: "TestFirst"},
		testEvent{Action: "output", Package: "example/pkg", Test: "TestFirst", Output: "first\n"},
		testEvent{Action: "pass", Package: "example/pkg", Test: "TestFirst", Elapsed: 0.125},
	)

	result, err := Parse(stream, required("TestFirst", "TestSecond"))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Passed() {
		t.Fatalf("Passed()=false, issues=%v", result.Issues)
	}
	if got, want := resultNames(result.Tests), []string{"TestFirst", "TestSecond"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("result order=%v, want %v", got, want)
	}
	assertTestResult(t, result.Tests[0], StatusPassed, 125*time.Millisecond, "first\n")
	assertTestResult(t, result.Tests[1], StatusPassed, 250*time.Millisecond, "second top\nsecond child\n")
	for _, testResult := range result.Tests {
		if testResult.Package != "example/pkg" {
			t.Errorf("%s package=%q, want example/pkg", testResult.Name, testResult.Package)
		}
	}
	if result.CommandOutput != "package setup\n" {
		t.Fatalf("CommandOutput=%q", result.CommandOutput)
	}
}

func TestParseFailClosedConditions(t *testing.T) {
	validPass := []testEvent{
		{Action: "run", Test: "TestOne"},
		{Action: "pass", Test: "TestOne", Elapsed: 0.1},
	}
	tests := []struct {
		name       string
		stream     io.Reader
		expected   []Expectation
		wantCodes  []IssueCode
		wantStatus []Status
	}{
		{
			name:       "zero tests",
			stream:     strings.NewReader(""),
			expected:   required("TestOne"),
			wantCodes:  []IssueCode{IssueZeroTests},
			wantStatus: []Status{StatusNotRun},
		},
		{
			name:       "one selected test absent",
			stream:     encodeEvents(t, validPass...),
			expected:   required("TestOne", "TestTwo"),
			wantCodes:  []IssueCode{IssueTestNotRun},
			wantStatus: []Status{StatusPassed, StatusNotRun},
		},
		{
			name: "selected test has no terminal event",
			stream: encodeEvents(t,
				testEvent{Action: "run", Test: "TestOne"},
				testEvent{Action: "output", Test: "TestOne", Output: "partial\n"},
			),
			expected:   required("TestOne"),
			wantCodes:  []IssueCode{IssueNoTerminal},
			wantStatus: []Status{StatusIncomplete},
		},
		{
			name: "mandatory test skips",
			stream: encodeEvents(t,
				testEvent{Action: "run", Test: "TestOne"},
				testEvent{Action: "skip", Test: "TestOne", Elapsed: 0.02},
			),
			expected:   required("TestOne"),
			wantCodes:  []IssueCode{IssueMandatorySkip},
			wantStatus: []Status{StatusSkipped},
		},
		{
			name: "represented test failure",
			stream: encodeEvents(t,
				testEvent{Action: "run", Test: "TestOne"},
				testEvent{Action: "fail", Test: "TestOne", Elapsed: 0.03},
			),
			expected:   required("TestOne"),
			wantCodes:  []IssueCode{IssueTestFailed},
			wantStatus: []Status{StatusFailed},
		},
		{
			name:       "malformed JSON",
			stream:     strings.NewReader("not-json\n"),
			expected:   required("TestOne"),
			wantCodes:  []IssueCode{IssueMalformedJSON, IssueZeroTests},
			wantStatus: []Status{StatusNotRun},
		},
		{
			name: "truncated JSON",
			stream: strings.NewReader(
				"{\"Action\":\"run\",\"Test\":\"TestOne\"}\n" +
					"{\"Action\":\"pass\",\"Test\":\"TestOne\"",
			),
			expected:   required("TestOne"),
			wantCodes:  []IssueCode{IssueMalformedJSON, IssueNoTerminal},
			wantStatus: []Status{StatusIncomplete},
		},
		{
			name: "unexpected top-level test",
			stream: encodeEvents(t,
				testEvent{Action: "run", Test: "TestOther"},
				testEvent{Action: "pass", Test: "TestOther"},
			),
			expected:   required("TestOne"),
			wantCodes:  []IssueCode{IssueUnexpectedTest, IssueZeroTests},
			wantStatus: []Status{StatusNotRun},
		},
		{
			name: "terminal without run",
			stream: encodeEvents(t,
				testEvent{Action: "pass", Test: "TestOne"},
			),
			expected:   required("TestOne"),
			wantCodes:  []IssueCode{IssueZeroTests, IssueInvalidSequence},
			wantStatus: []Status{StatusNotRun},
		},
		{
			name:       "valid JSON without Action",
			stream:     strings.NewReader("{}\n"),
			expected:   required("TestOne"),
			wantCodes:  []IssueCode{IssueInvalidEvent, IssueZeroTests},
			wantStatus: []Status{StatusNotRun},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := Parse(test.stream, test.expected)
			assertValidationError(t, err)
			for _, code := range test.wantCodes {
				if !result.HasIssue(code) {
					t.Errorf("missing issue %q in %+v", code, result.Issues)
				}
			}
			if got := resultStatuses(result.Tests); !reflect.DeepEqual(got, test.wantStatus) {
				t.Errorf("statuses=%v, want %v", got, test.wantStatus)
			}
			if result.Passed() {
				t.Error("Passed()=true for invalid result")
			}
		})
	}
}

func TestParseAllowsExplicitlyOptionalSkip(t *testing.T) {
	stream := encodeEvents(t,
		testEvent{Action: "run", Test: "TestOptional"},
		testEvent{Action: "output", Test: "TestOptional", Output: "not supported here\n"},
		testEvent{Action: "skip", Test: "TestOptional", Elapsed: 0.004},
	)
	result, err := Parse(stream, []Expectation{{Name: "TestOptional", AllowSkip: true}})
	if err != nil {
		t.Fatal(err)
	}
	assertTestResult(t, result.Tests[0], StatusSkipped, 4*time.Millisecond, "not supported here\n")
}

func TestParseAcceptsCompleteFinalObjectWithoutNewline(t *testing.T) {
	stream := strings.NewReader(
		"{\"Action\":\"run\",\"Test\":\"TestOne\"}\n" +
			"{\"Action\":\"pass\",\"Test\":\"TestOne\",\"Elapsed\":0.5}",
	)
	result, err := Parse(stream, required("TestOne"))
	if err != nil {
		t.Fatal(err)
	}
	assertTestResult(t, result.Tests[0], StatusPassed, 500*time.Millisecond, "")
}

func TestParseRejectsDuplicateAndCrossPackageSequences(t *testing.T) {
	tests := []struct {
		name   string
		events []testEvent
	}{
		{
			name: "duplicate run",
			events: []testEvent{
				{Action: "run", Test: "TestOne"},
				{Action: "run", Test: "TestOne"},
				{Action: "pass", Test: "TestOne"},
			},
		},
		{
			name: "duplicate terminal",
			events: []testEvent{
				{Action: "run", Test: "TestOne"},
				{Action: "pass", Test: "TestOne"},
				{Action: "fail", Test: "TestOne"},
			},
		},
		{
			name: "same name in multiple packages",
			events: []testEvent{
				{Action: "run", Package: "one/pkg", Test: "TestOne"},
				{Action: "pass", Package: "other/pkg", Test: "TestOne"},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := Parse(encodeEvents(t, test.events...), required("TestOne"))
			assertValidationError(t, err)
			if !result.HasIssue(IssueInvalidSequence) {
				t.Fatalf("issues=%+v, want invalid sequence", result.Issues)
			}
		})
	}
}

func TestParseBoundsRetainedOutputWithoutChangingOutcome(t *testing.T) {
	stream := encodeEvents(t,
		testEvent{Action: "start", Output: "command-output"},
		testEvent{Action: "run", Test: "TestOne"},
		testEvent{Action: "output", Test: "TestOne", Output: "top-"},
		testEvent{Action: "output", Test: "TestOne/child", Output: "child"},
		testEvent{Action: "pass", Test: "TestOne"},
	)
	result, err := (Parser{MaxOutputBytes: 7}).Parse(stream, required("TestOne"))
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Tests[0].Output; got != "top-chi" {
		t.Fatalf("test output=%q, want %q", got, "top-chi")
	}
	if !result.Tests[0].OutputTruncated {
		t.Fatal("test output was not marked truncated")
	}
	if got := result.CommandOutput; got != "command" {
		t.Fatalf("command output=%q, want %q", got, "command")
	}
	if !result.CommandOutputTruncated {
		t.Fatal("command output was not marked truncated")
	}
}

func TestParseBoundsEncodedEventSize(t *testing.T) {
	stream := encodeEvents(t,
		testEvent{Action: "run", Test: "TestOne", Output: strings.Repeat("x", 128)},
		testEvent{Action: "pass", Test: "TestOne"},
	)
	result, err := (Parser{MaxEventBytes: 32}).Parse(stream, required("TestOne"))
	assertValidationError(t, err)
	if !result.HasIssue(IssueEventTooLarge) || !result.HasIssue(IssueZeroTests) {
		t.Fatalf("issues=%+v, want event-too-large and zero-tests", result.Issues)
	}
}

func TestParsePropagatesReaderFailure(t *testing.T) {
	wantErr := errors.New("synthetic read failure")
	result, err := Parse(errorReader{err: wantErr}, required("TestOne"))
	assertValidationError(t, err)
	if !result.HasIssue(IssueReadFailure) || !result.HasIssue(IssueZeroTests) {
		t.Fatalf("issues=%+v, want read-failure and zero-tests", result.Issues)
	}
}

func TestParseRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name     string
		parser   Parser
		reader   io.Reader
		expected []Expectation
	}{
		{name: "nil reader", reader: nil, expected: required("TestOne")},
		{name: "no expectations", reader: strings.NewReader(""), expected: nil},
		{name: "empty name", reader: strings.NewReader(""), expected: []Expectation{{}}},
		{name: "subtest name", reader: strings.NewReader(""), expected: required("TestOne/child")},
		{name: "whitespace name", reader: strings.NewReader(""), expected: required("Test One")},
		{name: "duplicate name", reader: strings.NewReader(""), expected: required("TestOne", "TestOne")},
		{name: "negative event limit", parser: Parser{MaxEventBytes: -1}, reader: strings.NewReader(""), expected: required("TestOne")},
		{name: "negative output limit", parser: Parser{MaxOutputBytes: -1}, reader: strings.NewReader(""), expected: required("TestOne")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := test.parser.Parse(test.reader, test.expected)
			assertValidationError(t, err)
			if !result.HasIssue(IssueInvalidConfig) {
				t.Fatalf("issues=%+v, want invalid config", result.Issues)
			}
		})
	}
}

func TestValidationErrorCopiesIssues(t *testing.T) {
	result, err := Parse(strings.NewReader(""), required("TestOne"))
	validationErr := assertValidationError(t, err)
	result.Issues[0].Detail = "mutated"
	if validationErr.Issues[0].Detail == "mutated" {
		t.Fatal("Error shared mutable issue storage with Result")
	}
	if !strings.Contains(validationErr.Error(), string(IssueZeroTests)) {
		t.Fatalf("Error()=%q", validationErr.Error())
	}
}

func encodeEvents(t *testing.T, events ...testEvent) *bytes.Reader {
	t.Helper()
	var stream bytes.Buffer
	encoder := json.NewEncoder(&stream)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			t.Fatal(err)
		}
	}
	return bytes.NewReader(stream.Bytes())
}

func required(names ...string) []Expectation {
	expected := make([]Expectation, len(names))
	for i, name := range names {
		expected[i] = Expectation{Name: name}
	}
	return expected
}

func resultNames(results []TestResult) []string {
	names := make([]string, len(results))
	for i, result := range results {
		names[i] = result.Name
	}
	return names
}

func resultStatuses(results []TestResult) []Status {
	statuses := make([]Status, len(results))
	for i, result := range results {
		statuses[i] = result.Status
	}
	return statuses
}

func assertTestResult(t *testing.T, result TestResult, status Status, duration time.Duration, output string) {
	t.Helper()
	if result.Status != status || result.Duration != duration || result.Output != output {
		t.Fatalf("result=%+v, want status=%s duration=%s output=%q", result, status, duration, output)
	}
}

func assertValidationError(t *testing.T, err error) *Error {
	t.Helper()
	if err == nil {
		t.Fatal("expected validation error")
	}
	var validationErr *Error
	if !errors.As(err, &validationErr) {
		t.Fatalf("error type=%T, want *Error", err)
	}
	return validationErr
}

type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) {
	return 0, r.err
}
