package gotestjson

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultWaitDelay bounds waiting for I/O pipes after cancellation or
	// process exit. See os/exec.Cmd.WaitDelay.
	DefaultWaitDelay = 5 * time.Second
	// DefaultMaxJSONBytes bounds each JSON stdout and diagnostic stderr capture.
	DefaultMaxJSONBytes = 32 << 20
)

// Request describes one go test package and -run pattern invocation.
type Request struct {
	Dir         string
	Package     string
	Pattern     string
	Expected    []Expectation
	TestTimeout time.Duration
	Env         []string
	// Race enables the Go race detector for this exact test invocation.
	Race bool
	// CommandPrefix wraps the go invocation without a shell. For example,
	// []string{"setpriv", "--bounding-set=-net_admin"} executes
	// "setpriv ... go test -json ..." while preserving JSON validation and
	// process containment, cancellation, and cleanup.
	CommandPrefix []string
}

// Executor runs go test and parses its JSON stream. Zero-valued fields use
// bounded defaults.
type Executor struct {
	GoBinary     string
	WaitDelay    time.Duration
	MaxJSONBytes int
	Parser       Parser

	commandContext func(context.Context, string, ...string) *exec.Cmd
	containProcess func(*exec.Cmd) (processContainment, error)
}

type processContainment interface {
	cleanup(time.Duration, bool) processCleanupResult
}

type processCleanupResult struct {
	evidence ProcessCleanupEvidence
	err      error
}

// Run executes a request with the default Executor.
func Run(ctx context.Context, request Request) (Result, error) {
	return Executor{}.Run(ctx, request)
}

// Run executes go test -json and validates the result. A represented test
// failure is reported as IssueTestFailed; a non-zero command without such a
// failure additionally reports IssueCommandFailed. On Linux, surviving
// descendants invalidate the result even when the command exits successfully.
func (e Executor) Run(ctx context.Context, request Request) (Result, error) {
	if issues := validateRequest(ctx, request, e); len(issues) != 0 {
		result, _ := initialResult(request.Expected)
		result.Issues = issues
		return result, resultError(issues)
	}

	binary := e.GoBinary
	if binary == "" {
		binary = "go"
	}
	args := buildArgs(request)
	command := make([]string, 0, len(request.CommandPrefix)+1+len(args))
	command = append(command, request.CommandPrefix...)
	command = append(command, binary)
	command = append(command, args...)
	maxJSONBytes := valueOrDefault(e.MaxJSONBytes, DefaultMaxJSONBytes)
	waitDelay := e.WaitDelay
	if waitDelay == 0 {
		waitDelay = DefaultWaitDelay
	}

	factory := e.commandContext
	if factory == nil {
		factory = exec.CommandContext
	}
	cmd := factory(ctx, command[0], command[1:]...)
	cmd.Dir = request.Dir
	if request.Env != nil {
		cmd.Env = append(os.Environ(), request.Env...)
	}
	cmd.WaitDelay = waitDelay
	containProcess := e.containProcess
	if containProcess == nil {
		containProcess = configureProcessContainment
	}
	containment, containmentErr := containProcess(cmd)
	if containmentErr != nil {
		result, _ := initialResult(request.Expected)
		result.Command = command
		result.Issues = []Issue{{Code: IssueProcessContainment, Detail: containmentErr.Error()}}
		return result, resultError(result.Issues)
	}

	jsonCapture := &boundedBuffer{limit: maxJSONBytes}
	stderrCapture := &boundedBuffer{limit: maxJSONBytes}
	cmd.Stdout = jsonCapture
	cmd.Stderr = stderrCapture
	started := time.Now()
	runErr := cmd.Run()
	processCleanup := containment.cleanup(waitDelay, ctx.Err() == nil)
	duration := time.Since(started)

	result, _ := e.Parser.Parse(bytes.NewReader(jsonCapture.Bytes()), request.Expected)
	result.Command = command
	result.Duration = duration
	result.CommandOutput = joinCommandDiagnostics(result.CommandOutput, stderrCapture.Bytes())
	result.CommandOutputTruncated = result.CommandOutputTruncated || stderrCapture.Truncated()
	result.ProcessCleanup = processCleanup.evidence
	issues := append([]Issue(nil), result.Issues...)

	if jsonCapture.Truncated() || stderrCapture.Truncated() {
		result.CaptureTruncated = true
		issues = append(issues, Issue{
			Code:   IssueCaptureLimit,
			Detail: fmt.Sprintf("go test JSON or stderr exceeded %d bytes", maxJSONBytes),
		})
	}
	if runErr != nil {
		switch {
		case ctx.Err() != nil:
			issues = append(issues, Issue{Code: IssueCommandCanceled, Detail: ctx.Err().Error()})
		case !hasRepresentedTestFailure(result.Tests):
			detail := runErr.Error()
			if diagnostic := strings.TrimSpace(string(stderrCapture.Bytes())); diagnostic != "" {
				detail += ": " + diagnostic
			}
			issues = append(issues, Issue{Code: IssueCommandFailed, Detail: detail})
		}
	}
	if processCleanup.evidence.LeakDetected {
		detail := fmt.Sprintf(
			"containment=%s detected %d surviving descendants; termination_confirmed=%t",
			processCleanup.evidence.Method,
			processCleanup.evidence.DescendantCount,
			processCleanup.evidence.TerminationConfirmed,
		)
		issues = append(issues, Issue{Code: IssueProcessLeak, Detail: detail})
	}
	if processCleanup.err != nil {
		issues = append(issues, Issue{Code: IssueProcessCleanup, Detail: processCleanup.err.Error()})
	}

	result.Issues = issues
	return result, resultError(issues)
}

func joinCommandDiagnostics(commandOutput string, stderr []byte) string {
	diagnostic := strings.TrimSpace(string(stderr))
	if diagnostic == "" {
		return commandOutput
	}
	if commandOutput == "" {
		return diagnostic
	}
	if strings.HasSuffix(commandOutput, "\n") {
		return commandOutput + diagnostic
	}
	return commandOutput + "\n" + diagnostic
}

func validateRequest(ctx context.Context, request Request, executor Executor) []Issue {
	var issues []Issue
	if ctx == nil {
		issues = append(issues, Issue{Code: IssueInvalidConfig, Detail: "nil context"})
	}
	if strings.TrimSpace(request.Package) == "" {
		issues = append(issues, Issue{Code: IssueInvalidConfig, Detail: "Package must not be empty"})
	}
	if request.Pattern == "" {
		issues = append(issues, Issue{Code: IssueInvalidConfig, Detail: "Pattern must not be empty"})
	}
	if request.TestTimeout < 0 {
		issues = append(issues, Issue{Code: IssueInvalidConfig, Detail: "TestTimeout must not be negative"})
	}
	if executor.WaitDelay < 0 {
		issues = append(issues, Issue{Code: IssueInvalidConfig, Detail: "WaitDelay must not be negative"})
	}
	if executor.MaxJSONBytes < 0 {
		issues = append(issues, Issue{Code: IssueInvalidConfig, Detail: "MaxJSONBytes must not be negative"})
	}
	for _, env := range request.Env {
		if index := strings.IndexByte(env, '='); index <= 0 {
			issues = append(issues, Issue{Code: IssueInvalidConfig, Detail: fmt.Sprintf("invalid environment entry %q", env)})
		}
	}
	for _, arg := range request.CommandPrefix {
		if strings.TrimSpace(arg) == "" {
			issues = append(issues, Issue{Code: IssueInvalidConfig, Detail: "CommandPrefix entries must not be empty"})
		}
	}
	issues = append(issues, validateParserInput(strings.NewReader(""), request.Expected, executor.Parser)...)
	return issues
}

func buildArgs(request Request) []string {
	args := []string{"test", "-json", "-count=1", "-run", request.Pattern}
	if request.Race {
		args = append(args, "-race")
	}
	if request.TestTimeout > 0 {
		args = append(args, "-timeout", request.TestTimeout.String())
	}
	return append(args, request.Package)
}

func hasRepresentedTestFailure(results []TestResult) bool {
	for _, result := range results {
		if result.Status == StatusFailed {
			return true
		}
	}
	return false
}

type boundedBuffer struct {
	mu        sync.Mutex
	limit     int
	value     bytes.Buffer
	truncated bool
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	written := len(data)
	remaining := b.limit - b.value.Len()
	if remaining <= 0 {
		b.truncated = true
		return written, nil
	}
	if len(data) > remaining {
		_, _ = b.value.Write(data[:remaining])
		b.truncated = true
		return written, nil
	}
	_, _ = b.value.Write(data)
	return written, nil
}

func (b *boundedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.value.Bytes()...)
}

func (b *boundedBuffer) Truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}
