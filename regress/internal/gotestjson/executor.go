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
	// DefaultMaxJSONBytes bounds the combined JSON stdout/stderr capture.
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
	// process-group cancellation.
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
}

// Run executes a request with the default Executor.
func Run(ctx context.Context, request Request) (Result, error) {
	return Executor{}.Run(ctx, request)
}

// Run executes go test -json and validates the result. A represented test
// failure is reported as IssueTestFailed; a non-zero command without such a
// failure additionally reports IssueCommandFailed.
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
	configureProcessGroup(cmd)

	capture := &boundedBuffer{limit: maxJSONBytes}
	cmd.Stdout = capture
	cmd.Stderr = capture
	started := time.Now()
	runErr := cmd.Run()
	duration := time.Since(started)

	result, _ := e.Parser.Parse(bytes.NewReader(capture.Bytes()), request.Expected)
	result.Command = command
	result.Duration = duration
	issues := append([]Issue(nil), result.Issues...)

	if capture.Truncated() {
		result.CaptureTruncated = true
		issues = append(issues, Issue{
			Code:   IssueCaptureLimit,
			Detail: fmt.Sprintf("combined go test JSON exceeded %d bytes", maxJSONBytes),
		})
	}
	if runErr != nil {
		switch {
		case ctx.Err() != nil:
			issues = append(issues, Issue{Code: IssueCommandCanceled, Detail: ctx.Err().Error()})
		case !hasRepresentedTestFailure(result.Tests):
			issues = append(issues, Issue{Code: IssueCommandFailed, Detail: runErr.Error()})
		}
	}

	result.Issues = issues
	return result, resultError(issues)
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
