package gotestjson

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	helperScenarioEnv          = "GOTESTJSON_HELPER_SCENARIO"
	helperDescendantEnv        = "GOTESTJSON_HELPER_DESCENDANT"
	helperDescendantPIDFileEnv = "GOTESTJSON_HELPER_DESCENDANT_PID_FILE"
	helperDescendantEscapeEnv  = "GOTESTJSON_HELPER_DESCENDANT_ESCAPE"
)

func TestBuildArgs(t *testing.T) {
	request := Request{
		Package:     "./internal/matrix/...",
		Pattern:     "^(?:TestOne|TestTwo)$",
		TestTimeout: 6 * time.Minute,
		Race:        true,
	}
	want := []string{
		"test", "-json", "-count=1", "-run", "^(?:TestOne|TestTwo)$",
		"-race", "-timeout", "6m0s", "./internal/matrix/...",
	}
	if got := buildArgs(request); !reflect.DeepEqual(got, want) {
		t.Fatalf("buildArgs()=%#v, want %#v", got, want)
	}
}

func TestExecutorReturnsOrderedSyntheticResults(t *testing.T) {
	executor := syntheticExecutor()
	result, err := executor.Run(context.Background(), syntheticRequest(t, "pass", required("TestFirst", "TestSecond")))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := resultNames(result.Tests), []string{"TestFirst", "TestSecond"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("results=%v, want %v", got, want)
	}
	assertTestResult(t, result.Tests[0], StatusPassed, 100*time.Millisecond, "first output\n")
	assertTestResult(t, result.Tests[1], StatusPassed, 200*time.Millisecond, "second output\n")
	if len(result.Command) == 0 || result.Command[0] != "synthetic-go" {
		t.Fatalf("Command=%v", result.Command)
	}
	if result.Duration <= 0 {
		t.Fatalf("Duration=%s, want positive", result.Duration)
	}

	result, err = syntheticExecutor().Run(context.Background(), syntheticRequest(t, "stderr-pass", required("TestOne")))
	if err != nil || !result.Passed() {
		t.Fatalf("stderr diagnostics invalidated JSON: result=%+v err=%v", result, err)
	}
	if result.HasIssue(IssueMalformedJSON) || !strings.Contains(result.CommandOutput, "go: downloading synthetic/dependency") {
		t.Fatalf("stderr result=%+v", result)
	}
}

func TestExecutorClassifiesNonzeroExitByRepresentedFailure(t *testing.T) {
	t.Run("represented test failure", func(t *testing.T) {
		result, err := syntheticExecutor().Run(
			context.Background(),
			syntheticRequest(t, "test-fail", required("TestOne")),
		)
		assertValidationError(t, err)
		if !result.HasIssue(IssueTestFailed) {
			t.Fatalf("issues=%+v, want test failure", result.Issues)
		}
		if result.HasIssue(IssueCommandFailed) {
			t.Fatalf("represented failure also reported command failure: %+v", result.Issues)
		}
	})

	t.Run("unrepresented command failure", func(t *testing.T) {
		result, err := syntheticExecutor().Run(
			context.Background(),
			syntheticRequest(t, "command-fail", required("TestOne")),
		)
		assertValidationError(t, err)
		if !result.HasIssue(IssueCommandFailed) {
			t.Fatalf("issues=%+v, want command failure", result.Issues)
		}
		if result.HasIssue(IssueTestFailed) {
			t.Fatalf("passing test reported failed: %+v", result.Issues)
		}
	})
}

func TestExecutorRejectsMalformedAndTruncatedCapture(t *testing.T) {
	t.Run("malformed stream", func(t *testing.T) {
		result, err := syntheticExecutor().Run(
			context.Background(),
			syntheticRequest(t, "malformed", required("TestOne")),
		)
		assertValidationError(t, err)
		if !result.HasIssue(IssueMalformedJSON) {
			t.Fatalf("issues=%+v, want malformed JSON", result.Issues)
		}
	})

	t.Run("bounded capture", func(t *testing.T) {
		executor := syntheticExecutor()
		executor.MaxJSONBytes = 256
		result, err := executor.Run(
			context.Background(),
			syntheticRequest(t, "large", required("TestOne")),
		)
		assertValidationError(t, err)
		if !result.CaptureTruncated || !result.HasIssue(IssueCaptureLimit) {
			t.Fatalf("result=%+v, want capture limit", result)
		}
	})
}

func TestExecutorCancellationIsBounded(t *testing.T) {
	executor := syntheticExecutor()
	executor.WaitDelay = 100 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()

	started := time.Now()
	result, err := executor.Run(ctx, syntheticRequest(t, "hang", required("TestOne")))
	elapsed := time.Since(started)
	assertValidationError(t, err)
	if !result.HasIssue(IssueCommandCanceled) {
		t.Fatalf("issues=%+v, want command canceled", result.Issues)
	}
	if result.HasIssue(IssueProcessLeak) || result.HasIssue(IssueProcessCleanup) {
		t.Fatalf("cancellation left process cleanup issues: %+v", result.Issues)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("canceled executor returned after %s, want <=3s", elapsed)
	}

	t.Run("cleanup failure invalidates a passing command", func(t *testing.T) {
		executor := syntheticExecutor()
		executor.containProcess = func(*exec.Cmd) (processContainment, error) {
			return staticProcessContainment{result: processCleanupResult{
				evidence: ProcessCleanupEvidence{
					Method:          ProcessContainmentSubreaper,
					LeakDetected:    true,
					DescendantCount: 1,
				},
				err: errors.New("synthetic reap failure"),
			}}, nil
		}
		result, err := executor.Run(
			context.Background(),
			syntheticRequest(t, "pass", required("TestFirst", "TestSecond")),
		)
		assertValidationError(t, err)
		if !result.HasIssue(IssueProcessLeak) || !result.HasIssue(IssueProcessCleanup) {
			t.Fatalf("issues=%+v, want process leak and cleanup failure", result.Issues)
		}
	})

	testLinuxProcessGroupCleanup(t)
}

type staticProcessContainment struct {
	result processCleanupResult
}

func (s staticProcessContainment) cleanup(time.Duration, bool) processCleanupResult {
	return s.result
}

func TestExecutorRejectsInvalidRequestWithoutStarting(t *testing.T) {
	started := false
	executor := Executor{
		commandContext: func(context.Context, string, ...string) *exec.Cmd {
			started = true
			return nil
		},
	}
	result, err := executor.Run(context.Background(), Request{
		Expected: required("TestOne"),
	})
	assertValidationError(t, err)
	if started {
		t.Fatal("invalid request started a command")
	}
	if !result.HasIssue(IssueInvalidConfig) {
		t.Fatalf("issues=%+v, want invalid config", result.Issues)
	}
}

func TestExecutorFailsClosedWhenContainmentCannotBeConfigured(t *testing.T) {
	executor := syntheticExecutor()
	executor.containProcess = func(*exec.Cmd) (processContainment, error) {
		return nil, errors.New("synthetic containment failure")
	}
	result, err := executor.Run(
		context.Background(),
		syntheticRequest(t, "pass", required("TestFirst", "TestSecond")),
	)
	assertValidationError(t, err)
	if !result.HasIssue(IssueProcessContainment) || result.HasIssue(IssueZeroTests) {
		t.Fatalf("issues=%+v, want only typed containment failure", result.Issues)
	}
}

func TestExecutorHelperProcess(t *testing.T) {
	if os.Getenv(helperDescendantEnv) != "" {
		time.Sleep(10 * time.Minute)
		os.Exit(96)
	}
	scenario := os.Getenv(helperScenarioEnv)
	if scenario == "" {
		return
	}

	encoder := json.NewEncoder(os.Stdout)
	emit := func(event testEvent) {
		if err := encoder.Encode(event); err != nil {
			os.Exit(97)
		}
	}

	switch scenario {
	case "pass":
		emit(testEvent{Action: "run", Package: "synthetic/pkg", Test: "TestSecond"})
		emit(testEvent{Action: "output", Package: "synthetic/pkg", Test: "TestSecond", Output: "second output\n"})
		emit(testEvent{Action: "pass", Package: "synthetic/pkg", Test: "TestSecond", Elapsed: 0.2})
		emit(testEvent{Action: "run", Package: "synthetic/pkg", Test: "TestFirst"})
		emit(testEvent{Action: "output", Package: "synthetic/pkg", Test: "TestFirst", Output: "first output\n"})
		emit(testEvent{Action: "pass", Package: "synthetic/pkg", Test: "TestFirst", Elapsed: 0.1})
		os.Exit(0)
	case "stderr-pass":
		_, _ = os.Stderr.WriteString("go: downloading synthetic/dependency\n")
		emit(testEvent{Action: "run", Test: "TestOne"})
		emit(testEvent{Action: "pass", Test: "TestOne", Elapsed: 0.01})
		os.Exit(0)
	case "test-fail":
		emit(testEvent{Action: "run", Test: "TestOne"})
		emit(testEvent{Action: "output", Test: "TestOne", Output: "assertion failed\n"})
		emit(testEvent{Action: "fail", Test: "TestOne", Elapsed: 0.01})
		os.Exit(1)
	case "command-fail":
		emit(testEvent{Action: "run", Test: "TestOne"})
		emit(testEvent{Action: "pass", Test: "TestOne", Elapsed: 0.01})
		os.Exit(2)
	case "malformed":
		_, _ = os.Stdout.WriteString("{\"Action\":\"run\",\"Test\":\"TestOne\"}\n")
		_, _ = os.Stdout.WriteString("{\"Action\":\"pass\",\"Test\":\"TestOne\"")
		os.Exit(0)
	case "large":
		emit(testEvent{Action: "run", Test: "TestOne"})
		for range 20 {
			emit(testEvent{Action: "output", Test: "TestOne", Output: strings.Repeat("x", 64)})
		}
		emit(testEvent{Action: "pass", Test: "TestOne"})
		os.Exit(0)
	case "hang":
		emit(testEvent{Action: "run", Test: "TestOne"})
		time.Sleep(10 * time.Minute)
		os.Exit(98)
	case "hang-descendant", "leak-descendant":
		pidFile := os.Getenv(helperDescendantPIDFileEnv)
		if pidFile == "" {
			os.Exit(95)
		}
		startEscapingDescendant(pidFile)
		emit(testEvent{Action: "run", Test: "TestOne"})
		if scenario == "hang-descendant" {
			time.Sleep(10 * time.Minute)
			os.Exit(91)
		}
		emit(testEvent{Action: "pass", Test: "TestOne", Elapsed: 0.01})
		os.Exit(0)
	default:
		os.Exit(99)
	}
}

func startEscapingDescendant(pidFile string) {
	child := exec.Command(os.Args[0], "-test.run=^TestExecutorHelperProcess$")
	child.Env = append(os.Environ(), helperDescendantEnv+"=1")
	configureEscapingDescendant(child, os.Getenv(helperDescendantEscapeEnv))
	if err := child.Start(); err != nil {
		os.Exit(94)
	}
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(child.Process.Pid)), 0o600); err != nil {
		_ = child.Process.Kill()
		_, _ = child.Process.Wait()
		os.Exit(93)
	}
	if err := child.Process.Release(); err != nil {
		_ = child.Process.Kill()
		os.Exit(92)
	}
}

func syntheticExecutor() Executor {
	return Executor{
		GoBinary: "synthetic-go",
		commandContext: func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
			return exec.CommandContext(ctx, os.Args[0], "-test.run=^TestExecutorHelperProcess$")
		},
	}
}

func syntheticRequest(t *testing.T, scenario string, expected []Expectation) Request {
	t.Helper()
	return Request{
		Dir:      t.TempDir(),
		Package:  "./synthetic/package",
		Pattern:  "^TestSynthetic$",
		Expected: expected,
		Env:      []string{helperScenarioEnv + "=" + scenario},
	}
}
