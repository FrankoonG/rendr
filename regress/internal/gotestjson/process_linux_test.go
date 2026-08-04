//go:build linux

package gotestjson

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func configureEscapingDescendant(cmd *exec.Cmd, escape string) {
	switch escape {
	case "setsid":
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	case "setpgid":
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}
}

func testLinuxProcessGroupCleanup(t *testing.T) {
	t.Helper()

	containments := []struct {
		name           string
		containProcess func(*exec.Cmd) (processContainment, error)
		wantMethod     ProcessContainmentMethod
	}{
		{name: "preferred", containProcess: configureProcessContainment},
		{
			name: "forced fallback",
			containProcess: func(cmd *exec.Cmd) (processContainment, error) {
				return configureLinuxProcessContainment(cmd, false)
			},
			wantMethod: ProcessContainmentSubreaper,
		},
	}
	for _, containment := range containments {
		for _, escape := range []string{"setsid", "setpgid"} {
			t.Run(containment.name+" "+escape+" descendant is detected and terminated", func(t *testing.T) {
				pidFile := filepath.Join(t.TempDir(), "descendant.pid")
				executor := syntheticExecutor()
				executor.WaitDelay = 2 * time.Second
				executor.containProcess = containment.containProcess
				request := syntheticRequest(t, "leak-descendant", required("TestOne"))
				request.Env = append(
					request.Env,
					helperDescendantPIDFileEnv+"="+pidFile,
					helperDescendantEscapeEnv+"="+escape,
				)

				result, err := executor.Run(context.Background(), request)
				assertValidationError(t, err)
				if !result.HasIssue(IssueProcessLeak) {
					t.Fatalf("issues=%+v, want typed process leak", result.Issues)
				}
				if result.HasIssue(IssueProcessCleanup) {
					t.Fatalf("issues=%+v, descendant teardown failed", result.Issues)
				}
				evidence := result.ProcessCleanup
				if !evidence.LeakDetected ||
					evidence.DescendantCount < 1 ||
					!evidence.TerminationConfirmed ||
					(evidence.Method != ProcessContainmentCgroupV2 &&
						evidence.Method != ProcessContainmentSubreaper) {
					t.Fatalf("process cleanup evidence=%+v", evidence)
				}
				if containment.wantMethod != "" && evidence.Method != containment.wantMethod {
					t.Fatalf("containment method=%q, want %q", evidence.Method, containment.wantMethod)
				}
				t.Logf("containment=%s escape=%s termination confirmed", evidence.Method, escape)

				contents, readErr := os.ReadFile(pidFile)
				if readErr != nil {
					t.Fatal(readErr)
				}
				pid, parseErr := strconv.Atoi(string(contents))
				if parseErr != nil {
					t.Fatalf("parse descendant PID %q: %v", contents, parseErr)
				}
				if signalErr := syscall.Kill(pid, 0); !errors.Is(signalErr, syscall.ESRCH) {
					_ = syscall.Kill(pid, syscall.SIGKILL)
					t.Fatalf("escaping descendant PID %d still exists after cleanup: %v", pid, signalErr)
				}
			})
		}
	}

	for _, escape := range []string{"setsid", "setpgid"} {
		t.Run("cancellation terminates forced fallback "+escape+" descendant", func(t *testing.T) {
			pidFile := filepath.Join(t.TempDir(), "descendant.pid")
			executor := syntheticExecutor()
			executor.WaitDelay = 2 * time.Second
			executor.containProcess = func(cmd *exec.Cmd) (processContainment, error) {
				return configureLinuxProcessContainment(cmd, false)
			}
			request := syntheticRequest(t, "hang-descendant", required("TestOne"))
			request.Env = append(
				request.Env,
				helperDescendantPIDFileEnv+"="+pidFile,
				helperDescendantEscapeEnv+"="+escape,
			)
			ctx, cancel := context.WithCancel(context.Background())
			type outcome struct {
				result Result
				err    error
			}
			done := make(chan outcome, 1)
			go func() {
				result, err := executor.Run(ctx, request)
				done <- outcome{result: result, err: err}
			}()

			pid := readPIDEventually(t, pidFile, 2*time.Second)
			cancel()
			var run outcome
			select {
			case run = <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("canceled escaping-descendant invocation did not return")
			}
			assertValidationError(t, run.err)
			if !run.result.HasIssue(IssueCommandCanceled) ||
				run.result.HasIssue(IssueProcessLeak) ||
				run.result.HasIssue(IssueProcessCleanup) {
				t.Fatalf("cancellation issues=%+v", run.result.Issues)
			}
			if evidence := run.result.ProcessCleanup; evidence.Method != ProcessContainmentSubreaper ||
				!evidence.TerminationConfirmed {
				t.Fatalf("cancellation cleanup evidence=%+v", evidence)
			}
			if signalErr := syscall.Kill(pid, 0); !errors.Is(signalErr, syscall.ESRCH) {
				_ = syscall.Kill(pid, syscall.SIGKILL)
				t.Fatalf("canceled escaping descendant PID %d still exists: %v", pid, signalErr)
			}
		})
	}

	t.Run("process group termination failure is typed", func(t *testing.T) {
		if err := killProcessGroup(-1); err == nil {
			t.Fatal("killProcessGroup accepted an invalid process group ID")
		}
	})
}

func readPIDEventually(t *testing.T, path string, timeout time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		contents, err := os.ReadFile(path)
		if err == nil {
			pid, parseErr := strconv.Atoi(string(contents))
			if parseErr != nil {
				t.Fatalf("parse descendant PID %q: %v", contents, parseErr)
			}
			return pid
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("descendant PID file %s was not created", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
