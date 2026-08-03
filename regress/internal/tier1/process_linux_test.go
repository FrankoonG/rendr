//go:build linux

package tier1

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/gotestjson"
)

func TestRunGoCancellationKillsCompiledTestProcessTree(t *testing.T) {
	root := t.TempDir()
	pidFile := filepath.Join(root, "pids")
	writeTestModule(t, root)
	t.Setenv("RENDR_TIER1_PID_FILE", pidFile)

	if err := runGo(context.Background(), root, "test", "-run", "^$", "."); err != nil {
		t.Fatalf("warm test build: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runGo(ctx, root, "test", "-count=1", "-run", "^TestBlocked$", ".")
	}()

	processes := waitForProcessIDs(t, pidFile, 5*time.Second)
	assertContainedProcessGroup(t, processes)
	started := time.Now()
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled go test returned nil")
		}
		if errors.Is(err, errUnsafeProcessTeardown) {
			t.Fatalf("process group cleanup was unsafe: %v", err)
		}
	case <-time.After(tier1CommandWaitDelay + tier1ProcessCleanupTimeout + time.Second):
		t.Fatal("canceled go test exceeded bounded wait and cleanup")
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("canceled go test returned after %s, want <=3s", elapsed)
	}

	for _, pid := range processes.uniquePIDs() {
		waitForProcessExit(t, pid, 3*time.Second)
	}
}

func TestGoTestExecutorCancellationKillsCompiledTestProcessTree(t *testing.T) {
	root := t.TempDir()
	pidFile := filepath.Join(root, "pids")
	writeTestModule(t, root)
	t.Setenv("RENDR_TIER1_PID_FILE", pidFile)

	if err := runGo(context.Background(), root, "test", "-run", "^$", "."); err != nil {
		t.Fatalf("warm test build: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type executorResult struct {
		result gotestjson.Result
		err    error
	}
	done := make(chan executorResult, 1)
	go func() {
		result, err := tier1GoTestExecutor.Run(ctx, gotestjson.Request{
			Dir:         root,
			Package:     ".",
			Pattern:     "^TestBlocked$",
			Expected:    []gotestjson.Expectation{{Name: "TestBlocked"}},
			TestTimeout: time.Minute,
		})
		done <- executorResult{result: result, err: err}
	}()

	processes := waitForProcessIDs(t, pidFile, 5*time.Second)
	assertContainedProcessGroup(t, processes)
	started := time.Now()
	cancel()

	select {
	case got := <-done:
		if got.err == nil || !got.result.HasIssue(gotestjson.IssueCommandCanceled) {
			t.Fatalf("canceled executor result = %+v, err = %v", got.result, got.err)
		}
	case <-time.After(tier1CommandWaitDelay + time.Second):
		t.Fatal("canceled go test executor exceeded bounded wait")
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("canceled go test executor returned after %s, want <=3s", elapsed)
	}
	for _, pid := range processes.uniquePIDs() {
		waitForProcessExit(t, pid, 3*time.Second)
	}
}

type containmentProcesses struct {
	groupLeader int
	parent      int
	test        int
}

func (p containmentProcesses) uniquePIDs() []int {
	seen := make(map[int]bool, 3)
	pids := make([]int, 0, 3)
	for _, pid := range []int{p.groupLeader, p.parent, p.test} {
		if pid > 0 && !seen[pid] {
			seen[pid] = true
			pids = append(pids, pid)
		}
	}
	return pids
}

func assertContainedProcessGroup(t *testing.T, processes containmentProcesses) {
	t.Helper()
	if processes.groupLeader <= 0 || processes.parent <= 0 || processes.test <= 0 || processes.groupLeader == processes.test {
		t.Fatalf("published processes = %+v, want go group leader and compiled test", processes)
	}
	for _, pid := range processes.uniquePIDs() {
		pgid, err := syscall.Getpgid(pid)
		if err != nil {
			t.Fatalf("get process group for pid %d: %v", pid, err)
		}
		if pgid != processes.groupLeader {
			t.Fatalf("pid %d process group = %d, want go parent group %d", pid, pgid, processes.groupLeader)
		}
	}
}

func writeTestModule(t *testing.T, root string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/tier1containment\n\ngo 1.26.3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := `package containment

import (
	"fmt"
	"os"
	"syscall"
	"testing"
)

func TestBlocked(t *testing.T) {
	pidFile := os.Getenv("RENDR_TIER1_PID_FILE")
	if pidFile == "" {
		t.Fatal("RENDR_TIER1_PID_FILE is empty")
	}
	value := fmt.Sprintf("%d %d %d", syscall.Getpgrp(), os.Getppid(), os.Getpid())
	if err := os.WriteFile(pidFile, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
	select {}
}
`
	if err := os.WriteFile(filepath.Join(root, "containment_test.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
}

func waitForProcessIDs(t *testing.T, path string, timeout time.Duration) containmentProcesses {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			fields := strings.Fields(string(data))
			if len(fields) == 3 {
				pids := make([]int, 3)
				valid := true
				for i, field := range fields {
					pids[i], err = strconv.Atoi(field)
					valid = valid && err == nil && pids[i] > 0
				}
				if valid {
					return containmentProcesses{groupLeader: pids[0], parent: pids[1], test: pids[2]}
				}
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("read pid file: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("compiled test did not publish process IDs within %s", timeout)
	return containmentProcesses{}
}

func waitForProcessExit(t *testing.T, pid int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		if err != nil && !errors.Is(err, syscall.EPERM) {
			t.Fatalf("probe pid %d: %v", pid, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(fmt.Sprintf("pid %d survived process-tree cleanup", pid))
}
