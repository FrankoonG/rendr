//go:build linux

package smoke

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestHysteriaCancellationKillsPipeHoldingDescendantGroup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pidFile := filepath.Join(t.TempDir(), "descendant.pid")
	p := startHysteriaTestProcess(t, ctx, "HYSTERIA_RELAY_DESCENDANT_PID_FILE="+pidFile)
	descendantPID := readHysteriaDescendantPID(t, pidFile, time.Second)
	rootPID := p.cmd.Process.Pid
	t.Cleanup(func() {
		_ = syscall.Kill(-rootPID, syscall.SIGKILL)
		_ = syscall.Kill(descendantPID, syscall.SIGKILL)
	})

	rootGroup, err := syscall.Getpgid(rootPID)
	if err != nil {
		t.Fatalf("get wrapper process group: %v", err)
	}
	descendantGroup, err := syscall.Getpgid(descendantPID)
	if err != nil {
		t.Fatalf("get descendant process group: %v", err)
	}
	if rootGroup != rootPID || descendantGroup != rootGroup {
		t.Fatalf("process groups: root pid=%d group=%d descendant pid=%d group=%d", rootPID, rootGroup, descendantPID, descendantGroup)
	}

	type outcome struct {
		log string
		err error
	}
	returned := make(chan outcome, 1)
	go func() {
		log, err := runHysteriaSpeedtestProcess(ctx, p, 0, nil, time.Millisecond, 2*time.Second)
		returned <- outcome{log: log, err: err}
	}()
	cancel()

	select {
	case got := <-returned:
		if !errors.Is(got.err, context.Canceled) {
			t.Fatalf("cancellation error = %v, want context.Canceled", got.err)
		}
		var mustStop interface {
			error
			MustStop() bool
		}
		if errors.As(got.err, &mustStop) && mustStop.MustStop() {
			t.Fatalf("confirmed descendant cleanup requested MustStop: %v", got.err)
		}
		if got.log == "" {
			t.Fatal("joined descendant process log is empty")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation remained blocked by descendant-held pipes")
	}

	assertHysteriaProcessJoined(t, p)
	waitForHysteriaProcessExit(t, descendantPID, time.Second)
	if err := syscall.Kill(-rootGroup, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("process group %d survived confirmed teardown: %v", rootGroup, err)
	}
}

func readHysteriaDescendantPID(t *testing.T, path string, limit time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(limit)
	for {
		contents, err := os.ReadFile(path)
		if err == nil {
			pid, parseErr := strconv.Atoi(string(contents))
			if parseErr != nil || pid <= 0 {
				t.Fatalf("parse descendant pid %q: %v", contents, parseErr)
			}
			return pid
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("read descendant pid: %v", err)
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("descendant pid was not published within %s", limit)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForHysteriaProcessExit(t *testing.T, pid int, limit time.Duration) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		if err != nil && !errors.Is(err, syscall.EPERM) {
			t.Fatalf("inspect descendant pid %d: %v", pid, err)
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("descendant pid %d survived cleanup", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
