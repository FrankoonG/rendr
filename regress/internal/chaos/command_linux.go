//go:build linux

package chaos

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func configureExternalCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
}

func cleanupExternalCommand(cmd *exec.Cmd, limit time.Duration) error {
	if cmd == nil || cmd.Process == nil || cmd.Process.Pid <= 0 {
		return nil
	}
	processGroup := -cmd.Process.Pid
	if err := syscall.Kill(processGroup, 0); errors.Is(err, syscall.ESRCH) {
		return nil
	} else if err != nil && !errors.Is(err, syscall.EPERM) {
		return fmt.Errorf("inspect command process group: %w", err)
	}
	if err := syscall.Kill(processGroup, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("terminate command process group: %w", err)
	}

	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(processGroup, 0); errors.Is(err, syscall.ESRCH) {
			return nil
		} else if err != nil && !errors.Is(err, syscall.EPERM) {
			return fmt.Errorf("verify command process group cleanup: %w", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("command process group %d survived cleanup deadline %s", -processGroup, limit)
}
