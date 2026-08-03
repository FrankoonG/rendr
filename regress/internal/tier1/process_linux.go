//go:build linux

package tier1

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const processExitPollInterval = 10 * time.Millisecond

type processTree struct {
	cmd *exec.Cmd
}

func configureProcessTree(cmd *exec.Cmd) *processTree {
	tree := &processTree{cmd: cmd}
	if cmd == nil {
		return tree
	}
	// The go command and every compiled test process inherit this group.
	// Killing the group avoids leaving a test binary behind when the case
	// context only reaches the go parent first.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = tree.cancel
	return tree
}

func (p *processTree) cancel() error {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return os.ErrProcessDone
	}
	err := syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}

func (p *processTree) cleanup(timeout time.Duration) error {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return nil
	}
	pgid := p.cmd.Process.Pid
	if pgid <= 0 {
		return nil
	}

	if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return fmt.Errorf("kill process group %d: %w", pgid, err)
	}

	deadline := time.Now().Add(timeout)
	for {
		err := syscall.Kill(-pgid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		if err != nil && !errors.Is(err, syscall.EPERM) {
			return fmt.Errorf("probe process group %d: %w", pgid, err)
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("process group %d remained after cleanup limit %s", pgid, timeout)
		}
		time.Sleep(processExitPollInterval)
	}
}
