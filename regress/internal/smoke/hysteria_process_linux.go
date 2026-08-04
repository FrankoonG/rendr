//go:build linux

package smoke

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const hysteriaProcessPollInterval = 10 * time.Millisecond

func configureHysteriaProcessContainment(cmd *exec.Cmd) (*hysteriaProcessContainment, error) {
	if cmd == nil {
		return nil, fmt.Errorf("configure process containment: command is nil")
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	if !cmd.SysProcAttr.Setsid {
		cmd.SysProcAttr.Setpgid = true
		cmd.SysProcAttr.Pgid = 0
	}

	kill := func() error {
		if cmd.Process == nil || cmd.Process.Pid <= 0 {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	confirm := func(limit time.Duration) error {
		if cmd.Process == nil || cmd.Process.Pid <= 0 {
			return fmt.Errorf("process group identity is unavailable")
		}
		processGroup := -cmd.Process.Pid
		deadline := time.Now().Add(max(limit, 0))
		for {
			err := syscall.Kill(processGroup, 0)
			switch {
			case errors.Is(err, syscall.ESRCH):
				return nil
			case err != nil && !errors.Is(err, syscall.EPERM):
				return fmt.Errorf("inspect process group %d: %w", -processGroup, err)
			case !time.Now().Before(deadline):
				return fmt.Errorf("process group %d survived cleanup deadline", -processGroup)
			}
			time.Sleep(hysteriaProcessPollInterval)
		}
	}

	cmd.Cancel = kill
	return &hysteriaProcessContainment{kill: kill, confirm: confirm}, nil
}
