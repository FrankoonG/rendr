//go:build !linux

package smoke

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func configureHysteriaProcessContainment(cmd *exec.Cmd) (*hysteriaProcessContainment, error) {
	if cmd == nil {
		return nil, fmt.Errorf("configure process containment: command is nil")
	}
	kill := func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := cmd.Process.Kill()
		if errors.Is(err, os.ErrInvalid) || errors.Is(err, syscall.EINVAL) {
			return os.ErrProcessDone
		}
		return err
	}
	confirm := func(time.Duration) error {
		if cmd.ProcessState == nil {
			return fmt.Errorf("direct process Wait completion is unavailable")
		}
		return nil
	}

	cmd.Cancel = kill
	return &hysteriaProcessContainment{kill: kill, confirm: confirm}, nil
}
