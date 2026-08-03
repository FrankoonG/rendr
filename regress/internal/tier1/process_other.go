//go:build !linux

package tier1

import (
	"os/exec"
	"time"
)

type processTree struct{}

func configureProcessTree(_ *exec.Cmd) *processTree {
	return &processTree{}
}

func (*processTree) cleanup(time.Duration) error {
	return nil
}
