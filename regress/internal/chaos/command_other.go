//go:build !linux

package chaos

import (
	"os/exec"
	"time"
)

func configureExternalCommand(_ *exec.Cmd) {}

func cleanupExternalCommand(_ *exec.Cmd, _ time.Duration) error { return nil }
