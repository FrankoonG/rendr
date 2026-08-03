package tier1

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

const (
	tier1CommandWaitDelay      = 5 * time.Second
	tier1ProcessCleanupTimeout = 2 * time.Second
	processTeardownEvidence    = "process_teardown"
)

var errUnsafeProcessTeardown = errors.New("unsafe process teardown")

func newTier1Command(ctx context.Context, name string, args ...string) (*exec.Cmd, *processTree) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = tier1CommandWaitDelay
	return cmd, configureProcessTree(cmd)
}

func runTier1Command(cmd *exec.Cmd, tree *processTree) error {
	runErr := cmd.Run()
	cleanupErr := tree.cleanup(tier1ProcessCleanupTimeout)
	if cleanupErr == nil {
		return runErr
	}
	unsafeErr := fmt.Errorf("%w: %v", errUnsafeProcessTeardown, cleanupErr)
	if runErr == nil {
		return unsafeErr
	}
	return errors.Join(runErr, unsafeErr)
}
