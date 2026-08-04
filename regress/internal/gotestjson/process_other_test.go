//go:build !linux

package gotestjson

import (
	"os/exec"
	"testing"
)

func configureEscapingDescendant(_ *exec.Cmd, _ string) {}

func testLinuxProcessGroupCleanup(_ *testing.T) {}
