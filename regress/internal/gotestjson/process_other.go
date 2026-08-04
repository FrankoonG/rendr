//go:build !linux

package gotestjson

import (
	"os/exec"
	"time"
)

type unsupportedProcessContainment struct{}

func configureProcessContainment(_ *exec.Cmd) (processContainment, error) {
	return unsupportedProcessContainment{}, nil
}

func (unsupportedProcessContainment) cleanup(_ time.Duration, _ bool) processCleanupResult {
	return processCleanupResult{evidence: ProcessCleanupEvidence{
		Method: ProcessContainmentNone,
	}}
}
