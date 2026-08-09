//go:build !linux

package platform

import "runtime"

func lockExecutionThread() func() { return func() {} }

type executionContextLease struct {
	Identity ExecutionContext
}

func (lease *executionContextLease) Close() error { return nil }

func acquireExecutionContext() (*executionContextLease, error) {
	return &executionContextLease{Identity: ExecutionContext{
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		ProbeRevision: ProbeRevision,
	}}, nil
}
