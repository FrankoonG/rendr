package platform

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
	"time"
)

func TestClassifyProbeErrorErrnoTable(t *testing.T) {
	at := time.Date(2026, time.August, 9, 1, 2, 3, 0, time.UTC)
	tests := []struct {
		name      string
		errno     syscall.Errno
		state     FeatureState
		reason    FeatureReason
		retryable bool
	}{
		{name: "EPERM", errno: syscall.EPERM, state: FeaturePermissionDenied, reason: ReasonPermissionDenied},
		{name: "EACCES", errno: syscall.EACCES, state: FeaturePermissionDenied, reason: ReasonPermissionDenied},
		{name: "ENOPROTOOPT", errno: syscall.ENOPROTOOPT, state: FeatureUnsupported, reason: ReasonPrimitiveUnsupported},
		{name: "EOPNOTSUPP", errno: syscall.EOPNOTSUPP, state: FeatureUnsupported, reason: ReasonPrimitiveUnsupported},
		{name: "ENOSYS", errno: syscall.ENOSYS, state: FeatureUnsupported, reason: ReasonPrimitiveUnsupported},
		{name: "ENOTTY", errno: syscall.ENOTTY, state: FeatureUnsupported, reason: ReasonPrimitiveUnsupported},
		{name: "ENOENT", errno: syscall.ENOENT, state: FeatureUnsupported, reason: ReasonDeviceUnavailable},
		{name: "ENODEV", errno: syscall.ENODEV, state: FeatureUnsupported, reason: ReasonDeviceUnavailable},
		{name: "EMFILE", errno: syscall.EMFILE, state: FeatureProbeFailed, reason: ReasonResourceExhausted, retryable: true},
		{name: "ENFILE", errno: syscall.ENFILE, state: FeatureProbeFailed, reason: ReasonResourceExhausted, retryable: true},
		{name: "ENOMEM", errno: syscall.ENOMEM, state: FeatureProbeFailed, reason: ReasonResourceExhausted, retryable: true},
		{name: "ENOBUFS", errno: syscall.ENOBUFS, state: FeatureProbeFailed, reason: ReasonResourceExhausted, retryable: true},
		{name: "ENOSPC", errno: syscall.ENOSPC, state: FeatureProbeFailed, reason: ReasonResourceExhausted, retryable: true},
		{name: "EAGAIN", errno: syscall.EAGAIN, state: FeatureProbeFailed, reason: ReasonSyscallFailed, retryable: true},
		{name: "EINTR", errno: syscall.EINTR, state: FeatureProbeFailed, reason: ReasonSyscallFailed, retryable: true},
		{name: "EBUSY", errno: syscall.EBUSY, state: FeatureProbeFailed, reason: ReasonSyscallFailed, retryable: true},
		{name: "unmapped", errno: syscall.EINVAL, state: FeatureProbeFailed, reason: ReasonSyscallFailed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			forms := []struct {
				name string
				err  error
			}{
				{name: "direct", err: test.errno},
				{name: "wrapped", err: fmt.Errorf("probe failed: %w", test.errno)},
			}
			for _, form := range forms {
				t.Run(form.name, func(t *testing.T) {
					evidence, err := classifyProbeError(FeatureTUNOpen, at, SourceRuntimeSyscall, form.err)
					if err != nil {
						t.Fatalf("classifyProbeError() error = %v", err)
					}
					assertClassifiedEvidence(t, evidence, at, test.state, test.reason, test.retryable, test.errno)
				})
			}
		})
	}
}

func TestClassifyProbeErrorNonErrno(t *testing.T) {
	at := time.Date(2026, time.August, 9, 1, 2, 3, 0, time.UTC)
	evidence, err := classifyProbeError(FeatureTUNOpen, at, SourceRuntimeSyscall, errors.New("round trip mismatch"))
	if err != nil {
		t.Fatalf("classifyProbeError() error = %v", err)
	}
	assertClassifiedEvidence(t, evidence, at, FeatureProbeFailed, ReasonSyscallFailed, false, 0)
}

func TestClassifyProbeErrorRejectsNil(t *testing.T) {
	evidence, err := classifyProbeError(FeatureTUNOpen, time.Now(), SourceRuntimeSyscall, nil)
	if err == nil {
		t.Fatal("classifyProbeError() accepted a nil error")
	}
	if evidence != (FeatureEvidence{}) {
		t.Fatalf("classifyProbeError() evidence = %#v, want zero value", evidence)
	}
}

func assertClassifiedEvidence(t *testing.T, evidence FeatureEvidence, at time.Time, state FeatureState, reason FeatureReason, retryable bool, errno syscall.Errno) {
	t.Helper()
	if evidence.ID != FeatureTUNOpen {
		t.Errorf("ID = %q, want %q", evidence.ID, FeatureTUNOpen)
	}
	if evidence.State != state {
		t.Errorf("State = %q, want %q", evidence.State, state)
	}
	if evidence.Reason != reason {
		t.Errorf("Reason = %q, want %q", evidence.Reason, reason)
	}
	if !evidence.ProbedAt.Equal(at) {
		t.Errorf("ProbedAt = %v, want %v", evidence.ProbedAt, at)
	}
	if evidence.Source != SourceRuntimeSyscall {
		t.Errorf("Source = %q, want %q", evidence.Source, SourceRuntimeSyscall)
	}
	if evidence.Retryable != retryable {
		t.Errorf("Retryable = %t, want %t", evidence.Retryable, retryable)
	}
	if evidence.RawErrno() != errno {
		t.Errorf("RawErrno() = %v, want %v", evidence.RawErrno(), errno)
	}
}
