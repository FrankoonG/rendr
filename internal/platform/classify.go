package platform

import (
	"errors"
	"syscall"
	"time"
)

// classifyProbeError converts a failed active probe into validated evidence.
func classifyProbeError(id FeatureID, at time.Time, source EvidenceSource, err error) (FeatureEvidence, error) {
	if err == nil {
		return FeatureEvidence{}, errors.New("platform: cannot classify a nil probe error")
	}

	state := FeatureProbeFailed
	reason := ReasonSyscallFailed
	retryable := false

	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.EPERM, syscall.EACCES:
			state = FeaturePermissionDenied
			reason = ReasonPermissionDenied
		case syscall.ENOPROTOOPT, syscall.EOPNOTSUPP, syscall.ENOSYS, syscall.ENOTTY,
			syscall.EAFNOSUPPORT, syscall.EPFNOSUPPORT, syscall.EPROTONOSUPPORT, syscall.ESOCKTNOSUPPORT:
			state = FeatureUnsupported
			reason = ReasonPrimitiveUnsupported
		case syscall.ENOENT, syscall.ENODEV:
			state = FeatureUnsupported
			reason = ReasonDeviceUnavailable
		case syscall.EMFILE, syscall.ENFILE, syscall.ENOMEM, syscall.ENOBUFS, syscall.ENOSPC:
			reason = ReasonResourceExhausted
			retryable = true
		case syscall.EAGAIN, syscall.EINTR, syscall.EBUSY:
			retryable = true
		}
	}

	return NewEvidence(id, state, reason, at, source, errno, retryable)
}
