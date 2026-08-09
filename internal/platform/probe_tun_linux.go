//go:build linux

package platform

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	tunDevicePath      = "/dev/net/tun"
	tunCleanupDeadline = 250 * time.Millisecond
)

var tunProbeSequence atomic.Uint32

type tunProbeHandle interface {
	Fd() uintptr
	Close() error
}

type tunProbeOps struct {
	open    func() (tunProbeHandle, error)
	setIFF  func(fd int, name string, flags uint16) (string, error)
	getIFF  func(fd int) (string, uint16, error)
	ifIndex func(name string) (int, error)
	name    func() string
}

func defaultTUNProbeOps() tunProbeOps {
	return tunProbeOps{
		open: func() (tunProbeHandle, error) {
			return os.OpenFile(tunDevicePath, os.O_RDWR|syscall.O_NONBLOCK, 0)
		},
		setIFF: func(fd int, name string, flags uint16) (string, error) {
			request, err := unix.NewIfreq(name)
			if err != nil {
				return "", err
			}
			request.SetUint16(flags)
			if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, request); err != nil {
				return "", err
			}
			return request.Name(), nil
		},
		getIFF: func(fd int) (string, uint16, error) {
			request, err := unix.NewIfreq("")
			if err != nil {
				return "", 0, err
			}
			if err := unix.IoctlIfreq(fd, unix.TUNGETIFF, request); err != nil {
				return "", 0, err
			}
			return request.Name(), request.Uint16(), nil
		},
		ifIndex: linuxInterfaceIndex,
		name: func() string {
			return fmt.Sprintf("rndr%05x%05x", os.Getpid()&0xfffff, tunProbeSequence.Add(1)&0xfffff)
		},
	}
}

func linuxInterfaceIndex(name string) (index int, err error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer func() {
		if closeErr := unix.Close(fd); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()
	request, err := unix.NewIfreq(name)
	if err != nil {
		return 0, err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFINDEX, request); err != nil {
		return 0, err
	}
	index = int(request.Uint32())
	if index <= 0 {
		return 0, fmt.Errorf("interface %q returned invalid index %d", name, index)
	}
	return index, nil
}

func probeTUN(ctx context.Context, at time.Time, ops tunProbeOps) ([]FeatureEvidence, error) {
	if err := validateTUNProbeOps(ops); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	observations := make([]FeatureEvidence, 0, 4)
	openEvidence, setIFFEvidence, singleEvidence := probeTUNSingleQueue(ctx, at, ops)
	observations = append(observations, openEvidence)
	if setIFFEvidence.ID != "" {
		observations = append(observations, setIFFEvidence)
	}
	if singleEvidence.ID != "" {
		observations = append(observations, singleEvidence)
	}
	if openEvidence.State == FeatureAvailable && setIFFEvidence.State == FeatureAvailable &&
		singleEvidence.State == FeatureAvailable && ctx.Err() == nil {
		observations = append(observations, probeTUNMultiQueue(ctx, at, ops))
	}
	return observations, nil
}

func validateTUNProbeOps(ops tunProbeOps) error {
	if ops.open == nil || ops.setIFF == nil || ops.getIFF == nil || ops.ifIndex == nil || ops.name == nil {
		return fmt.Errorf("platform: incomplete TUN probe operations")
	}
	return nil
}

func probeTUNSingleQueue(ctx context.Context, at time.Time, ops tunProbeOps) (FeatureEvidence, FeatureEvidence, FeatureEvidence) {
	handle, err := ops.open()
	if err != nil {
		return classifiedOrFailed(FeatureTUNOpen, at, err), FeatureEvidence{}, FeatureEvidence{}
	}
	if err := ctx.Err(); err != nil {
		return availableUnlessCleanup(FeatureTUNOpen, at, handle.Close()), FeatureEvidence{}, FeatureEvidence{}
	}
	requestedName := ops.name()
	flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_TUN_EXCL)
	actualName, err := ops.setIFF(int(handle.Fd()), requestedName, flags)
	if err != nil {
		closeErr := handle.Close()
		openEvidence := availableUnlessCleanup(FeatureTUNOpen, at, closeErr)
		return openEvidence, classifiedOrFailed(FeatureTUNSetIFF, at, err), FeatureEvidence{}
	}
	semanticErr := ctx.Err()
	if semanticErr == nil {
		semanticErr = validateCreatedTUNName(requestedName, actualName)
	}
	var index int
	setIFFConfirmed := false
	if semanticErr == nil {
		index, semanticErr = ops.ifIndex(actualName)
	}
	if semanticErr == nil {
		setIFFConfirmed = true
		semanticErr = verifyTUNQueue(ops, int(handle.Fd()), actualName, false)
	}
	var secondaryCleanupErr error
	classifySingleFailure := false
	if semanticErr == nil {
		semanticErr, secondaryCleanupErr, classifySingleFailure = verifyTUNSingleQueueExclusive(ctx, ops, actualName, index, handle)
	}
	closeErr := handle.Close()
	cleanupErr := errors.Join(secondaryCleanupErr, closeErr)
	if actualName != "" {
		cleanupErr = errors.Join(cleanupErr, waitInterfaceGone(ctx, actualName, index, ops.ifIndex))
	}
	if cleanupErr != nil {
		failure := errors.Join(semanticErr, cleanupErr)
		return cleanupFailureEvidence(FeatureTUNOpen, at, failure),
			cleanupFailureEvidence(FeatureTUNSetIFF, at, failure),
			cleanupFailureEvidence(FeatureTUNSingleQueue, at, failure)
	}
	if semanticErr != nil {
		setIFFEvidence := semanticFailureEvidence(FeatureTUNSetIFF, at, semanticErr)
		if setIFFConfirmed {
			setIFFEvidence = availableEvidence(FeatureTUNSetIFF, at, SourceRuntimeRoundTrip)
		}
		singleEvidence := semanticFailureEvidence(FeatureTUNSingleQueue, at, semanticErr)
		if classifySingleFailure {
			singleEvidence = classifiedOrFailed(FeatureTUNSingleQueue, at, semanticErr)
		}
		return availableEvidence(FeatureTUNOpen, at, SourceRuntimeSyscall),
			setIFFEvidence,
			singleEvidence
	}
	return availableEvidence(FeatureTUNOpen, at, SourceRuntimeSyscall),
		availableEvidence(FeatureTUNSetIFF, at, SourceRuntimeRoundTrip),
		availableEvidence(FeatureTUNSingleQueue, at, SourceRuntimeRoundTrip)
}

func verifyTUNSingleQueueExclusive(ctx context.Context, ops tunProbeOps, name string, index int, first tunProbeHandle) (semanticErr, cleanupErr error, classify bool) {
	if err := ctx.Err(); err != nil {
		return err, nil, true
	}
	second, err := ops.open()
	if err != nil {
		return err, nil, true
	}
	defer func() {
		cleanupErr = errors.Join(cleanupErr, second.Close())
	}()
	if err := ctx.Err(); err != nil {
		return err, cleanupErr, true
	}
	flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI)
	_, attachErr := ops.setIFF(int(second.Fd()), name, flags)
	if !errors.Is(attachErr, unix.EBUSY) {
		if attachErr == nil {
			semanticErr = fmt.Errorf("single-queue TUN accepted a second queue")
		} else {
			semanticErr = fmt.Errorf("single-queue second attach: %w", attachErr)
		}
	}
	if err := verifyTUNQueue(ops, int(first.Fd()), name, false); err != nil {
		semanticErr = errors.Join(semanticErr, err)
	}
	currentIndex, err := ops.ifIndex(name)
	if err != nil {
		semanticErr = errors.Join(semanticErr, err)
	} else if currentIndex != index {
		semanticErr = errors.Join(semanticErr, fmt.Errorf("single-queue index changed from %d to %d", index, currentIndex))
	}
	return semanticErr, cleanupErr, false
}

func probeTUNMultiQueue(ctx context.Context, at time.Time, ops tunProbeOps) FeatureEvidence {
	first, err := ops.open()
	if err != nil {
		return classifiedOrFailed(FeatureTUNMultiQueue, at, err)
	}
	if err := ctx.Err(); err != nil {
		return finishFailedTUNMultiQueue(ctx, at, ops, "", 0, []tunProbeHandle{first}, err, true)
	}
	requestedName := ops.name()
	createFlags := uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_MULTI_QUEUE | unix.IFF_TUN_EXCL)
	actualName, err := ops.setIFF(int(first.Fd()), requestedName, createFlags)
	if err != nil {
		return finishFailedTUNMultiQueue(ctx, at, ops, "", 0, []tunProbeHandle{first}, err, true)
	}
	if err := ctx.Err(); err != nil {
		return finishFailedTUNMultiQueue(ctx, at, ops, actualName, 0, []tunProbeHandle{first}, err, true)
	}
	if err := validateCreatedTUNName(requestedName, actualName); err != nil {
		return finishFailedTUNMultiQueue(ctx, at, ops, actualName, 0, []tunProbeHandle{first}, err, false)
	}
	index, err := ops.ifIndex(actualName)
	if err != nil {
		return finishFailedTUNMultiQueue(ctx, at, ops, actualName, 0, []tunProbeHandle{first}, err, false)
	}
	if err := verifyTUNQueue(ops, int(first.Fd()), actualName, true); err != nil {
		return finishFailedTUNMultiQueue(ctx, at, ops, actualName, index, []tunProbeHandle{first}, err, false)
	}
	if err := ctx.Err(); err != nil {
		return finishFailedTUNMultiQueue(ctx, at, ops, actualName, index, []tunProbeHandle{first}, err, true)
	}

	second, err := ops.open()
	if err != nil {
		return finishFailedTUNMultiQueue(ctx, at, ops, actualName, index, []tunProbeHandle{first}, err, true)
	}
	if err := ctx.Err(); err != nil {
		return finishFailedTUNMultiQueue(ctx, at, ops, actualName, index, []tunProbeHandle{second, first}, err, true)
	}
	attachFlags := uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_MULTI_QUEUE)
	secondName, err := ops.setIFF(int(second.Fd()), actualName, attachFlags)
	if err == nil {
		err = validateCreatedTUNName(actualName, secondName)
	}
	if err == nil {
		err = verifyTUNQueue(ops, int(second.Fd()), actualName, true)
	}
	if err != nil {
		return finishFailedTUNMultiQueue(ctx, at, ops, actualName, index, []tunProbeHandle{second, first}, err, false)
	}

	secondCloseErr := second.Close()
	if secondCloseErr != nil {
		return finishFailedTUNMultiQueue(ctx, at, ops, actualName, index, []tunProbeHandle{first}, secondCloseErr, false)
	}
	intermediateErr := verifyTUNQueue(ops, int(first.Fd()), actualName, true)
	if intermediateErr == nil {
		var currentIndex int
		currentIndex, intermediateErr = ops.ifIndex(actualName)
		if intermediateErr == nil && currentIndex != index {
			intermediateErr = fmt.Errorf("TUN multiqueue index changed from %d to %d", index, currentIndex)
		}
	}
	if intermediateErr != nil {
		return finishFailedTUNMultiQueue(ctx, at, ops, actualName, index, []tunProbeHandle{first}, intermediateErr, false)
	}

	firstCloseErr := first.Close()
	disappearErr := waitInterfaceGone(ctx, actualName, index, ops.ifIndex)
	if cleanupErr := errors.Join(firstCloseErr, disappearErr); cleanupErr != nil {
		return cleanupFailureEvidence(FeatureTUNMultiQueue, at, cleanupErr)
	}
	return availableEvidence(FeatureTUNMultiQueue, at, SourceRuntimeRoundTrip)
}

func validateCreatedTUNName(requested, actual string) error {
	if actual == "" || actual != requested {
		return fmt.Errorf("TUN name mismatch: requested=%q actual=%q", requested, actual)
	}
	return nil
}

func verifyTUNQueue(ops tunProbeOps, fd int, name string, multiqueue bool) error {
	actualName, flags, err := ops.getIFF(fd)
	if err != nil {
		return err
	}
	if actualName != name {
		return fmt.Errorf("TUNGETIFF name=%q want %q", actualName, name)
	}
	tunType := int(flags) & (unix.IFF_TUN | unix.IFF_TAP)
	if tunType != unix.IFF_TUN {
		return fmt.Errorf("TUNGETIFF type flags=%#x", flags)
	}
	if int(flags)&(unix.IFF_PERSIST|unix.IFF_DETACH_QUEUE) != 0 {
		return fmt.Errorf("TUNGETIFF forbidden flags=%#x", flags)
	}
	hasMultiQueue := int(flags)&unix.IFF_MULTI_QUEUE != 0
	if hasMultiQueue != multiqueue {
		return fmt.Errorf("TUNGETIFF multiqueue=%v want %v flags=%#x", hasMultiQueue, multiqueue, flags)
	}
	return nil
}

func finishFailedTUNMultiQueue(ctx context.Context, at time.Time, ops tunProbeOps, name string, index int, handles []tunProbeHandle, cause error, classify bool) FeatureEvidence {
	cleanupErr := closeTUNHandles(handles...)
	if name != "" {
		cleanupErr = errors.Join(cleanupErr, waitInterfaceGone(ctx, name, index, ops.ifIndex))
	}
	if cleanupErr != nil {
		return cleanupFailureEvidence(FeatureTUNMultiQueue, at, errors.Join(cause, cleanupErr))
	}
	if classify {
		return classifiedOrFailed(FeatureTUNMultiQueue, at, cause)
	}
	return semanticFailureEvidence(FeatureTUNMultiQueue, at, cause)
}

func closeTUNHandles(handles ...tunProbeHandle) error {
	var errs []error
	for _, handle := range handles {
		if handle != nil {
			if err := handle.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func waitInterfaceGone(_ context.Context, name string, expectedIndex int, lookup func(string) (int, error)) error {
	deadline := time.NewTimer(tunCleanupDeadline)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		index, err := lookup(name)
		if errors.Is(err, unix.ENODEV) {
			return nil
		}
		if err != nil {
			return err
		}
		if expectedIndex != 0 && index != expectedIndex {
			return fmt.Errorf("temporary TUN name %q was reused: index=%d want=%d", name, index, expectedIndex)
		}
		select {
		case <-deadline.C:
			return fmt.Errorf("temporary TUN interface %q index %d still exists", name, index)
		case <-ticker.C:
		}
	}
}

func availableEvidence(id FeatureID, at time.Time, source EvidenceSource) FeatureEvidence {
	return mustEvidence(id, FeatureAvailable, ReasonConfirmed, at, source, 0, false)
}

func availableUnlessCleanup(id FeatureID, at time.Time, cleanupErr error) FeatureEvidence {
	if cleanupErr != nil {
		return cleanupFailureEvidence(id, at, cleanupErr)
	}
	return availableEvidence(id, at, SourceRuntimeSyscall)
}

func cleanupFailureEvidence(id FeatureID, at time.Time, err error) FeatureEvidence {
	var errno syscall.Errno
	_ = errors.As(err, &errno)
	return mustEvidence(id, FeatureProbeFailed, ReasonSyscallFailed, at, SourceRuntimeSyscall, errno, true)
}

func semanticFailureEvidence(id FeatureID, at time.Time, err error) FeatureEvidence {
	var errno syscall.Errno
	_ = errors.As(err, &errno)
	return mustEvidence(id, FeatureProbeFailed, ReasonSemanticMismatch, at, SourceRuntimeRoundTrip, errno, false)
}

func classifiedOrFailed(id FeatureID, at time.Time, err error) FeatureEvidence {
	evidence, classifyErr := classifyProbeError(id, at, SourceRuntimeSyscall, err)
	if classifyErr != nil {
		return cleanupFailureEvidence(id, at, errors.Join(err, classifyErr))
	}
	return evidence
}
