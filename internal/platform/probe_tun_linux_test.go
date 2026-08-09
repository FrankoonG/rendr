//go:build linux

package platform

import (
	"context"
	"errors"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type fakeTUNHandle struct {
	kernel   *fakeTUNKernel
	fd       int
	closeErr error
	closed   bool
}

func (handle *fakeTUNHandle) Fd() uintptr { return uintptr(handle.fd) }
func (handle *fakeTUNHandle) Close() error {
	handle.kernel.mu.Lock()
	defer handle.kernel.mu.Unlock()
	if handle.closed {
		return errors.New("double close")
	}
	handle.closed = true
	handle.kernel.closeFDLocked(handle.fd)
	return handle.closeErr
}

type fakeTUNInterface struct {
	index  int
	flags  uint16
	queues int
}

type fakeTUNKernel struct {
	mu                sync.Mutex
	nextFD            int
	nextIndex         int
	handles           []*fakeTUNHandle
	nameByFD          map[int]string
	interfaces        map[string]*fakeTUNInterface
	setIFFErrAt       int
	setIFFCalls       int
	openErrAt         int
	openCalls         int
	closeErrAt        int
	nameCalls         int
	emptyGETNameAt    int
	setIFFNoCreateAt  int
	allowSingleAttach bool
	getCalls          int
	sawMQIntermediate bool
}

func newFakeTUNKernel() *fakeTUNKernel {
	return &fakeTUNKernel{
		nextFD:     10,
		nextIndex:  100,
		nameByFD:   make(map[int]string),
		interfaces: make(map[string]*fakeTUNInterface),
	}
}

func (kernel *fakeTUNKernel) ops() tunProbeOps {
	return tunProbeOps{
		open: func() (tunProbeHandle, error) {
			kernel.mu.Lock()
			defer kernel.mu.Unlock()
			kernel.openCalls++
			if kernel.openErrAt == kernel.openCalls {
				return nil, syscall.EMFILE
			}
			handle := &fakeTUNHandle{kernel: kernel, fd: kernel.nextFD}
			kernel.nextFD++
			if kernel.closeErrAt == kernel.openCalls {
				handle.closeErr = errors.New("injected close failure")
			}
			kernel.handles = append(kernel.handles, handle)
			return handle, nil
		},
		setIFF: func(fd int, name string, flags uint16) (string, error) {
			kernel.mu.Lock()
			defer kernel.mu.Unlock()
			kernel.setIFFCalls++
			if kernel.setIFFErrAt == kernel.setIFFCalls {
				return "", syscall.EPERM
			}
			if kernel.setIFFNoCreateAt == kernel.setIFFCalls {
				return name, nil
			}
			iface, exists := kernel.interfaces[name]
			isMulti := int(flags)&unix.IFF_MULTI_QUEUE != 0
			if exists {
				if (!isMulti || int(iface.flags)&unix.IFF_MULTI_QUEUE == 0) && !kernel.allowSingleAttach {
					return "", syscall.EBUSY
				}
				iface.queues++
			} else {
				iface = &fakeTUNInterface{
					index:  kernel.nextIndex,
					flags:  flags &^ uint16(unix.IFF_TUN_EXCL),
					queues: 1,
				}
				kernel.nextIndex++
				kernel.interfaces[name] = iface
			}
			kernel.nameByFD[fd] = name
			return name, nil
		},
		getIFF: func(fd int) (string, uint16, error) {
			kernel.mu.Lock()
			defer kernel.mu.Unlock()
			kernel.getCalls++
			name, ok := kernel.nameByFD[fd]
			if !ok {
				return "", 0, syscall.ENODEV
			}
			iface, ok := kernel.interfaces[name]
			if !ok {
				return "", 0, syscall.ENODEV
			}
			if kernel.emptyGETNameAt == kernel.getCalls {
				name = ""
			}
			return name, iface.flags, nil
		},
		ifIndex: func(name string) (int, error) {
			kernel.mu.Lock()
			defer kernel.mu.Unlock()
			iface, ok := kernel.interfaces[name]
			if !ok {
				return 0, syscall.ENODEV
			}
			if iface.queues == 1 && int(iface.flags)&unix.IFF_MULTI_QUEUE != 0 {
				kernel.sawMQIntermediate = true
			}
			return iface.index, nil
		},
		name: func() string {
			kernel.mu.Lock()
			defer kernel.mu.Unlock()
			kernel.nameCalls++
			if kernel.nameCalls == 1 {
				return "tun-a"
			}
			return "tun-b"
		},
	}
}

func (kernel *fakeTUNKernel) closeFDLocked(fd int) {
	name, ok := kernel.nameByFD[fd]
	if !ok {
		return
	}
	delete(kernel.nameByFD, fd)
	iface := kernel.interfaces[name]
	iface.queues--
	if iface.queues == 0 {
		delete(kernel.interfaces, name)
	}
}

func TestProbeTUNConfirmsSingleAndMultiQueueLifecycle(t *testing.T) {
	kernel := newFakeTUNKernel()
	evidence, err := probeTUN(context.Background(), time.Unix(100, 0).UTC(), kernel.ops())
	if err != nil {
		t.Fatal(err)
	}
	assertTUNEvidenceState(t, evidence, FeatureTUNOpen, FeatureAvailable)
	assertTUNEvidenceState(t, evidence, FeatureTUNSetIFF, FeatureAvailable)
	assertTUNEvidenceState(t, evidence, FeatureTUNSingleQueue, FeatureAvailable)
	assertTUNEvidenceState(t, evidence, FeatureTUNMultiQueue, FeatureAvailable)
	if !kernel.sawMQIntermediate {
		t.Fatal("probe did not prove first MQ queue survived second queue close")
	}
	assertFakeTUNClean(t, kernel)
}

func TestProbeTUNRejectsSetIFFThatDidNotCreateInterface(t *testing.T) {
	kernel := newFakeTUNKernel()
	kernel.setIFFNoCreateAt = 1
	evidence, err := probeTUN(context.Background(), time.Unix(100, 0).UTC(), kernel.ops())
	if err != nil {
		t.Fatal(err)
	}
	assertTUNEvidenceState(t, evidence, FeatureTUNOpen, FeatureAvailable)
	assertTUNEvidenceState(t, evidence, FeatureTUNSetIFF, FeatureProbeFailed)
	assertTUNEvidenceState(t, evidence, FeatureTUNSingleQueue, FeatureProbeFailed)
	assertFakeTUNClean(t, kernel)
}

func TestProbeTUNGETIFFMustWriteActualName(t *testing.T) {
	kernel := newFakeTUNKernel()
	kernel.emptyGETNameAt = 1
	evidence, err := probeTUN(context.Background(), time.Unix(100, 0).UTC(), kernel.ops())
	if err != nil {
		t.Fatal(err)
	}
	assertTUNEvidenceState(t, evidence, FeatureTUNOpen, FeatureAvailable)
	assertTUNEvidenceState(t, evidence, FeatureTUNSetIFF, FeatureAvailable)
	assertTUNEvidenceState(t, evidence, FeatureTUNSingleQueue, FeatureProbeFailed)
	assertFakeTUNClean(t, kernel)
}

func TestProbeTUNRejectsSingleQueueThatAcceptsSecondAttach(t *testing.T) {
	kernel := newFakeTUNKernel()
	kernel.allowSingleAttach = true
	evidence, err := probeTUN(context.Background(), time.Unix(100, 0).UTC(), kernel.ops())
	if err != nil {
		t.Fatal(err)
	}
	assertTUNEvidenceState(t, evidence, FeatureTUNOpen, FeatureAvailable)
	assertTUNEvidenceState(t, evidence, FeatureTUNSetIFF, FeatureAvailable)
	assertTUNEvidenceState(t, evidence, FeatureTUNSingleQueue, FeatureProbeFailed)
	assertFakeTUNClean(t, kernel)
}

func TestProbeTUNCleansFirstQueueWhenSecondOpenFails(t *testing.T) {
	kernel := newFakeTUNKernel()
	kernel.openErrAt = 4
	evidence, err := probeTUN(context.Background(), time.Unix(100, 0).UTC(), kernel.ops())
	if err != nil {
		t.Fatal(err)
	}
	assertTUNEvidenceState(t, evidence, FeatureTUNMultiQueue, FeatureProbeFailed)
	assertFakeTUNClean(t, kernel)
}

func TestProbeTUNCloseFailureCannotPublishAvailability(t *testing.T) {
	kernel := newFakeTUNKernel()
	kernel.closeErrAt = 1
	evidence, err := probeTUN(context.Background(), time.Unix(100, 0).UTC(), kernel.ops())
	if err != nil {
		t.Fatal(err)
	}
	assertTUNEvidenceState(t, evidence, FeatureTUNOpen, FeatureProbeFailed)
	assertTUNEvidenceState(t, evidence, FeatureTUNSetIFF, FeatureProbeFailed)
	assertTUNEvidenceState(t, evidence, FeatureTUNSingleQueue, FeatureProbeFailed)
	if _, ok := findEvidence(evidence, FeatureTUNMultiQueue); ok {
		t.Fatal("multiqueue probe ran after single-queue cleanup failed")
	}
	assertFakeTUNClean(t, kernel)
}

func TestProbeTUNPermissionFailureDoesNotImplySingleQueue(t *testing.T) {
	kernel := newFakeTUNKernel()
	kernel.setIFFErrAt = 1
	evidence, err := probeTUN(context.Background(), time.Unix(100, 0).UTC(), kernel.ops())
	if err != nil {
		t.Fatal(err)
	}
	assertTUNEvidenceState(t, evidence, FeatureTUNOpen, FeatureAvailable)
	assertTUNEvidenceState(t, evidence, FeatureTUNSetIFF, FeaturePermissionDenied)
	if _, ok := findEvidence(evidence, FeatureTUNSingleQueue); ok {
		t.Fatal("single queue was inferred after TUNSETIFF denial")
	}
	if _, ok := findEvidence(evidence, FeatureTUNMultiQueue); ok {
		t.Fatal("multiqueue ran after contradictory TUNSETIFF denial")
	}
	if kernel.setIFFCalls != 1 {
		t.Fatalf("TUNSETIFF calls=%d want 1", kernel.setIFFCalls)
	}
	assertFakeTUNClean(t, kernel)
}

func TestProbeTUNCancellationCannotShortCircuitCleanupProof(t *testing.T) {
	kernel := newFakeTUNKernel()
	ops := kernel.ops()
	ctx, cancel := context.WithCancel(context.Background())
	originalSetIFF := ops.setIFF
	setCalls := 0
	ops.setIFF = func(fd int, name string, flags uint16) (string, error) {
		actualName, err := originalSetIFF(fd, name, flags)
		setCalls++
		if setCalls == 1 {
			cancel()
		}
		return actualName, err
	}
	originalIfIndex := ops.ifIndex
	delayedGoneChecks := 0
	ops.ifIndex = func(name string) (int, error) {
		index, err := originalIfIndex(name)
		if errors.Is(err, syscall.ENODEV) && ctx.Err() != nil && delayedGoneChecks < 3 {
			delayedGoneChecks++
			return 100, nil
		}
		return index, err
	}
	evidence, err := probeTUN(ctx, time.Unix(100, 0).UTC(), ops)
	if err != nil {
		t.Fatal(err)
	}
	assertTUNEvidenceState(t, evidence, FeatureTUNOpen, FeatureAvailable)
	assertTUNEvidenceState(t, evidence, FeatureTUNSetIFF, FeatureProbeFailed)
	if delayedGoneChecks != 3 {
		t.Fatalf("cleanup stopped after cancellation: checks=%d", delayedGoneChecks)
	}
	if setCalls != 1 {
		t.Fatalf("mutation continued after cancellation: setIFF calls=%d", setCalls)
	}
	assertFakeTUNClean(t, kernel)
}

func assertFakeTUNClean(t *testing.T, kernel *fakeTUNKernel) {
	t.Helper()
	kernel.mu.Lock()
	defer kernel.mu.Unlock()
	if len(kernel.interfaces) != 0 || len(kernel.nameByFD) != 0 {
		t.Fatalf("fake kernel leaked interfaces=%v fds=%v", kernel.interfaces, kernel.nameByFD)
	}
	for _, handle := range kernel.handles {
		if !handle.closed {
			t.Fatalf("fd %d leaked", handle.fd)
		}
	}
}

func assertTUNEvidenceState(t *testing.T, evidence []FeatureEvidence, id FeatureID, state FeatureState) {
	t.Helper()
	result, ok := findEvidence(evidence, id)
	if !ok {
		t.Fatalf("missing %s evidence: %+v", id, evidence)
	}
	if result.State != state {
		t.Fatalf("%s state=%s reason=%s, want %s", id, result.State, result.Reason, state)
	}
}

func findEvidence(evidence []FeatureEvidence, id FeatureID) (FeatureEvidence, bool) {
	for _, result := range evidence {
		if result.ID == id {
			return result, true
		}
	}
	return FeatureEvidence{}, false
}
