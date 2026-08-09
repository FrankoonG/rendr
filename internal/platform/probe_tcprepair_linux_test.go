//go:build linux

package platform

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type fakeTCPRepairProbePair struct {
	controlErr  error
	validateErr error
	exchangeErr error
	closeErr    error
	validates   int
	exchanges   int
	closes      int
	onExchange  func(request, response []byte)
}

func (pair *fakeTCPRepairProbePair) control(fn func(int) error) error {
	if pair.controlErr != nil {
		return pair.controlErr
	}
	return fn(42)
}

func (pair *fakeTCPRepairProbePair) validate() error {
	pair.validates++
	return pair.validateErr
}

func (pair *fakeTCPRepairProbePair) exchange(request, response []byte) error {
	pair.exchanges++
	if pair.exchangeErr == nil && pair.onExchange != nil {
		pair.onExchange(request, response)
	}
	return pair.exchangeErr
}

func (pair *fakeTCPRepairProbePair) close() error {
	pair.closes++
	return pair.closeErr
}

type fakeTCPRepairKernel struct {
	repair                int
	queue                 int
	scratchRepair         int
	scratchQueue          int
	scratchSendSequence   uint32
	scratchRecvSequence   uint32
	scratchOpen           bool
	scratchCloses         int
	ignoreScratchSequence bool
	timestamp             int
	window                tcpRepairProbeWindow
	info                  tcpRepairProbeInfo
	sendSequence          uint32
	recvSequence          uint32
	setIntHook            func(option, value int) error
	getIntHook            func(option int) (int, error, bool)
	getWindowErr          error
	setWindowErr          error
	ignoreWindowWrites    bool
	ignoreOptionsWrites   bool
	ignoreTimestampWrites bool
	getInfoErr            error
	setOptionsErr         error
	setOptions            []unix.TCPRepairOpt
	setOptionsCalls       int
	setCalls              [][2]int
	windowWrites          []tcpRepairProbeWindow
}

func newFakeTCPRepairProbeOps(pair *fakeTCPRepairProbePair) (tcpRepairProbeOps, *fakeTCPRepairKernel) {
	kernel := &fakeTCPRepairKernel{
		timestamp: 101,
		window: tcpRepairProbeWindow{
			SendWindowLastUpdate: 10,
			SendWindow:           20,
			MaxWindow:            30,
			ReceiveWindow:        40,
			ReceiveWindowUpdate:  50,
		},
		info: tcpRepairProbeInfo{
			State:       tcpRepairEstablished,
			Options:     tcpInfoTimestamps | tcpInfoSACK | tcpInfoWindowScale,
			WindowScale: 3 | 5<<4,
			SendMSS:     1460,
			ReceiveMSS:  1460,
		},
		sendSequence: 1234,
		recvSequence: 5678,
	}
	pair.onExchange = func(request, response []byte) {
		kernel.sendSequence += uint32(len(request))
		kernel.recvSequence += uint32(len(response))
	}
	ops := tcpRepairProbeOps{
		open: func(context.Context) (tcpRepairProbePair, error) { return pair, nil },
		openScratch: func() (int, error) {
			kernel.scratchOpen = true
			return 84, nil
		},
		closeFD: func(fd int) error {
			if fd != 84 || !kernel.scratchOpen {
				return syscall.EBADF
			}
			kernel.scratchOpen = false
			kernel.scratchCloses++
			return nil
		},
		setInt: func(fd int, _ int, option, value int) error {
			kernel.setCalls = append(kernel.setCalls, [2]int{option, value})
			if kernel.setIntHook != nil {
				if err := kernel.setIntHook(option, value); err != nil {
					return err
				}
			}
			if fd == 84 {
				switch option {
				case unix.TCP_REPAIR:
					kernel.scratchRepair = value
				case unix.TCP_REPAIR_QUEUE:
					kernel.scratchQueue = value
				case unix.TCP_QUEUE_SEQ:
					if kernel.ignoreScratchSequence {
						return nil
					}
					if kernel.scratchQueue == tcpRepairSendQueue {
						kernel.scratchSendSequence = uint32(value)
					} else if kernel.scratchQueue == tcpRepairRecvQueue {
						kernel.scratchRecvSequence = uint32(value)
					} else {
						return syscall.EINVAL
					}
				}
				return nil
			}
			switch option {
			case unix.TCP_REPAIR:
				kernel.repair = value
			case unix.TCP_REPAIR_QUEUE:
				kernel.queue = value
			case unix.TCP_TIMESTAMP:
				if !kernel.ignoreTimestampWrites {
					kernel.timestamp = value
				}
			}
			return nil
		},
		getInt: func(fd int, _ int, option int) (int, error) {
			if kernel.getIntHook != nil {
				if value, err, handled := kernel.getIntHook(option); handled {
					return value, err
				}
			}
			if fd == 84 {
				switch option {
				case unix.TCP_REPAIR:
					return kernel.scratchRepair, nil
				case unix.TCP_REPAIR_QUEUE:
					return kernel.scratchQueue, nil
				case unix.TCP_QUEUE_SEQ:
					if kernel.scratchQueue == tcpRepairSendQueue {
						return int(kernel.scratchSendSequence), nil
					}
					if kernel.scratchQueue == tcpRepairRecvQueue {
						return int(kernel.scratchRecvSequence), nil
					}
					return 0, syscall.EINVAL
				default:
					return 0, syscall.ENOPROTOOPT
				}
			}
			switch option {
			case unix.TCP_REPAIR:
				return kernel.repair, nil
			case unix.TCP_REPAIR_QUEUE:
				return kernel.queue, nil
			case unix.TCP_QUEUE_SEQ:
				if kernel.queue == tcpRepairSendQueue {
					return int(kernel.sendSequence), nil
				}
				if kernel.queue == tcpRepairRecvQueue {
					return int(kernel.recvSequence), nil
				}
				return 0, syscall.EINVAL
			case unix.TCP_TIMESTAMP:
				return kernel.timestamp, nil
			default:
				return 0, syscall.ENOPROTOOPT
			}
		},
		getWindow: func(int) (tcpRepairProbeWindow, error) {
			return kernel.window, kernel.getWindowErr
		},
		setWindow: func(_ int, window tcpRepairProbeWindow) error {
			kernel.windowWrites = append(kernel.windowWrites, window)
			if kernel.setWindowErr == nil && !kernel.ignoreWindowWrites {
				kernel.window = window
			}
			return kernel.setWindowErr
		},
		getInfo: func(int) (tcpRepairProbeInfo, error) {
			if kernel.getInfoErr != nil {
				return tcpRepairProbeInfo{}, kernel.getInfoErr
			}
			return kernel.info, nil
		},
		setOptions: func(_ int, options []unix.TCPRepairOpt) error {
			kernel.setOptionsCalls++
			kernel.setOptions = append([]unix.TCPRepairOpt(nil), options...)
			if kernel.setOptionsErr != nil {
				return kernel.setOptionsErr
			}
			if !kernel.ignoreOptionsWrites {
				for _, option := range options {
					switch option.Code {
					case unix.TCPOPT_MAXSEG:
						kernel.info.SendMSS = option.Val
					case unix.TCPOPT_WINDOW:
						kernel.info.WindowScale = uint8(option.Val&0x0f) | uint8((option.Val>>16)&0x0f)<<4
					}
				}
			}
			return nil
		},
	}
	return ops, kernel
}

func TestProbeTCPRepairSuccessRequiresAllSemantics(t *testing.T) {
	pair := &fakeTCPRepairProbePair{}
	ops, kernel := newFakeTCPRepairProbeOps(pair)
	evidence, err := probeTCPRepair(context.Background(), probeTestTime(), ops)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != len(tcpRepairFeatureIDs) {
		t.Fatalf("evidence=%d want %d", len(evidence), len(tcpRepairFeatureIDs))
	}
	for _, id := range tcpRepairFeatureIDs {
		got := findTCPRepairEvidence(t, evidence, id)
		if got.State != FeatureAvailable || got.Reason != ReasonConfirmed {
			t.Fatalf("%s=%s/%s", id, got.State, got.Reason)
		}
	}
	if pair.validates != 2 || pair.exchanges != 2 || pair.closes != 1 {
		t.Fatalf("validates=%d exchanges=%d closes=%d", pair.validates, pair.exchanges, pair.closes)
	}
	if kernel.repair != unix.TCP_REPAIR_OFF || kernel.queue != tcpRepairNoQueue {
		t.Fatalf("repair=%d queue=%d after probe", kernel.repair, kernel.queue)
	}
	if kernel.setOptionsCalls != 2 || len(kernel.setOptions) != 4 || kernel.setOptions[0].Code != unix.TCPOPT_MAXSEG || kernel.setOptions[0].Val != 1460 ||
		kernel.setOptions[1].Code != unix.TCPOPT_WINDOW || kernel.setOptions[1].Val != 3|5<<16 ||
		kernel.setOptions[2].Code != unix.TCPOPT_SACK_PERMITTED || kernel.setOptions[3].Code != unix.TCPOPT_TIMESTAMP {
		t.Fatalf("options=%+v", kernel.setOptions)
	}
	if len(kernel.windowWrites) < 3 || kernel.window != (tcpRepairProbeWindow{10, 20, 30, 40, 50}) {
		t.Fatalf("window writes=%+v final=%+v", kernel.windowWrites, kernel.window)
	}
	sequenceWrites := 0
	for _, call := range kernel.setCalls {
		if call[0] == unix.TCP_QUEUE_SEQ {
			sequenceWrites++
		}
	}
	if sequenceWrites != 2 || kernel.scratchOpen || kernel.scratchCloses != 1 {
		t.Fatalf("scratch sequence writes=%d open=%v closes=%d", sequenceWrites, kernel.scratchOpen, kernel.scratchCloses)
	}
}

func TestProbeTCPRepairPermissionDeniedLeavesDependentStagesUnprobed(t *testing.T) {
	pair := &fakeTCPRepairProbePair{}
	ops, kernel := newFakeTCPRepairProbeOps(pair)
	kernel.setIntHook = func(option, value int) error {
		if option == unix.TCP_REPAIR && value == unix.TCP_REPAIR_ON {
			return syscall.EPERM
		}
		return nil
	}
	evidence, err := probeTCPRepair(context.Background(), probeTestTime(), ops)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 2 {
		t.Fatalf("evidence=%d want permission and base only", len(evidence))
	}
	for _, id := range []FeatureID{FeatureTCPRepairPermission, FeatureTCPRepairBase} {
		got := findTCPRepairEvidence(t, evidence, id)
		if got.State != FeaturePermissionDenied || got.Reason != ReasonPermissionDenied {
			t.Fatalf("%s=%s/%s", id, got.State, got.Reason)
		}
	}
	if pair.validates != 2 || pair.exchanges != 1 || pair.closes != 1 {
		t.Fatalf("denied probe did not prove original pair health: validates=%d exchanges=%d closes=%d", pair.validates, pair.exchanges, pair.closes)
	}
}

func TestProbeTCPRepairPairCreationDoesNotInventRepairPermission(t *testing.T) {
	for _, test := range []struct {
		name      string
		err       error
		reason    FeatureReason
		retryable bool
	}{
		{name: "sandbox denied socket", err: syscall.EPERM, reason: ReasonSyscallFailed},
		{name: "descriptor exhaustion", err: syscall.EMFILE, reason: ReasonResourceExhausted, retryable: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ops, _ := newFakeTCPRepairProbeOps(&fakeTCPRepairProbePair{})
			ops.open = func(context.Context) (tcpRepairProbePair, error) { return nil, test.err }
			evidence, err := probeTCPRepair(context.Background(), probeTestTime(), ops)
			if err != nil {
				t.Fatal(err)
			}
			if len(evidence) != len(tcpRepairFeatureIDs) {
				t.Fatalf("evidence=%d", len(evidence))
			}
			for _, id := range tcpRepairFeatureIDs {
				got := findTCPRepairEvidence(t, evidence, id)
				if got.State != FeatureProbeFailed || got.Reason != test.reason || got.Retryable != test.retryable {
					t.Fatalf("%s=%s/%s retryable=%v", id, got.State, got.Reason, got.Retryable)
				}
			}
		})
	}
}

func TestProbeTCPRepairBaseRequiresStateReadback(t *testing.T) {
	pair := &fakeTCPRepairProbePair{}
	ops, kernel := newFakeTCPRepairProbeOps(pair)
	kernel.getIntHook = func(option int) (int, error, bool) {
		if option == unix.TCP_REPAIR && kernel.repair == unix.TCP_REPAIR_ON {
			return unix.TCP_REPAIR_OFF, nil, true
		}
		return 0, nil, false
	}
	evidence, err := probeTCPRepair(context.Background(), probeTestTime(), ops)
	if err != nil {
		t.Fatal(err)
	}
	permission := findTCPRepairEvidence(t, evidence, FeatureTCPRepairPermission)
	base := findTCPRepairEvidence(t, evidence, FeatureTCPRepairBase)
	if permission.State != FeatureAvailable || base.State != FeatureProbeFailed || base.Reason != ReasonSemanticMismatch {
		t.Fatalf("permission=%s base=%s/%s", permission.State, base.State, base.Reason)
	}
}

func TestProbeTCPRepairStopsAfterQueueFailure(t *testing.T) {
	pair := &fakeTCPRepairProbePair{}
	ops, kernel := newFakeTCPRepairProbeOps(pair)
	kernel.setIntHook = func(option, value int) error {
		if option == unix.TCP_REPAIR_QUEUE && value == tcpRepairRecvQueue {
			return syscall.ENOPROTOOPT
		}
		return nil
	}
	evidence, err := probeTCPRepair(context.Background(), probeTestTime(), ops)
	if err != nil {
		t.Fatal(err)
	}
	queue := findTCPRepairEvidence(t, evidence, FeatureTCPRepairQueueSeq)
	if queue.State != FeatureUnsupported || queue.Reason != ReasonPrimitiveUnsupported {
		t.Fatalf("queue=%s/%s", queue.State, queue.Reason)
	}
	if hasTCPRepairEvidence(evidence, FeatureTCPRepairWindow) || hasTCPRepairEvidence(evidence, FeatureTCPRepairOptions) {
		t.Fatal("dependent stages ran after queue failure")
	}
}

func TestProbeTCPRepairQueueRequiresClosedSocketSetter(t *testing.T) {
	for _, test := range []struct {
		name   string
		setup  func(*fakeTCPRepairKernel)
		state  FeatureState
		reason FeatureReason
	}{
		{
			name: "setter denied",
			setup: func(kernel *fakeTCPRepairKernel) {
				kernel.setIntHook = func(option, _ int) error {
					if option == unix.TCP_QUEUE_SEQ {
						return syscall.EPERM
					}
					return nil
				}
			},
			state:  FeaturePermissionDenied,
			reason: ReasonPermissionDenied,
		},
		{
			name:   "setter ignored",
			setup:  func(kernel *fakeTCPRepairKernel) { kernel.ignoreScratchSequence = true },
			state:  FeatureProbeFailed,
			reason: ReasonSemanticMismatch,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			pair := &fakeTCPRepairProbePair{}
			ops, kernel := newFakeTCPRepairProbeOps(pair)
			test.setup(kernel)
			evidence, err := probeTCPRepair(context.Background(), probeTestTime(), ops)
			if err != nil {
				t.Fatal(err)
			}
			queue := findTCPRepairEvidence(t, evidence, FeatureTCPRepairQueueSeq)
			if queue.State != test.state || queue.Reason != test.reason {
				t.Fatalf("queue=%s/%s", queue.State, queue.Reason)
			}
			if kernel.scratchOpen || kernel.scratchCloses != 1 {
				t.Fatalf("scratch open=%v closes=%d", kernel.scratchOpen, kernel.scratchCloses)
			}
		})
	}
}

func TestProbeTCPRepairClassifiesWindowAndOptionsIndependently(t *testing.T) {
	for _, test := range []struct {
		name string
		id   FeatureID
		fail func(*fakeTCPRepairKernel)
	}{
		{name: "window", id: FeatureTCPRepairWindow, fail: func(kernel *fakeTCPRepairKernel) { kernel.getWindowErr = syscall.ENOPROTOOPT }},
		{name: "options", id: FeatureTCPRepairOptions, fail: func(kernel *fakeTCPRepairKernel) { kernel.setOptionsErr = syscall.EOPNOTSUPP }},
	} {
		t.Run(test.name, func(t *testing.T) {
			pair := &fakeTCPRepairProbePair{}
			ops, kernel := newFakeTCPRepairProbeOps(pair)
			test.fail(kernel)
			evidence, err := probeTCPRepair(context.Background(), probeTestTime(), ops)
			if err != nil {
				t.Fatal(err)
			}
			got := findTCPRepairEvidence(t, evidence, test.id)
			if got.State != FeatureUnsupported || got.Reason != ReasonPrimitiveUnsupported {
				t.Fatalf("%s=%s/%s", test.id, got.State, got.Reason)
			}
		})
	}
}

func TestProbeTCPRepairCleanupFailureRevokesEveryPositive(t *testing.T) {
	pair := &fakeTCPRepairProbePair{}
	ops, kernel := newFakeTCPRepairProbeOps(pair)
	kernel.setIntHook = func(option, value int) error {
		if option == unix.TCP_REPAIR && value == unix.TCP_REPAIR_OFF {
			return syscall.EIO
		}
		return nil
	}
	evidence, err := probeTCPRepair(context.Background(), probeTestTime(), ops)
	if err != nil {
		t.Fatal(err)
	}
	assertAllTCPRepairProbeFailed(t, evidence, ReasonSyscallFailed)
}

func TestProbeTCPRepairExchangeFailureRevokesEveryPositive(t *testing.T) {
	pair := &fakeTCPRepairProbePair{exchangeErr: errors.New("broken payload")}
	ops, _ := newFakeTCPRepairProbeOps(pair)
	evidence, err := probeTCPRepair(context.Background(), probeTestTime(), ops)
	if err != nil {
		t.Fatal(err)
	}
	assertAllTCPRepairProbeFailed(t, evidence, ReasonSemanticMismatch)
}

func TestProbeTCPRepairCloseFailureRevokesEveryPositive(t *testing.T) {
	pair := &fakeTCPRepairProbePair{closeErr: syscall.EIO}
	ops, _ := newFakeTCPRepairProbeOps(pair)
	evidence, err := probeTCPRepair(context.Background(), probeTestTime(), ops)
	if err != nil {
		t.Fatal(err)
	}
	assertAllTCPRepairProbeFailed(t, evidence, ReasonSyscallFailed)
}

func TestProbeTCPRepairCancellationStillRestoresAndChecksPair(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pair := &fakeTCPRepairProbePair{}
	ops, kernel := newFakeTCPRepairProbeOps(pair)
	kernel.setIntHook = func(option, value int) error {
		if option == unix.TCP_REPAIR && value == unix.TCP_REPAIR_ON {
			cancel()
		}
		return nil
	}
	evidence, err := probeTCPRepair(ctx, probeTestTime(), ops)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	if evidence != nil {
		t.Fatalf("canceled probe returned cacheable evidence: %+v", evidence)
	}
	if kernel.repair != unix.TCP_REPAIR_OFF || kernel.queue != tcpRepairNoQueue {
		t.Fatalf("repair=%d queue=%d after cancellation", kernel.repair, kernel.queue)
	}
	if pair.validates != 2 || pair.exchanges != 1 || pair.closes != 1 {
		t.Fatalf("validates=%d exchanges=%d closes=%d", pair.validates, pair.exchanges, pair.closes)
	}
}

func TestProbeTCPRepairRejectsSequenceValuesUnrelatedToPayload(t *testing.T) {
	pair := &fakeTCPRepairProbePair{}
	ops, _ := newFakeTCPRepairProbeOps(pair)
	pair.onExchange = nil
	evidence, err := probeTCPRepair(context.Background(), probeTestTime(), ops)
	if err != nil {
		t.Fatal(err)
	}
	assertAllTCPRepairProbeFailed(t, evidence, ReasonSemanticMismatch)
}

func TestProbeTCPRepairSequenceDeltaHandlesUint32Wrap(t *testing.T) {
	pair := &fakeTCPRepairProbePair{}
	ops, kernel := newFakeTCPRepairProbeOps(pair)
	kernel.sendSequence = ^uint32(0) - 10
	kernel.recvSequence = ^uint32(0) - 20
	evidence, err := probeTCPRepair(context.Background(), probeTestTime(), ops)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range tcpRepairFeatureIDs {
		if got := findTCPRepairEvidence(t, evidence, id); got.State != FeatureAvailable {
			t.Fatalf("%s=%s/%s", id, got.State, got.Reason)
		}
	}
}

func TestProbeTCPRepairWindowRejectsNoopSetter(t *testing.T) {
	pair := &fakeTCPRepairProbePair{}
	ops, kernel := newFakeTCPRepairProbeOps(pair)
	kernel.ignoreWindowWrites = true
	evidence, err := probeTCPRepair(context.Background(), probeTestTime(), ops)
	if err != nil {
		t.Fatal(err)
	}
	window := findTCPRepairEvidence(t, evidence, FeatureTCPRepairWindow)
	if window.State != FeatureProbeFailed || window.Reason != ReasonSemanticMismatch {
		t.Fatalf("window=%s/%s", window.State, window.Reason)
	}
}

func TestProbeTCPRepairOptionsWithoutObservableScaleFailClosed(t *testing.T) {
	pair := &fakeTCPRepairProbePair{}
	ops, kernel := newFakeTCPRepairProbeOps(pair)
	kernel.info.Options = 0
	kernel.info.WindowScale = 0
	evidence, err := probeTCPRepair(context.Background(), probeTestTime(), ops)
	if err != nil {
		t.Fatal(err)
	}
	if got := findTCPRepairEvidence(t, evidence, FeatureTCPRepairOptions); got.State != FeatureProbeFailed || got.Reason != ReasonSemanticMismatch {
		t.Fatalf("options=%s/%s", got.State, got.Reason)
	}
	for _, call := range kernel.setCalls {
		if call[0] == unix.TCP_TIMESTAMP {
			t.Fatal("probe touched TCP_TIMESTAMP when timestamps were not negotiated")
		}
	}
	if kernel.setOptionsCalls != 0 {
		t.Fatalf("set options calls=%d", kernel.setOptionsCalls)
	}
}

func TestProbeTCPRepairOptionsSkipUnnegotiatedTimestamp(t *testing.T) {
	pair := &fakeTCPRepairProbePair{}
	ops, kernel := newFakeTCPRepairProbeOps(pair)
	kernel.info.Options = tcpInfoWindowScale
	evidence, err := probeTCPRepair(context.Background(), probeTestTime(), ops)
	if err != nil {
		t.Fatal(err)
	}
	if got := findTCPRepairEvidence(t, evidence, FeatureTCPRepairOptions); got.State != FeatureAvailable {
		t.Fatalf("options=%s/%s", got.State, got.Reason)
	}
	for _, call := range kernel.setCalls {
		if call[0] == unix.TCP_TIMESTAMP {
			t.Fatal("probe touched TCP_TIMESTAMP when timestamps were not negotiated")
		}
	}
	if kernel.setOptionsCalls != 2 || len(kernel.setOptions) != 2 {
		t.Fatalf("set options calls=%d options=%+v", kernel.setOptionsCalls, kernel.setOptions)
	}
}

func TestProbeTCPRepairOptionsRejectLargeTimestampDrift(t *testing.T) {
	pair := &fakeTCPRepairProbePair{}
	ops, kernel := newFakeTCPRepairProbeOps(pair)
	timestampReads := 0
	kernel.getIntHook = func(option int) (int, error, bool) {
		if option != unix.TCP_TIMESTAMP {
			return 0, nil, false
		}
		timestampReads++
		if timestampReads == 1 {
			return 101, nil, true
		}
		return 10_000_101, nil, true
	}
	evidence, err := probeTCPRepair(context.Background(), probeTestTime(), ops)
	if err != nil {
		t.Fatal(err)
	}
	options := findTCPRepairEvidence(t, evidence, FeatureTCPRepairOptions)
	if options.State != FeatureProbeFailed || options.Reason != ReasonSemanticMismatch {
		t.Fatalf("options=%s/%s", options.State, options.Reason)
	}
}

func TestProbeTCPRepairOptionsRejectNoopSetters(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*fakeTCPRepairKernel)
	}{
		{name: "options", setup: func(kernel *fakeTCPRepairKernel) { kernel.ignoreOptionsWrites = true }},
		{name: "timestamp", setup: func(kernel *fakeTCPRepairKernel) { kernel.ignoreTimestampWrites = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			pair := &fakeTCPRepairProbePair{}
			ops, kernel := newFakeTCPRepairProbeOps(pair)
			test.setup(kernel)
			evidence, err := probeTCPRepair(context.Background(), probeTestTime(), ops)
			if err != nil {
				t.Fatal(err)
			}
			options := findTCPRepairEvidence(t, evidence, FeatureTCPRepairOptions)
			if options.State != FeatureProbeFailed || options.Reason != ReasonSemanticMismatch {
				t.Fatalf("options=%s/%s", options.State, options.Reason)
			}
		})
	}
}

func TestProbeTCPRepairTimestampUsesOpaqueWrapAwareClock(t *testing.T) {
	for _, test := range []struct {
		name    string
		initial uint32
	}{
		{name: "kernel5 odd millisecond step", initial: 100},
		{name: "uint32 wrap", initial: ^uint32(0) - 5},
	} {
		t.Run(test.name, func(t *testing.T) {
			pair := &fakeTCPRepairProbePair{}
			ops, kernel := newFakeTCPRepairProbeOps(pair)
			kernel.timestamp = int(test.initial)
			reads := 0
			kernel.getIntHook = func(option int) (int, error, bool) {
				if option != unix.TCP_TIMESTAMP {
					return 0, nil, false
				}
				reads++
				advance := uint32(0)
				if reads == 2 {
					advance = 1
				} else if reads >= 3 {
					advance = 3
				}
				return int(uint32(kernel.timestamp) + advance), nil, true
			}
			evidence, err := probeTCPRepair(context.Background(), probeTestTime(), ops)
			if err != nil {
				t.Fatal(err)
			}
			if got := findTCPRepairEvidence(t, evidence, FeatureTCPRepairOptions); got.State != FeatureAvailable {
				t.Fatalf("options=%s/%s", got.State, got.Reason)
			}
		})
	}
}

func TestProbeTCPRepairInitialTupleValidationPreventsMutation(t *testing.T) {
	pair := &fakeTCPRepairProbePair{validateErr: errors.New("tuple mismatch")}
	ops, kernel := newFakeTCPRepairProbeOps(pair)
	evidence, err := probeTCPRepair(context.Background(), probeTestTime(), ops)
	if err != nil {
		t.Fatal(err)
	}
	assertAllTCPRepairProbeFailed(t, evidence, ReasonSemanticMismatch)
	if len(kernel.setCalls) != 0 || pair.exchanges != 0 || pair.closes != 1 {
		t.Fatalf("mutation after invalid tuple: sets=%v exchanges=%d closes=%d", kernel.setCalls, pair.exchanges, pair.closes)
	}
}

func TestProbeTCPRepairRejectsIncompleteOps(t *testing.T) {
	if _, err := probeTCPRepair(context.Background(), probeTestTime(), tcpRepairProbeOps{}); err == nil {
		t.Fatal("incomplete operations accepted")
	}
}

func probeTestTime() time.Time {
	return time.Unix(1_700_000_000, 0).UTC()
}

func findTCPRepairEvidence(t *testing.T, evidence []FeatureEvidence, id FeatureID) FeatureEvidence {
	t.Helper()
	for _, got := range evidence {
		if got.ID == id {
			return got
		}
	}
	t.Fatalf("no evidence for %s", id)
	return FeatureEvidence{}
}

func hasTCPRepairEvidence(evidence []FeatureEvidence, id FeatureID) bool {
	for _, got := range evidence {
		if got.ID == id {
			return true
		}
	}
	return false
}

func assertAllTCPRepairProbeFailed(t *testing.T, evidence []FeatureEvidence, reason FeatureReason) {
	t.Helper()
	if len(evidence) != len(tcpRepairFeatureIDs) {
		t.Fatalf("evidence=%d want %d", len(evidence), len(tcpRepairFeatureIDs))
	}
	for _, id := range tcpRepairFeatureIDs {
		got := findTCPRepairEvidence(t, evidence, id)
		if got.State != FeatureProbeFailed || got.Reason != reason {
			t.Fatalf("%s=%s/%s want probe_failed/%s", id, got.State, got.Reason, reason)
		}
	}
}
