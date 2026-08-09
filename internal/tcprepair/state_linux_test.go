//go:build linux && amd64

package tcprepair

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

var errFakeSocketCall = errors.New("fake socket call failed")

func TestInspectFDRejectsBeforeRepair(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fakeLinuxSocketOps)
		want   error
	}{
		{
			name: "non-established state",
			mutate: func(ops *fakeLinuxSocketOps) {
				ops.tcpInfo[0] = 7
			},
			want: ErrIneligibleState,
		},
		{
			name: "unknown negotiated option",
			mutate: func(ops *fakeLinuxSocketOps) {
				ops.tcpInfo[5] |= 0x80
			},
			want: ErrUnsupportedOption,
		},
		{
			name: "invalid window scale",
			mutate: func(ops *fakeLinuxSocketOps) {
				ops.tcpInfo[6] = 4<<4 | 15
			},
			want: ErrUnsupportedOption,
		},
		{
			name: "ULP installed",
			mutate: func(ops *fakeLinuxSocketOps) {
				ops.ulp = "tls"
			},
			want: ErrUnsupportedOption,
		},
		{
			name: "ULP cannot be inspected",
			mutate: func(ops *fakeLinuxSocketOps) {
				ops.ulpErr = unix.EPERM
			},
			want: ErrUnsupportedOption,
		},
		{
			name: "keepalive enabled",
			mutate: func(ops *fakeLinuxSocketOps) {
				ops.intValues[socketOption{unix.SOL_SOCKET, unix.SO_KEEPALIVE}] = 1
			},
			want: ErrUnsupportedOption,
		},
		{
			name: "cork enabled",
			mutate: func(ops *fakeLinuxSocketOps) {
				ops.intValues[socketOption{unix.IPPROTO_TCP, unix.TCP_CORK}] = 1
			},
			want: ErrUnsupportedOption,
		},
		{
			name: "user timeout enabled",
			mutate: func(ops *fakeLinuxSocketOps) {
				ops.intValues[socketOption{unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT}] = 1
			},
			want: ErrUnsupportedOption,
		},
		{
			name: "receive queue exceeds budget",
			mutate: func(ops *fakeLinuxSocketOps) {
				ops.ioctlValues[uint(unix.SIOCINQ)] = MaxQueueBytes + 1
			},
			want: ErrQueueBudget,
		},
		{
			name: "send queue exceeds budget",
			mutate: func(ops *fakeLinuxSocketOps) {
				ops.ioctlValues[uint(unix.SIOCOUTQ)] = MaxQueueBytes + 1
			},
			want: ErrQueueBudget,
		},
		{
			name: "unsent queue exceeds budget",
			mutate: func(ops *fakeLinuxSocketOps) {
				ops.ioctlValues[uint(unix.SIOCOUTQNSD)] = MaxQueueBytes + 1
			},
			want: ErrQueueBudget,
		},
		{
			name: "unsent queue exceeds send queue",
			mutate: func(ops *fakeLinuxSocketOps) {
				ops.ioctlValues[uint(unix.SIOCOUTQ)] = 1
				ops.ioctlValues[uint(unix.SIOCOUTQNSD)] = 2
			},
			want: ErrIneligibleState,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ops := newFakeLinuxSocketOps()
			test.mutate(ops)

			_, err := inspectFD(ops.fd, testLinuxTuple(), ops)
			if !errors.Is(err, test.want) {
				t.Fatalf("inspectFD() error = %v, want %v\ncalls:\n%s", err, test.want, ops.trace())
			}
			for _, call := range ops.calls {
				if isSetInt(call, unix.IPPROTO_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_ON) {
					t.Fatalf("inspectFD() entered repair before rejecting endpoint\ncalls:\n%s", ops.trace())
				}
			}
		})
	}
}

func TestCaptureFDSuccessKeepsSocketInRepair(t *testing.T) {
	ops := newFakeLinuxSocketOps()

	result, err := captureFD(ops.fd, testLinuxTuple(), ops)
	if err != nil {
		t.Fatalf("captureFD() error = %v\ncalls:\n%s", err, ops.trace())
	}
	if result.state != SourceStateRepair || result.snapshot == nil {
		t.Fatalf("capture result = (state=%d snapshot=%v), want repair snapshot", result.state, result.snapshot)
	}
	snapshot := result.snapshot
	if err := snapshot.valid(); err != nil {
		t.Fatalf("captured snapshot is invalid: %v", err)
	}
	if !ops.repair {
		t.Fatalf("captureFD() resumed socket on success\ncalls:\n%s", ops.trace())
	}
	if ops.queue != tcpNoQueue {
		t.Fatalf("captureFD() left queue %d selected, want no queue", ops.queue)
	}
	if got := countCalls(ops.calls, func(call fakeSocketCall) bool {
		return isSetInt(call, unix.IPPROTO_TCP, unix.TCP_REPAIR, 0)
	}); got != 0 {
		t.Fatalf("captureFD() issued %d repair-off calls on success\ncalls:\n%s", got, ops.trace())
	}
	if !bytes.Equal(snapshot.receiveQueue, ops.queueBytes[tcpRecvQueue]) {
		t.Fatalf("receive queue = %x, want %x", snapshot.receiveQueue, ops.queueBytes[tcpRecvQueue])
	}
	if !bytes.Equal(snapshot.sendQueue, ops.queueBytes[tcpSendQueue]) {
		t.Fatalf("send queue = %x, want %x", snapshot.sendQueue, ops.queueBytes[tcpSendQueue])
	}

	receives := matchingCalls(ops.calls, func(call fakeSocketCall) bool { return call.op == "recv" })
	if len(receives) != 2 {
		t.Fatalf("recv call count = %d, want 2\ncalls:\n%s", len(receives), ops.trace())
	}
	for _, call := range receives {
		wantSize := len(ops.queueBytes[call.queue]) + 1
		if call.size != wantSize {
			t.Fatalf("queue %d recv buffer = %d, want %d", call.queue, call.size, wantSize)
		}
		if call.flags != unix.MSG_PEEK|unix.MSG_DONTWAIT {
			t.Fatalf("queue %d recv flags = %#x, want MSG_PEEK|MSG_DONTWAIT", call.queue, call.flags)
		}
	}
}

func TestCaptureFDFailureAfterFreezeAlwaysResumes(t *testing.T) {
	baseline := newFakeLinuxSocketOps()
	if _, err := captureFD(baseline.fd, testLinuxTuple(), baseline); err != nil {
		t.Fatalf("establish capture baseline: %v", err)
	}
	repairEntry := mustFindCall(t, baseline.calls, func(call fakeSocketCall) bool {
		return isSetInt(call, unix.IPPROTO_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_ON)
	})

	for failureIndex := repairEntry + 1; failureIndex < len(baseline.calls); failureIndex++ {
		failedCall := baseline.calls[failureIndex]
		t.Run(fmt.Sprintf("call_%02d_%s", failureIndex, failedCall.op), func(t *testing.T) {
			ops := newFakeLinuxSocketOps()
			ops.failAt = failureIndex

			result, err := captureFD(ops.fd, testLinuxTuple(), ops)
			if result.snapshot != nil {
				t.Fatal("captureFD() returned a snapshot after injected failure")
			}
			if result.state != SourceStateNormal {
				t.Fatalf("captureFD() source state = %d, want normal after successful unwind", result.state)
			}
			if !errors.Is(err, errFakeSocketCall) {
				t.Fatalf("captureFD() error = %v, want injected error\ncalls:\n%s", err, ops.trace())
			}
			assertCaptureCleanup(t, ops)
		})
	}

	t.Run("snapshot seal failure", func(t *testing.T) {
		ops := newFakeLinuxSocketOps()
		result, err := captureFD(ops.fd, Tuple{}, ops)
		if result.snapshot != nil || result.state != SourceStateNormal || !errors.Is(err, ErrSnapshotInvalid) {
			t.Fatalf("captureFD() = (%+v, %v), want normal nil-snapshot ErrSnapshotInvalid", result, err)
		}
		assertCaptureCleanup(t, ops)
	})
}

func TestCaptureFDPreRepairInspectionFailureDoesNotMutate(t *testing.T) {
	for _, failureIndex := range []int{0, 1} {
		t.Run(fmt.Sprintf("call_%d", failureIndex), func(t *testing.T) {
			ops := newFakeLinuxSocketOps()
			ops.failAt = failureIndex
			result, err := captureFD(ops.fd, testLinuxTuple(), ops)
			if result.snapshot != nil || result.state != SourceStateNormal || !errors.Is(err, errFakeSocketCall) {
				t.Fatalf("captureFD() = (%+v, %v), want non-destructive failure", result, err)
			}
			for _, call := range ops.calls {
				if call.op == "setInt" {
					t.Fatalf("pre-repair inspection mutated socket:\n%s", ops.trace())
				}
			}
		})
	}
}

func TestCaptureFDReportsUnknownWhenFailureCannotLeaveRepair(t *testing.T) {
	leaveFailure := errors.New("repair-off failed")
	readbackFailure := errors.New("repair state readback failed")
	ops := newFakeLinuxSocketOps()
	ops.setIntResults[socketOption{unix.IPPROTO_TCP, unix.TCP_REPAIR}] = []error{nil, leaveFailure}
	ops.intResults[socketOption{unix.IPPROTO_TCP, unix.TCP_REPAIR}] = []fakeIntResult{
		{value: unix.TCP_REPAIR_ON},
		{err: readbackFailure},
	}

	result, err := captureFD(ops.fd, Tuple{}, ops)
	if result.snapshot != nil || result.state != SourceStateUnknown {
		t.Fatalf("captureFD() result = %+v, want unknown without snapshot", result)
	}
	if !errors.Is(err, ErrSnapshotInvalid) || !errors.Is(err, leaveFailure) ||
		!errors.Is(err, readbackFailure) || !errors.Is(err, ErrSourceStateUnknown) {
		t.Fatalf("captureFD() error = %v, want snapshot and unwind failures", err)
	}
	if !ops.repair {
		t.Fatal("fake source did not remain in repair after failed unwind")
	}
}

func TestCaptureFDEnterRepairFailureDoesNotMutateAgain(t *testing.T) {
	ops := newFakeLinuxSocketOps()
	baseline := newFakeLinuxSocketOps()
	if _, err := captureFD(baseline.fd, testLinuxTuple(), baseline); err != nil {
		t.Fatal(err)
	}
	ops.failAt = mustFindCall(t, baseline.calls, func(call fakeSocketCall) bool {
		return isSetInt(call, unix.IPPROTO_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_ON)
	})

	result, err := captureFD(ops.fd, testLinuxTuple(), ops)
	if result.snapshot != nil || result.state != SourceStateNormal || !errors.Is(err, errFakeSocketCall) {
		t.Fatalf("captureFD() = (%+v, %v), want normal nil-snapshot injected error", result, err)
	}
	if len(ops.calls) != ops.failAt+2 ||
		!isSetInt(ops.calls[ops.failAt], unix.IPPROTO_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_ON) ||
		ops.calls[ops.failAt+1].op != "getInt" || ops.calls[ops.failAt+1].option != unix.TCP_REPAIR {
		t.Fatalf("calls after failed repair entry:\n%s", ops.trace())
	}
}

func TestCaptureQueueUsesLengthPlusOneProbe(t *testing.T) {
	tests := []struct {
		name      string
		queue     []byte
		wantError bool
	}{
		{name: "exact", queue: []byte("1234")},
		{name: "grew", queue: []byte("12345"), wantError: true},
		{name: "shrunk", queue: []byte("123"), wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ops := newFakeLinuxSocketOps()
			ops.repair = true
			ops.queueBytes[tcpRecvQueue] = append([]byte(nil), test.queue...)
			const expected = uint32(4)

			sequence, value, err := captureQueue(ops.fd, tcpRecvQueue, expected, "receive", ops)
			if test.wantError {
				if !errors.Is(err, ErrIneligibleState) {
					t.Fatalf("captureQueue() error = %v, want ErrIneligibleState", err)
				}
			} else {
				if err != nil {
					t.Fatalf("captureQueue() error = %v", err)
				}
				if sequence != ops.queueSequences[tcpRecvQueue] || !bytes.Equal(value, test.queue) {
					t.Fatalf("captureQueue() = (%d, %x), want (%d, %x)", sequence, value,
						ops.queueSequences[tcpRecvQueue], test.queue)
				}
			}

			receives := matchingCalls(ops.calls, func(call fakeSocketCall) bool { return call.op == "recv" })
			if len(receives) != 1 || receives[0].size != int(expected)+1 {
				t.Fatalf("recv probe calls = %+v, want one %d-byte probe", receives, expected+1)
			}
		})
	}
}

func TestRestoreFDReplaysExactTCPStateAndUnsentTail(t *testing.T) {
	snapshot := testLinuxSnapshot(t)
	ops := newFakeLinuxSocketOps()

	fd, err := restoreFD(context.Background(), snapshot, ops)
	if err != nil {
		t.Fatalf("restoreFD() error = %v\ncalls:\n%s", err, ops.trace())
	}
	if fd != ops.fd {
		t.Fatalf("restoreFD() fd = %d, want %d", fd, ops.fd)
	}
	if ops.closed {
		t.Fatalf("restoreFD() closed successful replacement\ncalls:\n%s", ops.trace())
	}
	transparentCalls := matchingCalls(ops.calls, func(call fakeSocketCall) bool {
		return isSetInt(call, unix.SOL_IP, unix.IP_TRANSPARENT, 1)
	})
	transparent := findCall(ops.calls, func(call fakeSocketCall) bool {
		return isSetInt(call, unix.SOL_IP, unix.IP_TRANSPARENT, 1)
	})
	bind := findCall(ops.calls, func(call fakeSocketCall) bool { return call.op == "bind" })
	if len(transparentCalls) != 1 || transparent < 0 || bind <= transparent {
		t.Fatalf("successful restore did not set IP_TRANSPARENT exactly once before bind\ncalls:\n%s", ops.trace())
	}
	connect := findCall(ops.calls, func(call fakeSocketCall) bool { return call.op == "connect" })
	transparentClear := findCall(ops.calls, func(call fakeSocketCall) bool {
		return isSetInt(call, unix.SOL_IP, unix.IP_TRANSPARENT, 0)
	})
	transparentReadback := findCall(ops.calls, func(call fakeSocketCall) bool {
		return call.op == "getInt" && call.level == unix.SOL_IP && call.option == unix.IP_TRANSPARENT
	})
	if connect < 0 || transparentClear <= connect || transparentReadback <= transparentClear || ops.transparent {
		t.Fatalf("successful restore retained temporary IP_TRANSPARENT\ncalls:\n%s", ops.trace())
	}

	sequenceCalls := matchingCalls(ops.calls, func(call fakeSocketCall) bool {
		return call.op == "setInt" && call.level == unix.IPPROTO_TCP && call.option == unix.TCP_QUEUE_SEQ
	})
	if len(sequenceCalls) != 2 {
		t.Fatalf("TCP_QUEUE_SEQ call count = %d, want 2\ncalls:\n%s", len(sequenceCalls), ops.trace())
	}
	wantReceiveStart := snapshot.receiveSequence - uint32(len(snapshot.receiveQueue))
	wantSendStart := snapshot.sendSequence - uint32(len(snapshot.sendQueue))
	if sequenceCalls[0].queue != tcpRecvQueue || uint32(sequenceCalls[0].value) != wantReceiveStart {
		t.Fatalf("receive queue start = queue %d seq %#x, want queue %d seq %#x",
			sequenceCalls[0].queue, uint32(sequenceCalls[0].value), tcpRecvQueue, wantReceiveStart)
	}
	if sequenceCalls[1].queue != tcpSendQueue || uint32(sequenceCalls[1].value) != wantSendStart {
		t.Fatalf("send queue start = queue %d seq %#x, want queue %d seq %#x",
			sequenceCalls[1].queue, uint32(sequenceCalls[1].value), tcpSendQueue, wantSendStart)
	}

	optionCalls := matchingCalls(ops.calls, func(call fakeSocketCall) bool {
		return call.op == "setRepairOptions"
	})
	wantOptions := []unix.TCPRepairOpt{
		{Code: tcpOptionSACK},
		{Code: tcpOptionWindow, Val: uint32(snapshot.options.SendScale) | uint32(snapshot.options.ReceiveScale)<<16},
		{Code: tcpOptionTimestamps},
		{Code: tcpOptionMSS, Val: snapshot.options.MSSClamp},
	}
	if len(optionCalls) != 1 || !reflect.DeepEqual(optionCalls[0].repairOptions, wantOptions) {
		t.Fatalf("TCP_REPAIR_OPTIONS = %+v, want %+v", optionCalls, wantOptions)
	}

	writes := matchingCalls(ops.calls, func(call fakeSocketCall) bool { return call.op == "write" })
	if len(writes) != 3 {
		t.Fatalf("write call count = %d, want receive/sent/unsent\ncalls:\n%s", len(writes), ops.trace())
	}
	sentBytes := len(snapshot.sendQueue) - int(snapshot.unsentBytes)
	assertWriteCall(t, writes[0], true, tcpRecvQueue, snapshot.receiveQueue)
	assertWriteCall(t, writes[1], true, tcpSendQueue, snapshot.sendQueue[:sentBytes])
	assertWriteCall(t, writes[2], false, tcpNoQueue, snapshot.sendQueue[sentBytes:])

	repairOff := findCall(ops.calls, func(call fakeSocketCall) bool {
		return isSetInt(call, unix.IPPROTO_TCP, unix.TCP_REPAIR, 0)
	})
	unsentWrite := findCall(ops.calls, func(call fakeSocketCall) bool {
		return call.op == "write" && !call.repair
	})
	if repairOff < 0 || unsentWrite <= repairOff {
		t.Fatalf("unsent tail was not written after repair-off\ncalls:\n%s", ops.trace())
	}
}

func TestRestoreFDPreservesOwnedBindingOptions(t *testing.T) {
	snapshot := testLinuxSnapshot(t)
	snapshot.options.ReuseAddress = true
	snapshot.options.Transparent = true
	snapshot.digest = [32]byte{}
	if err := snapshot.seal(); err != nil {
		t.Fatal(err)
	}
	ops := newFakeLinuxSocketOps()
	if _, err := restoreFD(context.Background(), snapshot, ops); err != nil {
		t.Fatalf("restoreFD() error = %v\ncalls:\n%s", err, ops.trace())
	}
	if !ops.reuseAddress || !ops.transparent {
		t.Fatalf("restored options reuse=%v transparent=%v", ops.reuseAddress, ops.transparent)
	}
}

func TestRestoreFDTupleReadbackMismatchRefreezesAndCloses(t *testing.T) {
	snapshot := testLinuxSnapshot(t)
	ops := newFakeLinuxSocketOps()
	ops.remote = sockaddr(netip.MustParseAddrPort("203.0.113.9:443"))
	fd, err := restoreFD(context.Background(), snapshot, ops)
	if fd != -1 || err == nil {
		t.Fatalf("restoreFD() = (%d, %v), want tuple validation failure", fd, err)
	}
	if !ops.closed || !ops.calls[len(ops.calls)-1].repair {
		t.Fatalf("tuple mismatch did not refreeze and close\ncalls:\n%s", ops.trace())
	}
}

func TestRestoreFDIPTransparentFailureRefreezesAndCloses(t *testing.T) {
	snapshot := testLinuxSnapshot(t)
	baseline := newFakeLinuxSocketOps()
	if _, err := restoreFD(context.Background(), snapshot, baseline); err != nil {
		t.Fatalf("establish restore baseline: %v", err)
	}

	ops := newFakeLinuxSocketOps()
	ops.failAt = mustFindCall(t, baseline.calls, func(call fakeSocketCall) bool {
		return isSetInt(call, unix.SOL_IP, unix.IP_TRANSPARENT, 1)
	})
	fd, err := restoreFD(context.Background(), snapshot, ops)
	if fd != -1 || !errors.Is(err, errFakeSocketCall) {
		t.Fatalf("restoreFD() = (%d, %v), want -1 wrapped injected error\ncalls:\n%s", fd, err, ops.trace())
	}
	if got, want := err.Error(), "tcprepair: set IP_TRANSPARENT: "+errFakeSocketCall.Error(); got != want {
		t.Fatalf("restoreFD() error = %q, want %q", got, want)
	}
	if !ops.closed || len(ops.calls) < 3 {
		t.Fatalf("IP_TRANSPARENT failure did not close replacement\ncalls:\n%s", ops.trace())
	}
	cleanup := ops.calls[len(ops.calls)-3:]
	if !isSetInt(cleanup[0], unix.IPPROTO_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_ON) ||
		!isSetInt(cleanup[1], unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, tcpNoQueue) ||
		cleanup[2].op != "close" || !cleanup[2].repair {
		t.Fatalf("IP_TRANSPARENT failure did not refreeze, select no queue, and close\ncalls:\n%s", ops.trace())
	}
}

func TestRestoreFDIPTransparentCleanupFailureRefreezesAndCloses(t *testing.T) {
	snapshot := testLinuxSnapshot(t)
	baseline := newFakeLinuxSocketOps()
	if _, err := restoreFD(context.Background(), snapshot, baseline); err != nil {
		t.Fatalf("establish restore baseline: %v", err)
	}

	tests := []struct {
		name string
		call func(fakeSocketCall) bool
	}{
		{
			name: "clear",
			call: func(call fakeSocketCall) bool {
				return isSetInt(call, unix.SOL_IP, unix.IP_TRANSPARENT, 0)
			},
		},
		{
			name: "readback",
			call: func(call fakeSocketCall) bool {
				return call.op == "getInt" && call.level == unix.SOL_IP && call.option == unix.IP_TRANSPARENT
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ops := newFakeLinuxSocketOps()
			ops.failAt = mustFindCall(t, baseline.calls, test.call)
			fd, err := restoreFD(context.Background(), snapshot, ops)
			if fd != -1 || !errors.Is(err, errFakeSocketCall) {
				t.Fatalf("restoreFD() = (%d, %v), want injected cleanup failure\ncalls:\n%s", fd, err, ops.trace())
			}
			if !ops.closed || !ops.calls[len(ops.calls)-1].repair {
				t.Fatalf("temporary option cleanup failure did not refreeze and close\ncalls:\n%s", ops.trace())
			}
		})
	}
}

func TestRestoreFDFailureRefreezesAndCloses(t *testing.T) {
	snapshot := testLinuxSnapshot(t)
	baseline := newFakeLinuxSocketOps()
	if _, err := restoreFD(context.Background(), snapshot, baseline); err != nil {
		t.Fatalf("establish restore baseline: %v", err)
	}

	tests := []struct {
		name         string
		failureIndex int
		wantRefreeze bool
	}{
		{
			name: "before initial freeze",
			failureIndex: mustFindCall(t, baseline.calls, func(call fakeSocketCall) bool {
				return isSetInt(call, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
			}),
			wantRefreeze: true,
		},
		{
			name: "while frozen",
			failureIndex: mustFindCall(t, baseline.calls, func(call fakeSocketCall) bool {
				return call.op == "connect"
			}),
			wantRefreeze: false,
		},
		{
			name: "after repair off",
			failureIndex: mustFindCall(t, baseline.calls, func(call fakeSocketCall) bool {
				return call.op == "setNonblock"
			}),
			wantRefreeze: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ops := newFakeLinuxSocketOps()
			ops.failAt = test.failureIndex

			fd, err := restoreFD(context.Background(), snapshot, ops)
			if fd != -1 || !errors.Is(err, errFakeSocketCall) {
				t.Fatalf("restoreFD() = (%d, %v), want -1 injected error\ncalls:\n%s", fd, err, ops.trace())
			}
			if !ops.closed {
				t.Fatalf("restoreFD() did not close failed replacement\ncalls:\n%s", ops.trace())
			}
			if len(ops.calls) < 2 || ops.calls[len(ops.calls)-1].op != "close" ||
				!isSetInt(ops.calls[len(ops.calls)-2], unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, tcpNoQueue) {
				t.Fatalf("failed restore did not select no queue and close\ncalls:\n%s", ops.trace())
			}
			if !ops.calls[len(ops.calls)-1].repair {
				t.Fatalf("failed restore closed an unfrozen socket\ncalls:\n%s", ops.trace())
			}
			refreeze := countCalls(ops.calls[test.failureIndex+1:], func(call fakeSocketCall) bool {
				return isSetInt(call, unix.IPPROTO_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_ON)
			}) != 0
			if refreeze != test.wantRefreeze {
				t.Fatalf("refreeze after failure = %v, want %v\ncalls:\n%s", refreeze, test.wantRefreeze, ops.trace())
			}
		})
	}
}

func TestRestoreFDCloseFailureMarksCleanupUnknown(t *testing.T) {
	closeFailure := errors.New("raw replacement close failed")
	snapshot := testLinuxSnapshot(t)
	ops := newFakeLinuxSocketOps()
	ops.failAt = 1 // SO_REUSEADDR, after socket creation.
	ops.closeErr = closeFailure

	fd, err := restoreFD(context.Background(), snapshot, ops)
	if fd != -1 || !errors.Is(err, errFakeSocketCall) || !errors.Is(err, closeFailure) ||
		!errors.Is(err, ErrRestoreCleanupUnknown) {
		t.Fatalf("restoreFD() = (%d, %v), want primary + close + cleanup-unknown", fd, err)
	}
	if ops.closed {
		t.Fatal("fake close failure was reported as proven closed")
	}
}

func TestRestoreFDContextCancellationStopsUnsentWrite(t *testing.T) {
	snapshot := testLinuxSnapshot(t)
	ops := newFakeLinuxSocketOps()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ops.writeHook = func(call fakeSocketCall) (int, error) {
		if !call.repair {
			return 0, unix.EAGAIN
		}
		return len(call.data), nil
	}
	ops.pollHook = func([]unix.PollFd, int) (int, error) {
		cancel()
		return 0, nil
	}

	fd, err := restoreFD(ctx, snapshot, ops)
	if fd != -1 || !errors.Is(err, context.Canceled) {
		t.Fatalf("restoreFD() = (%d, %v), want -1 context.Canceled\ncalls:\n%s", fd, err, ops.trace())
	}
	nonRepairWrites := matchingCalls(ops.calls, func(call fakeSocketCall) bool {
		return call.op == "write" && !call.repair
	})
	if len(nonRepairWrites) != 1 {
		t.Fatalf("unsent write attempts = %d, want 1\ncalls:\n%s", len(nonRepairWrites), ops.trace())
	}
	if got := countCalls(ops.calls, func(call fakeSocketCall) bool { return call.op == "poll" }); got != 1 {
		t.Fatalf("poll calls = %d, want 1\ncalls:\n%s", got, ops.trace())
	}
	if !ops.closed || !ops.calls[len(ops.calls)-1].repair {
		t.Fatalf("canceled restore was not refrozen and closed\ncalls:\n%s", ops.trace())
	}
}

func TestEnsureSocketBufferPaths(t *testing.T) {
	const (
		wanted = uint32(2048)
		option = unix.SO_SNDBUF
		force  = unix.SO_SNDBUFFORCE
	)
	request := int((wanted + 1) / 2)
	key := socketOption{unix.SOL_SOCKET, option}

	tests := []struct {
		name          string
		results       []fakeIntResult
		regularErr    error
		wantErr       bool
		wantBufferOps []fakeSocketCall
	}{
		{
			name:    "already sufficient",
			results: []fakeIntResult{{value: int(wanted)}},
			wantBufferOps: []fakeSocketCall{
				{op: "getInt", level: unix.SOL_SOCKET, option: option},
			},
		},
		{
			name:    "regular set and verify",
			results: []fakeIntResult{{value: 512}, {value: int(wanted)}},
			wantBufferOps: []fakeSocketCall{
				{op: "getInt", level: unix.SOL_SOCKET, option: option},
				{op: "setInt", level: unix.SOL_SOCKET, option: option, value: request},
				{op: "getInt", level: unix.SOL_SOCKET, option: option},
			},
		},
		{
			name:       "force after regular failure",
			results:    []fakeIntResult{{value: 512}, {value: 512}, {value: int(wanted)}},
			regularErr: unix.EPERM,
			wantBufferOps: []fakeSocketCall{
				{op: "getInt", level: unix.SOL_SOCKET, option: option},
				{op: "setInt", level: unix.SOL_SOCKET, option: option, value: request},
				{op: "getInt", level: unix.SOL_SOCKET, option: option},
				{op: "setInt", level: unix.SOL_SOCKET, option: force, value: request},
				{op: "getInt", level: unix.SOL_SOCKET, option: option},
			},
		},
		{
			name:    "force after verify error",
			results: []fakeIntResult{{value: 512}, {err: unix.EIO}, {value: int(wanted)}},
			wantBufferOps: []fakeSocketCall{
				{op: "getInt", level: unix.SOL_SOCKET, option: option},
				{op: "setInt", level: unix.SOL_SOCKET, option: option, value: request},
				{op: "getInt", level: unix.SOL_SOCKET, option: option},
				{op: "setInt", level: unix.SOL_SOCKET, option: force, value: request},
				{op: "getInt", level: unix.SOL_SOCKET, option: option},
			},
		},
		{
			name:    "final verification too small",
			results: []fakeIntResult{{value: 512}, {value: 1024}, {value: 1024}},
			wantErr: true,
			wantBufferOps: []fakeSocketCall{
				{op: "getInt", level: unix.SOL_SOCKET, option: option},
				{op: "setInt", level: unix.SOL_SOCKET, option: option, value: request},
				{op: "getInt", level: unix.SOL_SOCKET, option: option},
				{op: "setInt", level: unix.SOL_SOCKET, option: force, value: request},
				{op: "getInt", level: unix.SOL_SOCKET, option: option},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ops := newFakeLinuxSocketOps()
			ops.intResults[key] = append([]fakeIntResult(nil), test.results...)
			if test.regularErr != nil {
				ops.setIntErrors[key] = test.regularErr
			}

			err := ensureSocketBuffer(ops.fd, option, force, wanted, ops)
			if (err != nil) != test.wantErr {
				t.Fatalf("ensureSocketBuffer() error = %v, wantErr %v\ncalls:\n%s", err, test.wantErr, ops.trace())
			}
			got := matchingCalls(ops.calls, func(call fakeSocketCall) bool {
				return call.level == unix.SOL_SOCKET && (call.option == option || call.option == force)
			})
			if !equalCallShape(got, test.wantBufferOps) {
				t.Fatalf("buffer calls =\n%s\nwant =\n%s", traceCalls(got), traceCalls(test.wantBufferOps))
			}
		})
	}
}

type socketOption struct {
	level  int
	option int
}

type fakeIntResult struct {
	value int
	err   error
}

type fakeSocketCall struct {
	op            string
	fd            int
	level         int
	option        int
	value         int
	request       uint
	size          int
	flags         int
	repair        bool
	queue         int
	data          []byte
	repairOptions []unix.TCPRepairOpt
}

func (call fakeSocketCall) String() string {
	switch call.op {
	case "setInt":
		return fmt.Sprintf("setInt(fd=%d level=%d option=%d value=%d repair=%v queue=%d)",
			call.fd, call.level, call.option, call.value, call.repair, call.queue)
	case "getInt":
		return fmt.Sprintf("getInt(fd=%d level=%d option=%d repair=%v queue=%d)",
			call.fd, call.level, call.option, call.repair, call.queue)
	case "recv", "write":
		return fmt.Sprintf("%s(fd=%d size=%d repair=%v queue=%d data=%x)",
			call.op, call.fd, call.size, call.repair, call.queue, call.data)
	case "ioctlGetInt":
		return fmt.Sprintf("ioctlGetInt(fd=%d request=%#x)", call.fd, call.request)
	case "setRepairOptions":
		return fmt.Sprintf("setRepairOptions(fd=%d options=%+v)", call.fd, call.repairOptions)
	default:
		return fmt.Sprintf("%s(fd=%d level=%d option=%d value=%d repair=%v queue=%d)",
			call.op, call.fd, call.level, call.option, call.value, call.repair, call.queue)
	}
}

type fakeLinuxSocketOps struct {
	fd int

	calls  []fakeSocketCall
	failAt int

	repair       bool
	queue        int
	transparent  bool
	reuseAddress bool
	closed       bool
	closeErr     error

	tcpInfo        [8]byte
	ulp            string
	ulpErr         error
	window         repairWindow
	queueBytes     map[int][]byte
	queueSequences map[int]uint32
	unsentBytes    int

	intValues     map[socketOption]int
	intResults    map[socketOption][]fakeIntResult
	setIntResults map[socketOption][]error
	setIntErrors  map[socketOption]error
	ioctlValues   map[uint]int

	writeHook func(fakeSocketCall) (int, error)
	pollHook  func([]unix.PollFd, int) (int, error)
	local     unix.Sockaddr
	remote    unix.Sockaddr
}

func newFakeLinuxSocketOps() *fakeLinuxSocketOps {
	ops := &fakeLinuxSocketOps{
		fd:     73,
		failAt: -1,
		local:  sockaddr(testLinuxTuple().Local),
		remote: sockaddr(testLinuxTuple().Remote),
		queueBytes: map[int][]byte{
			tcpRecvQueue: []byte("recv"),
			tcpSendQueue: []byte("sentTAIL"),
		},
		queueSequences: map[int]uint32{
			tcpRecvQueue: 1,
			tcpSendQueue: 2,
		},
		unsentBytes:   4,
		intValues:     make(map[socketOption]int),
		intResults:    make(map[socketOption][]fakeIntResult),
		setIntResults: make(map[socketOption][]error),
		setIntErrors:  make(map[socketOption]error),
		ioctlValues:   make(map[uint]int),
		window: repairWindow{
			SendWindowLastSequence: 0x100,
			SendWindow:             0x200,
			MaxWindow:              0x300,
			ReceiveWindow:          0x400,
			ReceiveWindowUpdate:    0x500,
		},
	}
	ops.tcpInfo[0] = tcpEstablished
	ops.tcpInfo[5] = optionTimestamps | optionSACK | optionWindowScale
	ops.tcpInfo[6] = 4<<4 | 3
	return ops
}

func (ops *fakeLinuxSocketOps) record(call fakeSocketCall) error {
	call.repair = ops.repair
	call.queue = ops.queue
	index := len(ops.calls)
	ops.calls = append(ops.calls, call)
	if index == ops.failAt {
		return errFakeSocketCall
	}
	return nil
}

func (ops *fakeLinuxSocketOps) setInt(fd, level, option, value int) error {
	call := fakeSocketCall{op: "setInt", fd: fd, level: level, option: option, value: value}
	if err := ops.record(call); err != nil {
		return err
	}
	key := socketOption{level, option}
	if results := ops.setIntResults[key]; len(results) != 0 {
		err := results[0]
		ops.setIntResults[key] = results[1:]
		if err != nil {
			return err
		}
	}
	if err := ops.setIntErrors[key]; err != nil {
		return err
	}
	if level == unix.IPPROTO_TCP && option == unix.TCP_REPAIR {
		ops.repair = value == unix.TCP_REPAIR_ON
	}
	if level == unix.IPPROTO_TCP && option == unix.TCP_REPAIR_QUEUE {
		ops.queue = value
	}
	if level == unix.SOL_IP && option == unix.IP_TRANSPARENT {
		ops.transparent = value != 0
	}
	if level == unix.SOL_SOCKET && option == unix.SO_REUSEADDR {
		ops.reuseAddress = value != 0
	}
	if level == unix.IPPROTO_TCP && option == unix.TCP_QUEUE_SEQ {
		ops.queueSequences[ops.queue] = uint32(value)
		ops.queueBytes[ops.queue] = nil
		if ops.queue == tcpSendQueue {
			ops.unsentBytes = 0
		}
	}
	return nil
}

func (ops *fakeLinuxSocketOps) getInt(fd, level, option int) (int, error) {
	if err := ops.record(fakeSocketCall{op: "getInt", fd: fd, level: level, option: option}); err != nil {
		return 0, err
	}
	key := socketOption{level, option}
	if results := ops.intResults[key]; len(results) != 0 {
		result := results[0]
		ops.intResults[key] = results[1:]
		return result.value, result.err
	}
	if value, ok := ops.intValues[key]; ok {
		return value, nil
	}
	if level == unix.IPPROTO_TCP && option == unix.TCP_QUEUE_SEQ {
		return int(ops.queueSequences[ops.queue]), nil
	}
	if level == unix.IPPROTO_TCP && option == unix.TCP_REPAIR {
		if ops.repair {
			return unix.TCP_REPAIR_ON, nil
		}
		return 0, nil
	}
	if level == unix.SOL_IP && option == unix.IP_TRANSPARENT {
		if ops.transparent {
			return 1, nil
		}
		return 0, nil
	}
	if level == unix.SOL_SOCKET && option == unix.SO_REUSEADDR {
		if ops.repair {
			return 2, nil
		}
		if ops.reuseAddress {
			return 1, nil
		}
		return 0, nil
	}
	switch key {
	case socketOption{unix.SOL_SOCKET, unix.SO_SNDBUF}, socketOption{unix.SOL_SOCKET, unix.SO_RCVBUF}:
		return 1 << 20, nil
	case socketOption{unix.IPPROTO_TCP, unix.TCP_NODELAY}:
		return 1, nil
	case socketOption{unix.IPPROTO_TCP, unix.TCP_MAXSEG}:
		return 1460, nil
	case socketOption{unix.IPPROTO_TCP, unix.TCP_TIMESTAMP}:
		return 0x11223344, nil
	default:
		return 0, nil
	}
}

func (ops *fakeLinuxSocketOps) ioctlGetInt(fd int, request uint) (int, error) {
	if err := ops.record(fakeSocketCall{op: "ioctlGetInt", fd: fd, request: request}); err != nil {
		return 0, err
	}
	if value, ok := ops.ioctlValues[request]; ok {
		return value, nil
	}
	switch request {
	case uint(unix.SIOCINQ):
		return len(ops.queueBytes[tcpRecvQueue]), nil
	case uint(unix.SIOCOUTQ):
		return len(ops.queueBytes[tcpSendQueue]), nil
	case uint(unix.SIOCOUTQNSD):
		return ops.unsentBytes, nil
	default:
		return 0, unix.EINVAL
	}
}

func (ops *fakeLinuxSocketOps) getRaw(fd, level, option int, value []byte) (int, error) {
	if err := ops.record(fakeSocketCall{op: "getRaw", fd: fd, level: level, option: option, size: len(value)}); err != nil {
		return 0, err
	}
	var source []byte
	switch {
	case level == unix.IPPROTO_TCP && option == unix.TCP_INFO:
		source = ops.tcpInfo[:]
	case level == unix.IPPROTO_TCP && option == unix.TCP_REPAIR_WINDOW:
		source = encodeWindow(ops.window)
	default:
		return 0, unix.EINVAL
	}
	copy(value, source)
	return len(source), nil
}

func (ops *fakeLinuxSocketOps) setRaw(fd, level, option int, value []byte) error {
	if err := ops.record(fakeSocketCall{
		op: "setRaw", fd: fd, level: level, option: option, size: len(value), data: append([]byte(nil), value...),
	}); err != nil {
		return err
	}
	if level == unix.IPPROTO_TCP && option == unix.TCP_REPAIR_WINDOW && len(value) == 20 {
		ops.window = decodeWindow(value)
	}
	return nil
}

func (ops *fakeLinuxSocketOps) getString(fd, level, option int) (string, error) {
	if err := ops.record(fakeSocketCall{op: "getString", fd: fd, level: level, option: option}); err != nil {
		return "", err
	}
	return ops.ulp, ops.ulpErr
}

func (ops *fakeLinuxSocketOps) setRepairOptions(fd int, options []unix.TCPRepairOpt) error {
	return ops.record(fakeSocketCall{
		op: "setRepairOptions", fd: fd, repairOptions: append([]unix.TCPRepairOpt(nil), options...),
	})
}

func (ops *fakeLinuxSocketOps) recv(fd int, value []byte, flags int) (int, error) {
	if err := ops.record(fakeSocketCall{op: "recv", fd: fd, size: len(value), flags: flags}); err != nil {
		return 0, err
	}
	queue := ops.queueBytes[ops.queue]
	copy(value, queue)
	return len(queue), nil
}

func (ops *fakeLinuxSocketOps) write(fd int, value []byte) (int, error) {
	call := fakeSocketCall{op: "write", fd: fd, size: len(value), data: append([]byte(nil), value...)}
	if err := ops.record(call); err != nil {
		return 0, err
	}
	call.repair = ops.calls[len(ops.calls)-1].repair
	call.queue = ops.calls[len(ops.calls)-1].queue
	n, err := len(value), error(nil)
	if ops.writeHook != nil {
		n, err = ops.writeHook(call)
	}
	if n > len(value) {
		n = len(value)
	}
	if n > 0 {
		if ops.repair && (ops.queue == tcpRecvQueue || ops.queue == tcpSendQueue) {
			ops.queueBytes[ops.queue] = append(ops.queueBytes[ops.queue], value[:n]...)
			ops.queueSequences[ops.queue] += uint32(n)
		} else if !ops.repair {
			ops.queueBytes[tcpSendQueue] = append(ops.queueBytes[tcpSendQueue], value[:n]...)
			ops.queueSequences[tcpSendQueue] += uint32(n)
			ops.unsentBytes += n
		}
	}
	return n, err
}

func (ops *fakeLinuxSocketOps) socket(domain, socketType, protocol int) (int, error) {
	if err := ops.record(fakeSocketCall{
		op: "socket", level: domain, option: socketType, value: protocol,
	}); err != nil {
		return -1, err
	}
	return ops.fd, nil
}

func (ops *fakeLinuxSocketOps) bind(fd int, _ unix.Sockaddr) error {
	if !ops.transparent {
		return fmt.Errorf("bind without IP_TRANSPARENT")
	}
	return ops.record(fakeSocketCall{op: "bind", fd: fd})
}

func (ops *fakeLinuxSocketOps) connect(fd int, _ unix.Sockaddr) error {
	return ops.record(fakeSocketCall{op: "connect", fd: fd})
}

func (ops *fakeLinuxSocketOps) getSockname(fd int) (unix.Sockaddr, error) {
	if err := ops.record(fakeSocketCall{op: "getsockname", fd: fd}); err != nil {
		return nil, err
	}
	return ops.local, nil
}

func (ops *fakeLinuxSocketOps) getPeername(fd int) (unix.Sockaddr, error) {
	if err := ops.record(fakeSocketCall{op: "getpeername", fd: fd}); err != nil {
		return nil, err
	}
	return ops.remote, nil
}

func (ops *fakeLinuxSocketOps) setNonblock(fd int, nonblocking bool) error {
	value := 0
	if nonblocking {
		value = 1
	}
	return ops.record(fakeSocketCall{op: "setNonblock", fd: fd, value: value})
}

func (ops *fakeLinuxSocketOps) poll(fds []unix.PollFd, timeout int) (int, error) {
	if err := ops.record(fakeSocketCall{op: "poll", size: len(fds), value: timeout}); err != nil {
		return 0, err
	}
	if ops.pollHook != nil {
		return ops.pollHook(fds, timeout)
	}
	return 1, nil
}

func (ops *fakeLinuxSocketOps) close(fd int) error {
	if err := ops.record(fakeSocketCall{op: "close", fd: fd}); err != nil {
		return err
	}
	if ops.closeErr != nil {
		return ops.closeErr
	}
	ops.closed = true
	return nil
}

func (ops *fakeLinuxSocketOps) trace() string {
	return traceCalls(ops.calls)
}

func testLinuxTuple() Tuple {
	return Tuple{
		Local:  netip.MustParseAddrPort("192.0.2.1:12345"),
		Remote: netip.MustParseAddrPort("198.51.100.2:443"),
	}
}

func testLinuxSnapshot(t *testing.T) *Snapshot {
	t.Helper()
	snapshot := &Snapshot{
		tuple:           testLinuxTuple(),
		receiveSequence: 1,
		sendSequence:    2,
		receiveQueue:    []byte("recv"),
		sendQueue:       []byte("sentTAIL"),
		unsentBytes:     4,
		options: streamOptions{
			Mask:          optionTimestamps | optionSACK | optionWindowScale,
			SendScale:     3,
			ReceiveScale:  4,
			MSSClamp:      1460,
			Timestamp:     0x11223344,
			SendBuffer:    1 << 20,
			ReceiveBuffer: 1 << 20,
			NoDelay:       true,
		},
		window: repairWindow{
			SendWindowLastSequence: 0x100,
			SendWindow:             0x200,
			MaxWindow:              0x300,
			ReceiveWindow:          0x400,
			ReceiveWindowUpdate:    0x500,
		},
	}
	if err := snapshot.seal(); err != nil {
		t.Fatalf("seal test snapshot: %v", err)
	}
	return snapshot
}

func assertCaptureCleanup(t *testing.T, ops *fakeLinuxSocketOps) {
	t.Helper()
	if ops.repair {
		t.Fatalf("capture failure left socket in repair\ncalls:\n%s", ops.trace())
	}
	if len(ops.calls) < 3 ||
		!isSetInt(ops.calls[len(ops.calls)-3], unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, tcpNoQueue) ||
		!isSetInt(ops.calls[len(ops.calls)-2], unix.IPPROTO_TCP, unix.TCP_REPAIR, 0) ||
		ops.calls[len(ops.calls)-1].op != "getInt" || ops.calls[len(ops.calls)-1].option != unix.TCP_REPAIR {
		t.Fatalf("capture failure did not end with queue-none + repair-off + readback\ncalls:\n%s", ops.trace())
	}
}

func assertWriteCall(t *testing.T, call fakeSocketCall, repair bool, queue int, value []byte) {
	t.Helper()
	if call.repair != repair || call.queue != queue || !bytes.Equal(call.data, value) {
		t.Fatalf("write = {repair:%v queue:%d data:%x}, want {repair:%v queue:%d data:%x}",
			call.repair, call.queue, call.data, repair, queue, value)
	}
}

func isSetInt(call fakeSocketCall, level, option, value int) bool {
	return call.op == "setInt" && call.level == level && call.option == option && call.value == value
}

func countCalls(calls []fakeSocketCall, predicate func(fakeSocketCall) bool) int {
	return len(matchingCalls(calls, predicate))
}

func matchingCalls(calls []fakeSocketCall, predicate func(fakeSocketCall) bool) []fakeSocketCall {
	var matches []fakeSocketCall
	for _, call := range calls {
		if predicate(call) {
			matches = append(matches, call)
		}
	}
	return matches
}

func findCall(calls []fakeSocketCall, predicate func(fakeSocketCall) bool) int {
	for index, call := range calls {
		if predicate(call) {
			return index
		}
	}
	return -1
}

func mustFindCall(t *testing.T, calls []fakeSocketCall, predicate func(fakeSocketCall) bool) int {
	t.Helper()
	index := findCall(calls, predicate)
	if index < 0 {
		t.Fatalf("required call was not found:\n%s", traceCalls(calls))
	}
	return index
}

func equalCallShape(got, want []fakeSocketCall) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index].op != want[index].op || got[index].level != want[index].level ||
			got[index].option != want[index].option || got[index].value != want[index].value {
			return false
		}
	}
	return true
}

func traceCalls(calls []fakeSocketCall) string {
	var buffer bytes.Buffer
	for index, call := range calls {
		fmt.Fprintf(&buffer, "%02d %s\n", index, call.String())
	}
	return buffer.String()
}
