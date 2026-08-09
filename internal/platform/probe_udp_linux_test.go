//go:build linux

package platform

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type fakeUDPProbeDatagram struct {
	payload []byte
	control []byte
}

type fakeUDPProbeSocket struct {
	port   int
	gro    int
	queue  []fakeUDPProbeDatagram
	closed bool
}

type fakeUDPProbeSend struct {
	segmented   bool
	segmentSize int
	payloadSize int
	receiverGRO bool
}

type fakeUDPProbeKernel struct {
	nextFD                  int
	nextPort                int
	sockets                 map[int]*fakeUDPProbeSocket
	fdByPort                map[int]int
	openCalls               int
	closeCalls              int
	closeErrAt              int
	setGROCalls             int
	getGROCalls             int
	setGROErr               error
	getGROErr               error
	groReadback             *int
	sends                   []fakeUDPProbeSend
	segmentSendErr          error
	segmentSendErrAt        int
	ordinarySendErr         error
	ignoreSegmentControl    bool
	segmentOrdinaryDatagram bool
	omitGROControl          bool
	ordinaryHasGROControl   bool
	wrongGROSegmentSize     int
	corruptGROPayload       bool
	dropAllSends            bool
	waitErr                 error
	afterSuccessfulSend     func(call int)
}

func newFakeUDPProbeKernel() *fakeUDPProbeKernel {
	return &fakeUDPProbeKernel{
		nextFD:   20,
		nextPort: 30000,
		sockets:  make(map[int]*fakeUDPProbeSocket),
		fdByPort: make(map[int]int),
	}
}

func (kernel *fakeUDPProbeKernel) ops() udpProbeOps {
	return udpProbeOps{
		open: func() (int, error) {
			kernel.openCalls++
			fd := kernel.nextFD
			kernel.nextFD++
			kernel.sockets[fd] = &fakeUDPProbeSocket{}
			return fd, nil
		},
		bindLoopback: func(fd int) (udpProbeAddress, error) {
			socket, ok := kernel.sockets[fd]
			if !ok || socket.closed {
				return udpProbeAddress{}, unix.EBADF
			}
			socket.port = kernel.nextPort
			kernel.nextPort++
			kernel.fdByPort[socket.port] = fd
			return udpProbeAddress{IP: udpProbeLoopback, Port: socket.port}, nil
		},
		setGRO: func(fd, value int) error {
			kernel.setGROCalls++
			if kernel.setGROErr != nil {
				return kernel.setGROErr
			}
			socket, ok := kernel.sockets[fd]
			if !ok || socket.closed {
				return unix.EBADF
			}
			socket.gro = value
			return nil
		},
		getGRO: func(fd int) (int, error) {
			kernel.getGROCalls++
			if kernel.getGROErr != nil {
				return 0, kernel.getGROErr
			}
			if kernel.groReadback != nil {
				return *kernel.groReadback, nil
			}
			socket, ok := kernel.sockets[fd]
			if !ok || socket.closed {
				return 0, unix.EBADF
			}
			return socket.gro, nil
		},
		sendmsg: func(fd int, payload, control []byte, destination udpProbeAddress) (int, error) {
			sender, ok := kernel.sockets[fd]
			if !ok || sender.closed {
				return 0, unix.EBADF
			}
			receiverFD, ok := kernel.fdByPort[destination.Port]
			if !ok || destination.IP != udpProbeLoopback {
				return 0, unix.EHOSTUNREACH
			}
			receiver := kernel.sockets[receiverFD]
			segmentSize, segmented, err := parseFakeUDPControl(control, unix.UDP_SEGMENT)
			if err != nil {
				return 0, err
			}
			kernel.sends = append(kernel.sends, fakeUDPProbeSend{
				segmented:   segmented,
				segmentSize: segmentSize,
				payloadSize: len(payload),
				receiverGRO: receiver.gro == 1,
			})
			if segmented && kernel.segmentSendErr != nil && (kernel.segmentSendErrAt == 0 || kernel.segmentSendErrAt == len(kernel.sends)) {
				return 0, kernel.segmentSendErr
			}
			if !segmented && kernel.ordinarySendErr != nil {
				return 0, kernel.ordinarySendErr
			}
			if !kernel.dropAllSends {
				kernel.enqueueFakeUDPSend(receiver, payload, segmented, segmentSize)
			}
			if kernel.afterSuccessfulSend != nil {
				kernel.afterSuccessfulSend(len(kernel.sends))
			}
			return len(payload), nil
		},
		recvmsg: func(fd int, payload, control []byte) (int, int, int, error) {
			socket, ok := kernel.sockets[fd]
			if !ok || socket.closed {
				return 0, 0, 0, unix.EBADF
			}
			if len(socket.queue) == 0 {
				return 0, 0, 0, unix.EAGAIN
			}
			datagram := socket.queue[0]
			socket.queue = socket.queue[1:]
			payloadN := copy(payload, datagram.payload)
			controlN := copy(control, datagram.control)
			flags := 0
			if payloadN != len(datagram.payload) {
				flags |= unix.MSG_TRUNC
			}
			if controlN != len(datagram.control) {
				flags |= unix.MSG_CTRUNC
			}
			return payloadN, controlN, flags, nil
		},
		waitReadable: func(ctx context.Context, fd int, deadline time.Time) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !time.Now().Before(deadline) {
				return context.DeadlineExceeded
			}
			if kernel.waitErr != nil {
				return kernel.waitErr
			}
			socket, ok := kernel.sockets[fd]
			if !ok || socket.closed {
				return unix.EBADF
			}
			if len(socket.queue) != 0 {
				return nil
			}
			return context.DeadlineExceeded
		},
		close: func(fd int) error {
			kernel.closeCalls++
			socket, ok := kernel.sockets[fd]
			if !ok || socket.closed {
				return unix.EBADF
			}
			socket.closed = true
			socket.queue = nil
			if socket.port != 0 {
				delete(kernel.fdByPort, socket.port)
			}
			if kernel.closeCalls == kernel.closeErrAt {
				return errors.New("injected UDP close failure")
			}
			return nil
		},
	}
}

func (kernel *fakeUDPProbeKernel) enqueueFakeUDPSend(receiver *fakeUDPProbeSocket, payload []byte, segmented bool, segmentSize int) {
	if !segmented {
		if kernel.segmentOrdinaryDatagram {
			for start := 0; start < len(payload); start += udpProbeSegmentSize {
				end := min(start+udpProbeSegmentSize, len(payload))
				receiver.queue = append(receiver.queue, fakeUDPProbeDatagram{payload: append([]byte(nil), payload[start:end]...)})
			}
			return
		}
		control := []byte(nil)
		if kernel.ordinaryHasGROControl {
			control = fakeUDPGROControlMessage(udpProbeSegmentSize)
		}
		receiver.queue = append(receiver.queue, fakeUDPProbeDatagram{
			payload: append([]byte(nil), payload...),
			control: control,
		})
		return
	}

	if kernel.ignoreSegmentControl {
		receiver.queue = append(receiver.queue, fakeUDPProbeDatagram{payload: append([]byte(nil), payload...)})
		return
	}
	if segmentSize <= 0 {
		return
	}
	if receiver.gro == 1 {
		coalesced := append([]byte(nil), payload...)
		if kernel.corruptGROPayload && len(coalesced) > udpProbeSegmentSize {
			coalesced[udpProbeSegmentSize] ^= 0xff
		}
		control := []byte(nil)
		if !kernel.omitGROControl {
			groSize := segmentSize
			if kernel.wrongGROSegmentSize != 0 {
				groSize = kernel.wrongGROSegmentSize
			}
			control = fakeUDPGROControlMessage(groSize)
		}
		receiver.queue = append(receiver.queue, fakeUDPProbeDatagram{payload: coalesced, control: control})
		return
	}
	for start := 0; start < len(payload); start += segmentSize {
		end := min(start+segmentSize, len(payload))
		receiver.queue = append(receiver.queue, fakeUDPProbeDatagram{payload: append([]byte(nil), payload[start:end]...)})
	}
}

func parseFakeUDPControl(control []byte, messageType int) (int, bool, error) {
	if len(control) == 0 {
		return 0, false, nil
	}
	messages, err := unix.ParseSocketControlMessage(control)
	if err != nil {
		return 0, false, err
	}
	for _, message := range messages {
		if message.Header.Level != unix.IPPROTO_UDP || message.Header.Type != int32(messageType) {
			continue
		}
		if len(message.Data) != udpSegmentControlSize {
			return 0, false, unix.EINVAL
		}
		return int(binary.NativeEndian.Uint16(message.Data)), true, nil
	}
	return 0, false, nil
}

func fakeUDPGROControlMessage(segmentSize int) []byte {
	control := make([]byte, unix.CmsgSpace(udpGROControlSize))
	header := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
	header.Level = unix.IPPROTO_UDP
	header.Type = unix.UDP_GRO
	header.SetLen(unix.CmsgLen(udpGROControlSize))
	binary.NativeEndian.PutUint32(control[unix.CmsgSpace(0):], uint32(segmentSize))
	return control
}

func TestParseUDPGROControlUsesNativeIntPayload(t *testing.T) {
	segmentSize, found, err := parseUDPGROControl(fakeUDPGROControlMessage(udpProbeSegmentSize))
	if err != nil {
		t.Fatal(err)
	}
	if !found || segmentSize != udpProbeSegmentSize {
		t.Fatalf("UDP_GRO parse=(%d,%v), want (%d,true)", segmentSize, found, udpProbeSegmentSize)
	}
	if _, _, err := parseUDPGROControl(udpUint16ControlMessage(unix.UDP_GRO, udpProbeSegmentSize)); err == nil {
		t.Fatal("UDP_GRO parser accepted the UDP_SEGMENT uint16 ABI")
	}
}

func TestProbeUDPConfirmsGSOAndGROActiveSemantics(t *testing.T) {
	kernel := newFakeUDPProbeKernel()
	at := time.Unix(100, 0).UTC()
	evidence, err := probeUDP(context.Background(), at, kernel.ops())
	if err != nil {
		t.Fatal(err)
	}
	assertUDPFeature(t, evidence, FeatureUDPGSO, FeatureAvailable, ReasonConfirmed, 0)
	assertUDPFeature(t, evidence, FeatureUDPGRO, FeatureAvailable, ReasonConfirmed, 0)
	if kernel.setGROCalls != 1 || kernel.getGROCalls != 1 {
		t.Fatalf("UDP_GRO set/get calls=(%d,%d), want (1,1)", kernel.setGROCalls, kernel.getGROCalls)
	}
	if len(kernel.sends) != 4 {
		t.Fatalf("sendmsg calls=%d want 4", len(kernel.sends))
	}
	want := []fakeUDPProbeSend{
		{payloadSize: udpProbePayloadSize},
		{segmented: true, segmentSize: udpProbeSegmentSize, payloadSize: udpProbePayloadSize},
		{payloadSize: udpProbePayloadSize, receiverGRO: true},
		{segmented: true, segmentSize: udpProbeSegmentSize, payloadSize: udpProbePayloadSize, receiverGRO: true},
	}
	for index := range want {
		if kernel.sends[index] != want[index] {
			t.Fatalf("send %d=%+v want %+v", index, kernel.sends[index], want[index])
		}
	}
	assertFakeUDPProbeClean(t, kernel)
}

func TestProbeUDPGROSupportsKernelWithoutReadbackAPI(t *testing.T) {
	for _, errno := range []error{unix.ENOPROTOOPT, unix.EOPNOTSUPP} {
		kernel := newFakeUDPProbeKernel()
		kernel.getGROErr = errno
		evidence := mustProbeUDPGRO(t, kernel)
		assertSingleUDPFeature(t, evidence, FeatureUDPGRO, FeatureAvailable, ReasonConfirmed, 0)
		assertFakeUDPProbeClean(t, kernel)
	}
}

func TestProbeUDPGRORejectsContradictoryReadback(t *testing.T) {
	kernel := newFakeUDPProbeKernel()
	disabled := 0
	kernel.groReadback = &disabled
	evidence := mustProbeUDPGRO(t, kernel)
	assertSingleUDPFeature(t, evidence, FeatureUDPGRO, FeatureProbeFailed, ReasonSemanticMismatch, 0)
	assertFakeUDPProbeClean(t, kernel)
}

func TestProbeUDPGSORejectsIgnoredSegmentControl(t *testing.T) {
	kernel := newFakeUDPProbeKernel()
	kernel.ignoreSegmentControl = true
	evidence := probeUDPGSO(context.Background(), time.Unix(100, 0).UTC(), kernel.ops())
	assertSingleUDPFeature(t, evidence, FeatureUDPGSO, FeatureProbeFailed, ReasonSemanticMismatch, 0)
	if len(kernel.sends) != 2 || !kernel.sends[1].segmented {
		t.Fatalf("GSO treatment was not one segmented send: %+v", kernel.sends)
	}
	assertFakeUDPProbeClean(t, kernel)
}

func TestProbeUDPGSOOrdinaryFallbackIsNegativeControl(t *testing.T) {
	kernel := newFakeUDPProbeKernel()
	kernel.segmentOrdinaryDatagram = true
	evidence := probeUDPGSO(context.Background(), time.Unix(100, 0).UTC(), kernel.ops())
	assertSingleUDPFeature(t, evidence, FeatureUDPGSO, FeatureProbeFailed, ReasonSemanticMismatch, 0)
	if len(kernel.sends) != 1 || kernel.sends[0].segmented {
		t.Fatalf("probe continued past invalid ordinary control: %+v", kernel.sends)
	}
	assertFakeUDPProbeClean(t, kernel)
}

func TestProbeUDPGRORequiresControlAndPayloadReconstruction(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fakeUDPProbeKernel)
	}{
		{name: "missing-control", mutate: func(kernel *fakeUDPProbeKernel) { kernel.omitGROControl = true }},
		{name: "wrong-segment-size", mutate: func(kernel *fakeUDPProbeKernel) { kernel.wrongGROSegmentSize = udpProbeSegmentSize / 2 }},
		{name: "corrupt-segment", mutate: func(kernel *fakeUDPProbeKernel) { kernel.corruptGROPayload = true }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			kernel := newFakeUDPProbeKernel()
			test.mutate(kernel)
			evidence := mustProbeUDPGRO(t, kernel)
			assertSingleUDPFeature(t, evidence, FeatureUDPGRO, FeatureProbeFailed, ReasonSemanticMismatch, 0)
			assertFakeUDPProbeClean(t, kernel)
		})
	}
}

func TestProbeUDPGROOrdinaryDatagramRejectsFabricatedControl(t *testing.T) {
	kernel := newFakeUDPProbeKernel()
	kernel.ordinaryHasGROControl = true
	evidence := mustProbeUDPGRO(t, kernel)
	assertSingleUDPFeature(t, evidence, FeatureUDPGRO, FeatureProbeFailed, ReasonSemanticMismatch, 0)
	if len(kernel.sends) != 1 || kernel.sends[0].segmented {
		t.Fatalf("probe continued past invalid ordinary GRO control: %+v", kernel.sends)
	}
	assertFakeUDPProbeClean(t, kernel)
}

func TestProbeUDPErrnosRemainTyped(t *testing.T) {
	t.Run("GSO unsupported", func(t *testing.T) {
		kernel := newFakeUDPProbeKernel()
		kernel.segmentSendErr = unix.ENOPROTOOPT
		evidence := probeUDPGSO(context.Background(), time.Unix(100, 0).UTC(), kernel.ops())
		assertSingleUDPFeature(t, evidence, FeatureUDPGSO, FeatureUnsupported, ReasonPrimitiveUnsupported, syscall.ENOPROTOOPT)
		assertFakeUDPProbeClean(t, kernel)
	})

	t.Run("GRO permission denied", func(t *testing.T) {
		kernel := newFakeUDPProbeKernel()
		kernel.setGROErr = unix.EPERM
		evidence := mustProbeUDPGRO(t, kernel)
		assertSingleUDPFeature(t, evidence, FeatureUDPGRO, FeaturePermissionDenied, ReasonPermissionDenied, syscall.EPERM)
		assertFakeUDPProbeClean(t, kernel)
	})

	t.Run("GSO resource exhaustion", func(t *testing.T) {
		kernel := newFakeUDPProbeKernel()
		kernel.segmentSendErr = unix.ENOBUFS
		evidence := probeUDPGSO(context.Background(), time.Unix(100, 0).UTC(), kernel.ops())
		assertSingleUDPFeature(t, evidence, FeatureUDPGSO, FeatureProbeFailed, ReasonResourceExhausted, syscall.ENOBUFS)
		if !evidence.Retryable {
			t.Fatal("ENOBUFS evidence is not retryable")
		}
		assertFakeUDPProbeClean(t, kernel)
	})
}

func TestProbeUDPSkipsGROWhenGSOStimulusIsUnavailable(t *testing.T) {
	kernel := newFakeUDPProbeKernel()
	kernel.segmentSendErr = unix.ENOPROTOOPT
	evidence, err := probeUDP(context.Background(), time.Unix(100, 0).UTC(), kernel.ops())
	if err != nil {
		t.Fatal(err)
	}
	assertUDPFeature(t, evidence, FeatureUDPGSO, FeatureUnsupported, ReasonPrimitiveUnsupported, syscall.ENOPROTOOPT)
	assertUDPFeature(t, evidence, FeatureUDPGRO, FeatureUnprobed, ReasonNotProbed, 0)
	if kernel.setGROCalls != 0 || kernel.getGROCalls != 0 {
		t.Fatalf("GRO mutated after unavailable stimulus: set/get=(%d,%d)", kernel.setGROCalls, kernel.getGROCalls)
	}
	if len(kernel.sends) != 2 || kernel.sends[0].segmented || !kernel.sends[1].segmented {
		t.Fatalf("ordinary fallback and failed GSO treatment not both observed: %+v", kernel.sends)
	}
	assertFakeUDPProbeClean(t, kernel)
}

func TestProbeUDPSecondGSOFailureIsNonCacheableContradiction(t *testing.T) {
	kernel := newFakeUDPProbeKernel()
	kernel.segmentSendErr = unix.EIO
	kernel.segmentSendErrAt = 4
	evidence, err := probeUDP(context.Background(), time.Unix(100, 0).UTC(), kernel.ops())
	if err == nil || evidence != nil {
		t.Fatalf("contradiction evidence=%+v err=%v", evidence, err)
	}
	if len(kernel.sends) != 4 {
		t.Fatalf("sends=%d want second segmented stimulus", len(kernel.sends))
	}
	assertFakeUDPProbeClean(t, kernel)

	probeCalls := 0
	detector, detectorErr := newDetector(probeFunc(func(ctx context.Context, _ ExecutionContext, at time.Time) ([]FeatureEvidence, error) {
		probeCalls++
		attempt := newFakeUDPProbeKernel()
		attempt.segmentSendErr = unix.EIO
		attempt.segmentSendErrAt = 4
		return probeUDP(ctx, at, attempt.ops())
	}))
	if detectorErr != nil {
		t.Fatal(detectorErr)
	}
	identity := testExecutionContext("udp-contradiction")
	detector.acquireContext = func() (*executionContextLease, error) {
		return &executionContextLease{Identity: identity}, nil
	}
	for attempt := 0; attempt < 2; attempt++ {
		if snapshot, err := detector.Current(context.Background()); err == nil || snapshot.Generation != 0 {
			t.Fatalf("attempt %d cached contradiction: generation=%d err=%v", attempt, snapshot.Generation, err)
		}
	}
	if probeCalls != 2 {
		t.Fatalf("probe calls=%d want 2 uncached attempts", probeCalls)
	}
}

func TestProbeUDPCancellationReturnsErrorAndCompletesCleanup(t *testing.T) {
	for _, cancelAt := range []int{1, 3} {
		t.Run(fmt.Sprintf("send-%d", cancelAt), func(t *testing.T) {
			kernel := newFakeUDPProbeKernel()
			ctx, cancel := context.WithCancel(context.Background())
			kernel.afterSuccessfulSend = func(call int) {
				if call == cancelAt {
					cancel()
				}
			}
			evidence, err := probeUDP(ctx, time.Unix(100, 0).UTC(), kernel.ops())
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("probeUDP error=%v want context.Canceled", err)
			}
			if evidence != nil {
				t.Fatalf("canceled probe returned cacheable evidence: %+v", evidence)
			}
			if len(kernel.sends) != cancelAt {
				t.Fatalf("mutation continued after cancellation: sends=%d want %d", len(kernel.sends), cancelAt)
			}
			assertFakeUDPProbeClean(t, kernel)
		})
	}
}

func TestProbeUDPRejectsPreCanceledContext(t *testing.T) {
	kernel := newFakeUDPProbeKernel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	evidence, err := probeUDP(ctx, time.Unix(100, 0).UTC(), kernel.ops())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("probeUDP error=%v want context.Canceled", err)
	}
	if evidence != nil {
		t.Fatalf("pre-canceled probe returned evidence: %+v", evidence)
	}
	if kernel.openCalls != 0 {
		t.Fatalf("pre-canceled probe opened %d sockets", kernel.openCalls)
	}
}

func TestProbeUDPDeadlineIsBoundedAndCleansSockets(t *testing.T) {
	kernel := newFakeUDPProbeKernel()
	kernel.dropAllSends = true
	kernel.waitErr = context.DeadlineExceeded
	evidence := probeUDPGSO(context.Background(), time.Unix(100, 0).UTC(), kernel.ops())
	assertSingleUDPFeature(t, evidence, FeatureUDPGSO, FeatureProbeFailed, ReasonSyscallFailed, 0)
	assertFakeUDPProbeClean(t, kernel)
}

func TestProbeUDPCloseFailureCannotPublishAvailability(t *testing.T) {
	kernel := newFakeUDPProbeKernel()
	kernel.closeErrAt = 1
	evidence := probeUDPGSO(context.Background(), time.Unix(100, 0).UTC(), kernel.ops())
	assertSingleUDPFeature(t, evidence, FeatureUDPGSO, FeatureProbeFailed, ReasonSyscallFailed, 0)
	if !evidence.Retryable {
		t.Fatal("cleanup failure is not retryable")
	}
	assertFakeUDPProbeClean(t, kernel)
}

func TestProbeUDPRejectsIncompleteOperations(t *testing.T) {
	evidence, err := probeUDP(context.Background(), time.Unix(100, 0).UTC(), udpProbeOps{})
	if err == nil {
		t.Fatal("probeUDP accepted incomplete operations")
	}
	if evidence != nil {
		t.Fatalf("incomplete probe returned evidence: %+v", evidence)
	}
}

func TestProbeUDPRealLoopback(t *testing.T) {
	if os.Getenv("RENDR_EXPECT_UDP_OFFLOAD") != "available" {
		t.Skip("UDP offload expectation is unset")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	evidence, err := probeUDP(ctx, time.Now().UTC(), defaultUDPProbeOps())
	if err != nil {
		t.Fatal(err)
	}
	assertUDPFeature(t, evidence, FeatureUDPGSO, FeatureAvailable, ReasonConfirmed, 0)
	assertUDPFeature(t, evidence, FeatureUDPGRO, FeatureAvailable, ReasonConfirmed, 0)
}

func mustProbeUDPGRO(t *testing.T, kernel *fakeUDPProbeKernel) FeatureEvidence {
	t.Helper()
	evidence, err := probeUDPGRO(context.Background(), time.Unix(100, 0).UTC(), kernel.ops())
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func assertUDPFeature(t *testing.T, evidence []FeatureEvidence, id FeatureID, state FeatureState, reason FeatureReason, errno syscall.Errno) {
	t.Helper()
	for _, result := range evidence {
		if result.ID == id {
			assertSingleUDPFeature(t, result, id, state, reason, errno)
			return
		}
	}
	t.Fatalf("missing %s evidence: %+v", id, evidence)
}

func assertSingleUDPFeature(t *testing.T, evidence FeatureEvidence, id FeatureID, state FeatureState, reason FeatureReason, errno syscall.Errno) {
	t.Helper()
	if evidence.ID != id || evidence.State != state || evidence.Reason != reason || evidence.RawErrno() != errno {
		t.Fatalf("evidence=%s/%s/%s errno=%v, want %s/%s/%s errno=%v", evidence.ID, evidence.State, evidence.Reason, evidence.RawErrno(), id, state, reason, errno)
	}
	if state == FeatureAvailable && evidence.Source != SourceRuntimeRoundTrip {
		t.Fatalf("available %s source=%s want %s", id, evidence.Source, SourceRuntimeRoundTrip)
	}
}

func assertFakeUDPProbeClean(t *testing.T, kernel *fakeUDPProbeKernel) {
	t.Helper()
	if len(kernel.fdByPort) != 0 {
		t.Fatalf("fake UDP ports leaked: %v", kernel.fdByPort)
	}
	for fd, socket := range kernel.sockets {
		if !socket.closed {
			t.Fatalf("fake UDP fd %d leaked", fd)
		}
		if len(socket.queue) != 0 {
			t.Fatalf("fake UDP fd %d retained %d datagrams", fd, len(socket.queue))
		}
	}
}
