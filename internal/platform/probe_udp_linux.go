//go:build linux

package platform

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	udpProbeSegmentSize   = 96
	udpProbeSegmentCount  = 3
	udpProbePayloadSize   = udpProbeSegmentSize * udpProbeSegmentCount
	udpProbeIODeadline    = 500 * time.Millisecond
	udpProbePollInterval  = 10 * time.Millisecond
	udpSegmentControlSize = 2
	udpGROControlSize     = 4
)

var udpProbeLoopback = [4]byte{127, 0, 0, 1}

type udpProbeAddress struct {
	IP   [4]byte
	Port int
}

type udpProbeOps struct {
	open         func() (int, error)
	bindLoopback func(fd int) (udpProbeAddress, error)
	setGRO       func(fd, value int) error
	getGRO       func(fd int) (int, error)
	sendmsg      func(fd int, payload, control []byte, destination udpProbeAddress) (int, error)
	recvmsg      func(fd int, payload, control []byte) (payloadBytes, controlBytes, flags int, err error)
	waitReadable func(ctx context.Context, fd int, deadline time.Time) error
	close        func(fd int) error
}

func defaultUDPProbeOps() udpProbeOps {
	return udpProbeOps{
		open: func() (int, error) {
			return unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
		},
		bindLoopback: func(fd int) (udpProbeAddress, error) {
			if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: udpProbeLoopback}); err != nil {
				return udpProbeAddress{}, err
			}
			address, err := unix.Getsockname(fd)
			if err != nil {
				return udpProbeAddress{}, err
			}
			inet4, ok := address.(*unix.SockaddrInet4)
			if !ok {
				return udpProbeAddress{}, fmt.Errorf("UDP loopback bind returned %T", address)
			}
			bound := udpProbeAddress{IP: inet4.Addr, Port: inet4.Port}
			if err := validateUDPProbeAddress(bound); err != nil {
				return udpProbeAddress{}, err
			}
			return bound, nil
		},
		setGRO: func(fd, value int) error {
			return unix.SetsockoptInt(fd, unix.IPPROTO_UDP, unix.UDP_GRO, value)
		},
		getGRO: func(fd int) (int, error) {
			return unix.GetsockoptInt(fd, unix.IPPROTO_UDP, unix.UDP_GRO)
		},
		sendmsg: func(fd int, payload, control []byte, destination udpProbeAddress) (int, error) {
			return unix.SendmsgN(fd, payload, control, &unix.SockaddrInet4{
				Addr: destination.IP,
				Port: destination.Port,
			}, unix.MSG_NOSIGNAL)
		},
		recvmsg: func(fd int, payload, control []byte) (int, int, int, error) {
			n, controlN, flags, _, err := unix.Recvmsg(fd, payload, control, unix.MSG_DONTWAIT)
			return n, controlN, flags, err
		},
		waitReadable: waitUDPProbeReadable,
		close:        unix.Close,
	}
}

// probeUDP actively proves UDP offload semantics. systemProber owns how these
// observations are combined with the other platform probes.
func probeUDP(ctx context.Context, at time.Time, ops udpProbeOps) ([]FeatureEvidence, error) {
	if err := validateUDPProbeOps(ops); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	observations := make([]FeatureEvidence, 0, 2)
	gsoEvidence := probeUDPGSO(ctx, at, ops)
	observations = append(observations, gsoEvidence)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if gsoEvidence.State != FeatureAvailable {
		observations = append(observations, unprobedUDPFeature(FeatureUDPGRO, at))
		return observations, nil
	}
	groEvidence, err := probeUDPGRO(ctx, at, ops)
	if err != nil {
		return nil, err
	}
	observations = append(observations, groEvidence)
	return observations, nil
}

func unprobedUDPFeature(id FeatureID, at time.Time) FeatureEvidence {
	return mustEvidence(id, FeatureUnprobed, ReasonNotProbed, at, SourceNotRun, 0, false)
}

func validateUDPProbeOps(ops udpProbeOps) error {
	if ops.open == nil || ops.bindLoopback == nil || ops.setGRO == nil || ops.getGRO == nil ||
		ops.sendmsg == nil || ops.recvmsg == nil || ops.waitReadable == nil || ops.close == nil {
		return fmt.Errorf("platform: incomplete UDP probe operations")
	}
	return nil
}

func probeUDPGSO(ctx context.Context, at time.Time, ops udpProbeOps) FeatureEvidence {
	err := runUDPGSOProbe(ctx, udpProbeDeadline(ctx), ops)
	return udpProbeEvidence(FeatureUDPGSO, at, err)
}

func probeUDPGRO(ctx context.Context, at time.Time, ops udpProbeOps) (FeatureEvidence, error) {
	err := runUDPGROProbe(ctx, udpProbeDeadline(ctx), ops)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return FeatureEvidence{}, ctxErr
	}
	var dependencyErr *udpProbeDependencyError
	if errors.As(err, &dependencyErr) {
		return FeatureEvidence{}, fmt.Errorf("platform: contradictory UDP GSO evidence during GRO probe: %w", dependencyErr)
	}
	return udpProbeEvidence(FeatureUDPGRO, at, err), nil
}

func runUDPGSOProbe(ctx context.Context, deadline time.Time, ops udpProbeOps) (err error) {
	pair, err := openUDPProbePair(ctx, ops)
	if err != nil {
		return err
	}
	defer func() {
		if cleanupErr := pair.close(ops); cleanupErr != nil {
			err = &udpProbeCleanupError{cause: errors.Join(err, cleanupErr)}
		}
	}()

	if err := verifyOrdinaryUDPDatagram(ctx, deadline, ops, pair, 0x31); err != nil {
		return err
	}

	payload := makeUDPProbePayload(0x73)
	control := udpUint16ControlMessage(unix.UDP_SEGMENT, udpProbeSegmentSize)
	if err := sendUDPProbeMessage(ctx, deadline, ops, pair, payload, control); err != nil {
		return err
	}
	for segment := range udpProbeSegmentCount {
		datagram, err := receiveUDPProbeDatagram(ctx, deadline, ops, pair.receiver)
		if err != nil {
			return err
		}
		start := segment * udpProbeSegmentSize
		want := payload[start : start+udpProbeSegmentSize]
		if !bytes.Equal(datagram.payload, want) {
			return udpProbeSemanticf("UDP_SEGMENT datagram %d boundary or payload mismatch: got=%d want=%d", segment, len(datagram.payload), len(want))
		}
		if size, found, err := parseUDPGROControl(datagram.control); err != nil {
			return udpProbeSemanticf("UDP_SEGMENT datagram %d control: %v", segment, err)
		} else if found {
			return udpProbeSemanticf("UDP_SEGMENT receiver had UDP_GRO disabled but returned segment size %d", size)
		}
	}
	return requireNoQueuedUDPDatagram(ops, pair.receiver)
}

func runUDPGROProbe(ctx context.Context, deadline time.Time, ops udpProbeOps) (err error) {
	pair, err := openUDPProbePair(ctx, ops)
	if err != nil {
		return err
	}
	defer func() {
		if cleanupErr := pair.close(ops); cleanupErr != nil {
			err = &udpProbeCleanupError{cause: errors.Join(err, cleanupErr)}
		}
	}()

	if err := checkUDPProbeDeadline(ctx, deadline); err != nil {
		return err
	}
	if err := ops.setGRO(pair.receiver, 1); err != nil {
		return fmt.Errorf("set UDP_GRO: %w", err)
	}
	if err := checkUDPProbeDeadline(ctx, deadline); err != nil {
		return err
	}
	enabled, err := ops.getGRO(pair.receiver)
	if err != nil && !errors.Is(err, unix.ENOPROTOOPT) && !errors.Is(err, unix.EOPNOTSUPP) {
		return fmt.Errorf("read back UDP_GRO: %w", err)
	}
	if err == nil && enabled != 1 {
		return udpProbeSemanticf("UDP_GRO readback=%d want 1", enabled)
	}

	// A successful setsockopt is not sufficient evidence. This control proves
	// an ordinary datagram remains ordinary and carries no fabricated GRO cmsg.
	if err := verifyOrdinaryUDPDatagram(ctx, deadline, ops, pair, 0x47); err != nil {
		return err
	}

	payload := makeUDPProbePayload(0xa5)
	control := udpUint16ControlMessage(unix.UDP_SEGMENT, udpProbeSegmentSize)
	if err := sendUDPProbeMessage(ctx, deadline, ops, pair, payload, control); err != nil {
		return &udpProbeDependencyError{cause: fmt.Errorf("send UDP_GRO stimulus with UDP_SEGMENT: %w", err)}
	}
	datagram, err := receiveUDPProbeDatagram(ctx, deadline, ops, pair.receiver)
	if err != nil {
		return err
	}
	segmentSize, found, err := parseUDPGROControl(datagram.control)
	if err != nil {
		return udpProbeSemanticf("parse UDP_GRO control: %v", err)
	}
	if !found {
		if err := verifyUDPGROOrdinaryFallback(ctx, deadline, ops, pair, payload, datagram); err != nil {
			return err
		}
		return udpProbeUnsupportedf("UDP_GRO left the controlled GSO stimulus as ordinary datagrams")
	}
	if segmentSize != udpProbeSegmentSize {
		return udpProbeSemanticf("UDP_GRO segment size=%d want %d", segmentSize, udpProbeSegmentSize)
	}
	if len(datagram.payload) != udpProbePayloadSize {
		return udpProbeSemanticf("UDP_GRO payload length=%d want %d", len(datagram.payload), udpProbePayloadSize)
	}
	for segment := range udpProbeSegmentCount {
		start := segment * int(segmentSize)
		got := datagram.payload[start : start+int(segmentSize)]
		want := payload[start : start+int(segmentSize)]
		if !bytes.Equal(got, want) {
			return udpProbeSemanticf("UDP_GRO reconstructed segment %d payload mismatch", segment)
		}
	}
	return requireNoQueuedUDPDatagram(ops, pair.receiver)
}

func verifyUDPGROOrdinaryFallback(
	ctx context.Context,
	deadline time.Time,
	ops udpProbeOps,
	pair udpProbePair,
	payload []byte,
	first udpProbeDatagram,
) error {
	for segment := range udpProbeSegmentCount {
		datagram := first
		if segment != 0 {
			var err error
			datagram, err = receiveUDPProbeDatagram(ctx, deadline, ops, pair.receiver)
			if err != nil {
				return err
			}
		}
		start := segment * udpProbeSegmentSize
		want := payload[start : start+udpProbeSegmentSize]
		if len(datagram.payload) != udpProbeSegmentSize || !bytes.Equal(datagram.payload, want) {
			return udpProbeSemanticf(
				"UDP_GRO ordinary fallback datagram %d boundary or payload mismatch: got=%d want=%d",
				segment, len(datagram.payload), len(want),
			)
		}
		if size, found, err := parseUDPGROControl(datagram.control); err != nil {
			return udpProbeSemanticf("UDP_GRO ordinary fallback datagram %d control: %v", segment, err)
		} else if found {
			return udpProbeSemanticf("UDP_GRO ordinary fallback datagram %d unexpectedly carried segment size %d", segment, size)
		}
	}
	return requireNoQueuedUDPDatagram(ops, pair.receiver)
}

type udpProbePair struct {
	sender      int
	receiver    int
	destination udpProbeAddress
}

func openUDPProbePair(ctx context.Context, ops udpProbeOps) (udpProbePair, error) {
	pair := udpProbePair{sender: -1, receiver: -1}
	if err := ctx.Err(); err != nil {
		return pair, err
	}
	receiver, err := ops.open()
	if err != nil {
		return pair, fmt.Errorf("open UDP receiver: %w", err)
	}
	pair.receiver = receiver
	if err := ctx.Err(); err != nil {
		return pair, finishUDPProbePairOpenFailure(pair, ops, err)
	}
	sender, err := ops.open()
	if err != nil {
		return pair, finishUDPProbePairOpenFailure(pair, ops, fmt.Errorf("open UDP sender: %w", err))
	}
	pair.sender = sender
	if err := ctx.Err(); err != nil {
		return pair, finishUDPProbePairOpenFailure(pair, ops, err)
	}
	destination, err := ops.bindLoopback(pair.receiver)
	if err != nil {
		return pair, finishUDPProbePairOpenFailure(pair, ops, fmt.Errorf("bind UDP receiver to loopback: %w", err))
	}
	if err := validateUDPProbeAddress(destination); err != nil {
		return pair, finishUDPProbePairOpenFailure(pair, ops, udpProbeSemanticf("bound UDP receiver address: %v", err))
	}
	pair.destination = destination
	return pair, nil
}

func finishUDPProbePairOpenFailure(pair udpProbePair, ops udpProbeOps, cause error) error {
	if cleanupErr := pair.close(ops); cleanupErr != nil {
		return &udpProbeCleanupError{cause: errors.Join(cause, cleanupErr)}
	}
	return cause
}

func (pair udpProbePair) close(ops udpProbeOps) error {
	var cleanupErr error
	if pair.sender >= 0 {
		cleanupErr = errors.Join(cleanupErr, ops.close(pair.sender))
	}
	if pair.receiver >= 0 {
		cleanupErr = errors.Join(cleanupErr, ops.close(pair.receiver))
	}
	return cleanupErr
}

func validateUDPProbeAddress(address udpProbeAddress) error {
	if address.IP != udpProbeLoopback || address.Port <= 0 || address.Port > 65535 {
		return fmt.Errorf("address=%v:%d is not allocated IPv4 loopback", address.IP, address.Port)
	}
	return nil
}

func verifyOrdinaryUDPDatagram(ctx context.Context, deadline time.Time, ops udpProbeOps, pair udpProbePair, marker byte) error {
	payload := makeUDPProbePayload(marker)
	if err := sendUDPProbeMessage(ctx, deadline, ops, pair, payload, nil); err != nil {
		return fmt.Errorf("ordinary UDP control send: %w", err)
	}
	datagram, err := receiveUDPProbeDatagram(ctx, deadline, ops, pair.receiver)
	if err != nil {
		return fmt.Errorf("ordinary UDP control receive: %w", err)
	}
	if !bytes.Equal(datagram.payload, payload) {
		return udpProbeSemanticf("ordinary UDP control changed datagram boundary or payload: got=%d want=%d", len(datagram.payload), len(payload))
	}
	if size, found, err := parseUDPGROControl(datagram.control); err != nil {
		return udpProbeSemanticf("ordinary UDP control metadata: %v", err)
	} else if found {
		return udpProbeSemanticf("ordinary UDP control unexpectedly carried UDP_GRO size %d", size)
	}
	return requireNoQueuedUDPDatagram(ops, pair.receiver)
}

func sendUDPProbeMessage(ctx context.Context, deadline time.Time, ops udpProbeOps, pair udpProbePair, payload, control []byte) error {
	if err := checkUDPProbeDeadline(ctx, deadline); err != nil {
		return err
	}
	written, err := ops.sendmsg(pair.sender, payload, control, pair.destination)
	if err != nil {
		return err
	}
	if written != len(payload) {
		return udpProbeSemanticf("sendmsg wrote %d bytes want %d", written, len(payload))
	}
	return nil
}

type udpProbeDatagram struct {
	payload []byte
	control []byte
}

func receiveUDPProbeDatagram(ctx context.Context, deadline time.Time, ops udpProbeOps, fd int) (udpProbeDatagram, error) {
	payload := make([]byte, udpProbePayloadSize+1)
	control := make([]byte, unix.CmsgSpace(udpGROControlSize))
	for {
		if err := checkUDPProbeDeadline(ctx, deadline); err != nil {
			return udpProbeDatagram{}, err
		}
		payloadN, controlN, flags, err := ops.recvmsg(fd, payload, control)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			if err := ops.waitReadable(ctx, fd, deadline); err != nil {
				return udpProbeDatagram{}, err
			}
			continue
		}
		if err != nil {
			return udpProbeDatagram{}, err
		}
		if payloadN < 0 || payloadN > len(payload) || controlN < 0 || controlN > len(control) {
			return udpProbeDatagram{}, udpProbeSemanticf("recvmsg returned invalid lengths payload=%d control=%d", payloadN, controlN)
		}
		if flags&unix.MSG_TRUNC != 0 {
			return udpProbeDatagram{}, udpProbeSemanticf("recvmsg truncated UDP payload")
		}
		if flags&unix.MSG_CTRUNC != 0 {
			return udpProbeDatagram{}, udpProbeSemanticf("recvmsg truncated UDP control message")
		}
		return udpProbeDatagram{
			payload: append([]byte(nil), payload[:payloadN]...),
			control: append([]byte(nil), control[:controlN]...),
		}, nil
	}
}

func requireNoQueuedUDPDatagram(ops udpProbeOps, fd int) error {
	var payload [udpProbePayloadSize + 1]byte
	control := make([]byte, unix.CmsgSpace(udpGROControlSize))
	payloadN, _, _, err := ops.recvmsg(fd, payload[:], control)
	if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
		return nil
	}
	if err != nil {
		return err
	}
	return udpProbeSemanticf("unexpected extra UDP datagram with %d bytes", payloadN)
}

func makeUDPProbePayload(marker byte) []byte {
	payload := make([]byte, udpProbePayloadSize)
	for segment := range udpProbeSegmentCount {
		for offset := range udpProbeSegmentSize {
			payload[segment*udpProbeSegmentSize+offset] = marker + byte(segment*37+offset*11)
		}
	}
	return payload
}

func udpUint16ControlMessage(messageType int, value int) []byte {
	control := make([]byte, unix.CmsgSpace(udpSegmentControlSize))
	header := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
	header.Level = unix.IPPROTO_UDP
	header.Type = int32(messageType)
	header.SetLen(unix.CmsgLen(udpSegmentControlSize))
	binary.NativeEndian.PutUint16(control[unix.CmsgSpace(0):], uint16(value))
	return control
}

func parseUDPGROControl(control []byte) (int, bool, error) {
	if len(control) == 0 {
		return 0, false, nil
	}
	messages, err := unix.ParseSocketControlMessage(control)
	if err != nil {
		return 0, false, err
	}
	segmentSize := 0
	found := false
	for _, message := range messages {
		if message.Header.Level != unix.IPPROTO_UDP || message.Header.Type != unix.UDP_GRO {
			continue
		}
		if found {
			return 0, false, fmt.Errorf("duplicate UDP_GRO control message")
		}
		if len(message.Data) != udpGROControlSize {
			return 0, false, fmt.Errorf("UDP_GRO control length=%d want %d", len(message.Data), udpGROControlSize)
		}
		value := binary.NativeEndian.Uint32(message.Data)
		if value == 0 || value > uint32(^uint16(0)) {
			return 0, false, fmt.Errorf("UDP_GRO returned invalid segment size %d", value)
		}
		segmentSize = int(value)
		found = true
	}
	return segmentSize, found, nil
}

func udpProbeDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(udpProbeIODeadline)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		return callerDeadline
	}
	return deadline
}

func checkUDPProbeDeadline(ctx context.Context, deadline time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func waitUDPProbeReadable(ctx context.Context, fd int, deadline time.Time) error {
	for {
		if err := checkUDPProbeDeadline(ctx, deadline); err != nil {
			return err
		}
		wait := time.Until(deadline)
		if wait > udpProbePollInterval {
			wait = udpProbePollInterval
		}
		timeoutMillis := int((wait + time.Millisecond - 1) / time.Millisecond)
		if timeoutMillis < 1 {
			timeoutMillis = 1
		}
		pollFDs := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		ready, err := unix.Poll(pollFDs, timeoutMillis)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if ready == 0 {
			continue
		}
		revents := pollFDs[0].Revents
		if revents&unix.POLLNVAL != 0 {
			return unix.EBADF
		}
		if revents&unix.POLLIN != 0 {
			return nil
		}
		if revents&(unix.POLLERR|unix.POLLHUP) != 0 {
			return unix.EIO
		}
	}
}

type udpProbeSemanticError struct{ cause error }

func (err *udpProbeSemanticError) Error() string { return err.cause.Error() }
func (err *udpProbeSemanticError) Unwrap() error { return err.cause }

func udpProbeSemanticf(format string, args ...any) error {
	return &udpProbeSemanticError{cause: fmt.Errorf(format, args...)}
}

type udpProbeCleanupError struct{ cause error }

func (err *udpProbeCleanupError) Error() string { return err.cause.Error() }
func (err *udpProbeCleanupError) Unwrap() error { return err.cause }

type udpProbeDependencyError struct{ cause error }

func (err *udpProbeDependencyError) Error() string { return err.cause.Error() }
func (err *udpProbeDependencyError) Unwrap() error { return err.cause }

type udpProbeUnsupportedError struct{ cause error }

func (err *udpProbeUnsupportedError) Error() string { return err.cause.Error() }
func (err *udpProbeUnsupportedError) Unwrap() error { return err.cause }

func udpProbeUnsupportedf(format string, args ...any) error {
	return &udpProbeUnsupportedError{cause: fmt.Errorf(format, args...)}
}

func udpProbeEvidence(id FeatureID, at time.Time, err error) FeatureEvidence {
	if err == nil {
		return availableEvidence(id, at, SourceRuntimeRoundTrip)
	}
	var cleanupErr *udpProbeCleanupError
	if errors.As(err, &cleanupErr) {
		return cleanupFailureEvidence(id, at, cleanupErr)
	}
	var unsupportedErr *udpProbeUnsupportedError
	if errors.As(err, &unsupportedErr) {
		return mustEvidence(id, FeatureUnsupported, ReasonPrimitiveUnsupported, at, SourceRuntimeRoundTrip, 0, false)
	}
	var semanticErr *udpProbeSemanticError
	if errors.As(err, &semanticErr) {
		return semanticFailureEvidence(id, at, semanticErr)
	}
	return classifiedOrFailed(id, at, err)
}
