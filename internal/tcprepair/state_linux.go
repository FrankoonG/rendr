//go:build linux && amd64

package tcprepair

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	tcpNoQueue   = 0
	tcpRecvQueue = 1
	tcpSendQueue = 2

	tcpEstablished = 1

	tcpOptionMSS        = 2
	tcpOptionWindow     = 3
	tcpOptionSACK       = 4
	tcpOptionTimestamps = 8
)

type socketState struct {
	inspection    Inspection
	sendBuffer    uint32
	receiveBuffer uint32
	noDelay       bool
	reuseAddress  bool
	transparent   bool
}

type linuxSocketOps interface {
	setInt(fd, level, option, value int) error
	getInt(fd, level, option int) (int, error)
	ioctlGetInt(fd int, request uint) (int, error)
	getRaw(fd, level, option int, value []byte) (int, error)
	setRaw(fd, level, option int, value []byte) error
	getString(fd, level, option int) (string, error)
	setRepairOptions(fd int, options []unix.TCPRepairOpt) error
	recv(fd int, value []byte, flags int) (int, error)
	write(fd int, value []byte) (int, error)
	socket(domain, socketType, protocol int) (int, error)
	bind(fd int, address unix.Sockaddr) error
	connect(fd int, address unix.Sockaddr) error
	getSockname(fd int) (unix.Sockaddr, error)
	getPeername(fd int) (unix.Sockaddr, error)
	setNonblock(fd int, nonblocking bool) error
	poll(fds []unix.PollFd, timeout int) (int, error)
	close(fd int) error
}

type systemSocketOps struct{}

func (systemSocketOps) setInt(fd, level, option, value int) error {
	return unix.SetsockoptInt(fd, level, option, value)
}

func (systemSocketOps) getInt(fd, level, option int) (int, error) {
	return unix.GetsockoptInt(fd, level, option)
}

func (systemSocketOps) ioctlGetInt(fd int, request uint) (int, error) {
	return unix.IoctlGetInt(fd, request)
}

func (systemSocketOps) getRaw(fd, level, option int, value []byte) (int, error) {
	if len(value) == 0 {
		return 0, unix.EINVAL
	}
	length := uint32(len(value))
	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fd), uintptr(level), uintptr(option),
		uintptr(unsafe.Pointer(&value[0])), uintptr(unsafe.Pointer(&length)), 0,
	)
	if errno != 0 {
		return 0, errno
	}
	return int(length), nil
}

func (systemSocketOps) setRaw(fd, level, option int, value []byte) error {
	if len(value) == 0 {
		return unix.EINVAL
	}
	_, _, errno := unix.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(fd), uintptr(level), uintptr(option),
		uintptr(unsafe.Pointer(&value[0])), uintptr(len(value)), 0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func (systemSocketOps) getString(fd, level, option int) (string, error) {
	return unix.GetsockoptString(fd, level, option)
}

func (systemSocketOps) setRepairOptions(fd int, options []unix.TCPRepairOpt) error {
	return unix.SetsockoptTCPRepairOpt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_OPTIONS, options)
}

func (systemSocketOps) recv(fd int, value []byte, flags int) (int, error) {
	n, _, err := unix.Recvfrom(fd, value, flags)
	return n, err
}

func (systemSocketOps) write(fd int, value []byte) (int, error) {
	return unix.Write(fd, value)
}

func (systemSocketOps) socket(domain, socketType, protocol int) (int, error) {
	return unix.Socket(domain, socketType, protocol)
}

func (systemSocketOps) bind(fd int, address unix.Sockaddr) error {
	return unix.Bind(fd, address)
}

func (systemSocketOps) connect(fd int, address unix.Sockaddr) error {
	return unix.Connect(fd, address)
}

func (systemSocketOps) getSockname(fd int) (unix.Sockaddr, error) {
	return unix.Getsockname(fd)
}

func (systemSocketOps) getPeername(fd int) (unix.Sockaddr, error) {
	return unix.Getpeername(fd)
}

func (systemSocketOps) setNonblock(fd int, nonblocking bool) error {
	return unix.SetNonblock(fd, nonblocking)
}

func (systemSocketOps) poll(fds []unix.PollFd, timeout int) (int, error) {
	return unix.Poll(fds, timeout)
}

func (systemSocketOps) close(fd int) error {
	return unix.Close(fd)
}

// Inspect performs only read-only syscalls. Capture repeats all mutable facts
// after TCP_REPAIR has frozen the socket.
func Inspect(conn *net.TCPConn) (Inspection, error) {
	tuple, err := tupleOf(conn)
	if err != nil {
		return Inspection{}, err
	}
	var state socketState
	err = controlTCP(conn, func(fd int) error {
		var inner error
		state, inner = inspectFD(fd, tuple, systemSocketOps{})
		return inner
	})
	if err != nil {
		return Inspection{}, err
	}
	return state.inspection, nil
}

// Capture freezes conn in TCP_REPAIR and returns an immutable state capsule.
// The caller must already have quiesced application I/O and quarantined both
// tuple directions. On success conn remains in repair until Resume or Close.
func Capture(conn *net.TCPConn) (*CaptureLease, error) {
	if conn == nil {
		return nil, fmt.Errorf("%w: nil TCPConn", ErrIneligibleState)
	}
	lease := &CaptureLease{token: &captureToken{conn: conn, state: SourceStateNormal}}
	tuple, err := tupleOf(conn)
	if err != nil {
		return lease, err
	}
	result := captureResult{state: SourceStateNormal}
	err = controlTCP(conn, func(fd int) error {
		var inner error
		result, inner = captureFD(fd, tuple, systemSocketOps{})
		return inner
	})
	lease.token.state = result.state
	lease.token.snapshot = result.snapshot
	if err != nil {
		return lease, &SourceError{Op: "capture", State: result.state, Err: err}
	}
	return lease, nil
}

func (lease *CaptureLease) Resume() error {
	if lease == nil || lease.token == nil {
		return ErrSourceStateUnknown
	}
	token := lease.token
	token.mu.Lock()
	defer token.mu.Unlock()
	if token.released {
		return nil
	}
	switch token.state {
	case SourceStateClosed:
		return ErrSourceClosed
	case SourceStateNormal:
		token.released = true
		return nil
	}
	state := SourceStateUnknown
	err := controlTCP(token.conn, func(fd int) error {
		var inner error
		state, inner = leaveRepairState(fd, systemSocketOps{})
		return inner
	})
	token.state = state
	if err != nil {
		return &SourceError{Op: "resume", State: state, Err: err}
	}
	if state != SourceStateNormal {
		return &SourceError{Op: "resume", State: state, Err: ErrSourceStateUnknown}
	}
	token.released = true
	return nil
}

func (lease *CaptureLease) Close() error {
	if lease == nil || lease.token == nil {
		return ErrSourceStateUnknown
	}
	token := lease.token
	token.mu.Lock()
	defer token.mu.Unlock()
	if token.released {
		return ErrSourceReleased
	}
	if token.state == SourceStateClosed {
		return nil
	}
	closeErr := token.conn.Close()
	closed := closeErr == nil || tcpConnClosed(token.conn)
	if closed {
		token.state = SourceStateClosed
		if closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			return &SourceError{Op: "close", State: token.state, Err: closeErr}
		}
		return nil
	}
	token.state = SourceStateUnknown
	return &SourceError{Op: "close", State: token.state, Err: errors.Join(closeErr, ErrSourceStateUnknown)}
}

func tcpConnClosed(conn *net.TCPConn) bool {
	if conn == nil {
		return true
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return true
	}
	called := false
	err = raw.Control(func(uintptr) { called = true })
	return err != nil || !called
}

// Resume returns a captured source socket to normal TCP processing.
func Resume(conn *net.TCPConn) error {
	return controlTCP(conn, func(fd int) error {
		return leaveRepair(fd, systemSocketOps{})
	})
}

// Enter freezes a live endpoint before it is discarded. A surrounding tuple
// quarantine is still required because an enter failure followed by close may
// otherwise emit a reset.
func Enter(conn *net.TCPConn) error {
	return controlTCP(conn, func(fd int) error {
		return systemSocketOps{}.setInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_ON)
	})
}

// Restore reconstructs a live TCPConn while the tuple quarantine remains
// installed. Unsent queue bytes are written only after leaving repair mode.
func Restore(ctx context.Context, snapshot *Snapshot) (*net.TCPConn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	copy, err := cloneSnapshot(snapshot)
	if err != nil {
		return nil, err
	}
	ops := systemSocketOps{}
	fd, err := restoreFD(ctx, copy, ops)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "rendr-tcp-repair")
	if file == nil {
		return nil, errors.Join(ErrUnsupported, discardFD(fd, ops))
	}
	conn, fileErr := net.FileConn(file)
	closeErr := file.Close()
	if fileErr != nil {
		return nil, errors.Join(fmt.Errorf("tcprepair: wrap restored socket: %w", fileErr), closeErr)
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		discardErr := conn.Close()
		return nil, errors.Join(fmt.Errorf("%w: restored socket became %T", ErrUnsupported, conn), discardErr)
	}
	if closeErr != nil {
		discardErr := tcpConn.Close()
		cleanupErr := errors.Join(closeErr, discardErr)
		return nil, fmt.Errorf("tcprepair: release restored file: %w", cleanupErr)
	}
	return tcpConn, nil
}

func inspectFD(fd int, tuple Tuple, ops linuxSocketOps) (socketState, error) {
	var info [8]byte
	n, err := ops.getRaw(fd, unix.IPPROTO_TCP, unix.TCP_INFO, info[:])
	if err != nil {
		return socketState{}, fmt.Errorf("%w: inspect TCP_INFO prefix: %w", ErrUnsupported, err)
	}
	if n != len(info) {
		return socketState{}, fmt.Errorf("%w: TCP_INFO prefix length %d", ErrUnsupported, n)
	}
	if info[0] != tcpEstablished {
		return socketState{}, fmt.Errorf("%w: TCP state %d", ErrIneligibleState, info[0])
	}
	mask := info[5]
	if mask&^supportedOptionMask != 0 {
		return socketState{}, fmt.Errorf("%w: TCP_INFO option mask %#x", ErrUnsupportedOption, mask)
	}
	sendScale, receiveScale := info[6]&0x0f, info[6]>>4
	if mask&optionWindowScale == 0 {
		sendScale, receiveScale = 0, 0
	}
	if sendScale > 14 || receiveScale > 14 {
		return socketState{}, fmt.Errorf("%w: TCP window scales %d/%d", ErrUnsupportedOption, sendScale, receiveScale)
	}
	ulp, err := ops.getString(fd, unix.IPPROTO_TCP, unix.TCP_ULP)
	if err != nil && !errors.Is(err, unix.ENOPROTOOPT) {
		return socketState{}, fmt.Errorf("%w: inspect TCP_ULP: %w", ErrUnsupportedOption, err)
	}
	if ulp != "" {
		return socketState{}, fmt.Errorf("%w: TCP_ULP %q", ErrUnsupportedOption, ulp)
	}
	for _, option := range []struct {
		level int
		name  int
		label string
	}{
		{unix.SOL_SOCKET, unix.SO_KEEPALIVE, "SO_KEEPALIVE"},
		{unix.IPPROTO_TCP, unix.TCP_CORK, "TCP_CORK"},
		{unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, "TCP_USER_TIMEOUT"},
	} {
		value, optionErr := ops.getInt(fd, option.level, option.name)
		if optionErr != nil {
			return socketState{}, fmt.Errorf("%w: inspect %s: %w", ErrUnsupportedOption, option.label, optionErr)
		}
		if value != 0 {
			return socketState{}, fmt.Errorf("%w: %s=%d", ErrUnsupportedOption, option.label, value)
		}
	}
	receiveBytes, err := queueLength(fd, unix.SIOCINQ, "receive", ops)
	if err != nil {
		return socketState{}, err
	}
	sendBytes, err := queueLength(fd, unix.SIOCOUTQ, "send", ops)
	if err != nil {
		return socketState{}, err
	}
	unsentBytes, err := queueLength(fd, unix.SIOCOUTQNSD, "unsent", ops)
	if err != nil {
		return socketState{}, err
	}
	if unsentBytes > sendBytes {
		return socketState{}, fmt.Errorf("%w: unsent queue %d exceeds send queue %d", ErrIneligibleState, unsentBytes, sendBytes)
	}
	sendBuffer, err := positiveSocketValue(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, "SO_SNDBUF", ops)
	if err != nil {
		return socketState{}, err
	}
	receiveBuffer, err := positiveSocketValue(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, "SO_RCVBUF", ops)
	if err != nil {
		return socketState{}, err
	}
	noDelay, err := ops.getInt(fd, unix.IPPROTO_TCP, unix.TCP_NODELAY)
	if err != nil {
		return socketState{}, fmt.Errorf("%w: inspect TCP_NODELAY: %w", ErrUnsupportedOption, err)
	}
	reuseAddress, err := booleanSocketValue(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, "SO_REUSEADDR", ops)
	if err != nil {
		return socketState{}, err
	}
	transparent, err := booleanSocketValue(fd, unix.SOL_IP, unix.IP_TRANSPARENT, "IP_TRANSPARENT", ops)
	if err != nil {
		return socketState{}, err
	}
	return socketState{
		inspection: Inspection{
			Tuple:             tuple,
			ReceiveQueueBytes: receiveBytes,
			SendQueueBytes:    sendBytes,
			UnsentBytes:       unsentBytes,
			OptionsMask:       mask,
			SendScale:         sendScale,
			ReceiveScale:      receiveScale,
		},
		sendBuffer:    sendBuffer,
		receiveBuffer: receiveBuffer,
		noDelay:       noDelay != 0,
		reuseAddress:  reuseAddress,
		transparent:   transparent,
	}, nil
}

type captureResult struct {
	snapshot *Snapshot
	state    SourceState
}

func captureFD(fd int, tuple Tuple, ops linuxSocketOps) (result captureResult, retErr error) {
	result.state = SourceStateNormal
	reuseAddress, err := booleanSocketValue(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, "SO_REUSEADDR", ops)
	if err != nil {
		return result, err
	}
	transparent, err := booleanSocketValue(fd, unix.SOL_IP, unix.IP_TRANSPARENT, "IP_TRANSPARENT", ops)
	if err != nil {
		return result, err
	}
	if err := ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_ON); err != nil {
		state, stateErr := readRepairState(fd, ops)
		result.state = state
		return result, errors.Join(fmt.Errorf("tcprepair: enter repair: %w", err), stateErr)
	}
	result.state = SourceStateUnknown
	keepRepair := false
	defer func() {
		if keepRepair {
			return
		}
		state, err := leaveRepairState(fd, ops)
		result.state = state
		if err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("tcprepair: unwind failed capture: %w", err))
		}
	}()
	repairState, err := readRepairState(fd, ops)
	result.state = repairState
	if err != nil || repairState != SourceStateRepair {
		return result, errors.Join(fmt.Errorf("tcprepair: verify repair entry state %d", repairState), err)
	}

	state, err := inspectFD(fd, tuple, ops)
	if err != nil {
		return result, err
	}
	// TCP_REPAIR can temporarily expose an internal SO_REUSEADDR value. The
	// capsule preserves the application-visible values sampled before repair.
	state.reuseAddress = reuseAddress
	state.transparent = transparent
	mss, err := positiveSocketValue(fd, unix.IPPROTO_TCP, unix.TCP_MAXSEG, "TCP_MAXSEG", ops)
	if err != nil {
		return result, err
	}
	timestamp := uint32(0)
	if state.inspection.OptionsMask&optionTimestamps != 0 {
		value, timestampErr := ops.getInt(fd, unix.IPPROTO_TCP, unix.TCP_TIMESTAMP)
		if timestampErr != nil {
			return result, fmt.Errorf("%w: capture TCP_TIMESTAMP: %w", ErrUnsupportedOption, timestampErr)
		}
		timestamp = uint32(value)
	}
	windowBytes := make([]byte, 20)
	if n, windowErr := ops.getRaw(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_WINDOW, windowBytes); windowErr != nil {
		return result, fmt.Errorf("%w: capture TCP_REPAIR_WINDOW: %w", ErrUnsupported, windowErr)
	} else if n != len(windowBytes) {
		return result, fmt.Errorf("%w: capture TCP_REPAIR_WINDOW length %d", ErrUnsupported, n)
	}
	receiveSequence, receiveQueue, err := captureQueue(
		fd, tcpRecvQueue, state.inspection.ReceiveQueueBytes, "receive", ops,
	)
	if err != nil {
		return result, err
	}
	sendSequence, sendQueue, err := captureQueue(
		fd, tcpSendQueue, state.inspection.SendQueueBytes, "send", ops,
	)
	if err != nil {
		return result, err
	}
	if err := ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, tcpNoQueue); err != nil {
		return result, fmt.Errorf("tcprepair: select no queue: %w", err)
	}
	snapshot := &Snapshot{
		tuple:           tuple,
		receiveSequence: receiveSequence,
		sendSequence:    sendSequence,
		receiveQueue:    receiveQueue,
		sendQueue:       sendQueue,
		unsentBytes:     state.inspection.UnsentBytes,
		options: streamOptions{
			Mask:          state.inspection.OptionsMask,
			SendScale:     state.inspection.SendScale,
			ReceiveScale:  state.inspection.ReceiveScale,
			MSSClamp:      mss,
			Timestamp:     timestamp,
			SendBuffer:    state.sendBuffer,
			ReceiveBuffer: state.receiveBuffer,
			NoDelay:       state.noDelay,
			ReuseAddress:  state.reuseAddress,
			Transparent:   state.transparent,
		},
		window: decodeWindow(windowBytes),
	}
	if err := snapshot.seal(); err != nil {
		return result, err
	}
	keepRepair = true
	result.snapshot = snapshot
	result.state = SourceStateRepair
	return result, nil
}

func restoreFD(ctx context.Context, snapshot *Snapshot, ops linuxSocketOps) (_ int, retErr error) {
	if err := snapshot.valid(); err != nil {
		return -1, err
	}
	fd, err := ops.socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		return -1, fmt.Errorf("tcprepair: create replacement socket: %w", err)
	}
	success := false
	inRepair := false
	defer func() {
		if success {
			return
		}
		if !inRepair {
			if err := ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_ON); err == nil {
				inRepair = true
			} else {
				retErr = errors.Join(retErr, fmt.Errorf("tcprepair: refreeze failed replacement: %w", err))
			}
		}
		queueErr := ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, tcpNoQueue)
		retErr = errors.Join(retErr, queueErr, closeReplacementFD(fd, ops))
	}()

	if err := ops.setInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return -1, fmt.Errorf("tcprepair: set SO_REUSEADDR: %w", err)
	}
	if err := ops.setInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
		return -1, fmt.Errorf("tcprepair: set IP_TRANSPARENT: %w", err)
	}
	temporarySendBuffer := queueRestoreBuffer(snapshot.options.SendBuffer, len(snapshot.sendQueue))
	temporaryReceiveBuffer := queueRestoreBuffer(snapshot.options.ReceiveBuffer, len(snapshot.receiveQueue))
	if err := ensureSocketBuffer(fd, unix.SO_SNDBUF, unix.SO_SNDBUFFORCE, temporarySendBuffer, ops); err != nil {
		return -1, err
	}
	if err := ensureSocketBuffer(fd, unix.SO_RCVBUF, unix.SO_RCVBUFFORCE, temporaryReceiveBuffer, ops); err != nil {
		return -1, err
	}
	noDelay := 0
	if snapshot.options.NoDelay {
		noDelay = 1
	}
	if err := ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_NODELAY, noDelay); err != nil {
		return -1, fmt.Errorf("tcprepair: restore TCP_NODELAY: %w", err)
	}
	if err := ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_ON); err != nil {
		return -1, fmt.Errorf("tcprepair: enter replacement repair: %w", err)
	}
	inRepair = true
	if err := ops.bind(fd, sockaddr(snapshot.tuple.Local)); err != nil {
		return -1, fmt.Errorf("tcprepair: bind original tuple: %w", err)
	}
	if err := setQueueSequence(fd, tcpRecvQueue, snapshot.receiveSequence-uint32(len(snapshot.receiveQueue)), ops); err != nil {
		return -1, err
	}
	if err := setQueueSequence(fd, tcpSendQueue, snapshot.sendSequence-uint32(len(snapshot.sendQueue)), ops); err != nil {
		return -1, err
	}
	if err := ops.connect(fd, sockaddr(snapshot.tuple.Remote)); err != nil {
		return -1, fmt.Errorf("tcprepair: connect original tuple: %w", err)
	}
	if err := restoreBooleanSocketOption(
		fd, unix.SOL_IP, unix.IP_TRANSPARENT, snapshot.options.Transparent, "IP_TRANSPARENT", ops,
	); err != nil {
		return -1, err
	}
	if err := restoreOptions(fd, snapshot.options, ops); err != nil {
		return -1, err
	}
	if err := restoreRepairQueue(fd, tcpRecvQueue, snapshot.receiveQueue, ops); err != nil {
		return -1, fmt.Errorf("tcprepair: restore receive queue: %w", err)
	}
	sentBytes := len(snapshot.sendQueue) - int(snapshot.unsentBytes)
	if err := restoreRepairQueue(fd, tcpSendQueue, snapshot.sendQueue[:sentBytes], ops); err != nil {
		return -1, fmt.Errorf("tcprepair: restore sent queue: %w", err)
	}
	if err := ops.setRaw(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_WINDOW, encodeWindow(snapshot.window)); err != nil {
		return -1, fmt.Errorf("tcprepair: restore TCP_REPAIR_WINDOW: %w", err)
	}
	if err := validateRestoredRepairState(fd, snapshot, ops); err != nil {
		return -1, err
	}
	if err := ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, tcpNoQueue); err != nil {
		return -1, fmt.Errorf("tcprepair: select no queue before resume: %w", err)
	}
	if err := ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR, 0); err != nil {
		return -1, fmt.Errorf("tcprepair: resume replacement: %w", err)
	}
	inRepair = false
	if err := restoreBooleanSocketOption(
		fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, snapshot.options.ReuseAddress, "SO_REUSEADDR", ops,
	); err != nil {
		return -1, err
	}
	if snapshot.unsentBytes != 0 {
		if err := ops.setNonblock(fd, true); err != nil {
			return -1, fmt.Errorf("tcprepair: make replacement nonblocking: %w", err)
		}
		if err := writeWithContext(ctx, fd, snapshot.sendQueue[sentBytes:], ops); err != nil {
			return -1, fmt.Errorf("tcprepair: restore unsent queue: %w", err)
		}
	}
	if err := setSocketBuffer(fd, unix.SO_SNDBUF, unix.SO_SNDBUFFORCE, snapshot.options.SendBuffer, ops); err != nil {
		return -1, err
	}
	if err := setSocketBuffer(fd, unix.SO_RCVBUF, unix.SO_RCVBUFFORCE, snapshot.options.ReceiveBuffer, ops); err != nil {
		return -1, err
	}
	if err := validateRestoredSocket(fd, snapshot, ops); err != nil {
		return -1, err
	}
	success = true
	return fd, nil
}

func booleanSocketValue(fd, level, option int, label string, ops linuxSocketOps) (bool, error) {
	value, err := ops.getInt(fd, level, option)
	if err != nil {
		return false, fmt.Errorf("%w: inspect %s: %w", ErrUnsupportedOption, label, err)
	}
	return value != 0, nil
}

func restoreBooleanSocketOption(
	fd, level, option int,
	wanted bool,
	label string,
	ops linuxSocketOps,
) error {
	value := 0
	if wanted {
		value = 1
	}
	if err := ops.setInt(fd, level, option, value); err != nil {
		return fmt.Errorf("tcprepair: restore %s: %w", label, err)
	}
	got, err := ops.getInt(fd, level, option)
	if err != nil {
		return fmt.Errorf("tcprepair: verify restored %s: %w", label, err)
	}
	if got != value {
		return fmt.Errorf("tcprepair: verify restored %s: got %d, want %d", label, got, value)
	}
	return nil
}

func validateRestoredRepairState(fd int, snapshot *Snapshot, ops linuxSocketOps) error {
	tuple, err := tupleFromFD(fd, ops)
	if err != nil {
		return fmt.Errorf("tcprepair: validate replacement tuple: %w", err)
	}
	if tuple != snapshot.tuple {
		return fmt.Errorf("tcprepair: validate replacement tuple: got %s -> %s, want %s -> %s",
			tuple.Local, tuple.Remote, snapshot.tuple.Local, snapshot.tuple.Remote)
	}

	receiveSequence, receiveQueue, err := captureQueue(
		fd, tcpRecvQueue, uint32(len(snapshot.receiveQueue)), "restored receive", ops,
	)
	if err != nil {
		return err
	}
	if receiveSequence != snapshot.receiveSequence || !bytes.Equal(receiveQueue, snapshot.receiveQueue) {
		return fmt.Errorf("tcprepair: restored receive queue mismatch")
	}
	sentBytes := len(snapshot.sendQueue) - int(snapshot.unsentBytes)
	sendSequence, sendQueue, err := captureQueue(
		fd, tcpSendQueue, uint32(sentBytes), "restored send", ops,
	)
	if err != nil {
		return err
	}
	wantSendSequence := snapshot.sendSequence - snapshot.unsentBytes
	if sendSequence != wantSendSequence || !bytes.Equal(sendQueue, snapshot.sendQueue[:sentBytes]) {
		return fmt.Errorf("tcprepair: restored send queue mismatch")
	}

	windowBytes := make([]byte, 20)
	if n, err := ops.getRaw(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_WINDOW, windowBytes); err != nil {
		return fmt.Errorf("tcprepair: validate TCP_REPAIR_WINDOW: %w", err)
	} else if n != len(windowBytes) || decodeWindow(windowBytes) != snapshot.window {
		return fmt.Errorf("tcprepair: validate TCP_REPAIR_WINDOW: length=%d", n)
	}
	return nil
}

func validateRestoredSocket(fd int, snapshot *Snapshot, ops linuxSocketOps) error {
	tuple, err := tupleFromFD(fd, ops)
	if err != nil {
		return fmt.Errorf("tcprepair: validate resumed tuple: %w", err)
	}
	if tuple != snapshot.tuple {
		return fmt.Errorf("tcprepair: validate resumed tuple: got %s -> %s, want %s -> %s",
			tuple.Local, tuple.Remote, snapshot.tuple.Local, snapshot.tuple.Remote)
	}
	if socketErr, err := ops.getInt(fd, unix.SOL_SOCKET, unix.SO_ERROR); err != nil {
		return fmt.Errorf("tcprepair: validate replacement SO_ERROR: %w", err)
	} else if socketErr != 0 {
		return fmt.Errorf("tcprepair: validate replacement SO_ERROR=%d", socketErr)
	}
	state, err := inspectFD(fd, tuple, ops)
	if err != nil {
		return fmt.Errorf("tcprepair: validate resumed replacement: %w", err)
	}
	if state.inspection.OptionsMask != snapshot.options.Mask ||
		state.inspection.SendScale != snapshot.options.SendScale ||
		state.inspection.ReceiveScale != snapshot.options.ReceiveScale ||
		state.noDelay != snapshot.options.NoDelay ||
		state.reuseAddress != snapshot.options.ReuseAddress ||
		state.transparent != snapshot.options.Transparent ||
		state.sendBuffer < snapshot.options.SendBuffer ||
		state.receiveBuffer < snapshot.options.ReceiveBuffer {
		return fmt.Errorf("tcprepair: resumed replacement options differ from snapshot")
	}
	return nil
}

func tupleFromFD(fd int, ops linuxSocketOps) (Tuple, error) {
	local, err := ops.getSockname(fd)
	if err != nil {
		return Tuple{}, err
	}
	remote, err := ops.getPeername(fd)
	if err != nil {
		return Tuple{}, err
	}
	tuple := Tuple{Local: addrPortFromSockaddr(local), Remote: addrPortFromSockaddr(remote)}
	if !tuple.ValidIPv4() {
		return Tuple{}, ErrIneligibleState
	}
	return tuple, nil
}

func addrPortFromSockaddr(address unix.Sockaddr) netip.AddrPort {
	ipv4, ok := address.(*unix.SockaddrInet4)
	if !ok || ipv4.Port <= 0 || ipv4.Port > 65535 {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(netip.AddrFrom4(ipv4.Addr), uint16(ipv4.Port))
}

func restoreOptions(fd int, options streamOptions, ops linuxSocketOps) error {
	repairOptions := make([]unix.TCPRepairOpt, 0, 4)
	if options.Mask&optionSACK != 0 {
		repairOptions = append(repairOptions, unix.TCPRepairOpt{Code: tcpOptionSACK})
	}
	if options.Mask&optionWindowScale != 0 {
		repairOptions = append(repairOptions, unix.TCPRepairOpt{
			Code: tcpOptionWindow,
			Val:  uint32(options.SendScale) | uint32(options.ReceiveScale)<<16,
		})
	}
	if options.Mask&optionTimestamps != 0 {
		repairOptions = append(repairOptions, unix.TCPRepairOpt{Code: tcpOptionTimestamps})
	}
	repairOptions = append(repairOptions, unix.TCPRepairOpt{Code: tcpOptionMSS, Val: options.MSSClamp})
	if err := ops.setRepairOptions(fd, repairOptions); err != nil {
		return fmt.Errorf("tcprepair: restore TCP_REPAIR_OPTIONS: %w", err)
	}
	if options.Mask&optionTimestamps != 0 {
		if err := ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_TIMESTAMP, int(options.Timestamp)); err != nil {
			return fmt.Errorf("tcprepair: restore TCP_TIMESTAMP: %w", err)
		}
	}
	return nil
}

func captureQueue(fd, queue int, expected uint32, label string, ops linuxSocketOps) (uint32, []byte, error) {
	if err := ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, queue); err != nil {
		return 0, nil, fmt.Errorf("tcprepair: select %s queue: %w", label, err)
	}
	sequence, err := ops.getInt(fd, unix.IPPROTO_TCP, unix.TCP_QUEUE_SEQ)
	if err != nil {
		return 0, nil, fmt.Errorf("tcprepair: get %s queue sequence: %w", label, err)
	}
	if expected == 0 {
		return uint32(sequence), nil, nil
	}
	buffer := make([]byte, int(expected)+1)
	n, err := ops.recv(fd, buffer, unix.MSG_PEEK|unix.MSG_DONTWAIT)
	if err != nil {
		return 0, nil, fmt.Errorf("tcprepair: read %s queue: %w", label, err)
	}
	if n != int(expected) {
		return 0, nil, fmt.Errorf("%w: %s queue changed: got %d bytes, expected %d", ErrIneligibleState, label, n, expected)
	}
	return uint32(sequence), append([]byte(nil), buffer[:n]...), nil
}

func restoreRepairQueue(fd, queue int, value []byte, ops linuxSocketOps) error {
	if len(value) == 0 {
		return nil
	}
	if err := ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, queue); err != nil {
		return err
	}
	return writeRepairQueue(fd, value, ops)
}

func writeRepairQueue(fd int, value []byte, ops linuxSocketOps) error {
	maxChunk := len(value)
	for offset := 0; offset < len(value); {
		chunk := len(value) - offset
		if chunk > maxChunk {
			chunk = maxChunk
		}
		n, err := ops.write(fd, value[offset:offset+chunk])
		if n > 0 {
			offset += n
		}
		if err == nil && n > 0 {
			continue
		}
		if n == 0 && maxChunk > 1024 && (errors.Is(err, unix.ENOMEM) || err == nil) {
			maxChunk /= 2
			continue
		}
		if err != nil {
			return err
		}
		return syscall.EIO
	}
	return nil
}

func writeWithContext(ctx context.Context, fd int, value []byte, ops linuxSocketOps) error {
	for len(value) != 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := ops.write(fd, value)
		if n > 0 {
			value = value[n:]
		}
		if err == nil && n > 0 {
			continue
		}
		if err != nil && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			return err
		}
		if err := waitWritable(ctx, fd, ops); err != nil {
			return err
		}
	}
	return nil
}

func waitWritable(ctx context.Context, fd int, ops linuxSocketOps) error {
	timeout := 100 * time.Millisecond
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return context.DeadlineExceeded
		}
		if remaining < timeout {
			timeout = remaining
		}
	}
	n, err := ops.poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}, max(1, int(timeout.Milliseconds())))
	if err != nil && !errors.Is(err, unix.EINTR) {
		return err
	}
	if n == 0 {
		return ctx.Err()
	}
	return nil
}

func ensureSocketBuffer(fd, option, forceOption int, wanted uint32, ops linuxSocketOps) error {
	current, err := ops.getInt(fd, unix.SOL_SOCKET, option)
	if err != nil {
		return fmt.Errorf("tcprepair: inspect socket buffer %d: %w", option, err)
	}
	if current >= 0 && uint32(current) >= wanted {
		return nil
	}
	return setSocketBuffer(fd, option, forceOption, wanted, ops)
}

func setSocketBuffer(fd, option, forceOption int, wanted uint32, ops linuxSocketOps) error {
	request := int((uint64(wanted) + 1) / 2)
	regularErr := ops.setInt(fd, unix.SOL_SOCKET, option, request)
	current, verifyErr := ops.getInt(fd, unix.SOL_SOCKET, option)
	if regularErr == nil && verifyErr == nil && current >= 0 && uint32(current) >= wanted {
		return nil
	}
	forceErr := ops.setInt(fd, unix.SOL_SOCKET, forceOption, request)
	current, finalErr := ops.getInt(fd, unix.SOL_SOCKET, option)
	if forceErr != nil || finalErr != nil || current < 0 || uint32(current) < wanted {
		return fmt.Errorf("tcprepair: cannot restore socket buffer %d to %d: %w", option, wanted,
			errors.Join(regularErr, verifyErr, forceErr, finalErr))
	}
	return nil
}

func queueRestoreBuffer(original uint32, queueBytes int) uint32 {
	// Repair queue injection creates different skb shapes than the original
	// send path. A bounded 2x payload allowance prevents skb accounting from
	// starving the normal-mode unsent tail; the original limit is restored
	// before the replacement is published.
	wanted := uint64(queueBytes)*2 + 64<<10
	if wanted < uint64(original) {
		return original
	}
	return uint32(wanted)
}

func setQueueSequence(fd, queue int, sequence uint32, ops linuxSocketOps) error {
	if err := ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, queue); err != nil {
		return fmt.Errorf("tcprepair: select repair queue %d: %w", queue, err)
	}
	if err := ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_QUEUE_SEQ, int(sequence)); err != nil {
		return fmt.Errorf("tcprepair: set repair queue %d sequence: %w", queue, err)
	}
	return nil
}

func leaveRepair(fd int, ops linuxSocketOps) error {
	_, err := leaveRepairState(fd, ops)
	return err
}

func leaveRepairState(fd int, ops linuxSocketOps) (SourceState, error) {
	queueErr := ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, tcpNoQueue)
	repairErr := ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR, 0)
	state, stateErr := readRepairState(fd, ops)
	joined := errors.Join(queueErr, repairErr, stateErr)
	if state == SourceStateUnknown {
		joined = errors.Join(joined, ErrSourceStateUnknown)
	} else if state != SourceStateNormal {
		joined = errors.Join(joined, fmt.Errorf("%w: repair-off readback=%d", ErrSourceStateUnknown, state))
	}
	return state, joined
}

func readRepairState(fd int, ops linuxSocketOps) (SourceState, error) {
	value, err := ops.getInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR)
	if err != nil {
		return SourceStateUnknown, errors.Join(ErrSourceStateUnknown, err)
	}
	switch value {
	case 0:
		return SourceStateNormal, nil
	case unix.TCP_REPAIR_ON:
		return SourceStateRepair, nil
	default:
		return SourceStateUnknown, fmt.Errorf("%w: TCP_REPAIR=%d", ErrSourceStateUnknown, value)
	}
}

func discardFD(fd int, ops linuxSocketOps) error {
	enterErr := ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_ON)
	queueErr := ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, tcpNoQueue)
	return errors.Join(enterErr, queueErr, closeReplacementFD(fd, ops))
}

func closeReplacementFD(fd int, ops linuxSocketOps) error {
	// Linux releases the descriptor before any later close error is reported.
	// Retrying this numeric fd could close an unrelated descriptor that another
	// goroutine has already allocated, so the error is diagnostic only.
	return ops.close(fd)
}

func queueLength(fd int, request uint, label string, ops linuxSocketOps) (uint32, error) {
	value, err := ops.ioctlGetInt(fd, request)
	if err != nil {
		return 0, fmt.Errorf("%w: inspect %s queue: %w", ErrUnsupported, label, err)
	}
	if value < 0 || value > MaxQueueBytes {
		return 0, fmt.Errorf("%w: %s queue length %d", ErrQueueBudget, label, value)
	}
	return uint32(value), nil
}

func positiveSocketValue(fd, level, option int, label string, ops linuxSocketOps) (uint32, error) {
	value, err := ops.getInt(fd, level, option)
	if err != nil {
		return 0, fmt.Errorf("%w: inspect %s: %w", ErrUnsupportedOption, label, err)
	}
	if value <= 0 {
		return 0, fmt.Errorf("%w: inspect %s=%d", ErrUnsupportedOption, label, value)
	}
	return uint32(value), nil
}

func decodeWindow(value []byte) repairWindow {
	return repairWindow{
		SendWindowLastSequence: binary.NativeEndian.Uint32(value[0:4]),
		SendWindow:             binary.NativeEndian.Uint32(value[4:8]),
		MaxWindow:              binary.NativeEndian.Uint32(value[8:12]),
		ReceiveWindow:          binary.NativeEndian.Uint32(value[12:16]),
		ReceiveWindowUpdate:    binary.NativeEndian.Uint32(value[16:20]),
	}
}

func encodeWindow(window repairWindow) []byte {
	value := make([]byte, 20)
	binary.NativeEndian.PutUint32(value[0:4], window.SendWindowLastSequence)
	binary.NativeEndian.PutUint32(value[4:8], window.SendWindow)
	binary.NativeEndian.PutUint32(value[8:12], window.MaxWindow)
	binary.NativeEndian.PutUint32(value[12:16], window.ReceiveWindow)
	binary.NativeEndian.PutUint32(value[16:20], window.ReceiveWindowUpdate)
	return value
}

func tupleOf(conn *net.TCPConn) (Tuple, error) {
	if conn == nil {
		return Tuple{}, fmt.Errorf("%w: nil TCPConn", ErrIneligibleState)
	}
	local, localOK := conn.LocalAddr().(*net.TCPAddr)
	remote, remoteOK := conn.RemoteAddr().(*net.TCPAddr)
	if !localOK || !remoteOK {
		return Tuple{}, fmt.Errorf("%w: non-TCP endpoint addresses", ErrIneligibleState)
	}
	tuple := Tuple{Local: addrPort(local), Remote: addrPort(remote)}
	if !tuple.ValidIPv4() {
		return Tuple{}, fmt.Errorf("%w: only concrete IPv4 tuples are supported", ErrIneligibleState)
	}
	return tuple, nil
}

func addrPort(address *net.TCPAddr) netip.AddrPort {
	if address == nil || address.Port <= 0 || address.Port > 65535 {
		return netip.AddrPort{}
	}
	ip, ok := netip.AddrFromSlice(address.IP)
	if !ok {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(address.Port))
}

func sockaddr(address netip.AddrPort) *unix.SockaddrInet4 {
	value := &unix.SockaddrInet4{Port: int(address.Port())}
	value.Addr = address.Addr().As4()
	return value
}

func controlTCP(conn *net.TCPConn, operation func(fd int) error) error {
	if conn == nil {
		return fmt.Errorf("%w: nil TCPConn", ErrIneligibleState)
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var operationErr error
	controlErr := raw.Control(func(fd uintptr) {
		operationErr = operation(int(fd))
	})
	return errors.Join(controlErr, operationErr)
}
