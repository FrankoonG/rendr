//go:build linux

package platform

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const tcpRepairProbeDeadline = 500 * time.Millisecond

const (
	tcpRepairEstablished      = 1
	tcpRepairNoQueue          = 0
	tcpRepairRecvQueue        = 1
	tcpRepairSendQueue        = 2
	tcpInfoTimestamps         = 1
	tcpInfoSACK               = 2
	tcpInfoWindowScale        = 4
	tcpRepairSequenceSendSize = 37
	tcpRepairSequenceRecvSize = 53
	tcpRepairFinalSendSize    = 29
	tcpRepairFinalRecvSize    = 41
)

var tcpRepairFeatureIDs = [...]FeatureID{
	FeatureTCPRepairPermission,
	FeatureTCPRepairBase,
	FeatureTCPRepairQueueSeq,
	FeatureTCPRepairWindow,
	FeatureTCPRepairOptions,
}

type tcpRepairProbeWindow struct {
	SendWindowLastUpdate uint32
	SendWindow           uint32
	MaxWindow            uint32
	ReceiveWindow        uint32
	ReceiveWindowUpdate  uint32
}

type tcpRepairProbeInfo struct {
	State       uint8
	CAState     uint8
	Retransmits uint8
	Probes      uint8
	Backoff     uint8
	Options     uint8
	WindowScale uint8
	Flags       uint8
	RTO         uint32
	ATO         uint32
	SendMSS     uint32
	ReceiveMSS  uint32
}

type tcpRepairProbeSequences struct {
	send uint32
	recv uint32
}

type tcpRepairProbePair interface {
	control(func(int) error) error
	validate() error
	exchange(request, response []byte) error
	close() error
}

type tcpRepairProbeOps struct {
	open        func(context.Context) (tcpRepairProbePair, error)
	openScratch func() (int, error)
	closeFD     func(int) error
	setInt      func(fd, level, option, value int) error
	getInt      func(fd, level, option int) (int, error)
	getWindow   func(fd int) (tcpRepairProbeWindow, error)
	setWindow   func(fd int, window tcpRepairProbeWindow) error
	getInfo     func(fd int) (tcpRepairProbeInfo, error)
	setOptions  func(fd int, options []unix.TCPRepairOpt) error
}

func defaultTCPRepairProbeOps() tcpRepairProbeOps {
	return tcpRepairProbeOps{
		open: openTCPRepairProbePair,
		openScratch: func() (int, error) {
			return unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
		},
		closeFD:   unix.Close,
		setInt:    unix.SetsockoptInt,
		getInt:    unix.GetsockoptInt,
		getWindow: getTCPRepairProbeWindow,
		setWindow: setTCPRepairProbeWindow,
		getInfo:   getTCPRepairProbeInfo,
		setOptions: func(fd int, options []unix.TCPRepairOpt) error {
			return unix.SetsockoptTCPRepairOpt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_OPTIONS, options)
		},
	}
}

type liveTCPRepairProbePair struct {
	client *net.TCPConn
	server *net.TCPConn
}

func openTCPRepairProbePair(ctx context.Context) (tcpRepairProbePair, error) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	closed := false
	defer func() {
		if !closed {
			_ = listener.Close()
		}
	}()
	if err := listener.SetDeadline(time.Now().Add(tcpRepairProbeDeadline)); err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: tcpRepairProbeDeadline}
	connection, err := dialer.DialContext(ctx, "tcp4", listener.Addr().String())
	if err != nil {
		return nil, err
	}
	client, ok := connection.(*net.TCPConn)
	if !ok {
		_ = connection.Close()
		return nil, fmt.Errorf("platform: loopback TCP dial returned %T", connection)
	}
	server, err := listener.AcceptTCP()
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	if err := listener.Close(); err != nil {
		_ = client.Close()
		_ = server.Close()
		return nil, err
	}
	closed = true
	return &liveTCPRepairProbePair{client: client, server: server}, nil
}

func (pair *liveTCPRepairProbePair) control(fn func(int) error) error {
	raw, err := pair.client.SyscallConn()
	if err != nil {
		return err
	}
	var operationErr error
	if err := raw.Control(func(fd uintptr) {
		operationErr = fn(int(fd))
	}); err != nil {
		return err
	}
	return operationErr
}

func (pair *liveTCPRepairProbePair) validate() error {
	clientLocal, clientLocalOK := pair.client.LocalAddr().(*net.TCPAddr)
	clientRemote, clientRemoteOK := pair.client.RemoteAddr().(*net.TCPAddr)
	serverLocal, serverLocalOK := pair.server.LocalAddr().(*net.TCPAddr)
	serverRemote, serverRemoteOK := pair.server.RemoteAddr().(*net.TCPAddr)
	if !clientLocalOK || !clientRemoteOK || !serverLocalOK || !serverRemoteOK {
		return fmt.Errorf("platform: TCP_REPAIR pair has non-TCP addresses")
	}
	if !sameTCPProbeAddress(clientLocal, serverRemote) || !sameTCPProbeAddress(clientRemote, serverLocal) {
		return fmt.Errorf("platform: TCP_REPAIR pair tuples do not cross-match")
	}
	for _, connection := range []*net.TCPConn{pair.client, pair.server} {
		raw, err := connection.SyscallConn()
		if err != nil {
			return err
		}
		var operationErr error
		if err := raw.Control(func(fd uintptr) {
			if socketErr, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ERROR); err != nil {
				operationErr = err
			} else if socketErr != 0 {
				operationErr = syscall.Errno(socketErr)
			} else if info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO); err != nil {
				operationErr = err
			} else if info.State != tcpRepairEstablished {
				operationErr = fmt.Errorf("TCP_INFO state=%d", info.State)
			}
		}); err != nil {
			return err
		}
		if operationErr != nil {
			return operationErr
		}
	}
	return nil
}

func sameTCPProbeAddress(left, right *net.TCPAddr) bool {
	return left.Port == right.Port && left.Zone == right.Zone && left.IP.Equal(right.IP)
}

func (pair *liveTCPRepairProbePair) exchange(request, response []byte) (retErr error) {
	deadline := time.Now().Add(tcpRepairProbeDeadline)
	if err := pair.client.SetDeadline(deadline); err != nil {
		return err
	}
	if err := pair.server.SetDeadline(deadline); err != nil {
		return errors.Join(err, pair.client.SetDeadline(time.Time{}))
	}
	defer func() {
		retErr = errors.Join(retErr, pair.client.SetDeadline(time.Time{}), pair.server.SetDeadline(time.Time{}))
	}()

	if err := writeAll(pair.client, request); err != nil {
		return err
	}
	gotRequest := make([]byte, len(request))
	if _, err := io.ReadFull(pair.server, gotRequest); err != nil {
		return err
	}
	if string(gotRequest) != string(request) {
		return fmt.Errorf("platform: TCP_REPAIR request payload mismatch")
	}
	if err := writeAll(pair.server, response); err != nil {
		return err
	}
	gotResponse := make([]byte, len(response))
	if _, err := io.ReadFull(pair.client, gotResponse); err != nil {
		return err
	}
	if string(gotResponse) != string(response) {
		return fmt.Errorf("platform: TCP_REPAIR response payload mismatch")
	}
	return nil
}

func (pair *liveTCPRepairProbePair) close() error {
	return errors.Join(pair.client.Close(), pair.server.Close())
}

func writeAll(connection net.Conn, payload []byte) error {
	for len(payload) > 0 {
		written, err := connection.Write(payload)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrNoProgress
		}
		payload = payload[written:]
	}
	return nil
}

type tcpRepairProbeOutcome struct {
	entered    bool
	sequences  tcpRepairProbeSequences
	enterErr   error
	baseErr    error
	queueErr   error
	windowErr  error
	optionsErr error
	canceled   error
	cleanupErr error
}

func probeTCPRepair(ctx context.Context, at time.Time, ops tcpRepairProbeOps) ([]FeatureEvidence, error) {
	if err := validateTCPRepairProbeOps(ops); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pair, err := ops.open(ctx)
	if err != nil {
		return tcpRepairInfrastructureFailure(at, err), nil
	}
	if err := pair.validate(); err != nil {
		if closeErr := pair.close(); closeErr != nil {
			return tcpRepairCleanupFailure(at, errors.Join(err, closeErr)), nil
		}
		return tcpRepairSemanticFailure(at, err), nil
	}
	outcome := runTCPRepairProbe(ctx, pair, ops)
	if outcome.entered && outcome.baseErr == nil && outcome.queueErr == nil && outcome.cleanupErr == nil && outcome.canceled == nil {
		setterErr, canceled, cleanupErr := exerciseTCPRepairSequenceSetter(ctx, ops)
		outcome.queueErr = errors.Join(outcome.queueErr, setterErr)
		outcome.canceled = errors.Join(outcome.canceled, canceled)
		outcome.cleanupErr = errors.Join(outcome.cleanupErr, cleanupErr)
	}
	var semanticErr error
	if outcome.cleanupErr == nil && outcome.complete() && outcome.canceled == nil {
		request := tcpRepairProbePayload(tcpRepairSequenceSendSize, 0x31)
		response := tcpRepairProbePayload(tcpRepairSequenceRecvSize, 0x71)
		if err := pair.exchange(request, response); err != nil {
			semanticErr = err
		} else {
			verificationErr, canceled, cleanupErr := verifyTCPRepairSequenceDelta(ctx, pair, ops, outcome.sequences, uint32(len(request)), uint32(len(response)))
			semanticErr = errors.Join(semanticErr, verificationErr)
			outcome.canceled = errors.Join(outcome.canceled, canceled)
			outcome.cleanupErr = errors.Join(outcome.cleanupErr, cleanupErr)
		}
	}
	finalExchangeErr := pair.exchange(
		tcpRepairProbePayload(tcpRepairFinalSendSize, 0xa3),
		tcpRepairProbePayload(tcpRepairFinalRecvSize, 0xc7),
	)
	semanticErr = errors.Join(semanticErr, finalExchangeErr)
	if finalExchangeErr == nil {
		semanticErr = errors.Join(semanticErr, pair.validate())
	}
	closeErr := pair.close()
	if outcome.canceled != nil {
		return nil, errors.Join(outcome.canceled, outcome.cleanupErr, semanticErr, closeErr)
	}
	if cleanupErr := errors.Join(outcome.cleanupErr, closeErr); cleanupErr != nil {
		return tcpRepairCleanupFailure(at, cleanupErr), nil
	}
	if semanticErr != nil {
		return tcpRepairSemanticFailure(at, semanticErr), nil
	}
	return tcpRepairOutcomeEvidence(at, outcome), nil
}

func (outcome tcpRepairProbeOutcome) complete() bool {
	return outcome.entered && outcome.enterErr == nil && outcome.baseErr == nil && outcome.queueErr == nil &&
		outcome.windowErr == nil && outcome.optionsErr == nil
}

func validateTCPRepairProbeOps(ops tcpRepairProbeOps) error {
	if ops.open == nil || ops.openScratch == nil || ops.closeFD == nil || ops.setInt == nil || ops.getInt == nil || ops.getWindow == nil ||
		ops.setWindow == nil || ops.getInfo == nil || ops.setOptions == nil {
		return fmt.Errorf("platform: incomplete TCP_REPAIR probe operations")
	}
	return nil
}

func runTCPRepairProbe(ctx context.Context, pair tcpRepairProbePair, ops tcpRepairProbeOps) tcpRepairProbeOutcome {
	outcome := tcpRepairProbeOutcome{}
	controlErr := pair.control(func(fd int) error {
		if err := ctx.Err(); err != nil {
			outcome.canceled = err
			return nil
		}
		if err := ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_ON); err != nil {
			outcome.enterErr = err
			return nil
		}
		outcome.entered = true
		defer func() {
			outcome.cleanupErr = errors.Join(
				ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, tcpRepairNoQueue),
				ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_OFF),
			)
			if outcome.cleanupErr == nil {
				state, err := ops.getInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR)
				if err != nil {
					outcome.cleanupErr = err
				} else if state != unix.TCP_REPAIR_OFF {
					outcome.cleanupErr = tcpRepairSemanticError{fmt.Errorf("TCP_REPAIR exit state=%d", state)}
				}
			}
		}()

		state, err := ops.getInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR)
		if err != nil {
			outcome.baseErr = err
			return nil
		}
		if state != unix.TCP_REPAIR_ON {
			outcome.baseErr = tcpRepairSemanticError{fmt.Errorf("TCP_REPAIR enter state=%d", state)}
			return nil
		}
		if err := ctx.Err(); err != nil {
			outcome.canceled = err
			return nil
		}

		outcome.sequences, outcome.queueErr = readTCPRepairQueues(fd, ops)
		if outcome.queueErr != nil {
			return nil
		}
		if err := ctx.Err(); err != nil {
			outcome.canceled = err
			return nil
		}
		outcome.windowErr = exerciseTCPRepairWindow(fd, ops)
		if outcome.windowErr != nil {
			return nil
		}
		if err := ctx.Err(); err != nil {
			outcome.canceled = err
			return nil
		}
		outcome.optionsErr = exerciseTCPRepairOptions(fd, ops)
		return nil
	})
	outcome.cleanupErr = errors.Join(outcome.cleanupErr, controlErr)
	return outcome
}

func readTCPRepairQueues(fd int, ops tcpRepairProbeOps) (tcpRepairProbeSequences, error) {
	sequences := tcpRepairProbeSequences{}
	for _, queue := range []int{tcpRepairSendQueue, tcpRepairRecvQueue} {
		if err := ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, queue); err != nil {
			return tcpRepairProbeSequences{}, err
		}
		selected, err := ops.getInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE)
		if err != nil {
			return tcpRepairProbeSequences{}, err
		}
		if selected != queue {
			return tcpRepairProbeSequences{}, tcpRepairSemanticError{fmt.Errorf("TCP_REPAIR_QUEUE=%d want %d", selected, queue)}
		}
		sequence, err := ops.getInt(fd, unix.IPPROTO_TCP, unix.TCP_QUEUE_SEQ)
		if err != nil {
			return tcpRepairProbeSequences{}, err
		}
		if queue == tcpRepairSendQueue {
			sequences.send = uint32(sequence)
		} else {
			sequences.recv = uint32(sequence)
		}
	}
	if err := ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, tcpRepairNoQueue); err != nil {
		return tcpRepairProbeSequences{}, err
	}
	selected, err := ops.getInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE)
	if err != nil {
		return tcpRepairProbeSequences{}, err
	}
	if selected != tcpRepairNoQueue {
		return tcpRepairProbeSequences{}, tcpRepairSemanticError{fmt.Errorf("TCP_REPAIR_QUEUE reset=%d", selected)}
	}
	return sequences, nil
}

func verifyTCPRepairSequenceDelta(ctx context.Context, pair tcpRepairProbePair, ops tcpRepairProbeOps, before tcpRepairProbeSequences, sent, received uint32) (probeErr, canceled, cleanupErr error) {
	controlErr := pair.control(func(fd int) error {
		if err := ctx.Err(); err != nil {
			canceled = err
			return nil
		}
		if err := ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_ON); err != nil {
			probeErr = err
			return nil
		}
		defer func() {
			cleanupErr = errors.Join(
				ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, tcpRepairNoQueue),
				ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_OFF),
			)
			if cleanupErr == nil {
				state, err := ops.getInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR)
				if err != nil {
					cleanupErr = err
				} else if state != unix.TCP_REPAIR_OFF {
					cleanupErr = tcpRepairSemanticError{fmt.Errorf("TCP_REPAIR verification exit state=%d", state)}
				}
			}
		}()
		state, err := ops.getInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR)
		if err != nil {
			probeErr = err
			return nil
		}
		if state != unix.TCP_REPAIR_ON {
			probeErr = tcpRepairSemanticError{fmt.Errorf("TCP_REPAIR verification enter state=%d", state)}
			return nil
		}
		after, err := readTCPRepairQueues(fd, ops)
		if err != nil {
			probeErr = err
			return nil
		}
		if delta := after.send - before.send; delta != sent {
			probeErr = tcpRepairSemanticError{fmt.Errorf("TCP send sequence delta=%d want %d", delta, sent)}
			return nil
		}
		if delta := after.recv - before.recv; delta != received {
			probeErr = tcpRepairSemanticError{fmt.Errorf("TCP receive sequence delta=%d want %d", delta, received)}
		}
		return nil
	})
	cleanupErr = errors.Join(cleanupErr, controlErr)
	return probeErr, canceled, cleanupErr
}

func tcpRepairProbePayload(size int, seed byte) []byte {
	payload := make([]byte, size)
	for index := range payload {
		payload[index] = seed + byte(index*29)
	}
	return payload
}

func exerciseTCPRepairSequenceSetter(ctx context.Context, ops tcpRepairProbeOps) (probeErr, canceled, cleanupErr error) {
	if err := ctx.Err(); err != nil {
		return nil, err, nil
	}
	fd, err := ops.openScratch()
	if err != nil {
		return err, nil, nil
	}
	entered := false
	defer func() {
		if entered {
			cleanupErr = errors.Join(
				cleanupErr,
				ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, tcpRepairNoQueue),
				ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_OFF),
			)
			if cleanupErr == nil {
				state, err := ops.getInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR)
				if err != nil {
					cleanupErr = err
				} else if state != unix.TCP_REPAIR_OFF {
					cleanupErr = tcpRepairSemanticError{fmt.Errorf("TCP_REPAIR scratch exit state=%d", state)}
				}
			}
		}
		cleanupErr = errors.Join(cleanupErr, ops.closeFD(fd))
	}()
	if err := ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_ON); err != nil {
		return err, nil, nil
	}
	entered = true
	state, err := ops.getInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR)
	if err != nil {
		return err, nil, nil
	}
	if state != unix.TCP_REPAIR_ON {
		return tcpRepairSemanticError{fmt.Errorf("TCP_REPAIR scratch enter state=%d", state)}, nil, nil
	}
	for _, test := range []struct {
		queue int
		value uint32
	}{
		{queue: tcpRepairSendQueue, value: ^uint32(0) - 15},
		{queue: tcpRepairRecvQueue, value: 0x10203040},
	} {
		if err := ctx.Err(); err != nil {
			return nil, err, nil
		}
		if err := ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, test.queue); err != nil {
			return err, nil, nil
		}
		selected, err := ops.getInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE)
		if err != nil {
			return err, nil, nil
		}
		if selected != test.queue {
			return tcpRepairSemanticError{fmt.Errorf("TCP_REPAIR scratch queue=%d want %d", selected, test.queue)}, nil, nil
		}
		if err := ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_QUEUE_SEQ, int(test.value)); err != nil {
			return err, nil, nil
		}
		observed, err := ops.getInt(fd, unix.IPPROTO_TCP, unix.TCP_QUEUE_SEQ)
		if err != nil {
			return err, nil, nil
		}
		if uint32(observed) != test.value {
			return tcpRepairSemanticError{fmt.Errorf("TCP_QUEUE_SEQ=%#x want %#x", uint32(observed), test.value)}, nil, nil
		}
	}
	return nil, nil, nil
}

func exerciseTCPRepairWindow(fd int, ops tcpRepairProbeOps) (retErr error) {
	original, err := ops.getWindow(fd)
	if err != nil {
		return err
	}
	if err := ops.setWindow(fd, original); err != nil {
		return err
	}
	after, err := ops.getWindow(fd)
	if err != nil {
		return err
	}
	if after != original {
		return tcpRepairSemanticError{fmt.Errorf("TCP_REPAIR_WINDOW changed after same-value write")}
	}

	perturbed := original
	maxUint32 := ^uint32(0)
	switch {
	case perturbed.MaxWindow < maxUint32:
		perturbed.MaxWindow++
	case perturbed.MaxWindow > perturbed.SendWindow:
		perturbed.MaxWindow--
	case perturbed.ReceiveWindow < maxUint32:
		perturbed.ReceiveWindow++
	case perturbed.ReceiveWindow > 0:
		perturbed.ReceiveWindow--
	default:
		return tcpRepairSemanticError{fmt.Errorf("TCP_REPAIR_WINDOW has no safe reversible probe value")}
	}
	if err := ops.setWindow(fd, perturbed); err != nil {
		return err
	}
	restoreNeeded := true
	defer func() {
		if !restoreNeeded {
			return
		}
		restoreErr := ops.setWindow(fd, original)
		if restoreErr == nil {
			var restored tcpRepairProbeWindow
			restored, restoreErr = ops.getWindow(fd)
			if restoreErr == nil && restored != original {
				restoreErr = tcpRepairSemanticError{fmt.Errorf("TCP_REPAIR_WINDOW emergency restore mismatch")}
			}
		}
		retErr = errors.Join(retErr, restoreErr)
	}()
	observed, err := ops.getWindow(fd)
	if err != nil {
		return err
	}
	if observed != perturbed {
		return tcpRepairSemanticError{fmt.Errorf("TCP_REPAIR_WINDOW perturbation was not observable")}
	}
	if err := ops.setWindow(fd, original); err != nil {
		return err
	}
	restored, err := ops.getWindow(fd)
	if err != nil {
		return err
	}
	if restored != original {
		return tcpRepairSemanticError{fmt.Errorf("TCP_REPAIR_WINDOW restore mismatch")}
	}
	restoreNeeded = false
	return nil
}

func exerciseTCPRepairOptions(fd int, ops tcpRepairProbeOps) (retErr error) {
	info, err := ops.getInfo(fd)
	if err != nil {
		return err
	}
	if info.State != tcpRepairEstablished || info.SendMSS == 0 {
		return tcpRepairSemanticError{fmt.Errorf("TCP_INFO is not a usable established connection")}
	}
	if info.Options&tcpInfoWindowScale == 0 {
		return tcpRepairSemanticError{fmt.Errorf("TCP_REPAIR_OPTIONS has no observable negotiated window scale")}
	}
	probeInfo := info
	sendScale := info.WindowScale & 0x0f
	if sendScale < 14 {
		sendScale++
	} else {
		sendScale--
	}
	probeInfo.WindowScale = info.WindowScale&0xf0 | sendScale
	originalOptions := tcpRepairOptionsFromInfo(info, info.SendMSS)
	probeOptions := tcpRepairOptionsFromInfo(probeInfo, info.SendMSS)
	if err := ops.setOptions(fd, probeOptions); err != nil {
		return err
	}
	restoreNeeded := true
	defer func() {
		if restoreNeeded {
			retErr = errors.Join(retErr, ops.setOptions(fd, originalOptions))
		}
	}()
	perturbedInfo, err := ops.getInfo(fd)
	if err != nil {
		return err
	}
	if perturbedInfo.State != tcpRepairEstablished || perturbedInfo.SendMSS != info.SendMSS ||
		perturbedInfo.Options&(tcpInfoTimestamps|tcpInfoSACK|tcpInfoWindowScale) != info.Options&(tcpInfoTimestamps|tcpInfoSACK|tcpInfoWindowScale) ||
		perturbedInfo.WindowScale != probeInfo.WindowScale {
		return tcpRepairSemanticError{fmt.Errorf("TCP_REPAIR_OPTIONS perturbation was not observable and lossless")}
	}
	if err := ops.setOptions(fd, originalOptions); err != nil {
		return err
	}
	restoredInfo, err := ops.getInfo(fd)
	if err != nil {
		return err
	}
	if restoredInfo.State != tcpRepairEstablished || restoredInfo.SendMSS != info.SendMSS ||
		restoredInfo.Options&(tcpInfoTimestamps|tcpInfoSACK|tcpInfoWindowScale) != info.Options&(tcpInfoTimestamps|tcpInfoSACK|tcpInfoWindowScale) ||
		(info.Options&tcpInfoWindowScale != 0 && restoredInfo.WindowScale != info.WindowScale) {
		return tcpRepairSemanticError{fmt.Errorf("TCP_REPAIR_OPTIONS restore mismatch")}
	}
	restoreNeeded = false
	if info.Options&tcpInfoTimestamps != 0 {
		return exerciseTCPRepairTimestamp(fd, ops)
	}
	return nil
}

func tcpRepairOptionsFromInfo(info tcpRepairProbeInfo, mss uint32) []unix.TCPRepairOpt {
	options := []unix.TCPRepairOpt{{Code: unix.TCPOPT_MAXSEG, Val: mss}}
	if info.Options&tcpInfoWindowScale != 0 {
		sendScale := uint32(info.WindowScale & 0x0f)
		receiveScale := uint32((info.WindowScale >> 4) & 0x0f)
		options = append(options, unix.TCPRepairOpt{Code: unix.TCPOPT_WINDOW, Val: sendScale | receiveScale<<16})
	}
	if info.Options&tcpInfoSACK != 0 {
		options = append(options, unix.TCPRepairOpt{Code: unix.TCPOPT_SACK_PERMITTED})
	}
	if info.Options&tcpInfoTimestamps != 0 {
		options = append(options, unix.TCPRepairOpt{Code: unix.TCPOPT_TIMESTAMP})
	}
	return options
}

func exerciseTCPRepairTimestamp(fd int, ops tcpRepairProbeOps) (retErr error) {
	timestamp, err := ops.getInt(fd, unix.IPPROTO_TCP, unix.TCP_TIMESTAMP)
	if err != nil {
		return err
	}
	original := uint32(timestamp)
	probe := original + 0x40000000
	if err := ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_TIMESTAMP, int(probe)); err != nil {
		return err
	}
	restoreNeeded := true
	defer func() {
		if restoreNeeded {
			retErr = errors.Join(retErr, ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_TIMESTAMP, int(original)))
		}
	}()
	observed, err := ops.getInt(fd, unix.IPPROTO_TCP, unix.TCP_TIMESTAMP)
	if err != nil {
		return err
	}
	const maxOpaqueTimestampAdvance = uint32(5_000_000)
	if uint32(observed)-probe > maxOpaqueTimestampAdvance {
		return tcpRepairSemanticError{fmt.Errorf("TCP_TIMESTAMP perturbation was not observable")}
	}
	if err := ops.setInt(fd, unix.IPPROTO_TCP, unix.TCP_TIMESTAMP, int(original)); err != nil {
		return err
	}
	restored, err := ops.getInt(fd, unix.IPPROTO_TCP, unix.TCP_TIMESTAMP)
	if err != nil {
		return err
	}
	if uint32(restored)-original > maxOpaqueTimestampAdvance {
		return tcpRepairSemanticError{fmt.Errorf("TCP_TIMESTAMP restore exceeded wrap-aware advance")}
	}
	restoreNeeded = false
	return nil
}

type tcpRepairSemanticError struct{ error }

func tcpRepairOutcomeEvidence(at time.Time, outcome tcpRepairProbeOutcome) []FeatureEvidence {
	if outcome.enterErr != nil {
		return []FeatureEvidence{
			tcpRepairEvidenceForError(FeatureTCPRepairPermission, at, outcome.enterErr),
			tcpRepairEvidenceForError(FeatureTCPRepairBase, at, outcome.enterErr),
		}
	}
	observations := []FeatureEvidence{
		availableEvidence(FeatureTCPRepairPermission, at, SourceRuntimeSyscall),
	}
	if outcome.baseErr != nil {
		return append(observations, tcpRepairEvidenceForError(FeatureTCPRepairBase, at, outcome.baseErr))
	}
	observations = append(observations, availableEvidence(FeatureTCPRepairBase, at, SourceRuntimeRoundTrip))
	for _, stage := range []struct {
		id  FeatureID
		err error
	}{
		{id: FeatureTCPRepairQueueSeq, err: outcome.queueErr},
		{id: FeatureTCPRepairWindow, err: outcome.windowErr},
		{id: FeatureTCPRepairOptions, err: outcome.optionsErr},
	} {
		if stage.err != nil {
			return append(observations, tcpRepairEvidenceForError(stage.id, at, stage.err))
		}
		observations = append(observations, availableEvidence(stage.id, at, SourceRuntimeRoundTrip))
	}
	return observations
}

func tcpRepairEvidenceForError(id FeatureID, at time.Time, err error) FeatureEvidence {
	var semantic tcpRepairSemanticError
	if errors.As(err, &semantic) {
		return semanticFailureEvidence(id, at, err)
	}
	return classifiedOrFailed(id, at, err)
}

func tcpRepairInfrastructureFailure(at time.Time, err error) []FeatureEvidence {
	var errno syscall.Errno
	_ = errors.As(err, &errno)
	reason := ReasonSyscallFailed
	retryable := errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR)
	switch errno {
	case syscall.EMFILE, syscall.ENFILE, syscall.ENOMEM, syscall.ENOBUFS, syscall.ENOSPC:
		reason = ReasonResourceExhausted
		retryable = true
	}
	observations := make([]FeatureEvidence, 0, len(tcpRepairFeatureIDs))
	for _, id := range tcpRepairFeatureIDs {
		observations = append(observations, mustEvidence(id, FeatureProbeFailed, reason, at, SourceRuntimeSyscall, errno, retryable))
	}
	return observations
}

func tcpRepairCleanupFailure(at time.Time, err error) []FeatureEvidence {
	observations := make([]FeatureEvidence, 0, len(tcpRepairFeatureIDs))
	for _, id := range tcpRepairFeatureIDs {
		observations = append(observations, cleanupFailureEvidence(id, at, err))
	}
	return observations
}

func tcpRepairSemanticFailure(at time.Time, err error) []FeatureEvidence {
	observations := make([]FeatureEvidence, 0, len(tcpRepairFeatureIDs))
	for _, id := range tcpRepairFeatureIDs {
		observations = append(observations, semanticFailureEvidence(id, at, err))
	}
	return observations
}

func getTCPRepairProbeInfo(fd int) (tcpRepairProbeInfo, error) {
	var info tcpRepairProbeInfo
	size := uint32(unsafe.Sizeof(info))
	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(unix.IPPROTO_TCP),
		uintptr(unix.TCP_INFO),
		uintptr(unsafe.Pointer(&info)),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if errno != 0 {
		return tcpRepairProbeInfo{}, errno
	}
	if size != uint32(unsafe.Sizeof(info)) {
		return tcpRepairProbeInfo{}, tcpRepairSemanticError{fmt.Errorf("TCP_INFO size=%d want %d", size, unsafe.Sizeof(info))}
	}
	return info, nil
}

func getTCPRepairProbeWindow(fd int) (tcpRepairProbeWindow, error) {
	var window tcpRepairProbeWindow
	size := uint32(unsafe.Sizeof(window))
	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(unix.IPPROTO_TCP),
		uintptr(unix.TCP_REPAIR_WINDOW),
		uintptr(unsafe.Pointer(&window)),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if errno != 0 {
		return tcpRepairProbeWindow{}, errno
	}
	if size != uint32(unsafe.Sizeof(window)) {
		return tcpRepairProbeWindow{}, tcpRepairSemanticError{fmt.Errorf("TCP_REPAIR_WINDOW size=%d", size)}
	}
	return window, nil
}

func setTCPRepairProbeWindow(fd int, window tcpRepairProbeWindow) error {
	_, _, errno := unix.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(unix.IPPROTO_TCP),
		uintptr(unix.TCP_REPAIR_WINDOW),
		uintptr(unsafe.Pointer(&window)),
		unsafe.Sizeof(window),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}
