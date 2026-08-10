// Package udpsocket owns rendr-created UDP sockets and their optional send
// acceleration. Platform evidence selects a treatment before the socket is
// opened; callers cannot force an offload through the public rendr API.
package udpsocket

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/internal/platform"
	"github.com/FrankoonG/rendr/transport"
)

const (
	DefaultBufferBytes = 8 * 1024 * 1024
	MaxGSOSegments     = 64
	MaxGSOSuperPacket  = 65535
)

var ErrAmbiguousWrite = errors.New("udpsocket: ambiguous datagram write")

const (
	causeProbeConfirmed      = "probe_confirmed"
	causeProbeFailed         = "probe_failed"
	causePlatformUnsupported = "platform_unsupported"
	causeRuntimeUnsupported  = "runtime_unsupported"
	causePathUnsupported     = "path_unsupported"
)

type treatment uint32

const (
	treatmentOrdinary treatment = iota
	treatmentGSO
)

type Config struct {
	Network     string
	LocalAddr   *net.UDPAddr
	RemoteAddr  *net.UDPAddr
	BufferBytes int
}

type policy struct {
	treatment       treatment
	cause           string
	probeGeneration uint64
	probedAt        time.Time
}

type writeMsgFunc func(payload, oob []byte, addr *net.UDPAddr) (int, int, error)

// Socket is an owned UDP endpoint. PacketConn returns the view intended for
// protocol stacks such as quic-go; direct Read/Write methods are provided for
// connected datagram adapters.
type Socket struct {
	conn  *net.UDPConn
	view  net.PacketConn
	send  sync.Mutex
	state sync.RWMutex

	mode            atomic.Uint32
	cause           atomic.Value
	probeGeneration uint64
	probedAt        time.Time
	writeMsg        writeMsgFunc
	invalidateGSO   func() error

	gsoAttempts         atomic.Uint64
	gsoSuperPackets     atomic.Uint64
	gsoSegments         atomic.Uint64
	ordinaryDatagrams   atomic.Uint64
	fallbackTransitions atomic.Uint64
}

var (
	_ net.Conn       = (*Socket)(nil)
	_ net.PacketConn = (*Socket)(nil)
)

// Dial obtains factual GSO evidence before opening a connected UDP socket.
func Dial(ctx context.Context, config Config) (*Socket, error) {
	if ctx == nil {
		return nil, errors.New("udpsocket: nil context")
	}
	if config.RemoteAddr == nil {
		return nil, errors.New("udpsocket: Dial requires a remote address")
	}
	config = normalizeConfig(config)
	if err := validateNetwork(config.Network); err != nil {
		return nil, err
	}
	selected, err := detectPolicy(ctx)
	if err != nil {
		return nil, err
	}
	remote := cloneUDPAddr(config.RemoteAddr)
	dialer := net.Dialer{LocalAddr: cloneUDPAddr(config.LocalAddr)}
	conn, err := dialer.DialContext(ctx, config.Network, remote.String())
	if err != nil {
		return nil, err
	}
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("udpsocket: %s dial returned %T", config.Network, conn)
	}
	return newSocket(udpConn, selected, config.BufferBytes), nil
}

// Listen obtains factual GSO evidence before opening an unconnected UDP
// socket. RemoteAddr is rejected so a listener cannot silently become a dial.
func Listen(ctx context.Context, config Config) (*Socket, error) {
	if ctx == nil {
		return nil, errors.New("udpsocket: nil context")
	}
	if config.RemoteAddr != nil {
		return nil, errors.New("udpsocket: Listen does not accept a remote address")
	}
	config = normalizeConfig(config)
	if err := validateNetwork(config.Network); err != nil {
		return nil, err
	}
	selected, err := detectPolicy(ctx)
	if err != nil {
		return nil, err
	}
	local := cloneUDPAddr(config.LocalAddr)
	if local == nil {
		local = &net.UDPAddr{}
	}
	listenConfig := net.ListenConfig{}
	packetConn, err := listenConfig.ListenPacket(ctx, config.Network, local.String())
	if err != nil {
		return nil, err
	}
	udpConn, ok := packetConn.(*net.UDPConn)
	if !ok {
		_ = packetConn.Close()
		return nil, fmt.Errorf("udpsocket: %s listen returned %T", config.Network, packetConn)
	}
	return newSocket(udpConn, selected, config.BufferBytes), nil
}

func normalizeConfig(config Config) Config {
	if config.Network == "" {
		config.Network = "udp"
	}
	if config.BufferBytes <= 0 {
		config.BufferBytes = DefaultBufferBytes
	}
	return config
}

func validateNetwork(network string) error {
	switch network {
	case "udp", "udp4", "udp6":
		return nil
	default:
		return fmt.Errorf("udpsocket: unsupported network %q", network)
	}
}

func cloneUDPAddr(address *net.UDPAddr) *net.UDPAddr {
	if address == nil {
		return nil
	}
	clone := *address
	clone.IP = append(net.IP(nil), address.IP...)
	return &clone
}

func detectPolicy(ctx context.Context) (policy, error) {
	return detectPolicyWith(ctx, platform.Detect, platformGSOAllowed())
}

func detectPolicyWith(
	ctx context.Context,
	detect func(context.Context) (platform.KernelFeatures, error),
	allowGSO bool,
) (policy, error) {
	if err := ctx.Err(); err != nil {
		return policy{}, err
	}
	snapshot, err := detect(ctx)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return policy{}, ctxErr
	}
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return policy{}, err
		}
		return policy{treatment: treatmentOrdinary, cause: causeProbeFailed}, nil
	}
	evidence, ok := snapshot.Feature(platform.FeatureUDPGSO)
	if !allowGSO {
		return policy{
			treatment: treatmentOrdinary, cause: causePlatformUnsupported,
			probeGeneration: snapshot.Generation, probedAt: snapshot.ProbedAt,
		}, nil
	}
	if allowGSO && ok && evidence.State == platform.FeatureAvailable {
		return policy{
			treatment: treatmentGSO, cause: causeProbeConfirmed,
			probeGeneration: snapshot.Generation, probedAt: evidence.ProbedAt,
		}, nil
	}
	cause := causeProbeFailed
	if ok {
		cause = string(evidence.State)
		if evidence.Reason != "" {
			cause += "_" + string(evidence.Reason)
		}
	}
	return policy{
		treatment: treatmentOrdinary, cause: cause,
		probeGeneration: snapshot.Generation, probedAt: snapshot.ProbedAt,
	}, nil
}

func newSocket(conn *net.UDPConn, selected policy, bufferBytes int) *Socket {
	socket := &Socket{
		conn: conn, probeGeneration: selected.probeGeneration,
		probedAt: selected.probedAt, writeMsg: conn.WriteMsgUDP,
		invalidateGSO: func() error { return platform.Invalidate(platform.FeatureUDPGSO) },
	}
	socket.mode.Store(uint32(selected.treatment))
	socket.cause.Store(selected.cause)
	if bufferBytes > 0 {
		_ = conn.SetReadBuffer(bufferBytes)
		_ = conn.SetWriteBuffer(bufferBytes)
	}
	socket.view = newPacketConnView(socket)
	return socket
}

func (s *Socket) PacketConn() net.PacketConn {
	if s == nil {
		return nil
	}
	return s.view
}

func (s *Socket) Read(payload []byte) (int, error) { return s.conn.Read(payload) }

func (s *Socket) Write(payload []byte) (int, error) {
	n, err := s.conn.Write(payload)
	if err == nil && n == len(payload) {
		s.ordinaryDatagrams.Add(1)
	} else if err == nil {
		err = io.ErrShortWrite
	}
	return n, err
}

func (s *Socket) ReadFrom(payload []byte) (int, net.Addr, error) {
	return s.conn.ReadFrom(payload)
}

func (s *Socket) WriteTo(payload []byte, address net.Addr) (int, error) {
	n, err := s.conn.WriteTo(payload, address)
	if err == nil && n == len(payload) {
		s.ordinaryDatagrams.Add(1)
	} else if err == nil {
		err = io.ErrShortWrite
	}
	return n, err
}

func (s *Socket) Close() error                       { return s.conn.Close() }
func (s *Socket) LocalAddr() net.Addr                { return s.conn.LocalAddr() }
func (s *Socket) RemoteAddr() net.Addr               { return s.conn.RemoteAddr() }
func (s *Socket) SetDeadline(t time.Time) error      { return s.conn.SetDeadline(t) }
func (s *Socket) SetReadDeadline(t time.Time) error  { return s.conn.SetReadDeadline(t) }
func (s *Socket) SetWriteDeadline(t time.Time) error { return s.conn.SetWriteDeadline(t) }
func (s *Socket) SetReadBuffer(bytes int) error      { return s.conn.SetReadBuffer(bytes) }
func (s *Socket) SetWriteBuffer(bytes int) error     { return s.conn.SetWriteBuffer(bytes) }

// WriteBatch writes two or more datagrams to one destination. It returns the
// number of complete datagrams sent. A capability contradiction before any
// bytes were accepted safely transitions this socket to ordinary writes and
// completes the same batch without surfacing an optional-offload failure.
func (s *Socket) WriteBatch(datagrams [][]byte, address *net.UDPAddr) (int, error) {
	segmentSize, payload, err := validateBatch(datagrams)
	if err != nil {
		return 0, err
	}
	if err := s.validateDestination(address); err != nil {
		return 0, err
	}
	return s.writeBatchPlatform(datagrams, payload, segmentSize, address)
}

func validateBatch(datagrams [][]byte) (int, []byte, error) {
	if len(datagrams) < 2 || len(datagrams) > MaxGSOSegments {
		return 0, nil, fmt.Errorf("udpsocket: batch has %d datagrams outside [2,%d]", len(datagrams), MaxGSOSegments)
	}
	segmentSize := len(datagrams[0])
	if segmentSize == 0 || segmentSize > MaxGSOSuperPacket {
		return 0, nil, fmt.Errorf("udpsocket: invalid segment size %d", segmentSize)
	}
	total := 0
	for index, datagram := range datagrams {
		if len(datagram) == 0 || len(datagram) > segmentSize || (index < len(datagrams)-1 && len(datagram) != segmentSize) {
			return 0, nil, fmt.Errorf("udpsocket: datagram %d size %d does not match segment size %d", index, len(datagram), segmentSize)
		}
		total += len(datagram)
		if total > MaxGSOSuperPacket {
			return 0, nil, fmt.Errorf("udpsocket: super-packet size %d exceeds %d", total, MaxGSOSuperPacket)
		}
	}
	payload := make([]byte, 0, total)
	for _, datagram := range datagrams {
		payload = append(payload, datagram...)
	}
	return segmentSize, payload, nil
}

func (s *Socket) validateDestination(address *net.UDPAddr) error {
	connected := s.conn.RemoteAddr() != nil
	if connected && address != nil {
		return errors.New("udpsocket: connected socket batch requires a nil destination")
	}
	if !connected && address == nil {
		return errors.New("udpsocket: unconnected socket batch requires a destination")
	}
	return nil
}

func (s *Socket) transitionToFallback(cause string, invalidate bool) {
	s.state.Lock()
	if !s.mode.CompareAndSwap(uint32(treatmentGSO), uint32(treatmentOrdinary)) {
		s.state.Unlock()
		return
	}
	s.cause.Store(cause)
	s.fallbackTransitions.Add(1)
	s.state.Unlock()
	if invalidate && s.invalidateGSO != nil {
		_ = s.invalidateGSO()
	}
}

func (s *Socket) currentTreatment() treatment {
	return treatment(s.mode.Load())
}

func (s *Socket) DatagramAccelerationStatus() transport.DatagramAccelerationStatus {
	if s == nil {
		return transport.DatagramAccelerationStatus{}
	}
	s.state.RLock()
	defer s.state.RUnlock()
	mode := transport.DatagramAccelerationOrdinary
	if s.currentTreatment() == treatmentGSO {
		mode = transport.DatagramAccelerationGSO
	}
	cause, _ := s.cause.Load().(string)
	return transport.DatagramAccelerationStatus{
		Mode: mode, Cause: cause, ProbeGeneration: s.probeGeneration, ProbedAt: s.probedAt,
		GSOAttempts: s.gsoAttempts.Load(), GSOSuperPackets: s.gsoSuperPackets.Load(),
		GSOSegments: s.gsoSegments.Load(), OrdinaryDatagrams: s.ordinaryDatagrams.Load(),
		FallbackTransitions: s.fallbackTransitions.Load(),
	}
}

// Status returns the selected treatment and actual send evidence without
// exposing an errno, descriptor, or execution-context identity.
func (s *Socket) Status() transport.DatagramAccelerationStatus {
	return s.DatagramAccelerationStatus()
}

func writeOrdinaryDatagrams(
	write writeMsgFunc,
	datagrams [][]byte,
	oob []byte,
	address *net.UDPAddr,
	onSuccess func(),
) (int, error) {
	for index, datagram := range datagrams {
		n, oobN, err := write(datagram, oob, address)
		if err != nil {
			if n != 0 || oobN != 0 || index != 0 {
				return index, ambiguousWriteError("ordinary batch", n, len(datagram), err)
			}
			return index, err
		}
		if n != len(datagram) || oobN != len(oob) {
			if n != 0 || oobN != 0 || index != 0 {
				return index, ambiguousWriteError("ordinary batch", n, len(datagram), nil)
			}
			return index, io.ErrShortWrite
		}
		onSuccess()
	}
	return len(datagrams), nil
}

func ambiguousWriteError(operation string, written, wanted int, cause error) error {
	if cause == nil {
		return fmt.Errorf("%w: %s wrote %d of %d bytes", ErrAmbiguousWrite, operation, written, wanted)
	}
	// Deliberately don't unwrap cause. In particular, exposing a nested
	// *os.SyscallError(EIO) would make quic-go replay an indeterminate batch.
	return fmt.Errorf("%w: %s wrote %d of %d bytes (%v)", ErrAmbiguousWrite, operation, written, wanted, cause)
}
