package udprelay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/FrankoonG/rendr"
)

const defaultBufferSize = 64 << 10

// Config describes one UDP relay endpoint.
//
// PacketConn is the rendr packet-mode connection used as the migrated
// carrier. It is required for now; callers can create one with
// Runtime.DialPacket or SessionListener.AcceptPacket.
//
// LocalAddr is the UDP address exposed to the application or used as
// the source socket for target traffic. Empty means "127.0.0.1:0".
//
// BufferSize is the largest datagram the relay accepts. A larger datagram
// terminates the relay without forwarding its truncated prefix. Zero selects
// the 64 KiB default; values above 64 KiB are rejected.
//
// TargetAddr selects server-side mode: packets received from rendr
// are written to this UDP target, and replies from the target are
// forwarded back over rendr. When empty, client-side mode learns the
// most recent UDP sender and writes rendr replies back to it.
type Config struct {
	PacketConn rendr.PacketConn
	LocalAddr  string
	TargetAddr string
	BufferSize int
}

// DialConfig creates a client-side relay and dials the rendr
// packet-mode carrier for it.
type DialConfig struct {
	Runtime    *rendr.Runtime
	Session    rendr.SessionConfig
	LocalAddr  string
	BufferSize int
}

// PacketAcceptor is the inbound packet-session capability used by the relay.
// A rendr SessionListener satisfies it without exposing listener internals.
type PacketAcceptor interface {
	AcceptPacket(context.Context) (rendr.PacketConn, error)
	Close() error
}

// ServeConfig creates a server-side relay from an accepted rendr
// packet-mode carrier.
type ServeConfig struct {
	Listener   PacketAcceptor
	LocalAddr  string
	TargetAddr string
	BufferSize int
}

// Server accepts rendr packet-mode connections and starts one
// server-side Relay for each accepted client.
type Server struct {
	listener   PacketAcceptor
	localAddr  string
	targetAddr string
	bufferSize int

	closeOnce sync.Once
	closeErr  error
	done      chan struct{}

	relaysMu sync.Mutex
	relays   map[*Relay]struct{}
}

// Relay bridges one local UDP socket to one rendr PacketConn.
type Relay struct {
	pc     rendr.PacketConn
	udp    net.PacketConn
	target net.Addr

	stateMu     sync.Mutex
	stopping    bool
	terminalErr error
	closeErr    error
	done        chan struct{}

	peerMu sync.RWMutex
	peer   net.Addr
}

// Dial dials a rendr PacketConn and starts a client-side local UDP
// relay for a self-managed UDP application.
func Dial(ctx context.Context, cfg DialConfig) (*Relay, error) {
	if cfg.Runtime == nil {
		return nil, errors.New("udprelay: Runtime is required")
	}
	bufferSize, err := normalizeBufferSize(cfg.BufferSize)
	if err != nil {
		return nil, err
	}
	pc, err := cfg.Runtime.DialPacket(ctx, cfg.Session)
	if err != nil {
		return nil, fmt.Errorf("udprelay: dial packet carrier: %w", err)
	}
	r, err := Start(ctx, Config{
		PacketConn: pc,
		LocalAddr:  cfg.LocalAddr,
		BufferSize: bufferSize,
	})
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	return r, nil
}

// Serve accepts one rendr PacketConn and starts a server-side UDP
// relay to TargetAddr. Call Serve once per accepted remote relay.
func Serve(ctx context.Context, cfg ServeConfig) (*Relay, error) {
	if cfg.Listener == nil {
		return nil, errors.New("udprelay: Listener is required")
	}
	if cfg.TargetAddr == "" {
		return nil, errors.New("udprelay: TargetAddr is required")
	}
	bufferSize, err := normalizeBufferSize(cfg.BufferSize)
	if err != nil {
		return nil, err
	}
	pc, err := cfg.Listener.AcceptPacket(ctx)
	if err != nil {
		return nil, fmt.Errorf("udprelay: accept packet carrier: %w", err)
	}
	r, err := Start(ctx, Config{
		PacketConn: pc,
		LocalAddr:  cfg.LocalAddr,
		TargetAddr: cfg.TargetAddr,
		BufferSize: bufferSize,
	})
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	return r, nil
}

// Listen starts a multi-client UDP relay server. The server accepts
// packet-mode rendr connections until ctx is cancelled or Close is
// called.
func Listen(ctx context.Context, cfg ServeConfig) (*Server, error) {
	if cfg.Listener == nil {
		return nil, errors.New("udprelay: Listener is required")
	}
	if cfg.TargetAddr == "" {
		return nil, errors.New("udprelay: TargetAddr is required")
	}
	bufferSize, err := normalizeBufferSize(cfg.BufferSize)
	if err != nil {
		return nil, err
	}
	s := &Server{
		listener:   cfg.Listener,
		localAddr:  cfg.LocalAddr,
		targetAddr: cfg.TargetAddr,
		bufferSize: bufferSize,
		done:       make(chan struct{}),
		relays:     make(map[*Relay]struct{}),
	}
	go s.acceptLoop(ctx)
	return s, nil
}

// Close stops accepting new clients and closes all active relays.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		s.closeErr = s.listener.Close()

		s.relaysMu.Lock()
		relays := make([]*Relay, 0, len(s.relays))
		for r := range s.relays {
			relays = append(relays, r)
		}
		s.relays = nil
		s.relaysMu.Unlock()

		for _, r := range relays {
			s.closeErr = errors.Join(s.closeErr, r.Close())
		}
	})
	return s.closeErr
}

// Relays returns the current active relay count.
func (s *Server) Relays() int {
	s.relaysMu.Lock()
	defer s.relaysMu.Unlock()
	return len(s.relays)
}

func (s *Server) acceptLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			_ = s.Close()
			return
		case <-s.done:
			return
		default:
		}

		pc, err := s.listener.AcceptPacket(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
				_ = s.Close()
			case <-s.done:
			default:
				_ = s.Close()
			}
			return
		}
		r, err := Start(ctx, Config{
			PacketConn: pc,
			LocalAddr:  s.localAddr,
			TargetAddr: s.targetAddr,
			BufferSize: s.bufferSize,
		})
		if err != nil {
			_ = pc.Close()
			continue
		}
		s.addRelay(r)
	}
}

func (s *Server) addRelay(r *Relay) {
	s.relaysMu.Lock()
	if s.relays == nil {
		s.relaysMu.Unlock()
		_ = r.Close()
		return
	}
	s.relays[r] = struct{}{}
	s.relaysMu.Unlock()

	go func() {
		<-r.Done()
		s.relaysMu.Lock()
		if s.relays != nil {
			delete(s.relays, r)
		}
		s.relaysMu.Unlock()
	}()
}

// Start creates and starts a UDP relay endpoint.
func Start(ctx context.Context, cfg Config) (*Relay, error) {
	if cfg.PacketConn == nil {
		return nil, errors.New("udprelay: PacketConn is required")
	}
	bufferSize, err := normalizeBufferSize(cfg.BufferSize)
	if err != nil {
		return nil, err
	}
	local := cfg.LocalAddr
	if local == "" {
		local = "127.0.0.1:0"
	}
	udp, err := net.ListenPacket("udp", local)
	if err != nil {
		return nil, fmt.Errorf("udprelay: listen udp %s: %w", local, err)
	}

	var target net.Addr
	if cfg.TargetAddr != "" {
		target, err = net.ResolveUDPAddr("udp", cfg.TargetAddr)
		if err != nil {
			_ = udp.Close()
			return nil, fmt.Errorf("udprelay: resolve target %s: %w", cfg.TargetAddr, err)
		}
	}
	return startRelay(ctx, cfg.PacketConn, udp, target, bufferSize), nil
}

func normalizeBufferSize(size int) (int, error) {
	if size <= 0 {
		return defaultBufferSize, nil
	}
	if size > defaultBufferSize {
		return 0, fmt.Errorf("udprelay: BufferSize %d exceeds maximum %d", size, defaultBufferSize)
	}
	return size, nil
}

func startRelay(ctx context.Context, pc rendr.PacketConn, udp net.PacketConn, target net.Addr, bufferSize int) *Relay {
	if ctx == nil {
		ctx = context.Background()
	}
	r := &Relay{
		pc:     pc,
		udp:    udp,
		target: target,
		done:   make(chan struct{}),
	}
	go r.closeOnContext(ctx)
	go r.udpToRendr(bufferSize)
	go r.rendrToUDP(bufferSize)
	return r
}

// LocalAddr returns the UDP socket address applications should use.
func (r *Relay) LocalAddr() net.Addr { return r.udp.LocalAddr() }

// PacketConn returns the underlying rendr carrier. Callers may
// type-assert it to rendr.PathController or rendr.MigrationController.
func (r *Relay) PacketConn() rendr.PacketConn { return r.pc }

// Done is closed when the relay is stopped.
func (r *Relay) Done() <-chan struct{} { return r.done }

// Err returns the first forwarding failure that stopped the relay. It returns
// nil while the relay is healthy and after an explicit or context-driven Close.
// Callers that need a terminal result should wait for Done before calling Err.
func (r *Relay) Err() error {
	r.stateMu.Lock()
	defer r.stateMu.Unlock()
	return r.terminalErr
}

// Close stops the relay and closes both the UDP socket and rendr
// PacketConn. A concurrent shutdown already in progress is left to its owner;
// callers can wait for Done when they need to observe its completion.
func (r *Relay) Close() error {
	return r.stop(nil)
}

func (r *Relay) closeOnContext(ctx context.Context) {
	select {
	case <-ctx.Done():
		_ = r.stop(nil)
	case <-r.done:
	}
}

func (r *Relay) udpToRendr(bufSize int) {
	buf := make([]byte, bufSize+1)
	for {
		n, addr, err := r.udp.ReadFrom(buf)
		if err = datagramReadError(n, len(buf), bufSize, err); err != nil {
			r.fail("UDP to rendr", "read UDP", err)
			return
		}
		if r.target == nil {
			if addr == nil {
				r.fail("UDP to rendr", "read UDP", errors.New("missing source address"))
				return
			}
			r.peerMu.Lock()
			r.peer = addr
			r.peerMu.Unlock()
		}
		written, err := r.pc.WriteTo(buf[:n], nil)
		if err != nil {
			r.fail("UDP to rendr", "write carrier", err)
			return
		}
		if written != n {
			r.fail("UDP to rendr", "write carrier", shortWriteError(written, n))
			return
		}
	}
}

func (r *Relay) rendrToUDP(bufSize int) {
	buf := make([]byte, bufSize+1)
	for {
		n, _, err := r.pc.ReadFrom(buf)
		if err = datagramReadError(n, len(buf), bufSize, err); err != nil {
			r.fail("rendr to UDP", "read carrier", err)
			return
		}
		dst := r.target
		if dst == nil {
			r.peerMu.RLock()
			dst = r.peer
			r.peerMu.RUnlock()
		}
		if dst == nil {
			continue
		}
		written, err := r.udp.WriteTo(buf[:n], dst)
		if err != nil {
			r.fail("rendr to UDP", "write UDP", err)
			return
		}
		if written != n {
			r.fail("rendr to UDP", "write UDP", shortWriteError(written, n))
			return
		}
	}
}

func (r *Relay) fail(direction, operation string, cause error) {
	_ = r.stop(fmt.Errorf("udprelay: %s %s: %w", direction, operation, cause))
}

func (r *Relay) stop(cause error) error {
	r.stateMu.Lock()
	if r.stopping {
		r.stateMu.Unlock()
		<-r.done
		r.stateMu.Lock()
		err := r.closeErr
		r.stateMu.Unlock()
		return err
	}
	r.stopping = true
	r.terminalErr = cause
	r.stateMu.Unlock()

	udpErr := r.udp.Close()
	carrierErr := r.pc.Close()
	closeErr := errors.Join(udpErr, carrierErr)

	r.stateMu.Lock()
	r.closeErr = closeErr
	close(r.done)
	r.stateMu.Unlock()
	return closeErr
}

func datagramReadError(n, bufferLen, limit int, err error) error {
	if n < 0 || n > bufferLen {
		return fmt.Errorf("invalid datagram read count %d for buffer length %d", n, bufferLen)
	}
	if n > limit || errors.Is(err, io.ErrShortBuffer) {
		if err != nil && !errors.Is(err, io.ErrShortBuffer) {
			return errors.Join(io.ErrShortBuffer, err)
		}
		return io.ErrShortBuffer
	}
	return err
}

func shortWriteError(written, want int) error {
	return fmt.Errorf("%w: wrote %d of %d bytes", io.ErrShortWrite, written, want)
}
