package l3session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/l3ingress"
)

const DefaultTCPPeerReadyTimeout = 10 * time.Second

// ErrTCPHalfCloseUnsupported means one relay endpoint cannot represent a
// directional FIN. Treating that condition as success would leave protocols
// which wait for request EOF blocked indefinitely.
var (
	ErrTCPHalfCloseUnsupported        = errors.New("l3session: TCP endpoint does not support CloseWrite")
	ErrTCPSourceReadFailed            = errors.New("l3session: TCP relay source read failed")
	ErrTCPDestinationWriteFailed      = errors.New("l3session: TCP relay destination write failed")
	ErrTCPDestinationCloseWriteFailed = errors.New("l3session: TCP relay destination CloseWrite failed")
)

// TCPPeerRejectReason identifies why the peer could not make its final TCP
// egress ready before the local userspace stack completed the handshake.
type TCPPeerRejectReason string

const (
	ReasonTCPPeerEgressUnavailable    TCPPeerRejectReason = "peer_egress_unavailable"
	ReasonTCPPeerEgressDialFailed     TCPPeerRejectReason = "peer_egress_dial_failed"
	ReasonTCPPeerHalfCloseUnsupported TCPPeerRejectReason = "peer_half_close_unsupported"
	ReasonTCPPeerInternalFailure      TCPPeerRejectReason = "peer_internal_failure"
)

// TCPPeerRejectError is returned before a local TCP handshake is accepted.
type TCPPeerRejectError struct {
	Reason TCPPeerRejectReason
}

func (e *TCPPeerRejectError) Error() string {
	return "l3session: TCP peer rejected flow readiness: " + string(e.Reason)
}

// TCPRelay bridges one accepted userspace TCP endpoint, such as a future
// gVisor TCP endpoint, to a per-flow rendr Conn session.
type TCPRelay struct {
	Manager *Manager

	BufferSize       int
	PeerReadyTimeout time.Duration

	owned Manager
}

// PreparedTCP is a peer-validated rendr stream whose final egress is already
// connected. It lets a TUN frontend defer its local SYN-ACK until the remote
// side is factual rather than accepting first and resetting on later failure.
type PreparedTCP struct {
	owner   *TCPRelay
	manager *Manager
	session *Session
	conn    l3ingress.TCPConn

	serveMu sync.Mutex
	served  bool
	close   sync.Once
	err     error
}

// Prepare creates the per-flow rendr session, sends the versioned identity
// envelope, and waits until the peer confirms that its TCP egress is connected.
func (r *TCPRelay) Prepare(ctx context.Context, ev l3ingress.PacketEvent) (*PreparedTCP, error) {
	if ctx == nil {
		return nil, errors.New("l3session: nil TCP relay context")
	}
	readyTimeout := r.PeerReadyTimeout
	if readyTimeout < 0 {
		return nil, errors.New("l3session: negative TCP peer readiness timeout")
	}
	if readyTimeout == 0 {
		readyTimeout = DefaultTCPPeerReadyTimeout
	}
	readyCtx, cancel := context.WithTimeout(ctx, readyTimeout)
	defer cancel()
	id := ev.Meta.Identity
	if id == (l3ingress.L3Identity{}) {
		id = ev.Flow.L3Identity
	}
	if id.Proto != l3ingress.ProtocolTCP {
		return nil, fmt.Errorf("l3session: TCP relay cannot handle %s", id.Proto)
	}
	manager := r.manager()
	sess, err := manager.EnsureSession(readyCtx, ev)
	if err != nil {
		return nil, err
	}
	if sess == nil || sess.Conn == nil {
		return nil, errors.New("l3session: TCP relay missing stream session")
	}
	if ev.Ref != (l3ingress.FlowRef{}) && sess.Request.Ref != ev.Ref {
		_ = manager.CloseSession(sess)
		return nil, fmt.Errorf("%w: prepared=%+v requested=%+v", ErrSessionGenerationConflict,
			sess.Request.Ref, ev.Ref)
	}
	stream, ok := sess.Conn.(l3ingress.TCPConn)
	if !ok {
		_ = manager.CloseSession(sess)
		return nil, fmt.Errorf("%w: rendr stream %T", ErrTCPHalfCloseUnsupported, sess.Conn)
	}
	prepared := &PreparedTCP{owner: r, manager: manager, session: sess, conn: stream}
	header, err := encodeTCPEnvelope(id, sess.Request.Egress)
	if err != nil {
		_ = prepared.Close()
		return nil, err
	}
	if err := writeAllContext(readyCtx, stream, header); err != nil {
		_ = prepared.Close()
		return nil, err
	}
	status, err := readTCPReadyContext(readyCtx, stream)
	if err != nil {
		_ = prepared.Close()
		return nil, err
	}
	if err := tcpReadyError(status); err != nil {
		_ = prepared.Close()
		return nil, err
	}
	return prepared, nil
}

// FlowRef returns the exact flow activation represented by p.
func (p *PreparedTCP) FlowRef() l3ingress.FlowRef {
	if p == nil || p.session == nil {
		return l3ingress.FlowRef{}
	}
	return p.session.Request.Ref
}

// Close releases a prepared stream that was rejected locally or has finished
// relaying. It removes only the exact Session object, never a tuple-reusing
// replacement generation.
func (p *PreparedTCP) Close() error {
	if p == nil {
		return nil
	}
	p.close.Do(func() { p.err = p.manager.CloseSession(p.session) })
	return p.err
}

// Serve starts or reuses the rendr stream session for ev and relays bytes
// between endpoint and the rendr Conn until either side closes or ctx is done.
func (r *TCPRelay) Serve(ctx context.Context, ev l3ingress.PacketEvent, endpoint net.Conn) error {
	if endpoint == nil {
		return errors.New("l3session: nil TCP relay endpoint")
	}
	prepared, err := r.Prepare(ctx, ev)
	if err != nil {
		_ = endpoint.Close()
		return err
	}
	return r.ServePrepared(ctx, prepared, endpoint)
}

// ServePrepared joins a peer-ready stream to the accepted userspace TCP
// endpoint. Each PreparedTCP can be consumed at most once.
func (r *TCPRelay) ServePrepared(ctx context.Context, prepared *PreparedTCP, endpoint net.Conn) error {
	if ctx == nil {
		return errors.New("l3session: nil TCP relay context")
	}
	if prepared == nil || prepared.owner != r || prepared.conn == nil {
		return errors.New("l3session: invalid prepared TCP stream")
	}
	if endpoint == nil {
		_ = prepared.Close()
		return errors.New("l3session: nil TCP relay endpoint")
	}
	if _, ok := endpoint.(l3ingress.TCPConn); !ok {
		_ = endpoint.Close()
		_ = prepared.Close()
		return fmt.Errorf("%w: local endpoint %T", ErrTCPHalfCloseUnsupported, endpoint)
	}
	prepared.serveMu.Lock()
	if prepared.served {
		prepared.serveMu.Unlock()
		_ = endpoint.Close()
		return errors.New("l3session: prepared TCP stream already consumed")
	}
	prepared.served = true
	prepared.serveMu.Unlock()
	defer endpoint.Close()
	defer prepared.Close()
	return relayTCP(ctx, endpoint, prepared.conn, r.BufferSize)
}

// ObserveFlow implements l3ingress.FlowObserver.
func (r *TCPRelay) ObserveFlow(snapshot l3ingress.FlowSnapshot) {
	r.manager().ObserveFlow(snapshot)
}

// CloseFlow closes one active TCP stream session.
func (r *TCPRelay) CloseFlow(id l3ingress.L3Identity) bool {
	manager := r.manager()
	if _, ok := manager.Session(id); !ok {
		return false
	}
	return manager.Close(id) == nil
}

// Close closes all active TCP stream sessions.
func (r *TCPRelay) Close() error {
	return r.manager().CloseAll()
}

func (r *TCPRelay) manager() *Manager {
	if r.Manager != nil {
		return r.Manager
	}
	return &r.owned
}

func writeAll(dst io.Writer, payload []byte) error {
	for len(payload) != 0 {
		n, err := dst.Write(payload)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(payload) {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

func writeAllContext(ctx context.Context, conn net.Conn, payload []byte) error {
	done := make(chan error, 1)
	go func() { done <- writeAll(conn, payload) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		interruptTCP(conn)
		<-done
		return ctx.Err()
	}
}

func readTCPReadyContext(ctx context.Context, conn net.Conn) (tcpReadyStatus, error) {
	type result struct {
		status tcpReadyStatus
		err    error
	}
	done := make(chan result, 1)
	go func() {
		status, err := readTCPReady(conn)
		done <- result{status: status, err: err}
	}()
	select {
	case got := <-done:
		return got.status, got.err
	case <-ctx.Done():
		interruptTCP(conn)
		<-done
		return tcpReadyInvalid, ctx.Err()
	}
}

func tcpReadyError(status tcpReadyStatus) error {
	var reason TCPPeerRejectReason
	switch status {
	case tcpReadyOK:
		return nil
	case tcpReadyEgressUnavailable:
		reason = ReasonTCPPeerEgressUnavailable
	case tcpReadyEgressDialFailed:
		reason = ReasonTCPPeerEgressDialFailed
	case tcpReadyHalfCloseUnsupported:
		reason = ReasonTCPPeerHalfCloseUnsupported
	default:
		reason = ReasonTCPPeerInternalFailure
	}
	return &TCPPeerRejectError{Reason: reason}
}

func relayTCP(ctx context.Context, left, right net.Conn, bufferSize int) error {
	if ctx == nil {
		return errors.New("l3session: nil TCP relay context")
	}
	type result struct{ err error }
	results := make(chan result, 2)
	forward := func(direction string, dst, src net.Conn) {
		err := copyTCPDirection(direction, dst, src, bufferSize)
		if err == nil {
			if closeErr := closeWrite(dst); closeErr != nil {
				err = newTCPRelayFailure(ErrTCPDestinationCloseWriteFailed, direction, closeErr)
			}
		}
		results <- result{err: err}
	}
	go forward("left_to_right", right, left)
	go forward("right_to_left", left, right)

	var first result
	select {
	case first = <-results:
	case <-ctx.Done():
		interruptTCP(left, right)
		<-results
		<-results
		return ctx.Err()
	}
	if first.err != nil {
		interruptTCP(left, right)
		second := <-results
		return errors.Join(first.err, second.err)
	}

	select {
	case second := <-results:
		if second.err != nil {
			interruptTCP(left, right)
		}
		return second.err
	case <-ctx.Done():
		interruptTCP(left, right)
		<-results
		return ctx.Err()
	}
}

func copyTCPDirection(direction string, dst net.Conn, src net.Conn, bufferSize int) error {
	if bufferSize <= 0 {
		bufferSize = 32 << 10
	}
	buf := make([]byte, bufferSize)
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			if err := writeAll(dst, buf[:n]); err != nil {
				return newTCPRelayFailure(ErrTCPDestinationWriteFailed, direction, err)
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return newTCPRelayFailure(ErrTCPSourceReadFailed, direction, readErr)
		}
		if n == 0 {
			return newTCPRelayFailure(ErrTCPSourceReadFailed, direction, io.ErrNoProgress)
		}
	}
}

type tcpRelayFailure struct {
	kind      error
	direction string
	cause     error
}

func newTCPRelayFailure(kind error, direction string, cause error) error {
	return &tcpRelayFailure{kind: kind, direction: direction, cause: cause}
}

func (e *tcpRelayFailure) Error() string {
	return fmt.Sprintf("%v (%s): %v", e.kind, e.direction, e.cause)
}

func (e *tcpRelayFailure) Unwrap() []error {
	return []error{e.kind, e.cause}
}

func interruptTCP(conns ...net.Conn) {
	now := time.Now()
	for _, conn := range conns {
		if conn != nil {
			_ = conn.SetDeadline(now)
			_ = conn.Close()
		}
	}
}

func closeWrite(conn net.Conn) error {
	if half, ok := conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return fmt.Errorf("%w: %T", ErrTCPHalfCloseUnsupported, conn)
}
