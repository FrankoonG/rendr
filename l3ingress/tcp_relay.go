package l3ingress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// TCPFlowRelay bridges one accepted userspace TCP endpoint to an
// embedding-provided peer egress hook.
type TCPFlowRelay struct {
	Egresses *EgressRegistry

	BufferSize int

	mu          sync.Mutex
	sessions    map[relayFlowKey]*tcpFlowSession
	pending     map[relayFlowKey]*tcpSessionPending
	closed      bool
	teardownErr error
}

type tcpSessionPending struct {
	key        relayFlowKey
	cancel     context.CancelFunc
	endpoint   *egressCloseAuthority
	reportOnce sync.Once
	closed     bool
	settled    bool
}

type tcpFlowSession struct {
	key          relayFlowKey
	id           L3Identity
	endpoint     TCPConn
	egress       TCPConn
	cancel       context.CancelFunc
	cleanup      *egressSessionCleanup
	reportOnce   sync.Once
	closeClaimed bool
}

// Serve relays one classified TCP flow between endpoint and the selected
// embedding egress until either side closes or ctx is done.
func (r *TCPFlowRelay) Serve(ctx context.Context, ev PacketEvent, endpoint TCPConn) (retErr error) {
	if endpoint == nil {
		return errors.New("l3ingress: nil TCP relay endpoint")
	}
	id := ev.Meta.Identity
	if id == (L3Identity{}) {
		id = ev.Flow.L3Identity
	}
	if id.Proto != ProtocolTCP {
		return fmt.Errorf("l3ingress: TCP relay cannot handle %s", id.Proto)
	}
	if !ev.Decided {
		return errors.New("l3ingress: TCP relay requires a flow decision")
	}
	key, err := relayFlowKeyFromEvent(ev, id)
	if err != nil {
		return err
	}
	endpointAuthority, err := newEgressCloseAuthority(endpoint, "TCPFlowRelay endpoint Close")
	if err != nil {
		return err
	}
	endpointAuthority.observeLateTerminal(r.recordTeardownError)
	endpointAdopted := false
	var pending *tcpSessionPending
	defer func() {
		if !endpointAdopted {
			cleanupErr := endpointAuthority.Close()
			if pending != nil {
				pending.reportOnce.Do(func() { r.recordTeardownError(cleanupErr) })
			} else {
				r.recordTeardownError(cleanupErr)
			}
			retErr = errors.Join(retErr, cleanupErr)
		}
	}()
	dialCtx, pending, err := r.beginTCPAdmission(ctx, key, endpointAuthority)
	if err != nil {
		return err
	}
	defer pending.cancel()
	egress, err := r.Egresses.dialTCPObserved(
		dialCtx,
		ev.Decision.Egress,
		id,
		func() { r.settleTCPAdmission(key, pending) },
		r.recordTeardownError,
	)
	if err != nil {
		r.failTCPAdmission(key, pending)
		return err
	}
	egressAuthority, ok := closeAuthorityOf(egress)
	if !ok {
		return errors.Join(
			errors.New("l3ingress: TCP egress connection has no cleanup authority"),
			egress.Close(),
		)
	}
	sessionCtx, cancel := context.WithCancel(ctx)
	session := &tcpFlowSession{
		key:      key,
		id:       id,
		endpoint: endpoint,
		egress:   egress,
		cancel:   cancel,
		cleanup: newEgressSessionCleanup(
			endpointAuthority,
			egressAuthority,
		),
	}
	if !r.publishTCPAdmission(key, pending, session) {
		cancel()
		egressCleanupErr := egressAuthority.Close()
		r.recordTeardownError(egressCleanupErr)
		return errors.Join(
			net.ErrClosed,
			egressCleanupErr,
		)
	}
	endpointAdopted = true
	defer func() {
		retErr = errors.Join(retErr, r.closeSession(session))
	}()
	stopOnCancel := context.AfterFunc(sessionCtx, func() { _ = r.closeTCPFlowSession(session) })
	defer stopOnCancel()

	return relayTCPStreams(sessionCtx, endpoint, egress, r.BufferSize, session.close)
}

// Close closes all active TCP relay sessions.
func (r *TCPFlowRelay) Close() error {
	r.mu.Lock()
	if r.closed {
		err := r.teardownErr
		r.mu.Unlock()
		return err
	}
	r.closed = true
	sessions := r.sessions
	r.sessions = nil
	pending := r.pending
	r.pending = nil
	for _, admission := range pending {
		admission.closed = true
	}
	r.mu.Unlock()
	for _, admission := range pending {
		admission.cancel()
	}
	closeRelaySessionsBounded(pending, func(admission *tcpSessionPending) {
		_ = r.closeTCPPendingEndpoint(admission)
	})
	closeRelaySessionsBounded(sessions, func(session *tcpFlowSession) {
		_ = r.closeTCPFlowSession(session)
	})
	r.mu.Lock()
	err := r.teardownErr
	r.mu.Unlock()
	return err
}

// CloseFlow closes a legacy tuple-owned TCP admission or session. It never
// matches a generation-owned flow.
func (r *TCPFlowRelay) CloseFlow(id L3Identity) bool {
	return r.closeFlowKey(legacyRelayFlowKey(id))
}

// CloseFlowRef closes exactly one nonzero TCP flow generation.
func (r *TCPFlowRelay) CloseFlowRef(ref FlowRef) bool {
	if ref.Generation == 0 {
		return false
	}
	return r.closeFlowKey(relayFlowKeyFromRef(ref))
}

func (r *TCPFlowRelay) closeFlowKey(key relayFlowKey) bool {
	var cancelAdmission context.CancelFunc
	var pendingAdmission *tcpSessionPending
	r.mu.Lock()
	if pending := r.pending[key]; pending != nil && !pending.closed {
		pending.closed = true
		cancelAdmission = pending.cancel
		pendingAdmission = pending
	}
	session := r.sessions[key]
	if session != nil && !session.closeClaimed {
		session.closeClaimed = true
	} else {
		session = nil
	}
	r.mu.Unlock()
	if cancelAdmission != nil {
		cancelAdmission()
		_ = r.closeTCPPendingEndpoint(pendingAdmission)
	}
	if session == nil {
		return cancelAdmission != nil
	}
	_ = r.closeTCPFlowSession(session)
	r.mu.Lock()
	if r.sessions[key] == session {
		delete(r.sessions, key)
	}
	r.mu.Unlock()
	return true
}

func (r *TCPFlowRelay) beginTCPAdmission(
	ctx context.Context,
	key relayFlowKey,
	endpoint *egressCloseAuthority,
) (context.Context, *tcpSessionPending, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	dialCtx, cancel := context.WithCancel(ctx)
	pending := &tcpSessionPending{key: key, cancel: cancel, endpoint: endpoint}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		cancel()
		return nil, nil, net.ErrClosed
	}
	if r.sessions == nil {
		r.sessions = make(map[relayFlowKey]*tcpFlowSession)
	}
	if r.pending == nil {
		r.pending = make(map[relayFlowKey]*tcpSessionPending)
	}
	if r.sessions[key] != nil || r.pending[key] != nil {
		r.mu.Unlock()
		cancel()
		return nil, nil, errors.New("l3ingress: TCP relay session already active")
	}
	r.pending[key] = pending
	r.mu.Unlock()
	return dialCtx, pending, nil
}

func (r *TCPFlowRelay) closeTCPPendingEndpoint(pending *tcpSessionPending) error {
	if pending == nil || pending.endpoint == nil {
		return nil
	}
	err := pending.endpoint.Close()
	pending.reportOnce.Do(func() { r.recordTeardownError(err) })
	return err
}

func (r *TCPFlowRelay) failTCPAdmission(key relayFlowKey, pending *tcpSessionPending) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending[key] != pending {
		return
	}
	pending.closed = true
	if pending.settled {
		delete(r.pending, key)
	}
}

func (r *TCPFlowRelay) settleTCPAdmission(key relayFlowKey, pending *tcpSessionPending) {
	if pending == nil {
		return
	}
	r.mu.Lock()
	pending.settled = true
	if r.pending[key] == pending && pending.closed {
		delete(r.pending, key)
	}
	r.mu.Unlock()
}

func (r *TCPFlowRelay) publishTCPAdmission(
	key relayFlowKey,
	pending *tcpSessionPending,
	session *tcpFlowSession,
) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.pending[key] != pending || pending.closed || r.sessions[key] != nil {
		if r.pending[key] == pending {
			pending.closed = true
			if pending.settled {
				delete(r.pending, key)
			}
		}
		return false
	}
	delete(r.pending, key)
	r.sessions[key] = session
	return true
}

func (r *TCPFlowRelay) closeSession(session *tcpFlowSession) error {
	err := r.closeTCPFlowSession(session)
	r.mu.Lock()
	if r.sessions[session.key] == session {
		delete(r.sessions, session.key)
	}
	r.mu.Unlock()
	return err
}

func (r *TCPFlowRelay) closeTCPFlowSession(session *tcpFlowSession) error {
	if session == nil {
		return nil
	}
	err := session.close()
	session.reportOnce.Do(func() { r.recordTeardownError(err) })
	return err
}

func (r *TCPFlowRelay) recordTeardownError(err error) {
	if err == nil {
		return
	}
	r.mu.Lock()
	r.teardownErr = errors.Join(r.teardownErr, err)
	r.mu.Unlock()
}

func (s *tcpFlowSession) close() error {
	if s == nil {
		return nil
	}
	s.cancel()
	return s.cleanup.Close()
}

func streamRelayError(err error) error {
	var callbackErr *CallbackError
	if errors.As(err, &callbackErr) {
		return err
	}
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func runTCPRelayWorker(
	ctx context.Context,
	results chan<- error,
	dst, src TCPConn,
	bufferSize int,
) {
	const defaultBufferSize = 32 << 10
	if bufferSize <= 0 {
		bufferSize = defaultBufferSize
	}
	buf := make([]byte, bufferSize)
	dstIO := newL3IngressDataPlaneTCP(dst, "TCPFlowRelay TCPConn")
	srcIO := newL3IngressDataPlaneTCP(src, "TCPFlowRelay TCPConn")
	callback := "TCPFlowRelay TCPConn.Read"
	result := error(&CallbackError{Callback: callback, Reason: CallbackFailureGoexit})
	defer func() {
		if recovered := recover(); recovered != nil {
			result = callbackPanicError(callback, recovered)
		}
		results <- result
	}()

	for {
		callback = "TCPFlowRelay TCPConn.Read"
		result = &CallbackError{Callback: callback, Reason: CallbackFailureGoexit}
		n, readErr := srcIO.read(ctx, buf)
		if n < 0 || n > len(buf) {
			result = fmt.Errorf("l3ingress: TCPConn.Read returned invalid byte count %d", n)
			return
		}
		for written := 0; written < n; {
			callback = "TCPFlowRelay TCPConn.Write"
			result = &CallbackError{Callback: callback, Reason: CallbackFailureGoexit}
			nw, writeErr := dstIO.write(ctx, buf[written:n])
			if nw < 0 || nw > n-written {
				result = fmt.Errorf("l3ingress: TCPConn.Write returned invalid byte count %d", nw)
				return
			}
			written += nw
			if writeErr != nil {
				result = streamRelayError(writeErr)
				return
			}
			if nw == 0 {
				result = io.ErrShortWrite
				return
			}
		}
		if readErr == nil {
			continue
		}
		if errors.Is(readErr, io.EOF) {
			select {
			case <-ctx.Done():
				result = nil
				return
			default:
			}
			callback = "TCPFlowRelay TCPConn.CloseWrite"
			result = &CallbackError{Callback: callback, Reason: CallbackFailureGoexit}
			result = streamRelayError(dstIO.closeWrite())
			return
		}
		result = streamRelayError(readErr)
		return
	}
}

func relayTCPStreams(
	ctx context.Context,
	left, right TCPConn,
	bufferSize int,
	cleanup func() error,
) error {
	results := make(chan error, 2)
	go runTCPRelayWorker(ctx, results, right, left, bufferSize)
	go runTCPRelayWorker(ctx, results, left, right, bufferSize)

	select {
	case first := <-results:
		if first != nil {
			cleanupErr := cleanup()
			return errors.Join(first, waitTCPRelayResult(results), cleanupErr)
		}
		select {
		case second := <-results:
			return second
		case <-ctx.Done():
			cleanupErr := cleanup()
			return errors.Join(streamRelayError(ctx.Err()), waitTCPRelayResult(results), cleanupErr)
		}
	case <-ctx.Done():
		cleanupErr := cleanup()
		return errors.Join(
			streamRelayError(ctx.Err()),
			waitTCPRelayResult(results),
			waitTCPRelayResult(results),
			cleanupErr,
		)
	}
}

func waitTCPRelayResult(results <-chan error) error {
	timer := time.NewTimer(DefaultEgressCloseTimeout)
	defer stopFlowCallbackTimer(timer)
	select {
	case err := <-results:
		return err
	case <-timer.C:
		select {
		case err := <-results:
			return err
		default:
		}
		return &CallbackError{Callback: "TCPFlowRelay copy worker", Reason: CallbackFailureTimeout}
	}
}
