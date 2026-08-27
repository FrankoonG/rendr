package l3ingress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"

	"github.com/FrankoonG/rendr/virtualif"
)

// UDPFlowRelay forwards classified UDP flow payloads to an embedding
// egress hook and writes egress replies back as raw IP packets.
type UDPFlowRelay struct {
	Device   virtualif.CancellableWriterDevice
	Egresses *EgressRegistry

	mu          sync.Mutex
	sessions    map[relayFlowKey]*udpFlowSession
	pending     map[relayFlowKey]*udpSessionPending
	closed      bool
	teardownErr error
}

type udpSessionPending struct {
	key     relayFlowKey
	done    chan struct{}
	cancel  context.CancelFunc
	session *udpFlowSession
	err     error
	waiters int
	closed  bool
	settled bool
	claimed bool
}

type udpFlowSession struct {
	key           relayFlowKey
	id            L3Identity
	pc            net.PacketConn
	dataPlane     *l3IngressDataPlanePacket
	remote        netip.AddrPort
	ctx           context.Context
	cancel        context.CancelFunc
	readDone      chan struct{}
	writeDone     chan struct{}
	readReady     chan struct{}
	writeRequests chan udpWriteRequest
	cleanup       *egressSessionCleanup
	reportOnce    sync.Once
	closeClaimed  bool
	ownerOnce     sync.Once
	ownerMu       sync.Mutex
	ownerStop     func() bool
	ownerClosed   bool
}

type udpWriteRequest struct {
	payload []byte
	result  chan error
}

// HandlePacket implements PacketHandler for UDP flow smoke paths.
func (r *UDPFlowRelay) HandlePacket(ctx context.Context, ev PacketEvent) error {
	if r.Device == nil {
		return errors.New("l3ingress: nil UDP relay device")
	}
	if ev.Meta.Identity.Proto != ProtocolUDP {
		return fmt.Errorf("l3ingress: UDP relay cannot handle %s", ev.Meta.Identity.Proto)
	}
	if !ev.Decided {
		return errors.New("l3ingress: UDP relay requires a flow decision")
	}
	payload, err := UDPPayload(ev.Packet, ev.Meta)
	if err != nil {
		return err
	}
	session, err := r.session(ctx, ev)
	if err != nil {
		return err
	}
	request := udpWriteRequest{
		payload: append([]byte(nil), payload...),
		result:  make(chan error, 1),
	}
	select {
	case session.writeRequests <- request:
	case <-ctx.Done():
		_ = r.closeUDPFlowSession(session)
		return ctx.Err()
	case <-session.ctx.Done():
		return net.ErrClosed
	case <-session.writeDone:
		return net.ErrClosed
	}
	select {
	case err := <-request.result:
		return err
	case <-ctx.Done():
		_ = r.closeUDPFlowSession(session)
		return ctx.Err()
	case <-session.ctx.Done():
		select {
		case err := <-request.result:
			return err
		default:
			return net.ErrClosed
		}
	case <-session.writeDone:
		select {
		case err := <-request.result:
			return err
		default:
			return net.ErrClosed
		}
	}
}

// Close closes all active UDP relay sessions.
func (r *UDPFlowRelay) Close() error {
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
		if !admission.closed {
			admission.err = net.ErrClosed
			admission.closed = true
			close(admission.done)
		}
	}
	r.mu.Unlock()
	for _, admission := range pending {
		admission.cancel()
	}
	r.closeUDPSessions(sessions)
	r.mu.Lock()
	err := r.teardownErr
	r.mu.Unlock()
	return err
}

func (r *UDPFlowRelay) closeUDPSessions(sessions map[relayFlowKey]*udpFlowSession) {
	closeRelaySessionsBounded(sessions, func(session *udpFlowSession) {
		_ = r.closeUDPFlowSession(session)
		workerErr := errors.Join(
			waitEgressWorker(session.readDone, "UDPFlowRelay reply worker"),
			waitEgressWorker(session.writeDone, "UDPFlowRelay write worker"),
		)
		if workerErr != nil {
			r.recordTeardownError(workerErr)
		}
	})
}

// CloseFlow closes a legacy tuple-owned UDP admission or session. It never
// matches a generation-owned flow.
func (r *UDPFlowRelay) CloseFlow(id L3Identity) bool {
	return r.closeFlowKey(legacyRelayFlowKey(id))
}

// CloseFlowRef closes exactly one nonzero UDP flow generation.
func (r *UDPFlowRelay) CloseFlowRef(ref FlowRef) bool {
	if ref.Generation == 0 {
		return false
	}
	return r.closeFlowKey(relayFlowKeyFromRef(ref))
}

func (r *UDPFlowRelay) closeFlowKey(key relayFlowKey) bool {
	var cancelAdmission context.CancelFunc
	r.mu.Lock()
	if pending := r.pending[key]; pending != nil && !pending.closed {
		pending.err = net.ErrClosed
		pending.closed = true
		close(pending.done)
		cancelAdmission = pending.cancel
		if pending.settled {
			delete(r.pending, key)
		}
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
	}
	if session == nil {
		return cancelAdmission != nil
	}
	_ = r.closeUDPFlowSession(session)
	if err := errors.Join(
		waitEgressWorker(session.readDone, "UDPFlowRelay reply worker"),
		waitEgressWorker(session.writeDone, "UDPFlowRelay write worker"),
	); err != nil {
		r.recordTeardownError(err)
	}
	r.mu.Lock()
	if r.sessions[key] == session {
		delete(r.sessions, key)
	}
	r.mu.Unlock()
	return true
}

func (r *UDPFlowRelay) session(ctx context.Context, ev PacketEvent) (*udpFlowSession, error) {
	id := ev.Meta.Identity
	key, err := relayFlowKeyFromEvent(ev, id)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, net.ErrClosed
	}
	if r.sessions == nil {
		r.sessions = make(map[relayFlowKey]*udpFlowSession)
	}
	if r.pending == nil {
		r.pending = make(map[relayFlowKey]*udpSessionPending)
	}
	if pending := r.pending[key]; pending != nil {
		pending.waiters++
		r.mu.Unlock()
		return r.waitUDPSession(ctx, pending)
	}
	if session := r.sessions[key]; session != nil {
		r.mu.Unlock()
		return session, nil
	}
	dialCtx, cancelDial := context.WithCancel(context.WithoutCancel(ctx))
	pending := &udpSessionPending{key: key, done: make(chan struct{}), cancel: cancelDial, waiters: 1}
	r.pending[key] = pending
	r.mu.Unlock()
	go r.admitUDPSession(dialCtx, pending, ev)
	return r.waitUDPSession(ctx, pending)
}

func (r *UDPFlowRelay) waitUDPSession(
	ctx context.Context,
	pending *udpSessionPending,
) (*udpFlowSession, error) {
	defer r.releaseUDPAdmissionWaiter(pending)
	select {
	case <-pending.done:
		return r.claimUDPSession(ctx, pending)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (r *UDPFlowRelay) admitUDPSession(
	dialCtx context.Context,
	pending *udpSessionPending,
	ev PacketEvent,
) {
	session, err := r.dialUDPSession(dialCtx, pending, ev)
	pending.cancel()

	cleanupSession := false
	reportAdmissionErr := false
	r.mu.Lock()
	key := pending.key
	if r.pending[key] != pending || pending.closed {
		reportAdmissionErr = reportableUDPAdmissionError(err)
		if r.pending[key] == pending && pending.settled && pending.waiters == 0 {
			delete(r.pending, key)
		}
		r.mu.Unlock()
		if session != nil {
			_ = r.closeUDPFlowSession(session)
		}
		if reportAdmissionErr {
			r.recordTeardownError(err)
		}
		return
	}
	if r.closed {
		pending.err = net.ErrClosed
	} else if err != nil {
		pending.err = err
		reportAdmissionErr = pending.waiters == 0 && reportableUDPAdmissionError(err)
		if pending.waiters == 0 && udpAdmissionFailureResolved(err, pending.settled) {
			delete(r.pending, key)
		}
	} else if pending.waiters == 0 {
		delete(r.pending, key)
		pending.err = context.Canceled
		cleanupSession = true
	} else {
		r.sessions[key] = session
		pending.session = session
		go r.readReplies(session.ctx, session)
		go r.writePackets(session.ctx, session)
	}
	pending.closed = true
	close(pending.done)
	r.mu.Unlock()
	if reportAdmissionErr {
		r.recordTeardownError(err)
	}
	if cleanupSession {
		_ = r.closeUDPFlowSession(session)
	}
}

func (r *UDPFlowRelay) dialUDPSession(
	dialCtx context.Context,
	pending *udpSessionPending,
	ev PacketEvent,
) (*udpFlowSession, error) {
	id := ev.Meta.Identity
	pc, remote, err := r.Egresses.dialUDPWithSettlement(
		dialCtx,
		ev.Decision.Egress,
		id,
		func() { r.settleUDPAdmission(pending.key, pending) },
		r.recordTeardownError,
	)
	if err != nil {
		return nil, err
	}
	if nilInterface(pc) {
		return nil, errors.New("l3ingress: UDP egress returned a nil connection")
	}
	authority, ok := closeAuthorityOf(pc)
	if !ok {
		return nil, errors.Join(
			errors.New("l3ingress: UDP egress connection has no cleanup authority"),
			pc.Close(),
		)
	}
	cleanup := newEgressSessionCleanup(authority)
	if !remote.IsValid() {
		return nil, errors.Join(
			errors.New("l3ingress: UDP egress returned an invalid socket or remote address"),
			cleanup.Close(),
		)
	}
	if err := dialCtx.Err(); err != nil {
		return nil, errors.Join(err, cleanup.Close())
	}
	sessionCtx, cancel := context.WithCancel(context.WithoutCancel(dialCtx))
	session := &udpFlowSession{
		key:           pending.key,
		id:            id,
		pc:            pc,
		dataPlane:     newL3IngressDataPlanePacket(pc, "UDPFlowRelay PacketConn"),
		remote:        remote,
		ctx:           sessionCtx,
		cancel:        cancel,
		readDone:      make(chan struct{}),
		writeDone:     make(chan struct{}),
		readReady:     make(chan struct{}),
		writeRequests: make(chan udpWriteRequest),
		cleanup:       cleanup,
	}
	return session, nil
}

func udpAdmissionFailureResolved(err error, settled bool) bool {
	return settled || !udpAdmissionAwaitsSettlement(err)
}

func udpAdmissionAwaitsSettlement(err error) bool {
	var callbackErr *CallbackError
	return errors.As(err, &callbackErr) &&
		callbackErr.Reason == CallbackFailureTimeout &&
		callbackErr.Callback == "Egress.DialUDP"
}

func (r *UDPFlowRelay) settleUDPAdmission(key relayFlowKey, pending *udpSessionPending) {
	if pending == nil {
		return
	}
	r.mu.Lock()
	pending.settled = true
	if r.pending[key] == pending && pending.closed && pending.waiters == 0 {
		delete(r.pending, key)
	}
	r.mu.Unlock()
}

func (r *UDPFlowRelay) claimUDPSession(
	ctx context.Context,
	pending *udpSessionPending,
) (*udpFlowSession, error) {
	r.mu.Lock()
	if err := ctx.Err(); err != nil {
		r.mu.Unlock()
		return nil, err
	}
	session, err := pending.session, pending.err
	bindOwner := session != nil && !pending.claimed
	if bindOwner {
		pending.claimed = true
		if r.pending[pending.key] == pending {
			delete(r.pending, pending.key)
		}
	}
	r.mu.Unlock()
	if bindOwner {
		r.bindUDPFlowSessionOwner(session, ctx)
	}
	return session, err
}

func (r *UDPFlowRelay) releaseUDPAdmissionWaiter(pending *udpSessionPending) {
	if pending == nil {
		return
	}
	var cleanup *udpFlowSession
	r.mu.Lock()
	pending.waiters--
	if pending.waiters == 0 && pending.closed && pending.session == nil && pending.settled {
		if r.pending[pending.key] == pending {
			delete(r.pending, pending.key)
		}
	}
	if pending.waiters == 0 && pending.closed && pending.session != nil && !pending.claimed {
		session := pending.session
		if r.pending[pending.key] == pending {
			delete(r.pending, pending.key)
		}
		if r.sessions[session.key] == session && !session.closeClaimed {
			session.closeClaimed = true
			delete(r.sessions, session.key)
			cleanup = session
		}
	}
	r.mu.Unlock()
	if cleanup != nil {
		_ = r.closeUDPFlowSession(cleanup)
	}
}

func reportableUDPAdmissionError(err error) bool {
	return err != nil && err != context.Canceled && err != net.ErrClosed
}

func (r *UDPFlowRelay) bindUDPFlowSessionOwner(session *udpFlowSession, ctx context.Context) {
	if session == nil || ctx == nil || ctx.Done() == nil {
		return
	}
	session.ownerOnce.Do(func() {
		stop := context.AfterFunc(ctx, func() { _ = r.closeUDPFlowSession(session) })
		session.ownerMu.Lock()
		if session.ownerClosed {
			session.ownerMu.Unlock()
			stop()
			return
		}
		session.ownerStop = stop
		session.ownerMu.Unlock()
	})
}

func (r *UDPFlowRelay) readReplies(ctx context.Context, session *udpFlowSession) {
	callback := "UDPFlowRelay PacketConn.ReadFrom"
	workerErr := error(&CallbackError{Callback: callback, Reason: CallbackFailureGoexit})
	stopOnCancel := context.AfterFunc(ctx, func() { _ = r.closeUDPFlowSession(session) })
	defer func() {
		if recovered := recover(); recovered != nil {
			workerErr = callbackPanicError(callback, recovered)
		}
		if workerErr != nil {
			r.recordTeardownError(workerErr)
		}
		stopOnCancel()
		_ = r.closeUDPFlowSession(session)
		session.cancel()
		r.forgetSession(session)
		close(session.readDone)
	}()
	select {
	case <-session.readReady:
	case <-ctx.Done():
		workerErr = nil
		return
	}
	buf := make([]byte, 64<<10)
	replyID := session.id.Reverse()
	packet := make([]byte, 0, len(buf)+28)
	for {
		select {
		case <-ctx.Done():
			workerErr = nil
			return
		default:
		}
		workerErr = &CallbackError{Callback: callback, Reason: CallbackFailureGoexit}
		n, source, readErr := session.dataPlane.readFrom(ctx, buf)
		if n < 0 || n > len(buf) {
			workerErr = errors.Join(readErr,
				fmt.Errorf("l3ingress: PacketConn.ReadFrom returned invalid byte count %d", n))
			return
		}
		if n == 0 && readErr != nil {
			workerErr = streamRelayError(readErr)
			return
		}
		if !udpReplySourceMatches(source, session.remote) {
			if readErr != nil {
				workerErr = readErr
				return
			}
			continue
		}
		packet = packet[:0]
		var appendErr error
		packet, appendErr = AppendUDPPacket(packet, replyID, buf[:n])
		if appendErr != nil {
			workerErr = appendErr
			return
		}
		if _, err := r.Device.WriteContext(ctx, packet); err != nil {
			workerErr = streamRelayError(err)
			return
		}
		if readErr != nil {
			workerErr = readErr
			return
		}
	}
}

func (r *UDPFlowRelay) writePackets(ctx context.Context, session *udpFlowSession) {
	callback := "UDPFlowRelay PacketConn.WriteTo"
	var current *udpWriteRequest
	workerErr := error(nil)
	readStarted := false
	defer func() {
		if recovered := recover(); recovered != nil {
			workerErr = callbackPanicError(callback, recovered)
		}
		if current != nil {
			current.result <- workerErr
		}
		if workerErr != nil {
			r.recordTeardownError(workerErr)
		}
		_ = r.closeUDPFlowSession(session)
		session.cancel()
		r.forgetSession(session)
		close(session.writeDone)
	}()

	remote := net.UDPAddrFromAddrPort(session.remote)
	for {
		select {
		case <-ctx.Done():
			return
		case request := <-session.writeRequests:
			current = &request
			workerErr = &CallbackError{Callback: callback, Reason: CallbackFailureGoexit}
			n, err := session.dataPlane.writeTo(ctx, request.payload, remote)
			if n < 0 || n > len(request.payload) {
				err = fmt.Errorf("l3ingress: PacketConn.WriteTo returned invalid byte count %d", n)
			} else if err == nil && n != len(request.payload) {
				err = io.ErrShortWrite
			}
			workerErr = nil
			var callbackErr *CallbackError
			if errors.As(err, &callbackErr) {
				workerErr = err
			}
			request.result <- err
			if !readStarted {
				close(session.readReady)
				readStarted = true
			}
			current = nil
			if err != nil {
				return
			}
			workerErr = nil
		}
	}
}

func udpReplySourceMatches(source net.Addr, expected netip.AddrPort) bool {
	if source == nil || !expected.IsValid() {
		return false
	}
	address, ok := source.(*net.UDPAddr)
	if !ok || address == nil {
		// DialUDP is an IP/UDP egress contract. Text supplied by an arbitrary
		// net.Addr is neither socket identity nor safe to invoke in this worker.
		return false
	}
	actual := address.AddrPort()
	return actual.Addr().Unmap() == expected.Addr().Unmap() && actual.Port() == expected.Port()
}

func (r *UDPFlowRelay) forgetSession(session *udpFlowSession) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions[session.key] == session {
		delete(r.sessions, session.key)
	}
}

func (r *UDPFlowRelay) closeUDPFlowSession(session *udpFlowSession) error {
	if session == nil {
		return nil
	}
	session.ownerMu.Lock()
	session.ownerClosed = true
	stopOwner := session.ownerStop
	session.ownerStop = nil
	session.ownerMu.Unlock()
	if stopOwner != nil {
		stopOwner()
	}
	session.cancel()
	err := session.cleanup.Close()
	session.reportOnce.Do(func() { r.recordTeardownError(err) })
	return err
}

func (r *UDPFlowRelay) recordTeardownError(err error) {
	if err == nil {
		return
	}
	r.mu.Lock()
	r.teardownErr = errors.Join(r.teardownErr, err)
	r.mu.Unlock()
}
