package l3ingress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// TCPFlowRelay bridges one accepted userspace TCP endpoint to an
// embedding-provided peer egress hook.
type TCPFlowRelay struct {
	Egresses *EgressRegistry

	BufferSize int

	mu       sync.Mutex
	sessions map[L3Identity]*tcpFlowSession
}

type tcpFlowSession struct {
	id       L3Identity
	endpoint net.Conn
	egress   net.Conn
	cancel   context.CancelFunc
}

// Serve relays one classified TCP flow between endpoint and the selected
// embedding egress until either side closes or ctx is done.
func (r *TCPFlowRelay) Serve(ctx context.Context, ev PacketEvent, endpoint net.Conn) error {
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
	egress, err := r.Egresses.DialTCP(ctx, ev.Decision.Egress, id)
	if err != nil {
		return err
	}
	sessionCtx, cancel := context.WithCancel(ctx)
	session := &tcpFlowSession{id: id, endpoint: endpoint, egress: egress, cancel: cancel}
	if !r.addSession(session) {
		cancel()
		_ = egress.Close()
		return errors.New("l3ingress: TCP relay session already active")
	}
	defer r.closeSession(session)

	errCh := make(chan error, 2)
	go func() { errCh <- copyStream(egress, endpoint, r.BufferSize) }()
	go func() { errCh <- copyStream(endpoint, egress, r.BufferSize) }()

	select {
	case err := <-errCh:
		_ = endpoint.Close()
		_ = egress.Close()
		if ctxErr := sessionCtx.Err(); ctxErr != nil {
			err = ctxErr
		}
		return streamRelayError(err)
	case <-sessionCtx.Done():
		_ = endpoint.Close()
		_ = egress.Close()
		return streamRelayError(sessionCtx.Err())
	}
}

// Close closes all active TCP relay sessions.
func (r *TCPFlowRelay) Close() error {
	r.mu.Lock()
	sessions := r.sessions
	r.sessions = nil
	r.mu.Unlock()
	var err error
	for _, session := range sessions {
		session.cancel()
		err = errors.Join(err, session.endpoint.Close(), session.egress.Close())
	}
	return err
}

// CloseFlow closes one active TCP relay session.
func (r *TCPFlowRelay) CloseFlow(id L3Identity) bool {
	r.mu.Lock()
	session := r.sessions[id]
	if session != nil {
		delete(r.sessions, id)
	}
	r.mu.Unlock()
	if session == nil {
		return false
	}
	session.cancel()
	_ = session.endpoint.Close()
	_ = session.egress.Close()
	return true
}

func (r *TCPFlowRelay) addSession(session *tcpFlowSession) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions == nil {
		r.sessions = make(map[L3Identity]*tcpFlowSession)
	}
	if r.sessions[session.id] != nil {
		return false
	}
	r.sessions[session.id] = session
	return true
}

func (r *TCPFlowRelay) closeSession(session *tcpFlowSession) {
	r.mu.Lock()
	if r.sessions[session.id] == session {
		delete(r.sessions, session.id)
	}
	r.mu.Unlock()
	session.cancel()
	_ = session.endpoint.Close()
	_ = session.egress.Close()
}

func copyStream(dst io.Writer, src io.Reader, bufferSize int) error {
	if bufferSize <= 0 {
		_, err := io.Copy(dst, src)
		return err
	}
	buf := make([]byte, bufferSize)
	_, err := io.CopyBuffer(dst, src, buf)
	return err
}

func streamRelayError(err error) error {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
