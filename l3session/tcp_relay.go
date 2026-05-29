package l3session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/FrankoonG/rendr/l3ingress"
)

// TCPRelay bridges one accepted userspace TCP endpoint, such as a future
// gVisor TCP endpoint, to a per-flow rendr Conn session.
type TCPRelay struct {
	Manager *Manager

	BufferSize int

	owned Manager
}

// Serve starts or reuses the rendr stream session for ev and relays bytes
// between endpoint and the rendr Conn until either side closes or ctx is done.
func (r *TCPRelay) Serve(ctx context.Context, ev l3ingress.PacketEvent, endpoint net.Conn) error {
	if endpoint == nil {
		return errors.New("l3session: nil TCP relay endpoint")
	}
	id := ev.Meta.Identity
	if id == (l3ingress.L3Identity{}) {
		id = ev.Flow.L3Identity
	}
	if id.Proto != l3ingress.ProtocolTCP {
		return fmt.Errorf("l3session: TCP relay cannot handle %s", id.Proto)
	}
	manager := r.manager()
	if err := manager.HandlePacket(ctx, ev); err != nil {
		return err
	}
	sess, ok := manager.Session(id)
	if !ok || sess.Conn == nil {
		return errors.New("l3session: TCP relay missing stream session")
	}
	defer endpoint.Close()
	defer manager.Close(id)

	errCh := make(chan error, 2)
	go func() { errCh <- copyConn(sess.Conn, endpoint, r.BufferSize) }()
	go func() { errCh <- copyConn(endpoint, sess.Conn, r.BufferSize) }()

	select {
	case err := <-errCh:
		_ = endpoint.Close()
		_ = sess.Conn.Close()
		return relayError(err)
	case <-ctx.Done():
		_ = endpoint.Close()
		_ = sess.Conn.Close()
		return ctx.Err()
	}
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

func copyConn(dst io.Writer, src io.Reader, bufferSize int) error {
	if bufferSize <= 0 {
		_, err := io.Copy(dst, src)
		return err
	}
	buf := make([]byte, bufferSize)
	_, err := io.CopyBuffer(dst, src, buf)
	return err
}

func relayError(err error) error {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
