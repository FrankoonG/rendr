package tcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/transport"
)

// Listener is the owned raw TCP ingress counterpart to Transport. Generic
// net.Listener values passed through rendr.StreamSource intentionally do not
// acquire this ownership claim.
type Listener struct {
	listener  *net.TCPListener
	accept    chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error
}

// NewListener transfers admission ownership of listener to a framed TCP path
// listener. Closing Listener does not close paths it has already returned.
func NewListener(listener *net.TCPListener) (*Listener, error) {
	if listener == nil {
		return nil, errors.New("tcp: nil TCPListener")
	}
	return newOwnedListener(listener), nil
}

// Listen creates an owned raw TCP path listener.
func Listen(network, address string) (*Listener, error) {
	addr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, fmt.Errorf("tcp: resolve listen address: %w", err)
	}
	listener, err := net.ListenTCP(network, addr)
	if err != nil {
		return nil, fmt.Errorf("tcp: listen %s: %w", address, err)
	}
	return newOwnedListener(listener), nil
}

func newOwnedListener(listener *net.TCPListener) *Listener {
	accept := make(chan struct{}, 1)
	accept <- struct{}{}
	return &Listener{listener: listener, accept: accept, closed: make(chan struct{})}
}

// AcceptPath accepts one concrete raw TCP socket and honors cancellation by
// interrupting AcceptTCP with a temporary listener deadline. The wake goroutine
// is joined before clearing the deadline so it cannot poison the next accept.
func (l *Listener) AcceptPath(ctx context.Context) (transport.PathConn, error) {
	if l == nil || l.listener == nil || l.accept == nil || l.closed == nil {
		return nil, net.ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.closed:
		return nil, net.ErrClosed
	case <-l.accept:
	}
	defer func() { l.accept <- struct{}{} }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	default:
	}

	deadline := time.Time{}
	if value, ok := ctx.Deadline(); ok {
		deadline = value
	}
	if err := l.listener.SetDeadline(deadline); err != nil {
		return nil, err
	}
	done := make(chan struct{})
	wakeDone := make(chan struct{})
	go func() {
		defer close(wakeDone)
		select {
		case <-ctx.Done():
			_ = l.listener.SetDeadline(time.Now())
		case <-done:
		}
	}()
	conn, err := l.listener.AcceptTCP()
	close(done)
	<-wakeDone
	clearErr := l.listener.SetDeadline(time.Time{})
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	if clearErr != nil {
		_ = conn.Close()
		return nil, clearErr
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		_ = conn.Close()
		return nil, ctxErr
	}
	select {
	case <-l.closed:
		_ = conn.Close()
		return nil, net.ErrClosed
	default:
	}
	_ = conn.SetKeepAlive(false)
	return wrapOwned(conn, leafmobility.RoleAcceptor), nil
}

func (*Listener) SessionKind() transport.PathSessionKind {
	return transport.PathSessionStream
}

func (l *Listener) Close() error {
	if l == nil || l.listener == nil {
		return nil
	}
	l.closeOnce.Do(func() {
		if l.closed != nil {
			close(l.closed)
		}
		l.closeErr = l.listener.Close()
	})
	return l.closeErr
}

func (l *Listener) Addr() net.Addr {
	if l == nil || l.listener == nil {
		return nil
	}
	return l.listener.Addr()
}
