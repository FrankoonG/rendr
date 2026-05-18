package xray

import (
	"context"
	"crypto/tls"
	"errors"
	"net"

	"github.com/FrankoonG/rendr"
)

// Listener wraps a rendr.Listener so it satisfies the integration
// surface xray expects for inbound transports.
type Listener struct {
	inner rendr.Listener
}

// ListenTCP starts a TCP-only rendr listener at addr suitable for
// the xray transport-bridge. The returned Listener exposes Accept /
// Close / Addr (net.Addr).
//
// Multi-transport listening (one bound address that accepts both
// TCP and QUIC inbound paths and bridges them to the same flow_id)
// is deferred to M9's X4/X5 sub-stage; until then xray-side
// integration creates one Listener per transport.
func ListenTCP(addr string) (*Listener, error) {
	ln, err := rendr.ListenTCP(addr)
	if err != nil {
		return nil, err
	}
	return &Listener{inner: ln}, nil
}

// ListenQUIC starts a QUIC-only rendr listener.
func ListenQUIC(addr string, tlsCfg *tls.Config) (*Listener, error) {
	if tlsCfg == nil {
		return nil, errors.New("rendr/xray: ListenQUIC requires a non-nil *tls.Config in production; pass a self-signed dev cert via the standalone transport/quic package for tests")
	}
	ln, err := rendr.ListenQUIC(addr, tlsCfg)
	if err != nil {
		return nil, err
	}
	return &Listener{inner: ln}, nil
}

// Accept blocks until an inbound rendr Conn is available. The
// listener accepts against context.Background; xray-side adapters
// supply per-Accept cancellation via AcceptContext below.
func (l *Listener) Accept() (net.Conn, error) {
	return l.inner.Accept(context.Background())
}

// AcceptContext is the cancellable variant.
func (l *Listener) AcceptContext(ctx context.Context) (net.Conn, error) {
	return l.inner.Accept(ctx)
}

// Close shuts the listener.
func (l *Listener) Close() error { return l.inner.Close() }

// Addr reports the local network address.
func (l *Listener) Addr() net.Addr { return l.inner.Addr() }

// FlowIDs returns the set of live flow_ids the listener is serving.
// Useful for monitoring panels that want to enumerate active rendr
// connections without inspecting each accepted net.Conn.
func (l *Listener) FlowIDs() [][16]byte { return l.inner.FlowIDs() }
