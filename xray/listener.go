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
func ListenTCP(addr string) (*Listener, error) {
	ln, err := rendr.ListenTCP(addr)
	if err != nil {
		return nil, err
	}
	return &Listener{inner: ln}, nil
}

// ListenConfig describes an xray-side multi-transport stream listener.
type ListenConfig struct {
	Paths []PathSpec

	// QUICTLS is used for any QUIC listen path. Nil is accepted for
	// local development and uses rendr's ephemeral dev certificate;
	// production embedders should supply a real server config.
	QUICTLS *tls.Config
}

// Listen starts a stream listener whose paths share one rendr bridge
// table. This is the xray-facing wrapper around rendr.Listen for
// streamSettings.network="rendr" deployments that expose more than
// one underlying path transport.
func Listen(cfg *ListenConfig) (*Listener, error) {
	if cfg == nil {
		return nil, errNilListenConfig
	}
	if len(cfg.Paths) == 0 {
		return nil, errNoListenPaths
	}
	specs := make([]rendr.ListenSpec, len(cfg.Paths))
	for i, p := range cfg.Paths {
		if p.Transport == "" {
			return nil, errPathNoTransport(i)
		}
		if p.Address == "" {
			return nil, errPathNoAddress(i, p.Transport)
		}
		specs[i] = rendr.ListenSpec{
			Transport: p.Transport,
			Address:   p.Address,
		}
		if p.Transport == "quic" {
			specs[i].TLSConfig = cfg.QUICTLS
		}
	}
	ln, err := rendr.Listen(specs...)
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

// Addrs reports every bound transport address. Single-transport
// listeners return a one-element slice.
func (l *Listener) Addrs() []net.Addr {
	type multi interface {
		Addrs() []net.Addr
	}
	if m, ok := l.inner.(multi); ok {
		return m.Addrs()
	}
	if addr := l.inner.Addr(); addr != nil {
		return []net.Addr{addr}
	}
	return nil
}

// FlowIDs returns the set of live flow_ids the listener is serving.
// Useful for monitoring panels that want to enumerate active rendr
// connections without inspecting each accepted net.Conn.
func (l *Listener) FlowIDs() [][16]byte { return l.inner.FlowIDs() }
