package quic

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	qg "github.com/quic-go/quic-go"
)

// Listener wraps *qg.Listener and yields (PathConn, error) per
// incoming connection: it does the AcceptStream step so callers see
// a ready-to-use rendr PathConn rather than a bare QUIC connection.
type Listener struct {
	ln *qg.Listener
}

// Listen binds a UDP socket at addr and waits for inbound QUIC
// connections. If tlsCfg is nil, an ephemeral self-signed dev cert
// is used (do NOT ship that in production).
func Listen(addr string, tlsCfg *tls.Config) (*Listener, error) {
	if tlsCfg == nil {
		st, _, err := devTLSConfig()
		if err != nil {
			return nil, err
		}
		tlsCfg = st
	}
	cfg := &qg.Config{
		MaxIdleTimeout:  90 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
	}
	ln, err := qg.ListenAddr(addr, tlsCfg, cfg)
	if err != nil {
		return nil, err
	}
	return &Listener{ln: ln}, nil
}

// Addr returns the underlying UDP address.
func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// Close shuts the listener. Already-accepted connections live on.
func (l *Listener) Close() error { return l.ln.Close() }

// Accept blocks until a new QUIC connection arrives and its first
// bidirectional stream has been opened by the peer. Returns the
// PathConn wrapping that stream, or an error if either step fails.
//
// Because of QUIC's lazy-stream semantics, the peer must write at
// least one byte to the stream before Accept returns. The rendr
// engine performs HELLO / BRIDGE_TAG as that first frame, so in
// normal use Accept unblocks within one handshake round-trip.
func (l *Listener) Accept(ctx context.Context) (*PathConn, error) {
	conn, err := l.ln.Accept(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		_ = conn.CloseWithError(0, "no stream")
		return nil, err
	}
	return wrap(conn, stream, true), nil
}
