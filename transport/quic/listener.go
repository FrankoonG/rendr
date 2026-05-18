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
	tr *qg.Transport
}

// Listen binds a UDP socket at addr and waits for inbound QUIC
// connections. If tlsCfg is nil, an ephemeral self-signed dev cert
// is used (do NOT ship that in production).
//
// The underlying UDP socket is opened with SO_RCVBUF/SO_SNDBUF set
// to DefaultUDPBufferBytes (8 MiB). Production deployments serving
// DATAGRAM-mode at >50k pps should raise the Linux kernel cap with
// `sysctl -w net.core.rmem_max=8388608 net.core.wmem_max=8388608`.
func Listen(addr string, tlsCfg *tls.Config) (*Listener, error) {
	if tlsCfg == nil {
		st, _, err := devTLSConfig()
		if err != nil {
			return nil, err
		}
		tlsCfg = st
	}
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	udpConn, err := udpConnWithBuffers(laddr)
	if err != nil {
		return nil, err
	}
	tr := &qg.Transport{Conn: udpConn}
	cfg := &qg.Config{
		MaxIdleTimeout:  90 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
		// Always advertise DATAGRAM support; stream-mode peers
		// ignore it. Lets the listener serve both stream- and
		// datagram-mode clients on the same UDP port.
		EnableDatagrams: true,
	}
	ln, err := tr.Listen(tlsCfg, cfg)
	if err != nil {
		_ = tr.Close()
		return nil, err
	}
	return &Listener{ln: ln, tr: tr}, nil
}

// Addr returns the underlying UDP address.
func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// Close shuts the listener. Already-accepted connections live on
// until they finish naturally or are explicitly closed.
func (l *Listener) Close() error {
	err := l.ln.Close()
	if l.tr != nil {
		_ = l.tr.Close()
	}
	return err
}

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

// AcceptDatagram blocks until a new QUIC connection arrives and
// wraps it as a DATAGRAM-mode PathConn. Use when the client dialed
// with PathSpec.Opts["mode"]="datagram". Unlike Accept, no stream is
// opened; the connection is ready for SendDatagram / ReceiveDatagram
// immediately.
func (l *Listener) AcceptDatagram(ctx context.Context) (*datagramPathConn, error) {
	conn, err := l.ln.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return wrapDatagram(conn, true), nil
}
