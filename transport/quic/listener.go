package quic

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"

	qg "github.com/quic-go/quic-go"

	"github.com/FrankoonG/rendr/transport"
)

// Listener wraps *qg.Listener and yields (PathConn, error) per
// incoming connection: it does the AcceptStream step so callers see
// a ready-to-use rendr PathConn rather than a bare QUIC connection.
type Listener struct {
	ln *qg.Listener
	tr *qg.Transport

	ownershipMu     sync.Mutex
	closing         bool
	listenerClosed  bool
	retained        int
	closeOnce       sync.Once
	closeErr        error
	transportDone   chan struct{}
	admissionCtx    context.Context
	cancelAdmission context.CancelFunc
}

// DatagramListener exposes only DATAGRAM-mode framed path acceptance.
// It deliberately holds rather than embeds Listener so stream acceptance is
// not part of its method set.
type DatagramListener struct {
	listener *Listener
}

var (
	_ transport.PathListener = (*Listener)(nil)
	_ transport.PathListener = (*DatagramListener)(nil)
)

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
	admissionCtx, cancelAdmission := context.WithCancel(context.Background())
	return &Listener{
		ln:              ln,
		tr:              tr,
		transportDone:   make(chan struct{}),
		admissionCtx:    admissionCtx,
		cancelAdmission: cancelAdmission,
	}, nil
}

// ListenDatagram binds a UDP socket and exposes DATAGRAM-only framed ingress.
func ListenDatagram(addr string, tlsCfg *tls.Config) (*DatagramListener, error) {
	listener, err := Listen(addr, tlsCfg)
	if err != nil {
		return nil, err
	}
	return &DatagramListener{listener: listener}, nil
}

// Addr returns the underlying UDP address.
func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// SessionKind reports that stream-backed QUIC paths can carry either rendr
// application session contract.
func (*Listener) SessionKind() transport.PathSessionKind { return transport.PathSessionAny }

// Close shuts the listener. Already-accepted connections live on
// until they finish naturally or are explicitly closed.
func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		l.ownershipMu.Lock()
		l.closing = true
		l.ownershipMu.Unlock()

		l.cancelAdmission()
		l.closeErr = l.ln.Close()

		l.ownershipMu.Lock()
		l.listenerClosed = true
		tr := l.takeTransportLocked()
		l.ownershipMu.Unlock()
		l.closeTransport(tr)
	})
	return l.closeErr
}

func (l *Listener) retainAccept() (func(), error) {
	l.ownershipMu.Lock()
	defer l.ownershipMu.Unlock()
	if l.closing {
		return nil, net.ErrClosed
	}
	l.retained++
	return sync.OnceFunc(l.release), nil
}

func (l *Listener) release() {
	l.ownershipMu.Lock()
	l.retained--
	tr := l.takeTransportLocked()
	l.ownershipMu.Unlock()
	l.closeTransport(tr)
}

func (l *Listener) takeTransportLocked() *qg.Transport {
	if !l.listenerClosed || l.retained != 0 || l.tr == nil {
		return nil
	}
	tr := l.tr
	l.tr = nil
	return tr
}

func (l *Listener) closeTransport(tr *qg.Transport) {
	if tr == nil {
		return
	}
	_ = tr.Close()
	if tr.Conn != nil {
		_ = tr.Conn.Close()
	}
	close(l.transportDone)
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
	release, err := l.retainAccept()
	if err != nil {
		return nil, err
	}
	conn, err := l.ln.Accept(ctx)
	if err != nil {
		release()
		return nil, err
	}
	streamCtx, cancel := context.WithCancel(ctx)
	stopCancel := context.AfterFunc(l.admissionCtx, cancel)
	stream, err := conn.AcceptStream(streamCtx)
	stopCancel()
	cancel()
	if err != nil {
		_ = conn.CloseWithError(0, "no stream")
		release()
		return nil, err
	}
	return wrap(conn, stream, true, release), nil
}

// AcceptPath delegates to Accept.
func (l *Listener) AcceptPath(ctx context.Context) (transport.PathConn, error) {
	path, err := l.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return path, nil
}

// AcceptDatagram blocks until a new QUIC connection arrives and
// wraps it as a DATAGRAM-mode PathConn. Use when the client dialed
// with PathSpec.Opts["mode"]="datagram". Unlike Accept, no stream is
// opened; the connection is ready for SendDatagram / ReceiveDatagram
// immediately.
func (l *Listener) AcceptDatagram(ctx context.Context) (*datagramPathConn, error) {
	release, err := l.retainAccept()
	if err != nil {
		return nil, err
	}
	conn, err := l.ln.Accept(ctx)
	if err != nil {
		release()
		return nil, err
	}
	return wrapDatagram(conn, true, release), nil
}

// AcceptPath delegates to the wrapped listener's DATAGRAM acceptor.
func (l *DatagramListener) AcceptPath(ctx context.Context) (transport.PathConn, error) {
	path, err := l.listener.AcceptDatagram(ctx)
	if err != nil {
		return nil, err
	}
	return path, nil
}

// SessionKind reports that QUIC DATAGRAM paths are packet-only.
func (*DatagramListener) SessionKind() transport.PathSessionKind {
	return transport.PathSessionPacket
}

// Close delegates to the wrapped listener.
func (l *DatagramListener) Close() error { return l.listener.Close() }

// Addr delegates to the wrapped listener.
func (l *DatagramListener) Addr() net.Addr { return l.listener.Addr() }
