package quic

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	qg "github.com/quic-go/quic-go"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/internal/udpsocket"
	"github.com/FrankoonG/rendr/transport"
)

// LengthPrefixSize and MaxFrameSize match the TCP adapter so the
// proto.Frame envelope is wire-identical regardless of transport.
const LengthPrefixSize = 2
const MaxFrameSize = 1<<16 - 1

// Transport is the QUIC adapter. It owns a tls.Config but no other
// per-call state; each DialPath opens a fresh QUIC connection.
type Transport struct {
	ClientTLS *tls.Config
}

// New returns a Transport using the dev TLS config. Production code
// should construct &Transport{ClientTLS: ...} explicitly.
func New() *Transport {
	_, ct, err := devTLSConfig()
	if err != nil {
		panic(fmt.Sprintf("quic: dev TLS init failed: %v", err))
	}
	return &Transport{ClientTLS: ct}
}

// DefaultUDPBufferBytes is the SO_RCVBUF / SO_SNDBUF target the QUIC
// adapter applies to every UDP socket it opens. 8 MiB is what
// G3 100k-pps DATAGRAM validation needed on Linux; smaller defaults
// (e.g. 208 KiB on stock Ubuntu) drop frames under high pps load.
// The set is best-effort: the kernel may clamp to net.core.rmem_max,
// and on platforms without setsockopt buffer support the calls
// silently no-op. To raise the kernel cap on Linux:
//
//	sysctl -w net.core.rmem_max=8388608 net.core.wmem_max=8388608
const DefaultUDPBufferBytes = 8 * 1024 * 1024

// udpSocketWithBuffers opens an evidence-driven UDP socket. The PacketConn
// view lets rendr enforce active/fallback selection before quic-go inspects
// the underlying descriptor.
func udpSocketWithBuffers(ctx context.Context, laddr *net.UDPAddr) (*udpsocket.Socket, error) {
	return udpsocket.Listen(ctx, udpsocket.Config{
		Network: "udp", LocalAddr: laddr, BufferBytes: DefaultUDPBufferBytes,
	})
}

// DialPath connects to spec.Address (host:port), completes the QUIC
// handshake, and opens a single bidirectional stream to carry rendr
// frames. The returned PathConn is the (Connection, Stream) pair.
//
// The adapter sets SO_RCVBUF/SO_SNDBUF on the underlying UDP socket
// to DefaultUDPBufferBytes (8 MiB) so the QUIC DATAGRAM receive
// queue can absorb burst loads (G3 100k-pps validation requirement).
//
// spec.Opts recognised keys:
//
//	server_name    TLS SNI override
//	alpn           comma-separated ALPN list override
//	insecure       "true" -> tls.Config.InsecureSkipVerify (dev only)
//	ca_pem         inline PEM root certificate bundle
//	mode           "datagram" -> use QUIC DATAGRAM frames instead
//	               of a bidi stream (RFC 9221). Per-frame ceiling is
//	               quic.MaxDatagramFrame. Pair with engine packet
//	               mode for opaque-UDP-style apps; not suitable for
//	               stream-mode rendr.
func (t *Transport) DialPath(ctx context.Context, spec transport.PathSpec) (transport.PathConn, error) {
	base := t.ClientTLS
	if base == nil {
		_, ct, err := devTLSConfig()
		if err != nil {
			return nil, err
		}
		base = ct
	}
	cfg, err := applyOptsToTLS(base, spec.Opts)
	if err != nil {
		return nil, err
	}

	useDatagram := spec.Opts["mode"] == "datagram"
	raddr, err := net.ResolveUDPAddr("udp", spec.Address)
	if err != nil {
		return nil, fmt.Errorf("quic: resolve %s: %w", spec.Address, err)
	}
	udpSocket, err := udpSocketWithBuffers(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("quic: udp listen: %w", err)
	}
	tr := &qg.Transport{Conn: udpSocket.PacketConn()}
	release := sync.OnceFunc(func() {
		_ = tr.Close()
		_ = udpSocket.Close()
	})
	conn, err := tr.Dial(ctx, raddr, cfg, &qg.Config{
		MaxIdleTimeout:  90 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
		EnableDatagrams: useDatagram,
	})
	if err != nil {
		release()
		return nil, fmt.Errorf("quic: dial %s: %w", spec.Address, err)
	}
	if useDatagram {
		return wrapDatagram(conn, false, release, leafmobility.RoleDialer, udpSocket), nil
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(0, "open stream failed")
		release()
		return nil, fmt.Errorf("quic: open stream: %w", err)
	}
	return wrap(conn, stream, false, release, leafmobility.RoleDialer, udpSocket), nil
}

// Probe times the handshake + first-stream open as a coarse RTT
// estimate. M6 will swap this for a cheap echo.
func (t *Transport) Probe(ctx context.Context, spec transport.PathSpec) (transport.PathQuality, error) {
	start := time.Now()
	pc, err := t.DialPath(ctx, spec)
	if err != nil {
		return transport.PathQuality{}, err
	}
	rtt := time.Since(start)
	_ = pc.Close()
	return transport.PathQuality{RTT: rtt, At: time.Now()}, nil
}

// Accept wraps an externally accepted (connection, stream) pair. It does not
// grant adapter ownership; Listener uses the private owned wrapper instead.
func Accept(conn *qg.Conn, stream *qg.Stream) *PathConn {
	return wrap(conn, stream, true, nil, leafmobility.RoleUnknown, nil)
}

func wrap(
	conn *qg.Conn,
	stream *qg.Stream,
	server bool,
	release func(),
	role leafmobility.Role,
	udpSocket *udpsocket.Socket,
) *PathConn {
	pc := &PathConn{
		conn: conn, stream: stream, server: server, release: release,
		udpSocket: udpSocket,
	}
	if role != leafmobility.RoleUnknown {
		pc.claim = leafmobility.MustNewClaim(leafmobility.Facts{
			Kind:       leafmobility.KindQUIC,
			Role:       role,
			Scope:      leafmobility.ScopeEndpoint,
			Session:    leafmobility.SessionAny,
			Generation: leafmobility.NextGeneration(),
		})
	}
	go pc.watchConn()
	return pc
}

// PathConn implements transport.PathConn over a single QUIC stream.
type PathConn struct {
	conn      *qg.Conn
	stream    *qg.Stream
	server    bool
	release   func()
	claim     *leafmobility.Claim
	udpSocket *udpsocket.Socket

	writeMu sync.Mutex
	readBuf [LengthPrefixSize]byte

	qualityMu sync.RWMutex
	quality   transport.PathQuality

	dead     atomic.Bool
	byeSeen  atomic.Bool
	quiesced atomic.Bool

	deathMu  sync.Mutex
	deathFn  func(cause transport.DeathCause, err error)
	deathErr error
}

var _ transport.DatagramAccelerationObserver = (*PathConn)(nil)

func (p *PathConn) LeafMobilityClaim() *leafmobility.Claim {
	if p == nil {
		return nil
	}
	return p.claim
}

func (p *PathConn) DatagramAccelerationStatus() transport.DatagramAccelerationStatus {
	if p == nil || p.udpSocket == nil {
		return transport.DatagramAccelerationStatus{}
	}
	return p.udpSocket.DatagramAccelerationStatus()
}

// Read returns one framed payload+header concatenated.
// (See the TCP adapter for the contract.)
func (p *PathConn) Read(buf []byte) (int, error) {
	if _, err := io.ReadFull(p.stream, p.readBuf[:]); err != nil {
		p.declareDeath(err)
		return 0, p.swallow(err)
	}
	n := int(binary.BigEndian.Uint16(p.readBuf[:]))
	if n == 0 {
		p.declareDeath(errors.New("quic: zero-length frame"))
		return 0, io.ErrUnexpectedEOF
	}
	if n > MaxFrameSize {
		p.declareDeath(fmt.Errorf("quic: oversize frame %d", n))
		return 0, io.ErrUnexpectedEOF
	}
	if len(buf) < n {
		p.declareDeath(fmt.Errorf("quic: read buf %d < frame %d", len(buf), n))
		return 0, io.ErrUnexpectedEOF
	}
	if _, err := io.ReadFull(p.stream, buf[:n]); err != nil {
		p.declareDeath(err)
		return 0, p.swallow(err)
	}
	return n, nil
}

// Write frames buf with 2-byte length prefix and pushes it.
func (p *PathConn) Write(frame []byte) (int, error) {
	if len(frame) == 0 || len(frame) > MaxFrameSize {
		return 0, fmt.Errorf("quic: frame size %d out of range", len(frame))
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if p.dead.Load() {
		return 0, net.ErrClosed
	}

	var lp [LengthPrefixSize]byte
	binary.BigEndian.PutUint16(lp[:], uint16(len(frame)))
	if _, err := p.stream.Write(lp[:]); err != nil {
		p.declareDeath(err)
		return 0, net.ErrClosed
	}
	n, err := p.stream.Write(frame)
	if err != nil {
		p.declareDeath(err)
		return n, net.ErrClosed
	}
	return n, nil
}

// Close closes the stream and synchronously completes quic-go's local
// connection close before releasing the owned transport and UDP socket.
func (p *PathConn) Close() error {
	p.claim.RetireUnbound()
	if !p.dead.CompareAndSwap(false, true) {
		return nil
	}
	_ = p.stream.Close()
	err := p.conn.CloseWithError(0, "rendr local close")
	p.deathMu.Lock()
	p.deathErr = err
	p.deathFn = nil
	p.deathMu.Unlock()
	p.releaseRetention()
	return err
}

// Quality / SetQuality / MarkByeSeen / MarkQuiesced mirror the TCP
// adapter exactly so the engine can use the same interface.
func (p *PathConn) Quality() transport.PathQuality {
	p.qualityMu.RLock()
	defer p.qualityMu.RUnlock()
	return p.quality
}

func (p *PathConn) SetQuality(q transport.PathQuality) {
	p.qualityMu.Lock()
	p.quality = q
	p.qualityMu.Unlock()
}

func (p *PathConn) OnDeath(fn func(cause transport.DeathCause, err error)) {
	p.deathMu.Lock()
	defer p.deathMu.Unlock()
	if p.dead.Load() {
		go fn(p.classify(p.deathErr), p.deathErr)
		return
	}
	p.deathFn = fn
}

func (p *PathConn) MarkByeSeen()  { p.byeSeen.Store(true) }
func (p *PathConn) MarkQuiesced() { p.quiesced.Store(true) }
func (p *PathConn) LocalAddr() string {
	if a := p.conn.LocalAddr(); a != nil {
		return a.String()
	}
	return ""
}
func (p *PathConn) RemoteAddr() string {
	if a := p.conn.RemoteAddr(); a != nil {
		return a.String()
	}
	return ""
}

// watchConn observes the QUIC connection's context: if it dies for
// any reason (idle, application close, network) we report death so
// the engine can migrate.
func (p *PathConn) watchConn() {
	<-p.conn.Context().Done()
	cause := context.Cause(p.conn.Context())
	if cause == context.Canceled {
		cause = nil
	}
	p.declareDeath(cause)
}

func (p *PathConn) classify(err error) transport.DeathCause {
	return transport.Classify(err, p.quiesced.Load(), p.byeSeen.Load())
}

func (p *PathConn) declareDeath(err error) {
	p.claim.RetireUnbound()
	if !p.dead.CompareAndSwap(false, true) {
		return
	}
	_ = p.stream.Close()
	_ = p.conn.CloseWithError(0, "")
	p.deathMu.Lock()
	p.deathErr = err
	fn := p.deathFn
	p.deathFn = nil
	p.deathMu.Unlock()
	p.releaseRetention()
	if fn != nil {
		fn(p.classify(err), err)
	}
}

func (p *PathConn) releaseRetention() {
	if p.release != nil {
		p.release()
	}
}

func (p *PathConn) swallow(err error) error {
	if errors.Is(err, io.EOF) && p.byeSeen.Load() {
		return io.EOF
	}
	return net.ErrClosed
}
