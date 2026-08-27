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

	qg "github.com/FrankoonG/quic-go"
	"github.com/FrankoonG/quic-go/qlogwriter"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/internal/udpsocket"
	"github.com/FrankoonG/rendr/transport"
)

// LengthPrefixSize and MaxFrameSize match the TCP adapter so the
// proto.Frame envelope is wire-identical regardless of transport.
const LengthPrefixSize = 2

var _ transport.PathQualityReader = (*PathConn)(nil)

const MaxFrameSize = 1<<16 - 1

// Transport is the QUIC adapter. ClientTLS and Tracer are shared
// configuration; each DialPath opens a fresh QUIC connection.
type Transport struct {
	ClientTLS *tls.Config
	// Tracer enables standard quic-go connection tracing. quic-go invokes it
	// once for each connection; the resulting trace remains attached while that
	// connection changes paths and connection IDs. It is observational only.
	Tracer func(context.Context, bool, qg.ConnectionID) qlogwriter.Trace
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
	return udpSocketWithBuffersPinned(ctx, laddr, false)
}

func udpSocketWithBuffersPinned(ctx context.Context, laddr *net.UDPAddr, pinSource bool) (*udpsocket.Socket, error) {
	return udpsocket.Listen(ctx, udpsocket.Config{
		Network: "udp", LocalAddr: laddr, BufferBytes: DefaultUDPBufferBytes, PinSource: pinSource,
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
	var local *net.UDPAddr
	if spec.Local != "" {
		local, err = net.ResolveUDPAddr("udp", spec.Local)
		if err != nil {
			return nil, fmt.Errorf("quic: resolve local %s: %w", spec.Local, err)
		}
	}
	baseline, _ := observeRouteSource(ctx, raddr)
	if local == nil && baseline.valid() {
		local = baseline.source
	}
	active, err := openCIDTransport(ctx, local)
	if err != nil {
		return nil, fmt.Errorf("quic: udp listen: %w", err)
	}
	conn, err := active.transport.Dial(ctx, raddr, cfg, &qg.Config{
		MaxIdleTimeout:  90 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
		EnableDatagrams: useDatagram,
		Tracer:          t.Tracer,
	})
	if err != nil {
		_ = active.close()
		return nil, fmt.Errorf("quic: dial %s: %w", spec.Address, err)
	}
	session := leafmobility.SessionAny
	if useDatagram {
		session = leafmobility.SessionPacket
	}
	owner, err := newRealCIDOwner(conn, leafmobility.RoleDialer, session, active, baseline, nil)
	if err != nil {
		_ = conn.CloseWithError(0, "initialize CID owner failed")
		_ = active.close()
		return nil, err
	}
	if useDatagram {
		return wrapDatagram(conn, false, owner), nil
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(0, "open stream failed")
		_ = owner.releaseResources()
		return nil, fmt.Errorf("quic: open stream: %w", err)
	}
	return wrap(conn, stream, false, owner), nil
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
	return wrap(conn, stream, true, nil)
}

func wrap(
	conn *qg.Conn,
	stream *qg.Stream,
	server bool,
	owner *cidOwner,
) *PathConn {
	pc := &PathConn{
		conn: conn, stream: stream, server: server, owner: owner,
	}
	if owner != nil {
		pc.claim = owner.claim
	}
	go pc.watchConn()
	return pc
}

type quicStream interface {
	io.Reader
	io.Writer
	Close() error
}

// PathConn implements transport.PathConn over a single QUIC stream.
type PathConn struct {
	conn   *qg.Conn
	stream quicStream
	server bool
	owner  *cidOwner
	claim  *leafmobility.Claim

	readMu   sync.Mutex
	writeMu  sync.Mutex
	writeBuf []byte

	qualityMu sync.RWMutex
	quality   transport.PathQuality

	dead     atomic.Bool
	byeSeen  atomic.Bool
	quiesced atomic.Bool

	deathMu  sync.Mutex
	deathFn  func(cause transport.DeathCause, err error)
	deathErr error
}

// MaxFrameSize reports the largest complete rendr frame accepted by one QUIC
// stream record. Packet sessions use this contract; stream sessions ignore it.
func (*PathConn) MaxFrameSize() int { return MaxFrameSize }

var _ transport.DatagramAccelerationObserver = (*PathConn)(nil)
var _ transport.OwnedFrameReader = (*PathConn)(nil)

func (p *PathConn) LeafMobilityClaim() *leafmobility.Claim {
	if p == nil {
		return nil
	}
	return p.claim
}

func (p *PathConn) DatagramAccelerationStatus() transport.DatagramAccelerationStatus {
	if p == nil || p.owner == nil {
		return transport.DatagramAccelerationStatus{}
	}
	return p.owner.accelerationStatus()
}

// Read delegates framing to ReadOwnedFrame, then copies one complete frame to
// the caller. A short destination consumes exactly that frame and reports the
// standard packet-shaped short-buffer result without killing the QUIC path.
func (p *PathConn) Read(buf []byte) (int, error) {
	frame, err := p.ReadOwnedFrame()
	if err != nil {
		return 0, err
	}
	if len(buf) < len(frame) {
		copy(buf, frame)
		return len(buf), io.ErrShortBuffer
	}
	return copy(buf, frame), nil
}

// ReadOwnedFrame serializes access to the QUIC stream framing boundary,
// allocates one exact immutable frame, and reads the payload directly into
// that allocation. Ownership transfers to the caller.
func (p *PathConn) ReadOwnedFrame() ([]byte, error) {
	p.readMu.Lock()
	defer p.readMu.Unlock()
	if p.dead.Load() {
		return nil, net.ErrClosed
	}
	var prefix [LengthPrefixSize]byte
	if _, err := io.ReadFull(p.stream, prefix[:]); err != nil {
		p.declareDeath(err)
		return nil, p.swallow(err)
	}
	n := int(binary.BigEndian.Uint16(prefix[:]))
	if n == 0 {
		p.declareDeath(errors.New("quic: zero-length frame"))
		return nil, io.ErrUnexpectedEOF
	}
	if n > MaxFrameSize {
		p.declareDeath(fmt.Errorf("quic: oversize frame %d", n))
		return nil, io.ErrUnexpectedEOF
	}
	frame := make([]byte, n)
	if _, err := io.ReadFull(p.stream, frame); err != nil {
		p.declareDeath(err)
		return nil, p.swallow(err)
	}
	return frame, nil
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

	total := LengthPrefixSize + len(frame)
	if cap(p.writeBuf) < total {
		p.writeBuf = make([]byte, total)
	} else {
		p.writeBuf = p.writeBuf[:total]
	}
	binary.BigEndian.PutUint16(p.writeBuf[:LengthPrefixSize], uint16(len(frame)))
	copy(p.writeBuf[LengthPrefixSize:], frame)
	n, err := p.stream.Write(p.writeBuf)
	if err == nil && n != total {
		err = io.ErrShortWrite
	}
	if err != nil {
		p.declareDeath(err)
		payloadWritten := n - LengthPrefixSize
		if payloadWritten < 0 {
			payloadWritten = 0
		}
		if payloadWritten > len(frame) {
			payloadWritten = len(frame)
		}
		return payloadWritten, net.ErrClosed
	}
	return len(frame), nil
}

// Close closes the stream and synchronously completes quic-go's local
// connection close before releasing the owned transport and UDP socket.
func (p *PathConn) Close() error {
	p.claim.RetireUnbound()
	if !p.dead.CompareAndSwap(false, true) {
		return p.releaseRetention()
	}
	if p.stream != nil {
		_ = p.stream.Close()
	}
	var err error
	if p.conn != nil {
		err = p.conn.CloseWithError(0, "rendr local close")
	}
	p.deathMu.Lock()
	p.deathErr = err
	p.deathFn = nil
	p.deathMu.Unlock()
	return errors.Join(err, p.releaseRetention())
}

// Quality / SetQuality / MarkByeSeen / MarkQuiesced mirror the TCP
// adapter exactly so the engine can use the same interface.
func (p *PathConn) Quality() transport.PathQuality {
	p.qualityMu.RLock()
	defer p.qualityMu.RUnlock()
	return p.quality
}

func (p *PathConn) QualityContext(ctx context.Context) (transport.PathQuality, error) {
	if err := ctx.Err(); err != nil {
		return transport.PathQuality{}, err
	}
	return p.Quality(), nil
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
	if p.owner != nil {
		p.owner.mu.Lock()
		active := p.owner.active
		p.owner.mu.Unlock()
		return addrString(active.localAddr())
	}
	if a := p.conn.LocalAddr(); a != nil {
		return a.String()
	}
	return ""
}
func (p *PathConn) RemoteAddr() string {
	if p.owner != nil {
		p.owner.mu.Lock()
		remote := cloneUDPAddr(p.owner.remote)
		p.owner.mu.Unlock()
		return addrString(remote)
	}
	if a := p.conn.RemoteAddr(); a != nil {
		return a.String()
	}
	return ""
}

var _ transport.PacketPathConn = (*PathConn)(nil)

// watchConn observes the QUIC connection's context: if it dies for
// any reason (idle, application close, network) we report death so
// the engine can migrate.
func (p *PathConn) watchConn() {
	<-p.conn.Context().Done()
	p.declareDeath(connectionDeathCause(p.conn.Context()))
}

func connectionDeathCause(ctx context.Context) error {
	cause := context.Cause(ctx)
	if cause == context.Canceled {
		return nil
	}
	return cause
}

func (p *PathConn) classify(err error) transport.DeathCause {
	return transport.Classify(err, p.quiesced.Load(), p.byeSeen.Load())
}

func (p *PathConn) declareDeath(err error) {
	p.claim.RetireUnbound()
	if !p.dead.CompareAndSwap(false, true) {
		return
	}
	if p.stream != nil {
		_ = p.stream.Close()
	}
	if p.conn != nil {
		_ = p.conn.CloseWithError(0, "")
	}
	p.deathMu.Lock()
	p.deathErr = err
	fn := p.deathFn
	p.deathFn = nil
	p.deathMu.Unlock()
	_ = p.releaseRetention()
	if fn != nil {
		fn(p.classify(err), err)
	}
}

func (p *PathConn) releaseRetention() error {
	if p.owner == nil {
		return nil
	}
	return p.owner.releaseResources()
}

func (p *PathConn) SubscribeLeafMobilityRefresh(
	ctx context.Context,
	fn func(leafmobility.RefreshEvidence),
) (func(), error) {
	if p == nil || p.owner == nil {
		return nil, errors.New("quic: CID refresh is unavailable")
	}
	return p.owner.subscribeRefresh(ctx, fn)
}

func (p *PathConn) CommitLeafMobilityRefresh(evidence leafmobility.RefreshEvidence) error {
	if p == nil || p.owner == nil {
		return errors.New("quic: CID refresh is unavailable")
	}
	return p.owner.commitRefresh(evidence)
}

func (p *PathConn) swallow(err error) error {
	if errors.Is(err, io.EOF) && p.byeSeen.Load() {
		return io.EOF
	}
	return net.ErrClosed
}
