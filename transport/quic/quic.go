package quic

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	qg "github.com/quic-go/quic-go"

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

func init() {
	if err := transport.Default.Register(New()); err != nil {
		panic(err)
	}
}

// Name implements transport.Transport.
func (*Transport) Name() string { return "quic" }

// DialPath connects to spec.Address (host:port), completes the QUIC
// handshake, and opens a single bidirectional stream to carry rendr
// frames. The returned PathConn is the (Connection, Stream) pair.
func (t *Transport) DialPath(ctx context.Context, spec transport.PathSpec) (transport.PathConn, error) {
	cfg := t.ClientTLS
	if cfg == nil {
		_, ct, err := devTLSConfig()
		if err != nil {
			return nil, err
		}
		cfg = ct
	}

	conn, err := qg.DialAddr(ctx, spec.Address, cfg, &qg.Config{
		// Long enough to survive a brief migration window; engine
		// MigrationBudget is the higher-level cap.
		MaxIdleTimeout:  90 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
		EnableDatagrams: false,
	})
	if err != nil {
		return nil, fmt.Errorf("quic: dial %s: %w", spec.Address, err)
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(0, "open stream failed")
		return nil, fmt.Errorf("quic: open stream: %w", err)
	}
	return wrap(conn, stream, false), nil
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

// Accept wraps a server-accepted (connection, stream) pair. Used by
// the listener-side dispatcher (see rendr.ListenQUIC).
func Accept(conn *qg.Conn, stream *qg.Stream) *PathConn {
	return wrap(conn, stream, true)
}

func wrap(conn *qg.Conn, stream *qg.Stream, server bool) *PathConn {
	pc := &PathConn{
		conn:   conn,
		stream: stream,
		server: server,
	}
	go pc.watchConn()
	return pc
}

// PathConn implements transport.PathConn over a single QUIC stream.
type PathConn struct {
	conn   *qg.Conn
	stream *qg.Stream
	server bool

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
		return 0, io.ErrClosedPipe
	}

	var lp [LengthPrefixSize]byte
	binary.BigEndian.PutUint16(lp[:], uint16(len(frame)))
	if _, err := p.stream.Write(lp[:]); err != nil {
		p.declareDeath(err)
		return 0, io.ErrClosedPipe
	}
	n, err := p.stream.Write(frame)
	if err != nil {
		p.declareDeath(err)
		return n, io.ErrClosedPipe
	}
	return n, nil
}

// Close closes the stream then the underlying QUIC connection.
func (p *PathConn) Close() error {
	if !p.dead.CompareAndSwap(false, true) {
		return nil
	}
	_ = p.stream.Close()
	err := p.conn.CloseWithError(0, "rendr local close")
	p.deathMu.Lock()
	p.deathErr = err
	p.deathFn = nil
	p.deathMu.Unlock()
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
	cause := p.conn.Context().Err()
	if cause == context.Canceled {
		cause = nil
	}
	p.declareDeath(cause)
}

func (p *PathConn) classify(err error) transport.DeathCause {
	return transport.Classify(err, p.quiesced.Load(), p.byeSeen.Load())
}

func (p *PathConn) declareDeath(err error) {
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
	if fn != nil {
		fn(p.classify(err), err)
	}
}

func (p *PathConn) swallow(err error) error {
	if errors.Is(err, io.EOF) && p.byeSeen.Load() {
		return io.EOF
	}
	return io.ErrClosedPipe
}
