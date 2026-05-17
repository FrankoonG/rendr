package tcp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/transport"
)

// LengthPrefixSize is the on-wire size of the per-frame length prefix.
const LengthPrefixSize = 2

// MaxFrameSize bounds a single framed unit (header+payload). 64 KiB
// is enough for any reasonable proto v0 frame and matches the max a
// 16-bit length can encode.
const MaxFrameSize = 1<<16 - 1

// Transport is the TCP adapter. It carries no state across DialPath
// calls; each call yields an independent PathConn.
type Transport struct{}

// New returns a Transport ready for use.
func New() *Transport { return &Transport{} }

func init() {
	if err := transport.Default.Register(New()); err != nil {
		// Duplicate registration is a programming error in init() chains.
		panic(err)
	}
}

// Name implements transport.Transport.
func (*Transport) Name() string { return "tcp" }

// DialPath dials a TCP socket and wraps it in a PathConn.
func (*Transport) DialPath(ctx context.Context, spec transport.PathSpec) (transport.PathConn, error) {
	d := net.Dialer{}
	if spec.Local != "" {
		la, err := net.ResolveTCPAddr("tcp", spec.Local)
		if err != nil {
			return nil, fmt.Errorf("tcp: bad local %q: %w", spec.Local, err)
		}
		d.LocalAddr = la
	}
	c, err := d.DialContext(ctx, "tcp", spec.Address)
	if err != nil {
		return nil, fmt.Errorf("tcp: dial %s: %w", spec.Address, err)
	}
	return Wrap(c), nil
}

// Probe dials, captures handshake RTT, and closes. M1 placeholder;
// M6 will swap this for a cheap echo.
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

// Wrap promotes an existing net.Conn (e.g. accepted from a listener)
// to a PathConn. Used by the Listener side.
func Wrap(c net.Conn) *PathConn {
	return &PathConn{
		c: c,
	}
}

// PathConn carries length-prefixed rendr frames over a single TCP socket.
type PathConn struct {
	c net.Conn

	writeMu sync.Mutex // serialises framed Writes
	readBuf [LengthPrefixSize]byte

	// quality is set by the engine via SetQuality; M1 keeps it static.
	qualityMu sync.RWMutex
	quality   transport.PathQuality

	// dead is set the first time the path is declared dead.
	dead atomic.Bool
	// byeSeen flips on inbound BYE so a subsequent Read EOF is classified
	// CleanClose. Set externally by the engine.
	byeSeen atomic.Bool
	// quiesced is set by the engine after the local side has finished
	// sending; used by Classify on the read side.
	quiesced atomic.Bool

	deathMu  sync.Mutex
	deathFn  func(cause transport.DeathCause, err error)
	deathErr error

	// Frame counters for diagnostics / race-mode tests.
	writes atomic.Uint64
	reads  atomic.Uint64
}

// Writes returns the cumulative count of successful Write calls
// that put a framed unit on the wire.
func (p *PathConn) Writes() uint64 { return p.writes.Load() }

// Reads returns the cumulative count of successful Read calls
// (one per inbound framed unit).
func (p *PathConn) Reads() uint64 { return p.reads.Load() }

// Read returns one framed payload+header concatenated. Callers parse
// the first 8 bytes as a proto.Header and the rest as payload.
//
// Hard rule #1 detail: any non-EOF read error is wrapped into a
// single net.ErrClosed surface; the cause is delivered via OnDeath.
// Returning the raw socket error would leak transport state into the
// application.
func (p *PathConn) Read(buf []byte) (int, error) {
	if _, err := io.ReadFull(p.c, p.readBuf[:]); err != nil {
		p.declareDeath(err)
		return 0, p.swallow(err)
	}
	n := int(binary.BigEndian.Uint16(p.readBuf[:]))
	if n == 0 {
		// Zero-length framed unit is a protocol error; declare death.
		err := errors.New("tcp: zero-length frame")
		p.declareDeath(err)
		return 0, net.ErrClosed
	}
	if n > MaxFrameSize {
		err := fmt.Errorf("tcp: oversize frame %d > %d", n, MaxFrameSize)
		p.declareDeath(err)
		return 0, net.ErrClosed
	}
	if len(buf) < n {
		err := fmt.Errorf("tcp: read buf %d < frame %d", len(buf), n)
		p.declareDeath(err)
		return 0, net.ErrClosed
	}
	if _, err := io.ReadFull(p.c, buf[:n]); err != nil {
		p.declareDeath(err)
		return 0, p.swallow(err)
	}
	p.reads.Add(1)
	return n, nil
}

// Write frames buf (which must already be header+payload) with a
// 2-byte length prefix and sends it. Concurrent Writes are
// serialised so a frame is never interleaved with another.
func (p *PathConn) Write(frame []byte) (int, error) {
	if len(frame) == 0 || len(frame) > MaxFrameSize {
		return 0, fmt.Errorf("tcp: frame size %d out of range (1..%d)", len(frame), MaxFrameSize)
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()

	if p.dead.Load() {
		return 0, net.ErrClosed
	}

	var lp [LengthPrefixSize]byte
	binary.BigEndian.PutUint16(lp[:], uint16(len(frame)))
	if _, err := p.c.Write(lp[:]); err != nil {
		p.declareDeath(err)
		return 0, p.swallow(err)
	}
	n, err := p.c.Write(frame)
	if err != nil {
		p.declareDeath(err)
		return n, p.swallow(err)
	}
	p.writes.Add(1)
	return n, nil
}

// Close shuts the socket. After Close, Read and Write return
// net.ErrClosed. Close idempotency: extra calls are no-ops.
func (p *PathConn) Close() error {
	if p.dead.CompareAndSwap(false, true) {
		err := p.c.Close()
		p.deathMu.Lock()
		p.deathErr = err
		fn := p.deathFn
		// Only fire callback for non-locally-initiated deaths. Local
		// Close intentionally does not deliver OnDeath - the engine
		// already knows it triggered the teardown.
		p.deathFn = nil
		p.deathMu.Unlock()
		_ = fn
		return err
	}
	return nil
}

// Quality returns the most recent measurement.
func (p *PathConn) Quality() transport.PathQuality {
	p.qualityMu.RLock()
	defer p.qualityMu.RUnlock()
	return p.quality
}

// SetQuality is invoked by the engine when a new measurement is
// available. M1 only writes static values here; M6 will probe.
func (p *PathConn) SetQuality(q transport.PathQuality) {
	p.qualityMu.Lock()
	p.quality = q
	p.qualityMu.Unlock()
}

// OnDeath registers a callback. The callback fires at most once.
func (p *PathConn) OnDeath(fn func(cause transport.DeathCause, err error)) {
	p.deathMu.Lock()
	defer p.deathMu.Unlock()
	if p.dead.Load() {
		// Already dead; fire immediately so the engine still gets notified.
		go fn(p.classify(p.deathErr), p.deathErr)
		return
	}
	p.deathFn = fn
}

// MarkByeSeen records that an inbound BYE control frame was observed,
// so a subsequent peer-side close is classified as CleanClose.
func (p *PathConn) MarkByeSeen() { p.byeSeen.Store(true) }

// MarkQuiesced records that the local side has finished sending. An
// io.EOF after this point is CleanClose.
func (p *PathConn) MarkQuiesced() { p.quiesced.Store(true) }

func (p *PathConn) classify(err error) transport.DeathCause {
	return transport.Classify(err, p.quiesced.Load(), p.byeSeen.Load())
}

func (p *PathConn) declareDeath(err error) {
	if !p.dead.CompareAndSwap(false, true) {
		return
	}
	_ = p.c.Close()
	p.deathMu.Lock()
	p.deathErr = err
	fn := p.deathFn
	p.deathFn = nil
	p.deathMu.Unlock()
	if fn != nil {
		fn(p.classify(err), err)
	}
}

// swallow converts a raw socket error into the muted Read/Write
// return value the application sees. The underlying error is
// preserved for OnDeath only.
func (p *PathConn) swallow(err error) error {
	if errors.Is(err, io.EOF) && p.byeSeen.Load() {
		return io.EOF
	}
	return net.ErrClosed
}

// LocalAddr returns the local end of the wrapped socket.
func (p *PathConn) LocalAddr() string {
	if a := p.c.LocalAddr(); a != nil {
		return a.String()
	}
	return ""
}

// RemoteAddr returns the remote end of the wrapped socket.
func (p *PathConn) RemoteAddr() string {
	if a := p.c.RemoteAddr(); a != nil {
		return a.String()
	}
	return ""
}
