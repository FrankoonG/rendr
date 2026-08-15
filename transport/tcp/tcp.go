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

	"github.com/FrankoonG/rendr/internal/leafmobility"
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

var _ transport.PathQualityReader = (*PathConn)(nil)

// New returns a Transport ready for use.
func New() *Transport { return &Transport{} }

// DialPath dials a TCP socket and wraps it in a PathConn.
//
// Disables Go's default 15-second TCP keepalive (Dialer.KeepAlive < 0).
// Go since 1.13 calls SetKeepAlive(true)+SetKeepAlivePeriod(15s)
// after dial; on Linux that sets TCP_KEEPIDLE/INTVL to 15s, and
// combined with tcp_keepalive_probes=9 the kernel kills the socket
// after ~150s if keepalive ACKs aren't seen. Under bandwidth
// shaping (REG-T4 chaos baseline at 50 Mbps tbf) the ACKs queue
// behind data, the kernel falsely declares the socket dead at
// that exact mark, both paths die simultaneously, and the engine
// surfaces "migration budget exceeded" — a direct CLAUDE.md hard
// rule #1 violation. HEAD 1f89fc3 stderr trace confirmed this with
// "write tcp ... write: connection timed out" at ~2m17s.
//
// rendr's engine has its own protocol-layer liveness via PathProbe;
// kernel TCP keepalive is both redundant and harmful here.
func (*Transport) DialPath(ctx context.Context, spec transport.PathSpec) (transport.PathConn, error) {
	d := net.Dialer{KeepAlive: -1}
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
	// Belt-and-suspenders: hard-disable keepalive on the dialed socket.
	// Dialer.KeepAlive=-1 SHOULD suppress it but Go version behavior
	// has surprised us before.
	tc, ok := c.(*net.TCPConn)
	if !ok {
		_ = c.Close()
		return nil, fmt.Errorf("tcp: dial returned %T, want *net.TCPConn", c)
	}
	_ = tc.SetKeepAlive(false)
	return wrapOwned(tc, leafmobility.RoleDialer), nil
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
		endpoint: newEndpointOwner(c),
	}
}

func wrapOwned(c *net.TCPConn, role leafmobility.Role) *PathConn {
	path := Wrap(c)
	path.claim = newOwnedClaim(path.endpoint, role)
	path.refreshState = leafmobility.NewRefreshSourceState()
	path.refreshEmitter, _ = leafmobility.NewRefreshEmitterWithSourceState(path.claim, path.refreshState)
	return path
}

func (p *PathConn) LeafMobilityClaim() *leafmobility.Claim {
	if p == nil {
		return nil
	}
	return p.claim
}

// PathConn carries length-prefixed rendr frames over a single TCP socket.
type PathConn struct {
	endpoint *endpointOwner
	claim    *leafmobility.Claim

	refreshMu       sync.Mutex
	refreshState    *leafmobility.RefreshSourceState
	refreshEmitter  *leafmobility.RefreshEmitter
	refreshCallback func(leafmobility.RefreshEvidence)
	refreshMonitor  pathRefreshMonitor

	readMu  sync.Mutex // preserves partial frame state across endpoint maintenance
	writeMu sync.Mutex // serialises framed Writes

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

	deathMu        sync.Mutex
	deathFn        func(cause transport.DeathCause, err error)
	deathErr       error
	deathCause     transport.DeathCause
	deathReady     bool
	deathLocal     bool
	deathDelivered bool

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
	p.readMu.Lock()
	defer p.readMu.Unlock()

	var prefix [LengthPrefixSize]byte
	if err := p.readFull(prefix[:]); err != nil {
		p.declareDeath(err)
		return 0, p.swallow(err)
	}
	n := int(binary.BigEndian.Uint16(prefix[:]))
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
	if err := p.readFull(buf[:n]); err != nil {
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
	if err := p.writeFull(lp[:]); err != nil {
		p.declareDeath(err)
		return 0, p.swallow(err)
	}
	if err := p.writeFull(frame); err != nil {
		p.declareDeath(err)
		return 0, p.swallow(err)
	}
	p.writes.Add(1)
	return len(frame), nil
}

// Close shuts the socket. After Close, Read and Write return
// net.ErrClosed. Close idempotency: extra calls are no-ops.
func (p *PathConn) Close() error {
	p.stopRefreshMonitor()
	var closeErr error
	p.claim.RetireUnbound()
	if p.dead.CompareAndSwap(false, true) {
		closeErr = p.endpoint.close()
		p.publishTerminal(true, closeErr)
	}
	p.waitRefreshMonitor()
	return closeErr
}

// SubscribeLeafMobilityRefresh installs the engine's non-blocking factual
// refresh callback. The Linux implementation lazily starts one exact
// route/source monitor only after both peers negotiated the specialized
// operation; generic TCP paths pay no monitor cost.
func (p *PathConn) SubscribeLeafMobilityRefresh(ctx context.Context, fn func(leafmobility.RefreshEvidence)) (func(), error) {
	if p == nil || fn == nil {
		return nil, errors.New("tcp: invalid leaf mobility refresh subscriber")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.refreshMu.Lock()
	defer p.refreshMu.Unlock()
	if p.dead.Load() || p.refreshEmitter == nil {
		return nil, errors.New("tcp: leaf mobility refresh is unavailable")
	}
	if p.refreshCallback != nil || p.refreshMonitor != nil {
		return nil, errors.New("tcp: leaf mobility refresh subscriber already installed")
	}
	p.refreshCallback = fn
	monitor, err := newPathRefreshMonitor(ctx, p)
	if err != nil {
		p.refreshCallback = nil
		return nil, err
	}
	p.refreshMonitor = monitor
	var once sync.Once
	return func() {
		once.Do(func() {
			p.refreshMu.Lock()
			p.refreshCallback = nil
			monitor := p.refreshMonitor
			p.refreshMu.Unlock()
			if monitor != nil {
				monitor.Stop()
			}
		})
	}, nil
}

func (p *PathConn) CommitLeafMobilityRefresh(evidence leafmobility.RefreshEvidence) error {
	if p == nil || p.refreshState == nil {
		return errors.New("tcp: leaf mobility refresh state is unavailable")
	}
	p.refreshMu.Lock()
	monitor := p.refreshMonitor
	p.refreshMu.Unlock()
	if monitor == nil {
		return errors.New("tcp: leaf mobility refresh monitor is unavailable")
	}
	return p.refreshState.CommitCurrent(evidence, monitor.Commit)
}

// CloseWrite half-closes the underlying TCP write side when available.
// It intentionally does not mark the path dead: the read side may still
// need to consume peer control frames during graceful rendr shutdown.
func (p *PathConn) CloseWrite() error {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	write, err := p.endpoint.acquireWrite()
	if err != nil {
		return net.ErrClosed
	}
	if cw, ok := write.conn.(interface{ CloseWrite() error }); ok {
		err = cw.CloseWrite()
	}
	_ = write.finish(err, err == nil)
	return err
}

// Quality returns the most recent measurement.
func (p *PathConn) Quality() transport.PathQuality {
	p.qualityMu.RLock()
	defer p.qualityMu.RUnlock()
	return p.quality
}

// QualityContext exposes the prompt in-memory quality snapshot to engines that
// require an explicit cancellation contract.
func (p *PathConn) QualityContext(ctx context.Context) (transport.PathQuality, error) {
	if err := ctx.Err(); err != nil {
		return transport.PathQuality{}, err
	}
	return p.Quality(), nil
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
	if fn == nil {
		return
	}
	p.deathMu.Lock()
	if !p.deathReady {
		p.deathFn = fn
		p.deathMu.Unlock()
		return
	}
	if p.deathLocal || p.deathDelivered {
		p.deathMu.Unlock()
		return
	}
	p.deathDelivered = true
	cause, err := p.deathCause, p.deathErr
	p.deathMu.Unlock()
	go fn(cause, err)
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
	p.claim.RetireUnbound()
	if !p.dead.CompareAndSwap(false, true) {
		return
	}
	p.stopRefreshMonitor()
	_ = p.endpoint.close()
	p.publishTerminal(false, err)
}

func (p *PathConn) publishRefresh(reason leafmobility.RefreshReason, source leafmobility.RefreshSourceSnapshot) {
	p.refreshMu.Lock()
	emitter := p.refreshEmitter
	callback := p.refreshCallback
	p.refreshMu.Unlock()
	if emitter == nil || callback == nil {
		return
	}
	evidence, err := emitter.Observe(reason, source)
	if err != nil {
		return
	}
	callback(evidence)
}

func (p *PathConn) stopRefreshMonitor() {
	if p == nil {
		return
	}
	p.refreshMu.Lock()
	p.refreshCallback = nil
	monitor := p.refreshMonitor
	p.refreshMu.Unlock()
	if monitor != nil {
		monitor.Stop()
	}
}

func (p *PathConn) waitRefreshMonitor() {
	if p == nil {
		return
	}
	p.refreshMu.Lock()
	monitor := p.refreshMonitor
	p.refreshMu.Unlock()
	if monitor != nil {
		<-monitor.Done()
	}
}

func (p *PathConn) publishTerminal(local bool, err error) {
	if !local && err == nil {
		err = net.ErrClosed
	}
	cause := transport.CauseUnknown
	if !local {
		cause = p.classify(err)
	}
	p.deathMu.Lock()
	if p.deathReady {
		p.deathMu.Unlock()
		return
	}
	p.deathErr = err
	p.deathCause = cause
	p.deathReady = true
	p.deathLocal = local
	fn := p.deathFn
	p.deathFn = nil
	if local || fn == nil {
		p.deathMu.Unlock()
		return
	}
	p.deathDelivered = true
	p.deathMu.Unlock()
	fn(cause, err)
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
	local, _ := p.endpoint.addresses()
	if local != nil {
		return local.String()
	}
	return ""
}

// RemoteAddr returns the remote end of the wrapped socket.
func (p *PathConn) RemoteAddr() string {
	_, remote := p.endpoint.addresses()
	if remote != nil {
		return remote.String()
	}
	return ""
}

func (p *PathConn) readFull(buf []byte) error {
	for offset := 0; offset < len(buf); {
		read, err := p.endpoint.acquireRead()
		if err != nil {
			return err
		}
		n, readErr := read.conn.Read(buf[offset:])
		complete := n > 0 && offset+n >= len(buf)
		interrupted := read.finish(readErr, complete)
		if n > 0 {
			offset += n
		}
		if offset == len(buf) {
			return nil
		}
		if readErr != nil {
			if interrupted {
				continue
			}
			if !p.endpoint.markFailure(read.generation) {
				continue
			}
			return readErr
		}
		if n == 0 {
			return errors.New("tcp: endpoint read made no progress")
		}
	}
	return nil
}

func (p *PathConn) writeFull(buf []byte) error {
	for len(buf) > 0 {
		write, err := p.endpoint.acquireWrite()
		if err != nil {
			return err
		}
		n, writeErr := write.conn.Write(buf)
		complete := n > 0 && n >= len(buf)
		interrupted := write.finish(writeErr, complete)
		if n > 0 {
			buf = buf[n:]
		}
		if writeErr != nil {
			if interrupted {
				continue
			}
			if !p.endpoint.markFailure(write.generation) {
				continue
			}
			return writeErr
		}
		if n == 0 {
			return errors.New("tcp: endpoint write made no progress")
		}
	}
	return nil
}
