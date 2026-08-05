package quic

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	qg "github.com/quic-go/quic-go"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/transport"
)

// MaxDatagramFrame is the largest single rendr frame the DATAGRAM
// variant will pass through. QUIC DATAGRAM is bounded by path MTU
// minus QUIC + UDP/IP headers; ~1200 bytes is the typical safe
// ceiling. Larger frames must use the stream-mode adapter.
const MaxDatagramFrame = 1200

// datagramIngressQueueLen decouples quic-go's small internal DATAGRAM
// receive queue from engine framing and reorder work. quic-go intentionally
// drops incoming DATAGRAMs when its 128-entry queue is full; a dedicated pump
// keeps that queue draining while this bounded queue absorbs scheduler and GC
// stalls. At MaxDatagramFrame, the retained payload bound is about 2.4 MiB per
// path, plus slice overhead.
const datagramIngressQueueLen = 2048

// datagramPathConn is the DATAGRAM-mode QUIC PathConn. It transports
// rendr frames over QUIC DATAGRAM frames (RFC 9221) instead of a
// bidirectional stream. Use when the rendr engine is in packet mode
// and per-frame loss is acceptable (the engine's reorder buffer
// still tries to serialise, so heavy loss will stall it; this is a
// per-deployment tradeoff).
//
// Wire shape: one DATAGRAM frame == one rendr frame. No length
// prefix - the DATAGRAM boundary IS the frame boundary.
type datagramPathConn struct {
	conn    *qg.Conn
	server  bool
	recvQ   chan []byte
	release func()
	claim   *leafmobility.Claim

	writeMu sync.Mutex

	qualityMu sync.RWMutex
	quality   transport.PathQuality

	reads   atomic.Uint64
	writes  atomic.Uint64
	recvHWM atomic.Uint64

	dead     atomic.Bool
	byeSeen  atomic.Bool
	quiesced atomic.Bool

	deathMu  sync.Mutex
	deathFn  func(cause transport.DeathCause, err error)
	deathErr error
}

// wrapDatagram wraps a freshly-negotiated DATAGRAM-capable QUIC
// connection. EnableDatagrams MUST have been true on both sides for
// the wrapped conn's SendDatagram/ReceiveDatagram calls to work.
func wrapDatagram(conn *qg.Conn, server bool, release func(), role leafmobility.Role) *datagramPathConn {
	p := &datagramPathConn{
		conn:    conn,
		server:  server,
		recvQ:   make(chan []byte, datagramIngressQueueLen),
		release: release,
	}
	if role != leafmobility.RoleUnknown {
		p.claim = leafmobility.MustNewClaim(leafmobility.Facts{
			Kind:       leafmobility.KindQUIC,
			Role:       role,
			Scope:      leafmobility.ScopeEndpoint,
			Session:    leafmobility.SessionPacket,
			Generation: leafmobility.NextGeneration(),
		})
	}
	go p.pumpDatagrams()
	go p.watchConn()
	return p
}

// AcceptDatagram wraps an externally accepted DATAGRAM-capable connection and
// does not grant adapter ownership.
func AcceptDatagram(conn *qg.Conn) *datagramPathConn {
	return wrapDatagram(conn, true, nil, leafmobility.RoleUnknown)
}

func (p *datagramPathConn) LeafMobilityClaim() *leafmobility.Claim {
	if p == nil {
		return nil
	}
	return p.claim
}

// Read pops one DATAGRAM and copies into buf. If buf is smaller than
// the datagram, the result is truncated (standard PacketConn-style
// semantics) and io.ErrShortBuffer is returned.
func (p *datagramPathConn) Read(buf []byte) (int, error) {
	data, err := p.ReadOwnedFrame()
	if err != nil {
		return 0, err
	}
	if len(buf) < len(data) {
		copy(buf, data)
		return len(buf), io.ErrShortBuffer
	}
	return copy(buf, data), nil
}

// ReadOwnedFrame transfers the immutable allocation returned by quic-go to
// the engine. This avoids copying every high-rate DATAGRAM through an
// intermediate PathConn.Read buffer before it enters the reorder pipeline.
func (p *datagramPathConn) ReadOwnedFrame() ([]byte, error) {
	if p.dead.Load() {
		return nil, net.ErrClosed
	}
	data, ok := <-p.recvQ
	if !ok {
		p.deathMu.Lock()
		err := p.deathErr
		p.deathMu.Unlock()
		return nil, p.swallow(err)
	}
	p.reads.Add(1)
	return data, nil
}

func (p *datagramPathConn) pumpDatagrams() {
	defer close(p.recvQ)
	for {
		data, err := p.conn.ReceiveDatagram(p.conn.Context())
		if err != nil {
			p.declareDeath(err)
			return
		}
		select {
		case p.recvQ <- data:
			updateAtomicMax(&p.recvHWM, uint64(len(p.recvQ)))
		case <-p.conn.Context().Done():
			return
		}
	}
}

func (p *datagramPathConn) IngressQueueStats() transport.IngressQueueStats {
	return transport.IngressQueueStats{
		Depth:     uint64(len(p.recvQ)),
		HighWater: p.recvHWM.Load(),
		Capacity:  uint64(cap(p.recvQ)),
	}
}

func updateAtomicMax(value *atomic.Uint64, candidate uint64) {
	for current := value.Load(); candidate > current; current = value.Load() {
		if value.CompareAndSwap(current, candidate) {
			return
		}
	}
}

// Write sends frame as one DATAGRAM. Rejects oversize frames - rendr
// must ensure engine MaxPayload is constrained when using a
// DATAGRAM path.
func (p *datagramPathConn) Write(frame []byte) (int, error) {
	if len(frame) == 0 || len(frame) > MaxDatagramFrame {
		return 0, fmt.Errorf("quic-datagram: frame size %d out of range (1..%d)", len(frame), MaxDatagramFrame)
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if p.dead.Load() {
		return 0, net.ErrClosed
	}
	if err := p.conn.SendDatagram(frame); err != nil {
		p.declareDeath(err)
		return 0, p.swallow(err)
	}
	p.writes.Add(1)
	return len(frame), nil
}

func (p *datagramPathConn) Close() error {
	p.claim.RetireUnbound()
	if !p.dead.CompareAndSwap(false, true) {
		return nil
	}
	err := p.conn.CloseWithError(0, "rendr local close")
	p.deathMu.Lock()
	p.deathErr = err
	p.deathFn = nil
	p.deathMu.Unlock()
	p.releaseRetention()
	return err
}

// Reads / Writes expose per-PathConn counters.
func (p *datagramPathConn) Reads() uint64  { return p.reads.Load() }
func (p *datagramPathConn) Writes() uint64 { return p.writes.Load() }

func (p *datagramPathConn) Quality() transport.PathQuality {
	p.qualityMu.RLock()
	defer p.qualityMu.RUnlock()
	return p.quality
}

func (p *datagramPathConn) SetQuality(q transport.PathQuality) {
	p.qualityMu.Lock()
	p.quality = q
	p.qualityMu.Unlock()
}

func (p *datagramPathConn) OnDeath(fn func(cause transport.DeathCause, err error)) {
	p.deathMu.Lock()
	defer p.deathMu.Unlock()
	if p.dead.Load() {
		go fn(p.classify(p.deathErr), p.deathErr)
		return
	}
	p.deathFn = fn
}

func (p *datagramPathConn) MarkByeSeen()  { p.byeSeen.Store(true) }
func (p *datagramPathConn) MarkQuiesced() { p.quiesced.Store(true) }

func (p *datagramPathConn) LocalAddr() string {
	if a := p.conn.LocalAddr(); a != nil {
		return a.String()
	}
	return ""
}
func (p *datagramPathConn) RemoteAddr() string {
	if a := p.conn.RemoteAddr(); a != nil {
		return a.String()
	}
	return ""
}

func (p *datagramPathConn) watchConn() {
	<-p.conn.Context().Done()
	cause := context.Cause(p.conn.Context())
	if cause == context.Canceled {
		cause = nil
	}
	p.declareDeath(cause)
}

func (p *datagramPathConn) classify(err error) transport.DeathCause {
	return transport.Classify(err, p.quiesced.Load(), p.byeSeen.Load())
}

func (p *datagramPathConn) declareDeath(err error) {
	p.claim.RetireUnbound()
	if !p.dead.CompareAndSwap(false, true) {
		return
	}
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

func (p *datagramPathConn) releaseRetention() {
	if p.release != nil {
		p.release()
	}
}

func (p *datagramPathConn) swallow(err error) error {
	if errors.Is(err, io.EOF) && p.byeSeen.Load() {
		return io.EOF
	}
	return net.ErrClosed
}
