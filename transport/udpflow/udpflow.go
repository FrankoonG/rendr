package udpflow

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

// MaxDatagram caps a single UDP payload (header + rendr frame).
// 1232 is the conservative QUIC-compatible UDP datagram size; we
// pick 1400 as a typical Ethernet-MTU-friendly default. Callers
// that need fragmentation must do it above the rendr layer; this
// adapter discards oversize writes.
const MaxDatagram = 1400

// Transport implements transport.Transport over opaque UDP. spec.Opts
// recognised keys:
//
//	flow_id_hex   14-char hex; overrides the random flow id.
//	(server side will land in M5(3/n))
type Transport struct{}

// New returns a Transport ready for client-side use.
func New() *Transport { return &Transport{} }

// Name implements transport.Transport.
func (*Transport) Name() string { return "udpflow" }

// DialPath dials a UDP socket toward spec.Address, generates a
// random flow_id (or accepts one from spec.Opts), and returns a
// PathConn that prepends / strips the UDPFlowHeader per datagram.
func (t *Transport) DialPath(ctx context.Context, spec transport.PathSpec) (transport.PathConn, error) {
	raddr, err := net.ResolveUDPAddr("udp", spec.Address)
	if err != nil {
		return nil, fmt.Errorf("udpflow: resolve %s: %w", spec.Address, err)
	}
	var laddr *net.UDPAddr
	if spec.Local != "" {
		laddr, err = net.ResolveUDPAddr("udp", spec.Local)
		if err != nil {
			return nil, fmt.Errorf("udpflow: bad local %q: %w", spec.Local, err)
		}
	}
	c, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		return nil, fmt.Errorf("udpflow: dial %s: %w", spec.Address, err)
	}

	flowID, err := parseOrRandomFlowID(spec.Opts)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	pc := &PathConn{conn: c, flowID: flowID}
	return pc, nil
}

// Probe sends a single tiny "ping" datagram and returns the
// observed RTT. M6's per-path prober will subsume this; for now we
// just report a coarse measurement.
func (t *Transport) Probe(ctx context.Context, spec transport.PathSpec) (transport.PathQuality, error) {
	start := time.Now()
	pc, err := t.DialPath(ctx, spec)
	if err != nil {
		return transport.PathQuality{}, err
	}
	_ = pc.Close()
	return transport.PathQuality{RTT: time.Since(start), At: time.Now()}, nil
}

// PathConn implements transport.PathConn over a connected UDP socket.
type PathConn struct {
	conn   *net.UDPConn
	flowID [proto.UDPFlowIDSize]byte

	writeMu sync.Mutex

	qualityMu sync.RWMutex
	quality   transport.PathQuality

	dead     atomic.Bool
	byeSeen  atomic.Bool
	quiesced atomic.Bool

	deathMu  sync.Mutex
	deathFn  func(cause transport.DeathCause, err error)
	deathErr error

	writes atomic.Uint64
	reads  atomic.Uint64
}

// FlowID returns the 7-byte flow identifier used on the wire.
func (p *PathConn) FlowID() [proto.UDPFlowIDSize]byte { return p.flowID }

// Writes / Reads expose per-PathConn counters for diagnostics.
func (p *PathConn) Writes() uint64 { return p.writes.Load() }
func (p *PathConn) Reads() uint64  { return p.reads.Load() }

// Read pulls one datagram from the underlying socket, strips its
// UDPFlowHeader, and returns the trailing bytes (which are the rendr
// frame: proto.Header + payload).
//
// Datagrams whose flow_id does not match this PathConn's flow_id
// are silently dropped on the client side; the server-side
// multiplexer (M5(3/n)) is responsible for fan-out.
func (p *PathConn) Read(buf []byte) (int, error) {
	scratch := make([]byte, MaxDatagram)
	for {
		n, err := p.conn.Read(scratch)
		if err != nil {
			p.declareDeath(err)
			return 0, p.swallow(err)
		}
		if n < proto.UDPFlowHeaderSize {
			// Malformed; drop and keep reading.
			continue
		}
		h, err := proto.DecodeUDPFlow(scratch[:proto.UDPFlowHeaderSize])
		if err != nil {
			continue
		}
		if h.FlowID != p.flowID {
			// Wrong flow on a shared socket - shouldn't happen on a
			// connected UDP socket but stay safe.
			continue
		}
		payload := scratch[proto.UDPFlowHeaderSize:n]
		if len(buf) < len(payload) {
			err := fmt.Errorf("udpflow: read buf %d < payload %d", len(buf), len(payload))
			p.declareDeath(err)
			return 0, io.ErrShortBuffer
		}
		copy(buf, payload)
		p.reads.Add(1)
		return len(payload), nil
	}
}

// Write wraps frame in a UDPFlowHeader and emits a single datagram.
func (p *PathConn) Write(frame []byte) (int, error) {
	if len(frame) == 0 {
		return 0, errors.New("udpflow: empty frame")
	}
	if len(frame)+proto.UDPFlowHeaderSize > MaxDatagram {
		return 0, fmt.Errorf("udpflow: frame %d + 8 header > MaxDatagram %d", len(frame), MaxDatagram)
	}

	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if p.dead.Load() {
		return 0, net.ErrClosed
	}

	out := make([]byte, proto.UDPFlowHeaderSize+len(frame))
	hdr := proto.UDPFlowHeader{Version: proto.UDPFlowVersion, FlowID: p.flowID}
	if err := hdr.Encode(out[:proto.UDPFlowHeaderSize]); err != nil {
		return 0, err
	}
	copy(out[proto.UDPFlowHeaderSize:], frame)

	if _, err := p.conn.Write(out); err != nil {
		p.declareDeath(err)
		return 0, p.swallow(err)
	}
	p.writes.Add(1)
	return len(frame), nil
}

// Close shuts the UDP socket.
func (p *PathConn) Close() error {
	if !p.dead.CompareAndSwap(false, true) {
		return nil
	}
	err := p.conn.Close()
	p.deathMu.Lock()
	p.deathErr = err
	p.deathFn = nil
	p.deathMu.Unlock()
	return err
}

// Quality / SetQuality / OnDeath / MarkByeSeen / MarkQuiesced /
// LocalAddr / RemoteAddr satisfy transport.PathConn (and the
// engine's optional SetQuality interface, used by the per-path
// prober in internal/engine).
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

func (p *PathConn) classify(err error) transport.DeathCause {
	return transport.Classify(err, p.quiesced.Load(), p.byeSeen.Load())
}

func (p *PathConn) declareDeath(err error) {
	if !p.dead.CompareAndSwap(false, true) {
		return
	}
	_ = p.conn.Close()
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
	return net.ErrClosed
}

// parseOrRandomFlowID consults spec.Opts["flow_id_hex"] (must be
// exactly 14 hex digits = 7 bytes) or, if unset, draws one from
// crypto/rand.
func parseOrRandomFlowID(opts map[string]string) ([proto.UDPFlowIDSize]byte, error) {
	var f [proto.UDPFlowIDSize]byte
	if v, ok := opts["flow_id_hex"]; ok && v != "" {
		if len(v) != 2*proto.UDPFlowIDSize {
			return f, fmt.Errorf("udpflow: flow_id_hex must be %d hex chars", 2*proto.UDPFlowIDSize)
		}
		for i := 0; i < proto.UDPFlowIDSize; i++ {
			b, err := hexByte(v[2*i], v[2*i+1])
			if err != nil {
				return f, err
			}
			f[i] = b
		}
		return f, nil
	}
	if _, err := rand.Read(f[:]); err != nil {
		return f, err
	}
	return f, nil
}

func hexByte(hi, lo byte) (byte, error) {
	h, err := hexNibble(hi)
	if err != nil {
		return 0, err
	}
	l, err := hexNibble(lo)
	if err != nil {
		return 0, err
	}
	return h<<4 | l, nil
}

func hexNibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, fmt.Errorf("udpflow: bad hex char %q", c)
}

func init() {
	if err := transport.Default.Register(New()); err != nil {
		panic(err)
	}
}
