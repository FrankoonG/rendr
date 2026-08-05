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

// PathConn implements transport.PathConn over a connected datagram
// socket. The conn field is typed net.Conn (not *net.UDPConn) so the
// same struct can carry datagrams sourced from a vanilla UDP dial AND
// from a user-supplied Runtime PacketFactory (which provides a
// net.PacketConn; we wrap it with packetAsConn into net.Conn shape).
type PathConn struct {
	conn   net.Conn
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
		if h.Version != proto.UDPFlowVersion {
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

// Wrap promotes an external net.PacketConn into an udpflow PathConn.
// peer is the single remote endpoint that every outbound datagram is
// targeted at (WriteTo) and every inbound datagram MUST come from
// (mismatched sources are dropped, mirroring the connected-UDP-socket
// behavior of DialPath).
//
// flowID is the 7-byte rendr UDP flow identifier embedded in every
// outgoing datagram and validated on every inbound. The caller is
// responsible for negotiating it out-of-band; the Runtime PacketFactory
// codepath generates a random flow_id at session
// start and passes it through here.
//
// Used by rendr.Runtime to back PacketFactory paths. Production
// embedders MUST guarantee the returned net.PacketConn preserves
// datagram boundaries and has an MTU sufficient for the rendr 8B
// flow-id header plus expected payload (C2 packet-mode contract).
func Wrap(pc net.PacketConn, peer net.Addr, flowID [proto.UDPFlowIDSize]byte) *PathConn {
	return &PathConn{
		conn:   &packetAsConn{pc: pc, peer: peer},
		flowID: flowID,
	}
}

// WrapFromSpec is the common Runtime session call site: resolve the peer addr
// from spec.Address (must be host:port for UDP), pick or generate the
// flow_id according to spec.Opts (same semantics as DialPath), and
// hand back a ready-to-attach PathConn. The supplied net.PacketConn
// has its lifetime taken over by the PathConn (Close closes the pc).
func WrapFromSpec(pc net.PacketConn, spec transport.PathSpec) (*PathConn, error) {
	peer, err := net.ResolveUDPAddr("udp", spec.Address)
	if err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("udpflow: resolve %s: %w", spec.Address, err)
	}
	flowID, err := parseOrRandomFlowID(spec.Opts)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	return Wrap(pc, peer, flowID), nil
}

// packetAsConn adapts a net.PacketConn pinned to a single peer into
// the net.Conn shape PathConn consumes. Read/Write delegate to
// ReadFrom/WriteTo with the pinned peer; deadlines and addresses
// pass through. ReadFrom-returned source addresses are NOT compared
// against peer here — the upper-layer flow_id check in PathConn.Read
// is the authoritative drop gate (matches the existing wrong-flow
// drop on the *net.UDPConn path).
type packetAsConn struct {
	pc   net.PacketConn
	peer net.Addr
}

func (c *packetAsConn) Read(b []byte) (int, error) {
	n, _, err := c.pc.ReadFrom(b)
	return n, err
}

func (c *packetAsConn) Write(b []byte) (int, error) {
	return c.pc.WriteTo(b, c.peer)
}

func (c *packetAsConn) Close() error                       { return c.pc.Close() }
func (c *packetAsConn) LocalAddr() net.Addr                { return c.pc.LocalAddr() }
func (c *packetAsConn) RemoteAddr() net.Addr               { return c.peer }
func (c *packetAsConn) SetDeadline(t time.Time) error      { return c.pc.SetDeadline(t) }
func (c *packetAsConn) SetReadDeadline(t time.Time) error  { return c.pc.SetReadDeadline(t) }
func (c *packetAsConn) SetWriteDeadline(t time.Time) error { return c.pc.SetWriteDeadline(t) }
