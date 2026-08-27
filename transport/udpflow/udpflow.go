package udpflow

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

// MaxDatagram caps a single UDP payload (header + rendr frame).
// 1232 is the conservative QUIC-compatible UDP datagram size; we
// pick 1400 as a typical Ethernet-MTU-friendly default. Callers
// that need fragmentation must do it above the rendr layer; this
// adapter discards oversize writes.
const (
	MaxDatagram = 1400
	// WireHeaderSize is the carrier overhead subtracted from every factual
	// endpoint datagram capacity.
	WireHeaderSize = proto.UDPFlowHeaderSize
	// MaxFrameSize is the exact rendr frame capacity after the udpflow header.
	MaxFrameSize       = MaxDatagram - proto.UDPFlowHeaderSize
	packetReadOOBSize  = 256
	packetMSGTruncated = 0x20 // Linux MSG_TRUNC; Linux is the v1.0 runtime target.
)

var (
	// ErrInvalidDatagramCapacity reports a missing or impossible factual limit
	// at the generic PacketFactory boundary.
	ErrInvalidDatagramCapacity = errors.New("udpflow: invalid datagram capacity")
	// ErrInvalidPeerIdentity reports an address that cannot be snapshotted into
	// an immutable packet peer.
	ErrInvalidPeerIdentity = errors.New("udpflow: invalid packet peer identity")
	// ErrInvalidPacketReadCount reports a PacketConn read count outside its
	// supplied payload buffer.
	ErrInvalidPacketReadCount = errors.New("udpflow: invalid packet read count")
	// ErrInvalidPacketWriteCount reports a PacketConn write count outside its
	// supplied datagram.
	ErrInvalidPacketWriteCount = errors.New("udpflow: invalid packet write count")
	// ErrInvalidPacketOOBCount reports a ReadMsgUDP OOB count outside its
	// supplied control buffer.
	ErrInvalidPacketOOBCount = errors.New("udpflow: invalid packet OOB count")
	// ErrTruncatedPacket reports a datagram that did not fit in the receive
	// buffer. A truncated datagram can look like a valid rendr frame prefix and
	// must never be acknowledged or delivered.
	ErrTruncatedPacket = errors.New("udpflow: truncated packet")
	// ErrConnectedPacketPeerMismatch reports that a connected UDP socket's
	// kernel-bound remote does not match the configured packet peer.
	ErrConnectedPacketPeerMismatch = errors.New("udpflow: connected UDP peer does not match configured peer")
)

// PeerIdentity is an immutable address value for a custom PacketConn. Its
// fields are copied while the caller's factory callback is still under rendr's
// bounded callback authority and cannot be mutated after construction. A
// custom PacketConn acknowledges this value at adoption, accepts it in WriteTo,
// and returns it from ReadFrom for datagrams received from that peer.
type PeerIdentity struct {
	network string
	address string
}

func (id PeerIdentity) Network() string { return id.network }
func (id PeerIdentity) String() string  { return id.address }

// SnapshotPeerIdentity calls an untrusted net.Addr exactly once per identity
// field and converts panics, typed nils, and empty identities into a fixed
// error. The copied strings can be compared without consulting the original
// mutable address again.
func SnapshotPeerIdentity(peer net.Addr) (identity PeerIdentity, err error) {
	if nilNetAddr(peer) {
		return PeerIdentity{}, ErrInvalidPeerIdentity
	}
	defer func() {
		if recover() != nil {
			identity = PeerIdentity{}
			err = ErrInvalidPeerIdentity
		}
	}()
	network, address := peer.Network(), peer.String()
	if network == "" || address == "" {
		return PeerIdentity{}, ErrInvalidPeerIdentity
	}
	return PeerIdentity{
		network: strings.Clone(network),
		address: strings.Clone(address),
	}, nil
}

func nilNetAddr(addr net.Addr) bool {
	if addr == nil {
		return true
	}
	value := reflect.ValueOf(addr)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (id PeerIdentity) matches(source net.Addr) bool {
	got, ok := source.(PeerIdentity)
	return ok && got == id
}

// PeerSnapshot owns the immutable outbound and comparison state for one
// PacketConn peer. Standard-library address types retain their concrete type
// and are deep-copied for every WriteTo call. A custom address is represented
// by PeerIdentity, so the original caller-owned object is never retained.
type PeerSnapshot struct {
	identity PeerIdentity
	standard bool
	outbound func() net.Addr
	matcher  func(net.Addr) bool
}

func (snapshot PeerSnapshot) Identity() PeerIdentity { return snapshot.identity }
func (snapshot PeerSnapshot) IsStandard() bool       { return snapshot.standard }

func (snapshot PeerSnapshot) OutboundAddr() net.Addr {
	if snapshot.outbound == nil {
		return nil
	}
	return snapshot.outbound()
}

func (snapshot PeerSnapshot) matches(source net.Addr) bool {
	return snapshot.matcher != nil && snapshot.matcher(source)
}

// SnapshotPeer captures both a comparison identity and a safe outbound
// representation without retaining peer. The concrete standard-library
// address types accepted by net.PacketConn are preserved and matched by their
// copied fields. Arbitrary custom types become PeerIdentity and require the
// caller's PacketConn to explicitly accept and return that representation at
// the public factory boundary. Runtime matching never calls source Addr
// methods supplied by caller code.
func SnapshotPeer(peer net.Addr) (PeerSnapshot, error) {
	identity, err := SnapshotPeerIdentity(peer)
	if err != nil {
		return PeerSnapshot{}, err
	}
	snapshot := PeerSnapshot{
		identity: identity,
		outbound: func() net.Addr { return identity },
		matcher:  identity.matches,
	}
	switch addr := peer.(type) {
	case *net.UDPAddr:
		ip := append(net.IP(nil), addr.IP...)
		port, zone := addr.Port, strings.Clone(addr.Zone)
		snapshot.standard = true
		snapshot.outbound = func() net.Addr {
			return &net.UDPAddr{IP: append(net.IP(nil), ip...), Port: port, Zone: zone}
		}
		snapshot.matcher = func(source net.Addr) bool {
			got, ok := source.(*net.UDPAddr)
			return ok && got != nil && got.Port == port && got.Zone == zone && ip.Equal(got.IP)
		}
	case *net.IPAddr:
		ip := append(net.IP(nil), addr.IP...)
		zone := strings.Clone(addr.Zone)
		snapshot.standard = true
		snapshot.outbound = func() net.Addr {
			return &net.IPAddr{IP: append(net.IP(nil), ip...), Zone: zone}
		}
		snapshot.matcher = func(source net.Addr) bool {
			got, ok := source.(*net.IPAddr)
			return ok && got != nil && got.Zone == zone && ip.Equal(got.IP)
		}
	case *net.UnixAddr:
		name, network := strings.Clone(addr.Name), strings.Clone(addr.Net)
		snapshot.standard = true
		snapshot.outbound = func() net.Addr {
			return &net.UnixAddr{Name: name, Net: network}
		}
		snapshot.matcher = func(source net.Addr) bool {
			got, ok := source.(*net.UnixAddr)
			return ok && got != nil && got.Name == name && got.Net == network
		}
	case *net.TCPAddr:
		ip := append(net.IP(nil), addr.IP...)
		port, zone := addr.Port, strings.Clone(addr.Zone)
		snapshot.standard = true
		snapshot.outbound = func() net.Addr {
			return &net.TCPAddr{IP: append(net.IP(nil), ip...), Port: port, Zone: zone}
		}
		snapshot.matcher = func(source net.Addr) bool {
			got, ok := source.(*net.TCPAddr)
			return ok && got != nil && got.Port == port && got.Zone == zone && ip.Equal(got.IP)
		}
	}
	outboundIdentity, err := SnapshotPeerIdentity(snapshot.OutboundAddr())
	if err != nil || outboundIdentity != identity {
		return PeerSnapshot{}, ErrInvalidPeerIdentity
	}
	return snapshot, nil
}

var _ transport.PathQualityReader = (*PathConn)(nil)

// Transport opens framed paths over opaque UDP. spec.Opts
// recognised keys:
//
//	flow_id_hex   14-char hex; overrides the random flow id.
//	(server side will land in M5(3/n))
type Transport struct{}

// New returns a Transport ready for client-side use.
func New() *Transport { return &Transport{} }

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
	pc := &PathConn{
		conn:            c,
		flowID:          flowID,
		maxDatagramSize: MaxDatagram,
		claim: leafmobility.MustNewClaim(leafmobility.Facts{
			Kind:       leafmobility.KindUDPFlow,
			Role:       leafmobility.RoleDialer,
			Scope:      leafmobility.ScopeEndpoint,
			Session:    leafmobility.SessionAny,
			Generation: leafmobility.NextGeneration(),
		}),
	}
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
	conn            net.Conn
	flowID          [proto.UDPFlowIDSize]byte
	maxDatagramSize int
	claim           *leafmobility.Claim

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

func (p *PathConn) LeafMobilityClaim() *leafmobility.Claim {
	if p == nil {
		return nil
	}
	return p.claim
}

// FlowID returns the 7-byte flow identifier used on the wire.
func (p *PathConn) FlowID() [proto.UDPFlowIDSize]byte { return p.flowID }

// Writes / Reads expose per-PathConn counters for diagnostics.
func (p *PathConn) Writes() uint64 { return p.writes.Load() }
func (p *PathConn) Reads() uint64  { return p.reads.Load() }

// MaxFrameSize reports the largest complete rendr frame that fits after the
// udpflow wire header in one datagram.
func (p *PathConn) MaxFrameSize() int {
	if p == nil || p.maxDatagramSize <= proto.UDPFlowHeaderSize {
		return 0
	}
	return p.maxDatagramSize - proto.UDPFlowHeaderSize
}

var _ transport.PacketPathConn = (*PathConn)(nil)

// Read pulls one datagram from the underlying socket, strips its
// UDPFlowHeader, and returns the trailing bytes (which are the rendr
// frame: proto.Header + payload).
//
// Datagrams whose flow_id does not match this PathConn's flow_id
// are silently dropped on the client side; the server-side
// multiplexer (M5(3/n)) is responsible for fan-out.
func (p *PathConn) Read(buf []byte) (int, error) {
	scratch := make([]byte, p.maxDatagramSize+1)
	for {
		n, err := p.conn.Read(scratch)
		if err != nil {
			p.declareDeath(err)
			return 0, p.swallow(err)
		}
		if n < 0 || n > len(scratch) {
			countErr := fmt.Errorf("%w: read %d into %d-byte buffer", ErrInvalidPacketReadCount, n, len(scratch))
			p.declareDeath(countErr)
			return 0, net.ErrClosed
		}
		if n > p.maxDatagramSize {
			p.declareDeath(ErrTruncatedPacket)
			return 0, net.ErrClosed
		}
		if n < proto.UDPFlowHeaderSize {
			// Malformed; drop and keep reading.
			continue
		}
		packet, err := proto.DecodeUDPFlowFrame(scratch[:n])
		if err != nil {
			continue
		}
		h := packet.Header
		if h.Version != proto.UDPFlowVersion {
			continue
		}
		if h.FlowID != p.flowID {
			// Wrong flow on a shared socket - shouldn't happen on a
			// connected UDP socket but stay safe.
			continue
		}
		payload := packet.Payload
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
	if len(frame)+proto.UDPFlowHeaderSize > p.maxDatagramSize {
		return 0, fmt.Errorf("udpflow: frame %d + %d header > datagram capacity %d", len(frame), proto.UDPFlowHeaderSize, p.maxDatagramSize)
	}

	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if p.dead.Load() {
		return 0, net.ErrClosed
	}

	out := make([]byte, proto.UDPFlowHeaderSize+len(frame))
	hdr := proto.UDPFlowHeader{Version: proto.UDPFlowVersion, FlowID: p.flowID, PayloadSize: uint32(len(frame))}
	if err := hdr.Encode(out[:proto.UDPFlowHeaderSize]); err != nil {
		return 0, err
	}
	copy(out[proto.UDPFlowHeaderSize:], frame)

	written, err := p.conn.Write(out)
	written, err = normalizePacketWriteResult(len(out), written, err)
	if err != nil {
		p.declareDeath(err)
		payloadWritten := written - proto.UDPFlowHeaderSize
		if payloadWritten < 0 {
			payloadWritten = 0
		}
		if payloadWritten > len(frame) {
			payloadWritten = len(frame)
		}
		return payloadWritten, p.swallow(err)
	}
	p.writes.Add(1)
	return len(frame), nil
}

func normalizePacketWriteResult(want, written int, err error) (int, error) {
	if written < 0 || written > want {
		countErr := fmt.Errorf("%w: wrote %d for %d-byte datagram", ErrInvalidPacketWriteCount, written, want)
		return 0, errors.Join(err, countErr)
	}
	if written != want && !errors.Is(err, io.ErrShortWrite) {
		err = errors.Join(err, io.ErrShortWrite)
	}
	return written, err
}

// Close shuts the UDP socket.
func (p *PathConn) Close() error {
	p.claim.RetireUnbound()
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
	p.claim.RetireUnbound()
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
// datagram boundaries and reports a factual capacity sufficient for the
// versioned UDP-flow header plus expected payload (C2 packet-mode contract).
func Wrap(
	pc net.PacketConn,
	peer PeerSnapshot,
	flowID [proto.UDPFlowIDSize]byte,
	maxDatagramSize int,
) (*PathConn, error) {
	if err := ValidateDatagramSize(maxDatagramSize); err != nil {
		return nil, err
	}
	adapter, err := newPacketAsConn(pc, peer)
	if err != nil {
		return nil, err
	}
	return &PathConn{
		conn:            adapter,
		flowID:          flowID,
		maxDatagramSize: min(maxDatagramSize, MaxDatagram),
	}, nil
}

// ValidateDatagramSize validates the factual packet boundary supplied by a
// generic PacketFactory. Values larger than udpflow's conservative adapter
// ceiling are valid; Wrap advertises the smaller, implementation-owned limit.
func ValidateDatagramSize(maxDatagramSize int) error {
	if maxDatagramSize <= proto.UDPFlowHeaderSize {
		return fmt.Errorf("%w: %d must exceed udpflow header size %d", ErrInvalidDatagramCapacity, maxDatagramSize, proto.UDPFlowHeaderSize)
	}
	return nil
}

// WrapFromSpec is the common Runtime session call site: resolve the peer addr
// from spec.Address (must be host:port for UDP), pick or generate the
// flow_id according to spec.Opts (same semantics as DialPath), and
// hand back a ready-to-attach PathConn. Ownership of pc transfers only when
// WrapFromSpec succeeds. On error the caller retains pc and is responsible for
// cleanup; validation never invokes caller-owned network methods.
func WrapFromSpec(pc net.PacketConn, spec transport.PathSpec, maxDatagramSize int) (*PathConn, error) {
	peer, err := net.ResolveUDPAddr("udp", spec.Address)
	if err != nil {
		return nil, fmt.Errorf("udpflow: resolve %s: %w", spec.Address, err)
	}
	flowID, err := parseOrRandomFlowID(spec.Opts)
	if err != nil {
		return nil, err
	}
	snapshot, err := SnapshotPeer(peer)
	if err != nil {
		return nil, err
	}
	return Wrap(pc, snapshot, flowID, maxDatagramSize)
}

// packetAsConn adapts a net.PacketConn pinned to a single peer into
// the net.Conn shape PathConn consumes. Read/Write delegate to
// ReadFrom/WriteTo with the pinned peer; deadlines and addresses
// pass through. Read drops datagrams that do not come from the immutable
// identity captured for peer, before PathConn considers their flow ID.
type packetAsConn struct {
	pc            net.PacketConn
	peer          PeerSnapshot
	messageReader packetMessageReader
	connected     *net.UDPConn

	readMu          sync.Mutex
	terminalReadErr error
	oob             [packetReadOOBSize]byte
}

type packetMessageReader interface {
	ReadMsgUDP(payload, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error)
}

func newPacketAsConn(pc net.PacketConn, peer PeerSnapshot) (*packetAsConn, error) {
	adapter := &packetAsConn{pc: pc, peer: peer}
	udpConn, ok := pc.(*net.UDPConn)
	if !ok {
		return adapter, nil
	}
	if _, ok := peer.OutboundAddr().(*net.UDPAddr); ok {
		adapter.messageReader = udpConn
	}
	remote := udpConn.RemoteAddr()
	if remote == nil {
		return adapter, nil
	}
	if !peer.matches(remote) {
		return adapter, ErrConnectedPacketPeerMismatch
	}
	adapter.connected = udpConn
	return adapter, nil
}

func (c *packetAsConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.terminalReadErr != nil {
		return 0, c.terminalReadErr
	}

	for {
		n, source, err := c.readPacket(b)
		if n < 0 || n > len(b) {
			countErr := fmt.Errorf("%w: read %d into %d-byte buffer", ErrInvalidPacketReadCount, n, len(b))
			return 0, errors.Join(err, countErr)
		}
		if n == 0 {
			if err != nil {
				return 0, err
			}
			if c.acceptsSource(source) {
				return 0, nil
			}
			continue
		}
		if !c.acceptsSource(source) {
			if err != nil {
				return 0, err
			}
			continue
		}
		if err != nil {
			c.terminalReadErr = err
		}
		return n, nil
	}
}

func (c *packetAsConn) readPacket(b []byte) (int, net.Addr, error) {
	reader := c.messageReader
	if reader == nil {
		return c.pc.ReadFrom(b)
	}
	n, oobn, flags, source, err := reader.ReadMsgUDP(b, c.oob[:])
	if flags&packetMSGTruncated != 0 {
		return 0, nil, errors.Join(err, ErrTruncatedPacket)
	}
	if oobn < 0 || oobn > len(c.oob) {
		oobErr := fmt.Errorf("%w: read %d into %d-byte OOB buffer", ErrInvalidPacketOOBCount, oobn, len(c.oob))
		return 0, nil, errors.Join(err, oobErr)
	}
	if source == nil {
		return n, nil, err
	}
	return n, source, err
}

func (c *packetAsConn) acceptsSource(source net.Addr) bool {
	if c.connected != nil && nilNetAddr(source) {
		// The kernel binds a connected UDP socket to its remote tuple. A nil
		// source from a compatible message reader therefore still has the peer
		// identity proved by newPacketAsConn.
		return true
	}
	return c.peer.matches(source)
}

func (c *packetAsConn) Write(b []byte) (int, error) {
	var n int
	var err error
	if c.connected != nil {
		n, err = c.connected.Write(b)
	} else {
		n, err = c.pc.WriteTo(b, c.peer.OutboundAddr())
	}
	return normalizePacketWriteResult(len(b), n, err)
}

func (c *packetAsConn) Close() error                       { return c.pc.Close() }
func (c *packetAsConn) LocalAddr() net.Addr                { return c.pc.LocalAddr() }
func (c *packetAsConn) RemoteAddr() net.Addr               { return c.peer.Identity() }
func (c *packetAsConn) SetDeadline(t time.Time) error      { return c.pc.SetDeadline(t) }
func (c *packetAsConn) SetReadDeadline(t time.Time) error  { return c.pc.SetReadDeadline(t) }
func (c *packetAsConn) SetWriteDeadline(t time.Time) error { return c.pc.SetWriteDeadline(t) }
