package udpflow

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

const (
	// inboxSize bounds the per-flow datagram buffer between the shared
	// reader and the engine. Datagrams in excess of this are dropped
	// silently; opaque UDP is a best-effort transport.
	inboxSize = 256

	acceptQueueSize  = 16
	maxListenerFlows = 1024

	readRetryInitialBackoff = 5 * time.Millisecond
	readRetryMaxBackoff     = 100 * time.Millisecond
)

var _ transport.PathQualityReader = (*ServerPathConn)(nil)

// ErrListenerRead identifies a terminal failure of the listener's shared
// PacketConn receive path. Accept returns an error wrapping this sentinel and
// the underlying read error.
var ErrListenerRead = errors.New("udpflow: listener packet read failed")

// Listener owns a single packet socket and dispatches inbound datagrams to
// per-flow_id virtual PathConns. The first datagram observed for a fresh
// flow_id allocates a ServerPathConn and makes it available to Accept;
// subsequent datagrams for that flow are pushed to the same PathConn's inbox.
//
// Migration is implicit: the listener tracks the most recently seen source
// address per flow_id. A datagram arriving from a new address with a known
// flow_id updates the virtual PathConn's RemoteAddr without involving the
// engine or application.
type Listener struct {
	conn net.PacketConn

	mu         sync.Mutex
	flows      map[[proto.UDPFlowIDSize]byte]*ServerPathConn
	accept     chan *ServerPathConn
	admitting  bool
	closed     chan struct{}
	connClosed chan struct{}

	connCloseOnce sync.Once
	connCloseErr  error
	terminalErr   error // protected by mu
}

// Listen binds a UDP socket and starts the reader.
func Listen(addr string) (*Listener, error) {
	c, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("udpflow: bind %s: %w", addr, err)
	}
	return NewListenerFromPacketConn(c)
}

// NewListenerFromPacketConn starts a listener over conn. The listener takes
// ownership of conn: it closes conn once the listener is closed and every
// already accepted ServerPathConn has also closed.
func NewListenerFromPacketConn(conn net.PacketConn) (*Listener, error) {
	if conn == nil {
		return nil, errors.New("udpflow: nil packet connection")
	}
	l := &Listener{
		conn:       conn,
		flows:      make(map[[proto.UDPFlowIDSize]byte]*ServerPathConn),
		accept:     make(chan *ServerPathConn, acceptQueueSize),
		admitting:  true,
		closed:     make(chan struct{}),
		connClosed: make(chan struct{}),
	}
	go l.readLoop()
	return l, nil
}

// Addr is the bound local address.
func (l *Listener) Addr() net.Addr { return l.conn.LocalAddr() }

// Close stops admission and Accept immediately. ServerPathConns which Accept
// already returned remain usable over the shared packet socket until they
// close. Pending, unaccepted flows are rejected. The packet socket closes when
// the final accepted flow closes.
func (l *Listener) Close() error {
	var pending []*ServerPathConn

	l.mu.Lock()
	if l.admitting {
		l.admitting = false
		close(l.closed)
	}
	for flowID, pc := range l.flows {
		if pc.accepted {
			continue
		}
		delete(l.flows, flowID)
		pending = append(pending, pc)
	}
	closeConn := len(l.flows) == 0
	l.mu.Unlock()

	for _, pc := range pending {
		_ = pc.Close()
	}
	if closeConn {
		return l.closePacketConn()
	}
	return nil
}

// Accept blocks until the next fresh flow_id arrives. The returned
// ServerPathConn is already wired to receive the first inbound rendr frame.
func (l *Listener) Accept(ctx context.Context) (*ServerPathConn, error) {
	for {
		select {
		case <-l.closed:
			return nil, l.acceptError()
		default:
		}

		select {
		case <-ctx.Done():
			select {
			case <-l.closed:
				return nil, l.acceptError()
			default:
				return nil, ctx.Err()
			}
		case <-l.closed:
			return nil, l.acceptError()
		case pc := <-l.accept:
			if l.claimFlow(pc) {
				return pc, nil
			}
			_ = pc.Close()
		}
	}
}

func (l *Listener) acceptError() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.terminalErr != nil {
		return l.terminalErr
	}
	return net.ErrClosed
}

func (l *Listener) claimFlow(pc *ServerPathConn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.admitting || pc.dead.Load() || l.flows[pc.flowID] != pc {
		return false
	}
	pc.accepted = true
	return true
}

func (l *Listener) readLoop() {
	buf := make([]byte, MaxDatagram)
	backoff := readRetryInitialBackoff
	for {
		n, src, err := l.conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-l.connClosed:
				return
			default:
			}
			if !retryablePacketReadError(err) {
				l.failRead(err)
				return
			}
			if !l.waitReadRetry(backoff) {
				return
			}
			if backoff < readRetryMaxBackoff {
				backoff *= 2
				if backoff > readRetryMaxBackoff {
					backoff = readRetryMaxBackoff
				}
			}
			continue
		}
		backoff = readRetryInitialBackoff
		if n < proto.UDPFlowHeaderSize {
			continue
		}
		hdr, err := proto.DecodeUDPFlow(buf[:proto.UDPFlowHeaderSize])
		if err != nil || hdr.Version != proto.UDPFlowVersion {
			continue
		}
		payload := make([]byte, n-proto.UDPFlowHeaderSize)
		copy(payload, buf[proto.UDPFlowHeaderSize:n])

		l.mu.Lock()
		pc := l.flows[hdr.FlowID]
		if pc != nil {
			pc.observe(src)
			l.mu.Unlock()
			pc.deliver(payload)
			continue
		}
		if !l.admitting || len(l.flows) >= maxListenerFlows {
			l.mu.Unlock()
			continue
		}

		pc = newServerPathConn(l, hdr.FlowID, src)
		l.flows[hdr.FlowID] = pc
		select {
		case l.accept <- pc:
			l.mu.Unlock()
			pc.deliver(payload)
		default:
			// Admission must never stall the sole packet reader. Remove the
			// rejected flow before closing it so cleanup cannot disturb a
			// later flow which reuses the same ID.
			if l.flows[hdr.FlowID] == pc {
				delete(l.flows, hdr.FlowID)
			}
			l.mu.Unlock()
			_ = pc.Close()
		}
	}
}

func retryablePacketReadError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && (netErr.Timeout() || netErr.Temporary())
}

func (l *Listener) waitReadRetry(delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-l.connClosed:
		return false
	}
}

func (l *Listener) failRead(err error) {
	terminalErr := fmt.Errorf("%w: %w", ErrListenerRead, err)

	l.mu.Lock()
	if l.terminalErr != nil {
		l.mu.Unlock()
		return
	}
	l.terminalErr = terminalErr
	if l.admitting {
		l.admitting = false
		close(l.closed)
	}
	paths := make([]*ServerPathConn, 0, len(l.flows))
	for _, pc := range l.flows {
		paths = append(paths, pc)
	}
	l.mu.Unlock()

	for _, pc := range paths {
		pc.declareDeath(terminalErr)
	}
	_ = l.closePacketConn()
}

func (l *Listener) removeFlow(flowID [proto.UDPFlowIDSize]byte, pc *ServerPathConn) {
	l.mu.Lock()
	if l.flows[flowID] == pc {
		delete(l.flows, flowID)
	}
	closeConn := !l.admitting && len(l.flows) == 0
	l.mu.Unlock()
	if closeConn {
		_ = l.closePacketConn()
	}
}

func (l *Listener) closePacketConn() error {
	l.connCloseOnce.Do(func() {
		close(l.connClosed)
		l.connCloseErr = l.conn.Close()
	})
	return l.connCloseErr
}

// ServerPathConn is the listener-side virtual PathConn. It shares the
// listener's packet socket; writes target the most recently observed peer for
// this flow_id.
type ServerPathConn struct {
	listener *Listener
	conn     net.PacketConn
	flowID   [proto.UDPFlowIDSize]byte
	claim    *leafmobility.Claim

	// accepted is protected by listener.mu.
	accepted bool

	remoteMu sync.RWMutex
	remote   net.Addr

	inbox chan []byte
	// inboxMu serializes sends with channel close. A dead-flag check alone is
	// not enough: Close could close inbox between deliver's check and send.
	inboxMu sync.RWMutex

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

func newServerPathConn(l *Listener, flowID [proto.UDPFlowIDSize]byte, src net.Addr) *ServerPathConn {
	return &ServerPathConn{
		listener: l,
		conn:     l.conn,
		flowID:   flowID,
		claim: leafmobility.MustNewClaim(leafmobility.Facts{
			Kind:       leafmobility.KindUDPFlow,
			Role:       leafmobility.RoleAcceptor,
			Scope:      leafmobility.ScopeSharedLink,
			Session:    leafmobility.SessionAny,
			Generation: leafmobility.NextGeneration(),
		}),
		remote: src,
		inbox:  make(chan []byte, inboxSize),
	}
}

func (p *ServerPathConn) LeafMobilityClaim() *leafmobility.Claim {
	if p == nil {
		return nil
	}
	return p.claim
}

func (p *ServerPathConn) FlowID() [proto.UDPFlowIDSize]byte { return p.flowID }
func (p *ServerPathConn) Writes() uint64                    { return p.writes.Load() }
func (p *ServerPathConn) Reads() uint64                     { return p.reads.Load() }

// observe records a newly seen source address for this flow. Subsequent writes
// target the new address.
func (p *ServerPathConn) observe(src net.Addr) {
	p.remoteMu.Lock()
	p.remote = src
	p.remoteMu.Unlock()
}

// deliver pushes an inbound rendr-frame payload to the inbox. If the inbox is
// full the datagram is dropped; opaque UDP is best-effort delivery.
func (p *ServerPathConn) deliver(payload []byte) {
	p.inboxMu.RLock()
	defer p.inboxMu.RUnlock()
	if p.dead.Load() {
		return
	}
	select {
	case p.inbox <- payload:
	default:
	}
}

// Read blocks until the next rendr frame arrives. The returned payload is the
// bytes following the UDPFlowHeader in one packet.
func (p *ServerPathConn) Read(buf []byte) (int, error) {
	frame, ok := <-p.inbox
	if !ok {
		return 0, net.ErrClosed
	}
	if len(buf) < len(frame) {
		return 0, errors.New("udpflow: server read buf too small")
	}
	copy(buf, frame)
	p.reads.Add(1)
	return len(frame), nil
}

// Write sends frame to the current peer with UDPFlowHeader prepended.
func (p *ServerPathConn) Write(frame []byte) (int, error) {
	if len(frame) == 0 {
		return 0, errors.New("udpflow: empty frame")
	}
	if len(frame)+proto.UDPFlowHeaderSize > MaxDatagram {
		return 0, fmt.Errorf("udpflow: frame %d + 8 header > MaxDatagram %d", len(frame), MaxDatagram)
	}
	if p.dead.Load() {
		return 0, net.ErrClosed
	}

	p.remoteMu.RLock()
	dst := p.remote
	p.remoteMu.RUnlock()
	if dst == nil {
		return 0, errors.New("udpflow: server side has no observed peer yet")
	}

	out := make([]byte, proto.UDPFlowHeaderSize+len(frame))
	hdr := proto.UDPFlowHeader{Version: proto.UDPFlowVersion, FlowID: p.flowID}
	if err := hdr.Encode(out[:proto.UDPFlowHeaderSize]); err != nil {
		return 0, err
	}
	copy(out[proto.UDPFlowHeaderSize:], frame)

	if _, err := p.conn.WriteTo(out, dst); err != nil {
		p.declareDeath(err)
		return 0, net.ErrClosed
	}
	p.writes.Add(1)
	return len(frame), nil
}

func (p *ServerPathConn) Close() error {
	p.finish(nil, false)
	return nil
}

func (p *ServerPathConn) Quality() transport.PathQuality {
	p.qualityMu.RLock()
	defer p.qualityMu.RUnlock()
	return p.quality
}

func (p *ServerPathConn) QualityContext(ctx context.Context) (transport.PathQuality, error) {
	if err := ctx.Err(); err != nil {
		return transport.PathQuality{}, err
	}
	return p.Quality(), nil
}

func (p *ServerPathConn) SetQuality(q transport.PathQuality) {
	p.qualityMu.Lock()
	p.quality = q
	p.qualityMu.Unlock()
}

func (p *ServerPathConn) OnDeath(fn func(cause transport.DeathCause, err error)) {
	p.deathMu.Lock()
	defer p.deathMu.Unlock()
	if p.dead.Load() {
		err := p.deathErr
		go fn(transport.Classify(err, p.quiesced.Load(), p.byeSeen.Load()), err)
		return
	}
	p.deathFn = fn
}

func (p *ServerPathConn) MarkByeSeen()  { p.byeSeen.Store(true) }
func (p *ServerPathConn) MarkQuiesced() { p.quiesced.Store(true) }

func (p *ServerPathConn) LocalAddr() string {
	if a := p.conn.LocalAddr(); a != nil {
		return a.String()
	}
	return ""
}

func (p *ServerPathConn) RemoteAddr() string {
	p.remoteMu.RLock()
	defer p.remoteMu.RUnlock()
	if p.remote != nil {
		return p.remote.String()
	}
	return ""
}

func (p *ServerPathConn) declareDeath(err error) {
	p.finish(err, true)
}

func (p *ServerPathConn) finish(err error, notify bool) {
	p.claim.RetireUnbound()
	var fn func(cause transport.DeathCause, err error)

	p.deathMu.Lock()
	if p.dead.Load() {
		p.deathMu.Unlock()
		return
	}
	p.deathErr = err
	if notify {
		fn = p.deathFn
	}
	p.deathFn = nil
	p.dead.Store(true)
	p.deathMu.Unlock()

	p.inboxMu.Lock()
	close(p.inbox)
	p.inboxMu.Unlock()

	p.listener.removeFlow(p.flowID, p)
	if fn != nil {
		fn(transport.Classify(err, p.quiesced.Load(), p.byeSeen.Load()), err)
	}
}
