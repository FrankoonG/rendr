package udpflow

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

// inboxSize bounds the per-flow datagram buffer between the shared
// reader and the engine. Datagrams in excess of this are dropped
// silently; the engine treats opaque-UDP as best-effort delivery so
// drop = "transport lost the packet", which is acceptable.
const inboxSize = 256

// Listener owns a single UDP socket and dispatches inbound
// datagrams to per-flow_id virtual PathConns. The first datagram
// observed for a fresh flow_id allocates a ServerPathConn and
// emits it on the Accept channel; subsequent datagrams for that
// flow are pushed to the same PathConn's inbox.
//
// Migration is implicit: the listener tracks the most recently-seen
// (src) tuple per flow_id, so a datagram arriving from a fresh
// 4-tuple but carrying a known flow_id silently updates the
// virtual PathConn's RemoteAddr - the engine and the application
// observe nothing.
type Listener struct {
	conn *net.UDPConn

	mu     sync.Mutex
	flows  map[[proto.UDPFlowIDSize]byte]*ServerPathConn
	accept chan *ServerPathConn

	closeOnce sync.Once
	closed    chan struct{}
}

// Listen binds a UDP socket and starts the reader.
func Listen(addr string) (*Listener, error) {
	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("udpflow: resolve %s: %w", addr, err)
	}
	c, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		return nil, fmt.Errorf("udpflow: bind %s: %w", addr, err)
	}
	l := &Listener{
		conn:   c,
		flows:  make(map[[proto.UDPFlowIDSize]byte]*ServerPathConn),
		accept: make(chan *ServerPathConn, 16),
		closed: make(chan struct{}),
	}
	go l.readLoop()
	return l, nil
}

// Addr is the bound local address.
func (l *Listener) Addr() net.Addr { return l.conn.LocalAddr() }

// Close shuts the listener and all attached virtual PathConns.
func (l *Listener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		close(l.closed)
		err = l.conn.Close()
		l.mu.Lock()
		for _, pc := range l.flows {
			_ = pc.Close()
		}
		l.flows = nil
		l.mu.Unlock()
	})
	return err
}

// Accept blocks until the next fresh flow_id arrives. The returned
// ServerPathConn is already wired with the first inbound rendr
// frame buffered.
func (l *Listener) Accept(ctx context.Context) (*ServerPathConn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.closed:
		return nil, net.ErrClosed
	case pc, ok := <-l.accept:
		if !ok {
			return nil, net.ErrClosed
		}
		return pc, nil
	}
}

func (l *Listener) readLoop() {
	buf := make([]byte, MaxDatagram)
	for {
		n, src, err := l.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-l.closed:
				return
			default:
			}
			// Continue on transient errors; permanent ones (socket
			// closed) drop us out via the next select.
			continue
		}
		if n < proto.UDPFlowHeaderSize {
			continue
		}
		hdr, err := proto.DecodeUDPFlow(buf[:proto.UDPFlowHeaderSize])
		if err != nil {
			continue
		}
		if hdr.Version != proto.UDPFlowVersion {
			continue
		}
		payload := make([]byte, n-proto.UDPFlowHeaderSize)
		copy(payload, buf[proto.UDPFlowHeaderSize:n])

		l.mu.Lock()
		if l.flows == nil {
			l.mu.Unlock()
			return
		}
		pc, exists := l.flows[hdr.FlowID]
		if !exists {
			pc = newServerPathConn(l.conn, hdr.FlowID, src)
			l.flows[hdr.FlowID] = pc
			l.mu.Unlock()

			// First datagram for this flow: queue the payload, then
			// publish on accept. If the consumer never picks it up,
			// the inbox will eventually fill and further datagrams
			// drop - the cap blocks the listener from leaking flows.
			pc.deliver(payload)
			select {
			case l.accept <- pc:
			case <-l.closed:
				_ = pc.Close()
			}
			continue
		}
		// Existing flow: update peer (migration) and queue.
		pc.observe(src)
		l.mu.Unlock()
		pc.deliver(payload)
	}
}

// ServerPathConn is the listener-side virtual PathConn. It shares
// the listener's UDP socket; writes go through the socket addressed
// to the most-recently-observed peer for this flow_id.
type ServerPathConn struct {
	conn   *net.UDPConn
	flowID [proto.UDPFlowIDSize]byte

	remoteMu sync.RWMutex
	remote   *net.UDPAddr

	inbox chan []byte
	// inboxMu serializes sends with channel close. A dead-flag check
	// alone is not enough for the race detector: Close can close inbox
	// between deliver's dead check and send.
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

func newServerPathConn(c *net.UDPConn, flowID [proto.UDPFlowIDSize]byte, src *net.UDPAddr) *ServerPathConn {
	return &ServerPathConn{
		conn:   c,
		flowID: flowID,
		remote: src,
		inbox:  make(chan []byte, inboxSize),
	}
}

func (p *ServerPathConn) FlowID() [proto.UDPFlowIDSize]byte { return p.flowID }
func (p *ServerPathConn) Writes() uint64                    { return p.writes.Load() }
func (p *ServerPathConn) Reads() uint64                     { return p.reads.Load() }

// observe records a newly-seen 4-tuple for this flow. Subsequent
// writes will target the new addr. This is the rendr migration
// semantic in action - the engine sees no event.
func (p *ServerPathConn) observe(src *net.UDPAddr) {
	p.remoteMu.Lock()
	p.remote = src
	p.remoteMu.Unlock()
}

// deliver pushes an inbound rendr-frame payload to the inbox. If
// the inbox is full the datagram is dropped on the floor - opaque
// UDP is best-effort, dedup belongs in the engine layer.
func (p *ServerPathConn) deliver(payload []byte) {
	p.inboxMu.RLock()
	defer p.inboxMu.RUnlock()
	if p.dead.Load() {
		return
	}
	select {
	case p.inbox <- payload:
	default:
		// Drop; advertise as a lossless transport would be a lie.
	}
}

// Read blocks until the next rendr frame arrives. The returned
// payload is exactly the (proto.Header + payload) bytes the peer
// PathConn put on the wire after stripping the UDPFlowHeader.
func (p *ServerPathConn) Read(buf []byte) (int, error) {
	select {
	case frame, ok := <-p.inbox:
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

	if _, err := p.conn.WriteToUDP(out, dst); err != nil {
		p.declareDeath(err)
		return 0, net.ErrClosed
	}
	p.writes.Add(1)
	return len(frame), nil
}

func (p *ServerPathConn) Close() error {
	if !p.dead.CompareAndSwap(false, true) {
		return nil
	}
	// Drain inbox so any blocked Read sees a clean close.
	p.inboxMu.Lock()
	close(p.inbox)
	p.inboxMu.Unlock()
	return nil
}

func (p *ServerPathConn) Quality() transport.PathQuality {
	p.qualityMu.RLock()
	defer p.qualityMu.RUnlock()
	return p.quality
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
		go fn(transport.Classify(p.deathErr, p.quiesced.Load(), p.byeSeen.Load()), p.deathErr)
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
	if !p.dead.CompareAndSwap(false, true) {
		return
	}
	p.deathMu.Lock()
	p.deathErr = err
	fn := p.deathFn
	p.deathFn = nil
	p.deathMu.Unlock()
	p.inboxMu.Lock()
	close(p.inbox)
	p.inboxMu.Unlock()
	if fn != nil {
		fn(transport.Classify(err, p.quiesced.Load(), p.byeSeen.Load()), err)
	}
}
