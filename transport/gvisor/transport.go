// Package gvisor provides a user-space TCP carrier backed by gVisor netstack.
// It supports both an in-process virtual link for cheap tests and an outer UDP
// packet-carrier link for real process/host boundaries. Selecting this carrier
// does not select gvisor_packet_link_rebind mobility; that requires a
// planner-owned endpoint handle and peer agreement.
package gvisor

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/transport"
	basetcp "github.com/FrankoonG/rendr/transport/tcp"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/veth"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

const (
	nicID      = tcpip.NICID(1)
	mtu        = 1500
	listenIP   = "10.0.0.2"
	listenPort = uint16(8080)
)

var (
	clientIP = tcpip.AddrFrom4([4]byte{10, 0, 0, 1})
	serverIP = tcpip.AddrFrom4([4]byte{10, 0, 0, 2})
)

// Domain owns process-local gVisor listener resolution. A Domain is explicit
// so independent rendr Runtime instances never share hidden endpoint state.
type Domain struct {
	mu        sync.RWMutex
	listeners map[string]*Listener
	nextID    uint64
}

// NewDomain returns an isolated process-local gVisor endpoint domain.
func NewDomain() *Domain {
	return &Domain{listeners: make(map[string]*Listener)}
}

// Transport is the gVisor netstack-backed TCP adapter. A transport returned
// by New dials real outer UDP packet carriers. Domain.Factory returns a
// transport bound to one explicit process-local Domain.
type Transport struct {
	domain       *Domain
	processLocal bool
}

// New returns a gVisor transport for real outer UDP packet carriers.
func New() *Transport { return &Transport{} }

// Factory returns a path factory scoped to d's process-local listeners.
func (d *Domain) Factory() *Transport { return &Transport{domain: d, processLocal: true} }

// Available reports whether the carrier is compiled in. It says nothing about
// whether a particular session is eligible for packet-link rebinding.
func Available() error { return nil }

// DialPath uses the explicit Domain when this Transport came from
// Domain.Factory; otherwise it connects through a real outer UDP packet
// carrier. Each dial creates a fresh gVisor TCP connection.
func (t *Transport) DialPath(ctx context.Context, spec transport.PathSpec) (transport.PathConn, error) {
	if t == nil {
		return nil, errors.New("gvisor: nil Transport")
	}
	if t.processLocal {
		if t.domain == nil {
			return nil, errors.New("gvisor: process-local factory has nil Domain")
		}
		t.domain.mu.RLock()
		l, exists := t.domain.listeners[spec.Address]
		t.domain.mu.RUnlock()
		if !exists || l == nil {
			return nil, fmt.Errorf("gvisor: process-local listener %q is unavailable", spec.Address)
		}
		return l.dial(ctx)
	}
	return dialPacketCarrier(ctx, spec.Address)
}

// Probe dials, captures handshake RTT, and closes.
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

// Listener accepts gVisor TCP paths for one virtual network.
type Listener struct {
	addr    string
	netAddr net.Addr
	domain  *Domain

	client *stack.Stack
	server *stack.Stack
	ln     *gonet.TCPListener
	ep     *channel.Endpoint
	wire   net.PacketConn

	closeOnce   sync.Once
	closeErr    error
	closed      chan struct{}
	acceptCh    chan acceptResult
	acceptDone  chan struct{}
	cleanupOnce sync.Once
	cleanupDone chan struct{}

	lifecycleMu   sync.Mutex
	closing       bool
	admissionDone bool
	active        int
	dialing       int

	remoteMu sync.RWMutex
	remote   net.Addr
	remotes  map[uint16]net.Addr
}

var _ transport.PathListener = (*Listener)(nil)

type acceptResult struct {
	pc  transport.PathConn
	err error
}

// Listen creates a process-local gVisor TCP listener in d. If addr is empty, a
// unique address is allocated within the Domain. The returned address is a
// Domain-local key, not an OS socket address.
func (d *Domain) Listen(addr string) (*Listener, error) {
	if d == nil {
		return nil, errors.New("gvisor: nil Domain")
	}
	d.mu.Lock()
	if d.listeners == nil {
		d.listeners = make(map[string]*Listener)
	}
	if addr == "" {
		for {
			d.nextID++
			addr = fmt.Sprintf("gvisor-%d", d.nextID)
			if _, exists := d.listeners[addr]; !exists {
				break
			}
		}
	}
	if _, exists := d.listeners[addr]; exists {
		d.mu.Unlock()
		return nil, fmt.Errorf("gvisor: listener %q already exists", addr)
	}
	// Reserve the key while stacks are constructed so concurrent duplicate
	// Listen calls cannot both succeed.
	d.listeners[addr] = nil
	d.mu.Unlock()
	reserved := true
	defer func() {
		if !reserved {
			return
		}
		d.mu.Lock()
		if listener, exists := d.listeners[addr]; exists && listener == nil {
			delete(d.listeners, addr)
		}
		d.mu.Unlock()
	}()

	clientEP, serverEP := veth.NewPair(mtu, veth.DefaultBacklogSize)
	clientStack, err := newStack(clientIP, clientEP)
	if err != nil {
		return nil, err
	}
	serverStack, err := newStack(serverIP, serverEP)
	if err != nil {
		clientStack.Close()
		return nil, err
	}
	ln, err := gonet.ListenTCP(serverStack, tcpip.FullAddress{
		NIC:  nicID,
		Addr: serverIP,
		Port: listenPort,
	}, header.IPv4ProtocolNumber)
	if err != nil {
		clientStack.Close()
		serverStack.Close()
		return nil, fmt.Errorf("gvisor: listen tcp: %w", err)
	}

	l := &Listener{
		addr:        addr,
		domain:      d,
		client:      clientStack,
		server:      serverStack,
		ln:          ln,
		closed:      make(chan struct{}),
		acceptCh:    make(chan acceptResult, 1),
		acceptDone:  make(chan struct{}),
		cleanupDone: make(chan struct{}),
	}
	d.mu.Lock()
	d.listeners[addr] = l
	d.mu.Unlock()
	reserved = false
	go l.acceptLoop()
	return l, nil
}

// ListenPacket creates a gVisor TCP listener whose virtual link is
// carried by outer UDP datagrams. Unlike Domain.Listen, addr is a real OS UDP
// listen address, so the transport can span processes or hosts while
// remaining unprivileged.
func ListenPacket(addr string) (*Listener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("gvisor: resolve udp %q: %w", addr, err)
	}
	pc, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("gvisor: listen udp %s: %w", addr, err)
	}
	ep := channel.New(1024, mtu, "")
	serverStack, err := newStack(serverIP, ep)
	if err != nil {
		_ = pc.Close()
		ep.Close()
		return nil, err
	}
	ln, err := gonet.ListenTCP(serverStack, tcpip.FullAddress{
		NIC:  nicID,
		Addr: serverIP,
		Port: listenPort,
	}, header.IPv4ProtocolNumber)
	if err != nil {
		_ = pc.Close()
		ep.Close()
		serverStack.Close()
		return nil, fmt.Errorf("gvisor: listen tcp: %w", err)
	}
	l := &Listener{
		addr:        pc.LocalAddr().String(),
		netAddr:     pc.LocalAddr(),
		server:      serverStack,
		ln:          ln,
		ep:          ep,
		wire:        pc,
		closed:      make(chan struct{}),
		acceptCh:    make(chan acceptResult, 1),
		acceptDone:  make(chan struct{}),
		cleanupDone: make(chan struct{}),
		remotes:     make(map[uint16]net.Addr),
	}
	go l.pumpInbound()
	go l.pumpOutbound()
	go l.acceptLoop()
	return l, nil
}

func newStack(addr tcpip.Address, ep stack.LinkEndpoint) (*stack.Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{gtcp.NewProtocol},
		HandleLocal:        false,
	})
	if err := s.CreateNIC(nicID, ep); err != nil {
		s.Close()
		return nil, fmt.Errorf("gvisor: create NIC: %v", err)
	}
	if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol: header.IPv4ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   addr,
			PrefixLen: 24,
		},
	}, stack.AddressProperties{}); err != nil {
		s.Close()
		return nil, fmt.Errorf("gvisor: add address: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})
	return s, nil
}

// Accept accepts one inbound gVisor TCP path and wraps it in rendr's
// standard length-prefixed PathConn framing.
func (l *Listener) Accept(ctx context.Context) (transport.PathConn, error) {
	select {
	case r := <-l.acceptCh:
		l.lifecycleMu.Lock()
		closing := l.closing
		l.lifecycleMu.Unlock()
		if closing {
			if r.pc != nil {
				_ = r.pc.Close()
			}
			return nil, net.ErrClosed
		}
		return r.pc, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

// AcceptPath delegates to Accept.
func (l *Listener) AcceptPath(ctx context.Context) (transport.PathConn, error) {
	return l.Accept(ctx)
}

// SessionKind reports that gVisor's framed TCP path can carry either rendr
// session contract.
func (*Listener) SessionKind() transport.PathSessionKind {
	return transport.PathSessionAny
}

func (l *Listener) acceptLoop() {
	defer l.finishAdmission()
	for {
		c, err := l.ln.Accept()
		var r acceptResult
		if err != nil {
			r.err = err
		} else {
			var retained bool
			r.pc, retained = l.retainAccepted(c)
			if !retained {
				return
			}
		}
		select {
		case l.acceptCh <- r:
		case <-l.closed:
			if r.pc != nil {
				_ = r.pc.Close()
			}
			return
		}
		if err != nil {
			return
		}
	}
}

// Close stops admission immediately. The virtual network remains alive until
// every accepted path has closed or terminally died.
func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		l.lifecycleMu.Lock()
		l.closing = true
		close(l.closed)
		l.lifecycleMu.Unlock()

		l.ln.Shutdown()
		l.closeErr = l.ln.Close()
		<-l.acceptDone
		l.discardPendingAccepts()
		l.cleanupIfIdle()
	})
	return l.closeErr
}

// Addr returns the Domain-local key or outer packet-carrier address.
func (l *Listener) Addr() net.Addr {
	if l.netAddr != nil {
		return l.netAddr
	}
	return addr(l.addr)
}

// Factory returns the client path factory paired with this listener. For a
// process-local listener it retains the explicit Domain; for a packet-carrier
// listener it dials the listener's real UDP address.
func (l *Listener) Factory() *Transport {
	if l == nil {
		return &Transport{processLocal: true}
	}
	return &Transport{domain: l.domain, processLocal: l.domain != nil}
}

func (l *Listener) dial(ctx context.Context) (transport.PathConn, error) {
	if !l.beginDial() {
		return nil, net.ErrClosed
	}
	c, err := gonet.DialContextTCP(ctx, l.client, tcpip.FullAddress{
		NIC:  nicID,
		Addr: serverIP,
		Port: listenPort,
	}, header.IPv4ProtocolNumber)
	if err != nil {
		closing := l.endDial()
		if closing {
			return nil, net.ErrClosed
		}
		if errors.Is(err, net.ErrClosed) {
			return nil, err
		}
		return nil, fmt.Errorf("gvisor: dial tcp: %w", err)
	}
	if l.finishDial(c) {
		return nil, net.ErrClosed
	}
	return basetcp.Wrap(c), nil
}

func dialPacketCarrier(ctx context.Context, remote string) (transport.PathConn, error) {
	raddr, err := net.ResolveUDPAddr("udp", remote)
	if err != nil {
		return nil, fmt.Errorf("gvisor: resolve udp %q: %w", remote, err)
	}
	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("gvisor: listen udp client: %w", err)
	}
	ep := channel.New(1024, mtu, "")
	clientStack, err := newStack(clientIP, ep)
	if err != nil {
		_ = pc.Close()
		ep.Close()
		return nil, err
	}
	link := &packetLink{ep: ep, wire: pc, remote: raddr}
	go link.pumpInbound()
	go link.pumpOutbound()
	c, err := gonet.DialContextTCP(ctx, clientStack, tcpip.FullAddress{
		NIC:  nicID,
		Addr: serverIP,
		Port: listenPort,
	}, header.IPv4ProtocolNumber)
	if err != nil {
		link.close()
		clientStack.Close()
		return nil, fmt.Errorf("gvisor: dial packet-carrier tcp: %w", err)
	}
	return newRetainedPathConn(basetcp.Wrap(c), func() {
		link.close()
		clientStack.Close()
	}), nil
}

// retainedPathConn keeps its owner's resources alive while the concrete TCP
// path is usable. Embedding the concrete basetcp type preserves its optional
// engine-facing methods in this wrapper's method set.
type retainedPathConn struct {
	*basetcp.PathConn

	releaseOnce sync.Once
	release     func()

	deathMu    sync.Mutex
	dead       bool
	deathCause transport.DeathCause
	deathErr   error
	deathFn    func(transport.DeathCause, error)
}

func newRetainedPathConn(path *basetcp.PathConn, release func()) *retainedPathConn {
	p := &retainedPathConn{PathConn: path, release: release}
	path.OnDeath(p.onDeath)
	return p
}

func (p *retainedPathConn) Close() error {
	err := p.PathConn.Close()
	p.releaseOnce.Do(p.release)
	return err
}

func (p *retainedPathConn) OnDeath(fn func(transport.DeathCause, error)) {
	p.deathMu.Lock()
	if !p.dead {
		p.deathFn = fn
		p.deathMu.Unlock()
		return
	}
	cause, err := p.deathCause, p.deathErr
	p.deathMu.Unlock()
	if fn != nil {
		go fn(cause, err)
	}
}

func (p *retainedPathConn) onDeath(cause transport.DeathCause, err error) {
	p.releaseOnce.Do(p.release)
	p.deathMu.Lock()
	p.dead = true
	p.deathCause = cause
	p.deathErr = err
	fn := p.deathFn
	p.deathFn = nil
	p.deathMu.Unlock()
	if fn != nil {
		fn(cause, err)
	}
}

func (l *Listener) retainAccepted(c net.Conn) (transport.PathConn, bool) {
	l.lifecycleMu.Lock()
	if l.closing {
		l.lifecycleMu.Unlock()
		_ = c.Close()
		return nil, false
	}
	l.active++
	l.lifecycleMu.Unlock()
	return newRetainedPathConn(basetcp.Wrap(c), l.releaseAccepted), true
}

func (l *Listener) releaseAccepted() {
	l.lifecycleMu.Lock()
	if l.active > 0 {
		l.active--
	}
	cleanup := l.cleanupReadyLocked()
	l.lifecycleMu.Unlock()
	if cleanup {
		l.cleanupShared()
	}
}

func (l *Listener) beginDial() bool {
	l.lifecycleMu.Lock()
	defer l.lifecycleMu.Unlock()
	if l.closing {
		return false
	}
	l.dialing++
	return true
}

func (l *Listener) endDial() bool {
	l.lifecycleMu.Lock()
	l.dialing--
	closing := l.closing
	cleanup := l.cleanupReadyLocked()
	l.lifecycleMu.Unlock()
	if cleanup {
		l.cleanupShared()
	}
	return closing
}

func (l *Listener) finishDial(c net.Conn) bool {
	closing := l.endDial()
	if closing {
		_ = c.Close()
	}
	return closing
}

func (l *Listener) finishAdmission() {
	l.lifecycleMu.Lock()
	l.admissionDone = true
	cleanup := l.cleanupReadyLocked()
	l.lifecycleMu.Unlock()
	close(l.acceptDone)
	if cleanup {
		l.cleanupShared()
	}
}

func (l *Listener) discardPendingAccepts() {
	for {
		select {
		case r := <-l.acceptCh:
			if r.pc != nil {
				_ = r.pc.Close()
			}
		default:
			return
		}
	}
}

func (l *Listener) cleanupIfIdle() {
	l.lifecycleMu.Lock()
	cleanup := l.cleanupReadyLocked()
	l.lifecycleMu.Unlock()
	if cleanup {
		l.cleanupShared()
	}
}

func (l *Listener) cleanupReadyLocked() bool {
	return l.closing && l.admissionDone && l.active == 0 && l.dialing == 0
}

func (l *Listener) cleanupShared() {
	l.cleanupOnce.Do(func() {
		if l.domain != nil {
			l.domain.mu.Lock()
			if l.domain.listeners[l.addr] == l {
				delete(l.domain.listeners, l.addr)
			}
			l.domain.mu.Unlock()
		}
		if l.wire != nil {
			_ = l.wire.Close()
		}
		if l.ep != nil {
			l.ep.Close()
		}
		if l.client != nil {
			l.client.Close()
		}
		if l.server != nil {
			l.server.Close()
		}
		close(l.cleanupDone)
	})
}

func (l *Listener) pumpInbound() {
	buf := make([]byte, mtu)
	for {
		n, addr, err := l.wire.ReadFrom(buf)
		if err != nil {
			return
		}
		l.remoteMu.Lock()
		l.remote = addr
		if port, ok := tcpSrcPort(buf[:n]); ok {
			l.remotes[port] = addr
		}
		l.remoteMu.Unlock()
		injectIPv4(l.ep, buf[:n])
	}
}

func (l *Listener) pumpOutbound() {
	for {
		pkt := l.ep.ReadContext(context.Background())
		if pkt == nil {
			return
		}
		view := pkt.ToView()
		pkt.DecRef()
		packet := append([]byte(nil), view.AsSlice()...)
		view.Release()
		var remote net.Addr
		if port, ok := tcpDstPort(packet); ok {
			l.remoteMu.RLock()
			remote = l.remotes[port]
			l.remoteMu.RUnlock()
		}
		l.remoteMu.RLock()
		if remote == nil {
			remote = l.remote
		}
		l.remoteMu.RUnlock()
		if remote == nil {
			continue
		}
		if _, err := l.wire.WriteTo(packet, remote); err != nil {
			return
		}
	}
}

type packetLink struct {
	ep     *channel.Endpoint
	wire   net.PacketConn
	remote net.Addr
	once   sync.Once
}

func (l *packetLink) pumpInbound() {
	buf := make([]byte, mtu)
	for {
		n, _, err := l.wire.ReadFrom(buf)
		if err != nil {
			return
		}
		injectIPv4(l.ep, buf[:n])
	}
}

func (l *packetLink) pumpOutbound() {
	for {
		pkt := l.ep.ReadContext(context.Background())
		if pkt == nil {
			return
		}
		view := pkt.ToView()
		pkt.DecRef()
		packet := append([]byte(nil), view.AsSlice()...)
		view.Release()
		if _, err := l.wire.WriteTo(packet, l.remote); err != nil {
			return
		}
	}
}

func (l *packetLink) close() {
	l.once.Do(func() {
		_ = l.wire.Close()
		l.ep.Close()
	})
}

type addr string

func (a addr) Network() string { return "gvisor" }
func (a addr) String() string  { return string(a) }

func injectIPv4(ep *channel.Endpoint, packet []byte) {
	if len(packet) == 0 || packet[0]>>4 != 4 {
		return
	}
	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(packet),
	})
	ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
}

func tcpSrcPort(packet []byte) (uint16, bool) {
	return tcpPort(packet, 0)
}

func tcpDstPort(packet []byte) (uint16, bool) {
	return tcpPort(packet, 2)
}

func tcpPort(packet []byte, off int) (uint16, bool) {
	if len(packet) < 20 || packet[0]>>4 != 4 || packet[9] != 6 {
		return 0, false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl+4 {
		return 0, false
	}
	return binary.BigEndian.Uint16(packet[ihl+off : ihl+off+2]), true
}
