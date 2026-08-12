// Package gvisor provides a user-space TCP carrier backed by gVisor netstack.
// It supports both an in-process virtual link for cheap tests and an outer UDP
// packet-carrier link for real process/host boundaries. Selecting this carrier
// does not select gvisor_packet_link_rebind mobility; that requires a
// planner-owned endpoint handle and peer agreement.
package gvisor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
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
	nicID           = tcpip.NICID(1)
	processLocalMTU = 1500
	listenIP        = "10.0.0.2"
	listenPort      = uint16(8080)

	maxPacketLinks        = 4096
	maxPendingPacketLinks = 32
	packetAdmissionTTL    = 10 * time.Second
	packetOutboundQueued  = 256
)

var (
	processClientIPv4 = [4]byte{10, 0, 0, 1}
	serverIPv4        = [4]byte{10, 0, 0, 2}
	clientIP          = tcpip.AddrFrom4(processClientIPv4)
	serverIP          = tcpip.AddrFrom4(serverIPv4)
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
	domain           *Domain
	processLocal     bool
	packetSecurity   packetSecurity
	packetConfigErr  error
	replayBudgetOnce sync.Once
	replayBudget     *packetReplayBudget
}

// New returns a gVisor transport for real outer UDP packet carriers. Packet
// dialing fails with ErrPacketTrustRequired unless options explicitly assert a
// trusted C2 carrier or configure a PSK. Configuration errors are reported by
// DialPath; NewPacket is available when eager validation is preferred.
func New(options ...PacketOption) *Transport {
	security, err := resolvePacketSecurity(options)
	return &Transport{
		packetSecurity: security, packetConfigErr: err, replayBudget: newDefaultPacketReplayBudget(),
	}
}

// NewPacket returns an eagerly validated outer UDP packet transport.
func NewPacket(options ...PacketOption) (*Transport, error) {
	security, err := resolvePacketSecurity(options)
	if err != nil {
		return nil, err
	}
	if err := PacketAvailable(); err != nil {
		return nil, err
	}
	return &Transport{packetSecurity: security, replayBudget: newDefaultPacketReplayBudget()}, nil
}

// Factory returns a path factory scoped to d's process-local listeners.
func (d *Domain) Factory() *Transport { return &Transport{domain: d, processLocal: true} }

// Available reports whether process-local gVisor carriers are compiled in. Use
// PacketAvailable for real outer UDP packet carriers. Neither method says
// whether a particular session is eligible for packet-link rebinding.
func Available() error { return nil }

// DialPath uses the explicit Domain when this Transport came from
// Domain.Factory; otherwise it connects through a real outer UDP packet
// carrier. Each dial creates a fresh gVisor TCP connection.
func (t *Transport) DialPath(ctx context.Context, spec transport.PathSpec) (transport.PathConn, error) {
	if t == nil {
		return nil, errors.New("gvisor: nil Transport")
	}
	if ctx == nil {
		ctx = context.Background()
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
	if t.packetConfigErr != nil {
		return nil, t.packetConfigErr
	}
	if t.packetSecurity.mode == packetTrustUnset {
		return nil, ErrPacketTrustRequired
	}
	return dialPacketCarrier(ctx, spec.Address, t.packetSecurity, t.packetReplayBudget())
}

func (t *Transport) packetReplayBudget() *packetReplayBudget {
	t.replayBudgetOnce.Do(func() {
		if t.replayBudget == nil {
			t.replayBudget = newDefaultPacketReplayBudget()
		}
	})
	return t.replayBudget
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
	shared *packetWire

	closeOnce    sync.Once
	shutdownOnce sync.Once
	closeErr     error
	terminalErr  error
	closed       chan struct{}
	acceptCh     chan acceptResult
	acceptDone   chan struct{}
	cleanupOnce  sync.Once
	cleanupDone  chan struct{}

	lifecycleMu   sync.Mutex
	closing       bool
	admissionDone bool
	active        int
	dialing       int

	packetMu           sync.RWMutex
	packetLinks        map[linkID]*linkOwner
	packetByIP         map[[4]byte]*linkOwner
	packetPending      map[linkID]struct{}
	nextPacketIP       uint32
	packetSecurity     packetSecurity
	packetCookieKey    linkSecret
	serverReplayBudget *packetReplayBudget
	clientReplayBudget *packetReplayBudget
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

	clientEP, serverEP := veth.NewPair(processLocalMTU, veth.DefaultBacklogSize)
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
func ListenPacket(addr string, options ...PacketOption) (*Listener, error) {
	security, err := resolvePacketSecurity(options)
	if err != nil {
		return nil, err
	}
	cookieKey, err := newPacketCookieKey()
	if err != nil {
		return nil, err
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("gvisor: resolve udp %q: %w", addr, err)
	}
	udpMode, err := outerUDPListenerMode(udpAddr)
	if err != nil {
		return nil, err
	}
	sharedWire, err := listenOuterUDPWire(udpMode, udpAddr, true)
	if err != nil {
		return nil, fmt.Errorf("gvisor: listen udp %s: %w", addr, err)
	}
	pc, ok := sharedWire.conn.(*net.UDPConn)
	if !ok {
		sharedWire.close()
		return nil, errors.New("gvisor: outer UDP listener is not a UDP socket")
	}
	ep := channel.New(1024, packetMTU, "")
	serverStack, err := newStack(serverIP, ep)
	if err != nil {
		sharedWire.close()
		ep.Close()
		return nil, err
	}
	ln, err := gonet.ListenTCP(serverStack, tcpip.FullAddress{
		NIC:  nicID,
		Addr: serverIP,
		Port: listenPort,
	}, header.IPv4ProtocolNumber)
	if err != nil {
		sharedWire.close()
		ep.Close()
		serverStack.Close()
		return nil, fmt.Errorf("gvisor: listen tcp: %w", err)
	}
	l := &Listener{
		addr:               pc.LocalAddr().String(),
		netAddr:            pc.LocalAddr(),
		server:             serverStack,
		ln:                 ln,
		ep:                 ep,
		wire:               pc,
		shared:             sharedWire,
		closed:             make(chan struct{}),
		acceptCh:           make(chan acceptResult, 1),
		acceptDone:         make(chan struct{}),
		cleanupDone:        make(chan struct{}),
		packetLinks:        make(map[linkID]*linkOwner),
		packetByIP:         make(map[[4]byte]*linkOwner),
		packetPending:      make(map[linkID]struct{}),
		packetSecurity:     security,
		packetCookieKey:    cookieKey,
		serverReplayBudget: newDefaultPacketReplayBudget(),
		clientReplayBudget: newDefaultPacketReplayBudget(),
	}
	go l.pumpPacketInbound()
	go l.pumpPacketOutbound()
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
			return nil, l.listenerTerminalError()
		}
		if r.err != nil {
			if terminal := l.listenerTerminalError(); !errors.Is(terminal, net.ErrClosed) {
				return nil, terminal
			}
		}
		return r.pc, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.closed:
		return nil, l.listenerTerminalError()
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
			if r.pc == nil {
				continue
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
		l.beginShutdown(nil)
		<-l.acceptDone
		l.discardPendingAccepts()
		l.closePendingPacketLinks()
		l.cleanupIfIdle()
	})
	l.lifecycleMu.Lock()
	err := l.closeErr
	if l.terminalErr != nil {
		err = l.terminalErr
	}
	l.lifecycleMu.Unlock()
	return err
}

func (l *Listener) beginShutdown(cause error) {
	if l == nil {
		return
	}
	l.lifecycleMu.Lock()
	if cause != nil && l.terminalErr == nil {
		l.terminalErr = cause
	}
	l.lifecycleMu.Unlock()
	l.shutdownOnce.Do(func() {
		l.lifecycleMu.Lock()
		l.closing = true
		close(l.closed)
		l.lifecycleMu.Unlock()
		l.ln.Shutdown()
		closeErr := l.ln.Close()
		l.lifecycleMu.Lock()
		if l.closeErr == nil {
			l.closeErr = closeErr
		}
		l.lifecycleMu.Unlock()
	})
}

func (l *Listener) listenerTerminalError() error {
	if l == nil {
		return net.ErrClosed
	}
	l.lifecycleMu.Lock()
	err := l.terminalErr
	l.lifecycleMu.Unlock()
	if err != nil {
		return err
	}
	return net.ErrClosed
}

func (l *Listener) closePendingPacketLinks() {
	if l == nil || l.domain != nil {
		return
	}
	l.packetMu.RLock()
	owners := make([]*linkOwner, 0, len(l.packetLinks))
	for _, owner := range l.packetLinks {
		owner.mu.Lock()
		pending := owner.endpoint == nil && !owner.closed
		owner.mu.Unlock()
		if pending {
			owners = append(owners, owner)
		}
	}
	l.packetMu.RUnlock()
	for _, owner := range owners {
		owner.close()
		<-owner.done
	}
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
	return &Transport{
		domain: l.domain, processLocal: l.domain != nil, packetSecurity: l.packetSecurity,
		replayBudget: l.clientReplayBudget,
	}
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
	return newRetainedOwnedPathConn(
		basetcp.Wrap(c), nil, leafmobility.RoleDialer, leafmobility.ScopeProcessLocal,
	), nil
}

func dialPacketCarrier(
	ctx context.Context,
	remote string,
	security packetSecurity,
	replayBudget *packetReplayBudget,
) (transport.PathConn, error) {
	raddr, err := net.ResolveUDPAddr("udp", remote)
	if err != nil {
		return nil, fmt.Errorf("gvisor: resolve udp %q: %w", remote, err)
	}
	udpMode, err := outerUDPRemoteMode(raddr)
	if err != nil {
		return nil, err
	}
	wire, err := listenOuterUDPWire(udpMode, nil, false)
	if err != nil {
		return nil, fmt.Errorf("gvisor: listen udp client: %w", err)
	}
	if _, ok := wire.conn.(*net.UDPConn); !ok {
		wire.close()
		return nil, errors.New("gvisor: outer UDP client is not a UDP socket")
	}
	id, err := newLinkID()
	if err != nil {
		wire.close()
		return nil, err
	}
	openCtx, cancelOpen := context.WithTimeout(ctx, packetAdmissionTTL)
	virtualIP, secret, err := openPacketLink(openCtx, wire, raddr, id, security)
	cancelOpen()
	if err != nil {
		wire.close()
		return nil, err
	}
	ep := channel.New(1024, packetMTU, "")
	clientStack, err := newStack(tcpip.AddrFrom4(virtualIP), ep)
	if err != nil {
		wire.close()
		ep.Close()
		return nil, err
	}
	link, err := newLinkOwnerWithReplayBudget(
		id, secret, leafmobility.RoleDialer, virtualIP, wire, raddr, nil,
		func(packet []byte) { injectIPv4(ep, packet) },
		replayBudget,
	)
	if err != nil {
		wire.close()
		ep.Close()
		clientStack.Close()
		return nil, err
	}
	link.startReceiver(link.active)
	link.startOutbound()
	go pumpEndpointOutbound(ep, link)
	c, err := gonet.DialContextTCP(ctx, clientStack, tcpip.FullAddress{
		NIC:  nicID,
		Addr: serverIP,
		Port: listenPort,
	}, header.IPv4ProtocolNumber)
	if err != nil {
		link.close()
		ep.Close()
		clientStack.Close()
		return nil, fmt.Errorf("gvisor: dial packet-carrier tcp: %w", err)
	}
	if err := link.bindEndpoint(c, func() {
		ep.Close()
		clientStack.Close()
	}); err != nil {
		_ = c.Close()
		link.close()
		ep.Close()
		clientStack.Close()
		return nil, err
	}
	path, err := newRetainedPacketPathConn(basetcp.Wrap(c), link, leafmobility.RoleDialer)
	if err != nil {
		link.close()
		return nil, err
	}
	return path, nil
}

func openPacketLink(
	ctx context.Context,
	wire *packetWire,
	remote net.Addr,
	id linkID,
	security packetSecurity,
) ([4]byte, linkSecret, error) {
	private, public, err := newLinkKeyPair()
	if err != nil {
		return [4]byte{}, linkSecret{}, err
	}
	nonce, err := newLinkNonce()
	if err != nil {
		return [4]byte{}, linkSecret{}, err
	}
	var cookie outerCookie
	buf := make([]byte, outerHeaderSize+outerOpenPayloadSize+outerAuthTagSize+1)
	for {
		if err := ctx.Err(); err != nil {
			return [4]byte{}, linkSecret{}, err
		}
		proof := security.admissionProof(id, public, nonce, cookie)
		request, err := encodeOuter(outerFrame{
			Type: outerTypeOpen, LinkID: id, Generation: 1,
			Payload: marshalOpen(public, nonce, cookie, proof),
		}, linkSecret{})
		if err != nil {
			return [4]byte{}, linkSecret{}, err
		}
		n, writeErr := wire.writeTo(ctx, request, remote)
		if writeErr != nil || n != len(request) {
			if writeErr == nil {
				writeErr = fmt.Errorf("short write %d/%d", n, len(request))
			}
			return [4]byte{}, linkSecret{}, fmt.Errorf("gvisor: send packet-link OPEN: %w", writeErr)
		}
		deadline := time.Now().Add(outerControlRetry)
		if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
			deadline = contextDeadline
		}
		if err := wire.conn.SetReadDeadline(deadline); err != nil {
			return [4]byte{}, linkSecret{}, err
		}
		for {
			n, source, readErr := wire.conn.ReadFrom(buf)
			if readErr != nil {
				if timeout, ok := readErr.(net.Error); ok && timeout.Timeout() && ctx.Err() == nil {
					break
				}
				return [4]byte{}, linkSecret{}, readErr
			}
			header, headerErr := decodeOuterHeader(buf[:n])
			if headerErr != nil || header.LinkID != id || header.Generation != 1 ||
				!addrEqualOnWire(wire, source, remote) {
				continue
			}
			if header.Type == outerTypeCookie {
				responseCookie, cookieErr := parseOuterCookie(header.Payload)
				if cookieErr == nil {
					cookie = responseCookie
					break
				}
				continue
			}
			if header.Type != outerTypeOpenAck || cookie == (outerCookie{}) {
				continue
			}
			serverPublic, virtualIP, responseNonce, parseErr := parseOpenAck(header.Payload)
			if parseErr != nil || responseNonce != nonce {
				continue
			}
			secret, secretErr := deriveLinkSecret(private, serverPublic, id, nonce, security)
			if secretErr != nil {
				continue
			}
			if _, decodeErr := decodeOuter(buf[:n], secret); decodeErr == nil {
				observation, observeErr := observeUDPRouteForWire(ctx, wire, remote)
				if observeErr != nil {
					return [4]byte{}, linkSecret{}, fmt.Errorf(
						"gvisor: observe initial packet-link route: %w", observeErr,
					)
				}
				if mtuErr := observation.maximumDataError(); mtuErr != nil {
					return [4]byte{}, linkSecret{}, mtuErr
				}
				qualificationContext, contextErr := qualificationAdmissionContext(nonce)
				if contextErr != nil {
					return [4]byte{}, linkSecret{}, contextErr
				}
				qualifier := &linkOwner{id: id, secret: secret}
				if _, qualifyErr := qualifier.runMaximumDataQualification(
					ctx, wire, remote, 1, outerQualificationAdmission, qualificationContext,
				); qualifyErr != nil {
					return [4]byte{}, linkSecret{}, fmt.Errorf(
						"gvisor: qualify initial packet-link maximum DATA: %w", qualifyErr,
					)
				}
				return virtualIP, secret, nil
			}
		}
	}
}

// retainedPathConn keeps its owner's resources alive while the concrete TCP
// path is usable. Embedding the concrete basetcp type preserves its optional
// engine-facing methods in this wrapper's method set.
type retainedPathConn struct {
	*basetcp.PathConn
	claim *leafmobility.Claim
	link  *linkOwner

	releaseOnce sync.Once
	release     func()

	deathMu    sync.Mutex
	dead       bool
	deathCause transport.DeathCause
	deathErr   error
	deathFn    func(transport.DeathCause, error)
}

func newRetainedPathConn(
	path *basetcp.PathConn,
	claim *leafmobility.Claim,
	release func(),
) *retainedPathConn {
	if release == nil {
		release = func() {}
	}
	p := &retainedPathConn{PathConn: path, claim: claim, release: release}
	path.OnDeath(p.onDeath)
	return p
}

func newRetainedOwnedPathConn(path *basetcp.PathConn, release func(), role leafmobility.Role, scope leafmobility.Scope) *retainedPathConn {
	claim := leafmobility.MustNewClaim(leafmobility.Facts{
		Kind:       leafmobility.KindGVisor,
		Role:       role,
		Scope:      scope,
		Session:    leafmobility.SessionAny,
		Generation: leafmobility.NextGeneration(),
	})
	return newRetainedPathConn(path, claim, release)
}

func newRetainedPacketPathConn(
	path *basetcp.PathConn,
	link *linkOwner,
	role leafmobility.Role,
) (*retainedPathConn, error) {
	claim, err := newPacketLinkClaim(link, role)
	if err != nil {
		return nil, err
	}
	p := newRetainedPathConn(path, claim, link.close)
	p.link = link
	return p, nil
}

func (p *retainedPathConn) LeafMobilityClaim() *leafmobility.Claim {
	if p == nil {
		return nil
	}
	return p.claim
}

func (p *retainedPathConn) SubscribeLeafMobilityRefresh(
	ctx context.Context,
	fn func(leafmobility.RefreshEvidence),
) (func(), error) {
	if p == nil || p.link == nil {
		return nil, errors.New("gvisor: packet-link mobility refresh is unavailable")
	}
	return p.link.subscribeRefresh(ctx, fn)
}

func (p *retainedPathConn) CommitLeafMobilityRefresh(evidence leafmobility.RefreshEvidence) error {
	if p == nil || p.link == nil {
		return errors.New("gvisor: packet-link mobility refresh is unavailable")
	}
	return p.link.commitRefresh(evidence)
}

func (p *retainedPathConn) Close() error {
	p.claim.RetireUnbound()
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
	p.claim.RetireUnbound()
	p.releaseOnce.Do(p.release)
	if p.link != nil {
		if terminalErr := p.link.terminalError(); terminalErr != nil {
			err = terminalErr
			cause = transport.Classify(err, false, false)
		}
	}
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
	if l.domain != nil {
		return newRetainedOwnedPathConn(
			basetcp.Wrap(c), l.releaseAccepted, leafmobility.RoleAcceptor, leafmobility.ScopeProcessLocal,
		), true
	}
	remote, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok || remote.IP.To4() == nil {
		l.releaseAccepted()
		_ = c.Close()
		return nil, true
	}
	var virtualIP [4]byte
	copy(virtualIP[:], remote.IP.To4())
	l.packetMu.RLock()
	owner := l.packetByIP[virtualIP]
	l.packetMu.RUnlock()
	if owner == nil {
		l.releaseAccepted()
		_ = c.Close()
		return nil, true
	}
	if err := owner.bindEndpoint(c, l.releaseAccepted); err != nil {
		l.releaseAccepted()
		_ = c.Close()
		return nil, true
	}
	l.packetMu.Lock()
	delete(l.packetPending, owner.id)
	l.packetMu.Unlock()
	path, err := newRetainedPacketPathConn(basetcp.Wrap(c), owner, leafmobility.RoleAcceptor)
	if err != nil {
		owner.close()
		return nil, true
	}
	return path, true
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
		if l.shared != nil {
			l.shared.close()
		} else if l.wire != nil {
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

func (l *Listener) pumpPacketInbound() {
	buf := make([]byte, outerHeaderSize+outerDataSequenceSize+packetMTU+outerAuthTagSize+1)
	for {
		n, remote, err := l.wire.ReadFrom(buf)
		if err != nil {
			l.failSharedPacketReader(err)
			return
		}
		if n > outerMaxDatagramSize {
			continue
		}
		header, err := decodeOuterHeader(buf[:n])
		if err != nil {
			continue
		}
		if header.Type == outerTypeOpen {
			l.handlePacketOpen(remote, buf[:n], header)
			continue
		}
		l.packetMu.RLock()
		owner := l.packetLinks[header.LinkID]
		l.packetMu.RUnlock()
		if owner != nil {
			owner.handleDatagram(l.shared, remote, buf[:n])
		}
	}
}

func (l *Listener) failSharedPacketReader(cause error) {
	if l == nil || cause == nil {
		return
	}
	l.lifecycleMu.Lock()
	alreadyClosing := l.closing
	hasTerminal := l.terminalErr != nil
	l.lifecycleMu.Unlock()
	if alreadyClosing && !hasTerminal && errors.Is(cause, net.ErrClosed) {
		return
	}
	cause = classifyOuterMTUError(outerMaxDatagramSize, cause)
	l.beginShutdown(cause)
	cause = l.listenerTerminalError()
	if l.shared != nil {
		l.shared.setError(cause)
	}
	l.packetMu.RLock()
	owners := make([]*linkOwner, 0, len(l.packetLinks))
	for _, owner := range l.packetLinks {
		owners = append(owners, owner)
	}
	l.packetMu.RUnlock()
	for _, owner := range owners {
		owner.failClosed(cause)
	}
	l.cleanupIfIdle()
}

func (l *Listener) handlePacketOpen(remote net.Addr, datagram []byte, header outerFrame) {
	clientPublic, nonce, cookie, proof, err := parseOpen(header.Payload)
	if err != nil {
		return
	}
	frame, err := decodeOuter(datagram, linkSecret{})
	if err != nil || frame.Type != outerTypeOpen || frame.Generation != 1 {
		return
	}
	if !validPacketAdmissionCookie(
		l.packetCookieKey, remote, frame.LinkID, clientPublic, nonce, cookie, time.Now(),
	) {
		bucket := time.Now().Unix() / int64(packetCookiePeriod/time.Second)
		challenge := packetAdmissionCookie(l.packetCookieKey, remote, frame.LinkID, clientPublic, nonce, bucket)
		_ = l.sendPacketCookie(remote, frame.LinkID, challenge)
		return
	}
	if !l.packetSecurity.validateAdmissionProof(frame.LinkID, clientPublic, nonce, cookie, proof) {
		return
	}
	l.lifecycleMu.Lock()
	if l.closing {
		l.lifecycleMu.Unlock()
		return
	}
	l.packetMu.Lock()
	owner := l.packetLinks[frame.LinkID]
	if owner != nil {
		owner.mu.Lock()
		sameAdmission := owner.admissionClientKey == clientPublic && owner.admissionNonce == nonce &&
			addrEqualOnWire(owner.active, owner.peerRemote, remote) &&
			!owner.closed && !owner.closing
		ack := append([]byte(nil), owner.admissionAck...)
		owner.mu.Unlock()
		l.packetMu.Unlock()
		l.lifecycleMu.Unlock()
		if sameAdmission {
			_ = l.sendPacketOpenAck(remote, ack)
		}
		return
	}
	if len(l.packetLinks) >= maxPacketLinks || len(l.packetPending) >= maxPendingPacketLinks {
		l.packetMu.Unlock()
		l.lifecycleMu.Unlock()
		return
	}
	virtualIP, ok := l.allocatePacketIPLocked()
	if !ok {
		l.packetMu.Unlock()
		l.lifecycleMu.Unlock()
		return
	}
	serverPrivate, serverPublic, err := newLinkKeyPair()
	if err != nil {
		l.packetMu.Unlock()
		l.lifecycleMu.Unlock()
		return
	}
	secret, err := deriveLinkSecret(serverPrivate, clientPublic, frame.LinkID, nonce, l.packetSecurity)
	if err != nil {
		l.packetMu.Unlock()
		l.lifecycleMu.Unlock()
		return
	}
	ack, err := encodeOuterControl(outerFrame{
		Type: outerTypeOpenAck, LinkID: frame.LinkID, Generation: 1,
		Payload: marshalOpenAck(serverPublic, virtualIP, nonce),
	}, secret)
	if err != nil {
		l.packetMu.Unlock()
		l.lifecycleMu.Unlock()
		return
	}
	owner, err = newLinkOwnerWithReplayBudget(
		frame.LinkID, secret, leafmobility.RoleAcceptor, virtualIP, l.shared, remote, l,
		func(packet []byte) { injectIPv4(l.ep, packet) },
		l.serverReplayBudget,
	)
	if err != nil {
		l.packetMu.Unlock()
		l.lifecycleMu.Unlock()
		return
	}
	owner.admissionClientKey = clientPublic
	owner.admissionNonce = nonce
	owner.admissionAck = append([]byte(nil), ack...)
	owner.admissionQualified = false
	l.packetLinks[frame.LinkID] = owner
	l.packetByIP[virtualIP] = owner
	l.packetPending[frame.LinkID] = struct{}{}
	l.packetMu.Unlock()
	l.lifecycleMu.Unlock()
	owner.armAdmissionTimeout(packetAdmissionTTL)
	if err := l.sendPacketOpenAck(remote, ack); err != nil {
		owner.close()
		return
	}
}

func (l *Listener) sendPacketCookie(remote net.Addr, id linkID, cookie outerCookie) error {
	payload, err := marshalOuterCookie(cookie)
	if err != nil {
		return err
	}
	datagram, err := encodeOuter(outerFrame{
		Type: outerTypeCookie, LinkID: id, Generation: 1, Payload: payload,
	}, linkSecret{})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), outerWriteBound)
	defer cancel()
	n, err := l.shared.writeTo(ctx, datagram, remote)
	if err != nil {
		return err
	}
	if n != len(datagram) {
		return fmt.Errorf("gvisor: short packet-link COOKIE write %d/%d", n, len(datagram))
	}
	return nil
}

func (l *Listener) sendPacketOpenAck(remote net.Addr, datagram []byte) error {
	if len(datagram) != outerHeaderSize+outerOpenAckPayloadSize+outerAuthTagSize {
		return errors.New("gvisor: invalid packet-link OPEN_ACK")
	}
	ctx, cancel := context.WithTimeout(context.Background(), outerWriteBound)
	defer cancel()
	n, err := l.shared.writeTo(ctx, datagram, remote)
	if err != nil {
		return err
	}
	if n != len(datagram) {
		return fmt.Errorf("gvisor: short packet-link OPEN_ACK write %d/%d", n, len(datagram))
	}
	return nil
}

func (l *Listener) allocatePacketIPLocked() ([4]byte, bool) {
	const addressCount = uint32(1 << 22)
	for range addressCount {
		l.nextPacketIP = (l.nextPacketIP + 1) % addressCount
		value := l.nextPacketIP
		candidate := [4]byte{10, byte(64 + value>>16), byte(value >> 8), byte(value)}
		if candidate == serverIPv4 || candidate == processClientIPv4 || candidate[3] == 0 || candidate[3] == 255 {
			continue
		}
		if _, exists := l.packetByIP[candidate]; !exists {
			return candidate, true
		}
	}
	return [4]byte{}, false
}

func (l *Listener) pumpPacketOutbound() {
	for {
		packet, ok := readEndpointPacket(l.ep)
		if !ok {
			return
		}
		destination, ok := ipv4Destination(packet)
		if !ok {
			continue
		}
		l.packetMu.RLock()
		owner := l.packetByIP[destination]
		l.packetMu.RUnlock()
		if owner == nil {
			continue
		}
		owner.enqueueSharedPacket(packet)
	}
}

func pumpEndpointOutbound(ep *channel.Endpoint, owner *linkOwner) {
	for {
		packet, ok := readEndpointPacket(ep)
		if !ok {
			return
		}
		if err := owner.enqueuePacket(packet); err != nil {
			return
		}
	}
}

func readEndpointPacket(ep *channel.Endpoint) ([]byte, bool) {
	if ep == nil {
		return nil, false
	}
	pkt := ep.ReadContext(context.Background())
	if pkt == nil {
		return nil, false
	}
	view := pkt.ToView()
	pkt.DecRef()
	packet := append([]byte(nil), view.AsSlice()...)
	view.Release()
	return packet, true
}

func (l *Listener) unregisterPacketLink(owner *linkOwner) {
	if l == nil || owner == nil {
		return
	}
	l.packetMu.Lock()
	if l.packetLinks[owner.id] == owner {
		delete(l.packetLinks, owner.id)
	}
	if l.packetByIP[owner.virtualIP] == owner {
		delete(l.packetByIP, owner.virtualIP)
	}
	delete(l.packetPending, owner.id)
	l.packetMu.Unlock()
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

func ipv4Destination(packet []byte) ([4]byte, bool) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return [4]byte{}, false
	}
	var destination [4]byte
	copy(destination[:], packet[16:20])
	return destination, true
}
