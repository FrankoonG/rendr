// Package gvisor provides a user-space TCP transport backed by gVisor
// netstack. It is the M4 no-CAP_NET_ADMIN companion to tcprepair:
// no kernel TCP_REPAIR sockopts are needed, and steady-state bytes are
// carried by gVisor TCP endpoints over an in-process virtual link.
package gvisor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/transport"
	basetcp "github.com/FrankoonG/rendr/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
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

	regMu    sync.RWMutex
	registry = map[string]*Listener{}
	nextID   atomic.Uint64
)

// Transport is the gVisor netstack-backed TCP adapter.
type Transport struct{}

// New returns a gVisor transport.
func New() *Transport { return &Transport{} }

func init() {
	if err := transport.Default.Register(New()); err != nil {
		panic(err)
	}
}

// Name implements transport.Transport.
func (*Transport) Name() string { return "gvisor" }

// Available reports whether the adapter is compiled in. Unlike
// tcprepair, gVisor netstack needs no kernel capability probe.
func Available() error { return nil }

// DialPath connects to a process-local gVisor listener created by
// Listen. The listener owns the virtual link and server stack; each
// dial creates a fresh gVisor TCP connection over the client stack.
func (*Transport) DialPath(ctx context.Context, spec transport.PathSpec) (transport.PathConn, error) {
	regMu.RLock()
	l := registry[spec.Address]
	regMu.RUnlock()
	if l == nil {
		return nil, fmt.Errorf("gvisor: listener %q not found", spec.Address)
	}
	return l.dial(ctx)
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
	addr string

	client *stack.Stack
	server *stack.Stack
	ln     *gonet.TCPListener

	closeOnce sync.Once
	closed    chan struct{}
	acceptCh  chan acceptResult
}

type acceptResult struct {
	pc  transport.PathConn
	err error
}

// Listen creates a process-local gVisor TCP listener. If addr is
// empty, a unique address is allocated. The returned address is a
// registry key, not an OS socket address.
func Listen(addr string) (*Listener, error) {
	if addr == "" {
		addr = fmt.Sprintf("gvisor-%d", nextID.Add(1))
	}

	regMu.Lock()
	if _, exists := registry[addr]; exists {
		regMu.Unlock()
		return nil, fmt.Errorf("gvisor: listener %q already exists", addr)
	}
	regMu.Unlock()

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
		addr:     addr,
		client:   clientStack,
		server:   serverStack,
		ln:       ln,
		closed:   make(chan struct{}),
		acceptCh: make(chan acceptResult, 1),
	}
	regMu.Lock()
	registry[addr] = l
	regMu.Unlock()
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
		return r.pc, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *Listener) acceptLoop() {
	for {
		c, err := l.ln.Accept()
		var r acceptResult
		if err != nil {
			r.err = err
		} else {
			r.pc = basetcp.Wrap(c)
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

// Close tears down the listener and its virtual network.
func (l *Listener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		regMu.Lock()
		if registry[l.addr] == l {
			delete(registry, l.addr)
		}
		regMu.Unlock()
		close(l.closed)
		l.ln.Shutdown()
		err = l.ln.Close()
		l.client.Close()
		l.server.Close()
	})
	return err
}

// Addr returns the process-local registry address.
func (l *Listener) Addr() net.Addr { return addr(l.addr) }

func (l *Listener) dial(ctx context.Context) (transport.PathConn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	default:
	}
	c, err := gonet.DialContextTCP(ctx, l.client, tcpip.FullAddress{
		NIC:  nicID,
		Addr: serverIP,
		Port: listenPort,
	}, header.IPv4ProtocolNumber)
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			return nil, err
		}
		return nil, fmt.Errorf("gvisor: dial tcp: %w", err)
	}
	return basetcp.Wrap(c), nil
}

type addr string

func (a addr) Network() string { return "gvisor" }
func (a addr) String() string  { return string(a) }
