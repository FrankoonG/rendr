package xray

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"

	xnet "github.com/xtls/xray-core/common/net"
	xinternet "github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// DefaultTransportName is the xray streamSettings.network value used
// by the default registration helpers.
const DefaultTransportName = "rendr"

var registeredProtocolConfigs sync.Map

// TransportSettings is the placeholder settings object xray-core
// stores in MemoryStreamConfig.ProtocolSettings for rendr transports.
// The actual rendr path configuration is supplied at registration
// time via Config / ListenConfig.
type TransportSettings struct{}

// RegisterRendrAsXrayTransport registers the default "rendr" xray
// transport dialer. After this succeeds, xray-core stream settings
// with ProtocolName/network "rendr" dial through a rendr Conn.
func RegisterRendrAsXrayTransport(cfg *Config) error {
	return RegisterRendrTransportDialer(DefaultTransportName, cfg)
}

// RegisterRendrAsXrayInbound registers the default "rendr" xray
// transport listener. If cfg is nil or has no paths, xray's requested
// listen address/port becomes a single TCP rendr listener. If cfg has
// paths, those paths are used as-is so embedders can expose a
// multi-transport rendr listener.
func RegisterRendrAsXrayInbound(cfg *ListenConfig) error {
	return RegisterRendrTransportListener(DefaultTransportName, cfg)
}

// RegisterRendrTransportDialer registers a named xray transport dialer.
// Tests and embedders that need more than one rendr registration in the
// same process can pass a custom name and set streamSettings.ProtocolName
// to the same value.
func RegisterRendrTransportDialer(name string, cfg *Config) error {
	if name == "" {
		name = DefaultTransportName
	}
	if err := ensureProtocolConfig(name); err != nil {
		return err
	}
	d, err := NewDialer(cfg)
	if err != nil {
		return err
	}
	return xinternet.RegisterTransportDialer(name, func(ctx context.Context, dest xnet.Destination, settings *xinternet.MemoryStreamConfig) (stat.Connection, error) {
		_ = dest
		conn, err := d.DialContext(ctx, nil)
		if err != nil {
			return nil, err
		}
		return conn, nil
	})
}

// RegisterRendrTransportListener registers a named xray transport
// listener. A nil cfg means "bind a TCP rendr listener to the address
// xray passes into internet.ListenTCP".
func RegisterRendrTransportListener(name string, cfg *ListenConfig) error {
	if name == "" {
		name = DefaultTransportName
	}
	if err := ensureProtocolConfig(name); err != nil {
		return err
	}
	return xinternet.RegisterTransportListener(name, func(ctx context.Context, address xnet.Address, port xnet.Port, settings *xinternet.MemoryStreamConfig, handler xinternet.ConnHandler) (xinternet.Listener, error) {
		ln, err := listenFromXray(ctx, address, port, cfg)
		if err != nil {
			return nil, err
		}
		w := &registeredListener{
			ctx:    ctx,
			inner:  ln,
			handle: handler,
			done:   make(chan struct{}),
		}
		go w.acceptLoop()
		return w, nil
	})
}

func ensureProtocolConfig(name string) error {
	if _, ok := registeredProtocolConfigs.Load(name); ok {
		return nil
	}
	if err := xinternet.RegisterProtocolConfigCreator(name, func() interface{} {
		return &TransportSettings{}
	}); err != nil {
		if _, loaded := registeredProtocolConfigs.LoadOrStore(name, struct{}{}); loaded {
			return nil
		}
		return err
	}
	registeredProtocolConfigs.Store(name, struct{}{})
	return nil
}

type registeredListener struct {
	ctx    context.Context
	inner  *Listener
	handle xinternet.ConnHandler
	done   chan struct{}
}

func (l *registeredListener) acceptLoop() {
	defer close(l.done)
	for {
		conn, err := l.inner.AcceptContext(l.ctx)
		if err != nil {
			return
		}
		l.handle(&xrayAddrConn{
			Conn:   conn,
			local:  tcpAddrOrLoopback(conn.LocalAddr()),
			remote: tcpAddrOrLoopback(conn.RemoteAddr()),
		})
	}
}

func (l *registeredListener) Close() error {
	err := l.inner.Close()
	select {
	case <-l.done:
	case <-l.ctx.Done():
	}
	return err
}

func (l *registeredListener) Addr() net.Addr {
	return l.inner.Addr()
}

func listenFromXray(ctx context.Context, address xnet.Address, port xnet.Port, cfg *ListenConfig) (*Listener, error) {
	_ = ctx
	if cfg != nil && len(cfg.Paths) > 0 {
		return Listen(cfg)
	}
	if address == nil {
		return nil, fmt.Errorf("rendr/xray: nil xray listen address")
	}
	return ListenTCP(joinXrayHostPort(address, port))
}

func joinXrayHostPort(address xnet.Address, port xnet.Port) string {
	host := address.String()
	if address.Family().IsIPv6() && len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

type xrayAddrConn struct {
	net.Conn
	local  net.Addr
	remote net.Addr
}

func (c *xrayAddrConn) LocalAddr() net.Addr {
	return c.local
}

func (c *xrayAddrConn) RemoteAddr() net.Addr {
	return c.remote
}

func tcpAddrOrLoopback(addr net.Addr) net.Addr {
	if addr == nil {
		return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
	}
	if _, ok := addr.(*net.TCPAddr); ok {
		return addr
	}
	if tcpAddr, err := net.ResolveTCPAddr("tcp", addr.String()); err == nil {
		return tcpAddr
	}
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
}
