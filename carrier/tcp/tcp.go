// Package tcp is rendr's built-in plaintext TCP carrier: a listener and a
// factory whose connections have TCP keepalive disabled on both ends
// (rendr's PING is the only liveness authority, so no keepalive timer can
// end a carrier that rendr still considers alive) and TCP_NODELAY on, and
// that refuse non-loopback addresses unless AllowNonLoopback is set (the
// carrier is neither encrypted nor authenticated: it is meant for tests and
// trusted networks). rendr recognises the connections this package creates
// and writes to them with zero-copy vectored writes (writev on Unix,
// WSASend on Windows); every other connection, one that wraps a connection
// of this package included, gets one copied Write per batch.
package tcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// ErrNonLoopback is returned by Listen and by the factory's Dial for a
// non-loopback address without Options.AllowNonLoopback.
var ErrNonLoopback = errors.New("rendr/carrier/tcp: non-loopback address requires AllowNonLoopback")

// Options configure the built-in TCP carrier.
type Options struct {
	// AllowNonLoopback permits non-loopback addresses. rendr provides no
	// confidentiality or authentication; only enable this on a trusted
	// network or inside the embedder's authenticated encrypted channel.
	AllowNonLoopback bool
}

// Listen listens on network ("tcp", "tcp4", "tcp6") and address exactly
// like net.Listen (a host name binds its IPv4 address when it has one).
// Accepted connections have keepalive disabled and NODELAY set and are
// rendr-owned. Pass the result to rendr.FromListener.
//
// Without AllowNonLoopback the address must be loopback, else Listen fails
// with ErrNonLoopback: an empty host (all interfaces) and non-loopback IPs
// are refused before any socket is opened, a host name is accepted only if
// every address it resolves to is loopback, and the address actually bound
// is checked once more (a name that resolves differently the second time is
// refused, not bound).
func Listen(network, address string, o Options) (net.Listener, error) {
	if err := checkNetwork(network); err != nil {
		return nil, err
	}
	lc := net.ListenConfig{KeepAlive: -1}
	if !o.AllowNonLoopback {
		if err := loopbackOnly(context.Background(), network, address); err != nil {
			return nil, err
		}
		lc.Control = func(_, addr string, _ syscall.RawConn) error { return checkAddr(addr) }
	}
	ln, err := lc.Listen(context.Background(), network, address)
	if err != nil {
		return nil, err
	}
	return &listener{ln: ln.(*net.TCPListener)}, nil
}

// Carrier returns a StreamCarrier named name that dials network/address
// like net.Dialer{KeepAlive: -1} (a host name's addresses are tried in
// turn, with the net package's IPv4/IPv6 fallback), then SetKeepAlive(false)
// and SetNoDelay(true), honouring ctx. Without AllowNonLoopback the address
// must be loopback as for Listen, and every address actually connected to
// is checked again (ErrNonLoopback).
func Carrier(name, network, address string, o Options) rendr.StreamCarrier {
	return rendr.StreamCarrier{
		Name: name,
		Dial: func(ctx context.Context) (net.Conn, error) { return dial(ctx, network, address, o) },
	}
}

func dial(ctx context.Context, network, address string, o Options) (net.Conn, error) {
	if err := checkNetwork(network); err != nil {
		return nil, err
	}
	d := net.Dialer{KeepAlive: -1}
	if !o.AllowNonLoopback {
		if err := loopbackOnly(ctx, network, address); err != nil {
			return nil, err
		}
		d.ControlContext = func(_ context.Context, _, addr string, _ syscall.RawConn) error { return checkAddr(addr) }
	}
	c, err := d.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	tc := c.(*net.TCPConn)
	if err := configure(tc); err != nil {
		tc.Close()
		return nil, err
	}
	return carrier.NewOwnedTCP(tc), nil
}

// listener hands out configured, rendr-owned connections.
type listener struct {
	ln *net.TCPListener
}

// Accept returns the next connection. A connection that cannot be
// configured is closed and skipped, so one bad peer never stops the
// accept loop.
func (l *listener) Accept() (net.Conn, error) {
	for {
		c, err := l.ln.AcceptTCP()
		if err != nil {
			return nil, err
		}
		if err := configure(c); err != nil {
			c.Close()
			continue
		}
		return carrier.NewOwnedTCP(c), nil
	}
}

// Close closes the listening socket.
func (l *listener) Close() error { return l.ln.Close() }

// Addr returns the listening address.
func (l *listener) Addr() net.Addr { return l.ln.Addr() }

// configure disables TCP keepalive (L26) and enables TCP_NODELAY.
func configure(c *net.TCPConn) error {
	if err := c.SetKeepAlive(false); err != nil {
		return err
	}
	return c.SetNoDelay(true)
}

func checkNetwork(network string) error {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return nil
	}
	return net.UnknownNetworkError(network)
}

// loopbackOnly requires the host of address to be loopback: an IP literal
// is checked as is, a host name is resolved and every address it yields
// must be loopback. An empty host (all interfaces) is not loopback.
func loopbackOnly(ctx context.Context, network, address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else if host != "" {
		ipNet := map[string]string{"tcp": "ip", "tcp4": "ip4", "tcp6": "ip6"}[network]
		if ips, err = net.DefaultResolver.LookupNetIP(ctx, ipNet, host); err != nil {
			return err
		}
	}
	return checkAddrs(address, ips)
}

// checkAddrs accepts a non-empty set of loopback addresses only.
func checkAddrs(address string, ips []netip.Addr) error {
	if len(ips) == 0 {
		return fmt.Errorf("%w: %q", ErrNonLoopback, address)
	}
	for _, ip := range ips {
		if !ip.Unmap().IsLoopback() {
			return fmt.Errorf("%w: %q", ErrNonLoopback, address)
		}
	}
	return nil
}

// checkAddr is the connect/bind hook: it accepts only a loopback ip:port,
// the address the net package resolved and is about to use.
func checkAddr(addr string) error {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil || !ap.Addr().Unmap().IsLoopback() {
		return fmt.Errorf("%w: %q", ErrNonLoopback, addr)
	}
	return nil
}
