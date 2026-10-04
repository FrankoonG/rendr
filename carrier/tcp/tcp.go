// Package tcp is rendr's built-in plaintext TCP carrier (plan §8, ≤ 300
// lines): a listener and a factory whose connections have TCP keepalive
// disabled on both ends (rendr's PING is the only liveness authority, L26)
// and TCP_NODELAY on, and that refuse non-loopback addresses unless
// AllowNonLoopback is set (plan §1.4: plaintext, for tests and trusted
// networks). Its connections carry rendr's ownership token, so the carrier
// writer uses zero-copy vectored writes on them.
package tcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

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

// Listen listens on network ("tcp", "tcp4", "tcp6") and address. Accepted
// connections have keepalive disabled and NODELAY set and are rendr-owned.
// Pass the result to rendr.FromListener. A non-loopback address fails with
// ErrNonLoopback unless allowed; without AllowNonLoopback a host name is
// resolved first and every address it yields must be loopback.
func Listen(network, address string, o Options) (net.Listener, error) {
	if err := checkNetwork(network); err != nil {
		return nil, err
	}
	if !o.AllowNonLoopback {
		ap, err := loopback(context.Background(), network, address)
		if err != nil {
			return nil, err
		}
		address = ap.String()
	}
	lc := net.ListenConfig{KeepAlive: -1}
	ln, err := lc.Listen(context.Background(), network, address)
	if err != nil {
		return nil, err
	}
	return &listener{ln: ln.(*net.TCPListener)}, nil
}

// Carrier returns a StreamCarrier named name that dials network/address
// with net.Dialer{KeepAlive: -1}, then SetKeepAlive(false) and
// SetNoDelay(true), honouring ctx. A non-loopback address fails with
// ErrNonLoopback unless allowed.
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
	if !o.AllowNonLoopback {
		ap, err := loopback(ctx, network, address)
		if err != nil {
			return nil, err
		}
		address = ap.String()
	}
	d := net.Dialer{KeepAlive: -1}
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

// loopback resolves address and requires every address of its host to be
// loopback; it returns the first one. An empty host (all interfaces) is
// not loopback.
func loopback(ctx context.Context, network, address string) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return netip.AddrPort{}, err
	}
	p, err := net.DefaultResolver.LookupPort(ctx, network, port)
	if err != nil {
		return netip.AddrPort{}, err
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else if host != "" {
		ipNet := map[string]string{"tcp": "ip", "tcp4": "ip4", "tcp6": "ip6"}[network]
		if ips, err = net.DefaultResolver.LookupNetIP(ctx, ipNet, host); err != nil {
			return netip.AddrPort{}, err
		}
	}
	if len(ips) == 0 {
		return netip.AddrPort{}, fmt.Errorf("%w: %q", ErrNonLoopback, address)
	}
	for _, ip := range ips {
		if !ip.Unmap().IsLoopback() {
			return netip.AddrPort{}, fmt.Errorf("%w: %q", ErrNonLoopback, address)
		}
	}
	return netip.AddrPortFrom(ips[0].Unmap(), uint16(p)), nil
}
