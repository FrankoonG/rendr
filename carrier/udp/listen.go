package udp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

const (
	// flowHeaderLen is the raw-UDP flow header every datagram of a carrier
	// starts with (the tokens write and check it).
	flowHeaderLen = wire.FlowHeaderLen
	// minMaxDatagram is the smallest MaxDatagram: the flow header and the
	// smallest frame budget (M2-D51).
	minMaxDatagram = wire.MinFrameBudget + flowHeaderLen
	// defaultReadBuffer and defaultWriteBuffer size the socket buffers when
	// Options leave them 0 (M2-D66: a burst of datagrams waits in the
	// kernel, not on the wire).
	defaultReadBuffer  = 4 << 20
	defaultWriteBuffer = 1 << 20
)

// maxDatagram returns the effective MaxDatagram: DefaultMaxDatagram for 0,
// else the value when it lies in minMaxDatagram–wire.MaxDatagram.
func (o Options) maxDatagram() (int, error) {
	switch m := o.MaxDatagram; {
	case m == 0:
		return DefaultMaxDatagram, nil
	case m < minMaxDatagram || m > wire.MaxDatagram:
		return 0, fmt.Errorf("rendr/carrier/udp: MaxDatagram %d outside %d–%d", m, minMaxDatagram, wire.MaxDatagram)
	default:
		return m, nil
	}
}

// buffers returns the effective socket buffer sizes (0 selects the
// defaults; a negative size is an error).
func (o Options) buffers() (read, write int, err error) {
	if o.ReadBuffer < 0 || o.WriteBuffer < 0 {
		return 0, 0, fmt.Errorf("rendr/carrier/udp: negative socket buffer size (read %d, write %d)", o.ReadBuffer, o.WriteBuffer)
	}
	read, write = o.ReadBuffer, o.WriteBuffer
	if read == 0 {
		read = defaultReadBuffer
	}
	if write == 0 {
		write = defaultWriteBuffer
	}
	return read, write, nil
}

// listen implements Listen. The net package resolves and binds exactly as
// net.ListenPacket does (a host name binds its IPv4 address when it has
// one); without AllowNonLoopback every address the host resolves to must be
// loopback before the socket is opened, and the address about to be bound
// is checked again (a name that resolves differently the second time is
// refused, not bound). The bound socket gets don't-fragment and its
// buffers, and a specific address clamps MaxDatagram to its interface's MTU
// (R1-16; a loopback address included). Every failure after the socket was
// opened closes it (L57).
func listen(ctx context.Context, network, address string, o Options) (net.PacketConn, error) {
	if err := checkNetwork(network); err != nil {
		return nil, err
	}
	maxDatagram, err := o.maxDatagram()
	if err != nil {
		return nil, err
	}
	rbuf, wbuf, err := o.buffers()
	if err != nil {
		return nil, err
	}
	var lc net.ListenConfig
	if !o.AllowNonLoopback {
		if err := loopbackOnly(ctx, network, address); err != nil {
			return nil, err
		}
		lc.Control = func(_, addr string, _ syscall.RawConn) error { return checkAddr(addr) }
	}
	pc, err := lc.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	u := pc.(*net.UDPConn)
	local := u.LocalAddr().(*net.UDPAddr).AddrPort()
	if err := sysConfigure(u, isIPv6(local.Addr()), rbuf, wbuf); err != nil {
		u.Close()
		return nil, err
	}
	if !local.Addr().IsUnspecified() {
		if maxDatagram, err = clampTo(ctx, maxDatagram, local.Addr(), sysInterfaceTable); err != nil {
			u.Close()
			return nil, err
		}
	}
	return carrier.NewOwnedUDPSocket(u, maxDatagram), nil
}

// configure gives a fresh socket don't-fragment with probe semantics and
// its buffers (sockopt_*.go). A socket that cannot refuse fragmentation is
// an error: a datagram that does not fit the path must be lost, never
// fragmented (L37).
func configure(u *net.UDPConn, v6 bool, rbuf, wbuf int) error {
	if err := setDontFragment(u, v6); err != nil {
		return fmt.Errorf("rendr/carrier/udp: don't-fragment: %w", err)
	}
	setBuffers(u, rbuf, wbuf)
	return nil
}

// isIPv6 reports whether a socket bound to a is an IPv6 socket (an
// IPv4-mapped address belongs to an IPv4 socket, as the net package binds
// it).
func isIPv6(a netip.Addr) bool { return a.Is6() && !a.Is4In6() }

func checkNetwork(network string) error {
	switch network {
	case "udp", "udp4", "udp6":
		return nil
	}
	return net.UnknownNetworkError(network)
}

// ipNetwork is the resolver network of a UDP network.
func ipNetwork(network string) string {
	switch network {
	case "udp4":
		return "ip4"
	case "udp6":
		return "ip6"
	}
	return "ip"
}

// loopbackOnly requires the host of address to be loopback: an IP literal
// is checked as is, a host name is resolved and every address it yields
// must be loopback. An empty host (all interfaces) is not loopback.
func loopbackOnly(ctx context.Context, network, address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ips, err := lookupHost(ctx, network, host)
	if err != nil {
		return err
	}
	return checkAddrs(address, ips)
}

// lookupHost returns the addresses host names: an IP literal as is, a host
// name through the resolver, nothing for an empty host.
func lookupHost(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	if host == "" {
		return nil, nil
	}
	return net.DefaultResolver.LookupNetIP(ctx, ipNetwork(network), host)
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

// checkAddr is the bind hook: it accepts only a loopback ip:port, the
// address the net package resolved and is about to bind.
func checkAddr(addr string) error {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil || !ap.Addr().Unmap().IsLoopback() {
		return fmt.Errorf("%w: %q", ErrNonLoopback, addr)
	}
	return nil
}
