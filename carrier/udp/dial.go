package udp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// dial implements the factory's Dial: resolve the peer (loopback only
// without AllowNonLoopback), clamp MaxDatagram to the route's interface MTU
// (R1-16), draw a fresh flow ID (L58: a redial never reuses one) and open
// an unconnected socket bound to the loopback address of the peer's family
// for a loopback peer, else the unspecified address: replies are accepted
// from exactly the peer's address and port (L59), and an unconnected socket
// sees no ICMP-derived errors on either OS. Every failure after the socket
// was opened closes it (L57).
func dial(ctx context.Context, network, address string, o Options) (net.PacketConn, net.Addr, error) {
	if err := checkNetwork(network); err != nil {
		return nil, nil, err
	}
	maxDatagram, err := o.maxDatagram()
	if err != nil {
		return nil, nil, err
	}
	rbuf, wbuf, err := o.buffers()
	if err != nil {
		return nil, nil, err
	}
	peer, err := resolvePeer(ctx, network, address, o.AllowNonLoopback)
	if err != nil {
		return nil, nil, err
	}
	if maxDatagram, err = routeClamp(ctx, peer, maxDatagram, routeSource, interfaceTable); err != nil {
		return nil, nil, err
	}
	bind, bindNet := netip.IPv4Unspecified(), "udp4"
	if isIPv6(peer.Addr()) {
		bind, bindNet = netip.IPv6Unspecified(), "udp6"
	}
	if peer.Addr().IsLoopback() {
		bind = netip.AddrFrom4([4]byte{127, 0, 0, 1})
		if bindNet == "udp6" {
			bind = netip.IPv6Loopback()
		}
	}
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, bindNet, netip.AddrPortFrom(bind, 0).String())
	if err != nil {
		return nil, nil, err
	}
	u := pc.(*net.UDPConn)
	if err := configure(u, bindNet == "udp6", rbuf, wbuf); err != nil {
		u.Close()
		return nil, nil, err
	}
	return carrier.NewOwnedUDP(u, peer, newFlowID(), maxDatagram), net.UDPAddrFromAddrPort(peer), nil
}

// resolvePeer returns the peer address network/address names, as
// net.ResolveUDPAddr picks it but honouring ctx: an IP literal as is
// (IPv4-mapped addresses unmapped), or the first address of the network's
// family a host name resolves to, IPv4 first for "udp"; without
// allowNonLoopback every address the host resolves to must be loopback. An
// empty or unspecified host is an error (a carrier needs a peer to send
// to). The address is resolved once and used as is, so no second lookup can
// move the carrier off loopback.
func resolvePeer(ctx context.Context, network, address string, allowNonLoopback bool) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return netip.AddrPort{}, err
	}
	ips, err := lookupHost(ctx, network, host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if !allowNonLoopback {
		if err := checkAddrs(address, ips); err != nil {
			return netip.AddrPort{}, err
		}
	}
	pn, err := net.DefaultResolver.LookupPort(ctx, network, port)
	if err != nil {
		return netip.AddrPort{}, err
	}
	ip, ok := pickAddr(network, ips)
	if !ok {
		return netip.AddrPort{}, &net.AddrError{Err: "no suitable address", Addr: address}
	}
	if ip.IsUnspecified() {
		return netip.AddrPort{}, &net.AddrError{Err: "unspecified peer address", Addr: address}
	}
	return netip.AddrPortFrom(ip, uint16(pn)), nil
}

// pickAddr returns the first address of network's family (unmapped): IPv4
// for "udp4", IPv6 for "udp6", for "udp" the first IPv4 address, else the
// first address.
func pickAddr(network string, ips []netip.Addr) (netip.Addr, bool) {
	for _, want4 := range [2]bool{true, false} {
		if (network == "udp6" && want4) || (network == "udp4" && !want4) {
			continue
		}
		for _, ip := range ips {
			if ip = ip.Unmap(); ip.Is4() == want4 {
				return ip, true
			}
		}
	}
	return netip.Addr{}, false
}

// newFlowID draws a carrier's flow ID from crypto/rand, redrawn while 0
// (M2 design §A3.4).
func newFlowID() uint64 {
	var b [8]byte
	for {
		rand.Read(b[:]) // never fails (crypto/rand crashes the process instead)
		if f := binary.BigEndian.Uint64(b[:]); f != 0 {
			return f
		}
	}
}

// ifaceMTU is one row of the local interface table: an interface's MTU and
// its unicast addresses (unmapped, without zone).
type ifaceMTU struct {
	mtu   int
	addrs []netip.Addr
}

// interfaceTable returns the local interface table (portable: the net
// package's interface list).
func interfaceTable() ([]ifaceMTU, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	table := make([]ifaceMTU, 0, len(ifs))
	for _, ifc := range ifs {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		row := ifaceMTU{mtu: ifc.MTU}
		for _, a := range addrs {
			var ip net.IP
			switch a := a.(type) {
			case *net.IPNet:
				ip = a.IP
			case *net.IPAddr:
				ip = a.IP
			}
			if na, ok := netip.AddrFromSlice(ip); ok {
				row.addrs = append(row.addrs, na.Unmap())
			}
		}
		table = append(table, row)
	}
	return table, nil
}

// errClampFloor: the interface a socket sends from carries too little for a
// carrier (R1-16).
var errClampFloor = errors.New("rendr/carrier/udp: the interface MTU is too small for a datagram carrier")

// clampMaxDatagram lowers maxDatagram to what the interface owning src
// carries: its MTU minus the IP (20 or 40 bytes) and UDP (8) headers, so
// the socket never refuses its own datagrams as too large with
// don't-fragment set (M2 design Revision 1, R1-16). An address no interface
// owns, or an interface whose MTU is unknown (≤ 0: the Windows loopback
// reports −1), leaves maxDatagram unchanged; an address several interfaces
// own takes the smallest MTU. A clamp below the smallest MaxDatagram
// (546) is errClampFloor. It never raises maxDatagram.
func clampMaxDatagram(maxDatagram int, src netip.Addr, table []ifaceMTU) (int, error) {
	src = src.Unmap().WithZone("")
	mtu := 0
	for _, row := range table {
		if row.mtu <= 0 {
			continue
		}
		for _, a := range row.addrs {
			if a == src && (mtu == 0 || row.mtu < mtu) {
				mtu = row.mtu
			}
		}
	}
	if mtu == 0 {
		return maxDatagram, nil
	}
	headers := 20 + 8
	if src.Is6() {
		headers = 40 + 8
	}
	clamp := mtu - headers
	if clamp >= maxDatagram {
		return maxDatagram, nil
	}
	if clamp < minMaxDatagram {
		return 0, fmt.Errorf("%w: MTU %d leaves %d bytes per datagram, below %d", errClampFloor, mtu, clamp, minMaxDatagram)
	}
	return clamp, nil
}

// routeClamp applies clampMaxDatagram to the interface the route to peer
// uses: source names the local address a datagram to peer leaves from,
// table the interfaces. A loopback peer is not looked up (its interface
// carries every UDP datagram on Linux and reports no MTU on Windows); an
// unknown interface table leaves maxDatagram to the MTU probe; a peer
// without a route fails the dial.
func routeClamp(ctx context.Context, peer netip.AddrPort, maxDatagram int,
	source func(context.Context, netip.AddrPort) (netip.Addr, error),
	table func() ([]ifaceMTU, error)) (int, error) {
	if peer.Addr().Unmap().IsLoopback() {
		return maxDatagram, nil
	}
	src, err := source(ctx, peer)
	if err != nil {
		return 0, err
	}
	t, err := table()
	if err != nil {
		return maxDatagram, nil
	}
	return clampMaxDatagram(maxDatagram, src, t)
}

// routeSource returns the local address a datagram to peer leaves from: a
// connected lookup socket asks the kernel's routing (a UDP connect sends
// nothing) and is closed at once.
func routeSource(ctx context.Context, peer netip.AddrPort) (netip.Addr, error) {
	network := "udp4"
	if isIPv6(peer.Addr()) {
		network = "udp6"
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, network, peer.String())
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).AddrPort().Addr(), nil
}
