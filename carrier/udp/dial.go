package udp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// The system calls of Listen and Dial that the tests replace (they check
// the clamp's and the close-on-failure paths without real interfaces or
// failing sockets): the interface table, the route lookup and the socket
// configuration. Nothing else changes them.
var (
	sysInterfaceTable = interfaceTable
	sysRouteSource    = routeSource
	sysConfigure      = configure
)

// dial implements the factory's Dial: resolve the peer (loopback only
// without AllowNonLoopback), clamp MaxDatagram to the interface MTU (R1-16),
// draw a fresh flow ID (L58: a redial never reuses one) and open an
// unconnected socket bound to the loopback address of the peer's family for
// a loopback peer, else the unspecified address: replies are accepted from
// exactly the peer's address and port (L59), and an unconnected socket sees
// no ICMP-derived errors on either OS. A failed clamp fails the dial before
// the socket is opened; every failure after it was opened closes it (L57).
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
	if maxDatagram, err = routeClamp(ctx, peer, maxDatagram, sysRouteSource, sysInterfaceTable); err != nil {
		return nil, nil, err
	}
	bind, bindNet := bindAddr(peer)
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, bindNet, netip.AddrPortFrom(bind, 0).String())
	if err != nil {
		return nil, nil, err
	}
	u := pc.(*net.UDPConn)
	if err := sysConfigure(u, bindNet == "udp6", rbuf, wbuf); err != nil {
		u.Close()
		return nil, nil, err
	}
	return carrier.NewOwnedUDP(u, peer, newFlowID(), maxDatagram), net.UDPAddrFromAddrPort(peer), nil
}

// bindAddr returns the address a dialer socket for peer binds and its
// network: the loopback address of the peer's family for a loopback peer,
// else the unspecified address (port 0 either way; peer is unmapped).
func bindAddr(peer netip.AddrPort) (netip.Addr, string) {
	a := peer.Addr()
	switch {
	case isIPv6(a) && a.IsLoopback():
		return netip.IPv6Loopback(), "udp6"
	case isIPv6(a):
		return netip.IPv6Unspecified(), "udp6"
	case a.IsLoopback():
		return netip.AddrFrom4([4]byte{127, 0, 0, 1}), "udp4"
	}
	return netip.IPv4Unspecified(), "udp4"
}

// resolvePeer returns the peer address network/address names, as
// net.ResolveUDPAddr picks it but honouring ctx: an IP literal as is
// (IPv4-mapped addresses unmapped, the zone as peerZone gives it), or the
// first address of the network's family a host name resolves to, IPv4
// first for "udp"; without allowNonLoopback every address the host resolves
// to must be loopback. An empty or unspecified host is an error (a carrier
// needs a peer to send to). The address is resolved once and used as is, so
// no second lookup can move the carrier off loopback.
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
	return netip.AddrPortFrom(peerZone(ip), uint16(pn)), nil
}

// peerZone returns ip with the zone the net package reports on the
// datagrams it receives from ip, so that the dialer token's exact source
// compare (L59) matches the peer's replies. An address that needs a scope
// (IPv6 link-local) keeps its zone as an interface name: a zone that names
// no interface but is a number is an interface index, which the net package
// reports by its name (a zone matching neither is kept as given). Every
// other address loses its zone: the kernel reports none on its datagrams.
func peerZone(ip netip.Addr) netip.Addr {
	zone := ip.Zone()
	switch {
	case zone == "":
		return ip
	case !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsInterfaceLocalMulticast():
		return ip.WithZone("")
	}
	if _, err := net.InterfaceByName(zone); err == nil {
		return ip
	}
	if i, err := strconv.ParseUint(zone, 10, 32); err == nil {
		if ifc, err := net.InterfaceByIndex(int(i)); err == nil {
			return ip.WithZone(ifc.Name)
		}
	}
	return ip
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

// interfaceTable returns the rows of the local interface table that can
// lower a MaxDatagram: the interfaces whose known MTU is less than below,
// each with its addresses (portable: the net package's interface list).
// Only those interfaces' addresses are listed — each list costs about as
// much as the interface list itself (≈ 3 ms on Windows), so a MaxDatagram
// that no interface MTU constrains costs one list — and ctx is checked
// before each.
func interfaceTable(ctx context.Context, below int) ([]ifaceMTU, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var table []ifaceMTU
	for _, ifc := range ifs {
		if ifc.MTU <= 0 || ifc.MTU >= below {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
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

// ipUDPHeaders is the IP and UDP header length of a datagram from src: 20 +
// 8 bytes for IPv4 (an IPv4-mapped address included), 40 + 8 for IPv6.
func ipUDPHeaders(src netip.Addr) int {
	if isIPv6(src) {
		return 40 + 8
	}
	return 20 + 8
}

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
	clamp := mtu - ipUDPHeaders(src)
	if clamp >= maxDatagram {
		return maxDatagram, nil
	}
	if clamp < minMaxDatagram {
		return 0, fmt.Errorf("%w: MTU %d leaves %d bytes per datagram, below %d", errClampFloor, mtu, clamp, minMaxDatagram)
	}
	return clamp, nil
}

// clampTo applies clampMaxDatagram for a socket sending from src, reading
// only the table rows that can lower maxDatagram: interfaces whose MTU is
// below maxDatagram plus the headers. An unknown interface table leaves
// maxDatagram to the MTU probe; a cancelled ctx is its error.
func clampTo(ctx context.Context, maxDatagram int, src netip.Addr,
	table func(context.Context, int) ([]ifaceMTU, error)) (int, error) {
	t, err := table(ctx, maxDatagram+ipUDPHeaders(src))
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return 0, cerr
		}
		return maxDatagram, nil
	}
	return clampMaxDatagram(maxDatagram, src, t)
}

// routeClamp clamps maxDatagram for a dialer socket toward peer: to the
// interface owning the source address the route to peer uses (source names
// it), or for a loopback peer to the interface owning the loopback address
// the socket binds, without a route lookup (Linux's loopback carries at most
// 65,488-byte IPv6 UDP payloads; the Windows loopback reports no MTU). A
// peer without a route fails the dial.
func routeClamp(ctx context.Context, peer netip.AddrPort, maxDatagram int,
	source func(context.Context, netip.AddrPort) (netip.Addr, error),
	table func(context.Context, int) ([]ifaceMTU, error)) (int, error) {
	src, _ := bindAddr(peer)
	if !peer.Addr().IsLoopback() {
		var err error
		if src, err = source(ctx, peer); err != nil {
			return 0, err
		}
	}
	return clampTo(ctx, maxDatagram, src, table)
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
