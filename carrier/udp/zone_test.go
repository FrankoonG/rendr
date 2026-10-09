package udp

import (
	"net"
	"net/netip"
	"strconv"
	"testing"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// TestUDPLinkLocalZone: a link-local IPv6 peer names its interface in the
// zone, by name or by index; either way Dial gives its peer the zone the net
// package reports on the datagrams it receives — the interface's name — so
// the listener's replies are the peer's, not foreign (L59). A zone naming no
// interface is kept as given; an address that needs no scope (loopback,
// global) loses its zone: the kernel reports none on its datagrams. The
// exchange runs on an IPv6 link-local address of an up interface
// (AllowNonLoopback); on a host without one the pure rule is checked alone.
func TestUDPLinkLocalZone(t *testing.T) {
	defer wp5NoLeak(t)()
	ifs, err := net.Interfaces()
	if err != nil || len(ifs) == 0 {
		t.Fatalf("net.Interfaces: %d, %v", len(ifs), err)
	}
	ifc, unused := ifs[0], 1
	for _, i := range ifs {
		unused = max(unused, i.Index+1)
	}
	ll := netip.AddrFrom16([16]byte{0: 0xfe, 1: 0x80, 15: 1})     // the link-local prefix, interface ID 1
	mc := netip.MustParseAddr(net.IPv6linklocalallnodes.String()) // link-local multicast: needs a scope too
	byIndex, unknown := strconv.Itoa(ifc.Index), strconv.Itoa(unused)
	for _, r := range []struct{ in, want netip.Addr }{
		{ll.WithZone(byIndex), ll.WithZone(ifc.Name)},
		{ll.WithZone(ifc.Name), ll.WithZone(ifc.Name)},
		{ll.WithZone(unknown), ll.WithZone(unknown)},
		{ll.WithZone("+" + byIndex), ll.WithZone("+" + byIndex)}, // not an index: the net package reads digits only
		{ll, ll},
		{mc.WithZone(byIndex), mc.WithZone(ifc.Name)},
		{netip.IPv6Loopback().WithZone(byIndex), netip.IPv6Loopback()}, // needs no scope
		{netip.IPv6Loopback().WithZone(ifc.Name), netip.IPv6Loopback()},
	} {
		if got := peerZone(r.in); got != r.want {
			t.Errorf("peerZone(%v) = %v, want %v", r.in, got, r.want)
		}
	}

	ip, lifc, ok := wp5LinkLocal(t)
	if !ok {
		t.Logf("no IPv6 link-local address of an up interface binds on this host: the exchange is not exercised")
		return
	}
	pc, err := Listen("udp6", netip.AddrPortFrom(ip.WithZone(lifc.Name), 0).String(), Options{AllowNonLoopback: true})
	if err != nil {
		t.Fatalf("Listen on a link-local address: %v", err)
	}
	s := pc.(*carrier.OwnedUDPSocket)
	defer s.Close()
	listener := wp5AP(s)
	if listener.Addr().Zone() != lifc.Name {
		t.Fatalf("the listener is at %v, want the zone %q", listener, lifc.Name)
	}
	for _, zone := range []string{lifc.Name, strconv.Itoa(lifc.Index)} {
		address := net.JoinHostPort(ip.WithZone(zone).String(), strconv.Itoa(int(listener.Port())))
		o, peer := wp5Dial(t, "udp6", address, Options{AllowNonLoopback: true})
		if got := peer.(*net.UDPAddr).AddrPort(); got != listener {
			t.Errorf("zone %q: Dial's peer is %v, want %v", zone, got, listener)
		}
		wp5ExchangeVia(t, o, listener, s, 100)
		o.Close()
	}
}

// wp5LinkLocal returns the first IPv6 link-local address of an up, running,
// non-loopback interface that a plain socket binds, and the interface.
func wp5LinkLocal(t *testing.T) (netip.Addr, net.Interface, bool) {
	t.Helper()
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces: %v", err)
	}
	for _, ifc := range ifs {
		if ifc.Flags&(net.FlagUp|net.FlagRunning) != net.FlagUp|net.FlagRunning || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, isNet := a.(*net.IPNet)
			if !isNet {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok || !ip.Is6() || ip.Is4In6() || !ip.IsLinkLocalUnicast() {
				continue
			}
			u, err := net.ListenUDP("udp6", net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip.WithZone(ifc.Name), 0)))
			if err != nil {
				t.Logf("interface index %d: a plain socket does not bind its link-local address: %v", ifc.Index, err)
				continue
			}
			u.Close()
			t.Logf("interface index %d", ifc.Index)
			return ip, ifc, true
		}
	}
	return netip.Addr{}, net.Interface{}, false
}
