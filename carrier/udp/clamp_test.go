package udp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestUDPInterfaceMTUClamp (M2 design Revision 1, R1-16): MaxDatagram is
// lowered to what the interface a socket sends from carries — its MTU minus
// 28 bytes of IPv4 and UDP headers or 48 of IPv6 and UDP (an IPv4-mapped
// address is IPv4; a zone is ignored) — and never raised; an address no
// interface owns, or an interface without a known MTU (the Windows loopback
// reports −1), leaves it; an address two interfaces own takes the smaller
// MTU; a clamp below 546 bytes fails. Dial looks the route up for a
// non-loopback peer only (a loopback peer consults neither the route nor
// the interface table), fails without a route and leaves the value to the
// MTU probe when the interface table is unknown. The "real" subtest checks
// Listen and Dial on an address of an up interface of this host.
func TestUDPInterfaceMTUClamp(t *testing.T) {
	// Addresses of the fake table, derived from the net package's constants
	// (the values are irrelevant: only ownership counts).
	base4 := netip.MustParseAddr(net.IPv4allsys.String())
	base6 := netip.MustParseAddr(net.IPv6linklocalallnodes.String())
	a4, b4, c4, d4, e4, x4 := base4, base4.Next(), base4.Next().Next(), base4.Next().Next().Next(), base4.Prev(), base4.Prev().Prev()
	a6, b6 := base6, base6.Next()
	table := []ifaceMTU{
		{mtu: 1500, addrs: []netip.Addr{a4, a6}},
		{mtu: 9000, addrs: []netip.Addr{b4}},
		{mtu: 576, addrs: []netip.Addr{c4}},
		{mtu: 573, addrs: []netip.Addr{d4}},
		{mtu: -1, addrs: []netip.Addr{e4}},
		{mtu: 1400, addrs: []netip.Addr{a4}},
		{mtu: 1280, addrs: []netip.Addr{b6}},
	}
	for _, r := range []struct {
		name     string
		max      int
		src      netip.Addr
		want     int
		floorErr bool
	}{
		{"IPv4, smaller of two owners", wire.MaxDatagram, a4, 1400 - 28, false},
		{"never raised", DefaultMaxDatagram, a4, DefaultMaxDatagram, false},
		{"IPv6 headers", wire.MaxDatagram, a6, 1500 - 48, false},
		{"jumbo", wire.MaxDatagram, b4, 9000 - 28, false},
		{"IPv4 minimum MTU", wire.MaxDatagram, c4, 576 - 28, false},
		{"IPv6 minimum MTU", wire.MaxDatagram, b6, DefaultMaxDatagram, false},
		{"below the floor", wire.MaxDatagram, d4, 0, true},
		{"below the floor at the minimum", 546, d4, 0, true},
		{"unknown MTU", wire.MaxDatagram, e4, wire.MaxDatagram, false},
		{"unknown address", wire.MaxDatagram, x4, wire.MaxDatagram, false},
		{"IPv4-mapped", wire.MaxDatagram, netip.AddrFrom16(c4.As16()), 576 - 28, false},
		{"zone", wire.MaxDatagram, a6.WithZone("wp5"), 1500 - 48, false},
	} {
		got, err := clampMaxDatagram(r.max, r.src, table)
		if r.floorErr {
			if !errors.Is(err, errClampFloor) {
				t.Errorf("%s: %d, %v; want errClampFloor", r.name, got, err)
			}
			continue
		}
		if err != nil || got != r.want {
			t.Errorf("%s: %d, %v; want %d", r.name, got, err, r.want)
		}
	}

	ctx := context.Background()
	noRoute := errors.New("wp5: no route")
	never := func(context.Context, netip.AddrPort) (netip.Addr, error) {
		t.Error("the route of a loopback peer was looked up")
		return netip.Addr{}, noRoute
	}
	neverTable := func() ([]ifaceMTU, error) {
		t.Error("the interface table was read for a loopback peer")
		return nil, nil
	}
	for _, peer := range []netip.AddrPort{
		netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 9),
		netip.AddrPortFrom(netip.IPv6Loopback(), 9),
	} {
		if got, err := routeClamp(ctx, peer, wire.MaxDatagram, never, neverTable); err != nil || got != wire.MaxDatagram {
			t.Errorf("loopback peer %v: %d, %v; want no clamp", peer, got, err)
		}
	}
	peer := netip.AddrPortFrom(x4, 9)
	via := func(src netip.Addr, err error) func(context.Context, netip.AddrPort) (netip.Addr, error) {
		return func(_ context.Context, p netip.AddrPort) (netip.Addr, error) {
			if p != peer {
				t.Errorf("route looked up for %v, want %v", p, peer)
			}
			return src, err
		}
	}
	tbl := func() ([]ifaceMTU, error) { return table, nil }
	if got, err := routeClamp(ctx, peer, wire.MaxDatagram, via(c4, nil), tbl); err != nil || got != 576-28 {
		t.Errorf("routed via the 576-byte interface: %d, %v", got, err)
	}
	if _, err := routeClamp(ctx, peer, wire.MaxDatagram, via(d4, nil), tbl); !errors.Is(err, errClampFloor) {
		t.Errorf("routed via the 573-byte interface: %v, want errClampFloor", err)
	}
	if _, err := routeClamp(ctx, peer, wire.MaxDatagram, via(netip.Addr{}, noRoute), tbl); !errors.Is(err, noRoute) {
		t.Errorf("no route: %v, want the lookup's error", err)
	}
	unknown := func() ([]ifaceMTU, error) { return nil, errors.New("wp5: no interface table") }
	if got, err := routeClamp(ctx, peer, wire.MaxDatagram, via(c4, nil), unknown); err != nil || got != wire.MaxDatagram {
		t.Errorf("unknown interface table: %d, %v; want no clamp", got, err)
	}

	t.Run("real", func(t *testing.T) {
		defer wp5NoLeak(t)()
		tab, err := interfaceTable()
		if err != nil {
			t.Fatalf("interfaceTable: %v", err)
		}
		for _, row := range tab {
			for _, a := range row.addrs {
				if !a.IsValid() || a.Is4In6() || a.Zone() != "" {
					t.Errorf("interface table address %v is not an unmapped address without zone", a)
				}
			}
		}
		ip, mtu, ok := wp5UpInterface(t)
		if !ok {
			t.Logf("no up non-loopback interface with an IPv4 address: the real clamp is not exercised here")
			return
		}
		want := min(wire.MaxDatagram, mtu-28)
		o := Options{AllowNonLoopback: true, MaxDatagram: wire.MaxDatagram}
		s, err := Listen("udp4", netip.AddrPortFrom(ip, 0).String(), o)
		if err != nil {
			t.Fatalf("Listen on an interface address: %v", err)
		}
		defer s.Close()
		if got := s.(interface{ MaxDatagram() int }).MaxDatagram(); got != want {
			t.Errorf("Listen on an interface with MTU %d: MaxDatagram %d, want %d", mtu, got, want)
		}
		src, err := routeSource(wp5Ctx(t), netip.AddrPortFrom(ip, 9))
		if err != nil {
			t.Fatalf("routeSource: %v", err)
		}
		if src != ip {
			if want, err = clampMaxDatagram(wire.MaxDatagram, src, tab); err != nil {
				t.Fatal(err)
			}
			t.Logf("the route to this host's own address leaves from another address; expecting its clamp, %d", want)
		}
		d, _ := wp5Dial(t, "udp4", netip.AddrPortFrom(ip, wp5AP(s).Port()).String(), o)
		defer d.Close()
		if d.Limit() != want-wire.FlowHeaderLen {
			t.Errorf("Dial over an interface with MTU %d: Limit %d, want %d", mtu, d.Limit(), want-wire.FlowHeaderLen)
		}
	})
}

// wp5UpInterface returns the first IPv4 global unicast address of an up,
// non-loopback interface with a known MTU, and that MTU.
func wp5UpInterface(t *testing.T) (netip.Addr, int, bool) {
	t.Helper()
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces: %v", err)
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || ifc.MTU <= 0 {
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
			if ip = ip.Unmap(); ok && ip.Is4() && ip.IsGlobalUnicast() {
				t.Logf("interface index %d, MTU %d", ifc.Index, ifc.MTU)
				return ip, ifc.MTU, true
			}
		}
	}
	return netip.Addr{}, 0, false
}
