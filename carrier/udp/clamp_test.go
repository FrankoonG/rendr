package udp

import (
	"context"
	"errors"
	"math"
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
// non-loopback peer; for a loopback peer it clamps to the loopback
// interface that owns the address its socket binds, with no route lookup
// (Linux's loopback MTU of 65,536 carries every IPv4 UDP payload but at most
// 65,488-byte IPv6 ones). It fails without a route, leaves the value to the
// MTU probe when the interface table is unknown, and fails when its context
// is done. Only the interfaces that can lower the value are read: those
// whose MTU is below MaxDatagram plus the headers. The "real" subtest
// checks that bound and the context on this host's interface table, and
// Listen and Dial on an address of an up interface.
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
	// tableOf serves rows and records the bound each read asked for (the
	// fake ignores it: clampMaxDatagram's answer does not depend on it).
	var asked []int
	tableOf := func(rows ...ifaceMTU) func(context.Context, int) ([]ifaceMTU, error) {
		return func(_ context.Context, below int) ([]ifaceMTU, error) {
			asked = append(asked, below)
			return rows, nil
		}
	}
	lo4, lo6 := netip.AddrFrom4([4]byte{127, 0, 0, 1}), netip.IPv6Loopback()
	for _, r := range []struct {
		name        string
		peer        netip.Addr
		mtu         int
		want, below int
	}{
		{"IPv4 loopback, MTU 65536", lo4, 65536, wire.MaxDatagram, wire.MaxDatagram + 28},
		{"IPv6 loopback, MTU 65536", lo6, 65536, 65536 - 48, wire.MaxDatagram + 48},
		{"IPv4 loopback, MTU 1500", lo4, 1500, 1500 - 28, wire.MaxDatagram + 28},
		{"IPv6 loopback, unknown MTU", lo6, -1, wire.MaxDatagram, wire.MaxDatagram + 48},
		{"another IPv4 loopback address", lo4.Next(), 1500, 1500 - 28, wire.MaxDatagram + 28},
	} {
		asked = nil
		peer := netip.AddrPortFrom(r.peer, 9)
		got, err := routeClamp(ctx, peer, wire.MaxDatagram, never, tableOf(ifaceMTU{mtu: r.mtu, addrs: []netip.Addr{lo4, lo6}}))
		if err != nil || got != r.want || len(asked) != 1 || asked[0] != r.below {
			t.Errorf("%s: %d, %v, table read with bounds %v; want %d, one read below %d", r.name, got, err, asked, r.want, r.below)
		}
	}
	if _, err := routeClamp(ctx, netip.AddrPortFrom(lo6, 9), wire.MaxDatagram, never,
		tableOf(ifaceMTU{mtu: 573, addrs: []netip.Addr{lo4, lo6}})); !errors.Is(err, errClampFloor) {
		t.Errorf("a loopback interface below the floor: %v, want errClampFloor", err)
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
	asked = nil
	if got, err := routeClamp(ctx, peer, wire.MaxDatagram, via(c4, nil), tableOf(table...)); err != nil || got != 576-28 ||
		len(asked) != 1 || asked[0] != wire.MaxDatagram+28 {
		t.Errorf("routed via the 576-byte interface: %d, %v, bounds %v", got, err, asked)
	}
	asked = nil
	if got, err := routeClamp(ctx, netip.AddrPortFrom(b6, 9), DefaultMaxDatagram, func(context.Context, netip.AddrPort) (netip.Addr, error) {
		return a6, nil
	}, tableOf(table...)); err != nil || got != DefaultMaxDatagram || len(asked) != 1 || asked[0] != DefaultMaxDatagram+48 {
		t.Errorf("routed from an IPv6 address: %d, %v, bounds %v; want %d below %d", got, err, asked, DefaultMaxDatagram, DefaultMaxDatagram+48)
	}
	if _, err := routeClamp(ctx, peer, wire.MaxDatagram, via(d4, nil), tableOf(table...)); !errors.Is(err, errClampFloor) {
		t.Errorf("routed via the 573-byte interface: %v, want errClampFloor", err)
	}
	if _, err := routeClamp(ctx, peer, wire.MaxDatagram, via(netip.Addr{}, noRoute), tableOf(table...)); !errors.Is(err, noRoute) {
		t.Errorf("no route: %v, want the lookup's error", err)
	}
	unknown := func(context.Context, int) ([]ifaceMTU, error) { return nil, errors.New("wp5: no interface table") }
	if got, err := routeClamp(ctx, peer, wire.MaxDatagram, via(c4, nil), unknown); err != nil || got != wire.MaxDatagram {
		t.Errorf("unknown interface table: %d, %v; want no clamp", got, err)
	}
	done, cancel := context.WithCancel(ctx)
	cancel()
	ctxTable := func(c context.Context, _ int) ([]ifaceMTU, error) { return nil, c.Err() }
	for _, p := range []netip.AddrPort{peer, netip.AddrPortFrom(lo4, 9)} {
		route := via(c4, nil)
		if p.Addr().IsLoopback() {
			route = never
		}
		if _, err := routeClamp(done, p, wire.MaxDatagram, route, ctxTable); !errors.Is(err, context.Canceled) {
			t.Errorf("a cancelled dial to %v: %v, want context.Canceled", p, err)
		}
	}

	t.Run("real", func(t *testing.T) {
		defer wp5NoLeak(t)()
		ctx := wp5Ctx(t)
		all, err := interfaceTable(ctx, math.MaxInt)
		if err != nil {
			t.Fatalf("interfaceTable: %v", err)
		}
		for _, row := range all {
			if row.mtu <= 0 {
				t.Errorf("interface table row with MTU %d: an unknown MTU is never listed", row.mtu)
			}
			for _, a := range row.addrs {
				if !a.IsValid() || a.Is4In6() || a.Zone() != "" {
					t.Errorf("interface table address %v is not an unmapped address without zone", a)
				}
			}
		}
		if _, err := interfaceTable(done, math.MaxInt); !errors.Is(err, context.Canceled) {
			t.Errorf("interfaceTable with a cancelled context: %v, want context.Canceled", err)
		}
		ip, mtu, ok := wp5UpInterface(t)
		if !ok {
			t.Logf("no up non-loopback interface with an IPv4 address: the real clamp is not exercised here")
			return
		}
		if !wp5Owns(all, ip, mtu) {
			t.Errorf("the full interface table has no MTU %d row owning the interface's address", mtu)
		}
		below, err := interfaceTable(ctx, mtu)
		if err != nil {
			t.Fatalf("interfaceTable below %d: %v", mtu, err)
		}
		for _, row := range below {
			if row.mtu >= mtu {
				t.Errorf("interfaceTable below %d listed a row with MTU %d", mtu, row.mtu)
			}
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
		src, err := routeSource(ctx, netip.AddrPortFrom(ip, 9))
		if err != nil {
			t.Fatalf("routeSource: %v", err)
		}
		if src != ip {
			if want, err = clampMaxDatagram(wire.MaxDatagram, src, all); err != nil {
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

// wp5Owns reports whether a row of table with the given MTU owns ip.
func wp5Owns(table []ifaceMTU, ip netip.Addr, mtu int) bool {
	for _, row := range table {
		for _, a := range row.addrs {
			if a == ip && row.mtu == mtu {
				return true
			}
		}
	}
	return false
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
