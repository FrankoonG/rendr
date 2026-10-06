package udp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// wp5Swap replaces *p with v until the test ends.
func wp5Swap[T any](t *testing.T, p *T, v T) {
	t.Helper()
	old := *p
	*p = v
	t.Cleanup(func() { *p = old })
}

// wp5Closed reports whether u was closed (a closed socket refuses even a
// deadline).
func wp5Closed(u *net.UDPConn) bool {
	return errors.Is(u.SetReadDeadline(time.Time{}), net.ErrClosed)
}

// TestUDPFailureClosesSocket_L57: Listen and Dial close the socket they
// opened on every later failure and return nothing (L57: a socket rendr
// opened is closed on every failure; ownership moves only on success) — a
// socket configuration that fails (don't-fragment refused) and, for Listen,
// an interface MTU below the floor for the address it bound (R1-16). Dial
// clamps before it opens its socket: an MTU below the floor on a loopback
// peer's loopback interface or on a routed peer's interface, and a peer
// without a route, fail it with no socket opened. With an interface table
// that constrains nothing the same calls succeed and hand the socket over
// open.
func TestUDPFailureClosesSocket_L57(t *testing.T) {
	defer wp5NoLeak(t)()
	ctx := wp5Ctx(t)
	var opened []*net.UDPConn
	failConfigure := false
	errConfigure := errors.New("wp5: socket configuration failed")
	wp5Swap(t, &sysConfigure, func(u *net.UDPConn, v6 bool, rbuf, wbuf int) error {
		opened = append(opened, u)
		if failConfigure {
			return errConfigure
		}
		return configure(u, v6, rbuf, wbuf)
	})
	check := func(what string, pc net.PacketConn, err, want error, nOpened int) {
		t.Helper()
		if pc != nil {
			pc.Close()
			t.Errorf("%s: returned a socket", what)
		}
		if !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", what, err, want)
		}
		if len(opened) != nOpened {
			t.Errorf("%s: %d sockets opened, want %d", what, len(opened), nOpened)
		}
		for _, u := range opened {
			if !wp5Closed(u) {
				u.Close()
				t.Errorf("%s: the socket it opened was left open", what)
			}
		}
		opened = nil
	}
	lo4 := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	far := netip.MustParseAddr(net.IPv4allsys.String()) // a non-loopback peer; the fake route sends to it from src
	src := far.Next()
	floor := func(owner netip.Addr) func(context.Context, int) ([]ifaceMTU, error) {
		return func(context.Context, int) ([]ifaceMTU, error) {
			return []ifaceMTU{{mtu: minMaxDatagram + 28 - 1, addrs: []netip.Addr{owner}}}, nil
		}
	}
	loopPeer := netip.AddrPortFrom(lo4, 9).String()
	farPeer := netip.AddrPortFrom(far, 9).String()

	failConfigure = true
	pc, err := Listen("udp4", "127.0.0.1:0", Options{})
	check("Listen, configuration", pc, err, errConfigure, 1)
	pc, peer, err := Carrier("x", "udp4", loopPeer, Options{}).Dial(ctx)
	check("Dial, configuration", pc, err, errConfigure, 1)
	if peer != nil {
		t.Errorf("Dial, configuration: returned the peer %v", peer)
	}
	failConfigure = false

	wp5Swap(t, &sysInterfaceTable, floor(lo4))
	pc, err = Listen("udp4", "127.0.0.1:0", Options{})
	check("Listen, an interface MTU below the floor", pc, err, errClampFloor, 1)
	pc, _, err = Carrier("x", "udp4", loopPeer, Options{}).Dial(ctx)
	check("Dial to a loopback peer, an interface MTU below the floor", pc, err, errClampFloor, 0)

	wp5Swap(t, &sysInterfaceTable, floor(src))
	wp5Swap(t, &sysRouteSource, func(_ context.Context, p netip.AddrPort) (netip.Addr, error) {
		if p.Addr() != far {
			t.Errorf("route looked up for %v, want %v", p, far)
		}
		return src, nil
	})
	pc, _, err = Carrier("x", "udp4", farPeer, Options{AllowNonLoopback: true}).Dial(ctx)
	check("Dial to a routed peer, an interface MTU below the floor", pc, err, errClampFloor, 0)
	noRoute := errors.New("wp5: no route")
	wp5Swap(t, &sysRouteSource, func(context.Context, netip.AddrPort) (netip.Addr, error) { return netip.Addr{}, noRoute })
	pc, _, err = Carrier("x", "udp4", farPeer, Options{AllowNonLoopback: true}).Dial(ctx)
	check("Dial without a route", pc, err, noRoute, 0)

	// The control: nothing constrains the value, so the calls succeed and
	// the socket they opened is the token's, open until it is closed.
	wp5Swap(t, &sysInterfaceTable, func(context.Context, int) ([]ifaceMTU, error) { return nil, nil })
	pc, err = Listen("udp4", "127.0.0.1:0", Options{})
	if err != nil || len(opened) != 1 || wp5Closed(opened[0]) {
		t.Fatalf("Listen with an unconstrained table: %v, %d sockets opened", err, len(opened))
	}
	s := pc.(*carrier.OwnedUDPSocket)
	if s.MaxDatagram() != DefaultMaxDatagram || wp5AP(s) != opened[0].LocalAddr().(*net.UDPAddr).AddrPort() {
		t.Errorf("Listen handed over %v with MaxDatagram %d", wp5AP(s), s.MaxDatagram())
	}
	s.Close()
	if !wp5Closed(opened[0]) {
		t.Error("closing the token left its socket open")
	}
	opened = nil
	o, _ := wp5Dial(t, "udp4", loopPeer, Options{})
	if len(opened) != 1 || wp5Closed(opened[0]) || wp5AP(o) != opened[0].LocalAddr().(*net.UDPAddr).AddrPort() {
		t.Errorf("Dial with an unconstrained table: %d sockets opened", len(opened))
	}
	o.Close()
}
