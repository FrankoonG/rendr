package tcp

import (
	"errors"
	"net"
	"net/netip"
	"testing"
)

// TestLoopbackChecks: the two checks behind Listen and Dial without
// AllowNonLoopback. A host name passes only if every address it resolves to
// is loopback (a mixed or empty answer is refused); the connect/bind hook
// refuses any address the net package is about to use that is not loopback,
// so a name that resolves differently for the dial than for the check (DNS
// rebinding) never reaches a non-loopback address.
func TestLoopbackChecks(t *testing.T) {
	lo4, lo6 := netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()
	far := netip.MustParseAddr(net.IPv4allsys.String()) // any non-loopback address
	sets := []struct {
		ips []netip.Addr
		ok  bool
	}{
		{[]netip.Addr{lo4}, true},
		{[]netip.Addr{lo6, lo4}, true},
		{[]netip.Addr{netip.AddrFrom16(lo4.As16())}, true}, // IPv4-mapped loopback
		{nil, false},
		{[]netip.Addr{lo4, far}, false},
		{[]netip.Addr{far, lo6}, false},
		{[]netip.Addr{netip.IPv6Unspecified()}, false},
	}
	for _, s := range sets {
		if err := checkAddrs("name:1", s.ips); (err == nil) != s.ok || (err != nil && !errors.Is(err, ErrNonLoopback)) {
			t.Errorf("checkAddrs(%v) = %v, want ok %v", s.ips, err, s.ok)
		}
	}
	farPort := netip.AddrPortFrom(far, 80).String()
	anyPort := netip.AddrPortFrom(netip.IPv4Unspecified(), 80).String()
	hook := map[string]bool{
		"127.0.0.1:0":           true,
		"[::1]:443":             true,
		"[::ffff:127.0.0.1]:80": true,
		farPort:                 false,
		anyPort:                 false,
		"[::]:80":               false,
		"not-an-address":        false,
	}
	for addr, ok := range hook {
		if err := checkAddr(addr); (err == nil) != ok || (err != nil && !errors.Is(err, ErrNonLoopback)) {
			t.Errorf("checkAddr(%q) = %v, want ok %v", addr, err, ok)
		}
	}
}
