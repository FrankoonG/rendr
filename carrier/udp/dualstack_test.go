package udp

import (
	"net/netip"
	"testing"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// TestUDPDualStackListener: a wildcard "udp" Listen (AllowNonLoopback) is a
// dual-stack IPv6 socket where the host has one. Its IPv4 datagrams refuse
// fragmentation too — Linux sets IP_MTU_DISCOVER beside IPV6_MTU_DISCOVER
// (best effort), and Windows' IPV6_DONTFRAG covers both — and an IPv4
// client's source is the unmapped IPv4 address: the AddrPort udpflow keys
// its flows by, equal to the client's own, so the reply reaches the client
// from the address it dialed.
func TestUDPDualStackListener(t *testing.T) {
	defer wp5NoLeak(t)()
	pc, err := Listen("udp", ":0", Options{AllowNonLoopback: true})
	if err != nil {
		t.Fatalf("Listen(udp, wildcard): %v", err)
	}
	s := pc.(*carrier.OwnedUDPSocket)
	defer s.Close()
	if !wp5AP(s).Addr().Is6() {
		t.Logf("the wildcard listen bound an IPv4 socket on this host: there is no dual-stack socket to check")
	} else if level, opt, want, ok := wp5DF(false); ok {
		if v := wp5Sockopt(t, s, level, opt); v != want {
			t.Errorf("dual-stack listener: the IPv4 don't-fragment option reads %d, want %d", v, want)
		}
	}
	peer := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), wp5AP(s).Port())
	o, _ := wp5Dial(t, "udp4", peer.String(), Options{})
	defer o.Close()
	wp5ExchangeVia(t, o, peer, s, 100)
}
