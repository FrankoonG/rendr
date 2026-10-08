package rendr

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestOpenFitTooSmall (W4 L3-1): a packet Dial maps ErrNoPath to
// ErrMetadataTooLarge only when every datagram factory returned a carrier
// whose budget — min(factory MTU, the rendr-owned socket's limit) — is too
// small for the OPEN. The wrapped factory records the budget of a
// rendr-owned UDP carrier it returns (stimulus: one real loopback socket
// of MaxDatagram 1472 behind a factory of MTU 3991); an embedder conn, a
// failed dial and a factory never dialled record nothing, and nothing then
// maps. Stream factories are left as they are.
func TestOpenFitTooSmall(t *testing.T) {
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	owned := carrier.NewOwnedUDP(u, netip.MustParseAddrPort("127.0.0.1:9"), 7, 1472)
	defer owned.Close()
	emb, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer emb.Close()
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	dialTo := func(pc net.PacketConn, err error) func(context.Context) (net.PacketConn, net.Addr, error) {
		return func(context.Context) (net.PacketConn, net.Addr, error) { return pc, peer, err }
	}
	stream := func(context.Context) (net.Conn, error) { return nil, net.ErrClosed }
	fs := []carrier.Factory{
		{Index: 0, Name: "owned", Kind: wire.KindDatagram, MTU: 3991, DialPacket: dialTo(owned, nil)},
		{Index: 1, Name: "embedder", Kind: wire.KindDatagram, MTU: 3991, DialPacket: dialTo(emb, nil)},
		{Index: 2, Name: "failed", Kind: wire.KindDatagram, MTU: 3991, DialPacket: dialTo(nil, net.ErrClosed)},
		{Index: 3, Name: "stream", Kind: wire.KindStream, Dial: stream},
	}
	f := newOpenFit(len(fs))
	w := f.wrap(fs)
	if &w[0] == &fs[0] || w[3].Dial == nil || w[3].DialPacket != nil {
		t.Fatal("wrap changed the Peer's snapshot or a stream factory")
	}
	for i := range 3 {
		_, _, _ = w[i].DialPacket(context.Background())
	}
	want := []int32{1472 - wire.FlowHeaderLen, 0, 0, 0}
	for i := range want {
		if got := f.budget[i].Load(); got != want[i] {
			t.Errorf("factory %s recorded budget %d, want %d", fs[i].Name, got, want[i])
		}
	}
	fit := 1463 - openOverhead // the most metadata the owned carrier's OPEN carries
	for _, c := range []struct {
		name   string
		budget []int32
		meta   int
		want   bool
	}{
		{"one factory, too small", []int32{1463}, fit + 1, true},
		{"one factory, fits", []int32{1463}, fit, false},
		{"another factory never returned a carrier", []int32{1463, 0}, 2000, false},
		{"another factory carries it", []int32{1463, 3991}, 2000, false},
		{"both too small", []int32{1463, 1200}, 2000, true},
		{"no factory", nil, 2000, false},
	} {
		g := newOpenFit(len(c.budget))
		for i, b := range c.budget {
			g.budget[i].Store(b)
		}
		if got := g.tooSmall(c.meta); got != c.want {
			t.Errorf("%s: tooSmall(%d) = %v, want %v", c.name, c.meta, got, c.want)
		}
	}
	var none *openFit
	if none.tooSmall(1 << 16) {
		t.Error("a nil openFit (a Peer with a stream factory) maps an error")
	}
}
