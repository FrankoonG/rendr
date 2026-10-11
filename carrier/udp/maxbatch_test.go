package udp

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// maxBatchRows are Options.MaxBatch values and the depth a socket gets
// (M5-D16, M5 design §A2.2): 0 and negative values select 32, 1 … 64 are
// kept, larger values become 64.
var maxBatchRows = []struct{ in, want int }{
	{0, 32}, {-1, 32}, {-1 << 20, 32},
	{1, 1}, {2, 2}, {31, 31}, {32, 32}, {33, 33}, {63, 63}, {64, 64},
	{65, 64}, {1 << 20, 64},
}

// TestUDPOptionsMaxBatch (§A10.1 WP4; M5-D16): Options.MaxBatch reaches
// both kinds of rendr-owned socket. Listen: the token rendr adopts through
// FromPacketConn carries the normalised value (OwnedUDPSocket.MaxBatch,
// which an owned Source's reads cap at 32, R1-6). Dial: the factory hands
// the option to the dialer token's constructor (newOwnedUDP, observed
// through the seam: the token shows its depth only once a carrier bound
// it on Linux amd64/arm64), which normalises it as Listen's does — the
// returned token is that constructor's. The real-socket half on Linux,
// where MaxBatch 1 makes every call move one datagram, is
// TestRealUDPBatchE2E (internal/scenario/realsock).
func TestUDPOptionsMaxBatch(t *testing.T) {
	defer wp5NoLeak(t)()

	for _, r := range maxBatchRows {
		pc, err := Listen("udp4", "127.0.0.1:0", Options{MaxBatch: r.in})
		if err != nil {
			t.Fatalf("Listen with MaxBatch %d: %v", r.in, err)
		}
		tok, ok := pc.(*carrier.OwnedUDPSocket)
		if !ok {
			pc.Close()
			t.Fatalf("Listen returned %T, want *carrier.OwnedUDPSocket", pc)
		}
		if got := tok.MaxBatch(); got != r.want {
			t.Errorf("Listen with MaxBatch %d: the socket's MaxBatch %d, want %d", r.in, got, r.want)
		}
		pc.Close()
	}

	orig := newOwnedUDP
	t.Cleanup(func() { newOwnedUDP = orig })
	var got []int
	var built *carrier.OwnedUDP
	newOwnedUDP = func(u *net.UDPConn, peer netip.AddrPort, flow uint64, maxDatagram, maxBatch int) *carrier.OwnedUDP {
		got = append(got, maxBatch)
		built = orig(u, peer, flow, maxDatagram, maxBatch)
		return built
	}
	for i, r := range maxBatchRows {
		c := Carrier("u", "udp4", "127.0.0.1:9", Options{MaxBatch: r.in})
		pc, _, err := c.Dial(context.Background())
		if err != nil {
			t.Fatalf("Dial with MaxBatch %d: %v", r.in, err)
		}
		if len(got) != i+1 || got[i] != r.in {
			pc.Close()
			t.Fatalf("Dial with MaxBatch %d: the token's constructor saw %v (row %d), want %d last", r.in, got, i, r.in)
		}
		if pc != built {
			t.Errorf("Dial with MaxBatch %d returned %T %p, not the token the constructor built", r.in, pc, pc)
		}
		pc.Close()
	}
}
