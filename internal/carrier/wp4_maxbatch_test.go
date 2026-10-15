package carrier

import (
	"net"
	"testing"
)

// TestOwnedUDPMaxBatchNormalised (M5 design §A10.1 WP4, §A2.2; M5-D16):
// both rendr-owned socket tokens store carrier/udp's Options.MaxBatch
// normalised — 0 and negative values select DefaultMaxBatch (32), 1 … 64
// are kept, larger values become 64 — so a dialer socket batches as deep
// as a Listen socket for the same option. The dialer token shows its depth
// through MaxBatch only once a carrier bound it on Linux amd64/arm64, so
// the row reads the stored value; carrier/udp's TestUDPOptionsMaxBatch
// checks that Dial and Listen hand the option over.
func TestOwnedUDPMaxBatchNormalised(t *testing.T) {
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close() // the tokens are dropped unused; none closes u
	for _, r := range []struct{ in, want int }{
		{0, DefaultMaxBatch}, {-1, DefaultMaxBatch}, {-1 << 20, DefaultMaxBatch},
		{1, 1}, {2, 2}, {31, 31}, {32, 32}, {33, 33}, {63, 63}, {64, 64},
		{65, 64}, {1 << 20, 64},
	} {
		if got := NewOwnedUDPBatch(u, wp5AP(u), wp5Flow, wp5MaxDatagram, r.in).maxBatch; got != r.want {
			t.Errorf("NewOwnedUDPBatch with MaxBatch %d stored %d, want %d", r.in, got, r.want)
		}
		if got := NewOwnedUDPSocketBatch(u, wp5MaxDatagram, r.in).MaxBatch(); got != r.want {
			t.Errorf("NewOwnedUDPSocketBatch with MaxBatch %d: MaxBatch %d, want %d", r.in, got, r.want)
		}
	}
	if got := NewOwnedUDP(u, wp5AP(u), wp5Flow, wp5MaxDatagram).maxBatch; got != DefaultMaxBatch {
		t.Errorf("NewOwnedUDP stored MaxBatch %d, want %d", got, DefaultMaxBatch)
	}
}
