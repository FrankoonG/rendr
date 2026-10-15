package udp

import (
	"testing"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// TestListenRecordsReadBuffer (M5 work item inboxtime, F-6; the options
// plumbing): Listen records in its token the read buffer it asked the
// kernel for — Options.ReadBuffer, or the 4-MiB default for 0 — whatever
// the kernel granted, so that the Source bounds each flow's inbox by the
// size the embedder configured. Mutant: Listen building the token without
// it (0: the 512-datagram bound).
func TestListenRecordsReadBuffer(t *testing.T) {
	defer wp5NoLeak(t)()
	for _, r := range []struct {
		rb, want int
	}{{0, defaultReadBuffer}, {256 << 10, 256 << 10}, {16 << 20, 16 << 20}} {
		pc, err := Listen("udp4", "127.0.0.1:0", Options{ReadBuffer: r.rb})
		if err != nil {
			t.Fatal(err)
		}
		if got := pc.(*carrier.OwnedUDPSocket).ReadBuffer(); got != r.want {
			t.Errorf("Options.ReadBuffer %d: the token records %d, want %d", r.rb, got, r.want)
		}
		pc.Close()
	}
}
