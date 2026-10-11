package packet

import (
	"flag"
	"fmt"
	"runtime"
	"testing"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/udp"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The package's MaxBatch seam (M5 design R3-22, I1): `go test
// ./internal/scenario/packet -maxbatch=1` runs the real-socket rows
// (newUDPPair) at MaxBatch 1 — one datagram per system call — and
// -maxbatch=32 at the batching default; without the flag they use
// carrier/udp's default (0: 32).
var maxBatchFlag = flag.Int("maxbatch", 0, "carrier/udp Options.MaxBatch of the package's real-socket rows (0: the default)")

// udpOpts are the carrier/udp options of the package's real-socket rows.
func udpOpts() udp.Options { return udp.Options{MaxBatch: *maxBatchFlag} }

// seamBatching reports whether this build batches rendr's own UDP sockets
// (sendmmsg/recvmmsg: Linux amd64 and arm64, M5-D8).
var seamBatching = runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64")

// TestMaxBatchSeam: the seam reaches rendr's sockets. 2,000 test datagrams
// go each way over newUDPPair's session (pump: at most 128 ahead of the
// reader), every one arriving once and intact. At -maxbatch=1 both
// Runtimes moved one datagram per send and per receive call; at any other
// setting on a target that batches, the senders' calls were batched
// (SentDatagrams > SendCalls on both Runtimes).
func TestMaxBatchSeam(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	u := newUDPPair(t, testhooks.Overrides{})
	const n = 2000
	for i, d := range []struct{ w, r *rendr.PacketConn }{{u.dc, u.pc}, {u.pc, u.dc}} {
		if got, _ := pump(t, d.w, d.r, uint64(0x5ea0+i), n, 128); got != n {
			t.Fatalf("direction %d: %d of %d datagrams arrived", i, got, n)
		}
	}
	u.close(t)
	ds, ps := u.d.Status().Datagram, u.p.Status().Datagram
	t.Logf("-maxbatch=%d: dialer %s; passive %s", *maxBatchFlag, seamIO(ds), seamIO(ps))
	for name, s := range map[string]rendr.DatagramStatus{"dialer": ds, "passive": ps} {
		switch {
		case s.SendCalls == 0 || s.RecvCalls == 0:
			t.Errorf("%s: %s, want calls both ways", name, seamIO(s))
		case *maxBatchFlag == 1:
			if s.SendCalls != s.SentDatagrams || s.RecvCalls != s.RecvDatagrams {
				t.Errorf("-maxbatch=1: %s %s, want one datagram per call", name, seamIO(s))
			}
		case seamBatching:
			if s.SentDatagrams <= s.SendCalls {
				t.Errorf("-maxbatch=%d (%s/%s): %s %s, want its sends batched", *maxBatchFlag, runtime.GOOS, runtime.GOARCH, name, seamIO(s))
			}
		}
	}
}

// seamIO formats the I/O counters of a DatagramStatus.
func seamIO(s rendr.DatagramStatus) string {
	return fmt.Sprintf("send %d calls / %d datagrams, recv %d calls / %d datagrams", s.SendCalls, s.SentDatagrams, s.RecvCalls, s.RecvDatagrams)
}
