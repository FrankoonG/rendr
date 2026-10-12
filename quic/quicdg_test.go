package quic

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/rendrtest"
	qgo "github.com/quic-go/quic-go"
)

// pinnedRcvQueue is quic-go v0.63's receive queue (maxDatagramRcvQueueLen,
// pinned by TestQUICGoPinnedBehaviour): DATAGRAMs beyond it are dropped
// silently while nobody receives.
const pinnedRcvQueue = 128

// stallPair returns a datagram carrier pair whose receiving end (the
// passive when passiveReceives, else the dialer) counts its handled
// DATAGRAM frames in the returned tracer; both ends count drops.
func stallPair(t *testing.T, passiveReceives bool) (w, r *dgramConn, ft *frameTracer, wc, rc *Counters) {
	t.Helper()
	ft, wc, rc = &frameTracer{}, &Counters{}, &Counters{}
	traced := &qgo.Config{Tracer: ft.trace}
	if passiveReceives {
		cli, srv, _ := dgramPair(t, Options{Config: traced, Counters: rc}, Options{Counters: wc})
		return cli, srv, ft, wc, rc
	}
	cli, srv, _ := dgramPair(t, Options{Counters: wc}, Options{Config: traced, Counters: rc})
	return srv, cli, ft, wc, rc
}

// holdPump stops r's pump before its next receive. parked returns once
// the pump stopped there and the number of datagrams it queued meanwhile
// (none, or the one it was waiting for as the hold began); release (also a
// cleanup) lets it run again.
func holdPump(t *testing.T, r *dgramConn) (parked func() int, release func()) {
	h := &pumpHold{gate: make(chan struct{}), parked: make(chan struct{}, 1)}
	r.hold.Store(h)
	done := false
	release = func() {
		if !done {
			done = true
			r.hold.Store(nil)
			close(h.gate)
		}
	}
	t.Cleanup(release)
	parked = func() int {
		t.Helper()
		select {
		case <-h.parked:
		case <-time.After(testEventuallyTime):
			t.Fatal("the pump did not stop at the hold")
		}
		return queued(r)
	}
	return parked, release
}

// writeTraced has w write the datagrams seqDatagram(from … to-1, 1000) in
// groups of 32 and waits after each group until r's quic-go handled them
// (queued or dropped by its receive queue): QUIC's congestion window never
// keeps a group in w's egress queue long enough for an age drop.
func writeTraced(t *testing.T, w *dgramConn, ft *frameTracer, from, to int) {
	t.Helper()
	base := ft.rcvDatagrams.Load() - int64(from)
	for i := from; i < to; i++ {
		if _, err := w.WriteTo(seqDatagram(i, 1000), nil); err != nil {
			t.Fatal(err)
		}
		if i%32 == 31 || i == to-1 {
			eventually(t, "the receiver's quic-go handled the group", func() bool { return ft.rcvDatagrams.Load() == base+int64(i+1) })
		}
	}
}

// readSeqs reads n datagrams from r and returns their seqDatagram indices,
// failing on a datagram that is not intact.
func readSeqs(t *testing.T, r *dgramConn, n int) []int {
	t.Helper()
	buf := make([]byte, DatagramBudget+1)
	seqs := make([]int, 0, n)
	for range n {
		k, _, err := r.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom after %d datagrams: %v", len(seqs), err)
		}
		i := int(binary.BigEndian.Uint32(buf))
		if !bytes.Equal(buf[:k], seqDatagram(i, 1000)) {
			t.Fatalf("datagram %d (seq %d, %d bytes) is not intact", len(seqs), i, k)
		}
		seqs = append(seqs, i)
	}
	return seqs
}

// TestQUICDatagramPumpStallLossCounted_L46 (KL-19) is the accounting row:
// quic-go keeps at most 128 received DATAGRAMs per connection and drops
// beyond silently, so a stalled pump would lose datagrams no counter sees.
// It proves the accounting path, not the production trigger (a stall of
// the whole receiving process, which no in-process row reproduces; the
// Linux pool's G3 QUIC rows are that evidence). Stimulus: per
// direction, the receiving end's pump is held (a stalled consumer: a VM or
// scheduler stall cannot be produced in process, a held pump is the same
// burst after a pause) while the peer writes a burst of 1000-byte
// datagrams that its quic-go fully handles, then released, then one more
// datagram. Load: a burst of 300 overflows quic-go's queue by 171 or 172
// (by 171 when the pump was waiting for the first datagram as the hold
// began); a burst of 100 fits. Integrity: every delivered datagram is intact and in order —
// the head of the burst, then the trailing one — and per direction
// delivered + IngressDrops + EgressDrops == written, with IngressDrops
// exactly quic-go's overflow (none for the burst that fits).
func TestQUICDatagramPumpStallLossCounted_L46(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	for _, dir := range []struct {
		name            string
		passiveReceives bool
	}{{"dialer to passive", true}, {"passive to dialer", false}} {
		for _, burst := range []int{300, 100} {
			t.Run(dir.name+"/"+map[bool]string{true: "overflow", false: "fits"}[burst > pinnedRcvQueue], func(t *testing.T) {
				w, r, ft, wc, rc := stallPair(t, dir.passiveReceives)
				parked, release := holdPump(t, r)
				writeTraced(t, w, ft, 0, burst)
				kept := min(burst, pinnedRcvQueue+parked()) // what the pump took as the hold began, and quic-go's queue
				release()
				eventually(t, "the pump drained quic-go's queue", func() bool { return queued(r) == kept })
				if _, err := w.WriteTo(seqDatagram(burst, 1000), nil); err != nil {
					t.Fatal(err)
				}
				eventually(t, "the trailing datagram arrived", func() bool { return queued(r) == kept+1 })
				seqs := readSeqs(t, r, kept+1)
				for k, s := range seqs {
					if want := map[bool]int{true: k, false: burst}[k < kept]; s != want {
						t.Fatalf("delivered %v: datagram %d is seq %d, want %d", seqs, k, s, want)
					}
				}
				in, eg := rc.IngressDrops.Load(), wc.EgressDrops.Load()
				t.Logf("written %d, delivered %d, IngressDrops %d, EgressDrops %d", burst+1, len(seqs), in, eg)
				if in != uint64(burst-kept) || eg != 0 || uint64(len(seqs))+in+eg != uint64(burst+1) {
					t.Errorf("IngressDrops %d, EgressDrops %d, delivered %d of %d written: want IngressDrops %d (quic-go's overflow), no egress drop",
						in, eg, len(seqs), burst+1, burst-kept)
				}
			})
		}
	}
}
