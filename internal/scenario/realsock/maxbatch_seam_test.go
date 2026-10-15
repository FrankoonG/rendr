package realsock

import (
	"flag"
	"runtime"
	"sync"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/udp"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The package's MaxBatch seam (M5 design R3-22, I1): `go test
// ./internal/scenario/realsock -maxbatch=1` runs every row that opens
// carrier/udp sockets through udpOpts at MaxBatch 1 — one datagram per
// system call — and -maxbatch=32 at the batching default; without the
// flag the rows use carrier/udp's default (0: 32). The rows with arms of
// their own (TestRealUDPBatchE2E, TestRealUDPSelectorSwitchSame_L55) keep
// them.
var maxBatchFlag = flag.Int("maxbatch", 0, "carrier/udp Options.MaxBatch of the package's real-socket rows (0: the default)")

// udpOpts are the carrier/udp options of the package's real-socket rows.
func udpOpts() udp.Options { return udp.Options{MaxBatch: *maxBatchFlag} }

// TestMaxBatchSeam: the seam reaches rendr's sockets. A selector packet
// session over carrier/udp sockets opened with udpOpts carries a burst of
// 200 datagrams each way (below a flow inbox, udpflow.DefaultInbox);
// every one arrives once and intact. At
// -maxbatch=1 both Runtimes moved one datagram per send and per receive
// call; at any other setting on a target that batches (Linux amd64 and
// arm64) the dialer's sends of the burst were batched (SentDatagrams >
// SendCalls).
func TestMaxBatchSeam(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	o := udpOpts()
	sock, err := udp.Listen("udp4", "127.0.0.1:0", o)
	if err != nil {
		t.Fatal(err)
	}
	m := newMsPair(t, rendr.Config{}, nil, rendr.ListenConfig{Sources: []rendr.Source{rendr.FromPacketConn(sock)}},
		[]rendr.Carrier{udp.Carrier("u", "udp4", sock.LocalAddr().String(), o)})
	dc, pc := m.openPacket(rendr.ModeSelector)
	const n = 200
	var wg sync.WaitGroup
	for _, d := range []struct {
		tx, rx *rendr.PacketConn
		seed   uint64
	}{{dc, pc, 0x5ea1}, {pc, dc, 0x5ea2}} {
		v := rendrtest.NewPacketVerifier(d.seed)
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 2048)
			d.rx.SetReadDeadline(time.Now().Add(10 * time.Second))
			for v.Result().Unique < n {
				k, _, err := d.rx.ReadFrom(buf)
				if err != nil {
					t.Errorf("seed %#x: ReadFrom after %d: %v", d.seed, v.Result().Unique, err)
					return
				}
				if err := v.Add(buf[:k], time.Now()); err != nil {
					t.Errorf("seed %#x: %v", d.seed, err)
				}
			}
			if r := v.Result(); r.Corrupt != 0 || r.BadSize != 0 || r.Duplicates != 0 {
				t.Errorf("seed %#x: %+v", d.seed, r)
			}
		}()
		buf := make([]byte, 1024)
		now := time.Now()
		for seq := range uint64(n) {
			if _, err := d.tx.WriteTo(rendrtest.PacketPayload(buf, d.seed, seq, rendrtest.PacketHeaderLen+int(seq%200), now), nil); err != nil {
				t.Fatalf("WriteTo %d: %v", seq, err)
			}
		}
	}
	wg.Wait()
	dc.Close()
	pc.Close()
	msDone(t, dc.Done(), "the dialer session")
	msDone(t, pc.Done(), "the passive session")
	m.muxZero()
	m.close()
	ds, ps := m.d.Status().Datagram, m.p.Status().Datagram
	t.Logf("-maxbatch=%d: dialer %s; passive %s", *maxBatchFlag, beIO(ds), beIO(ps))
	switch {
	case *maxBatchFlag == 1:
		for _, s := range []rendr.DatagramStatus{ds, ps} {
			if s.SendCalls != s.SentDatagrams || s.RecvCalls != s.RecvDatagrams || s.SendCalls == 0 {
				t.Errorf("-maxbatch=1: %s, want one datagram per call", beIO(s))
			}
		}
	case beBatching:
		if ds.SentDatagrams <= ds.SendCalls {
			t.Errorf("-maxbatch=%d (%s/%s): dialer %s, want the burst's sends batched", *maxBatchFlag, runtime.GOOS, runtime.GOARCH, beIO(ds))
		}
	}
}
