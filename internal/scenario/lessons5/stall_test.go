package lessons5

import (
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestPacketConsumerStalled_L40: the passive application stops reading its
// packet session. WriteTo never blocks (each call returns at once: < 1 ms of
// virtual time); the passive's receive queue (Packet.Queue 64 KiB: 65
// datagrams of 1000 bytes) drops its oldest datagrams, exactly the surplus
// (DropRecvQueue = Received − 65); the sender counts every datagram once
// (Sent + DropQueue + DropAge + … = accepted: where nothing backs up all are
// sent; on a stream carrier slower than the writer the sender's queue drops
// too, and WriteTo still returns at once); when the application reads again
// it gets exactly the newest 65 received, intact. Meanwhile a stream session
// of the same Runtime pair moves 1 MiB, SHA-256 equal, at its own rate
// (PA-15: "the same link" is the shared path — before M3's mux no carrier
// carries two sessions): with the packet session on a datagram carrier, on
// a stream carrier of the very link the stream session uses, and on a
// stream carrier of its own slow link.
//
// The shared link runs at 16 MiB/s: the stream session's in-flight bytes
// queue at the shared FIFO bottleneck ahead of the packet session's frames
// and PONGs, and at 4 MiB/s that queue could exceed MaxAge (100 ms), so
// the packet session's stream carrier stayed cap-blocked and datagrams
// aged out (DropAge 12 under -race at GOMAXPROCS=1, 2 of 15 runs); "nothing
// backs up" holds by construction only while that queue stays well below
// MaxAge.
func TestPacketConsumerStalled_L40(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stream bool // the packet session rides a stream carrier of link s
		slow   bool // … of its own stream link, slower than the writer
	}{{"datagram carrier", false, false}, {"stream carrier on the same link", true, false}, {"stream carrier slower than the writer", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				pcfg := rendr.Config{}
				pcfg.Packet.Queue = 64 << 10
				w := newWorld(t, worldOpts{pcfg: pcfg}, "d")
				dl := w.links[0]
				dl.SetDelay(rendrtest.Up, 5*time.Millisecond, 0)
				dl.SetDelay(rendrtest.Down, 5*time.Millisecond, 0)
				ls := w.addStreamLink("s")
				ls.SetDelay(5*time.Millisecond, 0)
				ls.SetRate(16 << 20)
				var pktCarrier rendr.Carrier = w.dgCarrier(dl, 1400)
				if tc.stream {
					pktCarrier = rendr.StreamCarrier{Name: "s", Dial: ls.Dial}
				}
				if tc.slow {
					// 256 KiB/s for 1 MB/s offered: the sender's queue fills.
					lp := w.addStreamLink("p")
					lp.SetDelay(5*time.Millisecond, 0)
					lp.SetRate(256 << 10)
					pktCarrier = rendr.StreamCarrier{Name: "p", Dial: lp.Dial}
				}
				dcP, pcP := w.open(w.peer(pktCarrier), rendr.DialOptions{})
				dcS, scS := w.openStream(w.peer(rendr.StreamCarrier{Name: "s", Dial: ls.Dial}))

				// 2000 datagrams of 1000 bytes, one per millisecond, that
				// nobody reads; 1 MiB on the stream session at the same time.
				const n, size = 2000, 1000
				wr := writePackets(dcP, 30, 0, n, time.Millisecond, func(int) int { return size })
				f := startStream(dcS, scS, 1<<20, 31)
				f.wait(t, 5*time.Second, "1 MiB on the stream session")
				took := f.rend.Sub(f.start)
				during := wr.accepted.Load()
				wr.wait(t, 10*time.Second, "the packet writer")
				if during >= n {
					t.Fatalf("load: the packet writer had finished before the stream did (%d of %d)", during, n)
				}
				// 1 MiB at 16 MiB/s is 62.5 ms; the packet session's share of
				// the link (1 MB/s on the shared link) leaves at least 15 MB/s.
				if took > 175*time.Millisecond {
					t.Fatalf("the stream session needed %v for 1 MiB beside the stalled packet session", took)
				}
				if wr.maxCall >= time.Millisecond {
					t.Fatalf("a WriteTo blocked for %v (L40: never)", wr.maxCall)
				}
				time.Sleep(500 * time.Millisecond)
				// The sender's queue drains (every accepted datagram sent or
				// counted as a drop) and the passive receives all it sent.
				for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
					ds, ps := dcP.Status().Packet, pcP.Status().Packet
					if ds.Sent+ds.DropQueue+ds.DropAge+ds.DropNoPath+ds.DropTooLarge == n && ps.Received == ds.Sent {
						break
					}
					if !time.Now().Before(deadline) {
						t.Fatalf("after 10 s: dialer %+v (Sent + drops ≠ %d accepted?), passive Received %d", *ds, n, ps.Received)
					}
				}
				synctest.Wait()

				ds, ps := dcP.Status().Packet, pcP.Status().Packet
				if sum := ds.Sent + ds.DropQueue + ds.DropAge + ds.DropNoPath + ds.DropTooLarge; sum != n {
					t.Fatalf("dialer: %d accepted ≠ %d = %+v", n, sum, *ds)
				}
				if !tc.slow && (ds.Sent != n || dl.Stats().Session.Lost != 0) {
					t.Fatalf("dialer: %+v, link lost %d; want all %d sent (nothing backs up)", *ds, dl.Stats().Session.Lost, n)
				}
				if tc.slow && ds.DropQueue+ds.DropAge == 0 {
					t.Fatalf("stimulus: the sender dropped nothing on the slow link: %+v", *ds)
				}
				const held = 65 // ⌊64 KiB / 1000⌋
				if ps.Received != ds.Sent || ps.DropRecvQueue != ps.Received-held || ps.DropLate+ps.Duplicates != 0 {
					t.Fatalf("passive %+v; want Received = the dialer's Sent %d and DropRecvQueue = Received − %d", *ps, ds.Sent, held)
				}
				// The application reads again: exactly the newest 65 received —
				// seqs n−65 … n−1 when the sender dropped nothing; otherwise
				// the last 65 the sender's drop-oldest queue let through, ending
				// with the newest datagram.
				r := readPackets(pcP, 30)
				waitFor(t, time.Second, "the queued datagrams", func() bool { return r.n.Load() == held })
				time.Sleep(200 * time.Millisecond)
				res := r.check(t, "the resumed reader")
				if r.n.Load() != held || res.Unique != held || res.Highest != n-1 {
					t.Fatalf("the resumed reader got %d: %+v; want %d ending with seq %d", r.n.Load(), res, held, n-1)
				}
				if !tc.slow && (len(res.Missing) != 1 || res.Missing[0] != (rendrtest.SeqRange{From: 0, To: n - held - 1})) {
					t.Fatalf("the resumed reader got %+v; want seqs %d … %d", res, n-held, n-1)
				}
				if got := pcP.Status().Packet; got.Received != uint64(r.n.Load())+got.DropRecvQueue {
					t.Fatalf("passive Received %d ≠ read %d + DropRecvQueue %d", got.Received, r.n.Load(), got.DropRecvQueue)
				}
				t.Logf("stream 1 MiB in %v; dialer %+v; passive %+v", took, *ds, *ps)

				dcP.Close()
				r.wait(t, 5*time.Second, "the passive packet reader")
				pcP.Close()
				waitDone(t, 5*time.Second, dcP, pcP)
				dcS.Close()
				scS.Close()
				waitFor(t, time.Minute, "the stream session's end", func() bool {
					return dcS.Status().State == rendr.StateEnded && scS.Status().State == rendr.StateEnded
				})
				w.close()
			})
		})
	}
}
