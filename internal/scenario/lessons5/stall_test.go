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
// (Sent + its drops = accepted; on a datagram carrier nothing backs up, so
// DropQueue and DropAge stay 0); when the application reads again it gets
// exactly the newest 65, intact. Meanwhile a stream session of the same
// Runtime pair moves 1 MiB, SHA-256 equal, at its own rate (PA-15: "the
// same link" is the shared path — before M3's mux no carrier carries two
// sessions): with the packet session on a datagram carrier, and with the
// packet session on a stream carrier of the very link the stream session
// uses.
func TestPacketConsumerStalled_L40(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stream bool // the packet session rides a stream carrier of link s
	}{{"datagram carrier", false}, {"stream carrier on the same link", true}} {
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
				ls.SetRate(4 << 20)
				var pktCarrier rendr.Carrier = w.dgCarrier(dl, 1400)
				if tc.stream {
					pktCarrier = rendr.StreamCarrier{Name: "s", Dial: ls.Dial}
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
				// 1 MiB at 4 MiB/s is 250 ms; the packet session's share of
				// the link (1 MB/s on the shared link) leaves at least 3 MB/s.
				if took > 700*time.Millisecond {
					t.Fatalf("the stream session needed %v for 1 MiB beside the stalled packet session", took)
				}
				if wr.maxCall >= time.Millisecond {
					t.Fatalf("a WriteTo blocked for %v (L40: never)", wr.maxCall)
				}
				time.Sleep(500 * time.Millisecond)
				synctest.Wait()

				ds, ps := dcP.Status().Packet, pcP.Status().Packet
				if sum := ds.Sent + ds.DropQueue + ds.DropAge + ds.DropNoPath + ds.DropTooLarge; sum != n {
					t.Fatalf("dialer: %d accepted ≠ %d = %+v", n, sum, *ds)
				}
				if !tc.stream && (ds.Sent != n || dl.Stats().Session.Lost != 0) {
					t.Fatalf("dialer on a datagram carrier: %+v, link lost %d; want all %d sent", *ds, dl.Stats().Session.Lost, n)
				}
				const held = 65 // ⌊64 KiB / 1000⌋
				if ps.Received != ds.Sent || ps.DropRecvQueue != ps.Received-held || ps.DropLate+ps.Duplicates != 0 {
					t.Fatalf("passive %+v; want Received = the dialer's Sent %d and DropRecvQueue = Received − %d", *ps, ds.Sent, held)
				}
				// The application reads again: exactly the newest 65.
				r := readPackets(pcP, 30)
				waitFor(t, time.Second, "the queued datagrams", func() bool { return r.n.Load() == held })
				time.Sleep(200 * time.Millisecond)
				res := r.check(t, "the resumed reader")
				if r.n.Load() != held || res.Unique != held || res.Highest != n-1 ||
					len(res.Missing) != 1 || res.Missing[0] != (rendrtest.SeqRange{From: 0, To: n - held - 1}) {
					t.Fatalf("the resumed reader got %d: %+v; want seqs %d … %d", r.n.Load(), res, n-held, n-1)
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
