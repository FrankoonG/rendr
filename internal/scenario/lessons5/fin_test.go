package lessons5

import (
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestPacketFinViaSurvivor_L40: a packet bond over links A (fast) and B. A
// silently drops the first datagram carrying application datagrams (a gap
// the passive can never fill), and later every copy of the dialer's FIN,
// which the dialer places on A, its fastest member; then A dies. The FIN is
// placed again on the survivor B: the passive's ReadFrom returns every
// datagram it accepted and then io.EOF, within 1 s of A's death — the gap
// costs only the bounded straggler wait (M2-D40) — and both sessions end
// cleanly.
func TestPacketFinViaSurvivor_L40(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stop := make(chan struct{})
		defer close(stop)
		w := newWorld(t, worldOpts{dcfg: noDialWait()}, "A", "B")
		la, lb := w.links[0], w.links[1]
		for _, d := range []rendrtest.Dir{rendrtest.Up, rendrtest.Down} {
			la.SetDelay(d, 2*time.Millisecond, 0)
			lb.SetDelay(d, 20*time.Millisecond, 0)
		}
		dc, pc := w.open(w.peer(w.dgCarrier(la, 1400), w.dgCarrier(lb, 1400)), rendr.DialOptions{Mode: rendr.ModeBond})
		waitFor(t, 5*time.Second, "both members on both ends", func() bool {
			return len(liveOf(dc.Status())) == 2 && len(liveOf(pc.Status())) == 2
		})
		var idA rendr.CarrierID
		for _, c := range liveOf(dc.Status()) {
			if c.Name == "A" {
				idA = c.ID
			}
		}
		r := readPackets(pc, 40)
		lostA := la.Stats().Session.Lost
		la.DropNext(rendrtest.Up, rendrtest.FrameDgram, 1)
		const n = 300
		wr := writePackets(dc, 40, 0, n, time.Millisecond, nil)
		wr.wait(t, 5*time.Second, "the datagrams")
		time.Sleep(500 * time.Millisecond)
		gapLost := la.Stats().Session.Lost - lostA
		if gapLost != 1 {
			t.Fatalf("stimulus: A lost %d session datagrams, want the one DGRAM datagram", gapLost)
		}
		accepted := pc.Status().Packet.Received
		if accepted >= n || accepted < n-64 || uint64(r.n.Load()) != accepted {
			t.Fatalf("before the FIN: passive Received %d, read %d of %d: want a gap of one datagram's DGRAMs", accepted, r.n.Load(), n)
		}

		// Every FIN copy on A is lost; the dialer closes at an instant no
		// timer shares, so only the FIN's wake decides where it goes.
		finA := stamp(la.CaptureNext(rendrtest.Up, rendrtest.FrameFin), stop)
		finB := stamp(lb.CaptureNext(rendrtest.Up, rendrtest.FrameFin), stop)
		la.DropNext(rendrtest.Up, rendrtest.FrameFin, 1<<20)
		retxA := uint64(0)
		if c, ok := carrierOf(dc.Status(), idA); ok {
			retxA = c.Retransmits
		}
		time.Sleep(777*time.Microsecond + 13)
		synctest.Wait()
		dc.Close()
		time.Sleep(300 * time.Millisecond) // the FIN and its first resend are lost on A
		la.Refuse(true)
		la.Kill()
		killAt := time.Now()
		res := r.wait(t, 5*time.Second, "the passive")
		pc.Close()
		waitDone(t, 5*time.Second, dc, pc)

		var fa, fb capture
		select {
		case fa = <-finA:
		default:
			t.Fatal("stimulus: the FIN was never placed on A")
		}
		select {
		case fb = <-finB:
		default:
			t.Fatal("the FIN never travelled on B")
		}
		if fa.at.After(killAt) || fb.at.Before(killAt) {
			t.Fatalf("FIN on A at %v, on B at %v, A killed at %v: want A first, B after A's death",
				fa.at.Format("05.000"), fb.at.Format("05.000"), killAt.Format("05.000"))
		}
		if c, ok := carrierOf(dc.Status(), idA); !ok || c.Retransmits <= retxA || c.State != rendr.CarrierDead {
			t.Fatalf("A's carrier %+v (found %v): want its FIN resent before its death (Retransmits > %d)", c, ok, retxA)
		}
		if d := r.endAt.Sub(killAt); d > time.Second {
			t.Fatalf("io.EOF %v after A's death, want within 1 s", d)
		}
		ps := pc.Status().Packet
		if uint64(res.Unique) != ps.Received || ps.Received != accepted || ps.DropRecvQueue+ps.DropLate+ps.Duplicates != 0 {
			t.Fatalf("before io.EOF %d datagrams returned (%+v); passive %+v; want every accepted one (%d)", res.Unique, res, *ps, accepted)
		}
		if len(res.Missing) == 0 && res.Highest == n-1 {
			t.Fatalf("stimulus: no gap in %+v", res)
		}
		t.Logf("gap of %d datagrams; after the FIN's first copy on A: A killed +%v, the FIN on B +%v, io.EOF +%v",
			n-int(accepted), killAt.Sub(fa.at), fb.at.Sub(fa.at), r.endAt.Sub(fa.at))
		w.noViolation()
		w.close()
	})
}
