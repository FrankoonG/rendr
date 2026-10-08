package lessons7

import (
	"context"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestPacketNatRebindHeld_L59 (integration 2's open item K5; R1-14, M2-D27):
// the dialer of a packet OPEN moves to a new address after its H2 arrived,
// while the passive holds the carrier (no Confirm for 3 more seconds). The
// dialer's Establish keeps sending its H1 verbatim every RelRTOMax while it
// waits for the response, so a copy arrives from the new address; the held
// passive flow challenges that address, the dialer's Establish answers,
// the rebind commits and the verdict at Confirm reaches the new address.
// DialPacket returns one one-way delay after Confirm on the first carrier
// (one dial, one rebind) and datagrams flow both ways.
//
// Before the keepalive, nothing reached the passive from the new address
// until the verdict: the verdict went to the old address, the attempt ended
// at DialTimeout (10 s after its start) and a second carrier opened the
// session — DialPacket returned 10.05 s after its start, 6 s after Confirm,
// with 2 dials and no rebind.
func TestPacketNatRebindHeld_L59(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const owd = 25 * time.Millisecond
		w := newWorld(t, worldOpts{hubUp: owd, hubDown: owd})
		start := time.Now()
		ch := dial(w.peer(w.hubCarrier("h0", 0)), rendr.DialOptions{})
		pp, err := w.ln.AcceptPacket(context.Background())
		if err != nil {
			t.Fatalf("AcceptPacket: %v", err)
		}
		time.Sleep(time.Second) // H2 arrived long ago: the dialer waits for the verdict
		if got, _ := w.dconns.last().snapshot(); len(got) != 1 || !got[0].preface {
			t.Fatalf("stimulus: before the rebind the dialer read %d datagrams, want the H2 alone", len(got))
		}
		reads, _ := w.tap.snapshot()
		oldAddr := reads[0].addr // the H1
		rebindAt := time.Now()
		w.hub.Rebind(0)
		time.Sleep(3 * time.Second)
		confirmAt := time.Now()
		pc, err := pp.Confirm()
		if err != nil {
			t.Fatalf("Confirm: %v", err)
		}
		var r dialed
		select {
		case r = <-ch:
		case <-time.After(20 * time.Second):
			t.Fatal("DialPacket did not return")
		}
		hs := w.hub.Stats()
		t.Logf("DialPacket returned %v after its start, %v after Confirm (%v); hub: %d dials, %d rebinds; passive Runtime rebinds %d",
			r.at.Sub(start), r.at.Sub(confirmAt), r.err, hs.Dials, hs.Rebinds, w.p.Status().Datagram.Rebinds)
		if r.err != nil {
			t.Fatalf("DialPacket: %v", r.err)
		}
		dc := r.c
		if hs.Rebinds != 1 {
			t.Fatalf("stimulus: hub rebinds %d, want 1", hs.Rebinds)
		}
		if d := r.at.Sub(confirmAt); hs.Dials != 1 || d > 4*owd+100*time.Millisecond {
			t.Fatalf("DialPacket returned %v after Confirm with %d dials: want one carrier, one round trip after Confirm", d, hs.Dials)
		}

		// The move was found during the hold, from an H1 copy of the new
		// address, and proven by the nonce round trip.
		reads, writes := w.tap.snapshot()
		var newAddr netip.AddrPort
		var copyAt time.Time
		for _, d := range reads {
			if d.at.After(rebindAt) && d.preface && d.addr != oldAddr {
				newAddr, copyAt = d.addr, d.at
				break
			}
		}
		if !newAddr.IsValid() || !copyAt.Before(rebindAt.Add(2*time.Second+2*owd)) {
			t.Fatalf("no H1 copy from the new address within RelRTOMax of the rebind (first at %v)", copyAt.Sub(rebindAt))
		}
		var chal, pong, verdict tapDgram
		for _, d := range writes {
			if d.at.Before(rebindAt) {
				continue
			}
			if d.addr == oldAddr && !(d.preface && d.at.Before(chalCommit(reads, newAddr))) {
				t.Fatalf("after the rebind the passive wrote %v to the old address at %v: only H2 repeats before the commit may go there", d.types(), d.at.Sub(start))
			}
			for _, f := range d.frames {
				switch {
				case f.typ == wire.TypePing && f.id == 0 && chal.at.IsZero():
					chal = d
				case f.typ == wire.TypeRel && f.inner == wire.TypeOpenAck && verdict.at.IsZero():
					verdict = d
				}
			}
		}
		for _, d := range reads {
			for _, f := range d.frames {
				if f.typ == wire.TypePong && f.id == 0 && pong.at.IsZero() {
					pong = d
				}
			}
		}
		if chal.addr != newAddr || pong.addr != newAddr || !chal.at.Before(confirmAt) || !pong.at.Before(confirmAt) {
			t.Fatalf("challenge %v to %v, its PONG %v from %v; want both before Confirm (%v), with the new address %v",
				chal.at.Sub(start), chal.addr, pong.at.Sub(start), pong.addr, confirmAt.Sub(start), newAddr)
		}
		if verdict.addr != newAddr {
			t.Fatalf("the verdict went to %v, want the new address %v", verdict.addr, newAddr)
		}
		ps := oneLive(t, "passive", pc)
		ds := oneLive(t, "dialer", dc)
		if ps.ID != ds.ID || ps.Rebinds != 1 || w.p.Status().Datagram.Rebinds != 1 {
			t.Fatalf("carriers: passive %+v, dialer %+v, Runtime rebinds %d; want one carrier with one rebind", ps, ds, w.p.Status().Datagram.Rebinds)
		}

		// Load and integrity after the open.
		burst(t, dc, pc, 21, 50, "dialer → passive")
		burst(t, pc, dc, 22, 50, "passive → dialer")
		w.noViolation()
		dc.Close()
		pc.Close()
		waitDone(t, 10*time.Second, dc, pc)
		w.close()
	})
}

// chalCommit returns when the challenge PONG from addr was read (the
// rebind's commit); far in the future when none was.
func chalCommit(reads []tapDgram, addr netip.AddrPort) time.Time {
	for _, d := range reads {
		for _, f := range d.frames {
			if f.typ == wire.TypePong && f.id == 0 && d.addr == addr {
				return d.at
			}
		}
	}
	return time.Now().Add(time.Hour)
}
