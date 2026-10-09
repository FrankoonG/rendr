package lessons5

import (
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestPacketReorderDuplicateNoViolation_L43: a packet bond over two links
// that duplicate 20 % of the datagrams and delay another 20 % past their
// successors, in both directions, while 2000 datagrams flow each way and
// REL control (PACKs, the end's FIN, FIN_DELIVERED and DONE) runs over
// them. The fseq window is not strict +1 (M2-D13): a reordered frame is
// accepted once, a duplicate is dropped — no carrier dies, nothing is a
// protocol violation. Each end's carriers count in Dropped exactly the
// duplicate frames that end read (the taps follow every fseq), and the
// duplicate datagrams the taps saw are exactly those the links made. Every
// datagram arrives once and intact, and the session ends cleanly under the
// same duplication and reordering.
func TestPacketReorderDuplicateNoViolation_L43(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{dcfg: noDialWait(), tap: true}, "a", "b")
		for i, l := range w.links {
			for _, d := range []rendrtest.Dir{rendrtest.Up, rendrtest.Down} {
				l.SetDelay(d, []time.Duration{5 * time.Millisecond, 8 * time.Millisecond}[i], time.Millisecond)
			}
		}
		disorder := func(on bool) {
			p, extra := 0.0, 5*time.Millisecond
			if on {
				p = 0.20
			}
			for _, l := range w.links {
				for _, d := range []rendrtest.Dir{rendrtest.Up, rendrtest.Down} {
					l.SetDuplicate(d, p)
					l.SetReorder(d, p, extra)
				}
			}
		}
		dc, pc := w.open(w.peer(w.dgCarrier(w.links[0], 1400), w.dgCarrier(w.links[1], 1400)), rendr.DialOptions{Mode: rendr.ModeBond})
		waitFor(t, 5*time.Second, "both members on both ends", func() bool {
			return len(liveOf(dc.Status())) == 2 && len(liveOf(pc.Status())) == 2
		})
		// Duplication starts after the handshakes: every duplicate from now
		// on is a frame duplicate that a started carrier reads.
		disorder(true)
		const n = 2000
		r := readPackets(pc, 50)
		back := readPackets(dc, 51)
		wr := writePackets(dc, 50, 0, n, 5*time.Millisecond, nil)
		wb := writePackets(pc, 51, 0, n, 5*time.Millisecond, nil)
		wr.wait(t, time.Minute, "dialer → passive")
		wb.wait(t, time.Minute, "passive → dialer")
		time.Sleep(300 * time.Millisecond)
		disorder(false)
		time.Sleep(500 * time.Millisecond)
		synctest.Wait()

		ds, ps := dc.Status(), pc.Status()
		var dupl, reord, lost uint64
		for _, l := range w.links {
			st := l.Stats().Session
			dupl, reord, lost = dupl+st.Duplicated, reord+st.Reordered, lost+st.Lost
		}
		dt, pt := w.taps.tapTotals(true), w.taps.tapTotals(false)
		dDrop, pDrop := dropped(ds), dropped(ps)
		t.Logf("links: Duplicated %d, Reordered %d, Lost %d; taps: dialer %+v, passive %+v; Dropped dialer %d, passive %d",
			dupl, reord, lost, dt, pt, dDrop, pDrop)
		if dupl < 500 || reord < 500 {
			t.Fatalf("stimulus: the links duplicated %d and reordered %d session datagrams", dupl, reord)
		}
		// No death, no switch: the disorder is never a violation.
		for _, st := range []rendr.SessionStatus{ds, ps} {
			if len(liveOf(st)) != 2 || len(deadOf(st)) != 0 || st.Migrations != (rendr.MigrationCounts{}) {
				t.Fatalf("%v: carriers %+v, migrations %+v; want both members alive", st.Role, st.Carriers, st.Migrations)
			}
		}
		if downs := len(w.dev.of(rendr.EventCarrierDown)) + len(w.pev.of(rendr.EventCarrierDown)); downs != 0 {
			t.Fatalf("%d carriers went down", downs)
		}
		// Every duplicate the links made was read and dropped by the fseq
		// window, frame by frame.
		if lost != 0 || dt.EarlyCopies+pt.EarlyCopies != 0 || uint64(dt.DupDgrams+pt.DupDgrams) != dupl {
			t.Fatalf("the taps saw %d duplicate datagrams (%d early copies), the links made %d (lost %d)",
				dt.DupDgrams+pt.DupDgrams, dt.EarlyCopies+pt.EarlyCopies, dupl, lost)
		}
		if dDrop != uint64(dt.DupFrames) || pDrop != uint64(pt.DupFrames) {
			t.Fatalf("Dropped dialer %d, passive %d; duplicate frames read %d, %d", dDrop, pDrop, dt.DupFrames, pt.DupFrames)
		}
		// Load and integrity: all of it, once.
		rr, br := r.check(t, "dialer → passive"), back.check(t, "passive → dialer")
		if rr.Unique != n || br.Unique != n || ps.Packet.Received != n || ds.Packet.Received != n ||
			ps.Packet.Duplicates+ds.Packet.Duplicates != 0 {
			t.Fatalf("delivered %d / %d of %d; passive %+v; dialer %+v", rr.Unique, br.Unique, n, *ps.Packet, *ds.Packet)
		}

		// The end runs under the same disorder.
		disorder(true)
		dc.Close()
		r.wait(t, 5*time.Second, "dialer → passive")
		back.waitClosed(t, 5*time.Second, "passive → dialer")
		pc.Close()
		waitDone(t, 5*time.Second, dc, pc)
		w.noViolation()
		for _, st := range []rendr.SessionStatus{dc.Status(), pc.Status()} {
			for _, c := range st.Carriers {
				switch c.DeathCause {
				case rendr.CauseNone, rendr.CauseRetired:
				default:
					t.Fatalf("%v carrier %d ended %v %q under disorder", st.Role, c.ID, c.DeathCause, c.DeathDetail)
				}
			}
		}
		w.close()
	})
}
