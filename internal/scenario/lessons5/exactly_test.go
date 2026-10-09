package lessons5

import (
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestPacketExactlyOnceAcrossSwitches_L39: 1000 counted datagrams each way
// over a selector session while it switches five times — three carrier
// deaths and two quality switches — on links that duplicate 5 % of the
// datagrams and reorder 10 % of them. Every datagram is returned at most
// once and intact. The network duplicates repeat their fseq, so the
// carriers' fseq windows drop them (CarrierStatus.Dropped) before the
// session sees them (R1-10): Dropped covers every duplicate frame the taps
// observed, and the duplicates observed cover the links' Duplicated count
// minus what the links lost. The session's dedup window (SeqWindow) is
// exercised by injected session-level duplicates — a DGRAM the dialer
// wrote, re-sent alone with a fresh fseq and a valid CRC, one after each
// switch and one before the first —: the passive's Duplicates equals the
// number injected, the dialer's stays 0. No carrier ends with
// protocol_violation. The session runs on dedicated carriers
// (CheapSubflow), whose rows count every frame they drop;
// TestPacketExactlyOnceAcrossSwitchesMux_L39 is the same run on rendr mux
// trunks.
func TestPacketExactlyOnceAcrossSwitches_L39(t *testing.T) { exactlyOnceAcrossSwitches(t, false) }

// TestPacketExactlyOnceAcrossSwitchesMux_L39 is the L39 run above on the
// default path, every carrier a view of a rendr mux trunk (M3-D2). Only the
// accounting of the network's duplicates changes: a view's final
// CarrierStatus row is settled at the view's Done, while its trunk may
// still read and drop late duplicates after it (per-view datagram counters
// on a shared trunk, a known limitation), so the carriers' fseq drops are
// read trunk-wide from each Runtime's Status.Datagram.Dropped. The
// exactly-once oracle — Duplicates equal to the injected ones on the
// passive and 0 on the dialer, every datagram intact and at most once — is
// unchanged.
func TestPacketExactlyOnceAcrossSwitchesMux_L39(t *testing.T) { exactlyOnceAcrossSwitches(t, true) }

func exactlyOnceAcrossSwitches(t *testing.T, mux bool) {
	synctest.Test(t, func(t *testing.T) {
		ov := testhooks.Overrides{
			ProbeInterval: 50 * time.Millisecond, ProbeFresh: time.Second, ProbeBackoffMax: 200 * time.Millisecond,
			SelectorDwell: 200 * time.Millisecond, SelectorCooldown: time.Second,
		}
		w := newWorld(t, worldOpts{ov: ov, dcfg: noDialWait(), tap: true}, "a", "b", "c")
		for i, l := range w.links {
			one := []time.Duration{2 * time.Millisecond, 20 * time.Millisecond, 25 * time.Millisecond}[i]
			for _, d := range []rendrtest.Dir{rendrtest.Up, rendrtest.Down} {
				l.SetDelay(d, one, time.Millisecond)
				l.SetDuplicate(d, 0.05)
				l.SetReorder(d, 0.10, 3*time.Millisecond)
			}
		}
		cs := make([]rendr.Carrier, len(w.links))
		for i, l := range w.links {
			// Dedicated: the session's own carriers, whose CarrierStatus.Dropped
			// counts every duplicate frame they read (M3-D2; a view's final
			// row is settled at its own Done, while a MUX trunk may still
			// read the network's late duplicates after it).
			c := w.dgCarrier(l, 1400)
			c.Props.CheapSubflow = !mux
			cs[i] = c
		}
		dc, pc := w.open(w.peer(cs...), rendr.DialOptions{})
		if act, ok := activeOf(dc.Status()); !ok || act.Name != "a" {
			t.Fatalf("the session did not start on a: %+v", dc.Status().Carriers)
		}
		if m := w.d.Status().Mux; mux != (m.Carriers > 0) {
			t.Fatalf("mux %v: the dialer's Mux %+v (stimulus)", mux, m)
		}

		const n = 1000
		start := time.Now()
		r := readPackets(pc, 10)
		back := readPackets(dc, 11)
		wr := writePackets(dc, 10, 0, n, 15*time.Millisecond, nil)
		wb := writePackets(pc, 11, 0, n, 15*time.Millisecond, nil)

		injected := 0
		inject := func(step string) {
			t.Helper()
			act, ok := activeOf(dc.Status())
			if !ok {
				t.Fatalf("%s: no active carrier", step)
			}
			tap := w.taps.dialerTap(act.ID)
			if tap == nil {
				t.Fatalf("%s: no tap for the active carrier %d", step, act.ID)
			}
			tap.arm()
			injected++
			waitFor(t, time.Second, step+": the injected duplicate counted", func() bool {
				return pc.Status().Packet.Duplicates == uint64(injected)
			})
		}
		active := func() string {
			act, _ := activeOf(dc.Status())
			return act.Name
		}
		var deaths []time.Time
		death := func(name string) {
			t.Helper()
			m := dc.Status().Migrations
			w.link(name).Refuse(true)
			w.link(name).Kill()
			deaths = append(deaths, time.Now())
			waitFor(t, 3*time.Second, "the death switch away from "+name, func() bool {
				a := active()
				return a != "" && a != name && dc.Status().Migrations.Death == m.Death+1
			})
			time.Sleep(300 * time.Millisecond)
			inject("after the death of " + name)
		}
		quality := func(to string, open ...string) {
			t.Helper()
			m := dc.Status().Migrations
			for _, name := range open {
				w.link(name).Refuse(false)
			}
			waitFor(t, 5*time.Second, "the quality switch to "+to, func() bool {
				return active() == to && dc.Status().Migrations.Quality == m.Quality+1
			})
			time.Sleep(300 * time.Millisecond)
			inject("after the quality switch to " + to)
		}

		time.Sleep(time.Second)
		inject("before the first switch")
		death("a")           // S1: a → b
		quality("a", "a")    // S2: b → a
		death("a")           // S3: a → b
		x := active()        // b, the better of b and c
		death(x)             // S4: b → c
		quality("a", "a", x) // S5: c → a
		if wr.accepted.Load() >= n || wb.accepted.Load() >= n {
			t.Fatalf("load: the writers finished before the last switch (%d, %d of %d)", wr.accepted.Load(), wb.accepted.Load(), n)
		}
		switchedAt := time.Now()
		wr.wait(t, time.Minute, "dialer → passive")
		wb.wait(t, time.Minute, "passive → dialer")
		time.Sleep(time.Second)
		for _, l := range w.links {
			for _, d := range []rendrtest.Dir{rendrtest.Up, rendrtest.Down} {
				l.SetDuplicate(d, 0)
			}
		}
		time.Sleep(500 * time.Millisecond)
		synctest.Wait()

		ds, ps := dc.Status(), pc.Status()
		// Stimulus: five switches of both kinds, counted alike on both ends.
		if m := ds.Migrations; m.Death != 3 || m.Quality != 2 || m.Explicit != 0 {
			t.Fatalf("dialer migrations %+v, want 3 deaths and 2 quality switches", m)
		}
		if ps.Migrations != ds.Migrations {
			t.Fatalf("passive migrations %+v ≠ dialer %+v", ps.Migrations, ds.Migrations)
		}
		// Integrity and load: at most once, intact, nearly all delivered.
		rr, br := r.check(t, "dialer → passive"), back.check(t, "passive → dialer")
		for _, x := range []struct {
			what string
			res  rendrtest.PacketResult
			got  uint64
		}{{"dialer → passive", rr, ps.Packet.Received}, {"passive → dialer", br, ds.Packet.Received}} {
			if x.res.Unique < n*90/100 || x.got != x.res.Unique {
				t.Fatalf("%s: %d unique datagrams returned, Received %d (of %d sent): %+v", x.what, x.res.Unique, x.got, n, x.res)
			}
			// The last datagram is written long after the last death: a loss
			// at the tail (which Missing does not list) is never near one.
			if x.res.Highest != n-1 {
				t.Fatalf("%s: the highest seq returned is %d, want %d: the tail was lost away from every death", x.what, x.res.Highest, n-1)
			}
			// Losses only at deaths: datagram k is written at start + k·15 ms;
			// a missing one was written while a dead carrier was being
			// replaced (its handshake may cost one RelRTOInit when the
			// response overtakes the PREFACE_ACK, M2-D20).
			for _, m := range x.res.Missing {
				for k := m.From; k <= m.To; k++ {
					at := start.Add(time.Duration(k) * 15 * time.Millisecond)
					near := false
					for _, d := range deaths {
						near = near || (!at.Before(d.Add(-50*time.Millisecond)) && at.Before(d.Add(500*time.Millisecond)))
					}
					if !near {
						t.Fatalf("%s: datagram %d (written at +%v) is missing away from every death %v", x.what, k, at.Sub(start), deaths)
					}
				}
			}
		}
		for _, x := range []struct {
			what     string
			accepted int64
			c        *rendr.PacketCounters
		}{{"dialer", wr.accepted.Load(), ds.Packet}, {"passive", wb.accepted.Load(), ps.Packet}} {
			if sum := x.c.Sent + x.c.DropQueue + x.c.DropAge + x.c.DropNoPath + x.c.DropTooLarge; sum != uint64(x.accepted) || x.accepted != n {
				t.Fatalf("%s: accepted %d ≠ %d = %+v", x.what, x.accepted, sum, *x.c)
			}
		}
		// Session-level duplicates: exactly the injected ones, all on the
		// passive; the taps confirm each was written.
		dt, pt := w.taps.tapTotals(true), w.taps.tapTotals(false)
		if dt.Injected != injected || ps.Packet.Duplicates != uint64(injected) || ds.Packet.Duplicates != 0 {
			t.Fatalf("Duplicates passive %d, dialer %d; injected %d (taps %d)", ps.Packet.Duplicates, ds.Packet.Duplicates, injected, dt.Injected)
		}
		// Network duplicates: dropped by the carriers' fseq windows.
		var dupl, lost uint64
		for _, l := range w.links {
			st := l.Stats().Session
			dupl, lost = dupl+st.Duplicated, lost+st.Lost
		}
		dDrop, pDrop := dropped(ds), dropped(ps)
		if mux {
			// Trunk-wide (see TestPacketExactlyOnceAcrossSwitchesMux_L39):
			// each Runtime's datagram drops, the late duplicates a trunk
			// read after a view's Done included.
			dDrop, pDrop = w.d.Status().Datagram.Dropped, w.p.Status().Datagram.Dropped
		}
		t.Logf("links: Duplicated %d, Lost %d; taps: dialer %+v, passive %+v; Dropped dialer %d, passive %d; injected %d; migrations %+v; last switch %v before the writers ended",
			dupl, lost, dt, pt, dDrop, pDrop, injected, ds.Migrations, time.Since(switchedAt))
		if dupl < 50 {
			t.Fatalf("stimulus: the links duplicated only %d session datagrams", dupl)
		}
		// Every duplicate the links made was read as one (by a started
		// carrier, or as a copy of a handshake-time datagram, which may also
		// be a verbatim protocol repeat) unless the link lost it.
		seen, early := uint64(dt.DupDgrams+pt.DupDgrams), uint64(dt.EarlyCopies+pt.EarlyCopies)
		if seen > dupl || seen+early+lost < dupl {
			t.Fatalf("the taps saw %d duplicate datagrams and %d early copies; the links made %d and lost %d", seen, early, dupl, lost)
		}
		if dDrop < uint64(dt.DupFrames) || pDrop < uint64(pt.DupFrames) {
			t.Fatalf("Dropped dialer %d < %d or passive %d < %d duplicate frames: a duplicate reached the session", dDrop, dt.DupFrames, pDrop, pt.DupFrames)
		}
		for _, st := range []rendr.SessionStatus{ds, ps} {
			for _, c := range st.Carriers {
				if c.DeathCause == rendr.CauseProtocolViolation {
					t.Fatalf("%v carrier %d: protocol_violation %q", st.Role, c.ID, c.DeathDetail)
				}
			}
		}
		w.noViolation()

		dc.Close()
		r.wait(t, 5*time.Second, "dialer → passive")
		back.waitClosed(t, 5*time.Second, "passive → dialer")
		pc.Close()
		waitDone(t, 5*time.Second, dc, pc)
		w.close()
	})
}
