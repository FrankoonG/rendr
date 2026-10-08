package lessons6

import (
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
)

// TestPacketPrefersDatagram_L28: a Peer with a stream factory s (configured
// first, and the faster path: 2 ms one way) and a datagram factory u (10 ms
// one way). A packet session ranks datagram factories first (M2-D47): it
// opens on u although s is first in the configuration and faster. UDP is
// then blocked (u's link drops everything, both directions): the carrier
// dies of silence and the session fails over to s (one death migration);
// datagrams keep flowing. When u is unblocked, its probes measure it again
// and the selector's class-up (M2-D48) moves the session back to u — a
// Quality migration, although u's RTT is five times s's (a lower class
// qualifies without Band and Floor), but only once its evidence is Fresh
// and after Dwell. Every datagram that arrived is intact and arrived once;
// losses are confined to the UDP failure.
func TestPacketPrefersDatagram_L28(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{}, "u")
		lu := w.links[0]
		for _, d := range bothDirs {
			lu.SetDelay(d, 10*time.Millisecond, 0)
		}
		ls := w.addStreamLink("s", 0)
		ls.SetDelay(2*time.Millisecond, 0)
		dc, pc := w.open(w.peer(stCarrier(ls), dgCarrier(lu, 1400)), rendr.DialOptions{})
		a, ok := activeOf(dc.Status())
		if !ok || a.Name != "u" || a.Kind != rendr.KindDatagram {
			t.Fatalf("the packet session opened on %+v (found %v), want the datagram factory u", a, ok)
		}
		if mp := dc.MaxPayload(); mp != 1400-25 {
			t.Fatalf("MaxPayload %d, want %d (the datagram factory's budget − 25)", mp, 1400-25)
		}
		first := a.ID
		up := startFlow(dc, pc, flowCfg{seed: 11, pace: 5 * time.Millisecond})
		down := startFlow(pc, dc, flowCfg{seed: 12, pace: 20 * time.Millisecond})
		time.Sleep(5 * time.Second)
		if c, _ := carrierOf(dc.Status(), first); c.TxBytes == 0 || c.RxBytes == 0 {
			t.Fatalf("load: u carried nothing: %+v", c)
		}

		// UDP blocked.
		lost0 := lu.Stats().All.Lost
		blocked := time.Now()
		for _, d := range bothDirs {
			lu.Blackhole(d, true)
		}
		waitFor(t, 10*time.Second, "the failover to s", func() bool {
			a, ok := activeOf(dc.Status())
			return ok && a.Name == "s"
		})
		failover := time.Now()
		a, _ = activeOf(dc.Status())
		if a.Kind != rendr.KindStream {
			t.Fatalf("the fallback carrier %+v is not a stream carrier", a)
		}
		if c, _ := carrierOf(dc.Status(), first); c.State != rendr.CarrierDead ||
			(c.DeathCause != rendr.CausePingTimeout && c.DeathCause != rendr.CauseWriteStall) {
			t.Fatalf("u's carrier after the block: %+v, want dead of silence", c)
		}
		if m := dc.Status().Migrations; m.Death != 1 || m.Quality != 0 {
			t.Fatalf("migrations after the failover: %+v, want one death migration", m)
		}
		if lu.Stats().All.Lost == lost0 {
			t.Fatalf("stimulus: the block dropped nothing")
		}
		time.Sleep(20 * time.Second)
		if a, _ := activeOf(dc.Status()); a.Name != "s" {
			t.Fatalf("while UDP is blocked the session left s for %+v", a)
		}
		if n := up.firstArrivalWrittenFrom(failover.Add(time.Second)); n.IsZero() {
			t.Fatalf("load: nothing arrived over s")
		}
		probes0 := lu.Stats().Probe.Delivered

		// UDP unblocked: back to u by a quality switch.
		unblocked := time.Now()
		for _, d := range bothDirs {
			lu.Blackhole(d, false)
		}
		waitFor(t, 60*time.Second, "the return to u", func() bool {
			a, ok := activeOf(dc.Status())
			return ok && a.Name == "u"
		})
		back := time.Now()
		a, _ = activeOf(dc.Status())
		if a.Kind != rendr.KindDatagram || a.ID == first {
			t.Fatalf("the session returned to %+v, want a new datagram carrier of u", a)
		}
		if m := dc.Status().Migrations; m.Death != 1 || m.Quality != 1 {
			t.Fatalf("migrations after the return: %+v, want one death and one quality migration", m)
		}
		// Events reach the log through the Runtime's event worker, after
		// the state Status shows: let it drain before reading the log.
		synctest.Wait()
		quality := 0
		for _, ev := range w.dev.of(rendr.EventMigration) {
			if ev.Cause == rendr.CauseQuality {
				quality++
				if ev.To != a.ID {
					t.Fatalf("the quality migration went to %d, want u's carrier %d: %+v", ev.To, a.ID, ev)
				}
			}
		}
		if quality != 1 {
			t.Fatalf("%d quality migration events, want 1", quality)
		}
		if lu.Stats().Probe.Delivered == probes0 {
			t.Fatalf("stimulus: no probe datagram crossed u after the unblock")
		}
		// Not before u's evidence is Fresh and Dwell passed: at least one
		// probe interval plus Dwell (3 s) after the unblock.
		if d := back.Sub(unblocked); d < 3*time.Second {
			t.Fatalf("the session returned %v after the unblock, before Dwell", d)
		}
		t.Logf("blocked → failover %v; unblocked → back on u %v", failover.Sub(blocked), back.Sub(unblocked))
		time.Sleep(5 * time.Second)
		if c, _ := carrierOf(dc.Status(), a.ID); c.TxBytes == 0 || c.RxBytes == 0 {
			t.Fatalf("load: the new u carrier carried nothing: %+v", c)
		}

		up.halt(t, "dialer → passive")
		down.halt(t, "passive → dialer")
		settle(t, dc, pc, up, down)
		for _, d := range []struct {
			name string
			f    *flow
		}{{"dialer → passive", up}, {"passive → dialer", down}} {
			for _, l := range d.f.losses() {
				if l.wrote.Before(blocked.Add(-10*time.Millisecond)) || l.wrote.After(failover) {
					t.Fatalf("%s: seq %d written at +%v of the block was lost: outside the UDP failure (failover +%v)",
						d.name, l.seq, l.wrote.Sub(blocked), failover.Sub(blocked))
				}
			}
			t.Logf("%s: %d lost of %d", d.name, len(d.f.losses()), d.f.accepted.Load())
		}
		endPair(t, dc, pc, up, down)
		w.noViolation()
		w.close()
	})
}
