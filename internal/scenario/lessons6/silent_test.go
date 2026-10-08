package lessons6

import (
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestPacketSilentDrop_L24: a G4-pkt miniature (M2 design B1.3 at reduced
// scale). Two datagram links of 20 ms RTT, a packet session (selector and
// bond) with 1,000 datagrams/s up and 100/s down; after a 10-s warm-up the
// link of the carrier that carries data (selector: the active one; bond:
// the member whose Tx grew most) silently drops everything in both
// directions — no error, no RST, no ICMP. Each end detects the death by
// itself (cause ping_timeout or write_stall, never a carrier error) and
// arrivals of datagrams written after the drop resume within 5 s on both
// directions (PacketPing + D + 2·RTT ≈ 4.05 s, PA-13); every datagram lost
// was written between the drop (less the one-way delay) and that resume;
// every datagram that arrived is intact and arrived once. The application
// sees no error and no io.EOF until the clean end.
func TestPacketSilentDrop_L24(t *testing.T) {
	for _, mode := range []rendr.Mode{rendr.ModeSelector, rendr.ModeBond} {
		t.Run(mode.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { silentDrop(t, mode) })
		})
	}
}

func silentDrop(t *testing.T, mode rendr.Mode) {
	const oneWay = 10 * time.Millisecond
	w := newWorld(t, worldOpts{}, "u1", "u2")
	for _, l := range w.links {
		for _, d := range bothDirs {
			l.SetDelay(d, oneWay, 0)
		}
	}
	dc, pc := w.open(w.peer(dgCarrier(w.links[0], 1400), dgCarrier(w.links[1], 1400)), rendr.DialOptions{Mode: mode})
	if mode == rendr.ModeBond {
		waitFor(t, 10*time.Second, "both members on both ends", func() bool {
			return len(liveOf(dc.Status())) == 2 && len(liveOf(pc.Status())) == 2
		})
	}
	up := startFlow(dc, pc, flowCfg{seed: 1, burst: 2, pace: 2 * time.Millisecond})
	down := startFlow(pc, dc, flowCfg{seed: 2, pace: 10 * time.Millisecond})

	// Warm-up, then pick the carrier that carries data.
	time.Sleep(9 * time.Second)
	tx0 := map[rendr.CarrierID]uint64{}
	for _, c := range liveOf(dc.Status()) {
		tx0[c.ID] = c.TxBytes
	}
	time.Sleep(time.Second)
	var victim rendr.CarrierStatus
	if mode == rendr.ModeSelector {
		var ok bool
		if victim, ok = activeOf(dc.Status()); !ok {
			t.Fatalf("no active carrier: %+v", dc.Status())
		}
	} else {
		var best uint64
		for _, c := range liveOf(dc.Status()) {
			if g := c.TxBytes - tx0[c.ID]; g >= best {
				victim, best = c, g
			}
		}
	}
	if g := victim.TxBytes - tx0[victim.ID]; g == 0 {
		t.Fatalf("stimulus: the picked carrier %+v carried no data in the last second", victim)
	}
	var vl *rendrtest.DatagramLink
	for _, l := range w.links {
		if l.Name() == victim.Name {
			vl = l
		}
	}
	if _, ok := carrierOf(pc.Status(), victim.ID); !ok {
		t.Fatalf("the passive does not know carrier %d: %+v", victim.ID, pc.Status().Carriers)
	}
	lost0 := vl.Stats().Session.Lost
	migr0 := dc.Status().Migrations

	// DROP: both directions, silently, to the end of the observation.
	drop := time.Now()
	for _, d := range bothDirs {
		vl.Blackhole(d, true)
	}
	time.Sleep(20 * time.Second)
	end := time.Now()
	// Stop writing and let every datagram in flight land before losses are
	// counted.
	up.halt(t, "dialer → passive")
	down.halt(t, "passive → dialer")
	settle(t, dc, pc, up, down)
	if vl.Stats().Session.Lost == lost0 {
		t.Fatalf("stimulus: the blackhole of %s dropped nothing", vl.Name())
	}

	// Each end declared the victim dead by itself, by a silence cause,
	// within the bound.
	var died [2]time.Time
	for i, side := range []struct {
		c   *rendr.PacketConn
		evs *eventLog
	}{{dc, w.dev}, {pc, w.pev}} {
		who := [2]string{"dialer", "passive"}[i]
		cs, ok := carrierOf(side.c.Status(), victim.ID)
		if !ok || cs.State != rendr.CarrierDead {
			t.Fatalf("%s: carrier %d is %+v (found %v), want dead", who, victim.ID, cs, ok)
		}
		if cs.DeathCause != rendr.CausePingTimeout && cs.DeathCause != rendr.CauseWriteStall {
			t.Fatalf("%s: carrier %d died of %v (%q), want ping_timeout or write_stall", who, victim.ID, cs.DeathCause, cs.DeathDetail)
		}
		ev, ok := side.evs.downOf(victim.ID)
		if !ok || ev.Cause != cs.DeathCause {
			t.Fatalf("%s: CarrierDown of %d: %+v (found %v)", who, victim.ID, ev, ok)
		}
		if d := ev.Time.Sub(drop); d > 5*time.Second {
			t.Fatalf("%s: carrier %d declared dead %v after the drop, want within 5 s", who, victim.ID, d)
		}
		died[i] = ev.Time
		t.Logf("%s: carrier %d (%s) dead +%v: %v %q", who, victim.ID, victim.Name, ev.Time.Sub(drop), cs.DeathCause, cs.DeathDetail)
	}
	if mode == rendr.ModeSelector {
		if m := dc.Status().Migrations; m.Death != migr0.Death+1 || m.Quality != migr0.Quality {
			t.Fatalf("dialer migrations %+v → %+v, want exactly one death migration", migr0, m)
		}
		if a, ok := activeOf(dc.Status()); !ok || a.Name == victim.Name {
			t.Fatalf("the active carrier after the drop is %+v (found %v), want the other link's", a, ok)
		}
	}

	// Recovery and losses, per direction.
	// A datagram is lost only when it was written between the drop (less
	// the one-way delay: those already on their way) and the later of the
	// resume and its sender's verdict on the victim (a bond's survivor
	// resumes at once; the victim's share is lost until its death).
	for _, d := range []struct {
		name   string
		f      *flow
		sender time.Time
	}{{"dialer → passive", up, died[0]}, {"passive → dialer", down, died[1]}} {
		resume := d.f.firstArrivalWrittenFrom(drop)
		if resume.IsZero() || resume.Sub(drop) > 5*time.Second {
			t.Fatalf("%s: the first datagram written after the drop arrived at +%v, want within 5 s", d.name, resume.Sub(drop))
		}
		until := resume
		if d.sender.After(until) {
			until = d.sender
		}
		ls := d.f.losses()
		for _, l := range ls {
			if l.wrote.Before(drop.Add(-oneWay)) || l.wrote.After(until) {
				t.Fatalf("%s: seq %d, written at %+v of the drop, was lost: outside [drop − %v, +%v]",
					d.name, l.seq, l.wrote.Sub(drop), oneWay, until.Sub(drop))
			}
		}
		if gap := d.f.maxArrivalGap(resume, end); gap > time.Second {
			t.Fatalf("%s: an arrival gap of %v after the resume", d.name, gap)
		}
		if n := d.f.writtenBetween(drop.Add(-oneWay), resume); mode == rendr.ModeSelector && len(ls) == 0 && n > 0 {
			t.Fatalf("%s: stimulus: no datagram lost although %d were written into the drop", d.name, n)
		}
		t.Logf("%s: resume +%v, %d lost of %d accepted, all written in [+%v, +%v]", d.name, resume.Sub(drop), len(ls),
			d.f.accepted.Load(), firstWrote(ls).Sub(drop), lastWrote(ls).Sub(drop))
	}
	if len(up.losses()) == 0 {
		t.Fatalf("stimulus: the drop cost no datagram dialer → passive")
	}

	// Remove the drop, end cleanly; the load was reached and intact.
	for _, d := range bothDirs {
		vl.Blackhole(d, false)
	}
	if n := up.accepted.Load(); n < 29000 {
		t.Fatalf("load: %d datagrams dialer → passive, want about 30,000", n)
	}
	if n := down.accepted.Load(); n < 2900 {
		t.Fatalf("load: %d datagrams passive → dialer, want about 3,000", n)
	}
	for _, s := range []*rendr.PacketConn{dc, pc} {
		if c := s.Status().Packet; c.Duplicates+c.DropLate+c.DropRecvQueue != 0 {
			t.Fatalf("%v: receive drops %+v", s.Status().Role, *c)
		}
	}
	endPair(t, dc, pc, up, down)
	w.noViolation()
	w.close()
}

// firstWrote and lastWrote return the earliest and latest write time of
// ls (zero when empty).
func firstWrote(ls []loss) time.Time {
	if len(ls) == 0 {
		return time.Time{}
	}
	return ls[0].wrote
}

func lastWrote(ls []loss) time.Time {
	if len(ls) == 0 {
		return time.Time{}
	}
	return ls[len(ls)-1].wrote
}
