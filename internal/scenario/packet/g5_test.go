package packet

import (
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestG5PktMiniature: gold/G5-pkt-sel and gold/G5-pkt-bond (M2 design
// B1.4) at reduced scale (§A8.3): B1.3's topology and workload in the
// miniature (the zero Config, two DatagramLinks p1 and p2 of 20 ms RTT,
// 1000-byte datagrams at 2,000 per second B → A and 200 per second A → B),
// streams until the end. G5Bound_pkt = T_gap + 3·RTT + S + 1 s = 4.06 s
// (F15, PA-13).
//
// Selector (the M1c G5-sel sequence; 89 s, so that the designed outage of
// the DROP stays below 5 % for DeliveryRatio, B6): (1) configuration order
// [p2, p1]; p1 made active by +20 ms on p2's B → A delay during
// DialPacket, restored, and still active after 20 s (≥ Cooldown), else the
// stimulus failed; (2) p1 dropped for 20 s from just after a PONG
// (afterPong, the worst phase; the failover to p2 judged by
// B1.3's PktRecovery and causes) and restored at T_rm; (3) at T_rm +
// 4.06 s the dialer's active carrier: on p2 (expected) its conn is closed
// under rendr (the hard kill, carrier.close: M2-D74, PA-23; T_k the time
// before it), already on p1 (the one quality switch plan:762 allows) no
// kill (E37, logged); (4) 45 s of observation, the clean end. PASS (kill
// branch): the dialer records the closed carrier dead with transport_error
// within 1 s; the new active comes from p1's factory; a datagram written
// after T_k arrives within 5 s of T_k; at most one quality switch in
// [T_rm, T_k]; after T_rm only datagrams written within T_k ± 200 ms (plus
// one send slot) are lost.
//
// Bond (90 s, as G4-pkt's miniature: B1.3's warm-up, 30 s here, comes
// first, since a bond places most datagrams on its fastest member, M2-D43,
// and loses that share until the member's death): a steady bond for 10 s;
// the path of B's member with the largest Tx growth dropped for 20 s and
// restored at T_rm; 30 s of observation; the clean end. PASS: within 4.06 s of T_rm a new member of
// the dropped factory is listed, and at the first 1-s sample that lists it
// it carries datagrams (Tx > 0 on both ends; R2-9, R1-19); no datagram
// written after T_rm is lost (plan:764).
//
// Common (plan:760–764, R1-25): B1.3's PktRecovery during the DROP and the
// dropped carrier's causes; PacketIntegrity; DeliveryRatio ≥ 0.95;
// NonBlockingWrite; no arrival gap above 500 ms in [T_rm, end] per
// direction (ArrivalInterruption, across the bond's rejoin and the
// selector's kill); no application error, a clean end with io.EOF on both
// ends; no order or retransmission check.
func TestG5PktMiniature(t *testing.T) {
	for _, mode := range []rendr.Mode{rendr.ModeSelector, rendr.ModeBond} {
		t.Run(mode.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				if mode == rendr.ModeSelector {
					g5Selector(t)
				} else {
					g5Bond(t)
				}
			})
		})
	}
}

// G5 bounds (B1.4, F15).
const (
	g5Bound      = 4060 * time.Millisecond
	g5Dropped    = 20 * time.Second
	g5Interrupt  = 500 * time.Millisecond
	g5SampleTick = time.Second // the harness samples Status every second
)

func g5Selector(t *testing.T) {
	w := newWorld(t, worldOpts{oneWay: goldOneWay}, "p1", "p2")
	p1, p2 := w.link("p1"), w.link("p2")
	// (1) p1 active: +20 ms on p2's B → A delay while the Peer's probes
	// rank the factories and DialPacket runs, then restored.
	p2.SetDelay(rendrtest.Down, goldOneWay+20*time.Millisecond, 0)
	dc, pc := w.open(w.peer("p2", "p1"), rendr.DialOptions{Mode: rendr.ModeSelector})
	p2.SetDelay(rendrtest.Down, goldOneWay, 0)
	up := startFlow(dc, pc, flowCfg{name: "A → B", seed: 1, rate: goldRateAB})
	down := startFlow(pc, dc, flowCfg{name: "B → A", seed: 2, rate: goldRateBA})
	sleepUntil(up.start.Add(20 * time.Second))
	if a, ok := activeOf(dc.Status()); !ok || a.Name != "p1" {
		t.Fatalf("stimulus: p1 is not active 20 s after the dial: %+v (found %v)", a, ok)
	}
	m0 := dc.Status().Migrations

	// (2) DROP p1 for 20 s, just after a PONG (the worst phase).
	afterPong(t, p1)
	lost0 := p1.Stats().Session.Lost
	act, _ := activeOf(dc.Status())
	drop := time.Now()
	for _, d := range bothDirs {
		p1.Blackhole(d, true)
	}
	sleepUntil(drop.Add(g5Dropped))
	rm := time.Now()
	for _, d := range bothDirs {
		p1.Blackhole(d, false)
	}
	if p1.Stats().Session.Lost == lost0 {
		t.Fatalf("stimulus: the drop of p1 lost nothing")
	}
	if a, ok := activeOf(dc.Status()); !ok || a.Name != "p2" {
		t.Fatalf("the failover did not reach p2: %+v (found %v)", a, ok)
	}

	// (3) At T_rm + 4.06 s: the hard kill of the active carrier on p2.
	sleepUntil(rm.Add(g5Bound))
	cur, ok := activeOf(dc.Status())
	if !ok {
		t.Fatalf("no active carrier at T_rm + %v: %+v", g5Bound, dc.Status())
	}
	kill := cur.Name == "p2"
	tk := time.Now()
	if kill {
		w.localClose(cur.ID)
	} else {
		t.Logf("E37 branch: p1 (%d) is already active at T_rm + %v, no kill", cur.ID, g5Bound)
	}

	// (4) Observe, end.
	sleepUntil(tk.Add(45 * time.Second))
	end := time.Now()
	endClean(t, dc, pc, up, down)

	droppedCause(t, w, dc, pc, act.ID, drop)
	if q := w.dev.migrations(rm, tk.Add(time.Nanosecond), isQuality); len(q) > 1 {
		t.Fatalf("%d quality switches in [T_rm, T_k], want ≤ 1: %+v", len(q), q)
	}
	if kill {
		dd, ok := w.dev.downOf(cur.ID)
		if !ok || dd.Cause != rendr.CauseTransportError || dd.Time.Sub(tk) > time.Second {
			t.Fatalf("the dialer's death record of the killed %d: %+v (found %v), want transport_error within 1 s", cur.ID, dd, ok)
		}
		ms := w.dev.migrations(tk, end, func(ev rendr.Event) bool { return ev.From == cur.ID })
		if len(ms) != 1 {
			t.Fatalf("%d migrations away from the killed carrier, want 1: %+v", len(ms), ms)
		}
		if to, ok := carrierOf(dc.Status(), ms[0].To); !ok || to.Name != "p1" {
			t.Fatalf("the new active after the kill is %+v (found %v), want p1's", to, ok)
		}
		t.Logf("kill: %d dead +%v, the new active %d after +%v", cur.ID, dd.Time.Sub(tk), ms[0].To, ms[0].Time.Sub(tk))
	}
	wantDeaths := uint64(1) // the drop
	if kill {
		wantDeaths++
	}
	if m := dc.Status().Migrations; m.Death-m0.Death != wantDeaths {
		t.Fatalf("dialer death migrations %+v → %+v, want one for the drop and one for the kill", m0, m)
	}
	if dm, pm := dc.Status().Migrations, pc.Status().Migrations; dm != pm {
		t.Fatalf("migration counts differ: dialer %+v, passive %+v", dm, pm)
	}

	for _, f := range []*flow{up, down} {
		pktRecovery(t, f, drop, rm, true, end)
		for _, l := range f.losses() {
			if !l.wrote.Before(rm) && (!kill || l.wrote.Before(tk.Add(-lossWindow)) || l.wrote.After(tk.Add(lossWindow))) {
				t.Fatalf("%s: seq %d, written at %+v of T_k, was lost after T_rm outside T_k ± %v", f.cfg.name, l.seq, l.wrote.Sub(tk), lossWindow)
			}
		}
		if kill {
			if a := f.firstArrivalWrittenFrom(tk); a.IsZero() || a.Sub(tk) > recoveryBound {
				t.Fatalf("%s: the first datagram written after T_k arrived at %+v, want within %v", f.cfg.name, a.Sub(tk), recoveryBound)
			}
		}
		g5Common(t, f, rm, end)
	}
	attribution(t, w, dc, pc)
	w.noViolation()
	w.close()
}

func g5Bond(t *testing.T) {
	w := newWorld(t, worldOpts{oneWay: goldOneWay}, "p1", "p2")
	dc, pc := w.open(w.peer("p1", "p2"), rendr.DialOptions{Mode: rendr.ModeBond})
	waitFor(t, 10*time.Second, "both members on both ends", func() bool {
		return len(liveOf(dc.Status())) == 2 && len(liveOf(pc.Status())) == 2
	})
	up := startFlow(dc, pc, flowCfg{name: "A → B", seed: 1, rate: goldRateAB})
	down := startFlow(pc, dc, flowCfg{name: "B → A", seed: 2, rate: goldRateBA})

	// The warm-up and a steady bond for 10 s; then the DROP of B's
	// busiest member's path.
	sleepUntil(up.start.Add(39 * time.Second))
	victim := pickDataCarrier(t, dc, pc, rendr.ModeBond)
	vl := w.link(victim.Name)
	lost0 := vl.Stats().Session.Lost
	drop := time.Now()
	for _, d := range bothDirs {
		vl.Blackhole(d, true)
	}
	sleepUntil(drop.Add(g5Dropped))
	rm := time.Now()
	for _, d := range bothDirs {
		vl.Blackhole(d, false)
	}
	if vl.Stats().Session.Lost == lost0 {
		t.Fatalf("stimulus: the drop of %s lost nothing", vl.Name())
	}

	// The rejoin: a new member of the dropped factory listed within
	// G5Bound_pkt, carrying datagrams at the first 1-s sample that lists
	// it.
	var joined rendr.CarrierStatus
	waitFor(t, g5Bound, "a new member of the dropped factory", func() bool {
		c, ok := liveNamed(dc.Status(), victim.Name)
		joined = c
		return ok && c.ID != victim.ID
	})
	listed := time.Now()
	sample := rm.Add((listed.Sub(rm)/g5SampleTick + 1) * g5SampleTick)
	sleepUntil(sample)
	dj, _ := carrierOf(dc.Status(), joined.ID)
	pj, ok := carrierOf(pc.Status(), joined.ID)
	if !ok || dj.TxBytes == 0 || pj.TxBytes == 0 {
		t.Fatalf("the rejoined member %d carries no datagrams at its first sample (+%v of T_rm): dialer %+v, passive %+v (found %v)",
			joined.ID, sample.Sub(rm), dj, pj, ok)
	}
	t.Logf("rejoin: member %d of %s listed at T_rm +%v; Tx %d (dialer), %d (passive) at +%v",
		joined.ID, victim.Name, listed.Sub(rm), dj.TxBytes, pj.TxBytes, sample.Sub(rm))

	sleepUntil(rm.Add(30 * time.Second))
	end := time.Now()
	endClean(t, dc, pc, up, down)

	droppedCause(t, w, dc, pc, victim.ID, drop)
	for _, f := range []*flow{up, down} {
		pktRecovery(t, f, drop, rm, false, end)
		for _, l := range f.losses() {
			if !l.wrote.Before(rm) {
				t.Fatalf("%s: seq %d, written at T_rm +%v, was lost", f.cfg.name, l.seq, l.wrote.Sub(rm))
			}
		}
		g5Common(t, f, rm, end)
	}
	attribution(t, w, dc, pc)
	w.noViolation()
	w.close()
}

// g5Common applies the criteria both modes share to one direction:
// ArrivalInterruption over [T_rm, end], PacketIntegrity, DeliveryRatio and
// NonBlockingWrite.
func g5Common(t *testing.T, f *flow, rm, end time.Time) {
	t.Helper()
	if g := f.maxGap(rm, end); g > g5Interrupt {
		t.Fatalf("%s: an arrival gap of %v in [T_rm, end], want ≤ %v", f.cfg.name, g, g5Interrupt)
	}
	f.integrity(t)
	f.nonBlocking(t)
	if r := f.ratio(); r < minRatio {
		t.Fatalf("%s: delivery ratio %.4f, want ≥ %v", f.cfg.name, r, minRatio)
	}
	t.Logf("%s: %d written, %d lost (ratio %.4f), longest gap after T_rm %v", f.cfg.name, f.accepted.Load(), len(f.losses()), f.ratio(), f.maxGap(rm, end))
}
