package race

import (
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
)

// TestG3RaceMiniature_L39_L40: gold/G3-race (M3 design B1.5, plan:740–744)
// at reduced scale: the zero Config on both ends, two DatagramLinks u1 and
// u2 of 20 ms RTT (frame budget 1223, carrier/udp's default less its flow
// header), one packet race session (both members listed on both ends
// first), 1000-byte datagrams at 10,000 per second B → A and 1,000 per
// second A → B for 90 virtual seconds (30 under -race, R1-11). Every 10 s
// the dialer's conn of a member is closed under rendr (the gold's
// carrier.close, F10), u1 and u2 in turn (8 closes; 2 under -race).
//
// PASS: per direction DeliveryRatio ≥ 0.99 (the other member carries a
// copy of every datagram), PacketIntegrity with 0 application duplicates
// (L39: copies are deduplicated) and NonBlockingWrite (L40); each receiver
// counts Duplicates ≥ 0.9 × Received (both members carried copies); the
// load: each generator wrote ≥ 95 % of its rate. Per close (B1.5): one
// death migration on the dialer (M3-D34: the member placed DGRAMs within
// PacketPing), the closed member recorded dead with transport_error by the
// dialer within 1 s and by the passive within DeadMax + 2 s, and its
// factory's rejoin within 2 s (a new member listed, Rejoins + 1). A clean
// end with io.EOF on both ends (F21) and nothing left after Runtime.Close.
func TestG3RaceMiniature_L39_L40(t *testing.T) {
	window := 90 * time.Second
	if raceEnabled {
		window = 30 * time.Second // R1-11
	}
	synctest.Test(t, func(t *testing.T) { g3(t, window) })
}

func g3(t *testing.T, window time.Duration) {
	const (
		rateBA = 10000
		rateAB = rateBA / 10
		every  = 10 * time.Second
	)
	w := newWorld(t, worldOpts{}, linkSpec{name: "u1", oneWay: 10 * time.Millisecond, dgram: true},
		linkSpec{name: "u2", oneWay: 10 * time.Millisecond, dgram: true})
	dc, pc := w.openPacket(w.peer("u1", "u2"), rendr.DialOptions{Mode: rendr.ModeRace})
	waitFor(t, 10*time.Second, "two race members on both ends", func() bool { return twoMembers(dc, pc) })
	up := w.startFlow(dc, pc, flowCfg{name: "A → B", seed: 1, rate: rateAB})
	down := w.startFlow(pc, dc, flowCfg{name: "B → A", seed: 2, rate: rateBA})
	start := up.start

	type closeEv struct {
		at     time.Time
		name   string
		id     rendr.CarrierID
		death  uint64 // the dialer's Death migrations before
		rejoin uint64 // the dialer's Rejoins before
	}
	var evs []closeEv
	for k := 1; time.Duration(k)*every < window; k++ {
		sleepUntil(start.Add(time.Duration(k) * every))
		name := [2]string{"u1", "u2"}[(k-1)%2]
		ds := dc.Status()
		if len(liveOf(ds)) != 2 || len(liveOf(pc.Status())) != 2 {
			t.Fatalf("close %d: not two members on both ends: dialer %+v, passive %+v", k, liveOf(ds), liveOf(pc.Status()))
		}
		m, _ := liveNamed(ds, name)
		ev := closeEv{time.Now(), name, m.ID, ds.Migrations.Death, ds.Rejoins}
		w.localClose(m.ID)
		waitFor(t, 2*time.Second, "the closed member's factory to rejoin", func() bool {
			n, ok := liveNamed(dc.Status(), name)
			return ok && n.ID != m.ID
		})
		t.Logf("close %d: %s's member %d closed at +%v, rejoined after %v", k, name, m.ID, ev.at.Sub(start), time.Since(ev.at))
		evs = append(evs, ev)
	}
	sleepUntil(start.Add(window))
	end := time.Now()
	finalDeath, finalRejoins := dc.Status().Migrations.Death, dc.Status().Rejoins
	endClean(t, dc, pc, up, down)

	for i, ev := range evs {
		death, rejoins := finalDeath, finalRejoins
		if i+1 < len(evs) {
			death, rejoins = evs[i+1].death, evs[i+1].rejoin
		}
		if d := death - ev.death; d != 1 {
			t.Fatalf("close %d of %s: the dialer's death migrations rose by %d, want 1 (M3-D34)", i, ev.name, d)
		}
		if r := rejoins - ev.rejoin; r != 1 {
			t.Fatalf("close %d of %s: Rejoins rose by %d, want 1", i, ev.name, r)
		}
		dd, ok := w.dev.downOf(ev.id)
		if !ok || dd.Cause != rendr.CauseTransportError || dd.Time.Sub(ev.at) > time.Second {
			t.Fatalf("close %d: the dialer's death record of %d: %+v (found %v), want transport_error within 1 s", i, ev.id, dd, ok)
		}
		if pd, ok := w.pev.downOf(ev.id); !ok || pd.Time.Sub(ev.at) > 6*time.Second {
			t.Fatalf("close %d: the passive's death record of %d: %+v (found %v), want within DeadMax + 2 s", i, ev.id, pd, ok)
		}
	}
	ds, ps := dc.Status().Packet, pc.Status().Packet
	for _, d := range []struct {
		f   *flow
		rx  *rendr.PacketCounters
		end string
	}{{up, ps, "the passive"}, {down, ds, "the dialer"}} {
		f := d.f
		f.integrity(t)
		f.nonBlocking(t)
		if r := f.ratio(); r < 0.99 {
			t.Fatalf("%s: delivery ratio %.5f, want ≥ 0.99", f.cfg.name, r)
		}
		if want := int64(0.95 * float64(f.cfg.rate) * end.Sub(f.start).Seconds()); f.accepted.Load() < want {
			t.Fatalf("load: %s: %d datagrams written, want ≥ %d", f.cfg.name, f.accepted.Load(), want)
		}
		if float64(d.rx.Duplicates) < 0.9*float64(d.rx.Received) {
			t.Fatalf("%s: %s counted %d Duplicates for %d Received, want ≥ 0.9 × Received (the members' copies)",
				f.cfg.name, d.end, d.rx.Duplicates, d.rx.Received)
		}
		t.Logf("%s: %d written, %d lost (ratio %.5f); receiver Duplicates %d / Received %d",
			f.cfg.name, f.accepted.Load(), f.lost(), f.ratio(), d.rx.Duplicates, d.rx.Received)
	}
	t.Logf("copies placed: dialer %d, passive %d", dc.Status().Race.Copies, pc.Status().Race.Copies)
	w.noViolation()
	w.close()
}
