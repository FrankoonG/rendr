package packet

import (
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestG3Miniature: gold/G3-sel and gold/G3-bond (M2 design B1.1) at
// reduced scale (§A8.3): the zero Config on both ends, two DatagramLinks of
// 20 ms RTT (u1, u2; frame budget 1223 as carrier/udp's default, Peer order
// u1, u2, so probe carriers exist), one packet session with 1000-byte
// datagrams at 2,000 per second B → A and 200 per second A → B (F3), for 60
// virtual seconds with events at t_k = 15 + 30k s (k = 0, 1: the gold's
// 30-s slots, two of its ten):
//
//   - selector, k even — quality: +60 ms on the active path's B → A delay,
//     proven by the one-way delay of the datagrams written after it (the
//     gold's RTTProbe); a quality migration of the dialer within 25 s (T_e
//     its time); the delay restored at T_e + 5 s;
//   - selector, k odd — local close: the dialer's conn of the active
//     carrier is closed under rendr (carrier.close, F10; T_e the time
//     before the command);
//   - bond, every k — member close: the member of u1 (k even) or u2 (k
//     odd), both members present beforehand.
//
// PASS (plan:742, B1.1, with the same windows and bounds): per direction
// DeliveryRatio ≥ 0.95, PacketIntegrity and NonBlockingWrite (L39, L40);
// every lost datagram written within T_e ± 200 ms (plus one 10-ms send
// slot) of an event (LossWindows, F8); per event and direction no arrival
// gap of 200 ms or more starting in [T_e − 200 ms, T_e + 2 s]
// (ArrivalInterruption, F9). Selector: each quality event exactly one
// quality migration in its slot and none from its restore to the next
// event; each close one death migration on both ends, the dialer's death
// record (transport_error) within 1 s and the passive's within DeadMax +
// 2 s = 6 s; at least one migration per event. Bond: each close one death
// migration on the dialer (M2-D44; the passive may count none, by design:
// integration 2, K6), the death records as above and the factory's rejoin
// within 2 s (a new member listed, Rejoins + 1; plan:140). One session, no
// application error, a clean end with io.EOF on both ends (F21), nothing
// left after Runtime.Close.
func TestG3Miniature(t *testing.T) {
	for _, mode := range []rendr.Mode{rendr.ModeSelector, rendr.ModeBond} {
		t.Run(mode.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { g3(t, mode) })
		})
	}
}

// Gold timing shared by the miniatures (B1.0, F8, F9, F15).
const (
	goldOneWay   = 10 * time.Millisecond // RTT 20 ms
	goldRateBA   = 2000                  // B → A datagrams per second (the miniature's 2 kpps)
	goldRateAB   = goldRateBA / 10       // A → B (F3)
	lossWindow   = 200*time.Millisecond + sendSlot
	gapWindow    = 2 * time.Second
	gapLimit     = 200 * time.Millisecond
	passiveDeath = 6 * time.Second // DeadMax + 2 s (B1.0)
	minRatio     = 0.95
)

// g3Event is one scheduled event of the run.
type g3Event struct {
	k       int
	quality bool
	slot    time.Time // t_k
	te      time.Time // T_e
	restore time.Time // quality: when the delay was restored
	victim  rendr.CarrierID
	name    string
	migr    [2]rendr.MigrationCounts // both ends' counts at t_k
	rejoins uint64                   // the dialer's Rejoins at t_k
}

func g3(t *testing.T, mode rendr.Mode) {
	const (
		window = 60 * time.Second
		first  = 15 * time.Second
		slot   = 30 * time.Second
	)
	w := newWorld(t, worldOpts{oneWay: goldOneWay}, "u1", "u2")
	dc, pc := w.open(w.peer("u1", "u2"), rendr.DialOptions{Mode: mode})
	if mode == rendr.ModeBond {
		waitFor(t, 10*time.Second, "both members on both ends", func() bool {
			return len(liveOf(dc.Status())) == 2 && len(liveOf(pc.Status())) == 2
		})
	}
	up := startFlow(dc, pc, flowCfg{name: "A → B", seed: 1, rate: goldRateAB})
	down := startFlow(pc, dc, flowCfg{name: "B → A", seed: 2, rate: goldRateBA})
	start := up.start

	var evs []*g3Event
	for k := 0; k < 2; k++ {
		sleepUntil(start.Add(first + time.Duration(k)*slot))
		ds := dc.Status()
		ev := &g3Event{k: k, quality: mode == rendr.ModeSelector && k%2 == 0, slot: time.Now(),
			migr: [2]rendr.MigrationCounts{ds.Migrations, pc.Status().Migrations}, rejoins: ds.Rejoins}
		evs = append(evs, ev)
		switch {
		case ev.quality:
			g3Quality(t, w, dc, down, ev)
		case mode == rendr.ModeSelector:
			act, ok := activeOf(ds)
			if !ok {
				t.Fatalf("event %d: no active carrier: %+v", k, ds)
			}
			ev.victim, ev.name, ev.te = act.ID, act.Name, time.Now()
			w.localClose(act.ID)
		default:
			ev.name = [2]string{"u1", "u2"}[k%2]
			if len(liveOf(ds)) != 2 {
				t.Fatalf("event %d: the bond has %d members before the close, want 2", k, len(liveOf(ds)))
			}
			m, _ := liveNamed(ds, ev.name)
			ev.victim, ev.te = m.ID, time.Now()
			w.localClose(m.ID)
			waitFor(t, 2*time.Second, "the closed member's factory to rejoin", func() bool {
				n, ok := liveNamed(dc.Status(), ev.name)
				return ok && n.ID != m.ID
			})
			t.Logf("event %d: %s's member %d closed, rejoined after %v", k, ev.name, m.ID, time.Since(ev.te))
		}
	}
	sleepUntil(start.Add(window))
	end := time.Now()
	final := [2]rendr.MigrationCounts{dc.Status().Migrations, pc.Status().Migrations}
	finalRejoins := dc.Status().Rejoins
	endClean(t, dc, pc, up, down)

	// Switches, per event.
	for i, ev := range evs {
		next, after, rejoins := end, final, finalRejoins
		if i+1 < len(evs) {
			next, after, rejoins = evs[i+1].slot, evs[i+1].migr, evs[i+1].rejoins
		}
		var d [2]rendr.MigrationCounts
		for s := range d {
			d[s] = rendr.MigrationCounts{Death: after[s].Death - ev.migr[s].Death, Quality: after[s].Quality - ev.migr[s].Quality,
				Explicit: after[s].Explicit - ev.migr[s].Explicit}
		}
		if ev.quality {
			if q := w.dev.migrations(ev.slot, ev.slot.Add(slot), isQuality); len(q) != 1 {
				t.Fatalf("event %d: %d quality migrations in its slot, want 1: %+v", ev.k, len(q), q)
			}
			if q := w.dev.migrations(ev.restore, next, isQuality); len(q) != 0 {
				t.Fatalf("event %d: a quality migration between the restore and the next event: %+v", ev.k, q)
			}
			if d[0] != (rendr.MigrationCounts{Quality: 1}) || d[1] != d[0] {
				t.Fatalf("event %d (quality): migrations rose by %+v (dialer) and %+v (passive), want one quality migration", ev.k, d[0], d[1])
			}
			continue
		}
		g3DeathRecords(t, w, ev)
		if mode == rendr.ModeSelector {
			if d[0] != (rendr.MigrationCounts{Death: 1}) || d[1] != d[0] {
				t.Fatalf("event %d (close): migrations rose by %+v (dialer) and %+v (passive), want one death migration", ev.k, d[0], d[1])
			}
			continue
		}
		if d[0] != (rendr.MigrationCounts{Death: 1}) || d[1].Quality+d[1].Explicit != 0 || d[1].Death > 1 {
			t.Fatalf("event %d (member close): migrations rose by %+v (dialer) and %+v (passive), want one dialer death migration", ev.k, d[0], d[1])
		}
		if r := rejoins - ev.rejoins; r != 1 {
			t.Fatalf("event %d (member close): Rejoins rose by %d, want 1", ev.k, r)
		}
		t.Logf("event %d (member close): passive death migrations +%d (K6)", ev.k, d[1].Death)
	}
	if m := final[0]; mode == rendr.ModeSelector && m.Death+m.Quality < uint64(len(evs)) {
		t.Fatalf("%+v migrations for %d events", m, len(evs))
	}

	// LossWindows, ArrivalInterruption, DeliveryRatio, integrity.
	for _, f := range []*flow{up, down} {
		g3Judge(t, f, evs, end)
	}
	attribution(t, w, dc, pc)
	if n := w.pendings(); n != 1 {
		t.Fatalf("the passive was offered %d PendingPackets", n)
	}
	w.noViolation()
	w.close()
}

// g3Quality raises the active path's B → A delay by 60 ms, proves the step
// by the one-way delay of the datagrams written on it, waits up to 25 s for
// the dialer's quality migration (T_e) and restores the delay at T_e + 5 s.
func g3Quality(t *testing.T, w *world, dc *rendr.PacketConn, down *flow, ev *g3Event) {
	act, ok := activeOf(dc.Status())
	if !ok {
		t.Fatalf("event %d: no active carrier", ev.k)
	}
	ev.victim, ev.name = act.ID, act.Name
	l := w.link(act.Name)
	step := time.Now()
	l.SetDelay(rendrtest.Down, goldOneWay+60*time.Millisecond, 0)
	time.Sleep(2 * time.Second)
	if ds := down.delays(step.Add(sendSlot), step.Add(time.Second)); len(ds) == 0 || ds[len(ds)/2] < goldOneWay+60*time.Millisecond {
		t.Fatalf("stimulus: event %d: B → A delays after the step on %s: median of %d is %v, want ≥ 70 ms",
			ev.k, act.Name, len(ds), median(ds))
	}
	deadline := step.Add(25 * time.Second)
	for {
		if q := w.dev.migrations(step, deadline, isQuality); len(q) > 0 {
			ev.te = q[0].Time
			if q[0].From != act.ID {
				t.Fatalf("event %d: the quality migration left %d, the stepped carrier is %d", ev.k, q[0].From, act.ID)
			}
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("event %d: a proven +60 ms step on %s without a quality switch within 25 s (B0.2 item 4): %+v",
				ev.k, act.Name, dc.Status())
		}
		time.Sleep(10 * time.Millisecond)
	}
	restore := ev.te.Add(5 * time.Second)
	if deadline.Before(restore) {
		restore = deadline
	}
	sleepUntil(restore)
	l.SetDelay(rendrtest.Down, goldOneWay, 0)
	ev.restore = time.Now()
	t.Logf("event %d: quality switch from %s after %v", ev.k, act.Name, ev.te.Sub(step))
}

// g3DeathRecords requires the closed carrier's death records: the dialer
// reports it dead with transport_error within 1 s of the close, the
// passive dead (any cause) within DeadMax + 2 s (B1.0).
func g3DeathRecords(t *testing.T, w *world, ev *g3Event) {
	t.Helper()
	dd, ok := w.dev.downOf(ev.victim)
	if !ok || dd.Cause != rendr.CauseTransportError || dd.Time.Sub(ev.te) > time.Second {
		t.Fatalf("event %d: the dialer's death record of %d: %+v (found %v), want transport_error within 1 s of %v",
			ev.k, ev.victim, dd, ok, ev.te)
	}
	pd, ok := w.pev.downOf(ev.victim)
	if !ok || pd.Time.Sub(ev.te) > passiveDeath {
		t.Fatalf("event %d: the passive's death record of %d: %+v (found %v), want within %v", ev.k, ev.victim, pd, ok, passiveDeath)
	}
	t.Logf("event %d: %s carrier %d closed; dead on the dialer +%v, on the passive +%v (%v)",
		ev.k, ev.name, ev.victim, dd.Time.Sub(ev.te), pd.Time.Sub(ev.te), pd.Cause)
}

// g3Judge applies LossWindows, ArrivalInterruption, DeliveryRatio,
// PacketIntegrity and NonBlockingWrite to one direction.
func g3Judge(t *testing.T, f *flow, evs []*g3Event, end time.Time) {
	t.Helper()
	f.integrity(t)
	f.nonBlocking(t)
	ls := f.losses()
	for _, l := range ls {
		in := false
		for _, ev := range evs {
			if !l.wrote.Before(ev.te.Add(-lossWindow)) && !l.wrote.After(ev.te.Add(lossWindow)) {
				in = true
			}
		}
		if !in {
			t.Fatalf("%s: seq %d, written at +%v, was lost outside every event's window", f.cfg.name, l.seq, l.wrote.Sub(f.start))
		}
	}
	for _, ev := range evs {
		if g, at := f.gapFrom(ev.te.Add(-200*time.Millisecond), ev.te.Add(gapWindow), end); g >= gapLimit {
			t.Fatalf("%s: event %d: an arrival gap of %v from %+v of T_e, want < %v", f.cfg.name, ev.k, g, at.Sub(ev.te), gapLimit)
		} else {
			t.Logf("%s: event %d: longest gap %v", f.cfg.name, ev.k, g)
		}
	}
	if r := f.ratio(); r < minRatio {
		t.Fatalf("%s: delivery ratio %.4f, want ≥ %v", f.cfg.name, r, minRatio)
	}
	if want := int64(0.95 * float64(f.cfg.rate) * end.Sub(f.start).Seconds()); f.accepted.Load() < want {
		t.Fatalf("load: %s: %d datagrams written, want ≥ %d", f.cfg.name, f.accepted.Load(), want)
	}
	t.Logf("%s: %d written, %d lost", f.cfg.name, f.accepted.Load(), len(ls))
}

// median returns the middle element of sorted ds (0 when empty).
func median(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	return ds[len(ds)/2]
}
