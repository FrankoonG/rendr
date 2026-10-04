package lessons4

import (
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// SCHED and routing authority (L45; design §7.5, §7.6).

// noDialWait is a dialer Config whose Dial does not wait for probe
// evidence: the first ranking is the configuration order.
func noDialWait() rendr.Config {
	return rendr.Config{Probe: rendr.ProbePolicy{DialWait: -1}}
}

// eventAt returns the first recorded event matching ok, and whether there
// was one.
func eventAt(l *eventLog, ok func(rendr.Event) bool) (rendr.Event, bool) {
	for _, ev := range l.all() {
		if ok(ev) {
			return ev, true
		}
	}
	return rendr.Event{}, false
}

// TestPassiveFollowsSchedWithinRTT_L45: the dialer is the only routing
// authority. A planned (quality) switch from A (40 ms RTT) to B (4 ms RTT)
// is published by SCHED while the passive keeps writing; the passive moves
// its reverse traffic off A as soon as the SCHED arrives — no DATA leaves
// it on A later than one RTT of the new path after the dialer's switch —
// and continues on B, counting the same quality migration; A, retired,
// stays alive until its CLOSE and the reverse stream arrives intact.
func TestPassiveFollowsSchedWithinRTT_L45(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ov := testhooks.Overrides{
			ProbeInterval: 50 * time.Millisecond, ProbeFresh: time.Second,
			SelectorDwell: 200 * time.Millisecond, SelectorCooldown: time.Second,
		}
		w := newWorld(t, worldOpts{ov: ov, dcfg: noDialWait()}, "a", "b")
		la, lb := w.link("a"), w.link("b")
		la.SetDelay(20*time.Millisecond, 0)
		lb.SetDelay(2*time.Millisecond, 0)
		dc, pc := w.open(w.peer(nil, la, lb), rendr.DialOptions{})
		act, ok := activeOf(dc.Status())
		if !ok || act.Name != "a" {
			t.Fatalf("the session did not start on a: %+v", dc.Status().Carriers)
		}
		// The passive writes 8 KiB every 2 ms (an application-limited
		// reverse stream that never loads the paths).
		const n = 16 << 20 / 4
		g := startFlow(pc, dc, n, 45, flowOpts{chunk: 8 << 10, pace: 2 * time.Millisecond, closeWrite: true, eof: true})

		// Follow the passive's DATA on A (every change of its send counter)
		// until well after the switch.
		var changes []time.Time
		var lastTx uint64
		var sw rendr.Event
		switched := false
		for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
			if c, ok := carrierOf(pc.Status(), act.ID); ok && c.TxBytes != lastTx {
				lastTx = c.TxBytes
				changes = append(changes, time.Now())
			}
			if !switched {
				sw, switched = eventAt(w.dev, func(ev rendr.Event) bool { return ev.Kind == rendr.EventMigration })
			}
			if switched && time.Since(sw.Time) > 300*time.Millisecond {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("no switch within 10 s: %+v / %+v", dc.Status(), w.peers0(t))
			}
		}
		nb, ok := carrierOf(dc.Status(), sw.To)
		if sw.From != act.ID || sw.Cause != rendr.CauseQuality || !ok || nb.Name != "b" {
			t.Fatalf("switch %+v (to %+v), want a quality switch from %d to a carrier on b", sw, nb, act.ID)
		}
		// The passive was sending on A right up to the switch (stimulus) and
		// stopped within one RTT of the new path: the SCHED copy on B (2 ms
		// one-way) moved it; the copy on A (20 ms) came far later.
		var before, lastA time.Time
		for _, at := range changes {
			if !at.After(sw.Time) {
				before = at
			}
			lastA = at
		}
		rttB := 4 * time.Millisecond
		t.Logf("dialer switched at %v; the passive's DATA on A: last %v before, last %v after it (bound: one RTT of B = %v)",
			sw.Time, sw.Time.Sub(before), lastA.Sub(sw.Time), rttB)
		if before.IsZero() || sw.Time.Sub(before) > 10*time.Millisecond || lastTx < 64<<10 {
			t.Fatalf("the passive was not sending on A at the switch (last DATA %v before it, %d bytes on A)", sw.Time.Sub(before), lastTx)
		}
		if lastA.Sub(sw.Time) > rttB {
			t.Fatalf("the passive sent DATA on A %v after the dialer's switch, want within one RTT of the new path (%v)", lastA.Sub(sw.Time), rttB)
		}
		waitFor(t, 5*time.Second, "A's retirement", func() bool {
			a, ok := carrierOf(dc.Status(), act.ID)
			return ok && a.State == rendr.CarrierDead
		})
		if a, _ := carrierOf(dc.Status(), act.ID); a.DeathCause != rendr.CauseRetired {
			t.Fatalf("A ended %v %q, want retired by its CLOSE", a.DeathCause, a.DeathDetail)
		}
		atSwitch, _ := carrierOf(pc.Status(), sw.To)
		g.wait(t, time.Minute, "reverse stream across the switch")
		after, _ := carrierOf(pc.Status(), sw.To)
		if after.TxBytes <= atSwitch.TxBytes || int64(after.TxBytes) < n/4 {
			t.Fatalf("the passive did not continue on B: %d → %d bytes", atSwitch.TxBytes, after.TxBytes)
		}
		for _, s := range []rendr.SessionStatus{dc.Status(), pc.Status()} {
			if s.Migrations != (rendr.MigrationCounts{Quality: 1}) {
				t.Fatalf("%v migrations %+v, want exactly one quality switch on both ends", s.Role, s.Migrations)
			}
		}
		if ps := w.peers0(t); ps.Factories[1].Evidence != rendr.EvidenceFresh || ps.Factories[1].Samples == 0 {
			t.Fatalf("b had no fresh evidence (stimulus): %+v", ps)
		}
		endClean(t, dc, pc)
		w.close()
	})
}

// TestStaleCloseIgnored_L45: a retirement message that arrives late never
// touches the replacement incarnation. A (factory a, 200 ms one-way) is
// the active carrier until a quality switch moves the session to B and
// retires A with CLOSE. B then dies and the failover races a new
// incarnation A' of factory a over the now fast path. A's CLOSE — still on
// its slow way — reaches the passive only after A' carries the session,
// and the passive's answering CLOSE reaches the dialer after that: both
// end A, and only A (retired, not a violation); A' stays the active carrier
// on both ends, the CLOSE counts no migration, DATA keeps flowing on A',
// and the stream arrives intact.
func TestStaleCloseIgnored_L45(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ov := testhooks.Overrides{
			ProbeInterval: 50 * time.Millisecond, ProbeFresh: time.Second,
			// A long dwell lets A learn its srtt (its drain after CLOSE is
			// then 2·srtt + 100 ms) before the one quality switch.
			SelectorDwell: 1500 * time.Millisecond, SelectorCooldown: time.Hour,
		}
		w := newWorld(t, worldOpts{ov: ov, dcfg: noDialWait()}, "a", "b")
		la, lb := w.link("a"), w.link("b")
		la.SetDelay(200*time.Millisecond, 0)
		lb.SetDelay(5*time.Millisecond, 0)
		dc, pc := w.open(w.peer(nil, la, lb), rendr.DialOptions{})
		oldA, ok := activeOf(dc.Status())
		if !ok || oldA.Name != "a" {
			t.Fatalf("the session did not start on a: %+v", dc.Status().Carriers)
		}
		var sw rendr.Event
		waitFor(t, 10*time.Second, "the quality switch to b", func() bool {
			sw, ok = eventAt(w.dev, func(ev rendr.Event) bool { return ev.Kind == rendr.EventMigration })
			return ok
		})
		if sw.From != oldA.ID || sw.Cause != rendr.CauseQuality {
			t.Fatalf("switch %+v, want quality from %d", sw, oldA.ID)
		}
		// The session is idle, so A's retirement (its CLOSE) follows the
		// switch at once; then the path of a turns fast for new bytes while
		// A's CLOSE keeps its 200 ms, and B dies.
		time.Sleep(10 * time.Millisecond)
		if a, _ := carrierOf(dc.Status(), oldA.ID); a.State != rendr.CarrierRetiring || a.SRTT == 0 {
			t.Fatalf("A after the switch: %+v, want retiring with a known srtt", a)
		}
		la.SetDelay(2*time.Millisecond, 0)
		lb.Kill()
		var newA rendr.CarrierStatus
		waitFor(t, 5*time.Second, "A' active on a", func() bool {
			var ok bool
			newA, ok = activeOf(dc.Status())
			return ok && newA.Name == "a" && newA.ID != oldA.ID
		})
		const n = 4 << 20
		f := startFlow(dc, pc, n, 451, flowOpts{chunk: 8 << 10, pace: 2 * time.Millisecond, closeWrite: true, eof: true})

		for _, side := range []struct {
			name string
			log  *eventLog
		}{{"passive", w.pev}, {"dialer", w.dev}} {
			var down rendr.Event
			waitFor(t, 5*time.Second, "A's end at the "+side.name, func() bool {
				var ok bool
				down, ok = eventAt(side.log, func(ev rendr.Event) bool { return ev.Kind == rendr.EventCarrierDown && ev.Carrier == oldA.ID })
				return ok
			})
			up, _ := eventAt(side.log, func(ev rendr.Event) bool { return ev.Kind == rendr.EventCarrierUp && ev.Carrier == newA.ID })
			t.Logf("%s: A' %d up at %v, A %d down at %v (%v)", side.name, newA.ID, up.Time, oldA.ID, down.Time, down.Cause)
			if up.Time.IsZero() || !down.Time.After(up.Time) || down.Cause != rendr.CauseRetired {
				t.Fatalf("%s: A ended %v at %v, A' attached at %v: want A retired by its CLOSE after A' (stimulus)", side.name, down.Cause, down.Time, up.Time)
			}
		}
		txAtClose, _ := carrierOf(dc.Status(), newA.ID)
		time.Sleep(100 * time.Millisecond)
		for _, s := range []rendr.SessionStatus{dc.Status(), pc.Status()} {
			if c, ok := activeOf(s); !ok || c.ID != newA.ID {
				t.Fatalf("%v: active %+v after A's stale CLOSE, want A' %d", s.Role, c, newA.ID)
			}
			if s.Migrations != (rendr.MigrationCounts{Death: 1, Quality: 1}) {
				t.Fatalf("%v migrations %+v, want the quality switch and B's death only", s.Role, s.Migrations)
			}
		}
		if c, _ := carrierOf(dc.Status(), newA.ID); c.TxBytes <= txAtClose.TxBytes {
			t.Fatalf("no DATA on A' after A's stale CLOSE: %d → %d", txAtClose.TxBytes, c.TxBytes)
		}
		if newA.Gen != oldA.Gen+1 {
			t.Fatalf("A' %+v is not the next incarnation of A %+v", newA, oldA)
		}
		f.wait(t, time.Minute, "stream across the stale CLOSE")
		endClean(t, dc, pc)
		w.close()
	})
}

// TestSchedResentUntilEcho_L45 (D6): the dialer's SCHED on the session's
// first carrier A is lost in transit. A lost frame leaves an fseq gap
// (L43), so A dies at its next frame (and only A); the dialer fails over
// to B, a slow path (200 ms RTT), publishes the routing change in a new
// SCHED and re-sends it, single-flight, every clamp(2·srtt, 50 ms, 1 s)
// until the passive echoes it. The passive receives that epoch several
// times and applies it once: both ends count one death migration, end at
// the same epoch with the echo in, and the data arrives intact.
func TestSchedResentUntilEcho_L45(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// No quality switch back to the faster path during the test: only
		// the failover publishes.
		ov := testhooks.Overrides{SelectorDwell: time.Hour, SelectorCooldown: time.Hour}
		w := newWorld(t, worldOpts{tap: true, ov: ov}, "a", "b")
		la, lb := w.link("a"), w.link("b")
		la.SetDelay(5*time.Millisecond, 0)
		lb.SetDelay(100*time.Millisecond, 0)
		res := dialAsync(w.peer(nil, la, lb), rendr.DialOptions{})
		pend := w.pending() // the OPEN crossed on a: its carrier exists
		la.DropNextFrame(rendrtest.Up, rendrtest.FrameSched)
		dc, pc := w.confirm(pend, res)
		const n = 4 << 20
		f := startFlow(dc, pc, n, 452, flowOpts{closeWrite: true, eof: true})
		waitFor(t, 10*time.Second, "the echo of the failover SCHED", func() bool {
			s := dc.Status()
			return s.Migrations.Death == 1 && s.SchedEchoed == s.SchedEpoch && s.SchedEpoch > 1
		})
		epoch := dc.Status().SchedEpoch
		f.wait(t, time.Minute, "transfer across the lost SCHED")

		if d := la.Stats().Session.FramesDropped; d != 1 {
			t.Fatalf("SCHED frames dropped: %d, want 1 (stimulus)", d)
		}
		if d := deadOf(pc.Status()); len(d) != 1 || d[0].DeathCause != rendr.CauseProtocolViolation {
			t.Fatalf("passive dead carriers %+v, want the gapped carrier (protocol_violation)", d)
		}
		copies := 0
		for _, c := range w.taps.all("b") {
			for _, e := range c.snapshot().epochs {
				if e == epoch {
					copies++
				}
			}
		}
		ds, ps := dc.Status(), pc.Status()
		t.Logf("epoch %d reached the passive %d times; dialer %d/%d, passive %d", epoch, copies, ds.SchedEpoch, ds.SchedEchoed, ps.SchedEpoch)
		if copies < 2 || copies > 8 {
			t.Fatalf("epoch %d crossed %d times, want re-sent (≥ 2) until echoed (bounded)", epoch, copies)
		}
		if ps.SchedEpoch != epoch || ps.SchedEchoed != epoch {
			t.Fatalf("passive at epoch %d, want %d", ps.SchedEpoch, epoch)
		}
		for _, s := range []rendr.SessionStatus{ds, ps} {
			if s.Migrations != (rendr.MigrationCounts{Death: 1}) {
				t.Fatalf("%v migrations %+v: the re-sent SCHED must be applied (and counted) once", s.Role, s.Migrations)
			}
		}
		if act, ok := activeOf(ds); !ok || act.Name != "b" {
			t.Fatalf("dialer active %+v, want b", ds.Carriers)
		}
		endClean(t, dc, pc)
		w.close()
	})
}

// TestBothSidesLoseActive_L45: both ends lose the active carrier A at the
// same moment while each has DATA in flight on it — "kill": the path is
// cut, both see its end at once; "silent": the path drops everything, and
// each end's own death detection fires. Neither end ends or resets the
// session: the dialer races a new carrier on B, the passive follows its
// SCHED, both replay their lost bytes, both count the same single death,
// and both streams arrive intact.
func TestBothSidesLoseActive_L45(t *testing.T) {
	for _, mode := range []string{"kill", "silent"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				n := int64(12 << 20)
				if raceEnabled {
					n = 6 << 20
				}
				w := newWorld(t, worldOpts{}, "a", "b")
				la, lb := w.link("a"), w.link("b")
				la.SetDelay(2*time.Millisecond, 0)
				lb.SetDelay(4*time.Millisecond, 0)
				for _, l := range []*rendrtest.Link{la, lb} {
					l.SetRate(8 << 20)
				}
				dc, pc := w.open(w.peer(nil, la, lb), rendr.DialOptions{})
				if act, ok := activeOf(dc.Status()); !ok || act.Name != "a" {
					t.Fatalf("the session did not start on a: %+v", dc.Status().Carriers)
				}
				f := startFlow(dc, pc, n, 453, flowOpts{closeWrite: true, eof: true})
				g := startFlow(pc, dc, n, 454, flowOpts{closeWrite: true, eof: true})
				waitFor(t, time.Minute, "30% both ways", func() bool { return f.got.Load() >= n*3/10 && g.got.Load() >= n*3/10 })
				if mode == "kill" {
					la.Kill()
				} else {
					la.SetBlackhole(true)
				}
				f.wait(t, time.Minute, "forward stream")
				g.wait(t, time.Minute, "reverse stream")
				waitFor(t, 5*time.Second, "both ends' death migration", func() bool {
					return dc.Status().Migrations.Death == 1 && pc.Status().Migrations.Death == 1
				})
				for _, s := range []rendr.SessionStatus{dc.Status(), pc.Status()} {
					act, ok := activeOf(s)
					if s.State != rendr.StateOpen || !ok || s.Migrations != (rendr.MigrationCounts{Death: 1}) || s.RetransmittedBytes == 0 {
						t.Fatalf("%v after losing A: %+v (active %+v)", s.Role, s, act)
					}
					if d := deadOf(s); len(d) != 1 {
						t.Fatalf("%v dead carriers %+v, want only A", s.Role, d)
					}
				}
				if act, _ := activeOf(dc.Status()); act.Name != "b" {
					t.Fatalf("dialer active %+v, want b", act)
				}
				st := la.Stats().Session
				if (mode == "kill" && (st.Killed != 1 || st.BufferLost == 0)) || (mode == "silent" && st.Dropped == 0) {
					t.Fatalf("no loss on a (stimulus): %+v", st)
				}
				la.SetBlackhole(false)
				endClean(t, dc, pc)
				w.close()
			})
		})
	}
}
