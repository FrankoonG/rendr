package lessons3

import (
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// selectorTimings are short quality-switch timings for the L22 scenarios
// (unclamped testhooks values, W15): a fresh, clearly better path wins
// after half a second of dwell. Cooldown is set by each test.
func selectorTimings(cooldown time.Duration) testhooks.Overrides {
	return testhooks.Overrides{
		SelectorDwell:    500 * time.Millisecond,
		SelectorCooldown: cooldown,
		ProbeInterval:    100 * time.Millisecond,
		ProbeFresh:       time.Second,
	}
}

// TestJoiningCarrierGetsNoData_L22: a carrier joins the session only when
// its JOIN_ACK is handled (L22: "承载在 JOIN_ACK 确认后才进入活跃集"). The
// dialer's handling of B's JOIN_ACK is held (Hooks.DialResult) while data
// flows both ways: the dialer reports B as joining, B carries no DATA in
// either direction (frame captures armed on B's link stay silent and the
// passive's B moves no byte), and the session keeps running over A. Once
// the result is released B joins: it becomes a bond member, or the
// selector's quality-switch target, and DATA appears on it both ways.
//
// The bond variant moves bulk over rate-limited paths, more than A alone
// can carry, so a member B would carry DATA both ways at once (demand
// within one member's capacity goes to the fastest member only, §4.11).
// The selector variant moves application-limited data, so the self-load
// guard (§8) leaves the probe evidence that triggers the switch unloaded.
func TestJoiningCarrierGetsNoData_L22(t *testing.T) {
	t.Run("bond", func(t *testing.T) { joiningNoData(t, rendr.ModeBond) })
	t.Run("selector", func(t *testing.T) { joiningNoData(t, rendr.ModeSelector) })
}

func joiningNoData(t *testing.T, mode rendr.Mode) {
	synctest.Test(t, func(t *testing.T) {
		g := newHoldGate()
		calls := 0
		g.arm(func(uint32) bool { calls++; return calls == 2 }) // the OPEN's result passes, B's JOIN result is held
		dov := selectorTimings(time.Hour)
		dov.Hooks = &testhooks.Hooks{DialResult: g.hook}
		pov := selectorTimings(time.Hour)
		links := []linkSpec{{name: "a", delay: 5 * time.Millisecond}, {name: "b", delay: 10 * time.Millisecond}}
		fo := flowOpts{chunk: 16 * kib, gap: 10 * time.Millisecond}
		if mode == rendr.ModeBond {
			links[0].rate, links[1].rate = 2*mib, 2*mib
			fo = flowOpts{}
		}
		w := newWorld(t, worldConfig{links: links, dov: &dov, pov: &pov}, g)
		a, b := w.link("a"), w.link("b")
		dc, pc := w.open(w.peer(), mode)
		first := mustCarrier(t, dc, "a")
		up := w.startFlow("up", dc, pc, 221, fo)
		down := w.startFlow("down", pc, dc, 222, fo)
		if mode == rendr.ModeSelector {
			// a degrades: b becomes the clearly better path and the
			// selector JOINs it after the dwell.
			time.Sleep(time.Second)
			a.SetDelay(40*time.Millisecond, 0)
		}
		var bid uint32
		select {
		case bid = <-g.held:
		case <-time.After(10 * time.Second):
			t.Fatal("no JOIN of B within 10 s")
		}
		// While B's JOIN_ACK is held: frames of B's link (B and b's probe
		// carrier, which never carries DATA) are watched for DATA.
		upData := b.CaptureNextFrame(rendrtest.Up, rendrtest.FrameData)
		downData := b.CaptureNextFrame(rendrtest.Down, rendrtest.FrameData)
		heldAt := time.Now()
		txA := mustCarrier(t, dc, "a").TxBytes
		time.Sleep(time.Second)
		cs, ok := carrierByID(dc, rendr.CarrierID(bid))
		if !ok || cs.State != rendr.CarrierJoining || cs.Name != "b" {
			t.Fatalf("held B %d on the dialer: %+v (found %v), want joining on b", bid, cs, ok)
		}
		if ps, ok := carrierByID(pc, rendr.CarrierID(bid)); !ok || ps.TxBytes != 0 || ps.RxBytes != 0 || ps.State == rendr.CarrierActive {
			t.Fatalf("passive's B while joining: %+v (found %v), want adopted with no DATA", ps, ok)
		}
		select {
		case <-upData:
			t.Fatal("DATA towards the passive on B's link while B was joining")
		case <-downData:
			t.Fatal("DATA towards the dialer on B's link while B was joining")
		default:
		}
		jc := sessionCarriers(b)
		if len(jc) != 1 || jc[0].First != rendrtest.FrameJoin || jc[0].Up+jc[0].Down > 512 {
			t.Fatalf("B's link session carriers while joining: %+v, want B's handshake bytes only", jc)
		}
		if now := mustCarrier(t, dc, "a"); now.ID != first.ID || now.TxBytes <= txA {
			t.Fatalf("A while B joins: %+v (before: %d bytes sent), want A carrying data", now, txA)
		}
		if mode == rendr.ModeSelector {
			if act := mustActive(t, dc, "dialer"); act.ID != first.ID {
				t.Fatalf("selector routed to %d while its target was joining, want A %d", act.ID, first.ID)
			}
		}

		mark := w.dev.mark()
		g.open()
		w.dev.wait(t, mark, time.Second, "CarrierUp of B", func(e rendr.Event) bool {
			return e.Kind == rendr.EventCarrierUp && e.Carrier == rendr.CarrierID(bid)
		})
		timer := time.After(2 * time.Second)
		for _, ch := range []<-chan []byte{upData, downData} {
			select {
			case <-ch:
			case <-timer:
				t.Fatalf("no DATA on B's link within 2 s after B joined (session stats %+v)", b.Stats().Session)
			}
		}
		// The link counts a capture right after handing it over.
		waitFor(t, time.Second, "B's link counting both captures as session frames", func() bool {
			return b.Stats().Session.FramesCaptured == 2
		})
		cs, _ = carrierByID(dc, rendr.CarrierID(bid))
		switch mode {
		case rendr.ModeBond:
			if cs.State != rendr.CarrierMember {
				t.Fatalf("bond B after its JOIN_ACK: %+v, want a member", cs)
			}
			wantMigrations(t, "dialer", dc, rendr.MigrationCounts{})
		case rendr.ModeSelector:
			if cs.State != rendr.CarrierActive {
				t.Fatalf("selector B after its JOIN_ACK: %+v, want active", cs)
			}
			wantMigrations(t, "dialer", dc, rendr.MigrationCounts{Quality: 1})
			waitFor(t, time.Second, "the passive following the quality SCHED", func() bool {
				return pc.Status().Migrations == rendr.MigrationCounts{Quality: 1}
			})
		}
		time.Sleep(500 * time.Millisecond)
		up.stop()
		down.stop()
		up.wait(t, 10*time.Second)
		down.wait(t, 10*time.Second)
		if d := time.Since(heldAt); up.recvd.Load() < mib || down.recvd.Load() < mib {
			t.Fatalf("load: %d / %d bytes carried in %v, want both flows running throughout", up.recvd.Load(), down.recvd.Load(), d)
		}
		if n := b.Stats().Session.Bytes; n < 64*kib {
			t.Fatalf("B carried %d bytes after it joined", n)
		}
		finishSession(t, dc, pc)
		w.finish()
	})
}

// mustCarrier returns the dialer's live carrier of factory name.
func mustCarrier(t testing.TB, dc *rendr.Conn, name string) rendr.CarrierStatus {
	t.Helper()
	for _, cs := range dc.Status().Carriers {
		if cs.Name == name && cs.State != rendr.CarrierDead && cs.State != rendr.CarrierJoining {
			return cs
		}
	}
	t.Fatalf("no live carrier of %q: %+v", name, dc.Status().Carriers)
	return rendr.CarrierStatus{}
}

// TestSuccessorDiesFallsBackToPredecessor_L22: a successor that dies right
// after the planned switch to it was confirmed leaves no stall without an
// active carrier (L22: "前任保留到后继被确认为止"; C7). A selector switches
// by quality from A (path a, degraded) to B (path b), and B is killed the
// moment the switch is published:
//
//   - predecessor-retiring: everything A carried is still unacknowledged
//     (the passive application has not read it; ACK = delivered, §4.6), so
//     Retire was not called on A: A itself becomes active again in B's
//     death step — no new carrier, no no-path episode — and its bytes
//     arrive once the application reads.
//   - predecessor-retired: the session was idle at the switch, so Retire
//     was called on A at once and A is never a fallback again (Conn.Retire
//     is irreversible): the failover race dials a new carrier of A's
//     factory, which becomes active within one round trip.
//
// The dialer counts the quality switch and B's death; the passive ends up
// routing over the dialer's active carrier.
func TestSuccessorDiesFallsBackToPredecessor_L22(t *testing.T) {
	t.Run("predecessor-retiring", func(t *testing.T) { successorDies(t, false, false) })
	t.Run("predecessor-retired", func(t *testing.T) { successorDies(t, true, false) })
}

// TestSuccessorDeathCountedOnBothEnds_L22: the scenarios of
// TestSuccessorDiesFallsBackToPredecessor_L22, checking that both ends
// count the same selector migrations (design §7.6: the passive counts from
// the SCHED cause bits, "both ends therefore count the same selector
// migrations"; §0.2). The dialer counts the quality switch to B and B's
// death. The passive counts a SCHED only when the carrier it names becomes
// its sender, which B never does there:
//
//   - predecessor-retired: the passive applies the quality SCHED, but B is
//     already dead on the passive by then, so only the death SCHED (naming
//     the new carrier of a) counts.
//   - predecessor-retiring: the death SCHED is published in the same
//     instant as the quality SCHED and supersedes it before it is sent;
//     the passive's sender goes from A to A, and nothing counts.
//
// It fails on the current code (reported to the integrator).
func TestSuccessorDeathCountedOnBothEnds_L22(t *testing.T) {
	t.Run("predecessor-retiring", func(t *testing.T) { successorDies(t, false, true) })
	t.Run("predecessor-retired", func(t *testing.T) { successorDies(t, true, true) })
}

// successorDies runs one TestSuccessorDiesFallsBackToPredecessor_L22
// scenario; bothEnds adds the both-ends migration count check.
func successorDies(t *testing.T, retired, bothEnds bool) {
	synctest.Test(t, func(t *testing.T) {
		ov := selectorTimings(time.Hour)  // one quality switch only
		ov.RetireGrace = 30 * time.Second // A's retirement waits for its acknowledgements
		w := newWorld(t, worldConfig{
			links: []linkSpec{{name: "a", delay: 5 * time.Millisecond}, {name: "b", delay: 10 * time.Millisecond}},
			dov:   &ov,
		})
		a, b := w.link("a"), w.link("b")
		dc, pc := w.open(w.peer(), rendr.ModeSelector)
		pred := mustActive(t, dc, "dialer")
		if pred.Name != "a" {
			t.Fatalf("initial active %+v, want a carrier of a", pred)
		}
		read := make(chan struct{}) // the passive application reads once closed
		var held *flow
		if retired {
			close(read)
			warm := w.startFlow("warm-up", dc, pc, 230, flowOpts{n: 256 * kib, keepOpen: true})
			warm.wait(t, 5*time.Second)
			waitFor(t, time.Second, "everything acknowledged", func() bool {
				st := dc.Status()
				return st.AckedBytes == st.TxBytes
			})
		} else {
			held = w.startFlow("held", dc, pc, 231, flowOpts{n: mib, readGate: read})
			waitFor(t, 5*time.Second, "1 MiB sent and unread", func() bool {
				return mustCarrier(t, dc, "a").TxBytes >= mib
			})
			if st := dc.Status(); st.AckedBytes != 0 {
				t.Fatalf("%d bytes acknowledged while the passive application did not read", st.AckedBytes)
			}
		}

		mark := w.dev.mark()
		a.SetDelay(40*time.Millisecond, 0) // b becomes the clearly better path
		q := w.dev.wait(t, mark, 10*time.Second, "quality switch", isKind(rendr.EventMigration, dc.ID()))
		killed := b.Kill() // the successor dies right after its confirmation
		if q.Cause != rendr.CauseQuality || q.From != pred.ID || killed < 1 {
			t.Fatalf("migration %+v (killed %d carriers of b), want a quality switch away from A %d", q, killed, pred.ID)
		}
		d := w.dev.wait(t, mark, 2*time.Second, "death migration", func(e rendr.Event) bool {
			return e.Kind == rendr.EventMigration && e.Session == dc.ID() && isDeathCause(e.Cause)
		})
		recovered := d.Time.Sub(q.Time)
		if d.From != q.To {
			t.Fatalf("death migration %+v, want away from the successor %d", d, q.To)
		}
		act := mustActive(t, dc, "dialer")
		st := dc.Status()
		if retired {
			// Retire was called on A: a new carrier of a won the race.
			old, _ := carrierByID(dc, pred.ID)
			if act.ID == pred.ID || act.Name != "a" || act.Gen != 2 || d.To != act.ID || old.State == rendr.CarrierActive {
				t.Fatalf("after B's death: active %+v (migration to %d), predecessor %+v; want a new carrier of a", act, d.To, old)
			}
			if recovered > time.Second || st.NoPathEpisodes != 1 || len(sessionCarriers(a)) != 2 {
				t.Fatalf("recovery after %v, %d no-path episodes, %d carriers on a; want one short episode and one new carrier",
					recovered, st.NoPathEpisodes, len(sessionCarriers(a)))
			}
		} else {
			// A itself took over in B's death step.
			if act.ID != pred.ID || act.Gen != 1 || d.To != pred.ID || recovered != 0 {
				t.Fatalf("after B's death: active %+v, migration to %d after %v; want the predecessor %d at once", act, d.To, recovered, pred.ID)
			}
			if st.NoPathEpisodes != 0 || len(sessionCarriers(a)) != 1 {
				t.Fatalf("%d no-path episodes, %d carriers on a; want none and A alone", st.NoPathEpisodes, len(sessionCarriers(a)))
			}
		}
		want := rendr.MigrationCounts{Death: 1, Quality: 1}
		wantMigrations(t, "dialer", dc, want)
		waitState(t, 2*time.Second, "the passive routing as the dialer", func() (bool, string) {
			cs, ok := activeCarrier(pc)
			ps, ds := pc.Status(), dc.Status()
			return ok && cs.ID == act.ID && ps.SchedEpoch == ds.SchedEpoch,
				fmt.Sprintf("passive active %d (%v), epoch %d of %d", cs.ID, ok, ps.SchedEpoch, ds.SchedEpoch)
		})
		if bothEnds {
			// Design §7.6, §0.2: both ends count the same selector
			// migrations; the passive counts them from the SCHED causes.
			if got := pc.Status().Migrations; got != want {
				t.Errorf("passive migrations %+v, dialer %+v: the ends disagree", got, want)
			}
		}

		if retired {
			// The session runs on over the new carrier, both ways.
			up := w.startFlow("up", dc, pc, 232, flowOpts{n: 4 * mib})
			down := w.startFlow("down", pc, dc, 233, flowOpts{n: 4 * mib})
			up.wait(t, 30*time.Second)
			down.wait(t, 30*time.Second)
		} else {
			close(read)
			held.wait(t, 30*time.Second)
		}
		if st := b.Stats().Session; st.Killed < 1 {
			t.Fatalf("stimulus: b killed %d session carriers", st.Killed)
		}
		wantMigrations(t, "dialer", dc, want)
		finishSession(t, dc, pc)
		w.finish()
	})
}

// TestRecoveredPathWinsAfterDwell_L22: A (the better path a) dies and the
// selector fails over to B (path b); a stays unreachable for a while, then
// recovers. The recovered path starts from the fresh evidence of its new
// probe incarnation and must win by the quality rule alone: the switch back
// to a new carrier A' of a comes one dwell (3 s, the default) after a's
// first fresh sample, never earlier, and exactly once (L22: "A 死亡、切到
// B、A' 回归：经过 3s dwell 后切回，迁移数 +1，交付零乱序"). Both streams
// arrive intact and in order across both migrations.
func TestRecoveredPathWinsAfterDwell_L22(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const dwell = 3 * time.Second // the default Selector.Dwell
		w := newWorld(t, worldConfig{
			links: []linkSpec{{name: "a", delay: 5 * time.Millisecond}, {name: "b", delay: 20 * time.Millisecond}},
		})
		a := w.link("a")
		p := w.peer()
		dc, pc := w.open(p, rendr.ModeSelector)
		first := mustActive(t, dc, "dialer")
		if first.Name != "a" {
			t.Fatalf("initial active %+v, want a carrier of a", first)
		}
		up := w.startFlow("up", dc, pc, 241, flowOpts{chunk: 4 * kib, gap: 10 * time.Millisecond})
		down := w.startFlow("down", pc, dc, 242, flowOpts{chunk: 4 * kib, gap: 10 * time.Millisecond})
		time.Sleep(time.Second)

		mark := w.dev.mark()
		a.SetRefuse(true)
		if n := a.Kill(); n < 2 { // A and a's probe carrier
			t.Fatalf("killed %d carriers of a, want A and a's probe carrier", n)
		}
		d := w.dev.wait(t, mark, 2*time.Second, "death migration", isKind(rendr.EventMigration, dc.ID()))
		if d.From != first.ID || !isDeathCause(d.Cause) {
			t.Fatalf("migration %+v, want A's death", d)
		}
		if cs := mustActive(t, dc, "dialer"); cs.Name != "b" {
			t.Fatalf("failover to %+v, want b", cs)
		}
		time.Sleep(5 * time.Second) // a stays unreachable: its redials fail
		if fs := p.Status().Factories[0]; fs.Evidence == rendr.EvidenceFresh && !fs.Failed {
			t.Fatalf("a is fresh and not failed while unreachable: %+v", fs)
		}
		failedDials := a.Stats().DialFailures

		a.SetRefuse(false)
		// a's first fresh sample after the recovery, observed to the
		// millisecond.
		recoveredAt := time.Now()
		var fresh time.Time
		for fresh.IsZero() {
			if fs := p.Status().Factories[0]; fs.Evidence == rendr.EvidenceFresh && !fs.Failed {
				fresh = time.Now()
				break
			}
			if time.Since(recoveredAt) > 15*time.Second {
				t.Fatalf("a not fresh 15 s after its recovery: %+v", p.Status().Factories[0])
			}
			time.Sleep(time.Millisecond)
		}
		mark = w.dev.mark()
		q := w.dev.wait(t, mark, dwell+5*time.Second, "quality switch back to a", isKind(rendr.EventMigration, dc.ID()))
		after := q.Time.Sub(fresh)
		back := mustActive(t, dc, "dialer")
		if q.Cause != rendr.CauseQuality || back.Name != "a" || back.ID == first.ID || back.Gen != 2 || q.To != back.ID {
			t.Fatalf("switch %+v to %+v, want a quality switch to A' (a new carrier of a)", q, back)
		}
		if after < dwell || after > dwell+500*time.Millisecond {
			t.Fatalf("switched back %v after a's first fresh sample, want one dwell (%v) plus at most one JOIN", after, dwell)
		}
		t.Logf("switched back %v after a became fresh", after)

		time.Sleep(20 * time.Second) // no flapping
		up.stop()
		down.stop()
		up.wait(t, 10*time.Second)
		down.wait(t, 10*time.Second)
		want := rendr.MigrationCounts{Death: 1, Quality: 1}
		wantMigrations(t, "dialer", dc, want)
		wantMigrations(t, "passive", pc, want)
		if cs := mustActive(t, dc, "dialer"); cs.ID != back.ID {
			t.Fatalf("active %+v after 20 s, want A' %d", cs, back.ID)
		}
		if failedDials < 1 || up.recvd.Load() < 3*mib || down.recvd.Load() < 3*mib {
			t.Fatalf("stimulus/load: %d failed dials of a while unreachable, %d / %d bytes carried", failedDials, up.recvd.Load(), down.recvd.Load())
		}
		finishSession(t, dc, pc)
		w.finish()
	})
}
