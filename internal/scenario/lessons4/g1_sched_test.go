package lessons4

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Forged SCHED counts (design §0.14 B1; L45, invariants 4 and 6). Every
// package-level identifier of this file starts with "g1".

// g1HeapBound bounds what the passive may allocate while it handles one
// forged SCHED, its carrier's death and the start of the dialer's redial
// (the handling itself is a few comparisons; before the bound the passive
// followed 2^20 claimed migrations with about 400 MiB).
const g1HeapBound = 16 << 20

// TestForgedSchedCountsKillCarrier_L45: one well-formed SCHED whose
// cumulative death count is forged (2^20, or B1's 2^62) — injected into the
// dialer → passive stream of the session's only carrier with the correct
// fseq and CRC, as a misbehaving relay could — claims more migrations than
// SCHEDs were published by its epoch, which no dialer can send. The
// passive kills exactly that carrier as a protocol_violation naming SCHED;
// its migration counters and applied epoch stay as they were, no Migration
// event and no dropped event appear, and handling it allocates almost
// nothing (before the bound the passive's actor followed the count one
// migration and one event at a time under the session lock: 2^20 grew the
// heap by about 400 MiB, 2^62 never returned and blocked Read, Write and
// Status). The dialer's redial is held until those checks ran, so no
// legitimate migration interferes; then it fails over to a new carrier,
// both ends count that one death, and the session keeps delivering
// (SHA-256 both ways, before and after).
func TestForgedSchedCountsKillCarrier_L45(t *testing.T) {
	for _, k := range []uint{20, 62} {
		t.Run(fmt.Sprintf("death=2^%d", k), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { g1ForgedSched(t, 1<<k) })
		})
	}
}

func g1ForgedSched(t *testing.T, death uint64) {
	w := newWorld(t, worldOpts{}, "a")
	l := w.link("a")
	l.SetDelay(2*time.Millisecond, 0)
	dc, pc := w.open(w.peer(nil, l), rendr.DialOptions{})
	g1Exchange(t, dc, pc, 64<<10, 4501)

	ds0, ps0 := dc.Status(), pc.Status()
	act, ok := activeOf(ps0)
	if !ok || ps0.SchedEpoch != ds0.SchedEpoch || ps0.Migrations != (rendr.MigrationCounts{}) || len(deadOf(ps0)) != 0 {
		t.Fatalf("before the forged SCHED: dialer %+v, passive %+v", ds0, ps0)
	}
	// The dialer's redial after the carrier's end hangs until released.
	l.SetDial(rendrtest.DialHang)
	var ids [wire.MaxSchedIDs]uint32
	ids[0] = uint32(act.ID)
	var p [wire.SchedFixedLen + 4]byte
	n := wire.PutSched(p[:], &wire.Sched{Epoch: ps0.SchedEpoch + 1, Death: death, N: 1, IDs: ids})

	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	injected := time.Now()
	l.InjectAfterNextFrame(rendrtest.Up, rendrtest.FramePing, rendrtest.FrameSched, uint8(wire.SchedDeath), wire.SessionHandle, p[:n])
	// The next PING of the idle carrier may be PingIdle away; poll coarsely,
	// since every Status call allocates.
	g1Until(t, 30*time.Second, "the forged SCHED handled (its carrier dead, or its epoch applied)", func() bool {
		st := pc.Status()
		return len(deadOf(st)) > 0 || st.SchedEpoch != ps0.SchedEpoch
	})
	runtime.ReadMemStats(&m1)

	ps1 := pc.Status()
	if down, ok := eventAt(w.pev, func(ev rendr.Event) bool { return ev.Kind == rendr.EventCarrierDown && ev.Carrier == act.ID }); ok {
		t.Logf("death %d: carrier %d down %v after the injection was armed (%v); %s allocated in %d mallocs meanwhile",
			death, act.ID, down.Time.Sub(injected), down.Cause, mib(int64(m1.TotalAlloc-m0.TotalAlloc)), m1.Mallocs-m0.Mallocs)
	}
	if inj := l.Stats().Session.FramesInjected; inj != 1 {
		t.Errorf("SCHED frames injected: %d, want 1 (stimulus)", inj)
	}
	if ps1.Migrations != ps0.Migrations || ps1.SchedEpoch != ps0.SchedEpoch {
		t.Errorf("passive after the forged SCHED (death %d): migrations %+v at epoch %d, want unchanged %+v at %d",
			death, ps1.Migrations, ps1.SchedEpoch, ps0.Migrations, ps0.SchedEpoch)
	}
	if grew := m1.TotalAlloc - m0.TotalAlloc; grew > g1HeapBound {
		t.Errorf("handling the forged SCHED allocated %s (%d mallocs), want at most %s",
			mib(int64(grew)), m1.Mallocs-m0.Mallocs, mib(g1HeapBound))
	}
	if evs, dropped := len(w.pev.of(rendr.EventMigration)), w.p.Status().EventsDropped; evs != 0 || dropped != 0 {
		t.Errorf("passive Migration events %d, events dropped %d; want none", evs, dropped)
	}
	if d := deadOf(ps1); len(d) != 1 || d[0].ID != act.ID || d[0].DeathCause != rendr.CauseProtocolViolation || !strings.Contains(d[0].DeathDetail, "SCHED") {
		t.Errorf("passive dead carriers %+v, want carrier %d dead of a protocol_violation naming SCHED", d, act.ID)
	}
	if t.Failed() {
		t.FailNow()
	}
	// The dialer saw the carrier end and its redial is held: no legitimate
	// migration was counted on either end yet.
	waitFor(t, 5*time.Second, "the dialer's held redial", func() bool { return l.Stats().Dials >= 2 })
	if ds, ps := dc.Status(), pc.Status(); ds.Migrations != (rendr.MigrationCounts{}) || len(deadOf(ds)) != 1 || ps.Migrations != ps0.Migrations {
		t.Fatalf("while the redial is held: dialer migrations %+v (dead %+v), passive %+v; want none", ds.Migrations, deadOf(ds), ps.Migrations)
	}

	// Release the redial: the held call fails, the next one attaches.
	l.SetDial(rendrtest.DialNormal)
	l.Release()
	waitFor(t, 30*time.Second, "the failover and the passive following it", func() bool {
		ds, ps := dc.Status(), pc.Status()
		da, dok := activeOf(ds)
		pa, pok := activeOf(ps)
		return dok && pok && da.ID == pa.ID && da.ID != act.ID && ps.SchedEpoch == ds.SchedEpoch &&
			ds.Migrations == (rendr.MigrationCounts{Death: 1}) && ps.Migrations == ds.Migrations
	})
	if evs := w.pev.of(rendr.EventMigration); len(evs) != 1 || evs[0].From != act.ID {
		t.Fatalf("passive Migration events %+v, want the one failover from %d", evs, act.ID)
	}
	if st := l.Stats(); st.Dials < 3 || st.DialFailures < 1 {
		t.Fatalf("link dials %d (failed %d), want the held redial and the one after it (stimulus)", st.Dials, st.DialFailures)
	}
	g1Exchange(t, dc, pc, 1<<20, 4502)
	endClean(t, dc, pc)
	w.close()
}

// TestForgedSchedWithinBoundNoChurn_L45: a forged SCHED that stays within
// the bound — two epochs ahead of the dialer, two explicit migrations,
// naming the active carrier, injected with the correct fseq and CRC —
// cannot be told from the dialer's own. The passive applies it and counts
// the two explicit migrations (as without the bound: nothing lowers a
// counter), and that SCHED must not decide how the dialer's later SCHEDs
// are judged. Through four failovers (the link killed under a paced flow)
// no carrier dies of a protocol violation and each failover costs one
// dial; the passive follows the dialer's deaths once its epochs passed the
// forged one; the flow and a 1 MiB exchange afterwards arrive intact.
// Measuring the bound from the newest SCHED received instead rejected
// every later SCHED of the dialer: each carrier that delivered one died,
// the dialer redialled at once, and the session churned through thousands
// of carriers while the passive stayed at the forged epoch.
func TestForgedSchedWithinBoundNoChurn_L45(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const failovers = 4
		w := newWorld(t, worldOpts{}, "a")
		l := w.link("a")
		l.SetDelay(2*time.Millisecond, 0)
		dc, pc := w.open(w.peer(nil, l), rendr.DialOptions{})
		g1Exchange(t, dc, pc, 64<<10, 4511)

		ps0 := pc.Status()
		act, ok := activeOf(ps0)
		if !ok || ps0.Migrations != (rendr.MigrationCounts{}) {
			t.Fatalf("before the forged SCHED: passive %+v", ps0)
		}
		forged := ps0.SchedEpoch + 2
		var ids [wire.MaxSchedIDs]uint32
		ids[0] = uint32(act.ID)
		var p [wire.SchedFixedLen + 4]byte
		n := wire.PutSched(p[:], &wire.Sched{Epoch: forged, Explicit: 2, N: 1, IDs: ids})
		l.InjectAfterNextFrame(rendrtest.Up, rendrtest.FramePing, rendrtest.FrameSched, uint8(wire.SchedExplicit), wire.SessionHandle, p[:n])
		waitFor(t, 30*time.Second, "the forged SCHED applied", func() bool { return pc.Status().SchedEpoch == forged })
		if ps := pc.Status(); ps.Migrations != (rendr.MigrationCounts{Explicit: 2}) || len(deadOf(ps)) != 0 {
			t.Fatalf("after the forged SCHED: passive %+v, want two explicit migrations and no dead carrier", ps)
		}

		f := startFlow(dc, pc, 512<<10, 4513, flowOpts{chunk: 8 << 10, pace: 10 * time.Millisecond})
		// wait polls cond for up to 10 s of virtual time; a timeout reports
		// both ends and the churn (protocol violations, dials).
		wait := func(what string, cond func() bool) {
			t.Helper()
			for deadline := time.Now().Add(10 * time.Second); !cond(); time.Sleep(time.Millisecond) {
				if !time.Now().Before(deadline) {
					ds, ps := dc.Status(), pc.Status()
					t.Fatalf("timed out waiting for %s: dialer %+v at epoch %d, passive %+v at epoch %d; "+
						"%d passive carriers dead of protocol_violation, %d dials; flow %d of %d bytes",
						what, ds.Migrations, ds.SchedEpoch, ps.Migrations, ps.SchedEpoch, g1Violations(w), l.Stats().Dials, f.got.Load(), f.n)
				}
			}
		}
		for i := 1; i <= failovers; i++ {
			// The flow moves 16 KiB over the current carrier first (load).
			from := f.got.Load()
			wait(fmt.Sprintf("16 KiB of the flow before failover %d", i), func() bool { return f.got.Load() >= from+16<<10 })
			prev, _ := activeOf(dc.Status())
			l.Kill()
			wait(fmt.Sprintf("failover %d", i), func() bool {
				ds := dc.Status()
				a, ok := activeOf(ds)
				return ok && a.ID != prev.ID && ds.Migrations.Death >= uint64(i)
			})
		}
		// The passive follows the dialer once the dialer's epochs passed the
		// forged one (from the third failover on).
		wait("the passive following the dialer", func() bool {
			ds, ps := dc.Status(), pc.Status()
			da, dok := activeOf(ds)
			pa, pok := activeOf(ps)
			return dok && pok && da.ID == pa.ID && ps.SchedEpoch == ds.SchedEpoch &&
				ds.Migrations == (rendr.MigrationCounts{Death: failovers}) &&
				ps.Migrations == (rendr.MigrationCounts{Death: failovers, Explicit: 2})
		})
		if got := f.got.Load(); got >= f.n {
			t.Fatalf("the paced flow ended (%d bytes) before the last failover was followed; want it across the failovers (load)", got)
		}
		f.wait(t, time.Minute, "the paced flow across the failovers")

		st := l.Stats()
		if st.Session.FramesInjected != 1 || st.Session.Killed != failovers {
			t.Errorf("SCHED frames injected %d, carriers killed %d; want 1 and %d (stimulus)", st.Session.FramesInjected, st.Session.Killed, failovers)
		}
		if v := g1Violations(w); v != 0 || st.Dials != 1+failovers || st.DialFailures != 0 {
			t.Errorf("%d passive carriers dead of protocol_violation, %d dials (%d failed); want 0 and %d (one per failover)",
				v, st.Dials, st.DialFailures, 1+failovers)
		}
		var deaths, explicit int
		for _, ev := range w.pev.of(rendr.EventMigration) {
			switch ev.Cause {
			case rendr.CauseNone:
				deaths++
			case rendr.CauseRetired:
				explicit++
			}
		}
		if deaths != failovers || explicit != 2 {
			t.Errorf("passive Migration events: %d deaths, %d explicit; want %d and 2", deaths, explicit, failovers)
		}
		if t.Failed() {
			t.FailNow()
		}
		g1Exchange(t, dc, pc, 1<<20, 4515)
		endClean(t, dc, pc)
		w.close()
	})
}

// g1Violations counts the passive's CarrierDown events for a protocol
// violation.
func g1Violations(w *world) int {
	n := 0
	for _, ev := range w.pev.of(rendr.EventCarrierDown) {
		if ev.Cause == rendr.CauseProtocolViolation {
			n++
		}
	}
	return n
}

// g1Until polls cond every 50 ms of virtual time (fewer Status calls than
// waitFor, so a heap measurement around it stays small).
func g1Until(t testing.TB, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if !time.Now().Before(deadline) {
			t.Fatalf("timed out after %v waiting for %s", within, what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// g1Exchange sends n bytes of PRNG(seed) from a to b and n bytes of
// PRNG(seed+1) from b to a at the same time; each reader's SHA-256 must
// equal its writer's.
func g1Exchange(t testing.TB, a, b net.Conn, n int64, seed uint64) {
	t.Helper()
	type sum struct {
		h   [sha256.Size]byte
		err error
	}
	send := func(c net.Conn, seed uint64, out chan<- sum) {
		h := sha256.New()
		_, err := io.CopyBuffer(c, io.TeeReader(io.LimitReader(rendrtest.PRNG(seed), n), h), make([]byte, 32<<10))
		out <- sum{[sha256.Size]byte(h.Sum(nil)), err}
	}
	recv := func(c net.Conn, out chan<- sum) {
		h := sha256.New()
		_, err := io.CopyN(h, c, n)
		out <- sum{[sha256.Size]byte(h.Sum(nil)), err}
	}
	ab, ba, ra, rb := make(chan sum, 1), make(chan sum, 1), make(chan sum, 1), make(chan sum, 1)
	go send(a, seed, ab)
	go send(b, seed+1, ba)
	go recv(b, rb)
	go recv(a, ra)
	timeout := time.After(time.Minute)
	for _, dir := range []struct {
		name     string
		sent, rx chan sum
	}{{"a → b", ab, rb}, {"b → a", ba, ra}} {
		var s, r sum
		for _, x := range []struct {
			ch  chan sum
			out *sum
		}{{dir.sent, &s}, {dir.rx, &r}} {
			select {
			case *x.out = <-x.ch:
			case <-timeout:
				t.Fatalf("%s: %d bytes not exchanged within a minute", dir.name, n)
			}
		}
		if s.err != nil || r.err != nil || !bytes.Equal(s.h[:], r.h[:]) {
			t.Fatalf("%s (%d bytes): writer %v, reader %v, SHA-256 %x → %x", dir.name, n, s.err, r.err, s.h[:8], r.h[:8])
		}
	}
}
