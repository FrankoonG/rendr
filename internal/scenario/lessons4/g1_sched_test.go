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
// its epoch advanced, which no dialer can send. The passive kills exactly
// that carrier as a protocol_violation naming SCHED; its migration
// counters and applied epoch stay as they were, no Migration event and no
// dropped event appear, and handling it allocates almost nothing (before
// the bound the passive's actor followed the count one migration and one
// event at a time under the session lock: 2^20 grew the heap by about
// 400 MiB, 2^62 never returned and blocked Read, Write and Status). The
// dialer's redial is held until those checks ran, so no legitimate
// migration interferes; then it fails over to a new carrier, both ends
// count that one death, and the session keeps delivering (SHA-256 both
// ways, before and after).
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
