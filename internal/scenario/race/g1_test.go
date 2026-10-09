package race

import (
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
)

// TestG1RaceMiniature: gold/G1-race (M3 design B1.1, §A11.2) at reduced
// scale: the zero Config on both ends, two Links p1 and p2 of 20 ms RTT
// (10 ms one way) shaped to 25 MiB/s each, one race session (Peer order
// p1, p2; both members listed on both ends before the transfer), B → A
// 256 MiB of PRNG data (64 MiB under -race on the same timeline, 6.25 MiB/s
// per link, R1-11). The control is the same transfer without kills in its
// own bubble; it must not migrate.
//
// Stimulus: when the dialer (A, the receiver) has received 30 %, 50 % and
// 70 % of the bytes, the member of p1, p2, p1 (F42) is hard-killed —
// Link.Kill closes both ends of the link's carriers, the RST of the gold.
// Each kill must end a session carrier (Link Stats Session.Killed), and
// before each kill both ends list two members and the member that replaced
// the previous victim has carried data again (B → A TxBytes on the
// passive).
//
// PASS (plan:725–730, B1.1, R1-18): every byte verified and io.EOF at the
// end (the SHA-256 of the gold); one Conn and no application error; no
// zero-delivery gap above 500 ms at the receiving application; the
// transfer time at most 1.10 × the control's; at least 3 death migrations
// on the sending side B (M3-D34: each kill hits a member with in-flight
// data); Rejoins + 3 on the dialer; each killed carrier's death record on
// both ends with transport_error; a clean end with io.EOF on both ends and
// nothing left after Runtime.Close.
func TestG1RaceMiniature(t *testing.T) {
	size := int64(256 << 20)
	if raceEnabled {
		size = 64 << 20 // R1-11: the same 10.24-s timeline at 6.25 MiB/s per link
	}
	rate := float64(size) / g1Span.Seconds()
	var control time.Duration
	t.Run("control", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) { control = g1(t, size, rate, false) })
	})
	if control == 0 {
		t.Fatal("the control run failed")
	}
	t.Run("kills", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			took := g1(t, size, rate, true)
			if limit := control * 110 / 100; took > limit {
				t.Fatalf("the transfer took %v, more than 1.10 × the control's %v", took, control)
			}
			t.Logf("transfer %v against the control's %v (%.3f×)", took, control, float64(took)/float64(control))
		})
	})
}

// g1Span is the transfer time of the miniature at the link rate.
const g1Span = 10240 * time.Millisecond

// g1 runs one transfer and returns its time (from the start of the sender
// to the receiver's last bytes).
func g1(t *testing.T, size int64, rate float64, kills bool) time.Duration {
	w := newWorld(t, worldOpts{}, linkSpec{name: "p1", oneWay: 10 * time.Millisecond, rate: rate},
		linkSpec{name: "p2", oneWay: 10 * time.Millisecond, rate: rate})
	dc, pc := w.open(w.peer("p1", "p2"), rendr.DialOptions{Mode: rendr.ModeRace})
	waitFor(t, 10*time.Second, "two race members on both ends", func() bool { return twoMembers(dc, pc) })

	down := startReceiver(dc, 1, size) // B → A, the gold's direction
	up := startReceiver(pc, 2, 0)
	tx := w.startSender(pc, 1, size, 0)
	w.startSender(dc, 2, 0, 0) // A has nothing to send: its FIN only

	type kill struct {
		at   time.Time
		name string
		id   rendr.CarrierID
	}
	var ks []kill
	var rejoins0 uint64
	if kills {
		rejoins0 = dc.Status().Rejoins
		for i, frac := range []float64{0.3, 0.5, 0.7} {
			name := [2]string{"p1", "p2"}[i%2]
			waitFor(t, time.Minute, fmt.Sprintf("%.0f %% of the bytes", 100*frac), func() bool {
				return down.got.Load() >= int64(frac*float64(size))
			})
			ds, ps := dc.Status(), pc.Status()
			if len(liveOf(ds)) != 2 || len(liveOf(ps)) != 2 {
				t.Fatalf("kill %d: not two members on both ends at %.0f %% (the previous victim did not rejoin): dialer %+v, passive %+v",
					i, 100*frac, liveOf(ds), liveOf(ps))
			}
			if i > 0 {
				prev, _ := liveNamed(ds, ks[i-1].name)
				if pm, ok := carrierOf(ps, prev.ID); !ok || pm.TxBytes == 0 {
					t.Fatalf("kill %d: the member %d that replaced %s's victim carried no data before the next kill: %+v", i, prev.ID, ks[i-1].name, pm)
				}
			}
			m, _ := liveNamed(ds, name)
			l := w.link(name)
			before := l.Stats().Session.Killed
			at := time.Now()
			l.Kill()
			if l.Stats().Session.Killed == before {
				t.Fatalf("stimulus: kill %d of %s ended no session carrier", i, name)
			}
			ks = append(ks, kill{at, name, m.ID})
		}
	}
	down.wait(t, 2*time.Minute)
	up.wait(t, time.Minute)
	tx.wait(t, time.Minute)
	took := down.end().Sub(tx.start)
	if g, at := down.maxGap(tx.start, down.end()); g > 500*time.Millisecond {
		t.Fatalf("a zero-delivery gap of %v at +%v, want ≤ 500 ms", g, at.Sub(tx.start))
	}
	ds, ps := dc.Status(), pc.Status()
	if !kills {
		if ds.Migrations != (rendr.MigrationCounts{}) || ps.Migrations != (rendr.MigrationCounts{}) {
			t.Fatalf("the control migrated: dialer %+v, passive %+v", ds.Migrations, ps.Migrations)
		}
	} else {
		if ps.Migrations.Death < 3 {
			t.Fatalf("the sending side B counted %+v migrations for 3 kills, want Death ≥ 3 (M3-D34)", ps.Migrations)
		}
		if r := ds.Rejoins - rejoins0; r < 3 {
			t.Fatalf("Rejoins rose by %d for 3 kills, want ≥ 3", r)
		}
		for i, k := range ks {
			for j, l := range []*eventLog{w.dev, w.pev} {
				ev, ok := l.downOf(k.id)
				if !ok || ev.Cause != rendr.CauseTransportError {
					t.Fatalf("kill %d: the %s's death record of %d: %+v (found %v), want transport_error", i, side(j), k.id, ev, ok)
				}
			}
			t.Logf("kill %d of %s's member %d at +%v", i, k.name, k.id, k.at.Sub(tx.start))
		}
		t.Logf("migrations: dialer %+v, passive %+v; Rejoins +%d", ds.Migrations, ps.Migrations, ds.Rejoins-rejoins0)
	}
	if ds.DeliveredBytes != uint64(size) || ps.TxBytes != uint64(size) || ps.Race.CopyBytes == 0 || ds.DupBytes == 0 {
		t.Fatalf("accounting: passive TxBytes %d, CopyBytes %d; dialer DeliveredBytes %d, DupBytes %d; want %d, > 0, %d, > 0",
			ps.TxBytes, ps.Race.CopyBytes, ds.DeliveredBytes, ds.DupBytes, size, size)
	}
	t.Logf("%d MiB in %v (%.2f MiB/s); copies %d B, duplicates %d B", size>>20, took, float64(size)/(1<<20)/took.Seconds(),
		ps.Race.CopyBytes, ds.DupBytes)
	finish(t, dc, pc)
	w.noViolation()
	w.close()
	return took
}
