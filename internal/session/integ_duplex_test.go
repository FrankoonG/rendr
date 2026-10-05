package session

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestIntegDuplexFailoverNoFalseDeath_L25: bulk flows both ways over a
// selector session on path a (1 ms one way) while path b (5 ms) is unused,
// both at rate R per direction, with a 1 MiB window and the actor tests'
// death timing (DeadMin 1 s, DeadMax 2 s; the passive's own deadline is
// 10 s). Then a's passive-to-dialer direction drops everything and the
// dialer's close of a never reaches the passive: only the dialer detects
// a's death (ping_timeout); it fails over to b, and both flows go on over
// b, the passive's requeued bulk included. The replacement carrier must
// survive that load: for 3 s after the passive applied the SCHED no other
// carrier of the dialer dies (one death migration, no redial of b), and
// both directions keep moving.
//
// With both ends BUSY our PONGs leave the peer's queue in clusters (ACK
// compression). Rate samples of 5 ms over such clusters inflated the rate
// estimate, and with it the capacity (the queue ahead of every PONG on b)
// while shrinking the death deadline's inflight/rate term: before a rate
// sample spanned at least half the smoothed RTT while the peer reports
// BUSY (design §0.13 A7b, the carrier's rateSpan), b died about one second
// after the failover ("no PONG for 1s") at 384 KiB/s, 512 KiB/s, 768 KiB/s
// and 1 MiB/s and was redialled (m1c-wpsess review, finding 4). 4 MiB/s is
// a control that never showed it.
func TestIntegDuplexFailoverNoFalseDeath_L25(t *testing.T) {
	for i, rate := range []int{384 << 10, 512 << 10, 768 << 10, 1 << 20, 4 << 20} {
		t.Run(fmt.Sprintf("%dKiBps", rate>>10), func(t *testing.T) {
			integDuplexFailover(t, float64(rate), uint64(601+2*i))
		})
	}
}

// integDuplexFailover runs one rate of TestIntegDuplexFailoverNoFalseDeath_L25.
func integDuplexFailover(t *testing.T, rate float64, seed uint64) {
	synctest.Test(t, func(t *testing.T) {
		const (
			bDelay   = 5 * time.Millisecond
			passDead = 10 * time.Second
			window   = 3 * time.Second // after the passive applied SCHED{b}
		)
		w := acNewWorld(t, nil)
		defer w.teardown()
		w.b.cenv.Timing.DeadMin, w.b.cenv.Timing.DeadMax = passDead, passDead
		var lossy, mute atomic.Bool
		var swallowed atomic.Int64
		la := rendrtest.NewLink(rendrtest.LinkConfig{Name: "a", Accept: func(nc net.Conn) error {
			return w.b.accept(&wpsessLossyConn{Conn: nc, lossy: &lossy, swallowed: &swallowed})
		}})
		la.SetDelay(acLinkDelay, 0)
		la.SetRate(rate)
		w.links = append(w.links, la)
		lb := w.link("b")
		lb.SetDelay(bDelay, 0)
		lb.SetRate(rate)
		spec := w.spec(ModeSelector, la, lb)
		spec.Factories[0].Dial = func(ctx context.Context) (net.Conn, error) {
			c, err := la.Dial(ctx)
			if err != nil {
				return nil, err
			}
			return &wpsessMuteCloseConn{Conn: c, mute: &mute}, nil
		}
		a, b := w.openSpec(spec, nil)
		da := wpsessLaneOf(a, 0)
		if da == nil || wpsessLaneOf(a, 1) != nil {
			t.Fatal("setup: the selector does not run on a alone")
		}
		up := wpsessStartFlow(a, b, seed)
		defer up.once.Do(func() { close(up.stop) })
		down := wpsessStartFlow(b, a, seed+1)
		defer down.once.Do(func() { close(down.stop) })
		acWaitFor(t, 10*time.Second, "1 MiB delivered each way", func() bool {
			return b.Status().DeliveredBytes >= 1<<20 && a.Status().DeliveredBytes >= 1<<20
		})
		pa := wpsessLaneByID(b, da.id)
		if pa == nil {
			t.Fatal("setup: the passive holds no carrier of a")
		}

		// Stimulus: a's reverse direction goes silent; only the dialer
		// detects the death, fails over to b, and the passive follows.
		lossy.Store(true)
		mute.Store(true)
		epoch := a.Status().SchedEpoch
		acWaitFor(t, 5*time.Second, "the dialer's failover", func() bool { return a.Status().SchedEpoch != epoch })
		acWaitFor(t, 2*time.Second, "the passive applying the dialer's SCHED", func() bool {
			return b.Status().SchedEpoch == a.Status().SchedEpoch
		})
		applied := time.Now()
		db := wpsessLaneOf(a, 1)
		pset := wpsessSchedOf(b)
		if db == nil || !schedLists(&pset, db.id) || schedLists(&pset, da.id) || swallowed.Load() == 0 {
			t.Fatalf("passive applied %v, dialer has a carrier of b: %v, %d bytes swallowed: want SCHED{b} after a's silent death (stimulus)",
				pset.IDs[:pset.N], db != nil, swallowed.Load())
		}
		upBefore, downBefore := b.Status().DeliveredBytes, a.Status().DeliveredBytes

		time.Sleep(time.Until(applied.Add(window)))
		dst := a.Status()
		var deadA bool
		for _, c := range dst.Carriers {
			switch {
			case c.ID == da.id:
				deadA = c.State == LaneDead && c.DeathCause == carrier.CausePingTimeout
			case c.DeathCause.Death():
				t.Fatalf("the dialer's carrier %d (%s) died of %v (%q) within %v of the failover: a false death under the failover load (dialer carriers %+v)",
					c.ID, c.Name, c.DeathCause, c.DeathDetail, window, dst.Carriers)
			}
		}
		if !deadA {
			t.Fatalf("dialer carriers %+v: want a (carrier %d) dead of ping_timeout (stimulus)", dst.Carriers, da.id)
		}
		if cur := wpsessLaneOf(a, 1); cur != db || dst.MigDeath != 1 || dst.MigQuality+dst.MigExplicit != 0 {
			t.Fatalf("failover carrier %d kept: %v; dialer migrations {%d %d %d}: want the failover carrier kept and one death",
				db.id, cur == db, dst.MigDeath, dst.MigQuality, dst.MigExplicit)
		}

		// Load: both directions keep moving over b.
		upGot, downGot := b.Status().DeliveredBytes-upBefore, a.Status().DeliveredBytes-downBefore
		t.Logf("rate %.0f KiB/s: %d B up and %d B down in the %v after the passive applied the SCHED", rate/1024, upGot, downGot, window)
		if floor := uint64(rate * window.Seconds() / 4); upGot < floor || downGot < floor {
			t.Fatalf("%d B up and %d B down in %v after the failover, want at least %d B each way", upGot, downGot, window, floor)
		}

		// Integrity: every byte arrives verified, then io.EOF, both ways.
		up.finish(t, 30*time.Second)
		down.finish(t, 30*time.Second)
	})
}
