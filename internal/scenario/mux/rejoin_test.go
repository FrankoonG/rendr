package mux

import (
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
)

// TestMuxLateWaiterRejoinsAfterOlderDialFails_L22 (M3 design §A5.5
// M3-D18, B1.9 G5; L22 — a rejoin follows the path's restoration within
// one dial's time): the ordering behind TestMuxG5Miniature_L22's late
// rejoins (one bond session listed its new member of a up to 7.8 s after
// T_rm, past G5Bound, in about 3 % of the runs at -cpu 4), made
// deterministic. Links b and a of 20 ms RTT, Peer order b then a, the
// dialer's DialTimeout 5 s and its backoff jitter fixed at its maximum
// (testhooks Rand = 1, so the n-th consecutive failure waits
// min(0.5 s · 2ⁿ, 4 s) × 1.2).
//
// Stimulus: bond session S2 loses its member of a (a is blackholed and
// killed) and redials a alone into the outage, one hung dial after the
// other, until its slot has failed four times (its next backoff is the
// cap, 4.8 s). Bond session S1 opens 17 s after S2's first redial; its
// member slot of a waits for S2's dial in flight (Coalesced grows). Just
// after the next dial starts (at 20 s) a is killed again: both slots
// fail, S1's after one or two failures (it redials within 1.2 s, into the
// outage: a dial that hangs until its DialTimeout), S2's at the cap. At
// 22 s the path is restored (T_rm). S2's next attempt starts at 24.8 s,
// after T_rm, and finds S1's hung dial in flight, which started before
// T_rm and before S2's attempt.
//
// PASS: both bond sessions list a live new member of a within DialTimeout
// + 1 s of T_rm (G5Bound's T_gap and slack; S2's own dial at 24.8 s, the
// dedicated case, would attach at once). Observed before the fix in
// internal/carrier/pool.go: S2 took the failure of S1's older dial as
// its own and backed off 4.8 s from its own start, listing its member
// 7.6 s after T_rm. Integrity: S1's and S2's exchanges after the rejoin
// are verified both ways.
func TestMuxLateWaiterRejoinsAfterOlderDialFails_L22(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const oneWay, dialTimeout = 10 * time.Millisecond, 5 * time.Second
		w := newWorld(t, worldOpts{dcfg: rendr.Config{DialTimeout: dialTimeout}, dov: testhooks.Overrides{Rand: func() float64 { return 1 }}},
			linkSpec{name: "b", oneWay: oneWay, rate: 25 << 20}, linkSpec{name: "a", oneWay: oneWay, rate: 25 << 20})
		peer := w.peer("b", "a")
		s2 := w.open(peer, "S2", rendr.ModeBond)
		waitFor(t, 10*time.Second, "S2's two members", func() bool { return len(liveOf(s2.d.Status())) == 2 })
		la := w.link("a")
		m, _ := liveNamed(s2.d.Status(), "a")

		// S2 loses its member of a and redials into the outage.
		la.SetBlackhole(true)
		killed := time.Now()
		if la.Kill(); la.Stats().Session.Killed == 0 {
			t.Fatal("stimulus: the kill of a ended no session carrier")
		}
		waitFor(t, 5*time.Second, "S2's redial of a", func() bool { return w.dialsIn("a", killed, time.Now().Add(time.Nanosecond)) > 0 })
		d := time.Now()
		if cs, ok := carrierOf(s2.d.Status(), m.ID); !ok || cs.State != rendr.CarrierDead {
			t.Fatalf("stimulus: S2's member %d of a is %+v after the kill, want dead", m.ID, cs)
		}

		// S1 opens during S2's fourth hung dial and waits for it.
		sleepUntil(d.Add(17 * time.Second))
		if n := w.dialsIn("a", killed, time.Now()); n != 4 {
			t.Fatalf("premise: %d session factory calls on a in the 17 s after S2's redial, want 4 (one hung dial per DialTimeout)", n)
		}
		co := w.d.Status().Mux.Coalesced
		s1 := w.open(peer, "S1", rendr.ModeBond)
		waitFor(t, time.Second, "S1's member slot of a waiting for S2's dial", func() bool { return w.d.Status().Mux.Coalesced > co })

		// The second kill, just after the dial of 20 s started.
		sleepUntil(d.Add(20*time.Second + 100*time.Millisecond))
		if n := w.dialsIn("a", d.Add(19*time.Second), time.Now()); n != 1 {
			t.Fatalf("premise: %d session factory calls on a around 20 s, want 1 (the sessions' coalesced redial)", n)
		}
		kill2 := time.Now()
		if la.Kill(); la.Stats().Session.Killed == 0 {
			t.Fatal("stimulus: the second kill of a ended no carrier")
		}

		// T_rm: the path works again; a dial sent before it still hangs.
		sleepUntil(d.Add(22 * time.Second))
		late := w.dialsIn("a", kill2, time.Now())
		rm := time.Now()
		la.SetBlackhole(false)
		if late != 1 {
			t.Fatalf("premise: %d session factory calls on a from the second kill to T_rm, want 1 (S1's dial into the outage)", late)
		}

		listed := map[string]time.Duration{}
		waitFor(t, dialTimeout+time.Second, "both bond sessions' new member of a", func() bool {
			for _, s := range []pair{s1, s2} {
				if _, ok := listed[s.key]; ok {
					continue
				}
				if _, ok := liveNamed(s.d.Status(), "a"); ok {
					listed[s.key] = time.Since(rm)
				}
			}
			return len(listed) == 2
		})
		t.Logf("new members of a listed at T_rm + %v; session factory calls on a from T_rm: %d", listed, w.dialsIn("a", rm, time.Now()))
		for i, s := range []pair{s1, s2} {
			if err := echo(s, 64<<10, uint64(10*i+1)); err != nil {
				t.Fatalf("integrity: %v", err)
			}
		}
		closeAll(t, []pair{s1, s2})
		w.noViolation()
		w.close()
	})
}

// TestMuxCoalescedRedialsKeepTheBackoff_L20 (M3 design §A5.5 M3-D18; L20
// — a dead path is not redialled faster than its backoff): the bound of
// the retry above. Links b and a of 20 ms RTT, the dialer's DialTimeout
// 1 s (below the backoff cap, so a slot waits after a hung dial) and its
// jitter fixed at its maximum (testhooks Rand = 1). Stimulus: a is
// blackholed and killed; both bond sessions' members of a die together
// and redial a into the outage for 20 s, waiting for one coalesced dial
// at a time (Coalesced grows). PASS: at most as many session factory
// calls on a as one slot's own schedule makes in those 20 s — starts at
// 0, 1, 2.2, 4.6, 9.4, 14.2 and 19 s (each attempt hangs its 1 s, then
// min(0.5 s · 2ⁿ, 4 s) × 1.2 from its start), 7 calls — and at least 4.
// A waiter that began with the claimant's dial shares its timeout (its
// own wait times out with it); only a dial older than the waiter's
// attempt is not its own failure. A guard row for that retry: it held
// before the retry existed, and the retry must add no dial to it.
func TestMuxCoalescedRedialsKeepTheBackoff_L20(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const oneWay = 10 * time.Millisecond
		w := newWorld(t, worldOpts{dcfg: rendr.Config{DialTimeout: time.Second}, dov: testhooks.Overrides{Rand: func() float64 { return 1 }}},
			linkSpec{name: "b", oneWay: oneWay, rate: 25 << 20}, linkSpec{name: "a", oneWay: oneWay, rate: 25 << 20})
		if adj := w.d.Status().ConfigAdjustments; len(adj) != 0 {
			t.Fatalf("the dialer's Config was adjusted: %q", adj)
		}
		peer := w.peer("b", "a")
		ps := []pair{w.open(peer, "S1", rendr.ModeBond), w.open(peer, "S2", rendr.ModeBond)}
		for _, s := range ps {
			waitFor(t, 10*time.Second, s.key+"'s two members", func() bool { return len(liveOf(s.d.Status())) == 2 })
		}
		la := w.link("a")
		la.SetBlackhole(true)
		killed := time.Now()
		co := w.d.Status().Mux.Coalesced
		if la.Kill(); la.Stats().Session.Killed == 0 {
			t.Fatal("stimulus: the kill of a ended no session carrier")
		}
		waitFor(t, 5*time.Second, "the redial of a", func() bool { return w.dialsIn("a", killed, time.Now().Add(time.Nanosecond)) > 0 })
		d := time.Now()
		sleepUntil(d.Add(20 * time.Second))
		calls := w.dialsIn("a", killed, time.Now())
		t.Logf("%d session factory calls on a in the 20 s after the first redial; Coalesced %d → %d", calls, co, w.d.Status().Mux.Coalesced)
		if w.d.Status().Mux.Coalesced == co {
			t.Fatal("premise: no attempt waited for the other session's dial of a")
		}
		if calls < 4 || calls > 7 {
			t.Fatalf("%d session factory calls on a in 20 s of outage, want 4–7 (one slot's backoff schedule: 7 starts)", calls)
		}
		la.SetBlackhole(false)
		for _, s := range ps {
			waitFor(t, 10*time.Second, s.key+"'s new member of a", func() bool { _, ok := liveNamed(s.d.Status(), "a"); return ok })
		}
		for i, s := range ps {
			if err := echo(s, 64<<10, uint64(10*i+1)); err != nil {
				t.Fatalf("integrity: %v", err)
			}
		}
		closeAll(t, ps)
		w.noViolation()
		w.close()
	})
}
