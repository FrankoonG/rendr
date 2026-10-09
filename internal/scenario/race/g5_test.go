package race

import (
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
)

// TestG5RaceMiniature_L22: gold/G5-race (M3 design B1.8, plan:754–765) at
// reduced scale: two Links p1 and p2 of 20 ms RTT shaped to 25 MiB/s each,
// one race session (both members listed on both ends first) with a
// continuous B → A transfer paced at 2 MiB/s (512 KiB/s under -race,
// R1-11; the gold paces at 40 Mbit/s).
//
// Stimulus: 5 s into the transfer p1 is blackholed in both directions (the
// gold's DROP of path A) for 20 s, then restored (T_rm); the transfer runs
// until T_rm + 15 s. The DROP must drop session bytes and kill the member
// (ping_timeout or write_stall, as G4).
//
// G5Bound (plan:756–759) recomputed for the miniature: a dial made through
// the blackhole "opens" and never answers, so an attempt in flight at T_rm
// hangs for its whole DialTimeout, and with DialTimeout = 5 s on the dialer
// (≥ 1.2 × RejoinBackoffMax, so the next attempt starts as the hung one
// times out, plan §3.6) T_gap = 5 s; G5Bound = T_gap + 3·RTT + S + 1 s =
// 5 s + 60 ms + 1 s + 1 s = 7.06 s, S being the 1-s Status sample.
//
// PASS (the bond criteria, plan:761, B1.8): within G5Bound of T_rm a new
// member of p1's factory is listed by the dialer and its TxBytes on the
// sending side B grow in 2 consecutive 1-s samples (L22: a rejoined
// member carries data); every byte verified and io.EOF at the end (zero
// loss, duplicate and reorder); B's RetransmittedBytes grow by at most one
// Window from T_rm (copies excluded, M3-D35); no zero-delivery gap above
// 500 ms from T_rm to the end; a clean end with io.EOF on both ends and
// nothing left after Runtime.Close.
func TestG5RaceMiniature_L22(t *testing.T) {
	rate := float64(2 << 20)
	if raceEnabled {
		rate = 512 << 10 // R1-11
	}
	synctest.Test(t, func(t *testing.T) { g5(t, rate) })
}

// G5 miniature bounds.
const (
	g5DialTimeout = 5 * time.Second
	g5Bound       = g5DialTimeout + 60*time.Millisecond + 2*time.Second
	g5Dropped     = 20 * time.Second
	g5Sample      = time.Second
	g5Window      = 8 << 20 // the default Window
)

func g5(t *testing.T, rate float64) {
	const (
		oneWay = 10 * time.Millisecond
		link   = 25 << 20
		before = 5 * time.Second
		after  = 15 * time.Second
	)
	size := int64(rate * (before + g5Dropped + after).Seconds())
	w := newWorld(t, worldOpts{dcfg: rendr.Config{DialTimeout: g5DialTimeout}},
		linkSpec{name: "p1", oneWay: oneWay, rate: link}, linkSpec{name: "p2", oneWay: oneWay, rate: link})
	dc, pc := w.open(w.peer("p1", "p2"), rendr.DialOptions{Mode: rendr.ModeRace})
	waitFor(t, 10*time.Second, "two race members on both ends", func() bool { return twoMembers(dc, pc) })
	if adj := w.d.Status().ConfigAdjustments; len(adj) != 0 {
		t.Fatalf("the dialer's Config was adjusted: %q", adj)
	}

	down := startReceiver(dc, 1, size)
	up := startReceiver(pc, 2, 0)
	tx := w.startSender(pc, 1, size, rate)
	w.startSender(dc, 2, 0, 0)

	// The DROP of p1 for 20 s.
	sleepUntil(tx.start.Add(before))
	victim, _ := liveNamed(dc.Status(), "p1")
	if pm, ok := carrierOf(pc.Status(), victim.ID); !ok || pm.TxBytes == 0 {
		t.Fatalf("stimulus: p1's member %d carried no data before the DROP: %+v", victim.ID, pm)
	}
	l := w.link("p1")
	dropped0 := l.Stats().Session.Dropped
	drop := time.Now()
	l.SetBlackhole(true)
	sleepUntil(drop.Add(g5Dropped))
	if l.Stats().Session.Dropped == dropped0 {
		t.Fatal("stimulus: the DROP of p1 dropped no session byte")
	}
	if cs, ok := carrierOf(dc.Status(), victim.ID); !ok || cs.State != rendr.CarrierDead {
		t.Fatalf("stimulus: p1's member %d is not dead after a %v DROP: %+v", victim.ID, g5Dropped, cs)
	}
	rm := time.Now()
	retx0 := pc.Status().RetransmittedBytes
	l.SetBlackhole(false)

	// The rejoin: listed within G5Bound, carrying data in 2 consecutive
	// samples.
	var joined rendr.CarrierStatus
	waitFor(t, g5Bound, "a new member of p1's factory", func() bool {
		var ok bool
		joined, ok = liveNamed(dc.Status(), "p1")
		return ok && joined.ID != victim.ID
	})
	listed := time.Now()
	var tx0 uint64
	if pm, ok := carrierOf(pc.Status(), joined.ID); ok {
		tx0 = pm.TxBytes
	}
	for k := 1; k <= 2; k++ {
		sleepUntil(listed.Add(time.Duration(k) * g5Sample))
		pm, ok := carrierOf(pc.Status(), joined.ID)
		if !ok || pm.TxBytes <= tx0 {
			t.Fatalf("the rejoined member %d's TxBytes on B did not grow in sample %d (+%v of T_rm): %d → %+v (found %v)",
				joined.ID, k, time.Since(rm), tx0, pm, ok)
		}
		tx0 = pm.TxBytes
	}
	t.Logf("rejoin: member %d of p1 listed at T_rm +%v; B's TxBytes on it %d at +%v", joined.ID, listed.Sub(rm), tx0, time.Since(rm))

	down.wait(t, 2*time.Minute)
	up.wait(t, time.Minute)
	tx.wait(t, time.Minute)
	if g, at := down.maxGap(rm, down.end()); g > 500*time.Millisecond {
		t.Fatalf("a zero-delivery gap of %v at T_rm +%v, want ≤ 500 ms from T_rm to the end", g, at.Sub(rm))
	}
	if r := pc.Status().RetransmittedBytes - retx0; r > g5Window {
		t.Fatalf("B retransmitted %d bytes from T_rm, more than one Window (%d)", r, g5Window)
	}
	droppedCause(t, w, dc, pc, victim.ID, drop)
	ds, ps := dc.Status(), pc.Status()
	t.Logf("migrations: dialer %+v, passive %+v; Rejoins %d; B retransmitted %d bytes in all; gap after T_rm %v",
		ds.Migrations, ps.Migrations, ds.Rejoins, ps.RetransmittedBytes, func() time.Duration { g, _ := down.maxGap(rm, down.end()); return g }())
	finish(t, dc, pc)
	w.noViolation()
	w.close()
}
