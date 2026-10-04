package carrier

import (
	"sync"
	"testing"
)

// TestGaugeLoadedNeedsBacklog (§8.2, §8.5): loaded ⇔ aggregate in-flight
// (forward unproven + reverse bound) ≥ threshold ∧ at least one carrier is
// backlogged on either side. In-flight alone (an application-limited flow
// on a slow path) never loads the gauge; neither does a backlog with little
// in flight.
func TestGaugeLoadedNeedsBacklog(t *testing.T) {
	const thr = 64 << 10
	g := NewGauge()
	check := func(step string, want bool) {
		t.Helper()
		if on, _ := g.Loaded(thr); on != want {
			t.Fatalf("%s: loaded %v, want %v", step, on, want)
		}
	}
	check("idle", false)
	g.AddInflight(90 << 10) // ≈ the app-limited 256 KiB/s × 350 ms of §8.1
	check("in-flight without backlog", false)
	g.SetBacklog(true) // carrier A backlogged
	check("in-flight and backlog", true)
	g.AddInflight(-40 << 10)
	check("backlog below the threshold", false)
	g.AddInflight(14 << 10) // exactly the threshold
	check("backlog at the threshold", true)
	g.SetBacklog(true)  // carrier B too
	g.SetBacklog(false) // A leaves
	check("one carrier still backlogged", true)
	g.SetBacklog(false) // B leaves
	check("no backlogged carrier", false)
	g.AddInflight(-64 << 10)
	if g.inflight.Load() != 0 || g.backlogged.Load() != 0 {
		t.Fatalf("residue: inflight %d backlogged %d", g.inflight.Load(), g.backlogged.Load())
	}
}

// TestGaugeEpochCatchesShortEpisode (§8.2): the epoch counts 0 → 1
// transitions of the backlogged count, so a load episode that starts and
// ends between two reads (a probe PING's commit and its PONG) is still
// visible; overlapping carriers do not add transitions; concurrent
// carriers keep the count exact.
func TestGaugeEpochCatchesShortEpisode(t *testing.T) {
	g := NewGauge()
	g.AddInflight(1 << 20)
	on0, e0 := g.Loaded(0)
	g.SetBacklog(true) // a short episode between the two reads
	g.SetBacklog(false)
	on1, e1 := g.Loaded(0)
	if on0 || on1 || e1 != e0+1 {
		t.Fatalf("short episode: loaded %v/%v, epoch %d → %d", on0, on1, e0, e1)
	}
	g.SetBacklog(true)
	g.SetBacklog(true) // overlap: 1 → 2 is not a new episode
	g.SetBacklog(false)
	g.SetBacklog(false)
	if _, e := g.Loaded(0); e != e1+1 {
		t.Fatalf("overlapping carriers: epoch %d, want %d", e, e1+1)
	}
	// 64 carriers flapping concurrently: the count returns to 0 exactly and
	// every episode start was counted at least once.
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				g.SetBacklog(true)
				g.AddInflight(1)
				g.SetBacklog(false)
				g.AddInflight(-1)
			}
		}()
	}
	wg.Wait()
	if on, e := g.Loaded(1); on || g.backlogged.Load() != 0 || g.inflight.Load() != 1<<20 || e < e1+2 {
		t.Fatalf("after concurrent carriers: loaded %v epoch %d backlogged %d inflight %d", on, e, g.backlogged.Load(), g.inflight.Load())
	}
}
