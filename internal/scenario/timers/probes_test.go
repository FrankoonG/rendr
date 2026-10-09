package timers

import (
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
)

// TestIdleSessionsParkUnderProbes (M3 design R1-22, §A8.3; M3-D42): n idle
// sessions (1,000; 250 under -race), half selector and half bond, on a
// two-factory Peer (Links a and b, default Props) whose probes sample each
// factory every ProbeInterval (2 s, the default). Every accepted probe
// sample publishes a health snapshot, and every publication rings each
// subscribed dialer session (every session of a two-factory Peer
// subscribes), so the parked actors are kicked about once a second. A step
// that only re-evaluates selector quality or bond ranking from an
// unchanged snapshot does no work (R1-22), so a kicked actor parks again
// at once.
//
// After the exchange and 2 × the linger, for 10 ProbeIntervals: at every
// 100-ms tick, once every goroutine of the bubble is blocked
// (synctest.Wait), Status.Actors is 0 on both Runtimes. Stimulus: the
// probes published (the factories' Samples rose by at least 16 over the
// window) and the publications reached the parked sessions (the dialer's
// actors started — counted by the AtPark hook, which runs once per start
// as the actor parks again — at least once per session). Bound: actor
// starts ≤ the subscribed sessions × the publications (the samples), i.e.
// at most one start per session per snapshot. Closing the sessions and the
// Runtimes leaves nothing.
func TestIdleSessionsParkUnderProbes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := population()
		var parks atomic.Int64
		dov := testhooks.Overrides{Hooks: &testhooks.Hooks{AtPark: func([16]byte) { parks.Add(1) }}}
		w := newWorld(t, worldOpts{n: n, dov: dov}, linkSpec{name: "a", oneWay: oneWay}, linkSpec{name: "b", oneWay: 2 * oneWay})
		ps := w.openMany(n, func(i int) rendr.Mode {
			if i%2 == 0 {
				return rendr.ModeSelector
			}
			return rendr.ModeBond
		})
		exchange(t, ps, 1)
		time.Sleep(2 * linger)
		synctest.Wait()
		if a, b := w.actors(); a != 0 || b != 0 {
			t.Fatalf("premise: Status.Actors %d and %d after 2 × the linger, want every actor parked", a, b)
		}
		if !w.peer.Status().Probing {
			t.Fatal("premise: the Peer does not probe")
		}
		samples := func() (s uint64) {
			for _, f := range w.peer.Status().Factories {
				s += f.Samples
			}
			return s
		}
		s0, p0 := samples(), parks.Load()
		const (
			interval = 2 * time.Second // ProbeInterval's default
			tick     = 100 * time.Millisecond
		)
		for k := 1; k <= int(10*interval/tick); k++ {
			time.Sleep(tick)
			synctest.Wait()
			if a, b := w.actors(); a != 0 || b != 0 {
				t.Fatalf("tick %d (+%v): Status.Actors %d and %d, want 0: an actor stayed running after a quality-only step (R1-22)",
					k, time.Duration(k)*tick, a, b)
			}
		}
		pubs, starts := samples()-s0, parks.Load()-p0
		t.Logf("%d sessions over 10 probe intervals: %d probe samples published, %d actor starts (%.2f per session per publication)",
			n, pubs, starts, float64(starts)/float64(n)/float64(max(pubs, 1)))
		if pubs < 16 {
			t.Fatalf("stimulus: %d probe samples in 10 intervals of two factories, want ≥ 16", pubs)
		}
		if starts < int64(n) {
			t.Fatalf("stimulus: %d actor starts for %d subscribed sessions, want at least one each (the publications ring them)", starts, n)
		}
		if starts > int64(n)*int64(pubs) {
			t.Fatalf("%d actor starts for %d publications to %d sessions, want ≤ one per session per publication", starts, pubs, n)
		}
		exchange(t, ps, 2)
		closeAll(t, ps)
		w.close()
	})
}
