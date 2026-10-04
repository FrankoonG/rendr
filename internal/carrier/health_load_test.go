package carrier

import (
	"testing"
	"testing/synctest"
	"time"
)

// TestHealthSessionBacklogLoadsProbes_L28 (design §8.2, P1; L28 at the
// carrier layer): a real dialer session carrier of factory 0 feeds the
// factory's Gauge (StartOptions.Gauge) — no test code touches the gauge.
// While its writer waits at the capacity cap with more than the threshold
// unproven in flight (bulk DATA towards a peer whose PONGs take 300 ms),
// factory 0's probe samples are tagged loaded and stay out of its window;
// once the whole transfer is proven and the backlog is over, its samples
// count again. Factory 1's samples are never loaded.
func TestHealthSessionBacklogLoadsProbes_L28(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newPhRig(t, 2, nil)
		r.h.Use()
		r.until(time.Second)
		base := r.h.Snapshot().Info[0]
		if base.Samples != 1 || base.LoadedSamples != 0 {
			t.Fatalf("baseline %+v", base)
		}
		senv := hEnv()
		senv.Timing.Window = 256 << 10 // capacity ceiling: a short transfer stays backlogged
		c, p := hPair(t, senv, nil)
		p.autoPong(func(uint32) time.Duration { return 300 * time.Millisecond })
		const total = 2 << 20
		src := newSource(senv, ChunkSize, true)
		src.offer(total)
		g := r.h.Gauges()[0]
		c.Start(src, &hBell{}, StartOptions{Gauge: g})

		// Stimulus: by the probe PING of 2.02 s the session carrier loads the
		// gauge (backlogged at the cap, ≥ 64 KiB unproven).
		r.until(2 * time.Second)
		st := c.Stats()
		if on, _ := g.Loaded(64 << 10); !on || !st.Backlogged || st.Inflight < 64<<10 {
			t.Fatalf("session carrier did not load the gauge: loaded %v, stats %+v", on, st)
		}
		r.until(2050 * time.Millisecond)
		s := r.h.Snapshot()
		if s.Info[0].Samples != 2 || s.Info[0].LoadedSamples != 1 || s.Sum[0].N != 1 {
			t.Fatalf("sample of 2.04 s: info %+v, window %d (want it loaded, outside the window)", s.Info[0], s.Sum[0].N)
		}

		// Load: the whole transfer reaches the peer and is proven by PONGs,
		// then the BUSY state clears (bounded wait in virtual time).
		var done time.Duration
		for d := 2100 * time.Millisecond; d <= 30*time.Second; d += 100 * time.Millisecond {
			r.until(d)
			if on, _ := g.Loaded(64 << 10); !on && p.dataBytes() == total && c.Inflight() == 0 {
				done = d
				break
			}
		}
		if done == 0 {
			t.Fatalf("transfer not proven: peer has %d of %d bytes, in flight %d", p.dataBytes(), total, c.Inflight())
		}
		loaded := r.h.Snapshot().Info[0].LoadedSamples
		if loaded < 1 {
			t.Fatalf("no loaded sample during the transfer")
		}
		// The next probe sample after the load ended is unloaded again.
		next := 20*time.Millisecond + (done/(2*time.Second)+1)*2*time.Second
		r.until(next + 30*time.Millisecond)
		s = r.h.Snapshot()
		unloaded := s.Info[0].Samples - s.Info[0].LoadedSamples
		if s.Info[0].LoadedSamples != loaded || unloaded != 2 || s.Sum[0].N != 2 || s.Sum[0].Mean != 20*time.Millisecond {
			t.Fatalf("after the load: info %+v, window %+v", s.Info[0], s.Sum[0])
		}
		if s.Info[1].LoadedSamples != 0 {
			t.Fatalf("factory 1 had loaded samples: %+v", s.Info[1])
		}
	})
}
