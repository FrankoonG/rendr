package carrier

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestHealthRepeatedMarkRingsNobody_L27 (m6 item rc5; L27): a dead shared
// path reports one failed mark per session it carried, each from that
// session's death step. Only the first rings the subscribers (each a
// dialer session whose actor the ring wakes); a mark of a factory marked
// already changes nothing a subscriber ranks by and rings nobody, and it
// stores no new snapshot unless the reason changed (FailReason: stored, no
// ring) or the mark is the current run's first evidence of the factory
// (WaitFirst returns at it). It keeps the later failure time, so a round
// trip committed before a later report no longer clears the mark, and the
// latest reason. Before rc5 every report published and rang every
// subscriber: the "rings" row's 2,000 reports rang each of its 64
// subscribers 2,001 times instead of once (G11-dns's DROP: ≈ 2,300 reports
// × ≈ 2,800 sessions under the health lock).
func TestHealthRepeatedMarkRingsNobody_L27(t *testing.T) {
	const ms = time.Millisecond
	t.Run("rings", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newG4Rig(t)
			h := r.h
			bells := make([]*hBell, 64)
			for i := range bells {
				bells[i] = &hBell{}
				defer h.Subscribe(bells[i])()
			}
			rung := func() (n int32) {
				for _, b := range bells {
					n += b.n.Load()
				}
				return n
			}
			time.Sleep(time.Second)
			v0 := h.Snapshot().Version
			died := time.Now()
			h.MarkFailedAt(0, "ping_timeout", died)
			s := h.Snapshot()
			if !s.Failed[0] || s.Info[0].FailReason != "ping_timeout" || s.Version != v0+1 || rung() != 64 {
				t.Fatalf("the first mark: failed %v, info %+v, version %d→%d, %d rings; want it published and every subscriber rung once", s.Failed[0], s.Info[0], v0, s.Version, rung())
			}
			// The other sessions of the path report the same death, dated
			// around it (each by its own carrier's death record).
			time.Sleep(10 * ms)
			for k := range 2000 {
				h.MarkFailedAt(0, "ping_timeout", died.Add(time.Duration(k%7-3)*ms))
			}
			if s := h.Snapshot(); !s.Failed[0] || s.Info[0].FailReason != "ping_timeout" || s.Version != v0+1 || rung() != 64 {
				t.Fatalf("2,000 repeated marks: failed %v, info %+v, version %d→%d, %d rings; want no new snapshot and no ring", s.Failed[0], s.Info[0], v0+1, s.Version, rung())
			}
			// A new reason is stored (Status's FailReason), still without a ring.
			h.MarkFailedAt(0, "peer_down", died)
			h.MarkFailedAt(0, "peer_down", died)
			if s := h.Snapshot(); !s.Failed[0] || s.Info[0].FailReason != "peer_down" || s.Version != v0+2 || rung() != 64 {
				t.Fatalf("a new reason: failed %v, info %+v, version %d→%d, %d rings; want one stored snapshot and no ring", s.Failed[0], s.Info[0], v0+1, s.Version, rung())
			}
			// The other factory's first mark rings as before.
			h.MarkFailedAt(1, "ping_timeout", time.Now())
			if s := h.Snapshot(); !s.Failed[1] || s.Version != v0+3 || rung() != 128 {
				t.Fatalf("factory 1's first mark: failed %v, version %d→%d, %d rings; want it published and rung", s.Failed[1], v0+2, s.Version, rung())
			}
		})
	})
	t.Run("later failure time", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newG4Rig(t)
			h := r.h
			time.Sleep(time.Second)
			died := time.Now()
			h.MarkFailedAt(0, "ping_timeout", died)
			time.Sleep(5 * ms)
			c := time.Now()
			h.obs.PingCommitted(r.cur[0], 1, c) // after the first death, before the later one
			time.Sleep(5 * ms)
			h.MarkFailedAt(0, "ping_timeout", time.Now()) // a later death on the same path
			time.Sleep(ms)
			h.obs.Pong(r.cur[0], 1, time.Since(c), time.Now())
			if s := h.Snapshot(); !s.Failed[0] || s.Info[0].Samples != 1 {
				t.Fatalf("a round trip committed before the later report cleared the mark: failed %v, info %+v", s.Failed[0], s.Info[0])
			}
			time.Sleep(ms)
			r.sample(0, 2, time.Now(), ms)
			if s := h.Snapshot(); s.Failed[0] || s.Info[0].Samples != 2 {
				t.Fatalf("a round trip after both deaths left the mark: failed %v, info %+v", s.Failed[0], s.Info[0])
			}
		})
	})
	t.Run("first evidence", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newPrRig(t, 2, nil)
			r.links[1].SetDial(rendrtest.DialHang) // factory 1 never gets a sample
			r.h.MarkFailed(1, "transport_error")   // before the run: a mark outlives runs
			r.h.Use()                              // a cold start: every factory needs first evidence again
			go func() {
				time.Sleep(100 * ms)
				r.h.MarkFailedAt(1, "transport_error", time.Now()) // the same mark again: factory 1's first evidence of the run
			}()
			r.h.WaitFirst(context.Background())
			if got := r.since(); got != 100*ms {
				t.Fatalf("WaitFirst returned at %v, want 100ms (factory 0's sample at 40 ms, factory 1's repeated mark at 100 ms)", got)
			}
		})
	})
}
