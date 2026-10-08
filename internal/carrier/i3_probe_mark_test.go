package carrier

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// probeSucceed applies a successful stream probe dial of factory i that
// started at start, as the run goroutine does when the attempt finished.
func (r *g4Rig) probeSucceed(i int, start time.Time) {
	run := &healthRun{h: r.h, slots: make([]probeSlot, len(r.cur))}
	a := &probeAttempt{id: 1, start: start, finished: true,
		est: &Established{Conn: r.cur[i], Resp: wire.Header{Type: wire.TypePong}}}
	r.h.mu.Lock()
	run.resultLocked(i, &run.slots[i], a, time.Now())
	r.h.publishLocked()
	r.h.mu.Unlock()
}

// TestHealthMarkAfterProbeDialProof_MARKAT (W4-MARKAT, the stream probe
// dial path left by G4): a successful stream probe dial is proof of the
// factory from the instant it started. A dial that started after a death
// and completed before the session's late MarkFailedAt must leave the
// factory unmarked, as a PONG committed after the death does; a dial that
// started before the death proves nothing about it.
func TestHealthMarkAfterProbeDialProof_MARKAT(t *testing.T) {
	ms := time.Millisecond
	t.Run("dial after the death", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newG4Rig(t)
			h := r.h
			time.Sleep(time.Second)
			died := time.Now()
			time.Sleep(5 * ms)
			r.probeSucceed(0, time.Now()) // started 5 ms after the death, completed at once
			time.Sleep(20 * ms)
			h.MarkFailedAt(0, "transport_error", died) // reported 25 ms after the death
			if s := h.Snapshot(); s.Failed[0] || s.Info[0].FailReason != "" {
				t.Fatalf("a death disproved by a later successful probe dial was marked: failed %v, info %+v", s.Failed[0], s.Info[0])
			}
			// A failure after the dial is still marked.
			h.MarkFailed(0, "transport_error")
			if s := h.Snapshot(); !s.Failed[0] || s.Failed[1] {
				t.Fatalf("a failure after the probe dial was not marked: failed %v, info %+v", s.Failed, s.Info)
			}
		})
	})
	t.Run("dial before the death", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newG4Rig(t)
			h := r.h
			time.Sleep(time.Second)
			start := time.Now()
			time.Sleep(5 * ms)
			died := time.Now()
			time.Sleep(5 * ms)
			r.probeSucceed(1, start) // started 5 ms before the death, completed after it
			time.Sleep(20 * ms)
			h.MarkFailedAt(1, "transport_error", died)
			if s := h.Snapshot(); !s.Failed[1] || s.Info[1].FailReason != "transport_error" || s.Failed[0] {
				t.Fatalf("a probe dial started before the death disproved it: failed %v, info %+v", s.Failed, s.Info)
			}
		})
	})
}
