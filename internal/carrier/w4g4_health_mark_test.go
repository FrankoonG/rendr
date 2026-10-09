package carrier

import (
	"net"
	"testing"
	"testing/synctest"
	"time"
)

// g4Rig is a two-factory Health whose probe incarnations are bare pipe
// carriers installed as each factory's current conn: the test drives the
// observer (PING commits, PONGs) itself, at exact virtual times.
type g4Rig struct {
	h   *Health
	cur [2]*Conn
}

func newG4Rig(t *testing.T) *g4Rig {
	env := hEnv()
	h := NewHealth(env, []Factory{{Name: "a"}, {Name: "b"}}, prParams())
	t.Cleanup(h.Close)
	r := &g4Rig{h: h}
	for i := range r.cur {
		a, b := net.Pipe()
		t.Cleanup(func() { a.Close(); b.Close() })
		r.cur[i] = newConn(env, a, env.IDs.Next(), hPassiveInst, i, "x", true)
	}
	h.mu.Lock()
	for i, c := range r.cur {
		h.fac[i].conn = c
	}
	h.mu.Unlock()
	return r
}

// sample feeds factory i one probe round trip: PING id committed at commit,
// its PONG arriving rtt later, with the clock at or after the arrival.
func (r *g4Rig) sample(i int, id uint32, commit time.Time, rtt time.Duration) {
	r.h.obs.PingCommitted(r.cur[i], id, commit)
	r.h.obs.Pong(r.cur[i], id, rtt, commit.Add(rtt))
}

// TestHealthMarkAfterSameInstantProof_MARKAT (W4-MARKAT, K12): a failed
// mark and a probe round trip at the same instant. (1) A sample whose PING
// was committed at T is processed before the MarkFailed of a failure at T
// (the session reports a death after its step, so in a synctest bubble the
// probe of the factory redialled at the death's instant gets there first):
// the factory is not left marked. (2) A mark set at T and then a PING
// committed at T whose PONG measures 0 (zero-delay link, or a round trip
// below the clock's resolution, which Windows' monotonic clock often
// reads): the PONG clears the mark — the 1 ns RTT floor must not move the
// commit before the mark.
func TestHealthMarkAfterSameInstantProof_MARKAT(t *testing.T) {
	t.Run("proof then mark", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newG4Rig(t)
			h := r.h
			time.Sleep(time.Second)
			at := time.Now()
			r.sample(0, 1, at, 0)
			s := h.Snapshot()
			if s.Info[0].Samples != 1 || s.Sum[0].N != 1 || s.Failed[0] {
				t.Fatalf("stimulus: factory 0 after its round trip: info %+v, summary %+v, failed %v", s.Info[0], s.Sum[0], s.Failed[0])
			}
			v := s.Version
			h.MarkFailed(0, CauseTransportError.String())
			if s = h.Snapshot(); s.Failed[0] || s.Info[0].FailReason != "" {
				t.Fatalf("a death at %v left factory 0 marked although its PING committed at that instant was answered: failed %v, info %+v", at, s.Failed[0], s.Info[0])
			}
			// Integrity: nothing else changed, and factory 1 is untouched.
			if s.Version != v || s.Info[0].Samples != 1 || s.Failed[1] || s.Info[1].Samples != 0 {
				t.Fatalf("snapshot after the disproved mark: version %d→%d, info %+v, failed %v", v, s.Version, s.Info, s.Failed)
			}
		})
	})
	t.Run("mark then proof", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newG4Rig(t)
			h := r.h
			time.Sleep(time.Second)
			at := time.Now()
			h.MarkFailed(1, CauseTransportError.String())
			if s := h.Snapshot(); !s.Failed[1] || s.Info[1].FailReason != "transport_error" {
				t.Fatalf("stimulus: factory 1 not marked: %+v", s.Info[1])
			}
			r.sample(1, 1, at, 0)
			s := h.Snapshot()
			if s.Info[1].Samples != 1 || s.Sum[1].N != 1 {
				t.Fatalf("stimulus: factory 1's round trip not sampled: info %+v, summary %+v", s.Info[1], s.Sum[1])
			}
			if s.Failed[1] || s.Info[1].FailReason != "" {
				t.Fatalf("a PONG of a PING committed at the mark's instant left factory 1 marked: failed %v, info %+v", s.Failed[1], s.Info[1])
			}
			if s.Failed[0] || s.Info[0].Samples != 0 {
				t.Fatalf("factory 0 changed: failed %v, info %+v", s.Failed[0], s.Info[0])
			}
		})
	})
}

// TestHealthMarkDatedByFailure_MARKAT (W4-MARKAT): MarkFailedAt dates the
// mark by the failure, not by the call, so the order of a late call and
// the probe evidence no longer matters. A round trip whose PING was
// committed after the death clears the mark whether its sample is
// processed before the call (no mark at all) or after it; a round trip
// committed before the death does not; a mark recorded for a later
// failure keeps its later time; a zero or future time means now.
func TestHealthMarkDatedByFailure_MARKAT(t *testing.T) {
	ms := time.Millisecond
	t.Run("proof between the death and the call", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newG4Rig(t)
			h := r.h
			time.Sleep(time.Second)
			died := time.Now()
			time.Sleep(5 * ms)
			r.sample(0, 1, time.Now(), ms) // committed at died+5ms, answered at died+6ms
			time.Sleep(20 * ms)
			s := h.Snapshot()
			if s.Info[0].Samples != 1 {
				t.Fatalf("stimulus: no sample: %+v", s.Info[0])
			}
			v := s.Version
			h.MarkFailedAt(0, "transport_error", died) // reported 26 ms after the death
			if s = h.Snapshot(); s.Failed[0] || s.Version != v {
				t.Fatalf("a death disproved by a later round trip was marked: failed %v, version %d→%d, info %+v", s.Failed[0], v, s.Version, s.Info[0])
			}
			// The same call without the date (the old behaviour) would have
			// marked it: the call's own time is after that round trip.
			h.MarkFailed(0, "transport_error")
			if s = h.Snapshot(); !s.Failed[0] || s.Info[0].FailReason != "transport_error" {
				t.Fatalf("a failure after the latest round trip was not marked: %+v", s.Info[0])
			}
		})
	})
	t.Run("proof committed before the death", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newG4Rig(t)
			h := r.h
			time.Sleep(time.Second)
			c1 := time.Now()
			r.sample(0, 1, c1, ms) // committed 2 ms before the death
			time.Sleep(2 * ms)
			died := time.Now()
			// PING 2 committed 1 ms after the death; its PONG comes after the call.
			time.Sleep(ms)
			c2 := time.Now()
			r.h.obs.PingCommitted(r.cur[0], 2, c2)
			time.Sleep(9 * ms)
			h.MarkFailedAt(0, "transport_error", died) // reported 10 ms after the death
			if s := h.Snapshot(); !s.Failed[0] || s.Info[0].Samples != 1 {
				t.Fatalf("a death after the latest round trip was not marked: failed %v, info %+v", s.Failed[0], s.Info[0])
			}
			time.Sleep(2 * ms)
			r.h.obs.Pong(r.cur[0], 2, time.Since(c2), time.Now())
			if s := h.Snapshot(); s.Failed[0] || s.Info[0].Samples != 2 || s.Sum[0].N != 2 {
				t.Fatalf("a PONG of a PING committed after the death (before the call) left the mark: failed %v, info %+v", s.Failed[0], s.Info[0])
			}
		})
	})
	t.Run("a later mark keeps its time", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newG4Rig(t)
			h := r.h
			time.Sleep(time.Second)
			died := time.Now()
			time.Sleep(10 * ms)
			c := time.Now()
			r.h.obs.PingCommitted(r.cur[1], 1, c) // after the death, before the later failure
			time.Sleep(10 * ms)
			h.MarkFailed(1, "ping_timeout")            // a later failure, at died+20ms
			h.MarkFailedAt(1, "transport_error", died) // the earlier death, reported late
			time.Sleep(ms)
			r.h.obs.Pong(r.cur[1], 1, time.Since(c), time.Now())
			if s := h.Snapshot(); !s.Failed[1] || s.Info[1].Samples != 1 {
				t.Fatalf("a round trip committed before the later failure cleared its mark: failed %v, info %+v", s.Failed[1], s.Info[1])
			}
			time.Sleep(ms)
			r.sample(1, 2, time.Now(), ms)
			if s := h.Snapshot(); s.Failed[1] || s.Info[1].Samples != 2 {
				t.Fatalf("a round trip after both failures did not clear the mark: failed %v, info %+v", s.Failed[1], s.Info[1])
			}
		})
	})
	t.Run("zero and future times mean now", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newG4Rig(t)
			h := r.h
			time.Sleep(time.Second)
			r.sample(0, 1, time.Now(), 0)
			h.MarkFailedAt(0, "transport_error", time.Time{}) // now: the same instant as the proof
			h.MarkFailedAt(1, "transport_error", time.Now().Add(time.Hour))
			s := h.Snapshot()
			if s.Failed[0] || !s.Failed[1] {
				t.Fatalf("zero time not now, or future mark missing: failed %v, info %+v", s.Failed, s.Info)
			}
			time.Sleep(ms)
			r.sample(1, 1, time.Now(), ms) // committed 1 ms after the call, long before the future time
			if s = h.Snapshot(); s.Failed[1] || s.Info[1].Samples != 1 {
				t.Fatalf("a future failure time was not clamped to the call: failed %v, info %+v", s.Failed[1], s.Info[1])
			}
		})
	})
	t.Run("out of range", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newG4Rig(t)
			v := r.h.Snapshot().Version
			r.h.MarkFailedAt(-1, "x", time.Now())
			r.h.MarkFailedAt(2, "x", time.Now())
			if s := r.h.Snapshot(); s.Version != v || s.Failed[0] || s.Failed[1] {
				t.Fatalf("an out-of-range factory changed the snapshot: version %d→%d, failed %v", v, s.Version, s.Failed)
			}
		})
	})
}
