package carrier

import (
	"context"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/sched"
)

// TestProbeSubTickRTTIsASample_L28 (wave-2 integration): a probe round trip
// shorter than the clock's resolution measures 0 — on Windows' monotonic
// clock (steps of about 0.3–0.5 ms) nearly every loopback or LAN probe
// does, and so does a zero-delay link in a bubble. sched.Aggregator rejects
// a zero RTT as untimed, so such a path never got evidence and every
// cold-start Dial of a multi-factory Peer waited the whole DialWait. The
// sample counts as 1 ns: the path becomes Fresh, and WaitFirst is released
// by it like by any other sample.
func TestProbeSubTickRTTIsASample_L28(t *testing.T) {
	t.Run("Observer", func(t *testing.T) {
		env := hEnv()
		h := NewHealth(env, []Factory{{Name: "a"}, {Name: "b"}}, prParams())
		defer h.Close()
		a, b := net.Pipe()
		t.Cleanup(func() { a.Close(); b.Close() })
		cur := newConn(env, a, env.IDs.Next(), hPassiveInst, 0, "a", true)
		h.mu.Lock()
		h.fac[0].conn = cur
		h.mu.Unlock()
		at := time.Now()
		h.obs.PingCommitted(cur, 1, at)
		h.obs.Pong(cur, 1, 0, at)
		s := h.Snapshot()
		if s.Info[0].Samples != 1 || s.Sum[0].N != 1 || !s.Sum[0].At.Equal(at) {
			t.Fatalf("a zero-RTT PONG gave no sample: info %+v, summary %+v", s.Info[0], s.Sum[0])
		}
		if ev := s.Evidence(0, at); ev.State != sched.EvFresh || ev.RTT != time.Nanosecond {
			t.Fatalf("evidence %+v, want Fresh 1ns", ev)
		}
		// A zero-RTT PONG that overtook its commit callback waits for it
		// and then counts the same way.
		at2 := at.Add(time.Second)
		h.obs.Pong(cur, 2, 0, at2)
		if s := h.Snapshot(); s.Info[0].Samples != 1 {
			t.Fatalf("a PONG ahead of its commit callback became a sample before it: %+v", s.Info[0])
		}
		h.obs.PingCommitted(cur, 2, at2)
		if s := h.Snapshot(); s.Info[0].Samples != 2 || s.Sum[0].N != 2 || s.Sum[0].Mean != time.Nanosecond {
			t.Fatalf("early zero-RTT PONG: info %+v, summary %+v", s.Info[0], s.Sum[0])
		}
	})
	t.Run("ZeroDelayLinks", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newPrRig(t, 2, nil)
			for _, l := range r.links {
				l.SetDelay(0, 0) // every round trip takes no virtual time: RTT 0
			}
			r.h.Use()
			r.h.WaitFirst(context.Background())
			// The establishment and two more probe PINGs (Interval 2 s): every
			// PONG measures 0. One that raced its PING's own write commit is
			// no sample (V6), but not all of them can.
			r.until(4500 * time.Millisecond)
			s := r.h.Snapshot()
			for i := range s.Sum {
				if s.Info[i].Samples == 0 || s.Failed[i] {
					t.Fatalf("factory %d: no sample from zero-delay round trips: info %+v, failed %v", i, s.Info[i], s.Failed[i])
				}
				if ev := s.Evidence(i, time.Now()); ev.State != sched.EvFresh || ev.RTT != time.Nanosecond {
					t.Fatalf("factory %d: evidence %+v, want Fresh 1ns", i, ev)
				}
			}
		})
	})
}
