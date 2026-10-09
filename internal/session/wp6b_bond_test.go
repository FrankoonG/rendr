package session

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// Packet bonds and redials (M2 design §A5.12; M2-D43, M2-D44; Revision 1,
// R1-19; L20).

// TestPacketBondDeathCount (M2-D44, R1-19): in a packet bond every member
// carries datagrams while the session sends (the minimum share: a DGRAM at
// least every PacketPing/2 on each member, also on the slower one), so the
// close of either member counts one death migration on the sending side;
// the side that sent nothing counts none. The member rejoins at once and
// the flow loses at most what was in flight on the dead carrier.
func TestPacketBondDeathCount(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := wpNewWorld(t, nil)
		defer w.teardown()
		l1, l2 := wpLink(w, "p1", 1400), wpLink(w, "p2", 1400)
		l2.SetDelay(5*time.Millisecond, 0) // the slower member: fastest-first alone would leave it idle
		spec := wpSpec(w, ModeBond, 1400, l1, l2)
		a, b := wpOpen(w, spec, nil)
		acWaitFor(t, time.Second, "both members attached", func() bool { return a.dataMembers() == 2 && b.dataMembers() == 2 })
		ping := spec.Params.Packet.PacketPing
		f := wpStartFlow(a, b, 200, 20*time.Millisecond) // 50 datagrams/s: never more than a batch queued
		time.Sleep(3 * time.Second)
		for round, victim := range []*struct {
			name string
			kill func() int
		}{{"p2", l2.Kill}, {"p1", l1.Kill}} {
			// Stimulus: every member placed a DGRAM within PacketPing/2.
			a.mu.Lock()
			for _, l := range a.lanes {
				if l.data && time.Since(l.lastDgramAt) > ping/2 {
					a.mu.Unlock()
					t.Fatalf("round %d: member %d placed no DGRAM for %v (> PacketPing/2): the minimum share does not hold", round, l.id, time.Since(l.lastDgramAt))
				}
			}
			a.mu.Unlock()
			d0, r0 := a.Status().MigDeath, a.Status().Rejoins
			if victim.kill() == 0 {
				t.Fatalf("round %d: killing %s hit no carrier", round, victim.name)
			}
			acWaitFor(t, time.Second, "the member rejoined", func() bool {
				return a.Status().Rejoins == r0+1 && a.dataMembers() == 2
			})
			if d := a.Status().MigDeath; d != d0+1 {
				t.Fatalf("round %d (%s closed): dialer death migrations %d → %d, want +1 (M2-D44)", round, victim.name, d0, d)
			}
			time.Sleep(3 * time.Second)
		}
		f.stop()
		acWaitFor(t, time.Second, "the flow drained", func() bool { return f.sent.Load()-f.got.Load() <= 4 })
		if bs := b.Status(); bs.MigDeath != 0 {
			t.Fatalf("passive death migrations %d: it placed no DGRAM, so its members' deaths count nothing", bs.MigDeath)
		}
		if lost := f.sent.Load() - f.got.Load(); lost > 4 || f.duplicates() != 0 || f.sent.Load() < 300 {
			t.Fatalf("flow: sent %d, got %d, duplicates %d; want ≤ 4 lost (in flight on the dead carriers)", f.sent.Load(), f.got.Load(), f.duplicates())
		}
	})
}

// errRefusedDial is the scripted factory failure of TestPacketRedial_L20.
var errRefusedDial = errors.New("scripted refusal")

// TestPacketRedial_L20 (L20, packet part): the factory fails its 2nd and
// 3rd calls. The carrier of a packet session dies in the middle of a flow
// in both directions; the immediate redial (call 2) and the first backoff
// retry (call 3) fail and call 4 attaches within 2 s of the death. Once the
// passive followed the replacement's SCHED it dies too; the session
// redials at once (call 5) and recovers. Both directions keep delivering
// after each recovery, nothing arrives twice, and both ends count exactly
// two death migrations.
func TestPacketRedial_L20(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := wpNewWorld(t, nil)
		defer w.teardown()
		l := wpLink(w, "a", 1400)
		l.SetDelay(20*time.Millisecond, 0)
		spec := wpSpec(w, ModeSelector, 1400, l)
		var calls atomic.Int64
		dial := spec.Factories[0].Dial
		spec.Factories[0].Dial = func(ctx context.Context) (net.Conn, error) {
			if n := calls.Add(1); n == 2 || n == 3 {
				return nil, errRefusedDial
			}
			return dial(ctx)
		}
		a, b := wpOpen(w, spec, nil)
		up := wpStartFlow(a, b, 300, 10*time.Millisecond)
		down := wpStartFlow(b, a, 300, 10*time.Millisecond)
		time.Sleep(time.Second)

		resumed := func(what string) {
			t.Helper()
			u, d := up.got.Load(), down.got.Load()
			acWaitFor(t, time.Second, what, func() bool { return up.got.Load() >= u+20 && down.got.Load() >= d+20 })
		}
		t0 := time.Now()
		if n := l.Kill(); n != 1 {
			t.Fatalf("Kill killed %d carriers", n)
		}
		took := wpPoll(t, 2*time.Second, "reattach", func() bool {
			st := a.Status()
			return st.NoPathEpisodes == 1 && !st.InNoPath
		}).Sub(t0)
		if n := calls.Load(); n != 4 {
			t.Fatalf("%d factory calls, want 4 (calls 2 and 3 failed)", n)
		}
		t.Logf("reattached %v after the death, at the 4th factory call", took)
		resumed("arrivals resume after the first recovery")
		acWaitFor(t, time.Second, "the passive follows the replacement", func() bool {
			return b.Status().SchedEpoch == a.Status().SchedEpoch
		})

		t1 := time.Now()
		if n := l.Kill(); n != 1 {
			t.Fatalf("second Kill killed %d carriers", n)
		}
		wpPoll(t, time.Second, "the immediate redial attaches", func() bool {
			st := a.Status()
			return st.NoPathEpisodes == 2 && !st.InNoPath
		})
		if n := calls.Load(); n != 5 {
			t.Fatalf("%d factory calls after the second death (%v ago), want 5", n, time.Since(t1))
		}
		resumed("arrivals resume after the second recovery")
		acWaitFor(t, time.Second, "the passive follows again", func() bool {
			return b.Status().SchedEpoch == a.Status().SchedEpoch
		})
		up.stop()
		down.stop()
		ds, ps := a.Status(), b.Status()
		if ds.Rejoins != 2 || ds.MigDeath != 2 || ps.MigDeath != 2 {
			t.Fatalf("after two deaths: dialer rejoins %d, death migrations dialer %d passive %d; want 2 each (L20)", ds.Rejoins, ds.MigDeath, ps.MigDeath)
		}
		if ds.State != StateOpen || ps.State != StateOpen {
			t.Fatalf("states dialer %v passive %v, want open", ds.State, ps.State)
		}
		if up.duplicates()+down.duplicates() != 0 {
			t.Fatalf("duplicates: up %d down %d", up.duplicates(), down.duplicates())
		}
	})
}
