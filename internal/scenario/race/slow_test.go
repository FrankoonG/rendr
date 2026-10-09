package race

import (
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
)

// TestRaceSlowMemberDoesNotDrag_L08 (M3 design §A11.2; L08 "race 模式下慢的
// 子承载拖累快的", M3-D30): a race session over a fast Link (5 ms one way,
// 4 MiB/s) and a slow one (200 ms one way, a tenth of the rate) moves
// 32 MiB B → A (8 MiB at a quarter of the rates under -race, the same
// timeline). Each member sends from its own cursor clamped to the
// acknowledged front, so the slow one skips what the fast one already
// delivered.
//
//   - goodput: the transfer's goodput is at least 0.9 × that of the same
//     transfer over the fast Link alone (a race session with one member,
//     its own bubble), and the slow member's TxBytes on the sending side B
//     are below 0.5 × the bytes moved (it never sends everything);
//   - fastKilled: the fast member is hard-killed (Link.Kill) when A has
//     half the bytes, and its factory refuses every redial from then on,
//     so the slow member alone must carry the rest. Stimulus: the kill
//     ended a session carrier, B counted a death migration (M3-D34), the
//     fast factory has no live member afterwards, and the slow member's
//     TxBytes on B grew by at least the bytes A still lacked at the kill
//     minus its in-flight then. No zero-delivery gap above 500 ms before
//     the kill; after it, no gap above (In + Cap) / R + 2 × D + 50 ms,
//     with In and Cap the slow member's in-flight and cap on B at the
//     kill, R the slow Link's rate and D its one-way delay. At the kill
//     the slow member is at its cap with copies the fast one already
//     delivered, queued at its bottleneck: they drain in In / R, the proof
//     of their arrival returns in D (until then the cap blocks new
//     sends), and the first byte A lacks leaves within the next Cap of
//     sends and arrives D later. (The design's flat 500 ms is out of
//     reach: the queue alone takes ≈ 0.63 s at the full size and 2.5 s at
//     the race size; see the WP12a report.)
//
// Every run verifies every byte and io.EOF at the end, a clean end on both
// ends and nothing left after Runtime.Close.
func TestRaceSlowMemberDoesNotDrag_L08(t *testing.T) {
	size, rate := int64(32<<20), float64(4<<20)
	if raceEnabled {
		size, rate = 8<<20, 1<<20
	}
	t.Run("goodput", func(t *testing.T) {
		var alone time.Duration
		synctest.Test(t, func(t *testing.T) { alone = slowRun(t, size, rate, false, false) })
		if alone == 0 {
			t.Fatal("the fast-link-alone run failed")
		}
		synctest.Test(t, func(t *testing.T) {
			took := slowRun(t, size, rate, true, false)
			ga, gr := float64(size)/alone.Seconds(), float64(size)/took.Seconds()
			if gr < 0.9*ga {
				t.Fatalf("race goodput %.0f B/s over fast + slow, below 0.9 × the fast link alone (%.0f B/s)", gr, ga)
			}
			t.Logf("goodput: fast alone %.0f B/s (%v), race fast + slow %.0f B/s (%v): %.3f", ga, alone, gr, took, gr/ga)
		})
	})
	t.Run("fastKilled", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) { slowRun(t, size, rate, true, true) })
	})
}

// slowRun moves size bytes B → A over the fast Link and, with slow, the
// slow one too; with kill it kills the fast member at half the bytes and
// refuses its redials. It returns the transfer time.
func slowRun(t *testing.T, size int64, rate float64, slow, kill bool) time.Duration {
	specs := []linkSpec{{name: "fast", oneWay: 5 * time.Millisecond, rate: rate}}
	names := []string{"fast"}
	if slow {
		specs = append(specs, linkSpec{name: "slow", oneWay: 200 * time.Millisecond, rate: rate / 10})
		names = append(names, "slow")
	}
	w := newWorld(t, worldOpts{}, specs...)
	dc, pc := w.open(w.peer(names...), rendr.DialOptions{Mode: rendr.ModeRace})
	waitFor(t, 10*time.Second, "every member on both ends", func() bool {
		return len(liveOf(dc.Status())) == len(names) && len(liveOf(pc.Status())) == len(names)
	})
	slowID := rendr.CarrierID(0)
	if slow {
		m, _ := liveNamed(dc.Status(), "slow")
		slowID = m.ID
	}

	down := startReceiver(dc, 1, size)
	up := startReceiver(pc, 2, 0)
	tx := w.startSender(pc, 1, size, 0)
	w.startSender(dc, 2, 0, 0)
	var killAt time.Time
	var atKill rendr.CarrierStatus // the slow member on B at the kill
	var lackAtKill int64           // the bytes A still lacked at the kill
	var death0 uint64
	if kill {
		waitFor(t, time.Minute, "half of the bytes", func() bool { return down.got.Load() >= size/2 })
		l := w.link("fast")
		before := l.Stats().Session.Killed
		atKill, _ = carrierOf(pc.Status(), slowID)
		death0 = pc.Status().Migrations.Death
		lackAtKill = size - down.got.Load()
		killAt = time.Now()
		l.SetRefuse(true) // the slow member must take over: no rejoin of the fast one
		l.Kill()
		if l.Stats().Session.Killed == before {
			t.Fatal("stimulus: the kill of the fast Link ended no session carrier")
		}
	}
	down.wait(t, 5*time.Minute)
	up.wait(t, time.Minute)
	tx.wait(t, time.Minute)
	took := down.end().Sub(tx.start)
	if kill {
		if g, at := down.maxGap(tx.start, killAt); g > 500*time.Millisecond {
			t.Fatalf("a zero-delivery gap of %v at +%v before the kill, want ≤ 500 ms", g, at.Sub(tx.start))
		}
		sp := w.spec("slow")
		drain := time.Duration(float64(atKill.Inflight+atKill.Cap) / sp.rate * float64(time.Second))
		limit := drain + 2*sp.oneWay + 50*time.Millisecond
		g, at := down.maxGap(killAt, down.end())
		if g > limit {
			t.Fatalf("a zero-delivery gap of %v at kill +%v, want ≤ %v ((in flight %d + cap %d) / %.0f B/s + 2 × %v + 50 ms; slow on B at the kill: %+v)",
				g, at.Sub(killAt), limit, atKill.Inflight, atKill.Cap, sp.rate, sp.oneWay, atKill)
		}
		ps := pc.Status()
		if ps.Migrations.Death == death0 {
			t.Fatalf("B counted no death migration for the kill of the fast member: %+v (M3-D34)", ps.Migrations)
		}
		for _, c := range []*rendr.Conn{dc, pc} {
			if m, ok := liveNamed(c.Status(), "fast"); ok {
				t.Fatalf("stimulus: a fast member %d is live although its factory refuses every redial", m.ID)
			}
		}
		sm, _ := carrierOf(ps, slowID)
		if grew, want := int64(sm.TxBytes-atKill.TxBytes), lackAtKill-int64(atKill.Inflight); grew < want {
			t.Fatalf("the slow member sent %d bytes after the kill, want ≥ %d (the %d bytes A lacked minus its in-flight %d): it must carry the rest",
				grew, want, lackAtKill, atKill.Inflight)
		}
		t.Logf("fast member killed at +%v (slow on B: SRTT %v, in flight %d, cap %d, proven rate %.0f B/s): first bytes after it +%v, longest gap after it %v (limit %v); slow member sent %d bytes after it",
			killAt.Sub(tx.start), atKill.SRTT, atKill.Inflight, atKill.Cap, atKill.Rate,
			down.firstAfter(killAt.Add(time.Nanosecond)).Sub(killAt), g, limit, sm.TxBytes-atKill.TxBytes)
	}
	if slow && !kill {
		sm, ok := carrierOf(pc.Status(), slowID)
		if !ok {
			t.Fatalf("B lists no slow member %d", slowID)
		}
		if float64(sm.TxBytes) >= 0.5*float64(size) {
			t.Fatalf("the slow member sent %d bytes for a %d-byte transfer, want < 0.5 × (it must skip what was delivered, L08)", sm.TxBytes, size)
		}
		t.Logf("slow member: %d bytes sent (%.3f of the transfer)", sm.TxBytes, float64(sm.TxBytes)/float64(size))
	}
	finish(t, dc, pc)
	w.noViolation()
	w.close()
	return took
}
