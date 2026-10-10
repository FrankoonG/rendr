package timers

import (
	"math/rand/v2"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
)

// The actor linger (testhooks.Overrides.ActorLinger's default, M3-D42)
// and the links' one-way delay.
const (
	linger = time.Second
	oneWay = 5 * time.Millisecond
)

// population is the idle population: 1,000 sessions; 250 under -race
// (R2-37), whose detector stops the binary past 8,128 live goroutines —
// 1,000 sessions over two factories run about 10,000 with the links'
// pumps. The size rule is about goroutines, so it binds only where the
// sessions bring their own carriers: the MUX halves run their 1,000 parked
// sessions over 4 trunks (a few dozen goroutines) in every lane, -race
// included, at the default MuxMaxViews with no override (R1-15).
func population() int {
	if raceEnabled {
		return 250
	}
	return 1000
}

// muxPopulation and muxViews: the MUX halves' 1,000 sessions over trunks
// of the default MuxMaxViews (256), ⌈1000/256⌉ = 4 trunks (R1-15).
const (
	muxPopulation = 1000
	muxViews      = 256
)

// Goroutines a carrier runs while its sessions are parked: a dedicated
// carrier and a MUX trunk alike run their reader and writer on each side.
// The owners keep no goroutine per trunk (R2-13: the passive trunk set's
// OnTrunkDone; R2-20: the dialer pool's watcher ends once the trunk is
// published), so a trunk costs 4, not the 6 of WP12a's bound.
const (
	dedicatedGoroutines = 4
	trunkGoroutines     = 4
)

// half is one half of the idle scenarios: n sessions on dedicated carriers
// (Props.CheapSubflow, M3-D2: every session dials its own) or over the MUX
// trunks of one Peer (default Props, the rendr mux; R1-15).
type half struct {
	name string
	mux  bool
}

var halves = []half{{"dedicated", false}, {"mux", true}}

// eachHalf runs body for each half in its own synctest bubble.
func eachHalf(t *testing.T, body func(t *testing.T, h half)) {
	for _, h := range halves {
		t.Run(h.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { body(t, h) })
		})
	}
}

// population is the half's session count: the dedicated half follows
// population() (250 under -race), the MUX half is 1,000 in every lane.
func (h half) population() int {
	if h.mux {
		return muxPopulation
	}
	return population()
}

// world builds the half's one-factory world for n sessions; the MUX half
// at the default Props and no testhook override.
func (h half) world(t testing.TB, n int) *world {
	if !h.mux {
		return newWorld(t, worldOpts{n: n}, linkSpec{name: "a", oneWay: oneWay, props: rendr.Props{CheapSubflow: true}})
	}
	return newWorld(t, worldOpts{n: n}, linkSpec{name: "a", oneWay: oneWay})
}

// carriers checks the half's carrier premise for the n open sessions ps
// and returns the carriers per side and the goroutines they run (both
// sides). Every session has exactly one live carrier on each end.
// Dedicated: n carriers per side, none of them MUX trunks (Status.Mux
// counts 0). MUX: Status.Mux.Carriers == ⌈n/256⌉ on each side (4, R1-15)
// with Views == n.
func (h half) carriers(t testing.TB, w *world, ps []pair) (cs, goroutines int) {
	t.Helper()
	n := len(ps)
	for i, s := range ps {
		for j, c := range []*rendr.Conn{s.d, s.p} {
			if k := live(c); k != 1 {
				t.Fatalf("premise: session %d's %s lists %d live carriers, want 1", i, [2]string{"dialer", "passive"}[j], k)
			}
		}
	}
	dm, pm := w.d.Status().Mux, w.p.Status().Mux
	if !h.mux {
		if dm.Carriers != 0 || pm.Carriers != 0 {
			t.Fatalf("premise: %d and %d MUX trunks under CheapSubflow, want 0 (dedicated carriers)", dm.Carriers, pm.Carriers)
		}
		return n, dedicatedGoroutines * n
	}
	trunks := (n + muxViews - 1) / muxViews
	if dm.Carriers != trunks || pm.Carriers != trunks || dm.Views != n || pm.Views != n {
		t.Fatalf("premise: Status.Mux dialer %+v, passive %+v; want %d trunks with %d views on each side (R1-15)", dm, pm, trunks, n)
	}
	return trunks, trunkGoroutines * trunks
}

// live counts a session end's live carriers (active or member).
func live(c *rendr.Conn) int {
	k := 0
	for _, cs := range c.Status().Carriers {
		if cs.State == rendr.CarrierActive || cs.State == rendr.CarrierMember {
			k++
		}
	}
	return k
}

// TestIdleSessionsHoldNoGoroutine (M3 design §A8.3, R1-15; plan:649, L52):
// n idle selector sessions exchange one byte each way and then stay idle,
// in two halves: each session on its own carrier (dedicated:
// Props.CheapSubflow; 1,000, 250 under -race), and 1,000 of them over the
// MUX trunks of one Peer at the default Props and no override in every
// lane (mux: ⌈1000/256⌉ = 4 trunks, Status.Mux.Carriers == 4 on each side). After
// 2 × the actor linger every actor on both ends is parked: Status.Actors
// is 0 on both Runtimes, the registry counts 2n live and 2n parked
// sessions, no actor goroutine runs, and the rendr goroutines are at most
// the baseline (both Runtimes, the Listener and the Peer before any
// session) + the carriers' goroutines (dedicated: a reader and a writer
// per carrier per side; mux: those of the 4 trunks, likewise) + 10 — a
// goroutine per parked session would exceed that by hundreds, and three
// more per trunk in the MUX half would exceed it (two more per trunk, 8
// in all, stay inside the slack). The parked sessions still carry a
// second byte each way; closing them and the Runtimes leaves nothing.
func TestIdleSessionsHoldNoGoroutine(t *testing.T) {
	eachHalf(t, func(t *testing.T, h half) {
		n := h.population()
		w := h.world(t, n)
		synctest.Wait()
		base, _, _ := goroutines()
		ps := w.openMany(n, func(int) rendr.Mode { return rendr.ModeSelector })
		exchange(t, ps, 1)
		cs, cg := h.carriers(t, w, ps)

		time.Sleep(2 * linger)
		synctest.Wait()
		if a, b := w.actors(); a != 0 || b != 0 {
			t.Fatalf("Status.Actors %d and %d after 2 × the linger, want every actor parked", a, b)
		}
		if l, p := w.registry(); l != int64(2*n) || p != int64(2*n) {
			t.Fatalf("registry: %d live and %d parked sessions, want %d each", l, p, 2*n)
		}
		ours, actors, byTop := goroutines()
		limit := base + cg + 10
		t.Logf("%d idle sessions on %d carriers per side (%s): %d rendr goroutines (baseline %d, carriers' %d, limit %d), %d actors:%s",
			n, cs, h.name, ours, base, cg, limit, actors, histogram(byTop))
		if actors != 0 || ours > limit {
			t.Fatalf("%d rendr goroutines (%d actors) for %d parked sessions, want 0 actors and ≤ %d", ours, actors, n, limit)
		}

		exchange(t, ps, 2) // parked sessions still carry data
		closeAll(t, ps)
		w.close()
	})
}

// TestParkedSessionsWakeForTraffic (M3 design §A8.3, R1-7, R1-15; L09): n
// parked selector sessions, in the two halves (and sizes) of
// TestIdleSessionsHoldNoGoroutine (dedicated carriers; the 4 MUX trunks of
// one Peer); 10 of them, picked at random (fixed seed), get data in turn,
// one byte from the dialer and its echo from the passive. The links are
// unshaped with a 5-ms one-way delay, so a frame written at t0 reaches the
// far carrier at t0 + 5 ms of virtual time; each byte must be read by the
// far application within 2 ms after that (a parked sender and a parked
// receiver are both kicked by the traffic: the Write rings the sender's
// actor, the frame the receiver's — on a trunk, through the trunk's
// reader, whose 999 other views stay parked). Before each wake every actor
// is parked (Status.Actors 0, 2n parked in the registry); 2 × the linger
// after the last one Status.Actors is back to 0 and every session parked.
func TestParkedSessionsWakeForTraffic(t *testing.T) {
	eachHalf(t, func(t *testing.T, h half) {
		n := h.population()
		w := h.world(t, n)
		ps := w.openMany(n, func(int) rendr.Mode { return rendr.ModeSelector })
		exchange(t, ps, 1)
		h.carriers(t, w, ps)
		time.Sleep(2 * linger)
		synctest.Wait()

		rng := rand.New(rand.NewPCG(1, 2))
		for k, i := range rng.Perm(n)[:10] {
			synctest.Wait()
			if a, b := w.actors(); a != 0 || b != 0 {
				t.Fatalf("wake %d: Status.Actors %d and %d before the traffic, want 0", k, a, b)
			}
			if _, p := w.registry(); p != int64(2*n) {
				t.Fatalf("wake %d: %d parked sessions before the traffic, want %d", k, p, 2*n)
			}
			s := ps[i]
			for j, dir := range [][2]*rendr.Conn{{s.d, s.p}, {s.p, s.d}} {
				t0 := time.Now()
				if _, err := dir[0].Write([]byte{byte(k)}); err != nil {
					t.Fatalf("wake %d (session %d): Write: %v", k, i, err)
				}
				var b [1]byte
				if _, err := dir[1].Read(b[:]); err != nil || b[0] != byte(k) {
					t.Fatalf("wake %d (session %d): Read %d, %v; want %d", k, i, b[0], err, k)
				}
				if d := time.Since(t0); d < oneWay || d > oneWay+2*time.Millisecond {
					t.Fatalf("wake %d (session %d, %s): the byte was read %v after its Write, want within 2 ms of its frame's arrival at +%v",
						k, i, [2]string{"A → B", "B → A"}[j], d, oneWay)
				}
			}
			time.Sleep(2 * linger) // the woken pair parks again
		}
		synctest.Wait()
		if a, b := w.actors(); a != 0 || b != 0 {
			t.Fatalf("Status.Actors %d and %d after the traffic, want 0", a, b)
		}
		if l, p := w.registry(); l != int64(2*n) || p != int64(2*n) {
			t.Fatalf("registry: %d live and %d parked sessions after the traffic, want %d each", l, p, 2*n)
		}
		closeAll(t, ps)
		w.close()
	})
}
