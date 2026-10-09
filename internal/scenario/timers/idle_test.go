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
// pumps.
func population() int {
	if raceEnabled {
		return 250
	}
	return 1000
}

// dedicated is a one-factory world whose factory has Props.CheapSubflow,
// so every session dials its own carrier (M3-D2): the dedicated half of
// the idle scenarios. The MUX half (n sessions over the ⌈n/256⌉ trunks of
// one Peer, R1-15) belongs to WP12b.
func dedicated(t testing.TB, n int) *world {
	return newWorld(t, worldOpts{n: n}, linkSpec{name: "a", oneWay: oneWay, props: rendr.Props{CheapSubflow: true}})
}

// TestIdleSessionsHoldNoGoroutine (M3 design §A8.3, R1-15; plan:649, L52),
// the dedicated half: n idle selector sessions (1,000; 250 under -race),
// each on its own carrier (CheapSubflow), exchange one byte each way and
// then stay idle. After 2 × the actor linger every actor on both ends is
// parked: Status.Actors is 0 on both Runtimes, the registry counts 2n live
// and 2n parked sessions, no actor goroutine runs, and the rendr
// goroutines are at most the baseline (both Runtimes, the Listener and the
// Peer before any session) + the carriers' goroutines (a reader and a
// writer per carrier per side) + 10. The parked sessions still carry a
// second byte each way; closing them and the Runtimes leaves nothing.
func TestIdleSessionsHoldNoGoroutine(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := population()
		w := dedicated(t, n)
		synctest.Wait()
		base, _, _ := goroutines()
		ps := w.openMany(n, func(int) rendr.Mode { return rendr.ModeSelector })
		exchange(t, ps, 1)
		cs := carriers(ps)
		if cs != n {
			t.Fatalf("premise: %d dialer carriers for %d dedicated sessions", cs, n)
		}

		time.Sleep(2 * linger)
		synctest.Wait()
		if a, b := w.actors(); a != 0 || b != 0 {
			t.Fatalf("Status.Actors %d and %d after 2 × the linger, want every actor parked", a, b)
		}
		if l, p := w.registry(); l != int64(2*n) || p != int64(2*n) {
			t.Fatalf("registry: %d live and %d parked sessions, want %d each", l, p, 2*n)
		}
		ours, actors, byTop := goroutines()
		limit := base + 4*cs + 10 // a reader and a writer per carrier per side
		t.Logf("%d idle sessions on %d carriers per side: %d rendr goroutines (baseline %d, limit %d), %d actors:%s",
			n, cs, ours, base, limit, actors, histogram(byTop))
		if actors != 0 || ours > limit {
			t.Fatalf("%d rendr goroutines (%d actors) for %d parked sessions, want 0 actors and ≤ %d", ours, actors, n, limit)
		}

		exchange(t, ps, 2) // parked sessions still carry data
		closeAll(t, ps)
		w.close()
	})
}

// TestParkedSessionsWakeForTraffic (M3 design §A8.3, R1-7; L09), the
// dedicated half: n parked selector sessions (1,000; 250 under -race), each
// on its own carrier; 10 of them, picked at random (fixed seed), get data
// in turn, one byte from the dialer and its echo from the passive. The
// links are unshaped with a 5-ms one-way delay, so a frame written at t0
// reaches the far carrier at t0 + 5 ms of virtual time; each byte must be
// read by the far application within 2 ms after that (a parked sender and
// a parked receiver are both kicked by the traffic: the Write rings the
// sender's actor, the frame the receiver's). Before each wake every actor
// is parked (Status.Actors 0, 2n parked in the registry); 2 × the linger
// after the last one Status.Actors is back to 0 and every session parked.
func TestParkedSessionsWakeForTraffic(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := population()
		w := dedicated(t, n)
		ps := w.openMany(n, func(int) rendr.Mode { return rendr.ModeSelector })
		exchange(t, ps, 1)
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
