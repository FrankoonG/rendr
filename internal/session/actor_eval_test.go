package session

import (
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestActorSerializesDeathsDuringEvaluation_L09: the actor alone decides,
// and decides on one consistent view (L09). Each run makes a challenger
// win the quality evaluation and then, while snapshot publications keep
// ringing the actor (10⁵ rings over the test), kills the switch target
// and/or the active carrier at a different phase of the planned switch:
// the target's JOIN in flight or attached, the active during the JOIN, or
// both. Afterwards, from the event stream: every death of the active lane
// is followed by exactly one death migration from that lane, no migration
// ever names a carrier already reported dead (never published to a dead
// lane), the final active carrier is alive, the reported active always
// equals the routed one, and each death was handled in the step that saw
// it (< 10 ms virtual).
func TestActorSerializesDeathsDuringEvaluation_L09(t *testing.T) {
	const runs, rings = 1000, 100
	synctest.Test(t, func(t *testing.T) {
		var dmu sync.Mutex
		var dialStarts []time.Time
		hooks := &testhooks.Hooks{DialStart: func(int) {
			dmu.Lock()
			dialStarts = append(dialStarts, time.Now())
			dmu.Unlock()
		}}
		w := acNewWorld(t, hooks)
		defer w.teardown()
		w.a.p.Selector.Dwell = 50 * time.Millisecond
		w.a.p.Selector.Cooldown = 50 * time.Millisecond
		h := acNewHealth(3, w.a.p.Selector.Fresh)
		h.set(10*time.Millisecond, 0, 0)
		var links [3]*rendrtest.Link
		for i := range links {
			links[i] = w.link("p" + string(rune('0'+i)))
			links[i].SetDelay(time.Millisecond, 0)
		}
		a, b := w.open(ModeSelector, h, links[:]...)
		defer acFreshen(h)()

		factoryOf := func(id uint32) int {
			for _, c := range a.Status().Carriers {
				if c.ID == id {
					return int(c.Name[1] - '0')
				}
			}
			return -1
		}
		type kill struct {
			at     time.Time
			active uint32 // the active carrier when it was killed (0: the target only)
		}
		var kills []kill
		ringsSent := 0
		for run := range runs {
			synctest.Wait()
			act := acActive(a)
			fa := factoryOf(act)
			if act == 0 || fa < 0 {
				t.Fatalf("run %d: no active carrier: %+v", run, a.Status())
			}
			tgt := (fa + 1 + run%2) % 3
			rtt := []time.Duration{20 * time.Millisecond, 20 * time.Millisecond, 20 * time.Millisecond}
			time.Sleep(w.a.p.Selector.Cooldown) // the previous switch's cooldown is over
			h.set(rtt...)                       // no challenger: every dwell restarts
			synctest.Wait()
			rtt[tgt] = 2 * time.Millisecond
			h.set(rtt...)
			phase := run % 4
			delay := time.Millisecond // the target's JOIN is in flight
			if phase == 2 {
				delay = 20 * time.Millisecond // the target attached and is active
			}
			time.Sleep(w.a.p.Selector.Dwell + delay)
			for i := range rings {
				h.bump()
				ringsSent++
				if i != rings/2 {
					continue
				}
				now := time.Now()
				if phase != 1 {
					links[tgt].Kill()
					kills = append(kills, kill{at: now})
				}
				if phase == 1 || phase == 3 || (phase == 2 && factoryOf(acActive(a)) == tgt) {
					cur := act
					if phase == 2 {
						cur = acActive(a)
						if phase == 2 && links[tgt].Stats().Session.Killed == 0 {
							t.Fatalf("run %d: target not killed", run)
						}
					} else {
						links[fa].Kill()
					}
					kills = append(kills, kill{at: now, active: cur})
				}
			}
			acWaitFor(t, 10*time.Second, "a stable active carrier", func() bool {
				st := a.Status()
				joining := false
				for _, c := range st.Carriers {
					joining = joining || c.State == LaneJoining
				}
				return acActive(a) != 0 && !joining
			})
			if rep, routed, n := acRouted(a); rep != routed || n != 1 {
				t.Fatalf("run %d: reported active %d, routed %d, %d data lanes", run, rep, routed, n)
			}
		}
		if ringsSent < 1e4 {
			t.Fatalf("only %d snapshot rings", ringsSent)
		}

		// The event stream.
		w.a.ev.mu.Lock()
		evs := append([]Event(nil), w.a.ev.evs...)
		w.a.ev.mu.Unlock()
		activeDeaths := acCheckMigrations(t, a.ID(), evs)
		st := a.Status()
		if st.MigDeath != uint64(activeDeaths) || activeDeaths == 0 {
			t.Fatalf("death migrations %d, active deaths in the event stream %d", st.MigDeath, activeDeaths)
		}
		if st.MigQuality == 0 {
			t.Fatal("no quality switch happened: the evaluation was never exercised")
		}
		final := acActive(a)
		a.mu.Lock()
		alive := a.ctl.active != nil && a.ctl.active.id == final
		if alive {
			dead, _, _, _ := a.ctl.active.c.Death()
			alive = !dead
		}
		a.mu.Unlock()
		if !alive {
			t.Fatalf("final active %d is not alive", final)
		}
		// Each death of the active was handled at once: its CarrierDown
		// within 10 ms of the kill, and either a fallback in the same step
		// or the race's first attempt within 10 ms.
		for _, k := range kills {
			if k.active == 0 {
				continue
			}
			var down time.Time
			for _, ev := range evs {
				if ev.Kind == EventCarrierDown && ev.Carrier == k.active {
					down = ev.Time
					break
				}
			}
			if down.IsZero() || down.Sub(k.at) >= 10*time.Millisecond {
				t.Fatalf("death of active %d killed at %v observed at %v", k.active, k.at, down)
			}
		}
		dmu.Lock()
		starts := len(dialStarts)
		dmu.Unlock()
		if starts < runs {
			t.Fatalf("%d dial attempts over %d runs: the switches did not run", starts, runs)
		}
		if we, re := acTransfer(a, b, 1<<20, 9, false); we != nil || re != nil {
			t.Fatalf("transfer after the runs: %v %v", we, re)
		}
		t.Logf("%d runs, %d rings, %d active deaths, %d quality switches, %d dial attempts", runs, ringsSent, activeDeaths, st.MigQuality, starts)
	})
}

// acCheckMigrations replays a dialer selector's event stream: the first
// CarrierUp is the active carrier; a quality migration moves it; the death
// of the active must be followed by exactly one death migration from it
// before the next death of an active; no migration names a carrier already
// reported dead. It returns the number of deaths of the active carrier.
func acCheckMigrations(t testing.TB, sid [16]byte, evs []Event) int {
	t.Helper()
	var cur, pending uint32
	started := false
	dead := map[uint32]bool{}
	deaths := 0
	for i, ev := range evs {
		if ev.Session != sid {
			continue
		}
		switch ev.Kind {
		case EventCarrierUp:
			if !started {
				started, cur = true, ev.Carrier
			}
		case EventCarrierDown:
			dead[ev.Carrier] = true
			if ev.Carrier == cur {
				if pending != 0 {
					t.Fatalf("event %d: active %d died while the death of %d was not yet migrated", i, cur, pending)
				}
				pending, cur = cur, 0
				deaths++
			}
		case EventMigration:
			if dead[ev.To] {
				t.Fatalf("event %d: migration %d → %d to a carrier reported dead", i, ev.From, ev.To)
			}
			if ev.Cause == carrier.CauseQuality {
				if ev.From != cur || pending != 0 {
					t.Fatalf("event %d: quality migration from %d while the active is %d (pending death %d)", i, ev.From, cur, pending)
				}
			} else {
				if pending == 0 || ev.From != pending {
					t.Fatalf("event %d: death migration from %d, want the dead active %d", i, ev.From, pending)
				}
				pending = 0
			}
			cur = ev.To
		}
	}
	if pending != 0 {
		t.Fatalf("the death of active %d was never migrated", pending)
	}
	return deaths
}
