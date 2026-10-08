package session

import (
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// g4Mark is one failed-mark report of the actor to the health layer.
type g4Mark struct {
	i      int
	reason string
	dated  bool      // MarkFailedAt (else MarkFailed)
	at     time.Time // the failure time MarkFailedAt was given
	called time.Time // when the call ran
}

// g4DatedHealth is acHealth that also offers the dated mark of
// carrier.Health (datedMarker) and records every report.
type g4DatedHealth struct {
	*acHealth
	mu    sync.Mutex
	marks []g4Mark
}

func (h *g4DatedHealth) MarkFailed(i int, reason string) {
	h.record(g4Mark{i: i, reason: reason, called: time.Now()})
	h.acHealth.MarkFailed(i, reason)
}

func (h *g4DatedHealth) MarkFailedAt(i int, reason string, at time.Time) {
	h.record(g4Mark{i: i, reason: reason, dated: true, at: at, called: time.Now()})
	h.acHealth.MarkFailed(i, reason)
}

func (h *g4DatedHealth) record(m g4Mark) {
	h.mu.Lock()
	h.marks = append(h.marks, m)
	h.mu.Unlock()
}

func (h *g4DatedHealth) of(i int) []g4Mark {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []g4Mark
	for _, m := range h.marks {
		if m.i == i {
			out = append(out, m)
		}
	}
	return out
}

// TestActorDeathMarkDatedByDeath_MARKAT (W4-MARKAT): the failed mark of a
// carrier death reaches the health layer dated by the carrier's death
// time, not by the actor step that handles it. A bond of two members: the
// actor is held in the event sink of member p1's death step while member
// p2 dies at T; the actor handles p2's death 50 ms later, and the health
// layer is told the failure happened at T (p2's DeathAt), so a probe round
// trip of p2 committed in those 50 ms still clears or prevents the mark
// (carrier.Health.MarkFailedAt). The session then recovers and carries a
// verified transfer.
func TestActorDeathMarkDatedByDeath_MARKAT(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		h := &g4DatedHealth{acHealth: acNewHealth(2, w.a.p.Selector.Fresh)}
		h.set(10*time.Millisecond, 20*time.Millisecond)
		l1, l2 := w.link("p1"), w.link("p2")
		a, b := w.open(ModeBond, h, l1, l2)
		ids := map[string]uint32{}
		acWaitFor(t, 2*time.Second, "both members live", func() bool {
			for _, c := range a.Status().Carriers {
				if c.State == LaneActive || c.State == LaneMember {
					ids[c.Name] = c.ID
				}
			}
			return ids["p1"] != 0 && ids["p2"] != 0
		})
		if len(h.of(0))+len(h.of(1)) != 0 {
			t.Fatalf("marks before any death: %+v %+v", h.of(0), h.of(1))
		}

		held, release := make(chan struct{}, 1), make(chan struct{})
		hold := func(ev Event) {
			if ev.Kind == EventCarrierDown && ev.Carrier == ids["p1"] {
				held <- struct{}{}
				<-release
			}
		}
		w.a.ev.hold.Store(&hold)
		l1.Kill()
		<-held // the actor is held after p1's death step
		died := time.Now()
		l2.Kill()
		time.Sleep(50 * time.Millisecond)
		synctest.Wait()
		if n := len(h.of(1)); n != 0 {
			t.Fatalf("p2's death was reported while the actor was held: %+v", h.of(1))
		}
		w.a.ev.hold.Store(nil)
		close(release)
		acWaitFor(t, time.Second, "p2's death reported", func() bool { return len(h.of(1)) > 0 })

		var dead *CarrierStatus
		st := a.Status()
		for i := range st.Carriers {
			if st.Carriers[i].ID == ids["p2"] {
				dead = &st.Carriers[i]
			}
		}
		if dead == nil || dead.State != LaneDead || !dead.DeathCause.Death() || !dead.DeathAt.Equal(died) {
			t.Fatalf("stimulus: p2's carrier %+v, want dead by a death cause at %v", dead, died)
		}
		m := h.of(1)[0]
		if !m.dated || !m.at.Equal(died) || m.reason != dead.DeathCause.String() {
			t.Fatalf("p2's death reported as %+v, want dated %v (%s)", m, died, dead.DeathCause)
		}
		if m.called.Sub(died) < 50*time.Millisecond {
			t.Fatalf("stimulus: the report ran %v after the death, want the 50 ms hold", m.called.Sub(died))
		}
		if pm := h.of(0); len(pm) == 0 || !pm[0].dated {
			t.Fatalf("p1's death reported as %+v, want dated", pm)
		}

		// Load and integrity: the session recovers and carries every byte.
		acWaitFor(t, 3*time.Second, "a live member again", func() bool {
			for _, c := range a.Status().Carriers {
				if c.State == LaneActive || c.State == LaneMember {
					return true
				}
			}
			return false
		})
		if we, re := acTransfer(a, b, 1<<20, 4, false); we != nil || re != nil {
			t.Fatalf("transfer after the deaths: write %v, read %v", we, re)
		}
	})
}
