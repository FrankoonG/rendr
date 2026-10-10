package session

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// TestLaneByIDPrefersCurrent (R1-6 rule 4): a session that returned to a
// MUX trunk it used before may hold, for a moment, the lane of its old view
// — ended, or detached by the peer, and not yet reaped — and the lane of
// its new view, both with the trunk's CarrierID. SCHED routing
// (laneByIDLocked, passiveRouteLocked) must take the current one in either
// order, and still find a lone ended lane (M2's first match). The lanes'
// carriers are real: one killed (ended) and one live, from a bond session
// over two links.
func TestLaneByIDPrefersCurrent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		l1, l2 := w.link("p1"), w.link("p2")
		a, _ := w.open(ModeBond, nil, l1, l2)
		var dead, live *carrier.Conn
		acWaitFor(t, 3*time.Second, "both members", func() bool {
			a.mu.Lock()
			defer a.mu.Unlock()
			if len(a.lanes) != 2 {
				return false
			}
			dead, live = a.lanes[0].c, a.lanes[1].c
			return true
		})
		l1.Kill()
		acWaitFor(t, 3*time.Second, "the killed member ends", func() bool {
			ended, _, _, _ := dead.Death()
			return ended
		})
		if ended, _, _, _ := live.Death(); ended {
			t.Fatal("the other member ended too (stimulus)")
		}
		const id = 77 // one trunk: both lanes carry its CarrierID
		old := &lane{c: dead, port: dead, id: id}
		cur := &lane{c: live, port: live, id: id}
		for _, order := range [][]*lane{{old, cur}, {cur, old}} {
			x := &actor{s: &Session{lanes: order}}
			if got := x.laneByIDLocked(id); got != cur {
				t.Fatalf("lanes [%p %p]: laneByIDLocked chose %p, want the current lane %p (not the ended %p)", order[0], order[1], got, cur, old)
			}
		}
		x := &actor{s: &Session{lanes: []*lane{old}}}
		if got := x.laneByIDLocked(id); got != old {
			t.Fatalf("a lone ended lane: %p, want %p", got, old)
		}
		if got := x.laneByIDLocked(id + 1); got != nil {
			t.Fatalf("an unknown id: %p, want nil", got)
		}
	})
}
