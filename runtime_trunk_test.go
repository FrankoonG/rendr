package rendr

import (
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// TestPassiveTrunkGoroutines (F44's two goroutines per carrier; L52; the
// passive twin of carrier TestPoolTrunkGoroutines): a passive MUX trunk
// costs its reader and writer only — the trunk set's bookkeeping runs at
// the trunk's Done (carrier OnTrunkDone), not on a goroutine that waits
// for it. Two Peers with one Link each put each session on its own trunk:
// once the actors are parked, the second trunk adds exactly four rendr
// goroutines (a reader and a writer on each end) and none of package rendr
// itself. Its end still runs the bookkeeping: the passive set drops the
// trunk after its last view retired it, and after Runtime.Close no rendr
// goroutine is left. Observed before the change: five goroutines per
// trunk, the fifth the passive Runtime's watchTrunk.
func TestPassiveTrunkGoroutines(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a", "b")
		parked := func() bool { return e.d.Status().Actors == 0 && e.p.Status().Actors == 0 }
		root := func(by map[string]int) int {
			n := 0
			for fn, k := range by {
				if strings.HasPrefix(fn, "github.com/FrankoonG/rendr/v2.") {
					n += k
				}
			}
			return n
		}

		da, qa := e2eOpen(t, e.peer(e.links[0]), e.ln, DialOptions{})
		mxWait(t, 30*time.Second, "one passive trunk, actors parked", func() bool {
			return len(mxTrunkSet(e.p)) == 1 && e.d.Status().Mux.Carriers == 1 && parked()
		})
		synctest.Wait()
		n1, by1 := rendrGoroutines()

		db, qb := e2eOpen(t, e.peer(e.links[1]), e.ln, DialOptions{})
		mxWait(t, 30*time.Second, "two passive trunks, actors parked", func() bool {
			return len(mxTrunkSet(e.p)) == 2 && e.d.Status().Mux.Carriers == 2 && parked()
		})
		synctest.Wait()
		n2, by2 := rendrGoroutines()
		if n2-n1 != 4 || root(by2) != root(by1) {
			t.Fatalf("a second trunk added %d rendr goroutines (%d of package rendr), want 4 (reader and writer per end) and none of package rendr:\nbefore %v\nafter  %v",
				n2-n1, root(by2)-root(by1), by1, by2)
		}

		// The bookkeeping at the trunk's Done: the session on link b ends,
		// the dialer retires the trunk at its last view, and the passive
		// set drops it.
		db.Close()
		qb.Close()
		mxWait(t, 30*time.Second, "the passive set dropped the retired trunk", func() bool {
			return len(mxTrunkSet(e.p)) == 1 && e.p.Status().Mux.Carriers == 1
		})
		e2eExchange(t, da, qa, 64<<10, 1) // the other trunk carries on
		da.Close()
		qa.Close()
		e.close()
		synctest.Wait()
		if n, by := rendrGoroutines(); n != 0 {
			t.Fatalf("%d rendr goroutines after both Runtimes closed: %v", n, by)
		}
	})
}
