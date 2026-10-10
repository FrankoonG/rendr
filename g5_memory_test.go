package rendr

import (
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// TestIdleSessionMemory (README "Memory"; design §0.14 B18, R16): the
// idle cost per side that the README states, measured as the G5 rows
// measure it (g5MeasureIdle over net.Pipe carriers, one virtual idle
// minute, garbage collected before each sample) but with a few hundred
// sessions per shape so that the per-session figures settle: the live
// heap plus the growth of the stack spans (runtime.MemStats.StackInuse)
// that n idle session pairs added (a shrink of the spans counts 0),
// divided by n and by the two sides.
// Shapes: a selector session with one dedicated carrier, a three-member
// bond on dedicated carriers, and a selector session added to one live
// MUX trunk (the warm-up session's; default Props).
//
// PASS: the goroutines per pair are exact (4 and 12: a reader and a
// writer per dedicated carrier on each side; 0 for a session added to a
// trunk: the trunk's goroutines are the warm-up session's and every actor
// is parked); a session added to a trunk adds no reader stage; and the
// per-side cost stays within the bounds below. The bounds sit about a
// third above the largest figures observed (selector 73, bond3 184 and
// selector-on-trunk 8 KiB per side, also under -race; the live heap per
// pair is stable to a few percent, the growth of the stack spans moves
// the selector figure between about 60 and 73 KiB), so a README figure
// that grows by more than about a third fails here, and a smaller drift
// does not.
// Every row checks the reader stages: one per dedicated carrier
// (g5StageBytes each), none for a session added to a trunk.
// Load: the sessions opened (actor resumptions counted while opening).
func TestIdleSessionMemory(t *testing.T) {
	rows := []struct {
		c       g5IdleCase
		perSide float64 // bound in bytes per side
	}{
		{g5IdleCase{name: "selector", mode: ModeSelector, factories: 1, goroutines: 4}, 100 << 10},
		{g5IdleCase{name: "bond3", mode: ModeBond, factories: 3, goroutines: 12}, 240 << 10},
		{g5IdleCase{name: "selector-on-trunk", mode: ModeSelector, factories: 1, shared: true}, 12 << 10},
	}
	const n = 200 // < MuxMaxViews (256): every added session shares the warm-up session's trunk
	for _, r := range rows {
		t.Run(r.c.name, func(t *testing.T) {
			g5EnableBlockProfile(t)
			synctest.Test(t, func(t *testing.T) {
				var parks atomic.Int64
				e := g5NewPair(t, r.c, &parks)
				cost := g5MeasureIdle(t, e, &parks, r.c, n, 30*time.Second, time.Minute, synctest.Wait, nil)
				side := (cost.heap + max(cost.stackSpans, 0)) / 2 // the spans may shrink: freed stacks of earlier goroutines
				t.Logf("%s, %d sessions: %.2f goroutines per pair; per side %.1f KiB (heap %.1f KiB and stack spans %+.1f KiB per pair; stack in use %.1f KiB per pair); reader stages %.0f B per side",
					r.c.name, n, cost.goroutines, side/1024, cost.heap/1024, cost.stackSpans/1024, cost.stackUsed/1024, cost.stages)
				if cost.opening < 1 {
					t.Errorf("load: %.2f actor resumptions per pair while opening: the sessions did not run", cost.opening)
				}
				if cost.goroutines != r.c.goroutines {
					t.Errorf("%.2f goroutines per pair, want %v", cost.goroutines, r.c.goroutines)
				}
				want := float64(r.c.carriers() * g5StageBytes)
				if r.c.shared {
					want = 0
				}
				if cost.stages != want {
					t.Errorf("%.0f bytes of reader stages per side and session, want %.0f", cost.stages, want)
				}
				if side > r.perSide {
					t.Errorf("%.1f KiB per side and session, want at most %.0f KiB", side/1024, r.perSide/1024)
				}
				e.close()
			})
		})
	}
}
