package carrier

import (
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestMuxRetireWaitsForRelRoom_L30 (§A5.5, M3-D6; L30; the m6-design
// decision on core defect A, 2026-10-21): a view's planned retirement
// places its DETACH after a Fill that placed nothing because nothing was
// left — never after one the REL window refused a frame of. A view whose
// last frames wait for REL room stays fillable, the RACK that frees room
// readies it (the REL list) and its DETACH follows those frames.
//
//   - views: 16 views of a datagram trunk (REL window 8) each owe one RST
//     and retire in one instant (16 sessions ending together); every RST
//     reaches its passive view, and every view retires by the DETACH
//     exchange.
//   - view 1: the one view of a trunk without a view table owes 12 FINs
//     (more than the window) and retires; all 12 reach the peer before the
//     view retires.
//
// The trunk lives throughout.
func TestMuxRetireWaitsForRelRoom_L30(t *testing.T) {
	t.Run("views", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			d, p, ia, ib := dgMuxPair(t, 1200, nil)
			ia.setDelay(5 * time.Millisecond)
			ib.setDelay(5 * time.Millisecond)
			var hs []uint32
			for i := range 16 {
				h := uint32(2 + i)
				d.open(t, wire.TypeOpen, byte(h))
				hs = append(hs, h)
			}
			time.Sleep(time.Second)
			synctest.Wait()
			for _, h := range hs {
				mv := d.view(h)
				mv.src.addCtl(hFrame{t: wire.TypeRst, payload: rstPayload(wire.RstIdle)})
				mv.c.Retire(wire.CloseRetire)
			}
			for _, h := range hs {
				waitDone(t, d.view(h).c.Done(), "a retiring view's Done")
			}
			var lost []uint32
			for _, h := range hs {
				rst := slices.ContainsFunc(p.view(h).ep.controls(), func(c wire.Header) bool { return c.Type == wire.TypeRst })
				if !rst {
					lost = append(lost, h)
				}
				if dead, cause, detail, _ := d.view(h).c.Death(); !dead || cause != CauseRetired {
					t.Errorf("view %d ended %v (%v %s), want retired by the DETACH exchange", h, dead, cause, detail)
				}
			}
			if len(lost) != 0 {
				t.Fatalf("L30: the RSTs of views %v never reached the peer: their DETACH left without them", lost)
			}
			if dead, cause, detail, _ := d.c.KillTrunkDeath(); dead {
				t.Fatalf("the trunk died: %v %s", cause, detail)
			}
		})
	})
	t.Run("view 1", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			d, p, ia, ib := dgMuxPair(t, 1200, nil)
			ia.setDelay(5 * time.Millisecond)
			ib.setDelay(5 * time.Millisecond)
			time.Sleep(time.Second)
			synctest.Wait()
			const fins = 12
			for k := range fins {
				d.v1.src.addCtl(hFrame{t: wire.TypeFin, payload: finInner(uint64(k))})
			}
			d.c.Retire(wire.CloseRetire)
			d.c.Wake()
			waitDone(t, d.c.Done(), "view 1's Done")
			n := 0
			for _, c := range p.v1.ep.controls() {
				if c.Type == wire.TypeFin {
					n++
				}
			}
			if n != fins {
				t.Fatalf("L30: %d of view 1's %d FINs reached the peer before it retired", n, fins)
			}
			if dead, cause, detail, _ := d.c.Death(); !dead || cause != CauseRetired {
				t.Fatalf("view 1 ended %v (%v %s), want retired by the DETACH exchange", dead, cause, detail)
			}
		})
	})
}
