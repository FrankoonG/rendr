package carrier

import (
	"fmt"
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
//     exchange (its detail; the DETACH bound gives the same cause).
//   - view 1: the one view of a trunk without a view table owes 12 FINs
//     (more than the window) and retires; all 12 reach the peer before the
//     view retires.
//
// The trunk lives throughout.
func TestMuxRetireWaitsForRelRoom_L30(t *testing.T) {
	const detachDone = "retired: DETACH exchange complete" // completeLocked's detail, not "retired: DETACH bound"
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
				if dead, cause, detail, _ := d.view(h).c.Death(); !dead || cause != CauseRetired || detail != detachDone {
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
			if dead, cause, detail, _ := d.c.Death(); !dead || cause != CauseRetired || detail != detachDone {
				t.Fatalf("view 1 ended %v (%v %s), want retired by the DETACH exchange", dead, cause, detail)
			}
		})
	})
}

// relOwedEP is a capEP whose session also owes a reliable frame (an RST)
// in every call, control pass included: on a datagram batch without REL
// room (capTrunk's) the window refuses it every time.
type relOwedEP struct {
	*capEP
	refused int
}

func (e *relOwedEP) Fill(c *Conn, b *Batch) {
	if !b.AddRst(c.Handle(), &wire.Rst{Code: wire.RstIdle}) && b.relRefused() {
		e.refused++
	}
	e.capEP.Fill(c, b)
}

// TestMuxDRRCutTurnRelRefusedKeepsRate (§A5.3 amended, R1-1; the m6-design
// decision on core defect A, 2026-10-21): a call the REL window refused a
// frame of is not drained (TestMuxRetireWaitsForRelRoom_L30), and the
// refusal changes none of the DRR rules. View 1 places whole 1016-B DGRAMs
// on a datagram batch: 64 of them (MaxBatchFrames) fill the batch with
// 512 B of its 64-KiB turn left, less than a frame, so in the next round
// the rest of the cut turn places nothing, the turn ends and the next
// starts at once. View 2 is idle and woken every round, so every round is
// a DRR round (one ready view is filled without quotas, oneViewFill).
// PASS, with and without an RST the REL window refuses in every call of
// view 1: view 1 places 64 DGRAMs in each of 8 rounds without any wake of
// its own, the rest of its cut turn (512 B) and then a fresh turn in the
// same round. Keeping the deficit and the cut-turn mark of a REL-refused
// call instead dropped view 1 from the round, and its datagrams waited for
// a RACK (2208ef2).
func TestMuxDRRCutTurnRelRefusedKeepsRate(t *testing.T) {
	const frame = 1016 // 64·1016 = 65,024: the batch ends 512 B short of the quantum
	for _, owes := range []bool{false, true} {
		t.Run(fmt.Sprintf("REL frame owed %v", owes), func(t *testing.T) {
			_, views, eps, pool, round := capTrunk(2, 256<<10)
			pool.dgram = 1400
			eps[0].frame, eps[0].dgram = frame, true
			eps[1].avail = 0
			ep := &relOwedEP{capEP: eps[0]}
			if owes {
				views[0].ep = ep
			}
			for r := 1; r <= 8; r++ {
				if r == 1 {
					round(1<<30, false, 0, 1)
				} else {
					round(1<<30, false, 1)
				}
				if got := pool.served[1]; got != MaxBatchFrames*frame {
					t.Fatalf("round %d: view 1 placed %d bytes, want %d DGRAMs (%d B) (it has data; its calls saw room %v; RST refused %d times)",
						r, got, MaxBatchFrames, MaxBatchFrames*frame, pool.rooms[1], ep.refused)
				}
				if want := []int{defMuxQuantum - MaxBatchFrames*frame, defMuxQuantum}; r > 1 && !slices.Equal(pool.rooms[1], want) {
					t.Fatalf("premise: round %d's calls of view 1 saw room %v, want %v (the rest of its cut turn, then a fresh turn)", r, pool.rooms[1], want)
				}
			}
			if owes && ep.refused < 8 {
				t.Fatalf("premise: the RST was refused %d times over 8 rounds, want every round", ep.refused)
			}
		})
	}
}
