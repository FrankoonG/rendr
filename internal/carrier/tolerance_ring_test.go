package carrier

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestToleranceRingRefusalsKeepRetiredHandles (§A3.3 tolerance ring,
// §A5.5, M3-D6; invariant 6): a passive view that placed its DETACH and
// retired at the DETACH bound keeps its handle tolerated until the
// dialer's late DETACH comes, however many refusals the trunk answers
// meanwhile. A refused handle's entry is needed only while a crossing RST
// or DETACH can be in flight, and the dialer sends nothing more for a
// refusal it read, so most refusal entries are never cleared: with one
// ring of MuxMaxViews entries for both kinds, a burst of refusals pushed
// the retired handle out, and the dialer's legal DETACH killed the healthy
// trunk with protocol_violation "DETACH for an unknown handle" (found by
// TestMuxDetachAfterLocalViewEnd_R1_9 once its trunks lived long: a
// retired handle tolerated for 0.8 s while 412 refusals were answered).
// Here the passive answers MuxMaxViews + 1 refusals after the retirement,
// then the dialer's DETACH for the retired handle arrives; a refused
// handle's crossing DETACH is still tolerated, and a DETACH for a handle
// the trunk never tolerated still kills it.
func TestToleranceRingRefusalsKeepRetiredHandles(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const h = 2
		s, p := muxRawPassive(t, nil)
		var mv *mView
		s.admit = func(s *muxSide, v *Conn, hdr wire.Header, pl []byte) {
			if v.Handle() != h {
				v.Refuse(v.Handle(), Answer{Type: wire.TypeOpenAck, Status: wire.StatusRejected, Code: 9})
				return
			}
			mv = &mView{c: v, ep: &dEP{}, src: newVSource(s.env), bell: &hBell{}, done: &hBell{}}
			mv.ep.fill = mv.src.fill
			v.OnDone(mv.done)
			s.add(mv)
			v.Start(mv.ep, mv.bell, StartOptions{})
		}
		_ = p.send(wire.TypeOpen, 0, h, mOpenPayload(h, false))
		synctest.Wait()
		if mv == nil {
			t.Fatal("OPEN(2) not admitted")
		}
		// The session answers OK and its view ends inside that call: the
		// passive places OPEN_ACK and DETACH; the dialer stays silent, so
		// the view retires at the DETACH bound and its handle is tolerated.
		killed := false
		mv.src.mu.Lock()
		mv.src.resp, mv.src.respSt = wire.TypeOpenAck, wire.StatusOK
		mv.src.noGo = true
		mv.src.hook = func(c *Conn, b *Batch) {
			if !killed {
				killed = true
				c.Kill(CauseLocalClose, "ended after its OK")
			}
		}
		mv.src.mu.Unlock()
		mv.c.Wake()
		synctest.Wait()
		time.Sleep(drainMax + 10*time.Millisecond)
		synctest.Wait()
		waitDone(t, mv.c.Done(), "view 2")
		if got := types(forHandle(p.received2(), h)); len(got) != 2 || got[0] != wire.TypeOpenAck || got[1] != wire.TypeDetach {
			t.Fatalf("stimulus: the passive placed %v for handle %d, want OPEN_ACK and DETACH", got, h)
		}
		s.c.mx.Lock()
		retired := s.c.lookupLocked(h) == nil
		s.c.mx.Unlock()
		if !retired {
			t.Fatal("stimulus: view 2 did not retire at the DETACH bound")
		}
		// A burst of refusals, answered and written in turn.
		n := s.c.trunk.maxViews() + 1
		last := uint32(h + n)
		for hh := uint32(h + 1); hh <= last; hh++ {
			_ = p.send(wire.TypeOpen, 0, hh, mOpenPayload(byte(hh), false))
			if hh%16 == 0 {
				synctest.Wait()
			}
		}
		synctest.Wait()
		if got := len(forHandle(p.received2(), last)); got != 1 {
			t.Fatalf("stimulus: handle %d got %d answers, want its refusal", last, got)
		}
		if dead, cause, detail, _ := s.c.KillTrunkDeath(); dead {
			t.Fatalf("stimulus: the trunk died during the refusals (%v: %s)", cause, detail)
		}
		_ = p.send(wire.TypeDetach, 0, 0, detachPayload(h, wire.DetachEnded))
		synctest.Wait()
		if dead, cause, detail, _ := s.c.KillTrunkDeath(); dead {
			t.Fatalf("the dialer's late DETACH for the retired handle killed the trunk (%v: %s)", cause, detail)
		}
		_ = p.send(wire.TypeDetach, 0, 0, detachPayload(last, wire.DetachEnded))
		synctest.Wait()
		if dead, cause, detail, _ := s.c.KillTrunkDeath(); dead {
			t.Fatalf("a crossing DETACH for a refused handle killed the trunk (%v: %s)", cause, detail)
		}
		_ = p.send(wire.TypeDetach, 0, 0, detachPayload(last-1, wire.DetachEnded))
		_ = p.send(wire.TypeDetach, 0, 0, detachPayload(last+100, wire.DetachEnded))
		synctest.Wait()
		if dead, cause, _, _ := s.c.KillTrunkDeath(); !dead || cause != CauseProtocolViolation {
			t.Fatalf("a DETACH for a handle never tolerated: trunk dead %v cause %v, want protocol_violation", dead, cause)
		}
	})
}
