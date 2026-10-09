package carrier

import (
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestRetireAfterNoRoomCall (M3 design §A5.5, R1-1, M3-D7; found with
// TestMuxDetachAfterLocalViewEnd_R1_9): a view's planned retirement places
// its DETACH (or, for a passive view without a placed verdict, the
// safety-net refusal) after a Fill that placed nothing — M2's CLOSE rule,
// per view. On a MUX trunk a call can place nothing because other views
// used the batch's room (the control arena, the frame slots): that call
// decided nothing about the view's own last frames (drrTurn reports it
// stuck, and the view stays ready), so the retirement waits for the next
// call. Here view A owes control frames that leave 5 bytes of the round's
// control arena; the retiring view B, called after A in the same round,
// owes a frame that does not fit. Before the fix B's DETACH (5 bytes: it
// fits) or its refusal followed at once:
//   - dialer, live view B owing its FIN: the DETACH was placed and the FIN
//     never was (the view takes no Fill after its DETACH);
//   - passive, pending view B whose session rejected it: the safety net
//     answered CAPACITY CodeBacklog instead of the session's REJECTED.
//
// PASS: B's frame goes out in the next round, before its DETACH (dialer)
// or as its only frame (passive: the session's refusal, no DETACH); the
// trunk lives.
func TestRetireAfterNoRoomCall(t *testing.T) {
	t.Run("dialer live view: its FIN before its DETACH", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, p := muxRawDialer(t, nil)
			openLive(t, s, p, 2, 3)
			hold(t, s)
			fillArena(s.view(2).src)
			s.view(3).src.addCtl(hFrame{t: wire.TypeFin, payload: finInner(0)})
			s.view(3).c.Retire(wire.CloseRetire)
			s.view(2).c.Wake()
			s.tap.release()
			synctest.Wait()
			time.Sleep(10 * time.Millisecond)
			synctest.Wait()
			got := types(forHandle(s.tap.log(), 3))
			if len(got) < 2 || got[len(got)-2] != wire.TypeFin || got[len(got)-1] != wire.TypeDetach {
				t.Fatalf("the retiring view placed %v, want its FIN, then its DETACH", got)
			}
			if dead, cause, detail, _ := s.c.KillTrunkDeath(); dead {
				t.Fatalf("the trunk died: %v %s", cause, detail)
			}
		})
	})
	t.Run("passive pending view: the session's REJECTED", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, p := muxRawPassive(t, nil)
			var mv *mView
			s.admit = func(s *muxSide, v *Conn, hdr wire.Header, pl []byte) {
				mv = &mView{c: v, ep: &dEP{}, src: newVSource(s.env), bell: &hBell{}, done: &hBell{}}
				mv.ep.fill = mv.src.fill // no verdict yet
				v.OnDone(mv.done)
				s.add(mv)
				v.Start(mv.ep, mv.bell, StartOptions{})
			}
			_ = p.send(wire.TypeOpen, 0, 2, mOpenPayload(2, false))
			synctest.Wait()
			if mv == nil {
				t.Fatal("OPEN(2) not admitted")
			}
			hold(t, s)
			fillArena(s.v1.src)
			mv.src.mu.Lock()
			mv.src.resp, mv.src.respSt = wire.TypeOpenAck, wire.StatusRejected
			mv.src.mu.Unlock()
			mv.c.Retire(wire.CloseRetire) // its session ended with the verdict (refusePendingLocked)
			s.c.Wake()
			s.tap.release()
			synctest.Wait()
			time.Sleep(10 * time.Millisecond)
			synctest.Wait()
			got := forHandle(p.received2(), 2)
			if len(got) != 1 || got[0].h.Type != wire.TypeOpenAck {
				t.Fatalf("the rejected view placed %v, want its OPEN_ACK only", types(got))
			}
			if a, err := wire.ParseOpenAck(got[0].p); err != nil || a.Status != wire.StatusRejected {
				t.Fatalf("the rejected view answered %+v (%v), want the session's REJECTED", a, err)
			}
			wantState(t, mv.c, viewGone, "refusal placed")
			if dead, cause, detail, _ := s.c.KillTrunkDeath(); dead {
				t.Fatalf("the trunk died: %v %s", cause, detail)
			}
		})
	})
}

// hold makes the side's writer block in a Write (a round triggered by a
// small control frame of view 1), so that what the test queues next is
// served together in the following round.
func hold(t *testing.T, s *muxSide) {
	t.Helper()
	s.tap.hold()
	s.v1.src.addCtl(hFrame{t: wire.TypeRst, payload: rstPayload(wire.RstWithdrawn)})
	s.c.Wake()
	synctest.Wait()
}

// fillArena makes src owe control frames that leave 5 bytes of a round's
// control arena: 31 RSTs of 260 payload bytes and one of 127 (8,187 of
// ControlArena's 8,192). A FIN (8) or an OPEN_ACK (10) no longer fits; a
// DETACH (5) does.
func fillArena(src *vSource) {
	big := make([]byte, wire.RstFixedLen+wire.MaxMsg)
	big[4] = wire.MaxMsg
	for range 31 {
		src.addCtl(hFrame{t: wire.TypeRst, payload: big})
	}
	last := make([]byte, 127)
	last[4] = 127 - wire.RstFixedLen
	src.addCtl(hFrame{t: wire.TypeRst, payload: last})
}

// TestRetireRequestedDuringCall (M3 design §A5.5, R1-1, M3-D7; found with
// TestMuxDetachAfterLocalViewEnd_R1_9): a view's planned retirement follows
// a Fill that placed nothing, and only a call that started after the
// retirement was requested decides it (M2's writer reads the retirement
// before Fill). Here the session requests the retirement during a call
// that places nothing (its verdict or last frame arrives with the
// request): the next call places that frame, then the retirement follows.
// Before the fix the writer read the request after the call:
//   - passive pending view whose session rejects it during the call: the
//     safety net answered CAPACITY CodeBacklog instead of the session's
//     REJECTED (the scenario's rare failure, a reject cycle answered
//     CAPACITY code 2);
//   - dialer live view whose session queues its FIN and retires during the
//     call: its DETACH was placed and the FIN never was;
//   - a one-view MUX trunk (no view table; mux control queued: a refusal
//     answer), view 1 queueing its FIN and retiring during the call: the
//     same.
func TestRetireRequestedDuringCall(t *testing.T) {
	t.Run("passive pending view: the session's REJECTED", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, p := muxRawPassive(t, nil)
			var mv *mView
			s.admit = func(s *muxSide, v *Conn, hdr wire.Header, pl []byte) {
				mv = &mView{c: v, ep: &dEP{}, src: newVSource(s.env), bell: &hBell{}, done: &hBell{}}
				mv.ep.fill = mv.src.fill // no verdict yet
				v.OnDone(mv.done)
				s.add(mv)
				v.Start(mv.ep, mv.bell, StartOptions{})
			}
			_ = p.send(wire.TypeOpen, 0, 2, mOpenPayload(2, false))
			synctest.Wait()
			if mv == nil {
				t.Fatal("OPEN(2) not admitted")
			}
			armed := true
			mv.src.mu.Lock()
			mv.src.hook = func(c *Conn, b *Batch) {
				if !armed || b.ControlOnly() {
					return
				}
				armed = false
				// The session rejects it during this DRR call (src.mu is held).
				mv.src.resp, mv.src.respSt = wire.TypeOpenAck, wire.StatusRejected
				c.Retire(wire.CloseRetire)
			}
			mv.src.mu.Unlock()
			mv.c.Wake()
			synctest.Wait()
			time.Sleep(10 * time.Millisecond)
			synctest.Wait()
			if armed {
				t.Fatal("the view's DRR call never ran")
			}
			got := forHandle(p.received2(), 2)
			if len(got) != 1 || got[0].h.Type != wire.TypeOpenAck {
				t.Fatalf("the rejected view placed %v, want its OPEN_ACK only", types(got))
			}
			if a, err := wire.ParseOpenAck(got[0].p); err != nil || a.Status != wire.StatusRejected {
				t.Fatalf("the rejected view answered %+v (%v), want the session's REJECTED", a, err)
			}
			if dead, cause, detail, _ := s.c.KillTrunkDeath(); dead {
				t.Fatalf("the trunk died: %v %s", cause, detail)
			}
		})
	})
	t.Run("dialer live view: its FIN before its DETACH", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, p := muxRawDialer(t, nil)
			openLive(t, s, p, 2)
			mv := s.view(2)
			armed, finDue := true, false
			mv.src.mu.Lock()
			mv.src.hook = func(c *Conn, b *Batch) {
				if finDue {
					// The session's FIN, due from its end on: this call places it.
					finDue = false
					mv.src.ctl = append(mv.src.ctl, hFrame{t: wire.TypeFin, payload: finInner(0)})
				}
				if !armed || b.ControlOnly() {
					return
				}
				// The session ends during this DRR call, which places nothing;
				// its FIN is due from the next call on.
				armed, finDue = false, true
				c.Retire(wire.CloseRetire)
			}
			mv.src.mu.Unlock()
			mv.c.Wake()
			synctest.Wait()
			time.Sleep(10 * time.Millisecond)
			synctest.Wait()
			if armed {
				t.Fatal("the view's DRR call never ran")
			}
			got := types(forHandle(s.tap.log(), 2))
			if len(got) < 2 || got[len(got)-2] != wire.TypeFin || got[len(got)-1] != wire.TypeDetach {
				t.Fatalf("the retiring view placed %v, want its FIN, then its DETACH", got)
			}
		})
	})
	t.Run("one-view trunk: view 1's FIN before its DETACH", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, p := muxRawPassive(t, nil)
			releaseHeld(p, wire.SessionHandle)
			synctest.Wait()
			var armed atomic.Bool
			finDue := false
			src := s.v1.src
			src.mu.Lock()
			src.hook = func(c *Conn, b *Batch) {
				if finDue {
					finDue = false
					src.ctl = append(src.ctl, hFrame{t: wire.TypeFin, payload: finInner(0)})
				}
				if !armed.CompareAndSwap(true, false) {
					return
				}
				finDue = true // view 1's session ends during this call
				c.Retire(wire.CloseRetire)
			}
			src.mu.Unlock()
			armed.Store(true)
			// A malformed OPEN: its refusal answer is mux control queued for
			// the round that calls view 1's Fill (the one-view round with
			// control, which decides a planned retirement of view 1).
			bad := mOpenPayload(2, false)
			bad[16] = 9 // an unknown session kind: BAD_REQUEST
			_ = p.send(wire.TypeOpen, 0, 2, bad)
			synctest.Wait()
			time.Sleep(10 * time.Millisecond)
			synctest.Wait()
			if armed.Load() {
				_, cause, detail, _ := s.c.KillTrunkDeath()
				t.Fatalf("view 1's Fill never ran (trunk: %v %s)", cause, detail)
			}
			if s.c.ms.multi.Load() {
				t.Fatal("the trunk built a view table: not the one-view round")
			}
			got := types(forHandle(s.tap.log(), wire.SessionHandle))
			if len(got) < 2 || got[len(got)-2] != wire.TypeFin || got[len(got)-1] != wire.TypeDetach {
				t.Fatalf("view 1 placed %v, want its FIN, then its DETACH", got)
			}
		})
	})
}
