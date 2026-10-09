package carrier

import (
	"context"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestMuxControlOnlyCallStaysReady (WP10 amendment to R1-1 rule 3): a DRR
// call that placed control frames only (an ACK, no payload) did not decide
// that its view is idle — a session marks its lane idle only after a Fill
// that placed nothing, and its producers wake only idle lanes — so the
// writer calls that view again in the next round by itself: data its
// producer queued after that call, without any Wake, is placed. Without
// the rule the view left the ready set and its data waited for an
// unrelated wakeup (the 1000-session echo of the root package stalled into
// Linger resets).
func TestMuxControlOnlyCallStaysReady(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var armed atomic.Bool
		var v3 *mView
		s, p := muxRawDialer(t, func(env *Env) {
			env.Hooks = &testhooks.Hooks{AfterViewFill: func(_, h uint32) {
				if h == 3 && armed.CompareAndSwap(true, false) {
					v3.src.offer(4096) // queued after the call, no Wake (the lane is not idle)
				}
			}}
		})
		openLive(t, s, p, 2, 3)
		v2, mv3 := s.view(2), s.view(3)
		v3 = mv3
		synctest.Wait()
		mv3.src.mu.Lock()
		mv3.src.hook = func(c *Conn, b *Batch) {
			if !b.ControlOnly() && mv3.src.end == mv3.src.next && len(mv3.src.ctl) == 0 && !armed.Load() && mv3.src.fills.Load() > 0 {
				mv3.src.ctl = append(mv3.src.ctl, hFrame{t: wire.TypeAck, payload: ackPayload()})
				armed.Store(true)
				mv3.src.hook = nil
			}
		}
		mv3.src.mu.Unlock()
		v2.src.offer(64 << 10) // a round with a DRR pass over both views
		v2.c.Wake()
		mv3.c.Wake()
		synctest.Wait()
		if armed.Load() {
			t.Fatal("stimulus: view 3 had no control-only DRR call")
		}
		if got := mv3.src.placed.Load(); got != 4096 {
			t.Fatalf("view 3 placed %d of the 4096 bytes queued after its control-only call, want all", got)
		}
	})
}

// TestMuxNearFullCallStaysReady (WP10 amendment to R1-1 rule 3): a DRR
// call that placed nothing because the batch had no room left for the
// control frame its view owes (the control arena nearly used by another
// view's frames) keeps the view ready, and the next round places that
// frame without any Wake. Two views each owe 31 RSTs of 260 payload bytes:
// one round's arena holds 31 of them, so whichever view goes second finds
// the arena nearly used. Without the rule the second view's frames waited
// for an unrelated wakeup.
func TestMuxNearFullCallStaysReady(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := muxRawDialer(t, nil)
		openLive(t, s, p, 2, 3)
		big := make([]byte, wire.RstFixedLen+wire.MaxMsg)
		big[4] = wire.MaxMsg
		for _, h := range []uint32{2, 3} {
			mv := s.view(h)
			for range 31 {
				mv.src.addCtl(hFrame{t: wire.TypeRst, payload: big})
			}
		}
		s.view(2).c.Wake()
		s.view(3).c.Wake()
		synctest.Wait()
		for _, h := range []uint32{2, 3} {
			mv := s.view(h)
			mv.src.mu.Lock()
			left := len(mv.src.ctl)
			mv.src.mu.Unlock()
			if left != 0 {
				t.Fatalf("view %d still owes %d of its 31 RSTs (no Wake came after the round that had no room)", h, left)
			}
		}
		if got := len(forHandle(s.tap.log(), 3)); got < 31 {
			t.Fatalf("view 3 wrote %d frames, want its 31 RSTs", got)
		}
	})
}

// TestMuxFramesAfterWithdrawRst (R1-5 rule 1; WP10): a dialer view whose
// OPEN was abandoned by its session's withdrawal places RST(AbortWithdrawn)
// for its handle, then DETACH. That RST is the dialer's first frame for the
// handle after its OPEN, so it ends the passive's response hold: what the
// passive placed for the handle meanwhile — its OK response crossing the
// withdrawal, then the session's data — is legal and dropped, never a
// violation; the trunk lives, and the passive's DETACH completes the
// view's retirement.
func TestMuxFramesAfterWithdrawRst(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := muxRawDialer(t, nil)
		v, err := s.c.openView(wire.TypeOpen, mOpenPayload(2, false), 2)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancelCause(context.Background())
		res := make(chan error, 1)
		go func() {
			_, err := v.awaitResponse(ctx, nil)
			res <- err
		}()
		synctest.Wait() // the OPEN is on the wire: the view awaits its response
		cancel(ErrWithdrawn)
		if err := <-res; err == nil {
			t.Fatal("the withdrawn attempt returned a view")
		}
		synctest.Wait()
		var types []wire.Type
		for _, r := range forHandle(s.tap.log(), v.handle) {
			types = append(types, r.h.Type)
		}
		if len(types) != 3 || types[0] != wire.TypeOpen || types[1] != wire.TypeRst || types[2] != wire.TypeDetach {
			t.Fatalf("dialer frames for the handle %v, want OPEN, RST, DETACH", types)
		}
		// The passive's frames that crossed the RST: its OK, then data.
		_ = p.send(wire.TypeOpenAck, 0, v.handle, okAck(wire.TypeOpenAck))
		_ = p.send(wire.TypeAck, 0, v.handle, ackPayload())
		_ = p.send(wire.TypeData, 0, v.handle, append(make([]byte, wire.DataPrefixLen), 1, 2, 3))
		_ = p.send(wire.TypeDetach, 0, 0, detachPayload(v.handle, wire.DetachEnded))
		synctest.Wait()
		if dead, cause, detail, _ := s.c.Death(); dead {
			t.Fatalf("the trunk died: %v %s", cause, detail)
		}
		waitDone(t, v.Done(), "the withdrawn view's Done")
		if st := viewStateOf(v); st != viewGone {
			t.Fatalf("view state %v, want gone", st)
		}
	})
}
