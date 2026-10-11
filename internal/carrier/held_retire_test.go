package carrier

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestHeldViewRetireAfterGo (M4 checkpoint C-L; M3-D8): a passive view of
// a started trunk whose session ends while the view is held after its OK
// (an l4 Server's Abort right after Confirm: a target that resets at once)
// places nothing before the dialer's go frame, then its session's last
// frames (the RST), then its DETACH. Before the fix the view was abandoned
// at the Retire with DETACH(ended) only and the RST was lost, so the dialer
// rejoined, met UNKNOWN_SESSION and reported ErrSessionLost instead of the
// peer's RST.
//
// Rows: "held" — Retire on a view already held; "during the OK" — Retire
// from inside the Fill that places the OK (before the writer records the
// hold: the retirement is queued as retireQ and the hold must keep it).
func TestHeldViewRetireAfterGo(t *testing.T) {
	for _, during := range []bool{false, true} {
		name := "held"
		if during {
			name = "during the OK"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { heldViewRetireRow(t, during) })
		})
	}
}

func heldViewRetireRow(t *testing.T, during bool) {
	const h = 2
	rst := hFrame{t: wire.TypeRst, payload: rstPayload(4242)}
	s, p := muxRawPassive(t, nil)
	s.admit = func(s *muxSide, v *Conn, hd wire.Header, pl []byte) {
		mv := &mView{c: v, ep: &dEP{}, src: newVSource(s.env), bell: &hBell{}, done: &hBell{}}
		mv.ep.fill = mv.src.fill // no verdict yet
		s.add(mv)
		v.Start(mv.ep, mv.bell, StartOptions{})
	}
	_ = p.send(wire.TypeOpen, 0, h, mOpenPayload(h, false))
	synctest.Wait()
	mv := s.view(h)
	if mv == nil {
		t.Fatal("OPEN not admitted")
	}
	wantState(t, mv.c, viewPending, "OPEN admitted")
	src := mv.src
	src.mu.Lock()
	src.resp, src.respSt = wire.TypeOpenAck, wire.StatusOK
	if during {
		// The session ends while its writer places the OK: the RST is
		// queued and the view retired from inside that Fill.
		once := false
		src.hook = func(c *Conn, b *Batch) {
			if !once {
				once = true
				src.ctl = append(src.ctl, rst) // under src.mu (fill holds it)
				c.Retire(wire.CloseRetire)
			}
		}
	}
	src.mu.Unlock()
	mv.c.Wake()
	synctest.Wait()
	if !during {
		wantState(t, mv.c, viewHeld, "Confirm")
		src.addCtl(rst)
		mv.c.Retire(wire.CloseRetire)
		synctest.Wait()
	}
	if got := forHandle(p.received2(), h); len(got) != 1 || got[0].h.Type != wire.TypeOpenAck {
		t.Fatalf("held view after its session's end placed %v, want its OPEN_ACK only until the go frame", types(got))
	}
	releaseHeld(p, h)
	synctest.Wait()
	got := forHandle(p.received2(), h)
	if len(got) != 3 || got[0].h.Type != wire.TypeOpenAck || got[1].h.Type != wire.TypeRst || got[2].h.Type != wire.TypeDetach {
		t.Fatalf("after the go frame the view placed %v, want OPEN_ACK, RST, DETACH", types(got))
	}
	if d, err := wire.ParseDetach(got[2].p); err != nil || d.Handle != h {
		t.Fatalf("DETACH %+v (%v), want one for handle %d", d, err, h)
	}
	if dead, cause, detail, _ := s.c.KillTrunkDeath(); dead {
		t.Fatalf("trunk died: %v %s", cause, detail)
	}
}

// TestHeldViewRetireBound (M4 checkpoint C-L): a held view retired while
// the dialer's go frame never comes (lost for good, or a dialer that never
// answers) is not held forever: drainMax after the Retire it is abandoned
// with its DETACH only (R1-9), as before the C-L fix; nothing else is
// placed for it before that. Rows as TestHeldViewRetireAfterGo's.
func TestHeldViewRetireBound(t *testing.T) {
	for _, during := range []bool{false, true} {
		name := "held"
		if during {
			name = "during the OK"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { heldViewRetireBoundRow(t, during) })
		})
	}
}

func heldViewRetireBoundRow(t *testing.T, during bool) {
	const h = 2
	rst := hFrame{t: wire.TypeRst, payload: rstPayload(4242)}
	s, p := muxRawPassive(t, nil)
	s.admit = func(s *muxSide, v *Conn, hd wire.Header, pl []byte) {
		mv := &mView{c: v, ep: &dEP{}, src: newVSource(s.env), bell: &hBell{}, done: &hBell{}}
		mv.ep.fill = mv.src.fill // no verdict yet
		s.add(mv)
		v.Start(mv.ep, mv.bell, StartOptions{})
	}
	_ = p.send(wire.TypeOpen, 0, h, mOpenPayload(h, false))
	synctest.Wait()
	mv := s.view(h)
	if mv == nil {
		t.Fatal("OPEN not admitted")
	}
	src := mv.src
	start := time.Now()
	src.mu.Lock()
	src.resp, src.respSt = wire.TypeOpenAck, wire.StatusOK
	if during {
		once := false
		src.hook = func(c *Conn, b *Batch) {
			if !once {
				once = true
				src.ctl = append(src.ctl, rst)
				c.Retire(wire.CloseRetire)
			}
		}
	}
	src.mu.Unlock()
	mv.c.Wake()
	synctest.Wait()
	if !during {
		wantState(t, mv.c, viewHeld, "Confirm")
		src.addCtl(rst)
		mv.c.Retire(wire.CloseRetire)
	}
	time.Sleep(drainMax - time.Millisecond)
	synctest.Wait()
	if got := forHandle(p.received2(), h); len(got) != 1 || got[0].h.Type != wire.TypeOpenAck {
		t.Fatalf("held view %v after its Retire placed %v, want its OPEN_ACK only", time.Since(start), types(got))
	}
	time.Sleep(time.Millisecond)
	synctest.Wait()
	got := forHandle(p.received2(), h)
	if len(got) != 2 || got[0].h.Type != wire.TypeOpenAck || got[1].h.Type != wire.TypeDetach {
		t.Fatalf("held view at the hold bound placed %v, want OPEN_ACK, DETACH", types(got))
	}
	if dead, cause, detail, _ := s.c.KillTrunkDeath(); dead {
		t.Fatalf("trunk died: %v %s", cause, detail)
	}
}
