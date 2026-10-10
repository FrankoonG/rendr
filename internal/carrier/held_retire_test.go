package carrier

import (
	"testing"
	"testing/synctest"

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
