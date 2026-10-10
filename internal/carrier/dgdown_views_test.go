package carrier

import (
	"testing"
	"testing/synctest"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestDgTrunkDeathReachesEveryViewState (M3 design §A5.4, §A5.7 item 6;
// DGDOWN): a datagram MUX trunk dies (a local Kill with transport_error,
// the harness's close of the dialer's socket) while it holds a view in
// every state that is not gone, and every one of them learns the death:
//
//   - dialer: awaiting (first frame placed, no response), attached-pending
//     (OK response read, the session has not started it), live, retiring
//     (its DETACH placed, the peer's not back) and opening (handle
//     allocated, first frame never released);
//   - passive: pending with its session attached (no verdict yet),
//     pending with no session attached (admitted, Start not called),
//     joining (an admitted JOIN, no answer yet), held (OK placed, no go
//     frame), live and retiring.
//
// PASS: each view ends in state dead with the trunk's cause, its Done
// closes, a started view's doorbell rang at the death (the session's
// actor wakes and records its CarrierDown), an unstarted view's doorbell
// rings at its Start after the death (the session that attaches it late
// reaps it at once, M3-D14), and the dialer's attempt still awaiting its
// response returns an error instead of blocking.
//
// Premise: before the kill every view is in the state its row names
// (wantState) and the trunk is alive.
func TestDgTrunkDeathReachesEveryViewState(t *testing.T) {
	t.Run("dialer", func(t *testing.T) { synctest.Test(t, dgDeathDialerRows) })
	t.Run("passive", func(t *testing.T) { synctest.Test(t, dgDeathPassiveRows) })
}

// dgViewRow is one view of the rows: its state before the kill, its
// doorbell (nil: not started before the kill) and the bell count at the
// kill.
type dgViewRow struct {
	name  string
	c     *Conn
	want  viewState
	bell  *hBell
	rang0 int32
}

func dgDeathDialerRows(t *testing.T) {
	s, p := dgMuxRaw(t, 1200, true, nil)
	var rs relSeq
	ok := func(h uint32) { p.send(rs.rel(wire.TypeOpenAck, 0, h, okAck(wire.TypeOpenAck))) }

	// awaiting: the OPEN placed, no response.
	v2, wait2 := s.openRaw(t, wire.TypeOpen, 2)
	// attached-pending: OK read, never started.
	v3, wait3 := s.openRaw(t, wire.TypeOpen, 3)
	// live and retiring: OK read, started; 5 retires.
	v4, wait4 := s.openRaw(t, wire.TypeOpen, 4)
	v5, wait5 := s.openRaw(t, wire.TypeOpen, 5)
	synctest.Wait()
	ok(3)
	ok(4)
	ok(5)
	for _, w := range []func() (*Established, error){wait3, wait4, wait5} {
		if _, err := w(); err != nil {
			t.Fatalf("attempt: %v", err)
		}
	}
	mv4, mv5 := s.attach(v4), s.attach(v5)
	synctest.Wait()
	v5.Retire(wire.CloseRetire)
	synctest.Wait()
	// opening: allocated after the others (the opens FIFO keeps
	// allocation order), its first frame never released.
	v6, err := s.c.openView(wire.TypeOpen, mOpenPayload(6, true), 6)
	if err != nil {
		t.Fatalf("openView: %v", err)
	}
	rows := []*dgViewRow{
		{name: "awaiting", c: v2, want: viewAwaiting},
		{name: "attached-pending", c: v3, want: viewAttachedPending},
		{name: "live", c: v4, want: viewLive, bell: mv4.bell},
		{name: "retiring", c: v5, want: viewRetiring, bell: mv5.bell},
		{name: "opening", c: v6, want: viewOpening},
	}
	dgKillAndJudge(t, s, rows)
	if _, err := wait2(); err == nil {
		t.Fatal("awaiting: the attempt returned no error after the trunk's death")
	}
}

func dgDeathPassiveRows(t *testing.T) {
	s, p := dgMuxRaw(t, 1200, false, nil)
	var rs relSeq
	unattached := map[uint32]*Conn{}
	s.admit = func(s *muxSide, v *Conn, h wire.Header, pl []byte) {
		switch v.Handle() {
		case 2, 3: // the session attached the view; no verdict yet
			mv := &mView{c: v, ep: &dEP{}, src: newVSource(s.env), bell: &hBell{}, done: &hBell{}}
			mv.ep.fill = mv.src.fill
			v.OnDone(mv.done)
			s.add(mv)
			v.Start(mv.ep, mv.bell, StartOptions{})
		case 4: // admitted; its session has not attached it
			unattached[4] = v
		default: // answered OK
			s.startAdmitted(v, h, wire.StatusOK)
		}
	}
	p.send(rs.rel(wire.TypeOpen, 0, 2, mOpenPayload(2, true)))
	p.send(rs.rel(wire.TypeJoin, 0, 3, mJoinPayload(3)))
	p.send(rs.rel(wire.TypeOpen, 0, 4, mOpenPayload(4, true)))
	p.send(rs.rel(wire.TypeOpen, 0, 5, mOpenPayload(5, true)))
	p.send(rs.rel(wire.TypeOpen, 0, 6, mOpenPayload(6, true)))
	p.send(rs.rel(wire.TypeOpen, 0, 7, mOpenPayload(7, true)))
	synctest.Wait()
	for h := uint32(2); h <= 7; h++ {
		if s.view(h) == nil && unattached[h] == nil {
			_, cause, detail, _ := s.c.KillTrunkDeath()
			t.Fatalf("handle %d not admitted (trunk %v: %s)", h, cause, detail)
		}
	}
	// 6 and 7 go live (the dialer's go frame: a plain PACK); 7 retires.
	p.send(rawFrame{t: wire.TypePack, handle: 6, payload: packPayload()})
	p.send(rawFrame{t: wire.TypePack, handle: 7, payload: packPayload()})
	synctest.Wait()
	s.view(7).c.Retire(wire.CloseRetire)
	synctest.Wait()
	rows := []*dgViewRow{
		{name: "pending (attached)", c: s.view(2).c, want: viewPending, bell: s.view(2).bell},
		{name: "joining (attached)", c: s.view(3).c, want: viewJoining, bell: s.view(3).bell},
		{name: "pending (not attached)", c: unattached[4], want: viewPending},
		{name: "held", c: s.view(5).c, want: viewHeld, bell: s.view(5).bell},
		{name: "live", c: s.view(6).c, want: viewLive, bell: s.view(6).bell},
		{name: "retiring", c: s.view(7).c, want: viewRetiring, bell: s.view(7).bell},
	}
	dgKillAndJudge(t, s, rows)
}

// dgKillAndJudge checks the rows' premise, kills s's trunk with
// transport_error and judges every row (see the test's comment).
func dgKillAndJudge(t *testing.T, s *muxSide, rows []*dgViewRow) {
	t.Helper()
	for _, r := range rows {
		wantState(t, r.c, r.want, r.name+" (premise)")
		if dead, cause, detail, _ := r.c.Death(); dead {
			t.Fatalf("%s (premise): the view ended before the kill (%v: %s)", r.name, cause, detail)
		}
		if r.bell != nil {
			r.rang0 = r.bell.n.Load()
		}
	}
	if dead, cause, detail, _ := s.c.KillTrunkDeath(); dead {
		t.Fatalf("premise: the trunk died before the kill (%v: %s)", cause, detail)
	}
	s.c.KillTrunk(CauseTransportError, "the socket was closed")
	synctest.Wait()
	for _, r := range rows {
		waitDone(t, r.c.Done(), r.name)
		wantState(t, r.c, viewDead, r.name+" at the trunk's death")
		if dead, cause, _, _ := r.c.Death(); !dead || cause != CauseTransportError {
			t.Fatalf("%s: Death dead %v cause %v, want the trunk's transport_error", r.name, dead, cause)
		}
		if r.bell != nil {
			if r.bell.n.Load() <= r.rang0 {
				t.Fatalf("%s: its doorbell did not ring at the trunk's death", r.name)
			}
			continue
		}
		// Not started: the session that attaches it after the death is
		// rung at its Start and nothing starts.
		late := &hBell{}
		r.c.Start(&dEP{}, late, StartOptions{})
		if late.n.Load() == 0 {
			t.Fatalf("%s: Start after the trunk's death did not ring the doorbell", r.name)
		}
		if viewStateOf(r.c) != viewDead {
			t.Fatalf("%s: Start after the trunk's death changed the state to %d", r.name, viewStateOf(r.c))
		}
	}
}
