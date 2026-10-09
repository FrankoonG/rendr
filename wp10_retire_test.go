package rendr

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// mxSwitchOverrides make the selector's quality switch fast and the old
// lane's retirement bound short (the timings of TestLocalCloseNoFailover_L01).
func mxSwitchOverrides(cooldown time.Duration) *testhooks.Overrides {
	return &testhooks.Overrides{
		ProbeInterval: 50 * time.Millisecond, ProbeFresh: time.Second,
		SelectorDwell: 200 * time.Millisecond, SelectorCooldown: cooldown,
		RetireGrace: time.Second,
	}
}

// mxSessionTaps returns the tampers of taps whose carrier is a session
// carrier (its first dialer frame an OPEN or a JOIN), oldest first.
func mxSessionTaps(t testing.TB, taps *mxTaps) []*rendrtest.Tamper {
	t.Helper()
	var out []*rendrtest.Tamper
	for i := range taps.count() {
		tp := taps.tap(t, i)
		if len(mxFrames(tp, rendrtest.Up, rendrtest.FrameOpen, 0))+len(mxFrames(tp, rendrtest.Up, rendrtest.FrameJoin, 0)) > 0 {
			out = append(out, tp)
		}
	}
	return out
}

// mxCarrierRows returns c's session-level rows of carrier id (live and
// dead), oldest first.
func mxCarrierRows(c *Conn, id CarrierID) []session.CarrierStatus {
	var out []session.CarrierStatus
	for _, cs := range mxSessionCarriers(c) {
		if CarrierID(cs.ID) == id {
			out = append(out, cs)
		}
	}
	return out
}

// TestRetireIsDetach (M3-D6, R1-3; A11.3's "Retire sends CLOSE on MUX
// trunks" mutant): a selector session's planned switch away from a MUX
// trunk that another session keeps alive retires its view with DETACH —
// no CLOSE on that trunk in either direction —, the old lane is reaped with
// its row retired, the session keeps delivering on its new lane, and when
// it then ends Session.Done closes while the trunk stays alive with one
// view fewer. On a dedicated carrier (CheapSubflow) the same switch
// retires the carrier with CLOSE, as in M2.
func TestRetireIsDetach(t *testing.T) {
	for _, cheap := range []bool{false, true} {
		name := "mux"
		if cheap {
			name = "dedicated"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := e2eNew(t, Config{}, Config{}, mxSwitchOverrides(time.Hour), ListenConfig{}, "a", "b")
				la, lb := e.links[0], e.links[1]
				la.SetDelay(time.Millisecond, 0)
				lb.SetDelay(5*time.Millisecond, 0)
				var ta, tb mxTaps
				defer ta.close()
				defer tb.close()
				ca, cb := mxTapCarrier(la, &ta), mxTapCarrier(lb, &tb)
				if cheap {
					ca, cb = dedicated(ca), dedicated(cb)
				}
				p := e.mxPeer(ca, cb)
				k, kq := e2eOpen(t, p, e.ln, DialOptions{Mode: ModeBond}) // keeps a carrier of a
				mxWait(t, 2*time.Second, "the keeper's members", func() bool { return mxMembers(k) == 2 })
				s, sq := e2eOpen(t, p, e.ln, DialOptions{})
				old := mxCarrier(t, s, "a")
				sa := mxSessionTaps(t, &ta)
				tpA := sa[len(sa)-1] // the trunk (mux) or carrier (dedicated) of s on a
				detBefore := len(mxFrames(tpA, rendrtest.Up, rendrtest.FrameDetach, 0))

				la.SetDelay(20*time.Millisecond, 0) // a degrades: s switches to b
				mxWait(t, 30*time.Second, "the quality switch and the old lane's end", func() bool {
					st := s.Status()
					if st.Migrations.Quality == 0 {
						return false
					}
					rows := mxCarrierRows(s, old.ID)
					return len(rows) == 1 && rows[0].State == session.LaneDead
				})
				synctest.Wait()
				row := mxCarrierRows(s, old.ID)[0]
				if row.DeathCause.String() != CauseRetired.String() {
					t.Fatalf("the old lane's row: %v %s, want retired", row.DeathCause, row.DeathDetail)
				}
				closes := len(mxFrames(tpA, rendrtest.Up, rendrtest.FrameClose, 0)) + len(mxFrames(tpA, rendrtest.Down, rendrtest.FrameClose, 0))
				dets := len(mxFrames(tpA, rendrtest.Up, rendrtest.FrameDetach, 0)) - detBefore
				if cheap {
					if closes == 0 || dets != 0 {
						t.Fatalf("dedicated: %d CLOSEs and %d DETACHes on the old carrier, want CLOSE and no DETACH", closes, dets)
					}
				} else {
					if closes != 0 || dets != 1 {
						t.Fatalf("mux: %d CLOSEs and %d DETACHes on the old trunk, want one DETACH and no CLOSE", closes, dets)
					}
					if c := mxCarrier(t, k, "a"); c.ID != old.ID || c.State != CarrierMember {
						t.Fatalf("the keeper's member on a %+v, want the trunk %d alive", c, old.ID)
					}
				}
				e2eExchange(t, s, sq, 256<<10, 1)
				before := e.d.Status().Mux
				e2eFinish(t, s, sq)
				if !cheap {
					after := e.d.Status().Mux
					if c := mxCarrier(t, k, "a"); c.ID != old.ID || after.Carriers != before.Carriers || after.Views != before.Views-1 {
						t.Fatalf("after the session's end: keeper on %+v, Mux %+v (was %+v); want the trunk alive with one view fewer", c, after, before)
					}
				}
				e2eExchange(t, k, kq, 128<<10, 2)
				e2eFinish(t, k, kq)
				e.close()
			})
		})
	}
}

// TestMuxReattachSameTrunk (M3-D64, R1-6; A11.3's id-only known-carrier
// mutant): a selector session switches by quality from trunk X to trunk Y
// and, after its Cooldown, back to X, which another session kept alive:
// the JOIN onto X is admitted at the first try (one JOIN placed for it),
// the session's lane on X is new (a new handle; its dead-lane history
// shows X twice, with two handles), SCHED routes its data to the new lane,
// and every byte arrives intact.
func TestMuxReattachSameTrunk(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, mxSwitchOverrides(3*time.Second), ListenConfig{}, "a", "b")
		la, lb := e.links[0], e.links[1]
		la.SetDelay(time.Millisecond, 0)
		lb.SetDelay(5*time.Millisecond, 0)
		var ta, tb mxTaps
		defer ta.close()
		defer tb.close()
		p := e.mxPeer(mxTapCarrier(la, &ta), mxTapCarrier(lb, &tb))
		k, kq := e2eOpen(t, p, e.ln, DialOptions{Mode: ModeBond})
		mxWait(t, 2*time.Second, "the keeper's members", func() bool { return mxMembers(k) == 2 })
		s, sq := e2eOpen(t, p, e.ln, DialOptions{})
		x := mxCarrier(t, s, "a")
		h1 := mxHandleOf(t, s, "a")
		tpX := mxSessionTaps(t, &ta)[0]

		la.SetDelay(20*time.Millisecond, 0)
		mxWait(t, 30*time.Second, "the switch to b", func() bool { return mxCarrier(t, s, "").Name == "b" && s.Status().Migrations.Quality == 1 })
		joinsBefore := len(mxFrames(tpX, rendrtest.Up, rendrtest.FrameJoin, 0))
		la.SetDelay(time.Millisecond, 0)
		lb.SetDelay(20*time.Millisecond, 0)
		mxWait(t, 60*time.Second, "the switch back to a", func() bool {
			c := mxCarrier(t, s, "")
			return c.Name == "a" && c.State == CarrierActive && s.Status().Migrations.Quality == 2
		})
		synctest.Wait()
		if n := len(mxFrames(tpX, rendrtest.Up, rendrtest.FrameJoin, 0)) - joinsBefore; n != 1 {
			t.Fatalf("%d JOINs placed on trunk X for the return, want 1 (admitted at the first try)", n)
		}
		if c := mxCarrier(t, s, "a"); c.ID != x.ID {
			t.Fatalf("returned to carrier %d, want trunk X %d", c.ID, x.ID)
		}
		h2 := mxHandleOf(t, s, "a")
		rows := mxCarrierRows(s, x.ID)
		if h2 == h1 || len(rows) != 2 || rows[0].Stats.Handle == rows[1].Stats.Handle {
			t.Fatalf("handles %d then %d; rows of X %+v; want two rows of X with two handles", h1, h2, rows)
		}
		e2eExchange(t, s, sq, 256<<10, 3)
		if got := mxHandles(tpX, rendrtest.Up, rendrtest.FrameData)[h2]; got == 0 {
			t.Fatalf("no DATA on the new lane (handle %d) of trunk X", h2)
		}
		if st := s.Status(); st.Migrations.Death != 0 || st.NoPathEpisodes != 0 {
			t.Fatalf("session %+v", st)
		}
		e2eFinish(t, s, sq)
		e2eFinish(t, k, kq)
		e.close()
	})
}

// TestDetachReasonInformational (R1-5 rule 3, M3-D6): DETACH's reason is
// informational — the receiver's view ends and its lane leaves as for M1's
// peer CLOSE, and session state never changes by it. A selector session's
// planned switch away from a shared trunk: the passive receives
// DETACH(retired) on the live view of its live session — its lane on that
// trunk leaves (its row retired), its session stays open with no error and
// keeps delivering on the new lane, it sends no RST —; the dialer receives
// the passive's answer, DETACH(ended), on its retiring view and its session
// likewise goes on. (No M3 path ends a live view of a live session with
// DETACH(ended) other than this answer: the session reads no reason, only
// the view's end.)
func TestDetachReasonInformational(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, mxSwitchOverrides(time.Hour), ListenConfig{}, "a", "b")
		la, lb := e.links[0], e.links[1]
		la.SetDelay(time.Millisecond, 0)
		lb.SetDelay(5*time.Millisecond, 0)
		var ta, tb mxTaps
		defer ta.close()
		defer tb.close()
		p := e.mxPeer(mxTapCarrier(la, &ta), mxTapCarrier(lb, &tb))
		k, kq := e2eOpen(t, p, e.ln, DialOptions{Mode: ModeBond})
		mxWait(t, 2*time.Second, "the keeper's members", func() bool { return mxMembers(k) == 2 })
		s, sq := e2eOpen(t, p, e.ln, DialOptions{})
		old := mxCarrier(t, sq, "")
		tpA := mxSessionTaps(t, &ta)[0]
		upDet := len(mxFrames(tpA, rendrtest.Up, rendrtest.FrameDetach, 0))
		downDet := len(mxFrames(tpA, rendrtest.Down, rendrtest.FrameDetach, 0))
		done := make(chan error, 1)
		go func() { done <- e2eExchangeErr(s, sq, 8<<20, 41) }()
		la.SetDelay(20*time.Millisecond, 0)
		mxWait(t, 30*time.Second, "both old lanes leave", func() bool {
			rows, drows := mxCarrierRows(sq, old.ID), mxCarrierRows(s, old.ID)
			return len(rows) == 1 && rows[0].State == session.LaneDead && len(drows) == 1 && drows[0].State == session.LaneDead
		})
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if row := mxCarrierRows(sq, old.ID)[0]; row.DeathCause.String() != CauseRetired.String() {
			t.Fatalf("the passive's detached lane: %v %s, want retired", row.DeathCause, row.DeathDetail)
		}
		if row := mxCarrierRows(s, old.ID); len(row) != 1 || row[0].DeathCause.String() != CauseRetired.String() {
			t.Fatalf("the dialer's detached lane: %+v, want retired", row)
		}
		if u, d := len(mxFrames(tpA, rendrtest.Up, rendrtest.FrameDetach, 0))-upDet, len(mxFrames(tpA, rendrtest.Down, rendrtest.FrameDetach, 0))-downDet; u != 1 || d != 1 {
			t.Fatalf("DETACHes on the old trunk: %d from the dialer, %d from the passive; want one each", u, d)
		}
		if n := len(mxFrames(tpA, rendrtest.Down, rendrtest.FrameRst, 0)) + len(mxFrames(tpA, rendrtest.Up, rendrtest.FrameRst, 0)); n != 0 {
			t.Fatalf("%d RSTs on the old trunk", n)
		}
		for _, c := range []*Conn{s, sq} {
			if st := c.Status(); st.State != StateOpen || st.Err != nil || st.Migrations.Death != 0 {
				t.Fatalf("%v after the DETACH: %+v", st.Role, st)
			}
		}
		e2eExchange(t, s, sq, 64<<10, 43)
		e2eFinish(t, s, sq)
		e2eFinish(t, k, kq)
		e.close()
	})
}

// TestHandleStateMachine (§A5.4, R1-9; the session half — the carrier half
// is the mux core's): the rows of the handle lifecycle a session sees, each
// on a live trunk shared with a neighbour session that must stay
// untouched (no death, no migration, its data intact):
//
//   - dialer opening/awaiting, abandoned (Dial withdrawn): RST then DETACH,
//     the passive's pending session withdraws (TestMuxCancelCrossesConfirm_L49);
//   - dialer attached-pending, the peer's DETACH: the carrier half (the
//     view retires; our DETACH answers); the session's half — the attach
//     finding PeerClosed and counting a carrier refusal — has no organic
//     stimulus here (a peer's DETACH of a live session's view needs that
//     session's end, which reaches the dialer first);
//   - live, the peer's DETACH: the lane leaves (TestDetachReasonInformational);
//   - live, planned retirement: DETACH (TestRetireIsDetach);
//   - passive held, its session ends: DETACH only (TestHeldViewSessionEnd);
//   - any, trunk death: every view's lane dies once, each session counts its
//     own death and recovers.
func TestHandleStateMachine(t *testing.T) {
	t.Run("trunk death", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a", "b")
			e.links[0].SetDelay(time.Millisecond, 0) // a ranks first
			e.links[1].SetDelay(5*time.Millisecond, 0)
			p := e.peer()
			var ds, ps [3]*Conn
			for i := range 3 {
				ds[i], ps[i] = e2eOpen(t, p, e.ln, DialOptions{})
			}
			trunk := mxCarrier(t, ds[0], "").ID
			for i := 1; i < 3; i++ {
				if mxCarrier(t, ds[i], "").ID != trunk {
					t.Fatal("the sessions do not share one trunk")
				}
			}
			e.links[0].Kill()
			for i := range 3 {
				mxWait(t, 10*time.Second, "the session recovers", func() bool {
					for _, c := range ds[i].Status().Carriers {
						if c.State == CarrierActive && c.ID != trunk {
							return true
						}
					}
					return false
				})
				e2eExchange(t, ds[i], ps[i], 64<<10, uint64(i))
				if st := ds[i].Status(); st.Migrations.Death != 1 {
					t.Fatalf("session %d: %+v, want one death migration", i, st.Migrations)
				}
				rows := mxCarrierRows(ds[i], trunk)
				if len(rows) != 1 || rows[0].State != session.LaneDead {
					t.Fatalf("session %d: rows of the dead trunk %+v, want one dead lane", i, rows)
				}
			}
			for i := range 3 {
				e2eFinish(t, ds[i], ps[i])
			}
			e.close()
		})
	})
}
