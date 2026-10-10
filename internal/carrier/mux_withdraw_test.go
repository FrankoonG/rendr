package carrier

import (
	"bytes"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestMuxWithdrawRstBeforeAsyncAttach_R1_5 (R1-5, §A3.3, §A5.4; WP16 W1):
// a second OPEN of a pending session on a live passive MUX trunk is
// attached by the session's actor later (AttachOpen posts an adopt), so a
// compliant dialer's withdrawal — RST(AbortWithdrawn) for the handle, then
// DETACH(ended) — can reach the reader while no session attached the view.
// That RST is legal: the trunk lives (stream: no protocol_violation;
// datagram: nothing dropped), and the following DETACH ends the view (its
// Done closes). An attach that comes after the RST does not revive the
// view, but its session gets the withdrawal — one RST(AbortWithdrawn)
// through Control, not inline (the attach runs under the session lock that
// Control takes) — and any other session frame for an unattached view
// stays illegal.
func TestMuxWithdrawRstBeforeAsyncAttach_R1_5(t *testing.T) {
	for _, dg := range []bool{false, true} {
		name := "stream"
		if dg {
			name = "datagram"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, send, rack := withdrawPassive(t, dg)
				var deferred *Conn
				s.admit = func(s *muxSide, v *Conn, h wire.Header, p []byte) {
					deferred = v // the session attaches it later (AttachOpen's adopt)
				}
				const h = 2
				dropped0 := s.c.Stats().Dropped
				send(wire.TypeOpen, h, mOpenPayload(h, dg))
				synctest.Wait()
				if deferred == nil {
					t.Fatal("handle 2 was not admitted")
				}
				send(wire.TypeRst, h, rstWithdrawnPayload)
				synctest.Wait()
				if dead, cause, detail, _ := s.c.KillTrunkDeath(); dead {
					t.Fatalf("the trunk died on a compliant withdrawal: %v %s", cause, detail)
				}
				if n := s.c.Stats().Dropped; n != dropped0 {
					t.Fatalf("Dropped %d → %d on a compliant withdrawal", dropped0, n)
				}
				send(wire.TypeDetach, h, detachPayload(h, wire.DetachEnded))
				synctest.Wait()
				rack()
				synctest.Wait()
				if dead, cause, detail, _ := s.c.KillTrunkDeath(); dead {
					t.Fatalf("the trunk died after the withdrawal's DETACH: %v %s", cause, detail)
				}
				if n := s.c.Stats().Dropped; n != dropped0 {
					t.Fatalf("Dropped %d → %d after the withdrawal's DETACH", dropped0, n)
				}
				waitDone(t, deferred.Done(), "view 2")
				// The session's adopt runs now (under its session lock): the
				// view stays ended, and the session still learns of the
				// withdrawal — its only lane may be this one (R1-5 rule 3).
				ep := &dEP{}
				bell := &hBell{}
				var sessMu sync.Mutex
				ep.setHook(func(wire.Header, []byte) { sessMu.Lock(); sessMu.Unlock() })
				sessMu.Lock()
				deferred.Start(ep, bell, StartOptions{})
				sessMu.Unlock()
				synctest.Wait()
				if bell.n.Load() == 0 {
					t.Fatal("Start on the withdrawn view did not ring its bell")
				}
				wantWithdrawal(t, ep, h)
				if dead, _, _, _ := deferred.Death(); !dead {
					t.Fatal("the withdrawn view is not ended")
				}
				if s.c.Views() != 1 {
					t.Fatalf("%d views on the trunk, want view 1 only", s.c.Views())
				}
			})
		})
	}
}

// TestMuxWithdrawRstThenAttach_R1_5 (R1-5; WP16 W1): the session's adopt
// runs between the withdrawal's RST and its DETACH: the view does not go
// live (the dialer withdrew it), its session sees it end and gets the
// withdrawal RST once, and the DETACH that follows is legal; the trunk
// lives.
func TestMuxWithdrawRstThenAttach_R1_5(t *testing.T) {
	for _, dg := range []bool{false, true} {
		name := "stream"
		if dg {
			name = "datagram"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, send, rack := withdrawPassive(t, dg)
				var deferred *Conn
				s.admit = func(s *muxSide, v *Conn, h wire.Header, p []byte) { deferred = v }
				const h = 2
				dropped0 := s.c.Stats().Dropped
				send(wire.TypeOpen, h, mOpenPayload(h, dg))
				synctest.Wait()
				send(wire.TypeRst, h, rstWithdrawnPayload)
				synctest.Wait()
				mv := &mView{c: deferred, ep: &dEP{}, src: newVSource(s.env), bell: &hBell{}, done: &hBell{}}
				mv.src.resp, mv.src.respSt = wire.TypeOpenAck, wire.StatusOK
				mv.ep.fill = mv.src.fill
				deferred.OnDone(mv.done)
				var sessMu sync.Mutex // the adopt runs under the session lock, which Control takes
				mv.ep.setHook(func(wire.Header, []byte) { sessMu.Lock(); sessMu.Unlock() })
				sessMu.Lock()
				deferred.Start(mv.ep, mv.bell, StartOptions{})
				sessMu.Unlock()
				synctest.Wait()
				if mv.bell.n.Load() == 0 {
					t.Fatal("the session was not rung for the withdrawn view")
				}
				wantWithdrawal(t, mv.ep, h)
				if dead, _, _, _ := deferred.Death(); !dead {
					t.Fatal("the withdrawn view went on after its session attached it")
				}
				send(wire.TypeDetach, h, detachPayload(h, wire.DetachEnded))
				synctest.Wait()
				rack()
				synctest.Wait()
				time.Sleep(10 * time.Millisecond) // the following writer rounds
				rack()
				synctest.Wait()
				if dead, cause, detail, _ := s.c.KillTrunkDeath(); dead {
					t.Fatalf("the trunk died: %v %s", cause, detail)
				}
				if n := s.c.Stats().Dropped; n != dropped0 {
					t.Fatalf("Dropped %d → %d", dropped0, n)
				}
				waitDone(t, deferred.Done(), "view 2")
				if s.c.Views() != 1 {
					t.Fatalf("%d views on the trunk, want view 1 only", s.c.Views())
				}
			})
		})
	}
}

// TestMuxUnattachedFramesStayIllegal (§A3.3; WP16 W1): only the
// withdrawal's RST is legal for a view no session attached yet: a second
// RST, a FIN or DATA for it, and an RST for an unattached joining view are
// violations (stream) or counted drops (datagram).
func TestMuxUnattachedFramesStayIllegal(t *testing.T) {
	rows := []struct {
		name  string
		first wire.Type
		seq   []wire.Type
	}{
		{"second RST", wire.TypeOpen, []wire.Type{wire.TypeRst, wire.TypeRst}},
		{"FIN", wire.TypeOpen, []wire.Type{wire.TypeFin}},
		{"RST then FIN", wire.TypeOpen, []wire.Type{wire.TypeRst, wire.TypeFin}},
		{"RST on a JOIN", wire.TypeJoin, []wire.Type{wire.TypeRst}},
	}
	for _, dg := range []bool{false, true} {
		for _, row := range rows {
			name := "stream/" + row.name
			if dg {
				name = "datagram/" + row.name
			}
			t.Run(name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					s, send, _ := withdrawPassive(t, dg)
					s.admit = func(s *muxSide, v *Conn, h wire.Header, p []byte) {}
					const h = 2
					dropped0 := s.c.Stats().Dropped
					pl := mOpenPayload(h, dg)
					if row.first == wire.TypeJoin {
						pl = mJoinPayload(h)
					}
					send(row.first, h, pl)
					synctest.Wait()
					for _, typ := range row.seq {
						switch typ {
						case wire.TypeRst:
							send(typ, h, rstWithdrawnPayload)
						case wire.TypeFin:
							send(typ, h, finInner(0))
						}
						synctest.Wait()
					}
					dead, cause, _, _ := s.c.KillTrunkDeath()
					switch {
					case !dg && (!dead || cause != CauseProtocolViolation):
						t.Fatalf("stream: dead %v cause %v, want protocol_violation", dead, cause)
					case dg && dead:
						t.Fatalf("datagram: the trunk died (%v), want a counted drop", cause)
					case dg && s.c.Stats().Dropped <= dropped0:
						t.Fatalf("datagram: Dropped %d → %d, want a counted drop", dropped0, s.c.Stats().Dropped)
					}
				})
			})
		}
	}
}

// wantWithdrawal asserts that the session of a view withdrawn before its
// attach got the withdrawal exactly once: one RST(AbortWithdrawn) for
// handle h through its endpoint's Control (R1-5 rule 3: a pending session
// withdraws only on the dialer's RST, and survives the loss of its lanes).
func wantWithdrawal(t testing.TB, ep *dEP, h uint32) {
	t.Helper()
	ep.dmu.Lock()
	cps := append([]ctrlRec(nil), ep.cps...)
	ep.dmu.Unlock()
	if len(cps) != 1 || cps[0].h.Type != wire.TypeRst || cps[0].h.Handle != h || !bytes.Equal(cps[0].p, rstWithdrawnPayload) {
		t.Fatalf("the session's Control calls %+v, want one RST(AbortWithdrawn) for handle %d", cps, h)
	}
}

// withdrawPassive returns a started passive MUX trunk (stream or datagram)
// against a raw peer, a sender of session frames, OPENs and DETACHes (REL
// on a datagram trunk), and rack, which acknowledges every REL the trunk
// sent so far (a datagram view retires once its REL{DETACH} is acked).
func withdrawPassive(t testing.TB, dg bool) (s *muxSide, send func(typ wire.Type, h uint32, p []byte), rack func()) {
	if !dg {
		var p *wirePeer
		s, p = muxRawPassive(t, nil)
		send = func(typ wire.Type, h uint32, pl []byte) {
			if typ == wire.TypeDetach {
				_ = p.send(typ, 0, 0, pl)
				return
			}
			_ = p.send(typ, 0, h, pl)
		}
		return s, send, func() {}
	}
	var p *rawPeer
	s, p = dgMuxRaw(t, 1200, false, nil)
	var rs relSeq
	send = func(typ wire.Type, h uint32, pl []byte) {
		if typ == wire.TypeDetach {
			h = 0
		}
		p.send(rs.rel(typ, 0, h, pl))
	}
	var top uint32
	var seen bool
	rack = func() {
		for _, d := range p.read() {
			fs, _ := dgDecode(d)
			for _, f := range fs {
				if f.Type != wire.TypeRel {
					continue
				}
				if rh, _, err := wire.ParseRel(f.Payload); err == nil && (!seen || wire.SeqLess(top, rh.Cseq)) {
					top, seen = rh.Cseq, true
				}
			}
		}
		if seen {
			p.send(rackFrame(top, 0))
		}
	}
	return s, send, rack
}
