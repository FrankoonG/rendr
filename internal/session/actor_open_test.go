package session

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The opening race and admission races (design §6.2, §6.3, §6.6; L47, L48;
// C4, C9, C16, C31).

// TestOpeningRaceRejectsOtherInstance_L47: factory p1 reaches the peer
// instance P1, factory p2 a restarted instance P2 (one byte stream must
// never be split across two passive instances, plan §3.4). Before binding
// is reached (p2's PREFACE_ACK passed the check before p1's OPEN_ACK(OK)
// bound the session) P2's later OPEN_ACK(OK) is answered RST(withdrawn);
// after binding p2's PREFACE_ACK itself is refused and the OPEN already
// written is withdrawn. Either way P2's session ends withdrawn and no
// carrier to P2 ever becomes a member of the bond.
func TestOpeningRaceRejectsOtherInstance_L47(t *testing.T) {
	for _, tc := range []struct {
		name  string
		bound bool // p2's PREFACE_ACK arrives after the binding
	}{{"ok-before-binding", false}, {"preface-after-binding", true}} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := acNewWorld(t, nil)
				defer w.teardown()
				p2 := acNewPassive(t, 3, nil)
				l1 := w.link("p1")
				l1.SetDelay(time.Millisecond, 0)
				l2 := w.linkTo("p2", p2)
				defer p2.wg.Wait()
				l2.SetDelay(time.Millisecond, 0)
				if tc.bound {
					l2.SetDelay(100*time.Millisecond, 0)
				}
				spec := w.spec(ModeBond, l1, l2)
				errc := make(chan error, 1)
				var a *Session
				go func() {
					s, err := w.dial(context.Background(), spec, nil)
					a = s
					errc <- err
				}()
				b1 := <-w.b.pending
				w.sess = append(w.sess, b1)
				var b2 *Session
				if tc.bound {
					time.Sleep(250 * time.Millisecond) // p2's attempt started at 200 ms; its PREFACE_ACK returns at ~400 ms
				} else {
					b2 = <-p2.pending // p2's OPEN passed the PREFACE_ACK check and is parked on P2
					w.sess = append(w.sess, b2)
				}
				if err := b1.Confirm(); err != nil {
					t.Fatalf("Confirm on P1: %v", err)
				}
				if err := <-errc; err != nil {
					t.Fatalf("Dial: %v", err)
				}
				if a.PeerInstance() != w.b.cenv.Local {
					t.Fatalf("bound to %x, want P1", a.PeerInstance())
				}
				if tc.bound {
					b2 = <-p2.pending // admitted before the dialer read P2's PREFACE_ACK
					w.sess = append(w.sess, b2)
				} else if err := b2.Confirm(); err != nil {
					t.Fatalf("Confirm on P2: %v", err)
				}
				select {
				case <-b2.Done():
				case <-time.After(5 * time.Second):
					t.Fatal("P2's session was not withdrawn")
				}
				v, _ := p2.reg.endedVerdict(b2)
				var ae *AbortError
				switch {
				case tc.bound && (v.Opened || v.Status != wire.StatusUnknownSession):
					t.Fatalf("P2 pending session verdict %+v, want withdrawn (UNKNOWN_SESSION)", v)
				case !tc.bound && (!errors.As(b2.Status().Err, &ae) || ae.Code != AbortWithdrawn || !ae.Remote):
					t.Fatalf("P2 confirmed session ended with %v, want RST(AbortWithdrawn)", b2.Status().Err)
				}
				time.Sleep(3 * time.Second) // p2's member slot keeps redialling P2
				st := a.Status()
				for _, c := range st.Carriers {
					if c.Name == "p2" && c.State != LaneDead && c.State != LaneJoining {
						t.Fatalf("a carrier to P2 became %v: %+v", c.State, st.Carriers)
					}
				}
				a.mu.Lock()
				for _, l := range a.lanes {
					if l.c.PeerInstance() != w.b.cenv.Local {
						a.mu.Unlock()
						t.Fatalf("lane %d reaches %x, not the bound instance", l.id, l.c.PeerInstance())
					}
				}
				a.mu.Unlock()
				if we, re := acTransfer(a, b1, 1<<20, 15, false); we != nil || re != nil {
					t.Fatalf("transfer on P1: %v %v", we, re)
				}
			})
		})
	}
}

// TestJoinRightAfterConfirm_L48: the passive's Registry.Opened is held, so
// the root's table would still say "pending"; the bond dialer's JOIN that
// arrives right after Confirm is decided by the session itself under its
// lock (C4): accepted, never BAD_REQUEST, and it attaches once the actor
// continues.
func TestJoinRightAfterConfirm_L48(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		release := make(chan struct{})
		w.b.reg.onOpened = func(*Session) { <-release }
		l1, l2 := w.link("p1"), w.link("p2")
		a, _ := w.open(ModeBond, nil, l1, l2)
		acWaitFor(t, time.Second, "the JOIN admitted", func() bool {
			joins, _ := w.b.counts()
			return joins[wire.StatusOK] == 1
		})
		joins, _ := w.b.counts()
		if joins[wire.StatusBadRequest] != 0 || len(joins) != 1 {
			t.Fatalf("JOIN answers while Opened was held: %v, want one OK", joins)
		}
		close(release)
		acWaitFor(t, time.Second, "the second member attached", func() bool { return a.dataMembers() == 2 })
		if st := a.Status(); st.State != StateOpen || st.Err != nil {
			t.Fatalf("dialer %+v", st)
		}
	})
}

// TestConcurrentJoinsRespectCarrierLimit_L48: a bond dialer with 12
// factories JOINs 11 members at once to a passive whose carrier limit is 4,
// while the passive's actor is held (its Registry.Opened call blocks), so
// no adopt is handled before every Join decided: the adopts posted but not
// yet handled count toward the limit (C31) — exactly 3 are accepted, the
// others get CAPACITY — and the session never holds more than 4 carriers.
func TestConcurrentJoinsRespectCarrierLimit_L48(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		w.b.p.MaxCarriers = 4
		w.a.p.MaxCarriers = 12
		release := make(chan struct{})
		w.b.reg.onOpened = func(*Session) { <-release }
		var links []*rendrtest.Link
		for i := range 12 {
			links = append(links, w.link(fmt.Sprintf("p%d", i)))
		}
		a, b := w.open(ModeBond, nil, links...)
		acWaitFor(t, time.Second, "every JOIN answered", func() bool {
			joins, _ := w.b.counts()
			return joins[wire.StatusOK]+joins[wire.StatusCapacity] >= 11
		})
		close(release)
		joins, _ := w.b.counts()
		if joins[wire.StatusOK] != 3 || joins[wire.StatusCapacity] < 8 {
			t.Fatalf("JOIN answers %v, want 3 OK and the rest CAPACITY", joins)
		}
		time.Sleep(3 * time.Second) // refused slots back off and retry
		b.mu.Lock()
		n := b.carriersLocked()
		b.mu.Unlock()
		if n > 4 || a.dataMembers() != 4 {
			t.Fatalf("passive holds %d carriers, dialer %d members; limit 4", n, a.dataMembers())
		}
		if we, re := acTransfer(a, b, 2<<20, 17, false); we != nil || re != nil {
			t.Fatalf("transfer: %v %v", we, re)
		}
	})
}

// TestOpeningRaceCarrierLimitNotTerminal_L48: with 16 factories and a slow
// Confirm, the opening race parks more OPENs than the passive's carrier
// limit (2) allows; OPEN_ACK(CAPACITY, CodeCarriers) refuses one carrier of
// the pending session, not the session: those attempts back off, the race
// continues, and Dial succeeds once the application confirms (P20, C16).
func TestOpeningRaceCarrierLimitNotTerminal_L48(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		w.b.p.MaxCarriers = 2
		w.a.p.JoinStagger = 10 * time.Millisecond
		var links []*rendrtest.Link
		for i := range 16 {
			links = append(links, w.link(fmt.Sprintf("p%d", i)))
		}
		spec := w.spec(ModeSelector, links...)
		errc := make(chan error, 1)
		var a *Session
		go func() {
			s, err := w.dial(context.Background(), spec, nil)
			a = s
			errc <- err
		}()
		b := <-w.b.pending
		w.sess = append(w.sess, b)
		time.Sleep(500 * time.Millisecond) // the slow application
		_, refused := w.b.counts()
		if refused[[2]uint32{uint32(wire.StatusCapacity), wire.CodeCarriers}] == 0 {
			t.Fatalf("no OPEN refused with CodeCarriers (stimulus): %v", refused)
		}
		start := time.Now()
		if err := b.Confirm(); err != nil {
			t.Fatalf("Confirm: %v", err)
		}
		if err := <-errc; err != nil {
			t.Fatalf("Dial: %v, want success after CodeCarriers refusals", err)
		}
		if d := time.Since(start); d > 50*time.Millisecond {
			t.Fatalf("Dial returned %v after Confirm", d)
		}
		if we, re := acTransfer(a, b, 1<<20, 18, false); we != nil || re != nil {
			t.Fatalf("transfer: %v %v", we, re)
		}
	})
}

// TestActorDialTypedAnswers: every refusal that ends the opening phase maps
// to its typed Dial error at once (design §6.6, §9; within 200 ms, one
// factory call): PREFACE_ACK VERSION or FEATURE → ErrVersion; PREFACE_ACK
// GOING_AWAY or CAPACITY, OPEN_ACK GOING_AWAY, and OPEN_ACK CAPACITY with
// any code but CodeCarriers → ErrCapacity (GOING_AWAY also notes the
// instance, D21); OPEN_ACK BAD_REQUEST → ErrProtocol, with CodeMetadataSize
// → ErrMetadataTooLarge; OPEN_ACK UNKNOWN_SESSION → ErrSessionLost (P8).
func TestActorDialTypedAnswers(t *testing.T) {
	cases := []struct {
		name   string
		gate   wire.PrefaceStatus // OK: answered by OPEN_ACK
		answer wire.OpenAck
		want   error
		noted  bool
	}{
		{"preface-version", wire.PrefaceVersion, wire.OpenAck{}, ErrVersion, false},
		{"preface-feature", wire.PrefaceFeature, wire.OpenAck{}, ErrVersion, false},
		{"preface-going-away", wire.PrefaceGoingAway, wire.OpenAck{}, ErrCapacity, true},
		{"preface-capacity", wire.PrefaceCapacity, wire.OpenAck{}, ErrCapacity, false},
		{"open-bad-request", wire.PrefaceOK, wire.OpenAck{Status: wire.StatusBadRequest, Code: wire.CodeBadMode}, ErrProtocol, false},
		{"open-metadata-size", wire.PrefaceOK, wire.OpenAck{Status: wire.StatusBadRequest, Code: wire.CodeMetadataSize}, ErrMetadataTooLarge, false},
		{"open-unknown-session", wire.PrefaceOK, wire.OpenAck{Status: wire.StatusUnknownSession}, ErrSessionLost, false},
		{"open-going-away", wire.PrefaceOK, wire.OpenAck{Status: wire.StatusGoingAway}, ErrCapacity, true},
		{"open-capacity", wire.PrefaceOK, wire.OpenAck{Status: wire.StatusCapacity, Code: wire.CodeMaxSessions}, ErrCapacity, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := acNewWorld(t, nil)
				defer w.teardown()
				if tc.gate != wire.PrefaceOK {
					st := tc.gate
					w.b.gate = func(*wire.Preface) wire.PrefaceStatus { return st }
				} else {
					oa := tc.answer
					w.b.answer = func(*wire.Open) (wire.OpenAck, bool) { return oa, true }
				}
				noted := make(chan [16]byte, 4)
				l1 := w.link("p1")
				spec := w.spec(ModeSelector, l1)
				spec.NoteGoAway = func(inst [16]byte) { noted <- inst }
				start := time.Now()
				s, err := w.dial(context.Background(), spec, nil)
				if s != nil || !errors.Is(err, tc.want) {
					t.Fatalf("Dial: %v, %v; want %v", s, err, tc.want)
				}
				if d := time.Since(start); d > 200*time.Millisecond {
					t.Fatalf("Dial failed after %v, want at once", d)
				}
				if n := l1.Stats().Dials; n != 1 {
					t.Fatalf("%d factory calls, want 1 (a terminal answer is not retried)", n)
				}
				switch {
				case tc.noted && len(noted) != 1:
					t.Fatalf("NoteGoAway called %d times, want once", len(noted))
				case tc.noted:
					if inst := <-noted; inst != w.b.cenv.Local {
						t.Fatalf("NoteGoAway(%x), want the passive instance", inst)
					}
				case len(noted) != 0:
					t.Fatal("an instance was noted as gone away")
				}
				if len(w.b.pending) != 0 {
					t.Fatal("a session was admitted")
				}
			})
		})
	}
}
