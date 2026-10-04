package session

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Routing decisions of the death step and the passive's send set (design
// §7.1, §7.3, §7.5, §7.6; L27, C7, D24, P13).

// acLane returns s's live lane with CarrierID id (nil if none).
func acLane(s *Session, id uint32) *lane {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.lanes {
		if l.id == id {
			return l
		}
	}
	return nil
}

// acActiveLane returns s's routed active lane (nil if none).
func acActiveLane(s *Session) *lane {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ctl.active
}

// acSwitchTo publishes evidence that makes factory to (of three or fewer)
// the quality target and waits for the dialer's quality migration and the
// passive's application of its SCHED.
func acSwitchTo(t testing.TB, h *acHealth, a *Session, rtt ...time.Duration) {
	t.Helper()
	q := a.Status().MigQuality
	h.set(rtt...)
	acWaitFor(t, 5*time.Second, "the quality switch", func() bool {
		st := a.Status()
		return st.MigQuality == q+1 && st.SchedEchoed == st.SchedEpoch
	})
}

// TestActorDeathSynchronousFallback: the active carrier B dies while its
// predecessor A — switched away from by quality — is still retiring.
//
//   - retire-pending: A's data is unacknowledged (the passive application
//     does not read) and RetireGrace is long, so Conn.Retire was not called
//     on A: it is a valid fallback (§7.3) and becomes active in B's death
//     step itself (held and checked with Hooks.DeathObserved), with one
//     death migration and SCHED cause death; the passive moves its sending
//     lane locally (D24) before that SCHED arrives, without counting, and
//     counts the one death migration when it applies the SCHED.
//   - retire-called: A was idle, so Retire was called at the switch, but
//     its CLOSE is still unwritten (A's writes are blocked) when B dies: Retire
//     is irreversible, so A is never made active again (C7) although nothing
//     else excludes it yet; a race replaces B, again with exactly one death
//     migration on both ends.
func TestActorDeathSynchronousFallback(t *testing.T) {
	for _, retireCalled := range []bool{false, true} {
		name := "retire-pending"
		if retireCalled {
			name = "retire-called"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				deaths := acNewHold()
				w := acNewWorld(t, &testhooks.Hooks{DeathObserved: deaths.hook})
				defer w.teardown()
				w.a.p.Selector.Dwell, w.a.p.Selector.Cooldown = 50*time.Millisecond, 50*time.Millisecond
				w.a.p.RetireGrace = 30 * time.Second
				h := acNewHealth(2, w.a.p.Selector.Fresh)
				h.set(30*time.Millisecond, 0)
				l1, l2 := w.link("p1"), w.link("p2")
				a, b := w.open(ModeSelector, h, l1, l2)
				defer acFreshen(h)()
				la := acActiveLane(a)
				const n = 256 << 10
				q := a.Status().MigQuality
				if retireCalled {
					// A's writes block from now on (until the stall watchdog
					// kills it after WriteStall): Retire is called at the
					// switch, but A's CLOSE stays unwritten. B dies within the
					// 5 ms polling step after the switch.
					l1.BlockWrites(rendrtest.Up, rendrtest.BlockSoft)
					h.set(30*time.Millisecond, 10*time.Millisecond)
					acWaitFor(t, 5*time.Second, "the quality switch", func() bool { return a.Status().MigQuality == q+1 })
					if la.c.CloseSent() {
						t.Fatal("A's CLOSE was written: the Retire-called rule is not isolated")
					}
				} else {
					if err := acWritePRNG(a, n, 81); err != nil { // unread: A keeps unacknowledged spans
						t.Fatalf("Write: %v", err)
					}
					acWaitFor(t, time.Second, "the data in flight on A", func() bool { return b.Status().RxBytes == n })
					acSwitchTo(t, h, a, 30*time.Millisecond, 10*time.Millisecond)
					// A (p1) becomes active again: p2 must not challenge it.
					// (With Retire called a race replaces B, and p2's 10 ms
					// keep whichever carrier wins from being switched again.)
					h.set(30*time.Millisecond, 0)
				}
				lb := acActiveLane(a)
				if lb == nil || lb == la {
					t.Fatalf("active after the switch: %v (A %d)", lb, la.id)
				}
				a.mu.Lock()
				retiring, called := la.state == LaneRetiring, la.retireCalled
				a.mu.Unlock()
				if dead, _, _, _ := la.c.Death(); dead || !retiring || called != retireCalled {
					t.Fatalf("A after the switch: dead %v, retiring %v, Retire called %v; want alive and retiring with Retire called %v", dead, retiring, called, retireCalled)
				}
				// After every critical section of the dialer's actor: A, once
				// Retire was called on it, never routes again (C7).
				var reactivated atomic.Bool
				uninstall := acAfterUnlock(func(s *Session) {
					if s == a && retireCalled && acActiveLane(a) == la {
						reactivated.Store(true)
					}
				})
				defer uninstall()
				epochQ := b.Status().SchedEpoch
				deaths.arm(lb.id)
				l2.Kill()
				<-deaths.held
				if got := acActive(a); got != lb.id {
					t.Fatalf("while B's death is held: active %d, want B %d", got, lb.id)
				}
				deaths.resume <- struct{}{}
				synctest.Wait() // no virtual time passes: B's death step and the passive's local fallback ran, no SCHED arrived
				if !retireCalled {
					if got := acActive(a); got != la.id {
						t.Fatalf("after B's death step: active %d, want A %d at once (synchronous fallback)", got, la.id)
					}
					a.mu.Lock()
					cause := a.ctl.cause
					a.mu.Unlock()
					if cause != wire.SchedDeath {
						t.Fatalf("SCHED cause %d, want death", cause)
					}
					if _, routed, _ := acRouted(b); routed != la.id || b.Status().SchedEpoch != epochQ || b.Status().MigDeath != 0 {
						t.Fatalf("passive before the SCHED: routed %d (want A %d), epoch %d (want %d), death migrations %d (want 0)",
							routed, la.id, b.Status().SchedEpoch, epochQ, b.Status().MigDeath)
					}
				}
				acWaitFor(t, 3*time.Second, "a new active carrier, its SCHED applied", func() bool {
					st := a.Status()
					id := acActive(a)
					return id != 0 && id != lb.id && st.SchedEchoed == st.SchedEpoch && st.MigDeath == 1
				})
				uninstall()
				if reactivated.Load() {
					t.Fatal("A, on which Retire was called, became active again (C7)")
				}
				if retireCalled {
					l1.BlockWrites(rendrtest.Up, rendrtest.BlockOff)
				}
				as, bs := a.Status(), b.Status()
				if as.MigDeath != 1 || bs.MigDeath != 1 || as.MigQuality != 1 || bs.MigQuality != 1 || as.MigExplicit+bs.MigExplicit != 0 {
					t.Fatalf("migrations: dialer %d/%d/%d passive %d/%d/%d, want one quality and one death on each end",
						as.MigDeath, as.MigQuality, as.MigExplicit, bs.MigDeath, bs.MigQuality, bs.MigExplicit)
				}
				if !retireCalled {
					acReadVerify(t, b, n, 81) // the data A carried, replayed on B and again on A
				}
				if we, re := acTransfer(a, b, 1<<20, 82, false); we != nil || re != nil {
					t.Fatalf("transfer: %v %v", we, re)
				}
			})
		})
	}
}

// TestActorSimultaneousDeathsCountOnce: B (active) and its retiring
// predecessor A die together. B's death step is held; A dies meanwhile, so
// when B's step runs A's carrier has a death record but no death step yet.
// A must not become B's fallback (§7.1: a lane observed dead is never made
// eligible): the race replaces B and both ends count one death migration
// (§7.6), not two on the dialer.
func TestActorSimultaneousDeathsCountOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		deaths := acNewHold()
		w := acNewWorld(t, &testhooks.Hooks{DeathObserved: deaths.hook})
		defer w.teardown()
		w.a.p.Selector.Dwell, w.a.p.Selector.Cooldown = 50*time.Millisecond, 50*time.Millisecond
		w.a.p.RetireGrace = 30 * time.Second
		h := acNewHealth(3, w.a.p.Selector.Fresh)
		h.set(30*time.Millisecond, 0, 0)
		l1, l2, l3 := w.link("p1"), w.link("p2"), w.link("p3")
		a, b := w.open(ModeSelector, h, l1, l2, l3)
		defer acFreshen(h)()
		la := acActiveLane(a)
		if err := acWritePRNG(a, 128<<10, 83); err != nil { // unread: A stays retiring, Retire not called
			t.Fatalf("Write: %v", err)
		}
		acSwitchTo(t, h, a, 30*time.Millisecond, 10*time.Millisecond, 0)
		lb := acActiveLane(a)
		h.set(30*time.Millisecond, 0, 0)
		deaths.arm(lb.id)
		l2.Kill()
		<-deaths.held
		l1.Kill()
		acWaitFor(t, time.Second, "A's carrier recorded its death", func() bool {
			dead, _, _, _ := la.c.Death()
			return dead
		})
		deaths.resume <- struct{}{}
		acWaitFor(t, 3*time.Second, "a new active carrier, its SCHED applied", func() bool {
			st := a.Status()
			id := acActive(a)
			return id != 0 && id != la.id && id != lb.id && st.SchedEchoed == st.SchedEpoch
		})
		for _, ev := range w.a.ev.of(a.ID(), EventMigration) {
			if ev.To == la.id && ev.From == lb.id {
				t.Fatalf("migration %d → %d to the carrier that already ended", ev.From, ev.To)
			}
		}
		as, bs := a.Status(), b.Status()
		if as.MigDeath != 1 || bs.MigDeath != 1 {
			t.Fatalf("death migrations: dialer %d, passive %d, want 1 each", as.MigDeath, bs.MigDeath)
		}
		if as.NoPathEpisodes != 1 {
			t.Fatalf("no-path episodes %d, want 1 (both carriers ended)", as.NoPathEpisodes)
		}
		acReadVerify(t, b, 128<<10, 83) // the bytes A carried, replayed through the race winner
		if we, re := acTransfer(a, b, 1<<20, 84, false); we != nil || re != nil {
			t.Fatalf("transfer: %v %v", we, re)
		}
	})
}

// acReadVerify reads exactly n bytes of PRNG(seed) from s.
func acReadVerify(t testing.TB, s *Session, n int, seed uint64) {
	t.Helper()
	v := rendrtest.NewVerifier(seed, int64(n))
	buf := make([]byte, 64<<10)
	for got := 0; got < n; {
		k, err := s.Read(buf[:min(len(buf), n-got)])
		v.Write(buf[:k])
		got += k
		if err != nil {
			t.Fatalf("%v read after %d of %d bytes: %v", s.Role(), got, n, err)
		}
	}
	if err := v.Done(io.EOF); err != nil { // exactly n bytes matched (the stream itself goes on)
		t.Fatalf("%v read: %v", s.Role(), err)
	}
}

// TestActorPassiveReportsSenderAtConfirm: Confirm routes the passive's
// epoch-0 sender at once (its DATA may follow its OPEN_ACK in the same
// batch), so the same critical section reports it active (L27): a check
// after every critical section of the passive's actor, from before Confirm
// until the open settled, never sees the reported active carrier differ
// from the routed one, in either mode.
func TestActorPassiveReportsSenderAtConfirm(t *testing.T) {
	for _, mode := range []Mode{ModeSelector, ModeBond} {
		t.Run(acModeName(mode), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := acNewWorld(t, nil)
				defer w.teardown()
				l1, l2 := w.link("p1"), w.link("p2")
				for i := range 10 {
					spec := w.spec(mode, l1, l2)
					errc := make(chan error, 1)
					go func() {
						_, err := w.dial(context.Background(), spec, nil)
						errc <- err
					}()
					b := <-w.b.pending
					w.sess = append(w.sess, b)
					rc, uninstall := acCheckRouting(b)
					if err := b.Confirm(); err != nil {
						t.Fatalf("Confirm: %v", err)
					}
					if v := acRoutingViolation(b); v != "" || b.dataMembers() == 0 {
						t.Fatalf("open %d right after Confirm: %s (%d data lanes)", i, v, b.dataMembers())
					}
					if err := <-errc; err != nil {
						t.Fatalf("Dial: %v", err)
					}
					synctest.Wait()
					uninstall()
					if v := rc.violation(); v != "" {
						t.Fatalf("open %d: %s", i, v)
					}
					if rc.checks[0].Load() == 0 {
						t.Fatal("no critical section of the passive was checked (stimulus)")
					}
					if mode == ModeBond {
						b.mu.Lock()
						for _, l := range b.lanes {
							if l.data && l.state == LaneJoining {
								b.mu.Unlock()
								t.Fatalf("open %d: data lane %d reported joining", i, l.id)
							}
						}
						b.mu.Unlock()
					}
				}
			})
		})
	}
}

// TestActorPassiveBondFallbackStable: the passive applied a bond SCHED whose
// listed carriers are not (yet) usable, so its D24 fallback carries the
// data; recomputing the routing — here two more such SCHEDs — keeps that
// fallback: its in-flight spans are never requeued and resent.
func TestActorPassiveBondFallbackStable(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		l1 := w.link("p1")
		a, b := w.open(ModeBond, nil, l1)
		acWaitFor(t, time.Second, "the first SCHED applied", func() bool { return b.Status().SchedEpoch == 1 })
		b.mu.Lock()
		pl := b.lanes[0]
		b.mu.Unlock()
		acSched(t, pl, wire.SchedInitial, 2, 999) // a carrier the passive does not have
		synctest.Wait()
		if !pl.data || b.dataMembers() != 1 {
			t.Fatal("the fallback is not the only data lane after a SCHED naming no usable carrier")
		}
		const n = 256 << 10
		if err := acWritePRNG(b, n, 85); err != nil { // the dialer does not read: the spans stay in flight
			t.Fatalf("Write: %v", err)
		}
		acWaitFor(t, time.Second, "the data in flight", func() bool { return a.Status().RxBytes == n })
		for e := uint32(3); e <= 4; e++ {
			acSched(t, pl, wire.SchedInitial, e, 999, 998)
			synctest.Wait()
			b.mu.Lock()
			retx, infl := b.st.retx.bytes(), pl.infl.bytes()
			b.mu.Unlock()
			if retx != 0 || infl != n || !pl.data {
				t.Fatalf("after SCHED %d: retx %d, in flight on the fallback %d (want %d), data %v", e, retx, infl, n, pl.data)
			}
		}
		if st := b.Status(); st.RetransmittedBytes != 0 || st.SchedEpoch != 4 {
			t.Fatalf("passive: %d bytes retransmitted, epoch %d", st.RetransmittedBytes, st.SchedEpoch)
		}
		acReadVerify(t, a, n, 85)
	})
}

// TestActorBondOwedDeathCounted: a single-member bond whose member dies
// mid-transfer: the sender's unacknowledged DATA has no member to move to,
// so its death migration is owed and counted when the redialled member
// starts carrying data — on the sender's side whichever side sends (§7.3,
// §7.6); the pure receiver counts none. Every byte arrives.
func TestActorBondOwedDeathCounted(t *testing.T) {
	for _, passiveSends := range []bool{false, true} {
		name := "dialer-sends"
		if passiveSends {
			name = "passive-sends"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := acNewWorld(t, nil)
				defer w.teardown()
				l1 := w.slowLink("p1")
				a, b := w.open(ModeBond, nil, l1)
				acWaitFor(t, time.Second, "the passive sends on the member", func() bool { return b.dataMembers() == 1 })
				src, dst := a, b
				if passiveSends {
					src, dst = b, a
				}
				const n = 8 << 20
				done := make(chan [2]error, 1)
				go func() {
					we, re := acTransfer(src, dst, n, 86, true)
					done <- [2]error{we, re}
				}()
				acWaitFor(t, 5*time.Second, "a quarter delivered", func() bool { return dst.Status().DeliveredBytes >= n/4 })
				if d := dst.Status().DeliveredBytes; d >= n/2 {
					t.Fatalf("%d of %d bytes delivered before the kill: no load across it", d, n)
				}
				if l1.Kill() == 0 {
					t.Fatal("the kill hit no carrier")
				}
				r := <-done
				if r[0] != nil || r[1] != nil {
					t.Fatalf("transfer: write %v, read %v", r[0], r[1])
				}
				ss, ds := src.Status(), dst.Status()
				if ss.MigDeath != 1 || ds.MigDeath != 0 || ss.RetransmittedBytes == 0 {
					t.Fatalf("sender %v: %d death migrations, %d bytes retransmitted; receiver %d death migrations; want 1 and 0",
						src.Role(), ss.MigDeath, ss.RetransmittedBytes, ds.MigDeath)
				}
				if a.Status().Rejoins != 1 {
					t.Fatalf("rejoins %d, want the member's redial", a.Status().Rejoins)
				}
			})
		})
	}
}

// TestActorGoAwayOnDyingLane: the peer's GOAWAY arrives on a bond member
// whose carrier dies before the actor's next step (the actor is held in
// another member's death step meanwhile). GOAWAY from the bound instance
// ends the session whether or not its lane is still alive (§4.7, §6.8):
// *AbortError{AbortGoingAway, Remote: true}, and the Peer notes the
// instance once.
func TestActorGoAwayOnDyingLane(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		deaths := acNewHold()
		w := acNewWorld(t, &testhooks.Hooks{DeathObserved: deaths.hook})
		defer w.teardown()
		noted := make(chan [16]byte, 4)
		l1, l2 := w.link("p1"), w.link("p2")
		spec := w.spec(ModeBond, l1, l2)
		spec.NoteGoAway = func(inst [16]byte) { noted <- inst }
		a, _ := w.openSpec(spec, nil)
		acWaitFor(t, time.Second, "both members", func() bool { return a.dataMembers() == 2 })
		a.mu.Lock()
		first, second := a.lanes[0], a.lanes[1]
		a.mu.Unlock()
		deaths.arm(first.id)
		if first.c.Name() == "p1" {
			l1.Kill()
		} else {
			l2.Kill()
		}
		<-deaths.held
		gl := l2
		if second.c.Name() == "p1" {
			gl = l1
		}
		gl.InjectAfterNextFrame(rendrtest.Down, rendrtest.FramePong, rendrtest.FrameGoAway, 0, 0, []byte{1})
		acWaitFor(t, 3*time.Second, "the GOAWAY recorded on the second member", func() bool { return second.c.PeerGoAway() })
		gl.Kill()
		acWaitFor(t, time.Second, "the second member's death recorded", func() bool {
			dead, _, _, _ := second.c.Death()
			return dead
		})
		deaths.resume <- struct{}{}
		acDone(t, a, 5*time.Second)
		var ae *AbortError
		if st := a.Status(); !errors.As(st.Err, &ae) || ae.Code != AbortGoingAway || !ae.Remote {
			t.Fatalf("end error %v, want *AbortError{AbortGoingAway, Remote}", st.Err)
		}
		select {
		case inst := <-noted:
			if inst != w.b.cenv.Local {
				t.Fatalf("NoteGoAway(%x), want the passive instance", inst)
			}
		default:
			t.Fatal("the gone-away instance was not noted")
		}
		if len(noted) != 0 {
			t.Fatal("the instance was noted more than once")
		}
		if gl.Stats().Session.FramesInjected != 1 {
			t.Fatal("no GOAWAY was injected (stimulus)")
		}
	})
}
