package session

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// WP4 race membership and HoLCoupled rows (M3 design §A6.1, §A6.6, §A7.3,
// §A11.1): race keeps bond's membership (Mode.members) — the SCHED lists
// every member, a dead member is redialled at once, deaths count as
// M3-D34 says — and one member per fate group; the ACK-duty move and the
// SCHED-resend target skip the HoLCoupled siblings of a write-blocked lane.

// mgSchedN returns how many members the dialer's current SCHED lists.
func mgSchedN(s *Session) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return int(s.ctl.set.N)
}

// TestModeRaceIsBondMembership: a race session over three independent
// factories keeps all three as members (M3-D29): the SCHED lists every
// member and the passive sends on exactly the listed carriers; every
// member carries every byte (each link moves at least 90 % of the transfer:
// a lane behind the ACK edge skips only what was delivered, L08); a member
// killed mid-transfer is redialled at once (one call, a rejoin within 100
// ms); its death counts one Death migration on the sending side (M3-D34),
// none on the receiver; every byte arrives once.
func TestModeRaceIsBondMembership(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		ls := []*rendrtest.Link{w.slowLink("p1"), w.slowLink("p2"), w.slowLink("p3")}
		a, b := w.open(ModeRace, nil, ls...)
		acWaitFor(t, time.Second, "three members on both ends", func() bool { return a.dataMembers() == 3 && b.dataMembers() == 3 })
		acWaitFor(t, time.Second, "the SCHED lists three members", func() bool { return mgSchedN(a) == 3 })

		const n = 8 << 20
		var up [3]int64
		for i, l := range ls {
			up[i] = l.Stats().Session.Bytes
		}
		done := make(chan [2]error, 1)
		go func() {
			we, re := acTransfer(a, b, n, 44, true)
			done <- [2]error{we, re}
		}()
		acWaitFor(t, 5*time.Second, "a quarter delivered", func() bool { return b.Status().DeliveredBytes >= n/4 })
		if d := b.Status().DeliveredBytes; d >= n/2 {
			t.Fatalf("%d of %d bytes delivered before the kill: no load across it", d, n)
		}
		dials := ls[1].Stats().Dials
		d0 := a.Status().MigDeath
		killed := time.Now()
		if ls[1].Kill() == 0 {
			t.Fatal("the kill hit no carrier")
		}
		acWaitFor(t, time.Second, "the member rejoined", func() bool { return a.Status().Rejoins == 1 && a.dataMembers() == 3 })
		if d := time.Since(killed); d > 100*time.Millisecond {
			t.Fatalf("member back %v after its death, want the immediate redial", d)
		}
		if got := ls[1].Stats().Dials - dials; got != 1 {
			t.Fatalf("%d redials of the dead member's factory, want 1", got)
		}
		if got := a.Status().MigDeath - d0; got != 1 {
			t.Fatalf("sender death migrations +%d at a member's death with DATA in flight, want +1 (M3-D34)", got)
		}
		acWaitFor(t, time.Second, "the SCHED lists the rejoined member", func() bool { return mgSchedN(a) == 3 && b.dataMembers() == 3 })
		r := <-done
		if r[0] != nil || r[1] != nil {
			t.Fatalf("transfer: write %v, read %v", r[0], r[1])
		}
		for i, l := range []int{0, 2} {
			if got := ls[l].Stats().Session.Bytes - up[l]; got < n*9/10 {
				t.Fatalf("member %d (p%d) moved %d session bytes, want a copy of nearly every byte (≥ %d)", i, l+1, got, n*9/10)
			}
		}
		as, bs := a.Status(), b.Status()
		if as.MigQuality+as.MigExplicit != 0 || bs.MigDeath+bs.MigQuality+bs.MigExplicit != 0 {
			t.Fatalf("migrations: sender %d/%d/%d receiver %d/%d/%d, want the one death on the sender only",
				as.MigDeath, as.MigQuality, as.MigExplicit, bs.MigDeath, bs.MigQuality, bs.MigExplicit)
		}
		if bs.DeliveredBytes != n || as.RetransmittedBytes != 0 {
			t.Fatalf("delivered %d (want %d), retransmitted %d (want 0: copies, no requeue while members live)", bs.DeliveredBytes, n, as.RetransmittedBytes)
		}
	})
}

// TestRaceOnePerFateGroup_L35: a race keeps one member per fate group
// (M3-D37): with p1, p2 in one group and p3 alone the copies travel on two
// carriers only (p2 is never dialled and carries nothing); unique
// accounting holds (L35): the receiver delivers each byte once, the
// sender's copies are at most one per byte.
func TestRaceOnePerFateGroup_L35(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		ls := []*rendrtest.Link{w.slowLink("p1"), w.slowLink("p2"), w.slowLink("p3")}
		a, b := wpOpen(w, mgSpec(w, ModeRace, []uint8{1, 1, 0}, ls...), nil)
		acWaitFor(t, time.Second, "two members", func() bool { return a.dataMembers() == 2 && b.dataMembers() == 2 })
		const n = 2 << 20
		if we, re := acTransfer(a, b, n, 45, true); we != nil || re != nil {
			t.Fatalf("transfer: write %v, read %v", we, re)
		}
		time.Sleep(5 * time.Second)
		synctest.Wait()
		if m := mgMembers(a); !mgSame(m, []int{0, 2}) {
			t.Fatalf("members %v, want p1 and p3", m)
		}
		if d := ls[1].Stats().Dials; d != 0 {
			t.Fatalf("p2 dialled %d times: a second member of p1's group", d)
		}
		for _, i := range []int{0, 2} {
			if got := ls[i].Stats().Session.Bytes; got < n {
				t.Fatalf("p%d moved %d session bytes, want every byte (≥ %d)", i+1, got, n)
			}
		}
		as, bs := a.Status(), b.Status()
		if bs.DeliveredBytes != n || as.AckedBytes != n {
			t.Fatalf("delivered %d, acked %d; want %d each (unique)", bs.DeliveredBytes, as.AckedBytes, n)
		}
		if as.Race.CopyBytes == 0 || as.Race.CopyBytes > n || bs.DupBytes > as.Race.CopyBytes {
			t.Fatalf("copies %d, receiver duplicates %d: want 0 < copies ≤ %d (two members) and duplicates ≤ copies", as.Race.CopyBytes, bs.DupBytes, n)
		}
	})
}

// TestRaceDeathCount (M3-D34, PA-32): a race data member's death counts
// one Death migration when its in-flight spans were non-empty — although
// nothing is requeued while the other member lives — and nothing when it
// had nothing in flight; a packet race member's death counts when it
// placed a DGRAM within the last PacketPing. The side that sent nothing
// counts no death; the rejoin counts Rejoins.
func TestRaceDeathCount(t *testing.T) {
	t.Run("stream", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := acNewWorld(t, nil)
			defer w.teardown()
			l1, l2 := w.slowLink("p1"), w.slowLink("p2")
			a, b := w.open(ModeRace, nil, l1, l2)
			acWaitFor(t, time.Second, "two members", func() bool { return a.dataMembers() == 2 && b.dataMembers() == 2 })
			const n = 8 << 20
			done := make(chan [2]error, 1)
			go func() {
				we, re := acTransfer(a, b, n, 46, false)
				done <- [2]error{we, re}
			}()
			acWaitFor(t, 5*time.Second, "a quarter delivered", func() bool { return b.Status().DeliveredBytes >= n/4 })
			a.mu.Lock()
			var infl uint64
			for _, l := range a.lanes {
				if l.factory == 1 {
					infl = l.infl.bytes()
				}
			}
			a.mu.Unlock()
			if infl == 0 {
				t.Fatal("premise: p2's member has nothing in flight at the kill")
			}
			if l2.Kill() == 0 {
				t.Fatal("the kill hit no carrier")
			}
			acWaitFor(t, time.Second, "the member rejoined", func() bool { return a.Status().Rejoins == 1 && a.dataMembers() == 2 })
			if as := a.Status(); as.MigDeath != 1 || as.RetransmittedBytes != 0 {
				t.Fatalf("after the busy member's death: death migrations %d (want 1), retransmitted %d (want 0)", as.MigDeath, as.RetransmittedBytes)
			}
			r := <-done
			if r[0] != nil || r[1] != nil {
				t.Fatalf("transfer: write %v, read %v", r[0], r[1])
			}
			acWaitFor(t, time.Second, "everything acknowledged", func() bool { return a.Status().AckedBytes == n })
			time.Sleep(time.Second)
			if l1.Kill() == 0 {
				t.Fatal("the idle kill hit no carrier")
			}
			acWaitFor(t, time.Second, "the idle member rejoined", func() bool { return a.Status().Rejoins == 2 && a.dataMembers() == 2 })
			as, bs := a.Status(), b.Status()
			if as.MigDeath != 1 {
				t.Fatalf("death migrations %d after an idle member's death, want still 1", as.MigDeath)
			}
			if bs.MigDeath != 0 {
				t.Fatalf("receiver death migrations %d, want 0 (it had nothing in flight)", bs.MigDeath)
			}
			if bs.DeliveredBytes != n {
				t.Fatalf("delivered %d, want %d", bs.DeliveredBytes, n)
			}
		})
	})
	t.Run("packet", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := wpNewWorld(t, nil)
			defer w.teardown()
			l1, l2 := wpLink(w, "p1", 1400), wpLink(w, "p2", 1400)
			l2.SetDelay(5*time.Millisecond, 0)
			a, b := wpOpen(w, wpSpec(w, ModeRace, 1400, l1, l2), nil)
			acWaitFor(t, time.Second, "two members", func() bool { return a.dataMembers() == 2 && b.dataMembers() == 2 })
			f := wpStartFlow(a, b, 200, 20*time.Millisecond)
			time.Sleep(3 * time.Second)
			for round, l := range []*rendrtest.Link{l2, l1} {
				d0, r0 := a.Status().MigDeath, a.Status().Rejoins
				if l.Kill() == 0 {
					t.Fatalf("round %d: the kill hit no carrier", round)
				}
				acWaitFor(t, time.Second, "the member rejoined", func() bool { return a.Status().Rejoins == r0+1 && a.dataMembers() == 2 })
				if d := a.Status().MigDeath; d != d0+1 {
					t.Fatalf("round %d: sender death migrations %d → %d, want +1", round, d0, d)
				}
				time.Sleep(3 * time.Second)
			}
			f.stop()
			acWaitFor(t, time.Second, "the flow drained", func() bool { return f.sent.Load() == f.got.Load() })
			if bs := b.Status(); bs.MigDeath != 0 {
				t.Fatalf("receiver death migrations %d, want 0", bs.MigDeath)
			}
			if f.duplicates() != 0 || f.sent.Load() < 300 {
				t.Fatalf("flow: sent %d, got %d, application duplicates %d", f.sent.Load(), f.got.Load(), f.duplicates())
			}
		})
	})
}

// mgHolSession is a dialer stream session with fake lanes a, b, c on
// factories 0, 1, 2: a and b form a HoLCoupled fate group, c is a group of
// its own; SRTTs 5, 10 and 50 ms put b before c in the duty order. Its
// actor is never run (state exited): it only carries the DialSpec.
func mgHolSession(t *testing.T, coupled bool) (s *Session, a *actor, lanes [3]*lane, ports [3]*stPort) {
	t.Helper()
	s = stSession(stOpt{})
	a = newActor(s)
	spec := DialSpec{Groups: [16]uint8{1, 1, 0}}
	if coupled {
		spec.Coupled = 1<<0 | 1<<1
	}
	a.d = newDialer(spec, nil)
	a.state.Store(actorExited)
	s.mb.actor.Store(a)
	for i, rtt := range []time.Duration{5, 10, 50} {
		lanes[i], ports[i] = stAddLane(s, uint32(i+1), i == 0)
		lanes[i].factory = i
		ports[i].set(func(f *stPort) { f.srtt = rtt * time.Millisecond })
	}
	s.mu.Lock()
	s.refreshOrderLocked(time.Now(), true)
	s.st.ackLane = lanes[0]
	s.mu.Unlock()
	return s, a, lanes, ports
}

// mgAckOn bumps an ACK and fills every lane but skip; it returns the lanes
// whose batch carried an ACK.
func mgAckOn(s *Session, lanes [3]*lane, skip *lane) []uint32 {
	s.mu.Lock()
	s.bumpNowLocked()
	s.mu.Unlock()
	var on []uint32
	for _, l := range lanes {
		if l == skip || l.state == LaneDead {
			continue
		}
		fs, b := stFill(l, time.Now())
		b.ReleaseRefs()
		if stCount(fs, wire.TypeAck) > 0 {
			on = append(on, l.id)
		}
	}
	return on
}

// TestHoLCoupledDutyMove_L08 (M3-D39, PA-30): a, b coupled, c independent;
// a's writes block: the ACK duty moves to c, never to its sibling b (which
// would stall with a), though b is faster; with c gone it moves to b. The
// SCHED-resend target follows the same rule. Without the coupling the duty
// moves to the faster b, as in M1.
func TestHoLCoupledDutyMove_L08(t *testing.T) {
	for _, coupled := range []bool{true, false} {
		name := "coupled"
		if !coupled {
			name = "independent"
		}
		t.Run(name, func(t *testing.T) {
			s, act, lanes, ports := mgHolSession(t, coupled)
			ports[0].set(func(f *stPort) { f.blocked = true })
			lanes[0].WriteBlocked(nil)
			want := lanes[2]
			if !coupled {
				want = lanes[1]
			}
			s.mu.Lock()
			duty := s.st.ackLane
			resend := act.resendLaneLocked()
			s.mu.Unlock()
			if duty != want || resend != want {
				t.Fatalf("a blocked: duty on %d, SCHED resend on %d; want %d", duty.id, resend.id, want.id)
			}
			if on := mgAckOn(s, lanes, lanes[0]); len(on) != 1 || on[0] != want.id {
				t.Fatalf("a blocked: the next ACK left on %v, want only %d", on, want.id)
			}
			if !coupled {
				stEnd(s, errClosed)
				return
			}
			stKillLane(s, lanes[2])
			s.mu.Lock()
			duty = s.st.ackLane
			resend = act.resendLaneLocked()
			s.mu.Unlock()
			if duty != lanes[1] || resend != lanes[1] {
				t.Fatalf("c gone: duty on %v, SCHED resend on %v; want b (%d), the only writable lane", duty, resend, lanes[1].id)
			}
			if on := mgAckOn(s, lanes, lanes[0]); len(on) != 1 || on[0] != lanes[1].id {
				t.Fatalf("c gone: the next ACK left on %v, want only b (%d)", on, lanes[1].id)
			}
			stEnd(s, errClosed)
		})
	}
}
