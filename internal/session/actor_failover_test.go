package session

import (
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Failover component tests (design §7.3, §7.4, §7.5, §7.7): selector death
// failover, bond member redial, SCHED convergence, no-path expiry and
// recovery. Each proves its stimulus (the link counters), the load (bytes
// moved across the event) and integrity (a verifier over every byte).

// TestActorSelectorFailover: killing the active carrier mid-transfer moves
// the session to the other factory in the death step's race; every byte
// arrives; both ends count exactly one death migration.
func TestActorSelectorFailover(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		l1, l2 := w.slowLink("p1"), w.slowLink("p2")
		a, b := w.open(ModeSelector, nil, l1, l2)
		first := acActive(a)
		if first == 0 {
			t.Fatal("no active carrier after the open")
		}

		const n = 8 << 20
		done := make(chan [2]error, 1)
		go func() {
			we, re := acTransfer(a, b, n, 21, true)
			done <- [2]error{we, re}
		}()
		acWaitFor(t, 5*time.Second, "a quarter of the bytes delivered", func() bool {
			return b.Status().DeliveredBytes >= n/4
		})
		if d := b.Status().DeliveredBytes; d >= n/2 {
			t.Fatalf("%d of %d bytes delivered before the kill: no load across it", d, n)
		}
		if k := l1.Kill(); k == 0 {
			t.Fatal("the kill hit no carrier")
		}
		r := <-done
		if r[0] != nil || r[1] != nil {
			t.Fatalf("transfer across the failover: write %v, read %v", r[0], r[1])
		}
		if l2.Stats().Session.Bytes == 0 {
			t.Fatal("the surviving link carried no session bytes")
		}
		as, bs := a.Status(), b.Status()
		if as.MigDeath != 1 || bs.MigDeath != 1 {
			t.Fatalf("death migrations: dialer %d, passive %d, want 1 and 1", as.MigDeath, bs.MigDeath)
		}
		if as.MigQuality+as.MigExplicit+bs.MigQuality+bs.MigExplicit != 0 {
			t.Fatalf("unexpected migrations: %+v / %+v", as, bs)
		}
		if now := acActive(a); now == 0 || now == first {
			t.Fatalf("active carrier %d after the failover (was %d)", now, first)
		}
		ev := w.a.ev.of(a.ID(), EventMigration)
		if len(ev) != 1 || ev[0].From != first || !ev[0].Cause.Death() {
			t.Fatalf("migration events %+v, want one death migration from %d", ev, first)
		}
	})
}

// TestActorBondMemberRedial: a bond member that dies is redialled at once
// (not gated by any mark, plan §3.2) and rejoins as a new incarnation of
// its slot; the transfer continues on the other member meanwhile and every
// byte arrives. The side whose unacknowledged DATA moved to the surviving
// member counts one death migration; the pure receiver counts none (§7.6).
func TestActorBondMemberRedial(t *testing.T) {
	for _, passiveSends := range []bool{false, true} {
		name := "dialer-sends"
		if passiveSends {
			name = "passive-sends"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := acNewWorld(t, nil)
				defer w.teardown()
				l1, l2 := w.slowLink("p1"), w.slowLink("p2")
				a, b := w.open(ModeBond, nil, l1, l2)
				acWaitFor(t, time.Second, "both members attached", func() bool { return a.dataMembers() == 2 })
				acWaitFor(t, time.Second, "the passive sends on both", func() bool { return b.dataMembers() == 2 })
				src, dst := a, b
				if passiveSends {
					src, dst = b, a
				}
				const n = 8 << 20
				done := make(chan [2]error, 1)
				go func() {
					we, re := acTransfer(src, dst, n, 22, true)
					done <- [2]error{we, re}
				}()
				acWaitFor(t, 5*time.Second, "a quarter delivered", func() bool { return dst.Status().DeliveredBytes >= n/4 })
				if d := dst.Status().DeliveredBytes; d >= n/2 {
					t.Fatalf("%d of %d bytes delivered before the kill: no load across it", d, n)
				}
				dials := l2.Stats().Dials
				killed := time.Now()
				if l2.Kill() == 0 {
					t.Fatal("the kill hit no carrier")
				}
				acWaitFor(t, time.Second, "the member rejoined", func() bool {
					return a.Status().Rejoins == 1 && a.dataMembers() == 2
				})
				if d := time.Since(killed); d > 100*time.Millisecond {
					t.Fatalf("member back %v after its death, want the immediate redial", d)
				}
				if got := l2.Stats().Dials - dials; got != 1 {
					t.Fatalf("%d redials of the dead member's factory, want 1", got)
				}
				r := <-done
				if r[0] != nil || r[1] != nil {
					t.Fatalf("transfer: write %v, read %v", r[0], r[1])
				}
				ss, ds := src.Status(), dst.Status()
				if ss.MigDeath != 1 || ss.MigQuality+ss.MigExplicit != 0 || ds.MigDeath+ds.MigQuality+ds.MigExplicit != 0 {
					t.Fatalf("migrations: sender %d/%d/%d receiver %d/%d/%d, want one death on the sender",
						ss.MigDeath, ss.MigQuality, ss.MigExplicit, ds.MigDeath, ds.MigQuality, ds.MigExplicit)
				}
			})
		})
	}
}

// dataMembers counts the data-eligible lanes (tests).
func (s *Session) dataMembers() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, l := range s.lanes {
		if l.data {
			n++
		}
	}
	return n
}

// TestActorSchedResentUntilEcho: while the passive's actor is held (its
// Registry.Opened call blocks), nothing echoes the dialer's first SCHED, so
// the dialer re-sends it single-flight (D6); once released the passive
// applies it exactly once, the echo arrives and the resends stop.
func TestActorSchedResentUntilEcho(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		release := make(chan struct{})
		w.b.reg.onOpened = func(*Session) { <-release }
		l1 := w.link("p1")
		a, b := w.open(ModeSelector, nil, l1)
		time.Sleep(time.Second)
		if st := a.Status(); st.SchedEpoch != 1 || st.SchedEchoed != 0 {
			t.Fatalf("held passive: dialer epoch %d echoed %d, want 1 and 0", st.SchedEpoch, st.SchedEchoed)
		}
		resent := l1.CaptureNextFrame(rendrtest.Up, rendrtest.FrameType(0x14)) // SCHED
		select {
		case f := <-resent:
			if len(f) == 0 {
				t.Fatal("empty capture")
			}
		case <-time.After(200 * time.Millisecond):
			t.Fatal("no SCHED resend within 200 ms while unechoed")
		}
		close(release)
		acWaitFor(t, time.Second, "the SCHED echoed", func() bool { return a.Status().SchedEchoed == 1 })
		if st := b.Status(); st.SchedEpoch != 1 || st.MigDeath+st.MigQuality+st.MigExplicit != 0 {
			t.Fatalf("passive: applied epoch %d, migrations %d/%d/%d", st.SchedEpoch, st.MigDeath, st.MigQuality, st.MigExplicit)
		}
		after := l1.CaptureNextFrame(rendrtest.Up, rendrtest.FrameType(0x14))
		select {
		case <-after:
			t.Fatal("SCHED re-sent after the echo")
		case <-time.After(2 * time.Second):
		}
		if we, re := acTransfer(a, b, 1<<20, 23, false); we != nil || re != nil {
			t.Fatalf("transfer: %v %v", we, re)
		}
	})
}

// TestActorNoPathExpiry: after its only carrier died and every redial is
// refused, the session ends with ErrNoPath once NoPathGrace passed since
// the death (not since the last frame), on both ends; blocked calls return
// it and the factory was retried (stimulus).
func TestActorNoPathExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		w.a.p.Grace = 3 * time.Second
		w.a.p.Retain = 4 * time.Second
		l1 := w.link("p1")
		a, b := w.open(ModeSelector, nil, l1)
		readErr := make(chan error, 1)
		go func() {
			_, err := a.Read(make([]byte, 8))
			readErr <- err
		}()
		synctest.Wait()
		l1.SetRefuse(true)
		dials := l1.Stats().Dials
		killed := time.Now()
		l1.Kill()
		err := <-readErr
		if !errors.Is(err, ErrNoPath) {
			t.Fatalf("blocked Read: %v, want ErrNoPath", err)
		}
		if d := time.Since(killed); d < 3*time.Second || d > 3500*time.Millisecond {
			t.Fatalf("ErrNoPath %v after the death, want the 3 s grace", d)
		}
		if l1.Stats().Dials-dials < 2 {
			t.Fatal("the factory was not retried during the episode")
		}
		st := a.Status()
		if st.NoPathEpisodes != 1 || !errors.Is(st.Err, ErrNoPath) {
			t.Fatalf("dialer status %+v", st)
		}
		<-b.Done() // the passive: PassiveRetain from its own detection
		if st := b.Status(); !errors.Is(st.Err, ErrNoPath) || st.NoPathEpisodes != 1 {
			t.Fatalf("passive end %v after %d episodes, want ErrNoPath", st.Err, st.NoPathEpisodes)
		}
		w.b.reg.mu.Lock()
		orphaned := w.b.reg.orphaned[b]
		w.b.reg.mu.Unlock()
		if orphaned != 1 {
			t.Fatalf("passive Orphaned(on) %d times, want 1", orphaned)
		}
	})
}

// TestActorNoPathRecovery: a carrier attaching before the grace ends the
// episode; the session continues intact and a later episode gets a fresh
// budget.
func TestActorNoPathRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		w.a.p.Grace = 3 * time.Second
		w.a.p.Retain = 4 * time.Second
		l1 := w.link("p1")
		a, b := w.open(ModeSelector, nil, l1)
		for ep := 1; ep <= 2; ep++ {
			l1.SetRefuse(true)
			l1.Kill()
			acWaitFor(t, time.Second, "the episode started", func() bool { return a.Status().InNoPath })
			time.Sleep(2 * time.Second) // inside the 3 s grace
			l1.SetRefuse(false)
			acWaitFor(t, 2*time.Second, "recovered", func() bool {
				st := a.Status()
				return !st.InNoPath && acActive(a) != 0
			})
			if st := a.Status(); st.NoPathEpisodes != uint64(ep) || st.State != StateOpen {
				t.Fatalf("episode %d: %+v", ep, st)
			}
			if we, re := acTransfer(a, b, 1<<20, uint64(30+ep), false); we != nil || re != nil {
				t.Fatalf("transfer after episode %d: %v %v", ep, we, re)
			}
		}
		if got := a.Status().MigDeath; got != 2 {
			t.Fatalf("dialer death migrations %d, want 2", got)
		}
		_ = carrier.CauseNone
	})
}

// TestActorBondRescue: one bond member's path stalls mid-transfer (its
// bytes in transit are held); the head of the send window stuck there is
// duplicated on the other member after RescueMin (§4.11, W7), so delivery
// keeps progressing before the stalled member is declared dead; every byte
// arrives once the member died and was redialled. The stalled member is the
// one that joined (p2): the passive's ACKs stay on its first carrier (p1),
// so the dialer's view of the head stays exact — with the ACKs held behind
// the stall as well, only the death of the member could recover.
//
// During the stall both rescue rules hold: the holder of the stuck head
// never sends the duplicate while the other member exists (rescueSendHook;
// the other member does), and each value of the head is rescued at most
// once (the retransmitted bytes stay within one segment per distinct head
// value). p2 itself may rescue a head p1 holds (any lane but the holder
// may): with p1's 400 ms delay a head on p1 can stay stuck for RescueWait,
// so p2's retransmitted bytes are not a measure of the holder rule.
// In the slow-rescuer variant the rescuing member's path has a 400 ms
// one-way delay, so the duplicate is acknowledged only after several
// rescue checks at the same head: none of them may rescue it again.
//
// The stall starts while p2 carries a burst (K8): the bond counts the
// member's death only when it requeues this side's unacknowledged DATA
// (m1b §7.6), and each rescue moves at most one segment off the stalled
// member, one per RescueMin plus a round trip on p1. A stall that caught
// fewer segments in transit than the rescues acknowledged before the death
// (at most DeadMax after the stall) left nothing to requeue, so the death
// rightly counted no migration — the wait for it below failed in about one
// of 20–60 runs under -race, where scheduling moves the stall's phase in
// p2's bursts. The test now waits for a burst holding more segments than
// that bound, so the death always finds DATA to requeue.
func TestActorBondRescue(t *testing.T) {
	for _, slow := range []bool{false, true} {
		name := "fast-rescuer"
		if slow {
			name = "slow-rescuer"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := acNewWorld(t, nil)
				defer w.teardown()
				window := 800 * time.Millisecond // before the stalled member's PING deadline (DeadMin 1 s)
				delay := time.Millisecond        // p1's one-way delay (slowLink)
				if slow {
					w.a.cenv.Timing.DeadMin, w.a.cenv.Timing.DeadMax = 3*time.Second, 4*time.Second
					window = 2500 * time.Millisecond
					delay = 400 * time.Millisecond
				}
				seg := int64(w.a.cenv.Timing.Segment)
				// Rescues acknowledged before the stalled member's death:
				// at most one per RescueMin plus p1's round trip until
				// DeadMax (and a PING interval) after the stall, plus one
				// already under way when it starts.
				maxRescued := int64((w.a.cenv.Timing.DeadMax+100*time.Millisecond)/(w.a.p.RescueMin+2*delay)) + 2
				l1, l2 := w.slowLink("p1"), w.slowLink("p2")
				l1.SetRate(8 << 20)
				l2.SetRate(8 << 20)
				a, b := w.open(ModeBond, nil, l1, l2)
				acWaitFor(t, time.Second, "both members", func() bool { return a.dataMembers() == 2 })
				if slow {
					l1.SetDelay(400*time.Millisecond, 0)
				}
				const n = 24 << 20
				done := make(chan [2]error, 1)
				go func() {
					we, re := acTransfer(a, b, n, 51, true)
					done <- [2]error{we, re}
				}()
				acWaitFor(t, 5*time.Second, "2 MiB delivered", func() bool { return b.Status().DeliveredBytes >= 2<<20 })
				if l2.Stats().Session.Bytes == 0 {
					t.Fatal("the joined member carried nothing before the stall")
				}
				// transit is the DATA payload the dialer wrote on p2 that the
				// passive has not received yet.
				transit := func() int64 {
					var tx, rx uint64
					var id uint32
					for _, c := range a.Status().Carriers {
						if c.Name == "p2" && c.State != LaneDead {
							tx, id = c.Stats.TxBytes, c.ID
						}
					}
					for _, c := range b.Status().Carriers {
						if c.ID == id {
							rx = c.Stats.RxBytes
						}
					}
					return int64(tx) - int64(rx)
				}
				// No goroutine of the bubble runs between the check and the
				// stall (acWaitFor returns after synctest.Wait). In the fast
				// variant p2 must also have room left under its capacity
				// cap: the holder rule below is only tested if the stalled
				// holder could place the duplicate itself (a holder at its
				// cap places nothing). The slow variant's p2 gets room while
				// the stall lasts, and a burst with room is rare there.
				acWaitFor(t, 3*time.Second, "a burst in transit on p2", func() bool {
					if transit() <= maxRescued*seg {
						return false
					}
					for _, c := range a.Status().Carriers {
						if c.Name == "p2" && c.State != LaneDead {
							return slow || c.Stats.Cap-c.Stats.Inflight >= seg
						}
					}
					return false
				})
				l2.SetStall(true)
				time.Sleep(100 * time.Millisecond)
				if got := transit(); got <= maxRescued*seg {
					t.Fatalf("%d bytes held on p2 by the stall, want more than %d segments (stimulus)", got, maxRescued)
				}
				retx := func(name string) uint64 {
					for _, c := range a.Status().Carriers {
						if c.Name == name && c.State != LaneDead {
							return c.Stats.RetxBytes
						}
					}
					t.Fatalf("no live carrier %s", name)
					return 0
				}
				d0, r0 := b.Status().DeliveredBytes, a.Status().RetransmittedBytes
				placed := rhWatchRescues(t, a)
				o0 := retx("p1")
				heads := map[uint64]bool{}
				for end := time.Now().Add(window); time.Now().Before(end); {
					heads[a.Status().AckedBytes] = true
					time.Sleep(10 * time.Millisecond)
				}
				st := a.Status()
				if st.MigDeath != 0 {
					t.Fatalf("the stalled member died before the rescue window ended: %+v", st)
				}
				// Without the rescue the in-order point stays at the held head.
				if d1 := b.Status().DeliveredBytes; d1 <= d0 || st.RetransmittedBytes <= r0 {
					t.Fatalf("during the stall: delivered %d → %d, retransmitted %d → %d; want progress by rescue", d0, d1, r0, st.RetransmittedBytes)
				}
				if holder, other, both := placed.counts(); both != 0 || holder != 0 || other == 0 {
					t.Fatalf("rescues placed during the stall: %d by the holder alone, %d by another member, %d by the holder beside another member; want only by another member", holder, other, both)
				}
				if o1 := retx("p1"); o1 <= o0 {
					t.Fatalf("p1 retransmitted %d → %d during the stall: the duplicate of p2's held head must leave on p1", o0, o1)
				}
				if got, bound := st.RetransmittedBytes-r0, uint64(len(heads))*uint64(w.a.cenv.Timing.Segment); got > bound {
					t.Fatalf("%d bytes retransmitted during the stall over %d head values: more than one segment per head", got, len(heads))
				}
				if l2.Stats().Session.Held == 0 {
					t.Fatal("no chunk was held by the stall (stimulus)")
				}
				acWaitFor(t, 10*time.Second, "the stalled member died", func() bool { return a.Status().MigDeath == 1 })
				l2.SetStall(false)
				r := <-done
				if r[0] != nil || r[1] != nil {
					t.Fatalf("transfer: write %v, read %v", r[0], r[1])
				}
			})
		})
	}
}

// TestActorPeerCloseIsExplicit: the passive (here: an injected frame)
// retires the dialer's active carrier with CLOSE while the session lives:
// the dialer answers it, loses the active lane — a routing loss repaired at
// once by its race — and both ends count one explicit migration, no death
// migration (§7.3, §7.6).
func TestActorPeerCloseIsExplicit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		l1, l2 := w.link("p1"), w.link("p2")
		// With a one-way delay the dialer's actor handles the CLOSE before
		// any later frame of the passive can arrive on that carrier (which
		// would be a violation after the peer's CLOSE, i.e. a death).
		l1.SetDelay(time.Millisecond, 0)
		l2.SetDelay(time.Millisecond, 0)
		a, b := w.open(ModeSelector, nil, l1, l2)
		first := acActive(a)
		acWaitFor(t, time.Second, "the SCHED echoed", func() bool { return a.Status().SchedEchoed == 1 })
		l1.InjectAfterNextFrame(rendrtest.Down, rendrtest.FramePong, rendrtest.FrameClose, 0, 0, []byte{1})
		acWaitFor(t, 3*time.Second, "the explicit migration", func() bool {
			id := acActive(a)
			return a.Status().MigExplicit == 1 && id != 0 && id != first
		})
		if l1.Stats().Session.FramesInjected != 1 {
			t.Fatal("no CLOSE was injected (stimulus)")
		}
		acWaitFor(t, 2*time.Second, "the passive followed", func() bool { return b.Status().MigExplicit == 1 })
		as, bs := a.Status(), b.Status()
		if as.MigDeath+bs.MigDeath+as.MigQuality+bs.MigQuality != 0 {
			t.Fatalf("migrations: dialer %d/%d/%d passive %d/%d/%d, want one explicit each",
				as.MigDeath, as.MigQuality, as.MigExplicit, bs.MigDeath, bs.MigQuality, bs.MigExplicit)
		}
		if ev := w.a.ev.of(a.ID(), EventMigration); len(ev) != 1 || ev[0].From != first || ev[0].Cause != carrier.CauseRetired {
			t.Fatalf("migration events %+v, want one from %d with cause retired", ev, first)
		}
		if we, re := acTransfer(a, b, 1<<20, 61, false); we != nil || re != nil {
			t.Fatalf("transfer: %v %v", we, re)
		}
	})
}

// TestActorBondEpisodeKicksMembers (§7.7): when the last bond member dies,
// the no-path episode makes every member slot redial at once — also a slot
// still in its backoff from earlier failures. Here p2's slot backs off for
// seconds (its path refused four redials) when p1 dies: p2 is redialled at
// the episode start, attaches, and the episode ends within one handshake.
func TestActorBondEpisodeKicksMembers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		w.a.p.Grace, w.a.p.Retain, w.a.p.BackoffMax = 30*time.Second, 40*time.Second, 4*time.Second
		l1, l2 := w.link("p1"), w.link("p2")
		a, b := w.open(ModeBond, nil, l1, l2)
		acWaitFor(t, time.Second, "both members", func() bool { return a.dataMembers() == 2 })
		l2.SetRefuse(true)
		l2.Kill()
		time.Sleep(4 * time.Second) // redials at +0, 0.5, 1.5 and 3.5 s fail: the next waits until +7.5 s
		failures := l2.Stats().DialFailures
		if failures < 4 {
			t.Fatalf("%d refused redials of p2, want its slot deep in backoff (stimulus)", failures)
		}
		l2.SetRefuse(false)
		l1.SetRefuse(true)
		killed := time.Now()
		dials := l2.Stats().Dials
		l1.Kill()
		acWaitFor(t, time.Second, "p2 back as a member", func() bool {
			st := a.Status()
			return !st.InNoPath && a.dataMembers() == 1
		})
		if d := time.Since(killed); d > 50*time.Millisecond {
			t.Fatalf("episode ended %v after the last member died, want p2 redialled at once", d)
		}
		if got := l2.Stats().Dials - dials; got != 1 {
			t.Fatalf("%d dials of p2 after the episode started, want 1", got)
		}
		if st := a.Status(); st.NoPathEpisodes != 1 {
			t.Fatalf("no-path episodes %d, want 1", st.NoPathEpisodes)
		}
		l1.SetRefuse(false)
		if we, re := acTransfer(a, b, 1<<20, 98, false); we != nil || re != nil {
			t.Fatalf("transfer: %v %v", we, re)
		}
	})
}
