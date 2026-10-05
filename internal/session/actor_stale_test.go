package session

import (
	"fmt"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Stale incarnations and routing consistency (design §7.3; L21, L27, C1).

// acGate holds a hook until released: armed for one carrier ID (or the
// first call when id is 0 and any is set).
type acGate struct {
	armed   atomic.Bool
	any     bool
	id      atomic.Uint32
	held    chan uint32   // receives the ID once the hook is held
	release chan struct{} // closed by the test
}

func acNewGate() *acGate {
	return &acGate{held: make(chan uint32, 1), release: make(chan struct{})}
}

// arm holds the next call for id (any call when any).
func (g *acGate) arm(id uint32, any bool) {
	g.id.Store(id)
	g.any = any
	g.armed.Store(true)
}

func (g *acGate) hook(id uint32) {
	if !g.armed.Load() || (!g.any && id != g.id.Load()) {
		return
	}
	if !g.armed.CompareAndSwap(true, false) {
		return
	}
	g.held <- id
	<-g.release
}

// TestStaleDeathCannotTouchSuccessor_L21: a stale incarnation's death never
// touches its successor (L21). Two variants:
//
//   - other-slot: the active carrier A dies; the race's first attempt
//     (factory p2) is established but its result is held
//     (Hooks.DialResult) while the race's next attempt — a redial of A's own
//     factory, A' — attaches and becomes active (one death migration). Then
//     p2's link is killed and the stale result released: it attaches as a
//     race loser and dies at once; that death is held too
//     (Hooks.DeathObserved) while the successor is checked, then released.
//     A' stays active and the death of A stays the only migration.
//   - same-slot: the stale incarnation and the successor are carriers of
//     the same factory slot. A (p1) is switched away from by quality and
//     drains its CLOSE exchange (the peer's CLOSE is held back); the new
//     active B (p2) dies, and the race redials p1: A' attaches and becomes
//     active while A still drains. A's death then arrives, is held while A'
//     is checked, and is released: A' stays active and no migration beyond
//     the quality switch and B's death is counted — identity is the lane
//     (the carrier incarnation), never the factory.
func TestStaleDeathCannotTouchSuccessor_L21(t *testing.T) {
	t.Run("other-slot", acStaleOtherSlot)
	t.Run("same-slot", acStaleSameSlot)
}

// acStaleOtherSlot is the other-slot variant of
// TestStaleDeathCannotTouchSuccessor_L21.
func acStaleOtherSlot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		results, deaths := acNewGate(), acNewGate()
		w := acNewWorld(t, &testhooks.Hooks{DialResult: results.hook, DeathObserved: deaths.hook})
		defer w.teardown()
		l1, l2 := w.link("p1"), w.link("p2")
		a, b := w.open(ModeSelector, nil, l1, l2)
		first := acActive(a)

		results.arm(0, true) // hold the first result after the death: the race starts with p2 (p1 is failed)
		l1.Kill()
		held := <-results.held
		synctest.Wait()
		joining := false
		for _, c := range a.Status().Carriers {
			joining = joining || (c.ID == held && c.State == LaneJoining && c.Name == "p2")
		}
		if !joining {
			t.Fatalf("the held attempt %d is not reported as joining: %+v", held, a.Status().Carriers)
		}
		acWaitFor(t, 2*time.Second, "A' attached", func() bool {
			id := acActive(a)
			return id != 0 && id != first && id != held
		})
		succ := acActive(a)
		if st := a.Status(); st.MigDeath != 1 || st.Carriers[0].Name != "p1" {
			t.Fatalf("successor: %+v, want A' on p1 after one death migration", st)
		}

		l2.Kill() // the held result's carrier is dead before the actor sees the result
		deaths.arm(held, false)
		close(results.release)
		if id := <-deaths.held; id != held {
			t.Fatalf("held death of %d, want the stale incarnation %d", id, held)
		}
		// The actor waits in the hook: the published routing is A'.
		if got := acActive(a); got != succ {
			t.Fatalf("while the stale death is held: active %d, want %d", got, succ)
		}
		close(deaths.release)
		synctest.Wait()
		if got := acActive(a); got != succ {
			t.Fatalf("after the stale death: active %d, want %d", got, succ)
		}
		st := a.Status()
		if st.MigDeath != 1 || st.MigExplicit+st.MigQuality != 0 {
			t.Fatalf("migrations %d/%d/%d, want the one death migration", st.MigDeath, st.MigQuality, st.MigExplicit)
		}
		for _, c := range st.Carriers {
			if c.ID == held && (c.State != LaneDead || !c.DeathCause.Death()) {
				t.Fatalf("stale incarnation %+v, want dead with a death cause", c)
			}
		}
		if we, re := acTransfer(a, b, 1<<20, 6, false); we != nil || re != nil {
			t.Fatalf("transfer on the successor: %v %v", we, re)
		}
	})
}

// acStaleSameSlot is the same-slot variant of
// TestStaleDeathCannotTouchSuccessor_L21. Factory p1 dials link x first
// and link y afterwards, so the drain of A (over x) can be held without
// holding A' (over y).
func acStaleSameSlot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		deaths := acNewHold()
		w := acNewWorld(t, &testhooks.Hooks{DeathObserved: deaths.hook})
		defer w.teardown()
		w.a.p.Selector.Dwell, w.a.p.Selector.Cooldown = 50*time.Millisecond, 50*time.Millisecond
		h := acNewHealth(2, w.a.p.Selector.Fresh)
		h.set(30*time.Millisecond, 0)
		x, y, l2 := w.link("p1"), w.link("p1-redial"), w.link("p2")
		spec := w.spec(ModeSelector, x, l2)
		spec.Factories[0] = acSwitchFactory("p1", x, y)
		a, b := w.openSpec(spec, h)
		defer acFreshen(h)()
		la := acActiveLane(a)
		// The peer's frames on A — its answering CLOSE included — wait from
		// now on: A drains until its bound, min(2·srtt + 100 ms, 1 s).
		x.BlockWrites(rendrtest.Down, rendrtest.BlockSoft)
		q := a.Status().MigQuality
		h.set(30*time.Millisecond, 10*time.Millisecond)
		acWaitFor(t, 5*time.Second, "the quality switch to p2", func() bool { return a.Status().MigQuality == q+1 })
		h.set(30*time.Millisecond, 0) // p2 never challenges again
		lb := acActiveLane(a)
		a.mu.Lock()
		called := la.retireCalled
		a.mu.Unlock()
		if dead, _, _, _ := la.c.Death(); dead || !called || lb == la || lb.factory != 1 {
			t.Fatalf("after the switch: A dead %v, Retire called %v; active factory %d", dead, called, lb.factory)
		}
		deaths.arm(la.id)
		l2.Kill() // B dies: the race redials p1, over y
		acWaitFor(t, time.Second, "A' (p1, second incarnation) active", func() bool {
			l := acActiveLane(a)
			return l != nil && l != la && l.factory == 0
		})
		succ := acActiveLane(a)
		if succ.gen != 2 {
			t.Fatalf("successor generation %d, want 2", succ.gen)
		}
		if id := <-deaths.held; id != la.id { // A's drain bound ended it, after A' attached
			t.Fatalf("held the death of %d, want A %d", id, la.id)
		}
		if got := acActive(a); got != succ.id {
			t.Fatalf("while A's death is held: active %d, want A' %d", got, succ.id)
		}
		deaths.resume <- struct{}{}
		synctest.Wait()
		if got := acActive(a); got != succ.id {
			t.Fatalf("after A's death: active %d, want A' %d", got, succ.id)
		}
		st := a.Status()
		if st.MigDeath != 1 || st.MigQuality != 1 || st.MigExplicit != 0 {
			t.Fatalf("migrations %d/%d/%d, want B's death and the quality switch only", st.MigDeath, st.MigQuality, st.MigExplicit)
		}
		for _, c := range st.Carriers {
			if c.ID == la.id && (c.State != LaneDead || c.DeathCause.Death()) {
				t.Fatalf("A %+v, want dead by its retirement", c)
			}
		}
		x.BlockWrites(rendrtest.Down, rendrtest.BlockOff)
		if x.Stats().Session.WritesBlocked == 0 {
			t.Fatal("the peer's writes on A were never held (stimulus)")
		}
		if we, re := acTransfer(a, b, 1<<20, 87, false); we != nil || re != nil {
			t.Fatalf("transfer on the successor: %v %v", we, re)
		}
	})
}

// acHold holds a hook call for one carrier ID per arming (re-armable,
// unlike acGate): the test arms it, waits on held, checks, then sends on
// resume.
type acHold struct {
	want   atomic.Uint32 // the armed ID; 0: disarmed
	held   chan uint32
	resume chan struct{}
}

func acNewHold() *acHold {
	return &acHold{held: make(chan uint32, 1), resume: make(chan struct{})}
}

func (h *acHold) arm(id uint32) { h.want.Store(id) }

func (h *acHold) hook(id uint32) {
	if id == 0 || !h.want.CompareAndSwap(id, 0) {
		return
	}
	h.held <- id
	<-h.resume
}

// acRoutingCheck installs a consistency check (acRouted) that runs on the
// actor goroutine right after every critical section of each given
// session's actor — the instants at which another goroutine can observe a
// new snapshot and routing. It counts the checks per session and keeps the
// first violation; uninstall restores the seam.
type acRoutingCheck struct {
	sess   []*Session
	checks []atomic.Int64
	bad    atomic.Pointer[string]
}

func acCheckRouting(sess ...*Session) (rc *acRoutingCheck, uninstall func()) {
	rc = &acRoutingCheck{sess: sess, checks: make([]atomic.Int64, len(sess))}
	return rc, acAfterUnlock(func(s *Session) {
		for i, x := range rc.sess {
			if x != s {
				continue
			}
			rc.checks[i].Add(1)
			if msg := acRoutingViolation(s); msg != "" {
				rc.bad.CompareAndSwap(nil, &msg)
			}
		}
	})
}

// acAfterUnlock installs f as the actor seam that runs right after every
// critical section of every session's actor (on the actor goroutine, no
// lock held); uninstall removes it (idempotent). Actor tests never run in
// parallel, so one seam at a time suffices.
func acAfterUnlock(f func(s *Session)) (uninstall func()) {
	afterUnlockHook.Store(&f)
	return func() { afterUnlockHook.CompareAndSwap(&f, nil) }
}

// acRoutingViolation compares, in one critical section of s, the routing
// (lane.data, ctl.active) with the published snapshot (L27) and describes
// a mismatch ("" if none). Selector: the reported active carrier is the
// routed one, at most one lane carries data, and it is the active one.
// Bond: no carrier is reported active, and every data lane is reported a
// member (a joining, retiring or dead report would hide a routed lane).
func acRoutingViolation(s *Session) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	rep := make(map[uint32]LaneState)
	var active uint32
	for _, ls := range s.snap.Load().lanes {
		if _, dup := rep[ls.id]; !dup { // live lanes come first; a dead one may share a reused ID
			rep[ls.id] = ls.state
		}
		if ls.state == LaneActive {
			active = ls.id
		}
	}
	if s.p.Mode == ModeBond {
		if active != 0 {
			return fmt.Sprintf("%v bond: carrier %d reported active", s.Role(), active)
		}
		for _, l := range s.lanes {
			if l.data && rep[l.id] != LaneMember {
				return fmt.Sprintf("%v bond: data lane %d reported %v", s.Role(), l.id, rep[l.id])
			}
		}
		return ""
	}
	var routed uint32
	if a := s.ctl.active; a != nil {
		routed = a.id
	}
	n := 0
	for _, l := range s.lanes {
		if l.data {
			n++
			if l != s.ctl.active {
				return fmt.Sprintf("%v: data lane %d is not the active %d", s.Role(), l.id, routed)
			}
		}
	}
	if active != routed || (routed == 0) != (n == 0) {
		return fmt.Sprintf("%v: reported active %d, routed %d, %d data lanes", s.Role(), active, routed, n)
	}
	return ""
}

// violation returns the first violation seen ("" if none).
func (rc *acRoutingCheck) violation() string {
	if p := rc.bad.Load(); p != nil {
		return *p
	}
	return ""
}

// TestReportedActiveEqualsRouting_L27: across 200 deaths of the active
// carrier the reported active carrier (the published snapshot) never
// differs from the routed one (lane.data, ctl.active) on either end. The
// check runs after every critical section of both actors, so every state
// another goroutine can ever observe is checked regardless of GOMAXPROCS
// or scheduling (each death runs at least two critical sections on each
// end, which the test requires as its stimulus proof); the dialer's death
// step is also held (Hooks.DeathObserved) and the routing checked while
// the dying lane still routes. Both ends count exactly one death migration
// per death.
func TestReportedActiveEqualsRouting_L27(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hold := acNewHold()
		w := acNewWorld(t, &testhooks.Hooks{DeathObserved: hold.hook})
		defer w.teardown()
		var links []*rendrtest.Link
		for _, n := range []string{"p1", "p2", "p3"} {
			links = append(links, w.link(n))
		}
		a, b := w.open(ModeSelector, nil, links...)
		acWaitFor(t, time.Second, "the first SCHED echoed", func() bool { return a.Status().SchedEchoed == a.Status().SchedEpoch })
		rc, uninstall := acCheckRouting(a, b)
		defer uninstall()
		const deaths = 200
		for i := range deaths {
			before := [2]int64{rc.checks[0].Load(), rc.checks[1].Load()}
			id := acActive(a)
			hold.arm(id)
			for _, c := range a.Status().Carriers {
				if c.ID == id {
					links[c.Name[1]-'1'].Kill()
				}
			}
			if got := <-hold.held; got != id {
				t.Fatalf("death %d: held the death of %d, want the active %d", i, got, id)
			}
			for _, s := range []*Session{a, b} { // the dialer's death step is held: the dying lane still routes
				if rep, routed, n := acRouted(s); rep != routed || n > 1 {
					t.Fatalf("death %d, %v, while held: reported %d, routed %d, %d data lanes", i, s.Role(), rep, routed, n)
				}
			}
			hold.resume <- struct{}{}
			acWaitFor(t, 2*time.Second, "a new active carrier, its SCHED applied", func() bool {
				st := a.Status()
				n := acActive(a)
				return n != 0 && n != id && st.SchedEchoed == st.SchedEpoch
			})
			if v := rc.violation(); v != "" {
				t.Fatalf("death %d: %s", i, v)
			}
			for side, s := range []*Session{a, b} {
				if n := rc.checks[side].Load() - before[side]; n < 2 {
					t.Fatalf("death %d: %d checks after %v critical sections, want at least 2 (stimulus)", i, n, s.Role())
				}
			}
		}
		if st, bs := a.Status(), b.Status(); st.MigDeath != deaths || bs.MigDeath != deaths {
			t.Fatalf("death migrations: dialer %d, passive %d, want %d each", st.MigDeath, bs.MigDeath, deaths)
		}
		if we, re := acTransfer(a, b, 256<<10, 7, false); we != nil || re != nil {
			t.Fatalf("transfer: %v %v", we, re)
		}
		if v := rc.violation(); v != "" {
			t.Fatal(v)
		}
		t.Logf("%d checks on the dialer, %d on the passive", rc.checks[0].Load(), rc.checks[1].Load())
	})
}

// TestDeathStepVsDyingWriterFill_L27: the active carrier dies while the
// session holds unsent data and a requested FIN. While the death step is
// held (Hooks.DeathObserved) the dying lane's Fill — a writer round already
// running when the carrier was killed — pulls the DATA and the FIN into a
// batch that is never written; the death step then requeues both (C1), a
// Fill after it appends nothing, and every byte and the FIN arrive through
// the successor.
func TestDeathStepVsDyingWriterFill_L27(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		deaths := acNewGate()
		w := acNewWorld(t, &testhooks.Hooks{DeathObserved: deaths.hook})
		defer w.teardown()
		l1, l2 := w.link("p1"), w.link("p2")
		a, b := w.open(ModeSelector, nil, l1, l2)
		a.mu.Lock()
		dying := a.ctl.active
		a.mu.Unlock()

		deaths.arm(dying.id, false)
		l1.Kill()
		<-deaths.held
		const n = 100 << 10
		if err := acWritePRNG(a, n, 8); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := a.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
		before := carrier.NewBatch(256 << 10)
		before.Reset(time.Now())
		dying.Fill(dying.c, before)
		var data, fins int
		for i := range before.Len() {
			switch f := before.Frame(i); f.Header.Type {
			case wire.TypeData:
				data += len(f.Body)
			case wire.TypeFin:
				fins++
			}
		}
		before.ReleaseRefs()
		if data != n || fins != 1 {
			t.Fatalf("the dying lane's Fill pulled %d DATA bytes and %d FINs, want %d and 1 (stimulus)", data, fins, n)
		}

		close(deaths.release)
		synctest.Wait()
		after := carrier.NewBatch(256 << 10)
		after.Reset(time.Now())
		dying.Fill(dying.c, after)
		if after.Len() != 0 {
			t.Fatalf("Fill after the death step appended %d frames", after.Len())
		}
		v := rendrtest.NewVerifier(8, n)
		if err := v.ReadAll(b); err != nil {
			t.Fatalf("passive read: %v", err)
		}
		synctest.Wait() // the link's pump counts a chunk once its Write to the far end returned
		if l2.Stats().Session.Bytes < n {
			t.Fatal("the successor did not carry the replay")
		}
		if st := a.Status(); st.MigDeath != 1 || st.RetransmittedBytes < n {
			t.Fatalf("dialer: %d death migrations, %d retransmitted bytes", st.MigDeath, st.RetransmittedBytes)
		}
	})
}
