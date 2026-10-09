package session

import (
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// WP4 (M3 design §A6.1, §A6.6, §A7.2, §A7.3, §A11.1): membership and
// carrier properties — one bond or race member per fate group, the
// member's failover within its group, the selector's failover order
// outside the dead carrier's group, race's death rules. Two Runtimes over
// rendrtest links in synctest bubbles (the actor harness, inert health:
// the ranking is the configuration order). Helpers start with "mg".

// mgSpec is w.spec with the fate-group index of every factory set.
func mgSpec(w *acWorld, mode Mode, groups []uint8, links ...*rendrtest.Link) DialSpec {
	spec := w.spec(mode, links...)
	copy(spec.Groups[:], groups)
	return spec
}

// mgMembers returns the member factories of dialer s's slots.
func mgMembers(s *Session) []int {
	a := s.mb.actor.Load()
	s.mu.Lock()
	defer s.mu.Unlock()
	var m []int
	for i := range a.d.slots {
		if a.d.slots[i].member {
			m = append(m, i)
		}
	}
	return m
}

// mgDataFactories returns the factory of every data lane of dialer s, in
// factory order.
func mgDataFactories(s *Session) []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var f []int
	for _, l := range s.lanes {
		if l.data {
			f = append(f, l.factory)
		}
	}
	slices.Sort(f)
	return f
}

// mgActiveFactory returns the factory of the selector's active lane (−1:
// none).
func mgActiveFactory(s *Session) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l := s.ctl.active; l != nil {
		return l.factory
	}
	return -1
}

// mgDials returns the factory calls of every link.
func mgDials(links ...*rendrtest.Link) []int64 {
	d := make([]int64, len(links))
	for i, l := range links {
		d[i] = l.Stats().Dials
	}
	return d
}

func mgSame(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestBondOnePerFateGroup_L32: a bond keeps at most one member per fate
// group (M3-D37, PA-31; L32: a group is not independent capacity): with
// p1, p2 in one group, p3 alone and p4, p5 in another, the members are the
// winner and the best-ranked factory of every other group (p1, p3, p4);
// p2 and p5 are never dialled, the SCHED lists three members and both ends
// send on exactly those. When the opening race's winner is the group's
// second factory (p1 refuses), its group counts as taken: p1 never becomes
// a member.
func TestBondOnePerFateGroup_L32(t *testing.T) {
	groups := []uint8{1, 1, 0, 2, 2}
	for _, refuseFirst := range []bool{false, true} {
		name := "winner-first"
		if refuseFirst {
			name = "winner-second-of-group"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := acNewWorld(t, nil)
				defer w.teardown()
				ls := []*rendrtest.Link{w.link("p1"), w.link("p2"), w.link("p3"), w.link("p4"), w.link("p5")}
				if refuseFirst {
					ls[0].SetRefuse(true)
				}
				a, b := wpOpen(w, mgSpec(w, ModeBond, groups, ls...), nil)
				ls[0].SetRefuse(false)
				want := []int{0, 2, 3}
				if refuseFirst {
					want = []int{1, 2, 3}
				}
				acWaitFor(t, time.Second, "three data members", func() bool { return a.dataMembers() == 3 && b.dataMembers() == 3 })
				time.Sleep(5 * time.Second) // every redial cadence would have fired by now
				synctest.Wait()
				if m := mgMembers(a); !mgSame(m, want) {
					t.Fatalf("member slots %v, want %v", m, want)
				}
				if f := mgDataFactories(a); !mgSame(f, want) {
					t.Fatalf("data lanes on factories %v, want %v", f, want)
				}
				dials := mgDials(ls...)
				wantDials := []int64{1, 0, 1, 1, 0}
				if refuseFirst {
					wantDials[1] = 1 // the opening race's winner; p1's refused OPEN is its only call
				}
				for i := range dials {
					if dials[i] != wantDials[i] {
						t.Fatalf("factory calls %v, want %v", dials, wantDials)
					}
				}
				a.mu.Lock()
				n := a.ctl.set.N
				a.mu.Unlock()
				if n != 3 {
					t.Fatalf("the SCHED lists %d members, want 3", n)
				}
				if we, re := acTransfer(a, b, 1<<20, 41, false); we != nil || re != nil {
					t.Fatalf("transfer: write %v, read %v", we, re)
				}
				for _, i := range []int{1, 4} {
					if refuseFirst && i == 1 {
						i = 0
					}
					if got := ls[i].Stats().Session.Bytes; got != 0 {
						t.Fatalf("p%d is no member but carried %d session bytes", i+1, got)
					}
				}
			})
		})
	}
}

// TestMemberFailoverWithinGroup: a dead member's slot redials its own
// factory first; once that attempt failed the membership moves to the
// group's next factory by rank, which is dialled at once and becomes the
// member; the first factory is not dialled again, and the group never
// holds two members (M3-D37). The transfer started before the death
// completes intact on the members that remain.
func TestMemberFailoverWithinGroup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		l1, l2, l3 := w.slowLink("p1"), w.slowLink("p2"), w.slowLink("p3")
		a, b := wpOpen(w, mgSpec(w, ModeBond, []uint8{1, 1, 0}, l1, l2, l3), nil)
		acWaitFor(t, time.Second, "two members", func() bool { return a.dataMembers() == 2 && b.dataMembers() == 2 })
		if m := mgMembers(a); !mgSame(m, []int{0, 2}) {
			t.Fatalf("members %v, want p1 and p3", m)
		}
		const n = 8 << 20
		done := make(chan [2]error, 1)
		go func() {
			we, re := acTransfer(a, b, n, 42, true)
			done <- [2]error{we, re}
		}()
		acWaitFor(t, 5*time.Second, "a quarter delivered", func() bool { return b.Status().DeliveredBytes >= n/4 })
		if d := b.Status().DeliveredBytes; d >= n/2 {
			t.Fatalf("%d of %d bytes delivered before the kill: no load across it", d, n)
		}
		before := mgDials(l1, l2, l3)
		l1.SetRefuse(true)
		if l1.Kill() == 0 {
			t.Fatal("the kill hit no carrier")
		}
		killed := time.Now()
		acWaitFor(t, 2*time.Second, "p2 took p1's place", func() bool {
			return mgSame(mgDataFactories(a), []int{1, 2})
		})
		if d := time.Since(killed); d > 100*time.Millisecond {
			t.Fatalf("p2 attached %v after p1's death, want the move right after p1's failed redial", d)
		}
		after := mgDials(l1, l2, l3)
		if after[0]-before[0] != 1 || after[1]-before[1] != 1 || after[2] != before[2] {
			t.Fatalf("calls since the kill p1 %d, p2 %d, p3 %d; want one redial of p1, then one of p2",
				after[0]-before[0], after[1]-before[1], after[2]-before[2])
		}
		if m := mgMembers(a); !mgSame(m, []int{1, 2}) {
			t.Fatalf("members %v, want p2 and p3 (one per group)", m)
		}
		l1.SetRefuse(false)
		r := <-done
		if r[0] != nil || r[1] != nil {
			t.Fatalf("transfer: write %v, read %v", r[0], r[1])
		}
		if l2.Stats().Session.Bytes == 0 {
			t.Fatal("the new member carried no session bytes")
		}
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if got := l1.Stats().Dials - before[0]; got != 1 {
			t.Fatalf("p1 dialled %d times after the move, want no call beyond its first redial", got)
		}
		if m := mgMembers(a); !mgSame(m, []int{1, 2}) {
			t.Fatalf("members %v later, want p2 and p3", m)
		}
	})
}

// TestSelectorFailoverPrefersOtherGroup: the selector's death failover race
// tries the factories outside the dead carrier's fate group first, stably
// in both halves (M3-D38): p1, p2 share a group, p3 is alone, ranks p1 >
// p2 > p3; p1 dies → the race starts with p3 (which wins: p2 is never
// dialled); when p3 refuses the race moves on to p2.
func TestSelectorFailoverPrefersOtherGroup(t *testing.T) {
	for _, refuseP3 := range []bool{false, true} {
		name := "p3-wins"
		if refuseP3 {
			name = "p3-refuses"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := acNewWorld(t, nil)
				defer w.teardown()
				l1, l2, l3 := w.slowLink("p1"), w.slowLink("p2"), w.slowLink("p3")
				a, b := wpOpen(w, mgSpec(w, ModeSelector, []uint8{1, 1, 0}, l1, l2, l3), nil)
				if f := mgActiveFactory(a); f != 0 {
					t.Fatalf("active factory %d after the open, want p1", f)
				}
				const n = 4 << 20
				done := make(chan [2]error, 1)
				go func() {
					we, re := acTransfer(a, b, n, 43, true)
					done <- [2]error{we, re}
				}()
				acWaitFor(t, 5*time.Second, "a quarter delivered", func() bool { return b.Status().DeliveredBytes >= n/4 })
				if refuseP3 {
					l3.SetRefuse(true)
				}
				l1.SetRefuse(true)
				before := mgDials(l1, l2, l3)
				if l1.Kill() == 0 {
					t.Fatal("the kill hit no carrier")
				}
				acWaitFor(t, 2*time.Second, "a new active carrier", func() bool { return mgActiveFactory(a) > 0 })
				d := mgDials(l1, l2, l3)
				for i := range d {
					d[i] -= before[i]
				}
				want, wantDials := 2, []int64{0, 0, 1}
				if refuseP3 {
					want, wantDials = 1, []int64{0, 1, 1}
				}
				if f := mgActiveFactory(a); f != want {
					t.Fatalf("active factory %d after the failover, want p%d (calls %v)", f, want+1, d)
				}
				for i := range d {
					if d[i] != wantDials[i] {
						t.Fatalf("calls in the failover race %v, want %v", d, wantDials)
					}
				}
				l1.SetRefuse(false)
				l3.SetRefuse(false)
				r := <-done
				if r[0] != nil || r[1] != nil {
					t.Fatalf("transfer: write %v, read %v", r[0], r[1])
				}
				if as := a.Status(); as.MigDeath != 1 {
					t.Fatalf("death migrations %d, want 1", as.MigDeath)
				}
			})
		})
	}
}

// TestRaceNoRequeueWhileMemberLives_L10: a race member's death requeues
// nothing while another data lane lives (M3-D30): its unacknowledged spans
// are copies the others carry, so the survivor's next Fill sends the bytes
// the dead member was ahead with as copies from its own cursor, never as
// retransmissions; laneGoneLocked still reports the dead member's
// in-flight bytes (the death count, M3-D34). When the last data lane dies,
// its spans are requeued from the ACK edge (L10) and the next lane resends
// them as retransmissions.
func TestRaceNoRequeueWhileMemberLives_L10(t *testing.T) {
	s := rcSender(stOpt{window: 4 << 20, segment: 16 << 10})
	a, _ := stAddLane(s, 1, true)
	b, bp := stAddLane(s, 2, true)
	rcRaceLanes(s)
	rcWrite(t, s, stPattern(0, 128<<10))
	fa, ba := stFill(a, time.Now())
	ba.ReleaseRefs()
	if _, n := rcDataSpan(fa); n != 128<<10 {
		t.Fatalf("premise: a sent %d bytes", n)
	}
	bp.set(func(f *stPort) { f.capacity = 64 << 10 })
	fb, bb := stFill(b, time.Now())
	bb.ReleaseRefs()
	if _, n := rcDataSpan(fb); n != 64<<10 {
		t.Fatalf("premise: b sent %d bytes", n)
	}
	// a dies 64 KiB ahead of b's cursor.
	if got := stKillLane(s, a); got != 128<<10 {
		t.Fatalf("laneGoneLocked reported %d in-flight bytes of the dead member, want 128 KiB", got)
	}
	if q := stLocked(s, func(st *stream) uint64 { return st.retx.bytes() }); q != 0 {
		t.Fatalf("%d bytes requeued while b lives, want 0", q)
	}
	bp.set(func(f *stPort) { f.capacity = 1 << 30 })
	fs, bf := stFill(b, time.Now())
	bf.ReleaseRefs()
	retx := 0
	for _, f := range fs {
		if f.typ == wire.TypeData && f.retx {
			retx += f.n
		}
	}
	if first, n := rcDataSpan(fs); first != 64<<10 || n != 64<<10 || retx != 0 {
		t.Fatalf("b's next Fill sent %d bytes from %d (%d flagged retransmission), want 64 KiB of copies from 64 KiB", n, first, retx)
	}
	if st := s.Status(); st.RetransmittedBytes != 0 || st.Race.CopyBytes != 128<<10 {
		t.Fatalf("Retransmitted %d, CopyBytes %d; want 0 and 128 KiB (b's every byte is a copy of a's)", st.RetransmittedBytes, st.Race.CopyBytes)
	}

	// b dies as the last data lane: M1's requeue from the ACK edge.
	if got := stKillLane(s, b); got != 128<<10 {
		t.Fatalf("laneGoneLocked reported %d bytes for the last lane, want 128 KiB", got)
	}
	if q := stLocked(s, func(st *stream) uint64 { return st.retx.bytes() }); q != 128<<10 {
		t.Fatalf("%d bytes requeued at the last data lane's death, want 128 KiB", q)
	}
	c, _ := stAddLane(s, 3, true)
	rcRaceLane(s, c)
	fc, bc := stFill(c, time.Now())
	bc.ReleaseRefs()
	retx = 0
	for _, f := range fc {
		if f.typ == wire.TypeData && f.retx {
			retx += f.n
		}
	}
	if retx != 128<<10 {
		t.Fatalf("the next lane resent %d bytes as retransmissions, want 128 KiB", retx)
	}
	stEnd(s, errClosed)
}
