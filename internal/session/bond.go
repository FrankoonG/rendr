package session

import (
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Bond (design §7.4, §4.11; L32, L34): after OPEN success the session
// keeps one member per member factory — the winner's and the top-ranked
// others, MaxCarriers in all, at most one per fate group (M3-D37). A
// member that dies is redialled at once (the death step kicks its slot;
// not gated by the failed mark, plan §3.2), then per cadence; the new
// incarnation is a rejoin, not a migration. The head of the send window is
// rescued by a duplicate on another member when it stays stuck — on the
// member holding it only while that member is the only data lane and DATA
// sent on several members is unacknowledged.
//
// Race keeps the same membership (M3-D29, Mode.members): every member
// carries every byte or datagram (race.go), and nothing is rescued.

// group returns the fate-group index of factory i (DialSpec.Groups; 0: a
// group of its own, also for an index beyond the Peer factory limit).
func (spec *DialSpec) group(i int) uint8 {
	if i < 0 || i >= len(spec.Groups) {
		return 0
	}
	return spec.Groups[i]
}

// coupled reports whether factory i's fate group is HoLCoupled
// (DialSpec.Coupled, M3-D39). A group of its own is never coupled.
func (spec *DialSpec) coupled(i int) bool {
	return spec.group(i) != 0 && i < 16 && spec.Coupled&(1<<i) != 0
}

// chooseMembersLocked fixes the member factories when the session opens
// on factory winner and kicks every other member slot: the winner, whose
// group counts as taken, then the best-ranked factory of each other fate
// group in rank order, up to MaxCarriers (sched.OnePerGroup, M3-D37; with
// zero Groups every factory is its own group, as in M2).
func (a *actor) chooseMembersLocked(now time.Time, winner int) {
	d := a.d
	d.slots[winner].member = true
	var buf [16]int
	order := append(buf[:0], winner)
	for _, i := range a.rankLocked(now) {
		if i != winner && len(order) < len(buf) {
			order = append(order, i)
		}
	}
	for _, i := range sched.OnePerGroup(order, d.spec.group, a.maxCarriers(), order)[1:] {
		d.slots[i].member = true
		d.slots[i].cad.Kick()
	}
}

// factoryUsableLocked reports whether factory i has a lane that can carry
// data.
func (a *actor) factoryUsableLocked(i int) bool {
	for _, l := range a.s.lanes {
		if l.factory == i && a.s.usableLocked(l) {
			return true
		}
	}
	return false
}

// bondSlotsLocked starts a JOIN on every member slot that has no usable
// lane and no attempt in flight, when its cadence allows, within
// MaxCarriers carriers and attempts. A member slot whose last attempt
// failed hands its membership to its fate group's next factory first
// (groupFailoverLocked).
func (a *actor) bondSlotsLocked(now time.Time) {
	s := a.s
	d := a.d
	live := 0
	for _, l := range s.lanes {
		if s.usableLocked(l) {
			live++
		}
	}
	a.groupFailoverLocked(now)
	for i := range d.slots {
		sl := &d.slots[i]
		if !sl.member || sl.att != nil || a.factoryUsableLocked(i) {
			continue
		}
		if live+d.running >= a.maxCarriers() {
			return
		}
		ok, at := sl.cad.Ready(now)
		if !ok {
			a.want(at)
			continue
		}
		a.startAttemptLocked(now, i, wire.TypeJoin)
	}
}

// groupFailoverLocked moves a member slot within its fate group (M3-D37,
// PA-31): a dead member's slot redials its own factory first (the death
// kicked it); once an attempt of it failed — its factory is marked failed
// (a refusal clears the mark: the path works, the peer refused) and its
// cadence holds it back — the membership moves to the next factory of the
// same group in rank order (cycling) that may dial now, so a group never
// holds two members and its next factory is tried at once. A group with
// no such factory keeps its member, which redials at its own cadence; the
// earliest readiness of the others is wanted, so the move happens when
// one is ready. Every move is to a factory that dials in the same step,
// and each factory keeps its own cadence, so a dead group is not
// redialled faster than M2 redials its members (L20).
func (a *actor) groupFailoverLocked(now time.Time) {
	d := a.d
	var snap *carrier.Snapshot
	if d.h != nil {
		snap = d.h.Snapshot()
	}
	var rank []int
	for i := range d.slots {
		sl := &d.slots[i]
		g := d.spec.group(i)
		if g == 0 || !sl.member || sl.att != nil || a.factoryUsableLocked(i) {
			continue
		}
		if ok, _ := sl.cad.Ready(now); ok || !a.failedLocked(snap, i) {
			continue // its own factory may dial now (the death's kick), or it was refused, not failed
		}
		if rank == nil {
			rank = a.rankLocked(now)
		}
		p := -1
		for k, f := range rank {
			if f == i {
				p = k
				break
			}
		}
		n := len(rank)
		for k := 1; k <= n; k++ {
			j := rank[(p+k+n)%n]
			o := &d.slots[j]
			if j == i || d.spec.group(j) != g || o.member || o.att != nil {
				continue
			}
			ok, at := o.cad.Ready(now)
			if !ok {
				a.want(at)
				continue
			}
			sl.member = false
			o.member = true
			break
		}
	}
}

// rescueLocked is the bond rescue check (§4.11, W7): while sBase < end it
// is armed at lastAdvance + RescueWait(fastest srtt, RescueMin) — never at
// a time already past —; when the head has been stuck that long, the stuck
// segment is duplicated (the receiver deduplicates) by the first data lane
// with capacity that may send it (rescueSenderLocked): any lane but its
// holder (L34), and the holder itself only while it is the only data lane
// and interleaved DATA is unacknowledged (st.interleaved, §0.8 V3): bytes
// the receiver dropped at its out-of-order cap or shed would otherwise
// never be resent, and the session would stall for good on a healthy
// carrier.
//
// One rescue per sBase value (ctl.rescuedBase), set only if some lane may
// send it: another data lane, or the holder under the rule above. When the
// holder sent its own duplicate (its record in st.rescue: not set, holder
// kept), that duplicate may sit behind the holder's own stalled carrier,
// so the same head is rescued once more as soon as another data lane
// exists (an attach, or a SCHED that adds a member). The holder never
// sends that second one while another data lane exists; only if every
// other data lane leaves again before taking it can the holder's duplicate
// and a further one follow (one more per lane that appears).
//
// While a rescue is pending, every step wakes the lanes that may send it,
// so a member's death, retirement or attach hands it over without waiting
// for an unrelated wake. It runs on both sides: the passive rescues its own
// sends over its data lanes (the applied SCHED's members). A packet session
// retransmits nothing (plan D9): no rescue.
func (a *actor) rescueLocked(now time.Time) {
	s := a.s
	st := &s.st
	if s.pk != nil || s.p.Mode != ModeBond || st.ended || st.sBase >= st.end { // race: no rescue (M3-D30)
		a.rescueAt = time.Time{}
		return
	}
	s.wakeRescueLocked()
	wait := sched.RescueWait(a.fastestSRTTLocked(), orDefault(s.p.RescueMin, defRescueMin))
	due := st.lastAdvance.Add(wait)
	if now.Before(due) {
		a.rescueAt = due
		a.want(due)
		return
	}
	if !st.rescue.set {
		if holder, sp, ok := s.rescueHolderLocked(); ok {
			other := s.otherDataLaneLocked(holder)
			first := st.sBase != s.ctl.rescuedBase && (other || st.interleaved)
			again := st.sBase == s.ctl.rescuedBase && st.rescue.holder == holder && other
			if first || again {
				st.rescue = rescueSlot{set: true, sp: sp, holder: holder}
				s.ctl.rescuedBase = st.sBase
				s.routingChangedLocked() // V15
				s.wakeRescueLocked()
			}
		}
	}
	a.rescueAt = now.Add(wait)
	a.want(a.rescueAt)
}
