package session

import (
	"time"

	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Bond (design §7.4, §4.11; L32, L34): after OPEN success the session
// keeps one member per member factory — the winner's and the top-ranked
// others, MaxCarriers in all. A member that dies is redialled at once
// (the death step kicks its slot; not gated by the failed mark, plan §3.2),
// then per cadence; the new incarnation is a rejoin, not a migration. The
// head of the send window is rescued by a duplicate on another member when
// it stays stuck — on the member holding it only while that member is the
// only data lane.

// chooseMembersLocked fixes the member factories when the session opens
// on factory winner and kicks every other member slot.
func (a *actor) chooseMembersLocked(now time.Time, winner int) {
	d := a.d
	d.slots[winner].member = true
	n := 1
	for _, i := range a.rankLocked(now) {
		if n >= a.maxCarriers() {
			break
		}
		if i == winner {
			continue
		}
		d.slots[i].member = true
		d.slots[i].cad.Kick()
		n++
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
// MaxCarriers carriers and attempts.
func (a *actor) bondSlotsLocked(now time.Time) {
	s := a.s
	d := a.d
	live := 0
	for _, l := range s.lanes {
		if s.usableLocked(l) {
			live++
		}
	}
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

// rescueLocked is the bond rescue check (§4.11, W7): while sBase < end it
// is armed at lastAdvance + RescueWait(fastest srtt, RescueMin) — never at
// a time already past —; when the head has been stuck that long and was
// not rescued at this sBase, the stuck segment is duplicated (the receiver
// deduplicates) by the first data lane with capacity that may send it: any
// lane but the holder while another data lane exists (L34), else the
// holder itself (rescueSenderLocked, §0.8 V3): bytes the receiver dropped
// at its out-of-order cap or shed would otherwise never be resent, and the
// session would stall for good on a healthy carrier. While the rescue
// is pending, every step wakes the lanes that may send it, so a member's
// death, retirement or attach hands it over without waiting for an
// unrelated wake. It runs on both sides: the passive rescues its own sends
// over its data lanes (the applied SCHED's members).
func (a *actor) rescueLocked(now time.Time) {
	s := a.s
	st := &s.st
	if s.p.Mode != ModeBond || st.ended || st.sBase >= st.end {
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
	if st.sBase != s.ctl.rescuedBase && !st.rescue.set {
		if holder, sp, ok := s.rescueHolderLocked(); ok {
			st.rescue = rescueSlot{set: true, sp: sp, holder: holder}
			s.ctl.rescuedBase = st.sBase
			s.routingChangedLocked() // V15
			s.wakeRescueLocked()
		}
	}
	a.rescueAt = now.Add(wait)
	a.want(a.rescueAt)
}
