package session

import (
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The SCHED protocol (design §7.5; L45, D6, D24). The dialer is the sole
// authority: it publishes SCHED{epoch, data-eligible carrier IDs, cause}
// whenever that set changes, offers it once on every live lane (Fill
// places it where lane.schedSent differs from ctl.epoch) and then re-sends
// it single-flight on one lane at a time until the passive echoes the
// epoch in an ACK. The passive applies a newer epoch idempotently and
// echoes it at once; when its sending lane dies or is retired it moves to
// a local fallback first and follows the next epoch (routing only: a
// selector passive counts migrations only from the cumulative counts each
// SCHED carries, P13, §0.13 A3).

// publishSchedLocked (dialer) publishes the current data-eligible set —
// the selector's active lane, or every bond member — with cause c as the
// next epoch. With no data lane nothing is published (N ≥ 1, V15).
func (a *actor) publishSchedLocked(now time.Time, c wire.SchedCause) {
	s := a.s
	ctl := &s.ctl
	var set wire.Sched
	for _, l := range s.lanes {
		if l.data && set.N < wire.MaxSchedIDs {
			set.IDs[set.N] = l.id
			set.N++
		}
	}
	if set.N == 0 {
		return
	}
	ctl.epoch++
	set.Epoch = ctl.epoch
	ctl.set, ctl.cause = set, c
	for _, l := range s.lanes {
		if l.state != LaneDead && !l.c.CloseSent() {
			wakeLaneLocked(l) // offered once on every live lane
		}
	}
	a.resendAt = now.Add(a.resendEvery())
	a.dirty = true
}

// resendEvery is the SCHED resend interval clamp(2 × min srtt, 50 ms, 1 s).
func (a *actor) resendEvery() time.Duration {
	var m time.Duration
	for _, l := range a.s.lanes {
		if r := l.port.SRTT(); r > 0 && (m == 0 || r < m) {
			m = r
		}
	}
	return min(max(2*m, minResend), maxResend)
}

// schedResendLocked (dialer) re-sends an unechoed SCHED on the next live
// lane in rotation that is not write-blocked (D6): setting its schedSent to
// epoch − 1 makes its Fill place the SCHED once more.
func (a *actor) schedResendLocked(now time.Time) {
	s := a.s
	ctl := &s.ctl
	if a.d == nil || ctl.set.N == 0 || !sched.EpochNewer(ctl.epoch, ctl.echoed) {
		a.resendAt = time.Time{}
		return
	}
	if a.resendAt.IsZero() {
		a.resendAt = now.Add(a.resendEvery())
	}
	if now.Before(a.resendAt) {
		a.want(a.resendAt)
		return
	}
	if l := a.resendLaneLocked(); l != nil {
		l.schedSent = ctl.epoch - 1
		wakeLaneLocked(l)
	}
	a.resendAt = now.Add(a.resendEvery())
	a.want(a.resendAt)
}

// resendLaneLocked picks the next lane for a SCHED resend: live, CLOSE not
// written, preferably neither write-blocked nor retired.
func (a *actor) resendLaneLocked() *lane {
	lanes := a.s.lanes
	var fallback *lane
	for k := range lanes {
		i := (a.resendIdx + k) % len(lanes)
		l := lanes[i]
		if l.state == LaneDead || l.c.CloseSent() {
			continue
		}
		if l.port.WriteBlocked() || l.retireCalled {
			if fallback == nil {
				fallback = l
			}
			continue
		}
		a.resendIdx = i + 1
		return l
	}
	return fallback
}

// applySchedLocked (passive) applies the newest SCHED stored by the stream
// if its epoch is newer than the applied one (L45: 3, 1, 2 ends at 3), then
// echoes it at once with an urgent ACK.
func (a *actor) applySchedLocked(now time.Time) {
	s := a.s
	ctl := &s.ctl
	if !ctl.schedInSet || !sched.EpochNewer(ctl.schedIn.Epoch, ctl.epoch) {
		return
	}
	ctl.epoch = ctl.schedIn.Epoch
	ctl.set = ctl.schedIn
	ctl.cause = ctl.schedInCause
	a.dirty = true
	a.passiveRouteLocked(now)
	if s.p.Mode != ModeBond {
		a.followCountsLocked(now)
	}
	s.bumpAckLocked(true)
}

// followCountsLocked (passive selector) takes the dialer's cumulative
// selector migration counts from the SCHED just applied (§7.6, P13, §0.13
// A3). The passive cannot classify a dialer switch by itself, and counting
// from the cause of each applied SCHED missed every SCHED superseded
// before it reached the passive — lost with the carrier that died right
// after it attached (L20), or never sent because the next publication came
// first (L22) — so the ends disagreed. Every migration taken this way is
// one Migration event, from the carrier the previous applied SCHED (or the
// epoch-0 choice) named to the one this SCHED names.
func (a *actor) followCountsLocked(now time.Time) {
	ctl := &a.s.ctl
	from, to := a.named, ctl.set.IDs[0]
	a.followLocked(now, &ctl.migDeath, ctl.set.Death, from, to, wire.SchedDeath)
	a.followLocked(now, &ctl.migQuality, ctl.set.Quality, from, to, wire.SchedQuality)
	a.followLocked(now, &ctl.migExplicit, ctl.set.Explicit, from, to, wire.SchedExplicit)
	a.named = to
}

// followLocked raises the passive counter *have to the dialer's count want,
// one Migration event per migration.
func (a *actor) followLocked(now time.Time, have *uint64, want uint64, from, to uint32, c wire.SchedCause) {
	for ; *have < want; *have++ {
		a.dirty = true
		a.event(now, EventMigration, 0, from, to, schedEventCause(c), nil)
	}
}

// schedLists reports whether set names carrier id.
func schedLists(set *wire.Sched, id uint32) bool {
	for _, x := range set.IDs[:set.N] {
		if x == id {
			return true
		}
	}
	return false
}

// passiveRouteLocked recomputes the passive's send set (§7.5): selector →
// the lane the applied SCHED names, if usable; else the current sender
// while it is alive; else the local fallback (D24) — the newest usable
// lane. A lane leaving the set has its spans requeued, so reverse traffic
// leaves it within one RTT (L45).
//
// Routing only: a local fallback counts nothing, and the counts come with
// the SCHED (followCountsLocked), so both ends count alike (§7.6, P13).
func (a *actor) passiveRouteLocked(now time.Time) {
	s := a.s
	ctl := &s.ctl
	if a.ending || (ctl.state != StateOpen && ctl.state != StateClosing) {
		return
	}
	if s.p.Mode == ModeBond {
		a.passiveBondRouteLocked(now)
		return
	}
	var named *lane
	if ctl.set.N > 0 {
		if l := a.laneByIDLocked(ctl.set.IDs[0]); l != nil && s.usableLocked(l) {
			named = l
		}
	}
	cur := ctl.active
	next := cur
	switch {
	case named != nil:
		next = named
	case cur != nil && s.aliveLocked(cur) && !cur.c.CloseSent():
		// keep (the epoch-0 sender may still be placing its OPEN_ACK)
	default:
		next = a.newestUsableLocked(nil)
	}
	if next != cur {
		if cur != nil && cur.state != LaneDead {
			cur.data = false
			if cur.state == LaneActive {
				cur.state = LaneMember
			}
			s.requeueLocked(cur)
		}
		ctl.active = next
		if next != nil {
			// Routed and reported in the same critical section (L27): a
			// lane whose first response was placed but not yet announced
			// is active as soon as it routes.
			next.data = true
			next.state = LaneActive
		}
		s.routingChangedLocked()
		a.dirty = true
	}
}

// passiveBondRouteLocked: the data lanes are the usable lanes the applied
// SCHED lists; before the first SCHED, the epoch-0 senders chosen at
// Confirm while they live; with none, one local fallback (D24): the
// current fallback while it stays usable — recomputing the routing never
// moves it, so its in-flight spans are not requeued and resent for
// nothing — else the newest usable lane.
//
// A lane that starts carrying data while a bond death is owed (the last
// data member died with this side's unacknowledged DATA requeued) counts
// that death migration (§7.6: each side counts at its next data lane).
func (a *actor) passiveBondRouteLocked(now time.Time) {
	s := a.s
	listed := false
	for _, l := range s.lanes {
		if a.bondListedLocked(l) {
			listed = true
			break
		}
	}
	var fb *lane
	if !listed {
		for _, l := range s.lanes {
			if l.data && s.usableLocked(l) {
				fb = l // keep the newest current fallback
			}
		}
		if fb == nil {
			fb = a.newestUsableLocked(nil)
		}
	}
	changed := false
	for _, l := range s.lanes {
		want := l == fb || (listed && a.bondListedLocked(l))
		if want == l.data {
			continue
		}
		l.data = want
		changed = true
		if !want {
			s.requeueLocked(l)
			continue
		}
		if l.state == LaneJoining {
			l.state = LaneMember // routed and reported together (L27)
		}
		a.owedDeathLocked(now, l.id)
	}
	if changed {
		s.routingChangedLocked()
		a.dirty = true
	}
}

// bondListedLocked (passive bond): l belongs to the send set — listed by
// the applied SCHED and usable, or, before the first SCHED, an epoch-0
// sender that is still alive.
func (a *actor) bondListedLocked(l *lane) bool {
	s := a.s
	if s.ctl.set.N > 0 {
		return s.usableLocked(l) && schedLists(&s.ctl.set, l.id)
	}
	return l.data && s.aliveLocked(l)
}

// schedEventCause is the Event cause of a passive migration counted from a
// SCHED.
func schedEventCause(c wire.SchedCause) carrier.Cause {
	switch c {
	case wire.SchedQuality:
		return carrier.CauseQuality
	case wire.SchedExplicit:
		return carrier.CauseRetired
	}
	return carrier.CauseNone
}
