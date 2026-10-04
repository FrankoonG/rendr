package session

import (
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Death handling (design §7.3; L19, L21, L27): the synchronous fallback.
// When the actor sees a carrier's death record, it marks the lane dead and
// data-ineligible before laneGoneLocked requeues the lane's spans (C1: a
// Fill of the dead lane racing this step appends nothing afterwards), and
// in the same critical section it chooses the fallback and publishes the
// new routing. Death bypasses band, dwell, cooldown and every control
// round trip.

// reapDead handles every lane whose carrier ended, one death per critical
// section. Hooks.DeathObserved runs before each, outside the lock (a test
// may hold the actor there, L21, L27). It returns now, refreshed after a
// hook held the actor (migration timestamps are publication times, L09).
func (a *actor) reapDead(now time.Time) time.Time {
	s := a.s
	for i := 0; i < len(s.lanes); {
		l := s.lanes[i]
		if dead, _, _, _ := l.c.Death(); !dead {
			i++
			continue
		}
		if h := s.env.Hooks; h != nil && h.DeathObserved != nil {
			h.DeathObserved(l.id)
			now = time.Now()
		}
		s.mu.Lock()
		a.laneDiedLocked(now, l) // removes l from s.lanes: i now names the next lane
		a.unlockStep(now)
	}
	return now
}

// laneDiedLocked is the death step of lane l (§7.3).
func (a *actor) laneDiedLocked(now time.Time, l *lane) {
	s := a.s
	ctl := &s.ctl
	_, cause, detail, at := l.c.Death()
	wasActive := ctl.active == l
	wasData := l.data
	l.state = LaneDead
	l.data = false
	requeued := s.laneGoneLocked(l) // spans to retx, FIN re-armed, ACK duty moved, survivors woken
	if wasActive {
		ctl.active = nil
	}
	a.removeLaneLocked(l, cause, detail, at)
	if a.ending {
		return
	}
	a.event(now, EventCarrierDown, l.id, 0, 0, cause, nil)
	if ctl.state == StatePending {
		return // a pending session survives the death of its carriers (§6.2, F6)
	}
	if a.d != nil {
		a.dialerLaneDiedLocked(now, l, cause, wasActive, wasData, requeued)
	} else {
		a.passiveRouteLocked(now) // local fallback (D24): routing only
		if s.p.Mode == ModeBond && wasData {
			a.bondDeathCountLocked(now, l.id, cause, requeued)
		}
	}
	if !a.hasAliveLocked() {
		a.episodeStartLocked(now, at)
	}
}

// dialerLaneDiedLocked is the dialer part of a death step: the failed mark
// and the immediate redial of the factory for a death cause (not gated by
// the mark, plan §3.2), then the bond shrink or the selector fallback.
func (a *actor) dialerLaneDiedLocked(now time.Time, l *lane, cause carrier.Cause, wasActive, wasData bool, requeued uint64) {
	d := a.d
	if cause.Death() && l.factory >= 0 && l.factory < len(d.slots) {
		a.markFailed(l.factory, cause.String())
		d.slots[l.factory].cad.Kick()
	}
	if a.s.p.Mode == ModeBond {
		if wasData {
			a.publishSchedLocked(now, wire.SchedDeath) // the shrunk member set, if a member is left
			a.bondDeathCountLocked(now, l.id, cause, requeued)
		}
		return
	}
	if wasActive {
		a.lostActiveLocked(now, l.id, cause)
	}
}

// lostActiveLocked repairs a selector's routing after its active lane was
// lost — to a death, to CauseRetired, or to a peer CLOSE or GOAWAY (§7.3:
// losing the active lane for any reason is a routing loss): the usable lane
// with the lowest srtt becomes active at once; without one a race over the
// ranking starts now and its winner is counted when published. A death
// cause counts death, the others explicit (§7.6).
func (a *actor) lostActiveLocked(now time.Time, from uint32, cause carrier.Cause) {
	d := a.d
	d.switchTo = -1 // a planned switch is moot; its JOIN, if it attaches, may win the race
	mc := wire.SchedDeath
	if !cause.Death() {
		mc = wire.SchedExplicit
	}
	if fb := a.bestUsableLocked(nil); fb != nil {
		a.activateLocked(fb)
		a.publishSchedLocked(now, mc)
		a.countLocked(now, mc, from, fb.id, cause)
		d.sel.Switched(now, false)
		a.s.routingChangedLocked()
		return
	}
	a.lossSet, a.lossCause, a.lossFrom, a.lossEv = true, mc, from, cause
	a.startRaceLocked(now)
}

// countLocked counts one migration of cause c (death, quality, explicit;
// initial never counts, C26) and queues its event.
func (a *actor) countLocked(now time.Time, c wire.SchedCause, from, to uint32, ev carrier.Cause) {
	ctl := &a.s.ctl
	switch c {
	case wire.SchedDeath:
		ctl.migDeath++
	case wire.SchedQuality:
		ctl.migQuality++
	case wire.SchedExplicit:
		ctl.migExplicit++
	default:
		return
	}
	a.dirty = true
	a.event(now, EventMigration, 0, from, to, ev, nil)
}

// bondDeathCountLocked counts a bond member's death that requeued this
// side's unacknowledged DATA (§7.6): now if another member carries data,
// else at the next attach (deathOwed; dropped if the session ends).
func (a *actor) bondDeathCountLocked(now time.Time, from uint32, cause carrier.Cause, requeued uint64) {
	if requeued == 0 {
		return
	}
	if a.dataLaneCountLocked() > 0 {
		a.countLocked(now, wire.SchedDeath, from, 0, cause)
		return
	}
	a.deathOwed = true
	a.lossFrom, a.lossEv = from, cause
}

// owedDeathLocked counts an owed bond death migration at an attach.
func (a *actor) owedDeathLocked(now time.Time, to uint32) {
	if a.deathOwed {
		a.deathOwed = false
		a.countLocked(now, wire.SchedDeath, a.lossFrom, to, a.lossEv)
	}
}

// peerSignalsLocked reconciles peer GOAWAY and CLOSE on live lanes. A
// GOAWAY comes from the bound instance (every lane of a session reaches
// it): the session ends (§6.8). A peer CLOSE retires the lane; losing the
// selector's active lane that way is a routing loss (§7.3).
func (a *actor) peerSignalsLocked(now time.Time) {
	if a.ending {
		return
	}
	s := a.s
	for _, l := range s.lanes {
		if l.state != LaneDead && l.c.PeerGoAway() {
			a.peerGoAwayLocked(now)
			return
		}
	}
	for _, l := range s.lanes {
		if l.state != LaneDead && !l.retireCalled && l.c.PeerClosed() {
			a.peerClosedLocked(now, l)
		}
	}
}

// peerGoAwayLocked ends the session after a GOAWAY from the bound instance:
// with *AbortError{AbortGoingAway, Remote: true} whether or not the RST
// arrived (plan §3.4); the dialer's Peer never OPENs to it again (D21). A
// pending session is withdrawn (its dialer is going away).
func (a *actor) peerGoAwayLocked(now time.Time) {
	s := a.s
	if d := a.d; d != nil && d.spec.NoteGoAway != nil {
		inst, note := s.peer, d.spec.NoteGoAway
		a.later = append(a.later, func() { note(inst) })
	}
	if s.ctl.state == StatePending {
		a.withdrawnLocked(now)
		return
	}
	a.terminateLocked(now, &AbortError{Code: AbortGoingAway, Msg: "peer going away", Remote: true}, nil, false)
}

// peerClosedLocked handles the peer's CLOSE on lane l: answer it (Retire;
// its spans are requeued and replayed elsewhere) and repair routing.
func (a *actor) peerClosedLocked(now time.Time, l *lane) {
	s := a.s
	wasActive := s.ctl.active == l
	wasData := l.data
	a.retireLaneLocked(l)
	if s.ctl.state == StatePending {
		return
	}
	if a.d == nil {
		a.passiveRouteLocked(now)
	} else if s.p.Mode == ModeBond {
		if wasData {
			a.publishSchedLocked(now, wire.SchedExplicit)
		}
	} else if wasActive {
		a.lostActiveLocked(now, l.id, carrier.CauseRetired)
	}
	if !a.hasAliveLocked() {
		a.episodeStartLocked(now, now)
	}
}
