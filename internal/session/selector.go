package session

import (
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The dialer selector (design §7.2; L22, L28, L29; D7, W10, W11): while it
// has an active lane, quality switches follow sched.Selector over the
// health snapshot — evaluated on every new snapshot version and at
// Verdict.Wake, nothing else (application silence never triggers anything,
// L30). Without an active lane the failover race runs instead (§7.3).

// selectorLocked is the selector's step after the session opened.
func (a *actor) selectorLocked(now time.Time) {
	d := a.d
	if a.s.ctl.active == nil {
		if !d.raceOn {
			a.startRaceLocked(now)
		}
		a.raceLocked(now)
		return
	}
	a.qualityLocked(now)
}

// startFailoverRaceLocked starts the selector's death failover race
// (§7.3) after factory dead's carrier died: the ranking at now — the dead
// factory ranks last (failed) but stays a candidate — stably partitioned
// so that the factories outside dead's fate group come first
// (sched.GroupFirst, M3-D38): members of one group fail together, so their
// siblings are tried only after every independent path. A dead factory
// with a group of its own (or −1, a loss that is no death) keeps M1's
// ranking.
func (a *actor) startFailoverRaceLocked(now time.Time, dead int) {
	d := a.d
	order := a.rankLocked(now)
	if g := d.spec.group(dead); g != 0 {
		order = sched.GroupFirst(order, d.spec.group, g, order)
	}
	d.race = sched.NewRace(order, orDefault(a.s.p.JoinStagger, defJoinStagger), now)
	d.raceOn = true
}

// qualityLocked evaluates the quality rule when the health layer published
// a new snapshot, the active factory changed, or Verdict.Wake passed.
func (a *actor) qualityLocked(now time.Time) {
	d := a.d
	if d.h == nil || d.switchTo >= 0 {
		return // inert health: no evidence; or a switch JOIN is running
	}
	snap := d.h.Snapshot()
	if snap == nil {
		return
	}
	act := a.s.ctl.active.factory
	if snap.Version == d.selVer && act == d.selAct && (d.selWake.IsZero() || now.Before(d.selWake)) {
		a.want(d.selWake)
		return
	}
	d.selVer, d.selAct = snap.Version, act
	for i := range d.selFailed {
		// A factory that just died is no challenger either, nor one the
		// session may not dial (integration 1 D6: marked failed for
		// Evaluate, so it never becomes a quality target).
		d.selFailed[i] = a.failedLocked(snap, i) || !d.spec.eligible(i)
	}
	v := d.sel.Evaluate(now, act, snap.Sum, d.selFailed)
	d.selWake = v.Wake
	a.want(v.Wake)
	if v.Switch {
		a.startSwitchLocked(now, v.To)
	}
}

// startSwitchLocked begins a planned switch to factory to (§7.2 steps 1–2):
// a live lane of that factory that can still carry data is used at once;
// otherwise a JOIN starts on its slot if the slot is ready (nothing changes
// until its JOIN_ACK); a slot in backoff restarts every dwell instead.
func (a *actor) startSwitchLocked(now time.Time, to int) {
	s := a.s
	d := a.d
	for _, l := range s.lanes {
		if l.factory == to && l != s.ctl.active && s.usableLocked(l) {
			a.qualitySwitchLocked(now, l)
			return
		}
	}
	if to < 0 || to >= len(d.slots) {
		return
	}
	if ok, _ := d.slots[to].cad.Ready(now); !ok {
		d.sel.Switched(now, false)
		return
	}
	d.switchTo = to
	a.startAttemptLocked(now, to, wire.TypeJoin)
}

// qualitySwitchLocked completes a planned switch to lane nl in one step
// (§7.2 step 3): nl becomes active; the old active retires (no new DATA,
// its unacknowledged spans replayed in order on nl, CLOSE once they are
// acknowledged or after RetireGrace); SCHED{quality}; one quality
// migration timestamped now (L09); the cooldown starts. A packet session
// requeues nothing — new datagrams take nl at once — and the old lane
// retires once the passive echoed the SCHED that removed it, plus 2·srtt
// for the datagrams the passive had in flight on it, or at RetireGrace
// (M2-D42, retiringLocked).
func (a *actor) qualitySwitchLocked(now time.Time, nl *lane) {
	s := a.s
	d := a.d
	old := s.ctl.active
	a.activateLocked(nl)
	var from uint32
	if old != nil && old != nl {
		from = old.id
		old.data = false
		old.state = LaneRetiring
		old.retireMark = s.st.sNext
		old.retireAt = now.Add(s.p.RetireGrace)
		s.requeueLocked(old)
	}
	a.publishSchedLocked(now, wire.SchedQuality)
	if s.pk != nil && old != nil && old != nl {
		old.retireEpoch, old.retireEchoAt = s.ctl.epoch, time.Time{}
	}
	a.countLocked(now, wire.SchedQuality, from, nl.id, carrier.CauseQuality)
	d.sel.Switched(now, true)
	d.switchTo = -1
	s.routingChangedLocked()
}
