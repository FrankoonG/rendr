package session

import (
	"io"
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
//
// A GOAWAY the peer sent on the dying carrier is reconciled first, in the
// same critical section: GOAWAY ends the session whether or not its lane
// is still alive (§4.7, §6.8), so a carrier that died right after
// delivering it never hides it.
func (a *actor) reapDead(now time.Time) time.Time {
	s := a.s
	a.readerWait = nil
	for i := 0; i < len(s.lanes); {
		l := s.lanes[i]
		if dead, _, _, _ := l.c.Death(); !dead {
			i++
			continue
		}
		s.mu.Lock()
		wait := a.awaitReaderLocked(l)
		s.mu.Unlock()
		if wait {
			if a.readerWait == nil {
				a.readerWait = l.c.Done() // the loop wakes when it closes
			}
			i++
			continue
		}
		if h := s.env.Hooks; h != nil && h.DeathObserved != nil {
			h.DeathObserved(l.id)
			now = time.Now()
		}
		s.mu.Lock()
		if l.c.PeerGoAway() {
			a.peerGoAwayLocked(now)
		}
		a.endIfPeerEndedLocked(now)
		a.laneDiedLocked(now, l) // removes l from s.lanes: i now names the next lane
		a.unlockStep(now)
	}
	return now
}

// awaitReaderLocked reports that the death step of the ended lane l waits
// for its reader (design §0.13 A2, amending X3). Once our DONE was sent
// and while the peer's is still outstanding, the peer may already have
// ended cleanly: it ends as soon as it holds both DONEs and then retires
// its carriers, so its DONE and the end of the carrier that carries it can
// reach this side together, and the death can be noticed first — by this
// carrier's writer, or through another lane — while the DONE still sits in
// this carrier's reader. Its reader dispatches every frame it read before
// it exits, so the death step waits until the carrier is done; a clean end
// found that way is no routing loss (X3: no failed mark, redial, no-path
// episode or migration). The wait is bounded by the carrier's own join
// (AbandonWait for a call stuck in embedder code). When the carrier is done
// and the peer's DONE did not come, the death step runs as before, with the
// death time the carrier recorded.
func (a *actor) awaitReaderLocked(l *lane) bool {
	st := &a.s.st
	if a.ending || !st.doneSent || st.peerDone {
		return false
	}
	select {
	case <-l.c.Done():
		return false
	default:
		return true
	}
}

// readersPendingLocked reports an ended lane whose death step waits for its
// reader (awaitReaderLocked): the session may still end cleanly, so no
// no-path episode starts before that lane's death step decides.
func (a *actor) readersPendingLocked() bool {
	for _, l := range a.s.lanes {
		if laneEnded(l) && a.awaitReaderLocked(l) {
			return true
		}
	}
	return false
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
	requeued := s.laneGoneLocked(l) // spans to retx (race: while no data lane lives), FIN re-armed, ACK duty moved, survivors woken
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
		a.dialerLaneDiedLocked(now, l, cause, at, wasActive, wasData, requeued)
	} else {
		a.passiveRouteLocked(now) // local fallback (D24): routing only
		if s.p.Mode.members() && wasData {
			a.bondDeathCountLocked(now, l.id, cause, requeued)
		}
	}
	if !a.hasAliveLocked() && !a.readersPendingLocked() {
		// The other lanes may have ended too and wait for their own death
		// step: the episode starts at the death of the last live carrier.
		a.episodeStartLocked(now, a.lastDeathLocked(at))
	}
}

// dialerLaneDiedLocked is the dialer part of a death step: the failed mark,
// dated by the carrier's death time diedAt (zero: now) rather than by this
// step, and the immediate redial of the factory for a death cause (not
// gated by the mark, plan §3.2), then the bond or race shrink or the
// selector fallback, whose race tries the factories outside the dead
// carrier's fate group first (M3-D38).
func (a *actor) dialerLaneDiedLocked(now time.Time, l *lane, cause carrier.Cause, diedAt time.Time, wasActive, wasData bool, requeued uint64) {
	d := a.d
	if cause.Death() && l.factory >= 0 && l.factory < len(d.slots) {
		if diedAt.IsZero() || diedAt.After(now) {
			diedAt = now
		}
		a.markFailed(l.factory, cause.String(), diedAt)
		d.slots[l.factory].cad.Kick()
	}
	if a.s.p.Mode.members() {
		if wasData {
			a.publishSchedLocked(now, wire.SchedDeath) // the shrunk member set, if a member is left
			a.bondDeathCountLocked(now, l.id, cause, requeued)
		}
		return
	}
	if wasActive {
		dead := -1
		if cause.Death() {
			dead = l.factory
		}
		a.lostActiveLocked(now, l.id, cause, dead)
	}
}

// lostActiveLocked repairs a selector's routing after its active lane was
// lost — to a death, to CauseRetired, or to a peer CLOSE or GOAWAY (§7.3:
// losing the active lane for any reason is a routing loss): the usable lane
// with the lowest srtt becomes active at once; without one a race over the
// ranking starts now and its winner is counted when published. A death
// cause counts death, the others explicit (§7.6). dead is the factory whose
// carrier died (−1: not a death): the race then ranks the factories outside
// its fate group first (startFailoverRaceLocked, M3-D38).
func (a *actor) lostActiveLocked(now time.Time, from uint32, cause carrier.Cause, dead int) {
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
	a.startFailoverRaceLocked(now, dead)
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
//
// A race member's death counts the same way when its in-flight spans were
// non-empty (M3-D34, PA-32): laneGoneLocked returns them although nothing
// is requeued while another data lane lives (the others carry copies), so
// the death counts whether or not another member lives. A packet member's
// death counts when it placed a DGRAM within the last PacketPing (M2-D44),
// in race as in bond.
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

// peerSignalsLocked reconciles peer GOAWAY and CLOSE on the lanes. A
// GOAWAY comes from the bound instance (every lane of a session reaches
// it): the session ends (§6.8); it is also reconciled during the end phase,
// because the peer's RST(GoingAway) may overtake its GOAWAY and end the
// session first (with the same error: endIfPeerEndedLocked,
// terminationLocked), and the dialer must still note the instance (D21). A
// peer CLOSE retires the lane; losing the selector's active lane that way
// is a routing loss (§7.3) — unless the peer's RST or DONE ended the
// session first (endIfPeerEndedLocked).
func (a *actor) peerSignalsLocked(now time.Time) {
	s := a.s
	for _, l := range s.lanes {
		if l.c.PeerGoAway() {
			a.peerGoAwayLocked(now)
			break
		}
	}
	if a.ending {
		return
	}
	if a.endIfPeerEndedLocked(now); a.ending {
		return
	}
	if a.readersPendingLocked() {
		// A peer CLOSE may be the peer's retirement after a DONE still
		// sitting in another lane's reader (awaitReaderLocked): its routing
		// repair waits for that reader as well.
		return
	}
	for _, l := range s.lanes {
		if l.state != LaneDead && !l.retireCalled && l.c.PeerClosed() {
			a.peerClosedLocked(now, l)
		}
	}
}

// endIfPeerEndedLocked ends an open session once the peer's end is known,
// before the step treats carrier ends as routing losses (reapDead) and
// before terminationLocked's other rules (peerSignalsLocked runs it in the
// critical section of actLocked, ahead of it):
//
//   - The DONE went both ways (D4): terminationLocked ends the session
//     cleanly. Once both DONEs crossed, the peer ends and retires its
//     carriers (CLOSE, then their close), and its DONE and its CLOSE often
//     reach this actor in one step (always at GOMAXPROCS=1); repairing
//     routing first would start a no-path episode — a NoPathStart event, an
//     Orphaned call, one more episode — and on the dialer a failover race,
//     right before terminationLocked ends the session cleanly in that same
//     step.
//   - A peer RST arrived, of any code: terminationLocked's reset rule ends
//     the session — with *AbortError, or cleanly (io.EOF) once our DONE was
//     sent (doneOr). The peer resets when its Linger or IdleTimeout expires
//     (after our DONE: our FIN_DELIVERED and DONE were lost, so it never
//     learned that its FIN was delivered), when it closed while we kept
//     sending, or because its Runtime is closing: RST(GoingAway), which
//     travels with a GOAWAY, and either may arrive first (a writer round
//     that had placed its carrier controls before the GOAWAY was requested
//     carries the RST alone, the GOAWAY follows in the next round; plan §3.4
//     gives both the same end, peerGoAwayLocked). The RST is the peer's last
//     session frame: it then retires its carriers, so its CLOSE and the
//     carriers' ends follow the RST, often into the same step — and a
//     session the peer reset is no routing loss (no episode, no Orphaned
//     call, no failover race or redial towards a peer that has ended it). No
//     RST is sent back (§4.7). A GOAWAY that follows still notes the
//     instance (D21): peerSignalsLocked reconciles it in the end phase.
//
// A session that never opened (a pending passive, a dialer in its opening
// phase) is left to pendingLocked and the opening rules.
func (a *actor) endIfPeerEndedLocked(now time.Time) {
	st := &a.s.st
	if !a.ending && a.opened && (st.rstIn != nil || (st.doneSent && st.peerDone)) {
		a.terminationLocked(now)
	}
}

// doneOr is the error of an end that proves the peer gone, going away or
// done waiting — the no-path episode's expiry, a GOING_AWAY answer, a
// GOAWAY, a JOIN that reached a restarted peer or was answered
// UNKNOWN_SESSION, a peer RST of any code (terminationLocked,
// endIfPeerEndedLocked): io.EOF once our DONE was sent, else err (D4,
// extended by design §0.14 B4 and, for every RST code, in M1c). Our
// DONE follows the peer's FIN_DELIVERED for our FIN and our own for its
// FIN: the peer delivered everything we sent, and its FIN reached our
// application. Only the peer's DONE is missing — lost with a dying carrier,
// or never sent because our FIN_DELIVERED was lost — so such an end is the
// clean end that DONE would have given, whichever comes first: it, Linger
// after our DONE (terminationLocked), or the proof that the peer is gone or
// gave up. An end before our DONE was sent keeps err — also one in the
// gap after DONE's conditions held and before the duty lane placed it (a
// writer round; longer while that lane's writer is blocked, until the duty
// moves after PingBusy): the gate is the DONE actually sent, one gate for
// every end listed here.
func (a *actor) doneOr(err error) error {
	if a.s.st.doneSent {
		return io.EOF
	}
	return err
}

// peerGoAwayLocked reconciles a GOAWAY from the bound instance: the
// dialer's Peer notes the instance once and never OPENs to it again (D21);
// an open session ends with *AbortError{AbortGoingAway, Remote: true}
// whether or not the RST arrived (plan §3.4) — or cleanly (io.EOF) once our
// DONE was sent (doneOr), as when the RST arrives first
// (endIfPeerEndedLocked) —; a pending session is withdrawn (its dialer is
// going away). A session that already ended only notes the instance.
func (a *actor) peerGoAwayLocked(now time.Time) {
	s := a.s
	if !a.goAwaySeen {
		a.goAwaySeen = true
		if a.d != nil {
			a.noteGoAway(s.peer)
		}
	}
	switch {
	case a.ending:
	case s.ctl.state == StatePending:
		a.withdrawnLocked(now)
	default:
		a.terminateLocked(now, a.doneOr(&AbortError{Code: AbortGoingAway, Msg: "peer going away", Remote: true}), nil, false)
	}
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
	} else if s.p.Mode.members() {
		if wasData {
			a.publishSchedLocked(now, wire.SchedExplicit)
		}
	} else if wasActive {
		a.lostActiveLocked(now, l.id, carrier.CauseRetired, -1)
	}
	if !a.hasAliveLocked() && !a.readersPendingLocked() {
		a.episodeStartLocked(now, now)
	}
}
