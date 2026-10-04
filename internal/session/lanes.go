package session

import (
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Lanes on the actor side (design §7.1): creation, removal, predicates and
// the routing primitives. A lane is (session, carrier incarnation); its
// data eligibility (lane.data) is the single routing variable the carrier
// writers and Status read (L27), written only here under the session lock.

// newLaneLocked registers the unstarted carrier c as a new lane in state
// st (the caller then sets its role and starts c). laneAddedLocked runs
// after the state is set, so a dialer lane qualifies for the ACK duty at
// once (§4.6).
func (a *actor) newLaneLocked(now time.Time, c *carrier.Conn, factory int, gen uint32, st LaneState) *lane {
	s := a.s
	l := &lane{s: s, c: c, port: c, id: c.ID(), factory: factory, gen: gen, since: now}
	l.state = st
	l.schedSent = s.ctl.epoch // a lane carries only SCHEDs published after it attached
	s.lanes = append(s.lanes, l)
	s.laneAddedLocked(l)
	a.dirty = true
	return l
}

// removeLaneLocked drops a dead lane from s.lanes (keeping the attach order
// of the others), keeps its carrier for the exit join and records it among
// the last dead lanes of Status.
func (a *actor) removeLaneLocked(l *lane, cause carrier.Cause, detail string, at time.Time) {
	s := a.s
	for i, o := range s.lanes {
		if o == l {
			copy(s.lanes[i:], s.lanes[i+1:])
			s.lanes[len(s.lanes)-1] = nil
			s.lanes = s.lanes[:len(s.lanes)-1]
			break
		}
	}
	if len(a.gone) >= 16 {
		a.joinWait() // drop the carriers already joined: churn never grows the list
	}
	a.gone = append(a.gone, l.c)
	if len(a.dead) == maxDeadLanes {
		copy(a.dead, a.dead[1:])
		a.dead = a.dead[:maxDeadLanes-1]
	}
	a.dead = append(a.dead, laneSnap{
		id: l.id, name: l.c.Name(), gen: l.gen, state: LaneDead, conn: l.c,
		deathCause: cause, deathDetail: detail, deathAt: at,
	})
	a.dirty = true
}

// usableLocked: l may carry DATA or serve as a fallback (§7.3, C7): live,
// Conn.Retire not called, no peer CLOSE or GOAWAY, our CLOSE not written;
// on the passive, its first response frame was placed and was not a
// refusal (a lane joins the data set only once confirmed, L22).
func (s *Session) usableLocked(l *lane) bool {
	if l.state == LaneDead || l.retireCalled {
		return false
	}
	if s.p.Role == RolePassive && (!l.firstSent || refusedLocked(l)) {
		return false
	}
	return !l.c.PeerClosed() && !l.c.PeerGoAway() && !l.c.CloseSent()
}

// aliveLocked: l counts as a carrier of the session for no-path purposes:
// not dead and not retired (a passive lane still placing its first
// response counts: it is attaching).
func (s *Session) aliveLocked(l *lane) bool {
	if l.state == LaneDead || l.retireCalled || (s.p.Role == RolePassive && refusedLocked(l)) {
		return false
	}
	return !l.c.PeerClosed() && !l.c.PeerGoAway()
}

// hasAliveLocked reports whether any lane is alive.
func (a *actor) hasAliveLocked() bool {
	for _, l := range a.s.lanes {
		if a.s.aliveLocked(l) {
			return true
		}
	}
	return false
}

// laneByIDLocked returns the live lane with CarrierID id, or nil.
func (a *actor) laneByIDLocked(id uint32) *lane {
	for _, l := range a.s.lanes {
		if l.id == id {
			return l
		}
	}
	return nil
}

// wakeLaneLocked makes l's writer run Fill again (a SCHED or first frame
// to place, a routing change).
func wakeLaneLocked(l *lane) {
	l.idle = false
	l.port.Wake()
}

// activateLocked makes l the selector's data lane: data-eligible, state
// active, any planned retirement cleared (a retiring lane on which Retire
// was not called yet is a valid fallback, §7.3).
func (a *actor) activateLocked(l *lane) {
	s := a.s
	l.data = true
	l.state = LaneActive
	l.retireAt, l.retireMark = time.Time{}, 0
	s.ctl.active = l
	a.dirty = true
}

// retireLaneLocked calls Conn.Retire on l (irreversible: never a data lane
// or a fallback again, §7.3 C7). retireCalled is set under the lock before
// the call (V15), so a Fill racing it places a pending delayed ACK first.
func (a *actor) retireLaneLocked(l *lane) {
	if l.retireCalled {
		return
	}
	s := a.s
	l.retireCalled = true
	l.data = false
	if l.state != LaneDead {
		l.state = LaneRetiring
	}
	if s.ctl.active == l {
		s.ctl.active = nil
	}
	s.requeueLocked(l)
	l.c.Retire(wire.CloseRetire)
	a.dirty = true
}

// fastestSRTTLocked returns the smallest known srtt of the data lanes (0
// when none is known).
func (a *actor) fastestSRTTLocked() time.Duration {
	var best time.Duration
	for _, l := range a.s.lanes {
		if !l.data {
			continue
		}
		if r := l.port.SRTT(); r > 0 && (best == 0 || r < best) {
			best = r
		}
	}
	return best
}

// bestUsableLocked returns the usable lane with the lowest srtt (unknown
// srtt last, then attach order), skipping skip; nil if none (§7.3).
func (a *actor) bestUsableLocked(skip *lane) *lane {
	var best *lane
	var bestRTT time.Duration
	for _, l := range a.s.lanes {
		if l == skip || !a.s.usableLocked(l) {
			continue
		}
		r := l.port.SRTT()
		if best == nil || srttBefore(r, bestRTT) {
			best, bestRTT = l, r
		}
	}
	return best
}

// newestUsableLocked returns the most recently attached usable lane (the
// passive's local fallback, D24), skipping skip.
func (a *actor) newestUsableLocked(skip *lane) *lane {
	for i := len(a.s.lanes) - 1; i >= 0; i-- {
		if l := a.s.lanes[i]; l != skip && a.s.usableLocked(l) {
			return l
		}
	}
	return nil
}

// dataLaneCountLocked counts the data-eligible lanes.
func (a *actor) dataLaneCountLocked() int {
	n := 0
	for _, l := range a.s.lanes {
		if l.data {
			n++
		}
	}
	return n
}
