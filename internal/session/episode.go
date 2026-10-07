package session

import (
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// No-path episodes (design §7.7; L18): an episode starts at the death time
// of the session's last live carrier (or its retirement) — not at the last
// frame received — and gets the full grace: NoPathGrace on the dialer,
// PassiveRetain from the OPEN on the passive. Any carrier attaching ends
// it, and the next episode starts with a fresh budget. Expiry is decided
// after the step handled its commands (an attach already queued wins) and
// only while no carrier is alive; the session then ends with ErrNoPath, or
// cleanly (io.EOF) once our DONE was sent (design §0.14 B4: the grace can
// be shorter than Linger, and the peer's DONE was lost with the carrier).

// episodeStartLocked starts an episode at time at (a death time; now if
// zero or later). The dialer redials at once: the selector's race was
// started by the death step; bond kicks every member slot.
func (a *actor) episodeStartLocked(now, at time.Time) {
	s := a.s
	ctl := &s.ctl
	if ctl.inNoPath || a.ending || ctl.state == StatePending {
		return
	}
	if at.IsZero() || at.After(now) {
		at = now
	}
	ctl.inNoPath = true
	ctl.episodeStart = at
	ctl.episodeGen++
	ctl.episodes++
	a.episodeBy = at.Add(orDefault(s.p.Grace, defGrace))
	a.want(a.episodeBy)
	a.dirty = true
	a.event(now, EventNoPathStart, 0, 0, 0, carrier.CauseNone, nil)
	if d := a.d; d != nil {
		if s.p.Mode == ModeBond {
			for i := range d.slots {
				if d.slots[i].member {
					d.slots[i].cad.Kick()
				}
			}
		}
		return
	}
	if !a.orphanOn {
		a.orphanOn = true
		a.registry(func(r Registry) { r.Orphaned(s, true) })
	}
}

// episodeEndLocked ends the current episode (a carrier attached). A packet
// session records the end time: a datagram queued before it that ages out
// later counts DropNoPath, not DropAge (M2-D35).
func (a *actor) episodeEndLocked(now time.Time) {
	s := a.s
	ctl := &s.ctl
	if !ctl.inNoPath {
		return
	}
	if s.pk != nil {
		s.pk.noPathEnd = now
	}
	ctl.inNoPath = false
	a.episodeBy = time.Time{}
	a.dirty = true
	a.event(now, EventNoPathEnd, 0, 0, 0, carrier.CauseNone, nil)
	if a.orphanOn {
		a.orphanOn = false
		a.registry(func(r Registry) { r.Orphaned(s, false) })
	}
}

// episodeExpiryLocked ends the session when the episode's grace passed and
// still no carrier is alive: with ErrNoPath, or with io.EOF once our DONE
// was sent (doneOr). With the defaults the dialer's NoPathGrace (15 s) and
// a PassiveRetain below Linger (a dialer NoPathGrace of 10 s or less) both
// expire before the Linger rule after our DONE could end the session.
func (a *actor) episodeExpiryLocked(now time.Time) {
	if !a.s.ctl.inNoPath {
		return
	}
	if a.hasAliveLocked() {
		a.episodeEndLocked(now)
		return
	}
	if now.Before(a.episodeBy) {
		a.want(a.episodeBy)
		return
	}
	a.terminateLocked(now, a.doneOr(ErrNoPath), nil, false)
}
