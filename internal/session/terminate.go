package session

import (
	"io"
	"net"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Termination on the actor side (design §4.7; D4): the DONE exchange, the
// linger and idle deadlines, the reset rules, the end procedure with its
// Kill bound (C24), planned retirement of switched-away lanes and the
// window re-advertisement deadline (D18, W6).

// terminationLocked applies the end rules of an open or closing session in
// precedence order and arms their deadlines. The IdleTimeout clock
// (st.lastData) counts from the last application Write or Read commit or the
// last acknowledged delivery of our data (an sBase advance, §0.14 B5), but
// never from before the session opened: a pending phase (passive) or an
// opening phase (dialer) longer than IdleTimeout is not idleness of the open
// session. Idle therefore means that the application committed no Write or
// Read and nothing of ours was delivered for IdleTimeout: a Write blocked
// behind a slow reader whose bytes keep arriving is not idle, a peer that
// stops reading is. The data path moves the clock without ringing the
// actor; the deadline armed below fires at the old time, and that step
// re-arms it from the new one. Once our DONE was sent the idle rule no
// longer applies: the exchange is complete, and Linger (or the episode
// expiry, a GOAWAY, a peer restart or a peer RST, each ending with io.EOF)
// bounds the wait for the peer's DONE.
//
// A peer RST ends the session with *AbortError{Code, Msg, Remote: true} —
// or with io.EOF once our DONE was sent (doneOr), whatever its code: our
// FIN was acknowledged as delivered and the peer's FIN reached our
// application, so the exchange is complete, and an RST that follows (a
// peer whose Linger or IdleTimeout expired because our FIN_DELIVERED and
// DONE were lost, or its Runtime closing) only says that the peer gave up
// waiting for our DONE. Invariant 1 holds: the peer's FIN was delivered at
// the contiguous point, where Read returns io.EOF anyway.
func (a *actor) terminationLocked(now time.Time) {
	s := a.s
	st := &s.st
	linger := orDefault(s.p.Linger, defLinger)
	idleBase := st.lastData
	if a.openedAt.After(idleBase) {
		idleBase = a.openedAt
	}
	switch {
	case st.rstIn != nil:
		// RST received: no RST is sent back (§4.7).
		r := st.rstIn
		a.terminateLocked(now, a.doneOr(&AbortError{Code: AbortCode(r.Code), Msg: string(r.Msg), Remote: true}), nil, false)
	case st.exhausted:
		// L14: exactly one RST(Exhausted); the Write already returned the error.
		a.terminateLocked(now, errExhausted(), &wire.Rst{Code: wire.RstExhausted}, false)
	case st.doneSent && st.peerDone:
		a.terminateLocked(now, io.EOF, nil, false) // D4: DONE went both ways
	case st.doneSent && !now.Before(st.doneSentAt.Add(linger)):
		// D4: everything of ours was confirmed; the peer's DONE was lost
		// with a dying carrier.
		a.terminateLocked(now, io.EOF, nil, false)
	case st.closed && st.fin.acked && !st.peerFinSet && st.discardedAfterClose:
		// TCP close() semantics: the peer keeps sending to a closed
		// application (requiring discarded data avoids resetting a clean
		// simultaneous close, R17).
		a.terminateLocked(now, net.ErrClosed, &wire.Rst{Code: wire.RstClosed}, false)
	case st.closed && !st.doneSent && !now.Before(st.closedAt.Add(linger)):
		a.terminateLocked(now, net.ErrClosed, &wire.Rst{Code: wire.RstLinger}, false)
	case s.p.IdleTimeout > 0 && !st.doneSent && !now.Before(idleBase.Add(s.p.IdleTimeout)):
		// After our DONE the exchange is complete and Linger bounds the
		// wait for the peer's DONE (design §0.14 B4): not idleness.
		a.terminateLocked(now, ErrIdleTimeout, &wire.Rst{Code: wire.RstIdle}, false)
	default:
		if st.doneSent {
			a.want(st.doneSentAt.Add(linger))
		} else if st.closed {
			a.want(st.closedAt.Add(linger))
		}
		if s.p.IdleTimeout > 0 && !st.doneSent {
			a.want(idleBase.Add(s.p.IdleTimeout))
		}
	}
}

// terminateLocked is the end procedure (§4.7): state Ended, the RST to
// place (if any), endLocked, every lane data-ineligible and retired (GOAWAY
// first on shutdown) — Fill places the RST before each writer's CLOSE —,
// the Kill bound closeBy = now + min(1 s, DeadMax) (C24), the Registry and
// the SessionEnd event, and every outstanding dial attempt withdrawn. The
// actor then waits for the lanes and attempts and exits.
func (a *actor) terminateLocked(now time.Time, err error, rst *wire.Rst, goAway bool) {
	if a.ending {
		return
	}
	s := a.s
	ctl := &s.ctl
	a.ending = true
	a.endErr = err
	if a.opened {
		a.verdict = Verdict{Opened: true}
	}
	ctl.state = StateEnded
	if rst != nil {
		ctl.rst = rst
	}
	s.endLocked(err)
	for _, l := range s.lanes {
		if l.state == LaneDead {
			continue
		}
		l.data = false
		l.state = LaneRetiring
		l.retireCalled = true
		if goAway {
			l.c.GoAway()
		} else {
			l.c.Retire(wire.CloseRetire)
		}
	}
	ctl.active = nil
	ctl.inNoPath = false
	ctl.closeBy = now.Add(min(closeBound, a.deadMax()))
	a.want(ctl.closeBy)
	a.adoptsLeft = ctl.adopting // the exit waits for them (quiet); endingLocked keeps it current
	a.dirty = true
	if a.orphanOn {
		a.orphanOn = false
		a.registry(func(r Registry) { r.Orphaned(s, false) })
	}
	if a.lingerOn {
		a.lingerOn = false
		a.registry(func(r Registry) { r.Lingering(s, false) })
	}
	v := a.verdict
	a.registry(func(r Registry) { r.Ended(s, v) })
	a.event(now, EventSessionEnd, 0, 0, 0, carrier.CauseNone, err)
	if a.d != nil {
		a.cancelAttemptsLocked(now)
	}
}

// endingLocked bounds the end phase: lanes whose CLOSE is still unwritten
// at closeBy are killed (their writers return, or are abandoned after
// AbandonWait), and dial attempts still running 2·AbandonWait after their
// cancellation are abandoned (cancelAttemptsLocked), so Done closes within
// about 2 s (C24). It
// also records the adopts still posted but unhandled (quiet): Join and
// AttachOpen refuse once the session ended, so that count only falls.
func (a *actor) endingLocked(now time.Time) {
	s := a.s
	a.adoptsLeft = s.ctl.adopting
	if by := s.ctl.closeBy; now.Before(by) {
		a.want(by)
	} else {
		for _, l := range s.lanes {
			if !l.c.CloseSent() {
				l.c.Kill(carrier.CauseLocalClose, "CLOSE not written within the close bound")
			}
		}
	}
	if d := a.d; d != nil && d.running > 0 {
		if now.Before(d.abandonBy) {
			a.want(d.abandonBy)
		} else {
			a.abandonAttemptsLocked()
		}
	}
}

// onShutdownLocked is Session.Shutdown (Runtime.Close, §6.8): a pending
// session answers OPEN_ACK(GOING_AWAY); an opening dialer fails with
// net.ErrClosed; an open session sends RST(AbortGoingAway) and GOAWAY and
// ends locally with net.ErrClosed.
func (a *actor) onShutdownLocked(now time.Time) {
	switch {
	case a.ending:
	case a.s.p.Role == RolePassive && a.s.ctl.state == StatePending:
		a.refusePendingLocked(now, wire.OpenAck{Status: wire.StatusGoingAway}, true)
	case a.d != nil && !a.d.opened:
		a.failOpeningLocked(now, net.ErrClosed)
	default:
		a.terminateLocked(now, net.ErrClosed, &wire.Rst{Code: wire.RstGoingAway, Msg: []byte("going away")}, true)
	}
}

// retiringLocked completes planned retirements (§7.2 step 4): a lane
// switched away from sends CLOSE once everything it carried is
// acknowledged (sBase ≥ retireMark) or at retireAt, whichever is first.
// ACK advances ring nobody, so the acknowledgement is polled every
// PingBusy while a retirement waits.
//
// A packet lane carried nothing that is ever acknowledged (M2-D42): it
// retires 2·srtt after the passive echoed the epoch that removed it — the
// datagrams the passive still had in flight on it arrive meanwhile — or at
// retireAt, whichever comes first. The echo rings the actor (factEcho), so
// nothing is polled.
func (a *actor) retiringLocked(now time.Time) {
	s := a.s
	for _, l := range s.lanes {
		if l.state != LaneRetiring || l.retireCalled {
			continue
		}
		if s.pk != nil {
			a.pktRetiringLocked(now, l)
			continue
		}
		if s.st.sBase >= l.retireMark || !now.Before(l.retireAt) {
			a.retireLaneLocked(l)
			continue
		}
		a.want(l.retireAt)
		a.want(now.Add(s.pingBusy()))
	}
}

// pktRetiringLocked is retiringLocked's rule for lane l of a packet session
// (M2-D42): retireEchoAt is stamped when the dialer's echoed epoch reaches
// the one that removed l; l retires at retireEchoAt + 2·srtt or at
// retireAt, whichever is first.
func (a *actor) pktRetiringLocked(now time.Time, l *lane) {
	if l.retireEchoAt.IsZero() && !sched.EpochNewer(l.retireEpoch, a.s.ctl.echoed) {
		l.retireEchoAt = now
	}
	due := l.retireAt
	if !l.retireEchoAt.IsZero() {
		if t := l.retireEchoAt.Add(2 * l.port.SRTT()); t.Before(due) {
			due = t
		}
	}
	if !now.Before(due) {
		a.retireLaneLocked(l)
		return
	}
	a.want(due)
}

// readvLocked keeps the window re-advertisement deadline (D18, W6): while
// readvertiseLocked reports a last advertised window below 64 KiB, it runs
// every Params.WindowReadvertise.
func (a *actor) readvLocked(now time.Time) {
	if a.readvAt.IsZero() || !now.Before(a.readvAt) {
		if a.s.readvertiseLocked(now) {
			a.readvAt = now.Add(orDefault(a.s.p.WindowReadvertise, defReadvertise))
		} else {
			a.readvAt = time.Time{}
		}
	}
	a.want(a.readvAt)
}
