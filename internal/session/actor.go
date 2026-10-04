package session

import (
	"math/rand/v2"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The session actor (design §3.4, L09): one goroutine per session that
// exclusively owns every control decision — lane membership, roles and
// routing (lane.data, ctl.active), the selector quality policy and the
// failover race, bond membership and rescue, SCHED publication and
// application, the redial cadence of every factory slot, no-path episodes,
// termination, migration counting and the status snapshot. It is woken by
// its mailbox (commands that carry ownership, and a coalescing doorbell for
// facts that live in objects) and by one timer for the earliest deadline.
//
// Every step drains the mailbox, then reconciles the facts it re-reads from
// the objects it holds (carrier death records, peer CLOSE/GOAWAY, stream
// facts, the health snapshot), then acts on deadlines. A fact of an object
// the actor no longer holds is never read, so a stale incarnation can never
// affect its successor (L21). Every change of routing is made under the
// session lock together with the publication of the status snapshot, so
// the reported routing always equals the real one (L27); events and
// Registry calls follow after the lock is released.

const (
	// maxDeadLanes is how many dead lanes Status keeps (design §10.1).
	maxDeadLanes = 8
	// closeBound caps the end-procedure Kill bound min(1 s, DeadMax) (C24).
	closeBound = time.Second
	// minArm is the shortest timer the actor arms: a deadline that is
	// already due is acted upon in the step that finds it, so a shorter
	// one would only spin.
	minArm = time.Millisecond

	defDeadMax       = 4 * time.Second
	defAbandonWait   = time.Second
	defJoinStagger   = time.Second
	defRetireGrace   = 2 * time.Second
	defLinger        = 30 * time.Second
	defAcceptTimeout = 10 * time.Second
	defRescueMin     = 300 * time.Millisecond
	defReadvertise   = 200 * time.Millisecond
	defBackoffMax    = 4 * time.Second
	defGrace         = 15 * time.Second
	defMaxCarriers   = 6
	minResend        = 50 * time.Millisecond
	maxResend        = time.Second
)

// actor is the state of one session's actor goroutine. Only that
// goroutine touches it (the dialer's shared fields say otherwise).
type actor struct {
	s *Session

	timer  *time.Timer
	wakeAt time.Time // earliest deadline collected by want during a step
	cmds   []command // drain buffer
	events []Event   // emitted after the step released the lock
	later  []func()  // Registry, health and reply calls made after the lock is released
	dirty  bool      // control state changed: publish before unlocking

	gen  uint32          // passive: lanes attached so far (lane.gen = attach order)
	gone []*carrier.Conn // carriers of removed lanes whose Done has not closed yet (joined at exit)
	dead []laneSnap      // the last maxDeadLanes dead lanes, oldest first (Status)

	ending   bool    // the end procedure ran (ctl.state == StateEnded)
	endErr   error   // the end error
	verdict  Verdict // what a tombstone answers (passive) once ending
	opened   bool    // the session reached StateOpen (events, verdict)
	decided  bool    // passive: a verdict ran while pending (Confirm, Reject, refusal, timeout, withdrawal)
	lingerOn bool    // Registry.Lingering(on) was reported
	orphanOn bool    // Registry.Orphaned(on) was reported

	acceptBy  time.Time // passive pending: the AcceptTimeout deadline
	episodeBy time.Time // the current no-path episode's expiry
	readvAt   time.Time // window re-advertisement deadline (D18, W6)
	rescueAt  time.Time // bond rescue check (W7)
	resendAt  time.Time // SCHED resend (D6)
	resendIdx int       // rotation position of the SCHED resend

	// Selector routing loss on the dialer (§7.3, §7.6): the active lane was
	// lost without a fallback; the race winner is counted with this cause
	// when it is published.
	lossSet   bool
	lossCause wire.SchedCause
	lossFrom  uint32
	lossEv    carrier.Cause
	// deathOwed (bond, both sides): a member died with requeued spans and
	// no member was left; the next attach counts the death migration.
	deathOwed bool
	// named (passive selector): the lane the last applied SCHED (or the
	// epoch-0 choice) made the sender; migrations count against it (§7.6).
	named uint32

	d *dialer // dialer only
}

// newActor returns the actor of s; run starts it.
func newActor(s *Session) *actor {
	return &actor{s: s}
}

// run is the actor goroutine (design §3.4).
func (a *actor) run() {
	s := a.s
	a.timer = time.NewTimer(time.Hour)
	a.timer.Stop()
	for {
		now := time.Now()
		a.wakeAt = time.Time{}
		a.step(now)
		if a.finished() {
			a.exit()
			return
		}
		a.arm(time.Now()) // a hook may have held the step
		var joined <-chan struct{}
		if a.ending {
			joined = a.joinWait()
		}
		select {
		case <-s.mb.bell:
		case <-a.timer.C:
		case <-joined:
		}
	}
}

// step is one actor round: commands in arrival order, then the facts
// re-read from the objects the actor holds, then deadlines (no-path expiry
// after the commands: an attach already queued wins, L18).
func (a *actor) step(now time.Time) {
	s := a.s
	a.cmds = s.mb.drain(a.cmds[:0])
	s.mu.Lock()
	for i, c := range a.cmds {
		a.handleLocked(now, c)
		a.cmds[i] = nil
	}
	a.factsLocked(now)
	a.unlockStep(now)
	now = a.reapDead(now)
	s.mu.Lock()
	a.peerSignalsLocked(now)
	a.actLocked(now)
	a.unlockStep(now)
	a.flush()
}

// unlockStep publishes the status snapshot if the control state changed
// and releases the session lock: every routing change and its report are
// one critical section (L27).
func (a *actor) unlockStep(now time.Time) {
	if a.dirty {
		a.publishLocked(now)
		a.dirty = false
	}
	a.s.mu.Unlock()
}

// handleLocked dispatches one command.
func (a *actor) handleLocked(now time.Time, c command) {
	switch c := c.(type) {
	case *dialResult:
		a.onDialResultLocked(now, c)
	case *adopt:
		a.onAdoptLocked(now, c)
	case *confirm:
		a.onConfirmLocked(now, c)
	case *reject:
		a.onRejectLocked(now, c)
	case *refuse:
		a.onRefuseLocked(now, c)
	case *shutdown:
		a.onShutdownLocked(now)
	case *withdraw:
		a.onWithdrawLocked(now)
	}
}

// factsLocked takes the stream facts and applies the ones that change
// control state directly; the others are conditions actLocked re-reads.
func (a *actor) factsLocked(now time.Time) {
	s := a.s
	f := s.takeFactsLocked()
	if f == 0 || a.ending {
		return
	}
	if f&factEcho != 0 && s.p.Role == RoleDialer && s.ctl.echoed != s.st.echoIn {
		s.ctl.echoed = s.st.echoIn
		a.dirty = true
	}
	if f&factSched != 0 && s.p.Role == RolePassive {
		a.applySchedLocked(now)
	}
	if f&factLaneConfirmed != 0 && s.p.Role == RolePassive {
		a.lanesConfirmedLocked(now)
	}
	if f&factWriteBlocked != 0 && s.p.Role == RoleDialer {
		a.resendAt = now // move an unechoed SCHED off the blocked lane now
	}
	if f&factClose != 0 {
		if s.ctl.state == StateOpen {
			s.ctl.state = StateClosing
			a.dirty = true
		}
		if !a.lingerOn {
			a.lingerOn = true
			a.registry(func(r Registry) { r.Lingering(s, true) })
		}
	}
}

// actLocked runs every deadline and policy decision of a step.
func (a *actor) actLocked(now time.Time) {
	if !a.ending {
		if a.s.p.Role == RolePassive && a.s.ctl.state == StatePending {
			a.pendingLocked(now)
		} else if a.d == nil || a.d.opened {
			a.terminationLocked(now)
		}
	}
	if !a.ending && a.d != nil {
		a.dialActLocked(now)
	}
	if a.ending {
		a.endingLocked(now)
		return
	}
	if a.s.ctl.state == StatePending {
		return
	}
	a.retiringLocked(now)
	a.schedResendLocked(now)
	a.rescueLocked(now)
	a.readvLocked(now)
	a.episodeExpiryLocked(now)
}

// want records a deadline: the timer is armed for the earliest one.
func (a *actor) want(t time.Time) {
	if !t.IsZero() && (a.wakeAt.IsZero() || t.Before(a.wakeAt)) {
		a.wakeAt = t
	}
}

// arm sets the timer for the earliest deadline of the step.
func (a *actor) arm(now time.Time) {
	if a.wakeAt.IsZero() {
		a.timer.Stop()
		return
	}
	a.timer.Reset(max(a.wakeAt.Sub(now), minArm))
}

// flush runs the calls deferred until the session lock was released, then
// emits the step's events in order (design §3.2: never under a lock).
func (a *actor) flush() {
	for i, f := range a.later {
		f()
		a.later[i] = nil
	}
	a.later = a.later[:0]
	if sink := a.s.env.Events; sink != nil {
		for _, ev := range a.events {
			sink.Emit(ev)
		}
	}
	clear(a.events)
	a.events = a.events[:0]
}

// event queues an event (emitted after the lock is released). Events of a
// dialer session that never opened are dropped: the application never saw
// it.
func (a *actor) event(now time.Time, k EventKind, carrierID, from, to uint32, cause carrier.Cause, err error) {
	if a.s.env.Events == nil || (a.d != nil && !a.d.opened) {
		return
	}
	a.events = append(a.events, Event{Kind: k, Session: a.s.id, Carrier: carrierID, From: from, To: to, Cause: cause, Err: err, Time: now})
}

// registry defers a Registry call until the lock is released.
func (a *actor) registry(f func(r Registry)) {
	if r := a.s.env.Registry; r != nil {
		a.later = append(a.later, func() { f(r) })
	}
}

// rand returns U[0,1) jitter (Env.Rand, deterministic under testhooks).
func (a *actor) rand() float64 {
	if r := a.s.env.Rand; r != nil {
		return r()
	}
	return rand.Float64()
}

// finished reports that the actor may exit: the session ended, every lane
// was removed and every carrier joined, and no dial attempt is in flight.
func (a *actor) finished() bool {
	if !a.ending || len(a.s.lanes) > 0 || (a.d != nil && a.d.running > 0) {
		return false
	}
	return a.joinWait() == nil
}

// joinWait prunes the carriers whose Done closed and returns the Done
// channel of the first one still open (nil when all are joined): the loop
// waits on it during the end phase, one at a time.
func (a *actor) joinWait() <-chan struct{} {
	k := 0
	for _, c := range a.gone {
		select {
		case <-c.Done():
		default:
			a.gone[k] = c
			k++
		}
	}
	clear(a.gone[k:])
	a.gone = a.gone[:k]
	if k == 0 {
		return nil
	}
	return a.gone[0].Done()
}

// exit closes the mailbox, cleans up commands posted since the last
// drain (each one exactly once, F9), releases the health subscription and
// hold, and closes Done.
func (a *actor) exit() {
	s := a.s
	for _, c := range s.mb.close() {
		a.discard(c)
	}
	if d := a.d; d != nil {
		if d.unsub != nil {
			d.unsub()
		}
		if d.release != nil {
			d.release()
		}
	}
	a.timer.Stop()
	close(s.done)
}

// discard cleans up a command that arrives after the session ended: dial
// results close their carrier, adopts get the session's verdict, replies
// get the matching error.
func (a *actor) discard(c command) {
	switch c := c.(type) {
	case *dialResult:
		kind := wire.TypeJoin
		if a.d != nil && !a.d.opened {
			kind = wire.TypeOpen
		}
		discardEst(c.est, kind)
	case *adopt:
		a.refuseAdopt(c)
	case *confirm:
		c.reply <- a.pendingErr()
	case *reject:
		c.reply <- a.pendingErr()
	case *refuse:
		c.reply <- false
	}
}

// deadMax, abandonWait and pingBusy read the carrier timing with the
// defaults of a partially filled Timing (tests).
func (a *actor) deadMax() time.Duration {
	if t := a.s.env.Carrier.Timing.DeadMax; t > 0 {
		return t
	}
	return defDeadMax
}

func (a *actor) abandonWait() time.Duration {
	if t := a.s.env.Carrier.Timing.AbandonWait; t > 0 {
		return t
	}
	return defAbandonWait
}

func orDefault(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

func (a *actor) maxCarriers() int {
	if n := a.s.p.MaxCarriers; n > 0 {
		return n
	}
	return defMaxCarriers
}
