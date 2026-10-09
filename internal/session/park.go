package session

import (
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
)

// Runtime-level timers: the parked actor (M3 design §A8; M3-D42 … M3-D44,
// PA-34). A session's actor runs on demand: after actorLinger without a
// step that did work (R1-22) it arms one reusable runtime timer for its
// earliest deadline and its goroutine returns; every mailbox ring (R1-7),
// that timer and a carrier's or view's Done restart it through one atomic
// state word, actor.state. Only the goroutine that moved the word from
// parked to running runs steps, so one step runs at a time per session
// (L09); a kick during a step sets again, which makes that goroutine run
// one more step.
//
// Every wakeup reaches a parked actor as a kick: the doorbell's ring kicks
// the actor published in mailbox.actor (post, Ring, ringActor, health
// notifications); the timer's callback is the doorbell's ring; and before
// it parks the actor registers the doorbell with Conn.OnDone on every
// carrier whose Done the running loop would select on (the carriers in
// gone, and an ended lane whose reader its death step awaits), so their
// joins ring it too (M3-D43). Every kick also leaves the doorbell token
// first, so the running loop needs no other channel.

// Actor states (actor.state). The zero value is parked: Start publishes
// the actor in mailbox.actor and then kicks it once.
const (
	actorParked  uint32 = 0 // no goroutine; the timer or a kick starts one
	actorRunning uint32 = 1 // a goroutine runs steps
	actorAgain   uint32 = 2 // running, and a kick arrived since the current step began: one more step
	actorExited  uint32 = 3 // the session ended (Session.Done): kicks do nothing
)

// defActorLinger is how long an actor stays running without a step that
// did work before it parks (Params.ActorLinger; testhooks.ActorLinger).
const defActorLinger = time.Second

// kick makes the actor run a step soon: it starts the actor's goroutine
// when it is parked and asks a running one for one more step. It never
// blocks and takes no lock, so it may be called from any goroutine with
// any lock held (mailbox.ring calls it). A kick of an exited actor does
// nothing.
func (a *actor) kick() {
	for {
		switch a.state.Load() {
		case actorParked:
			if a.state.CompareAndSwap(actorParked, actorRunning) {
				if g := a.s.p.Actors; g != nil {
					g.Add(1)
				}
				go a.run()
				return
			}
		case actorRunning:
			if a.state.CompareAndSwap(actorRunning, actorAgain) {
				return
			}
		default: // again: a step is already owed; exited: the session ended
			return
		}
	}
}

// linger returns how long the actor stays running after its last step
// that did work (Params.ActorLinger, 1 s by default).
func (a *actor) linger() time.Duration {
	return orDefault(a.s.p.ActorLinger, defActorLinger)
}

// begin runs at the start of every goroutine of the actor. The first one
// (Start's kick) makes the reusable timer, counts the session live
// (testhooks.LiveSessions, R1-24) and starts the linger clock; a later one
// was kicked out of parked.
func (a *actor) begin() {
	if a.timer == nil {
		// The timer's callback rings the doorbell: the bell token wakes a
		// running loop, the kick a parked actor. Made once: parking and
		// re-arming allocate nothing (TestActorParkZeroAllocs).
		a.timer = time.AfterFunc(time.Hour, a.s.mb.ring)
		a.timer.Stop()
		a.lastWork = time.Now()
		testhooks.LiveSessions.Add(1)
		return
	}
	testhooks.ParkedSessions.Add(-1)
}

// park tries to park the actor at now: it arms the timer for the step's
// earliest deadline (or stops it), registers the doorbell on every
// carrier whose join the loop would otherwise wait for, and moves the
// state word from running to parked. It reports whether the actor parked:
// the goroutine must then return at once, since a kick may already have
// started its successor. On false a kick arrived since the step began
// (again): the goroutine keeps the actor running and steps again.
func (a *actor) park(now time.Time) bool {
	s := a.s
	if a.wakeAt.IsZero() {
		a.timer.Stop()
	} else {
		a.timer.Reset(max(a.wakeAt.Sub(now), minArm))
	}
	// M3-D43, R1-7: the joins the running loop selects on ring instead.
	// OnDone rings at once when Done already closed, so a join between the
	// step's look and this registration is not lost: it leaves again.
	for _, c := range a.gone {
		c.OnDone(&s.mb)
	}
	if a.readerWait != nil {
		for _, l := range s.lanes { // the actor is the only writer of s.lanes
			if laneEnded(l) {
				l.c.OnDone(&s.mb) // an ended lane whose reader the death step awaits
			}
		}
	}
	if h := s.env.Hooks; h != nil && h.AtPark != nil {
		h.AtPark(s.id)
	}
	testhooks.ParkedSessions.Add(1)
	g := s.p.Actors
	if g != nil {
		g.Add(-1)
	}
	if a.state.CompareAndSwap(actorRunning, actorParked) {
		return true
	}
	testhooks.ParkedSessions.Add(-1)
	if g != nil {
		g.Add(1)
	}
	return false
}
