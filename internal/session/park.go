package session

import "time"

// Runtime-level timers: the parked actor (M3 design §A8; M3-D42 … M3-D44,
// PA-34). A session's actor runs on demand: after actorLinger without a
// step that did work (R1-22) it arms one reusable runtime timer for its
// earliest deadline and its goroutine returns; every mailbox ring (R1-7),
// that timer and a carrier's or view's Done restart it through one atomic
// state word, actor.state. Only the goroutine that moved the word from
// parked to running runs steps, so one step runs at a time per session
// (L09); a kick during a step sets again, which makes that goroutine run
// one more step.

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
//
// Until the parked-actor work lands the actor never parks: the first kick,
// Start's, starts the goroutine exactly as M2's Start did, and every later
// kick finds it running.
func (a *actor) kick() {
	for {
		switch a.state.Load() {
		case actorParked:
			if a.state.CompareAndSwap(actorParked, actorRunning) {
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
