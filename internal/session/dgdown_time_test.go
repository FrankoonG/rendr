package session

import (
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// TestCarrierDownDatedAtItsDeathStep (M3 design §A5 death fan-out, §A10
// events; DGDOWN, the first full-scale G6 run's packet kill k18): a
// carrier that dies while its session's actor is inside a step — after
// the step read its clock, before its death step (reapDead) — is reported
// by an EventCarrierDown dated at its death step, never before the death.
// The event's Time is when the change was published (rendr.Event); the
// step's clock is read once at its start, so without the fix the death
// step dated the lane's end, its EventCarrierDown and the failed mark at
// that earlier instant. A harness that selects the deaths of a kill by
// time (the gold cases' packet kills: every listed session's CarrierDown
// at or after the close) then finds no record for a session whose actor
// happened to run a step across the kill — G6's lu007, whose actor runs a
// step at every health update of its Peer.
//
// Stimulus: the dialer's actor is held right after the first critical
// section of a step (the seam afterUnlockHook, which runs before
// reapDead) for 10 ms of virtual time, and its only lane's carrier is
// killed there. PASS: exactly one EventCarrierDown of that carrier, dated
// at or after the kill and at or after the death record's time
// (Status DeathAt), with the kill's cause.
func TestCarrierDownDatedAtItsDeathStep(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		l := w.link("l1")
		d, _ := w.open(ModeSelector, nil, l)
		id := acActive(d)
		if id == 0 {
			t.Fatal("premise: the session reports no active carrier")
		}
		synctest.Wait()

		var armed atomic.Bool
		var killAt atomic.Pointer[time.Time]
		uninstall := acAfterUnlock(func(s *Session) {
			if s != d || !armed.CompareAndSwap(true, false) {
				return
			}
			time.Sleep(10 * time.Millisecond) // the step's clock is now 10 ms old
			at := time.Now()
			killAt.Store(&at)
			for _, ln := range s.lanes { // the actor goroutine: the only writer of s.lanes
				if ln.id == id {
					ln.c.Kill(carrier.CauseTransportError, "killed inside a step (test)")
				}
			}
		})
		defer uninstall()
		armed.Store(true)
		d.mb.ring() // a step: its first critical section ends at the seam
		acWaitFor(t, time.Second, "the death step", func() bool { return len(w.a.ev.of(d.id, EventCarrierDown)) > 0 })
		if armed.Load() || killAt.Load() == nil {
			t.Fatal("stimulus: the seam did not hold a step of the dialer's actor")
		}
		k := *killAt.Load()

		downs := w.a.ev.of(d.id, EventCarrierDown)
		if len(downs) != 1 || downs[0].Carrier != id || downs[0].Cause != carrier.CauseTransportError {
			t.Fatalf("CarrierDown events %+v, want one of carrier %d with transport_error", downs, id)
		}
		var row CarrierStatus
		for _, cs := range d.Status().Carriers {
			if cs.ID == id {
				row = cs
			}
		}
		if row.State != LaneDead || row.DeathAt.Before(k) {
			t.Fatalf("premise: carrier %d's row %+v, want dead at or after the kill %v", id, row, k)
		}
		if ev := downs[0]; ev.Time.Before(k) || ev.Time.Before(row.DeathAt) {
			t.Fatalf("CarrierDown dated %v: %v before the kill and %v before the death record (%v); want it at its death step",
				ev.Time, k.Sub(ev.Time), row.DeathAt.Sub(ev.Time), row.DeathAt)
		}
	})
}
