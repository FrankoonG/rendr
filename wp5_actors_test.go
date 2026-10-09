package rendr

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
)

// TestRuntimeActorsGauge (M3-D42, M3-D44, M3-D50; WP5): the Runtime hands
// every session its running-actor gauge and the testhooks ActorLinger.
// Status.Actors counts both ends' actors while the session opens; with
// ActorLinger 50 ms both park within it: Status.Actors is 0 on both
// Runtimes and testhooks.ParkedSessions counts the two; data still flows;
// once the sessions ended (Close restarts each parked actor for its end
// phase), nothing is counted, no session is live and none is parked.
func TestRuntimeActorsGauge(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const linger = 50 * time.Millisecond
		live0, parked0 := testhooks.LiveSessions.Load(), testhooks.ParkedSessions.Load()
		e := e2eNew(t, Config{}, Config{}, &testhooks.Overrides{ActorLinger: linger}, ListenConfig{}, "a")
		dc, pc := e2eOpen(t, e.peer(), e.ln, DialOptions{})
		synctest.Wait()
		if d, p := e.d.Status().Actors, e.p.Status().Actors; d != 1 || p != 1 {
			t.Fatalf("stimulus: Status.Actors %d and %d right after the open, want 1 and 1", d, p)
		}
		if n := testhooks.LiveSessions.Load() - live0; n != 2 {
			t.Fatalf("LiveSessions grew by %d, want 2", n)
		}
		time.Sleep(linger + 10*time.Millisecond)
		synctest.Wait()
		if d, p := e.d.Status().Actors, e.p.Status().Actors; d != 0 || p != 0 {
			t.Fatalf("Status.Actors %d and %d after the linger %v, want 0 and 0 (the override reached the sessions)", d, p, linger)
		}
		if n := testhooks.ParkedSessions.Load() - parked0; n != 2 {
			t.Fatalf("ParkedSessions grew by %d after the linger, want 2", n)
		}
		if _, err := dc.Write([]byte("wake")); err != nil {
			t.Fatalf("Write: %v", err)
		}
		var b [4]byte
		if _, err := pc.Read(b[:]); err != nil || string(b[:]) != "wake" {
			t.Fatalf("Read: %q, %v", b, err)
		}
		dc.Close()
		pc.Close()
		e2eDone(t, dc, 10*time.Second)
		e2eDone(t, pc, 10*time.Second)
		if d, p := e.d.Status().Actors, e.p.Status().Actors; d != 0 || p != 0 {
			t.Fatalf("Status.Actors %d and %d after the sessions ended, want 0 and 0", d, p)
		}
		if n := testhooks.LiveSessions.Load() - live0; n != 0 {
			t.Fatalf("%d sessions still live after both ended", n)
		}
		if n := testhooks.ParkedSessions.Load() - parked0; n != 0 {
			t.Fatalf("ParkedSessions %+d after both sessions ended, want 0 (a restart gives its count back)", n)
		}
		e.close()
	})
}
