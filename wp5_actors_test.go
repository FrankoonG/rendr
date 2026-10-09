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
// ActorLinger 50 ms both park within it and Status.Actors is 0 on both
// Runtimes; traffic restarts them; once the sessions ended, nothing is
// counted and no session is live.
func TestRuntimeActorsGauge(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const linger = 50 * time.Millisecond
		live0 := testhooks.LiveSessions.Load()
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
		e.close()
	})
}
