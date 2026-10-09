package rendrtest

import (
	"context"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
)

// TestAssertNoLeakSeesParkedSession_E2E (M3 design Revision 1, R1-24, the
// end-to-end row with WP5's real parked actors): one stream session between
// two Runtimes over a Link, with ActorLinger 50 ms. Once both actors parked
// (Status.Actors 0 on both Runtimes), the leak check taken before the
// session existed fails and its report names both live sessions as parked;
// after both Runtimes closed, a check from the same baseline passes: every
// parked actor was restarted for its end phase and exited, so the registry
// is back at its baseline.
func TestAssertNoLeakSeesParkedSession_E2E(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const linger = 50 * time.Millisecond
		lc := leakCheck{wait: 2 * time.Second}
		fLeak, fClean := &fakeTB{TB: t}, &fakeTB{TB: t}
		checkLeak, checkClean := lc.assert(fLeak), lc.assert(fClean)
		parked0 := testhooks.ParkedSessions.Load()

		ov := &testhooks.Overrides{ActorLinger: linger}
		var rts []*rendr.Runtime
		for range 2 {
			v, err := testhooks.NewRuntime(rendr.Config{}, ov)
			if err != nil {
				t.Fatalf("testhooks.NewRuntime: %v", err)
			}
			rts = append(rts, v.(*rendr.Runtime))
		}
		d, p := rts[0], rts[1]
		ln, err := p.Listen(rendr.ListenConfig{})
		if err != nil {
			t.Fatalf("Listen: %v", err)
		}
		link := NewLink(LinkConfig{Name: "a", Accept: ln.Handle})
		peer, err := d.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{rendr.StreamCarrier{Name: "a", Dial: link.Dial}}})
		if err != nil {
			t.Fatalf("NewPeer: %v", err)
		}
		dialed := make(chan error, 1)
		go func() {
			_, err := peer.Dial(context.Background(), rendr.DialOptions{})
			dialed <- err
		}()
		pend, err := ln.Accept(context.Background())
		if err != nil {
			t.Fatalf("Accept: %v", err)
		}
		if _, err := pend.Confirm(); err != nil {
			t.Fatalf("Confirm: %v", err)
		}
		if err := <-dialed; err != nil {
			t.Fatalf("Dial: %v", err)
		}
		time.Sleep(linger + 10*time.Millisecond)
		synctest.Wait()
		if a, b := d.Status().Actors, p.Status().Actors; a != 0 || b != 0 {
			t.Fatalf("stimulus: Status.Actors %d and %d after the linger, want both parked", a, b)
		}
		if n := testhooks.ParkedSessions.Load() - parked0; n != 2 {
			t.Fatalf("stimulus: ParkedSessions grew by %d, want 2", n)
		}

		checkLeak()
		msg := fLeak.failures()
		if !strings.Contains(msg, "leak after") || !strings.Contains(msg, "2 live session(s) (2 parked)") {
			t.Fatalf("the check missed or misreported the two parked sessions: %q", msg)
		}

		peer.Close()
		d.Close()
		p.Close()
		link.Close()
		checkClean()
		if msg := fClean.failures(); msg != "" {
			t.Fatalf("the check failed after both Runtimes closed: %q", msg)
		}
	})
}
