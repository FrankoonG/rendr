package rendr

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestPendingVerdictUnplacedAtCloseBy_L48 (m3 BACKLOG follow-up, fixed at
// I3 in carrier abandonLocked): the application rejects a session pending
// on a view of a live MUX trunk while the trunk's writer is held (the
// AfterViewFill gate) past the session's close bound, so the session's
// end procedure Kills the view with its REJECTED unplaced. The carrier's
// fallback refusal (abandonLocked) must be a code the dialer retries —
// never CAPACITY CodeBacklog, which says the backlog is full and is
// terminal — so the Dial retries and gets the verdict from the tombstone.
func TestPendingVerdictUnplacedAtCloseBy_L48(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := newBKGate()
		ovD, ovP := bkOverrides(g)
		e := &e2ePair{t: t, d: wpTestRuntime(t, Config{}, ovD), p: wpTestRuntime(t, Config{}, ovP)}
		e.ln = wpListen(t, e.p, ListenConfig{})
		l := rendrtest.NewLink(rendrtest.LinkConfig{Name: "a", Accept: e.ln.Handle})
		t.Cleanup(l.Close)
		p := e.mxPeer(e2eCarrier(l))
		dc, pc := e2eOpen(t, p, e.ln, DialOptions{})
		g.armed.Store(true)
		res := e2eDialAsync(context.Background(), p, DialOptions{})
		select {
		case <-g.fired:
		case <-time.After(5 * time.Second):
			t.Fatal("the passive writer never called the pending view's Fill")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pend, err := e.ln.Accept(ctx)
		if err != nil {
			t.Fatalf("Accept: %v", err)
		}
		if err := pend.Reject(4242, "rejected; the writer is held past closeBy"); err != nil {
			t.Fatalf("Reject: %v", err)
		}
		time.Sleep(1500 * time.Millisecond) // past closeBy = min(1 s, DeadMax): the view is killed
		close(g.release)
		var r dialResult
		select {
		case r = <-res:
		case <-time.After(30 * time.Second):
			t.Fatal("Dial did not return")
		}
		if r.err == nil {
			r.c.Close()
		}
		bkWantReject(t, r.err, 4242)
		dc.Close()
		pc.Close()
	})
}
