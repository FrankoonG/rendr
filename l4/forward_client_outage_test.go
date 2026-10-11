package l4

import (
	"context"
	"errors"
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestForwardClientResetDuringOutage (§A8.3, WP13 B-2): the documented
// M4 behaviour of a reset decided on the dialer while no carrier is alive.
// The ingress client resets while the only link is killed and refused; the
// ingress Forward's Abort(AbortReset) cancels the dialer's attempts, so its
// RST reaches no lane even though the link is back 10 ms later. The
// passive retains until PassiveRetain and ends with ErrNoPath (never
// io.EOF, invariant 1), and only then does the egress Forward reset the
// target: no later than PassiveRetain + 1 s after the abort. Nothing is
// left behind.
func TestForwardClientResetDuringOutage(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		live0, parked0 := testhooks.LiveSessions.Load(), testhooks.ParkedSessions.Load()
		ov := kitOverrides(worldOpts{})
		retain := ov.NoPathGrace + ov.PingIdle + ov.DeadMax + ov.RetainSlack // the kit's PassiveRetain
		w := newWorld(t, worldOpts{})
		tg := rendrtest.NewTarget(rendrtest.TargetEcho(), 0)
		d, p := w.open(rendr.DialOptions{})
		tconn, err := tg.Dial(context.Background(), kitTarget)
		if err != nil {
			t.Fatal(err)
		}
		spy := fullSpy{&spyConn{Conn: tconn}}
		cli, srv := rendrtest.TargetPipe(0)
		in := forwardAsync(context.Background(), d, srv)
		out := forwardAsync(context.Background(), p, spy)

		// The chain works end to end before the outage.
		if err := writePRNG(cli, 1, 4<<10); err != nil {
			t.Fatalf("client Write: %v", err)
		}
		if _, err := io.ReadFull(cli, make([]byte, 4<<10)); err != nil {
			t.Fatalf("echo: %v", err)
		}

		// The outage: the only link is refused and its carrier killed.
		w.links[0].SetRefuse(true)
		if n := w.links[0].Kill(); n == 0 {
			t.Fatal("stimulus: Kill found no carrier")
		}
		synctest.Wait()
		for _, c := range []*rendr.Conn{d, p} {
			for _, cs := range c.Status().Carriers {
				if cs.State != rendr.CarrierDead {
					t.Fatalf("stimulus: session %v still has carrier %+v during the outage", c.ID(), cs)
				}
			}
		}

		// The client resets during the outage; the link is back 10 ms later.
		if err := cli.SetLinger(0); err != nil {
			t.Fatal(err)
		}
		cli.Close()
		abortAt := time.Now()
		r := <-in
		if !isReset(r.LocalErr) || r.Clean {
			t.Fatalf("ingress Forward: %+v, want the client's reset as LocalErr", r)
		}
		time.Sleep(10 * time.Millisecond)
		w.links[0].SetRefuse(false)

		var eg ForwardResult
		select {
		case eg = <-out:
		case <-time.After(retain + time.Minute):
			t.Fatalf("the egress Forward did not end within %v of the abort: %+v", retain+time.Minute, p.Status())
		}
		if eg.Clean || errors.Is(eg.SessionErr, io.EOF) || !errors.Is(eg.SessionErr, rendr.ErrNoPath) {
			t.Fatalf("egress Forward: %+v, want ErrNoPath (the RST reaches no lane during the outage), never io.EOF", eg)
		}
		synctest.Wait() // the target notices the reset and closes
		_, linger0, closes, _ := spy.snapshot()
		spy.mu.Lock()
		resetAfter := spy.closedAt.Sub(abortAt)
		spy.mu.Unlock()
		if linger0 == 0 || closes != 1 || resetAfter > retain+time.Second {
			t.Fatalf("target reset %v after the abort (linger0 %d, closes %d), want a reset within PassiveRetain (%v) + 1 s",
				resetAfter, linger0, closes, retain)
		}
		if c := tg.Counts().Conns[0]; !c.RSTIn || c.FINIn || c.Open {
			t.Fatalf("target connection %+v: want a reset, no FIN", c)
		}
		t.Logf("target reset %v after the dialer's abort (PassiveRetain %v)", resetAfter, retain)

		// No leak: both sessions end and nothing is left after shutdown.
		waitDone(t, d, time.Minute)
		waitDone(t, p, time.Minute)
		tg.Close()
		w.shutdown()
		for i, rt := range []*rendr.Runtime{w.d, w.p} {
			st := rt.Status()
			sc := st.Sessions
			if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || st.Handshakes != 0 || st.Sessionless != 0 || st.Actors != 0 ||
				st.BufferedBytes != 0 || st.Abandoned != 0 {
				t.Errorf("Runtime %d: state left after shutdown: %+v", i, st)
			}
		}
		if l, pk := testhooks.LiveSessions.Load()-live0, testhooks.ParkedSessions.Load()-parked0; l != 0 || pk != 0 {
			t.Errorf("session registry after shutdown: %+d live, %+d parked", l, pk)
		}
	})
}
