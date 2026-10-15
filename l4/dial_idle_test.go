package l4

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
)

// TestDialEarlyReturnUnusedIdle (M4-D41, plan:277; K21 candidate 1): a
// Conn from Dial with EarlyReturn that the application never reads, writes
// or closes (a leaked Conn) ends with ErrIdleTimeout at DefaultIdleTimeout
// after Dial, not earlier; it never dialled a carrier, the Server never saw
// it, and the dialer Runtime holds no session afterwards.
func TestDialEarlyReturnUnusedIdle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newSrvWorld(t, srvOpts{})
		s := &Server{}
		sv := serve(w, s)
		c, err := Dial(context.Background(), w.peer, kitTarget, rendr.DialOptions{EarlyReturn: true})
		if err != nil {
			t.Fatalf("Dial with EarlyReturn: %v", err)
		}
		dialed := time.Now()
		time.Sleep(DefaultIdleTimeout - time.Second)
		select {
		case <-c.Done():
			t.Fatalf("the unused session ended %v after Dial, before DefaultIdleTimeout: %v", time.Since(dialed), c.Status().Err)
		default:
		}
		waitDone(t, c, 2*time.Second)
		if el := time.Since(dialed); el < DefaultIdleTimeout || el > DefaultIdleTimeout+5*time.Millisecond {
			t.Fatalf("the unused session ended %v after Dial, want DefaultIdleTimeout (%v)", el, DefaultIdleTimeout)
		}
		if err := c.Status().Err; !errors.Is(err, rendr.ErrIdleTimeout) {
			t.Fatalf("end %v, want ErrIdleTimeout", err)
		}
		if n := w.links[0].Stats().Dials; n != 0 {
			t.Fatalf("%d carrier dials for an unused session, want none", n)
		}
		if st := s.Status(); st.Confirmed+st.Rejected+st.Lost != 0 || st.Dialing != 0 {
			t.Fatalf("the Server saw the unused session: %+v", st)
		}
		if st := w.d.Status(); st.Sessions != (rendr.SessionCounts{}) {
			t.Fatalf("dialer sessions after the idle end: %+v", st.Sessions)
		}
		sv.stop(t)
		w.shutdown()
	})
}
