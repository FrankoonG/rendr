package l4

import (
	"errors"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestServerUDPEndsOnRuntimeClose: live flows that end because this side's
// Runtime closed count as Stopped at the Server (FlowEnds: "this side's ctx
// or Serve ended"), as the ingress counts them (flowEndCounts), never as
// Other; the dialer's flows see the passive go away (GoingAway).
func TestServerUDPEndsOnRuntimeClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newSUWorld(t, suOpts{})
		ts := newSUTargets(rendrtest.DatagramPipeConfig{})
		s := &Server{UDP: true, Dial: ts.dial}
		sv := suServe(w, s)
		const n = 3
		pcs := make([]*rendr.PacketConn, n)
		for i := range pcs {
			pcs[i] = suDial(t, w, pfTarget, nil)
			suEcho(ts.next(t, time.Minute))
			suRoundTrip(t, pcs[i], pfData(64, byte(i)))
		}
		w.p.Close()
		if err := sv.wait(t, time.Minute); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Serve = %v, want net.ErrClosed", err)
		}
		suUnits(t, s)
		u := s.Status().UDP
		if u.Ended.Stopped != n || u.Ended.Other != 0 || u.Live != 0 {
			t.Fatalf("the Server's flow ends %+v (live %d): want %d Stopped, none Other", u.Ended, u.Live, n)
		}
		for i, pc := range pcs {
			pc.SetReadDeadline(time.Now().Add(time.Minute))
			_, _, err := pc.ReadFrom(make([]byte, 64))
			var ae *rendr.AbortError
			if !errors.As(err, &ae) || ae.Code != rendr.AbortGoingAway {
				t.Errorf("flow %d at the dialer ended %v, want AbortGoingAway", i, err)
			}
			pc.Close()
		}
		w.shutdown()
	})
}
