package l4

import (
	"bytes"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestPortForwardFirstReplyAgeOnTrunk (A-11 on a MUX trunk, M6 w0's
// amendment 4; the package doc's "The first datagram" paragraph): on a
// datagram carrier that a Peer's sessions already share, the passive
// places a new flow's replies only once the dialer's first frame behind
// its OPEN_ACK has arrived, about one round trip later, and its session
// queue ages them by the passive's Packet.MaxAge meanwhile. The target
// answers at once a first datagram that rode the OPEN. At a 40-ms round
// trip the answer crosses at the first try; at 150 ms with the default
// MaxAge (100 ms) the passive drops it (DropAge) and only the client's
// resend is answered; with the passive's MaxAge raised to 500 ms it
// crosses at the first try again. The flow that opened the carrier is not
// held: its first answer crosses at 150 ms with the default MaxAge.
func TestPortForwardFirstReplyAgeOnTrunk(t *testing.T) {
	for _, r := range []struct {
		name    string
		oneWay  time.Duration
		maxAge  time.Duration // the passive's Packet.MaxAge (0: the default)
		dropped bool
	}{
		{"rtt 40ms", 20 * time.Millisecond, 0, false},
		{"rtt 150ms", 75 * time.Millisecond, 0, true},
		{"rtt 150ms, MaxAge 500ms", 75 * time.Millisecond, 500 * time.Millisecond, false},
	} {
		t.Run(r.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var o pwOpts
				o.pf.pcfg.Packet.MaxAge = r.maxAge
				w := newPWWorld(t, o)
				for _, l := range w.links {
					l.SetDelay(rendrtest.Up, r.oneWay, 0)
					l.SetDelay(rendrtest.Down, r.oneWay, 0)
				}
				rtt := 2 * r.oneWay
				w.serve()

				// The flow that dials the carrier: its first answer crosses.
				cold := w.client()
				b0 := pwTagged(100, 0xa0, 0)
				pfSend(t, cold, b0)
				if got, ok, err := pwRecvWithin(cold, time.Second); err != nil || !ok || !bytes.Equal(got, b0) {
					t.Fatalf("the first flow's first answer: ok %v, err %v", ok, err)
				}
				time.Sleep(time.Second)

				// A second flow on the same carrier, its first datagram
				// riding the OPEN.
				c := w.client()
				b1 := pwTagged(100, 0xa1, 0)
				start := time.Now()
				pfSend(t, c, b1)
				got, ok, err := pwRecvWithin(c, time.Second)
				if err != nil {
					t.Fatalf("client read: %v", err)
				}
				took := time.Since(start)
				fl := w.pas.flowOf(0xa1)
				if fl == nil {
					t.Fatal("the second flow's first datagram never reached the target")
				}
				if n := fl.rxCount.Load(); n != 1 {
					t.Fatalf("the target received %d datagrams of the second flow, want its first one", n)
				}
				if st := pwStatus(w.pf); st.FirstInOpen != 2 || st.Opened != 2 {
					t.Fatalf("both first datagrams must ride their OPENs: %s", pwDescribe(st))
				}
				if s := w.links[0].Stats(); s.Dials != 1 || s.Carriers != 1 {
					t.Fatalf("link dials %d, carriers %d: the two flows must share one carrier", s.Dials, s.Carriers)
				}
				ctr := fl.pc.Status().Packet
				t.Logf("rtt %v, MaxAge %v: answer after %v (delivered %v); passive DropAge %d, DropNoPath %d", rtt, r.maxAge, took, ok, ctr.DropAge, ctr.DropNoPath)
				if !r.dropped {
					if !ok || !bytes.Equal(got, b1) {
						t.Fatalf("the second flow's first answer was not delivered within 1 s (passive DropAge %d, DropNoPath %d)", ctr.DropAge, ctr.DropNoPath)
					}
					if took < 2*rtt {
						t.Fatalf("the answer took %v, want the held view's extra round trip (≥ %v)", took, 2*rtt)
					}
					if ctr.DropAge != 0 || ctr.DropNoPath != 0 {
						t.Fatalf("passive DropAge %d, DropNoPath %d, want 0", ctr.DropAge, ctr.DropNoPath)
					}
					return
				}
				if ok {
					t.Fatalf("the second flow's first answer was delivered after %v, want it aged out on the passive", took)
				}
				if ctr.DropAge != 1 || ctr.DropNoPath != 0 {
					t.Fatalf("passive DropAge %d, DropNoPath %d, want the one answer counted DropAge", ctr.DropAge, ctr.DropNoPath)
				}
				// The flow lives: the client's resend is answered at once.
				b2 := pwTagged(100, 0xa1, 1)
				pfSend(t, c, b2)
				pfExpect(t, c, b2)
				if st := pwStatus(w.pf); st.Flows != 2 || st.Opened != 2 {
					t.Fatalf("after the resend: %s", pwDescribe(st))
				}
			})
		})
	}
}
