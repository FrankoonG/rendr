package l4

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
)

// TestPortForwardUDPCarrierClosed_L52 is the UDP twin of
// TestPortForwardTCP_L02/carrier-closed (M6 design §A8.1, WP7's L52 rule:
// the serve halts only on the bare net.ErrClosed of a closed Peer or
// Runtime, never on errors.Is(err, net.ErrClosed)). A carrier whose Dial
// reports net.ErrClosed (an embedder tunnel that is down) fails a DialUDP
// with ErrNoPath wrapping it while the Peer is open: that flow's failure
// (counted, the source held), never the serve's end; once the carrier
// dials again a new source opens and a held one reopens after its hold.
func TestPortForwardUDPCarrierClosed_L52(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newPWWorld(t, pwOpts{})
		var broken atomic.Bool
		broken.Store(true)
		l := w.links[0]
		peer, err := w.d.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{rendr.DatagramCarrier{
			Name: "down", MTU: pfMTU,
			Dial: func(ctx context.Context) (net.PacketConn, net.Addr, error) {
				if broken.Load() {
					return nil, nil, net.ErrClosed
				}
				return l.Dial(ctx)
			},
		}}})
		if err != nil {
			t.Fatalf("NewPeer: %v", err)
		}
		defer peer.Close()
		w.pf.Peer = peer
		w.serve()

		c1 := w.client()
		pfSend(t, c1, pwTagged(40, 0xC1, 0))
		// The open fails at NoPathGrace (5 s); a halt would end the serve
		// before the failure is counted (the stop discards it).
		var ret error
		waitFor(t, 15*time.Second, "the open failure counted or the serve's end", func() bool {
			select {
			case ret = <-w.served:
				w.served = nil
				return true
			default:
				return pwStatus(w.pf).Failed == 1
			}
		})
		synctest.Wait()
		if w.served == nil {
			t.Fatalf("ServeUDP returned %v with the Peer open: a carrier's net.ErrClosed ended the serve", ret)
		}
		select {
		case err := <-w.served:
			w.served = nil
			t.Fatalf("ServeUDP returned %v with the Peer open: a carrier's net.ErrClosed ended the serve", err)
		default:
		}
		st := pwStatus(w.pf)
		if !errors.Is(st.LastErr, rendr.ErrNoPath) || !errors.Is(st.LastErr, net.ErrClosed) || st.Opened != 0 {
			t.Fatalf("status %s: want one failure, LastErr ErrNoPath wrapping the carrier's net.ErrClosed, no flow opened", pwDescribe(st))
		}
		if n, by := pwEntries(w.pf); n != 1 || by[FlowHeld] != 1 {
			t.Fatalf("table %d entries %v: want the failed source held", n, by)
		}

		broken.Store(false)
		c2 := w.client()
		d2 := pwTagged(40, 0xC2, 1)
		pfSend(t, c2, d2)
		pfExpect(t, c2, d2) // a new source opens and forwards

		time.Sleep(ingressHold) // c1's hold ends
		d1 := pwTagged(40, 0xC1, 2)
		pfSend(t, c1, d1)
		pfExpect(t, c1, d1)
		if st := pwStatus(w.pf); st.Opened != 2 || st.Failed != 1 {
			t.Fatalf("status %s: want 2 flows opened after the one failure", pwDescribe(st))
		}
		if err := w.stop(); !errors.Is(err, context.Canceled) {
			t.Fatalf("ServeUDP = %v, want context.Canceled", err)
		}
	})
}
