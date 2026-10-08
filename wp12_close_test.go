package rendr

import (
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// wp12ClosePC records the Close calls of a FromPacketConn socket.
type wp12ClosePC struct {
	net.PacketConn
	closes atomic.Int32
}

func (c *wp12ClosePC) Close() error {
	c.closes.Add(1)
	return c.PacketConn.Close()
}

// TestRuntimeCloseAbortsSources_L50_L52 (integration 2, K7): Runtime.Close
// aborts its FromPacketConn sources at the close bound (M2 design §A4.6,
// M2-D58), so a flow that would outlive the join bound cannot keep the
// shared socket open past Close. The passive listens on a DatagramHub
// socket; the path has a 400-ms one-way delay (srtt ≈ 800 ms), and once
// the session runs the dialer → passive direction loses everything, so
// the passive's RST(GoingAway), GOAWAY and CLOSE are never acknowledged.
// Its carrier's retirement then lasts its full 2-s bound after the CLOSE
// (M2-D31), beyond the Runtime's own join bound (the passive's AbandonWait
// is 100 ms: 1 s + 100 ms + 250 ms). Without Source.Abort, Close would
// return with the flow, the source and the socket still alive.
//
// Stimulus: the passive had a live flow when Close began and the hub lost
// the dialer's datagrams meanwhile. Assertions: Close returns within the
// join bound; by then the passive session ended, no flow or source is
// left and the socket was closed exactly once; nothing is left on either
// Runtime and the bubble ends with no goroutine.
func TestRuntimeCloseAbortsSources_L50_L52(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hub := rendrtest.NewDatagramHub(rendrtest.DatagramHubConfig{Name: "hub", Queue: 8192})
		defer hub.Close()
		src := &wp12ClosePC{PacketConn: hub.PacketConn()}
		d := wpTestRuntime(t, Config{}, nil)
		const abandonWait = 100 * time.Millisecond
		p := wpTestRuntime(t, Config{}, &testhooks.Overrides{AbandonWait: abandonWait})
		ln := wpListen(t, p, ListenConfig{Sources: []Source{FromPacketConn(src)}})
		for _, dir := range []rendrtest.Dir{rendrtest.Up, rendrtest.Down} {
			hub.SetDelay(dir, 400*time.Millisecond, 0)
		}
		peer, err := d.NewPeer(PeerConfig{Carriers: []Carrier{DatagramCarrier{Name: "h0", Dial: hub.DialFrom(0), MTU: 1223}}})
		if err != nil {
			t.Fatal(err)
		}
		dc, pc := peOpen(t, peer, ln, DialOptions{})

		// Load both ways for 5 s: every datagram arrives, and the carriers
		// measure the 800-ms round trip.
		done := make(chan *rendrtest.PacketVerifier, 1)
		go func() { done <- peRecv(t, pc, 7, 500, 3*time.Second) }()
		peSend(t, dc, 7, 0, 500, 200)
		peWait(t, 5*time.Second, "an RTT sample of the round trip", func() bool {
			cs := peLive(pc)
			return len(cs) == 1 && cs[0].SRTT > 600*time.Millisecond
		})
		if v := <-done; v.Result().Unique != 500 {
			t.Fatalf("load: %+v", v.Result())
		}

		hub.SetLoss(rendrtest.Up, 1) // the passive never hears from the dialer again
		lost := hub.Stats().Session.Lost
		if st := p.Status().Datagram; st.Flows != 1 || st.Sources != 1 {
			t.Fatalf("stimulus: the passive has %+v, want one live flow of one source", st)
		}
		start := time.Now()
		p.Close()
		took := time.Since(start)
		st := p.Status()
		if bound := time.Second + abandonWait + 250*time.Millisecond; took > bound {
			t.Errorf("Runtime.Close took %v, beyond its join bound %v", took, bound)
		}
		select {
		case <-pc.Done():
		default:
			t.Error("the passive session had not ended when Runtime.Close returned")
		}
		if st.Datagram.Flows != 0 || st.Datagram.Sources != 0 || src.closes.Load() != 1 {
			t.Errorf("after Runtime.Close: %+v, socket closed %d times; want no flow or source and one Close (Source.Abort)",
				st.Datagram, src.closes.Load())
		}
		if hub.Stats().Session.Lost == lost {
			t.Error("stimulus: no datagram of the dialer was lost during Close")
		}
		t.Logf("Runtime.Close took %v; passive carriers %+v", took, pc.Status().Carriers)

		d.Close()
		hub.Close()
		<-dc.Done()
		peNoState(t, d)
		peNoState(t, p)
	})
}
