package l4

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// serveOn runs s.Serve on ln with a cancellable ctx.
func serveOn(s *Server, ln *rendr.Listener) *served {
	ctx, cancel := context.WithCancel(context.Background())
	sv := &served{s: s, cancel: cancel, done: make(chan error, 1)}
	go func() {
		err := s.Serve(ctx, ln)
		sv.ended.Store(time.Now().UnixNano())
		sv.done <- err
	}()
	return sv
}

// TestServerSeveralListeners_L48 (Serve's doc; M4-D28, M6-D19; the shape of
// examples/portforward's server, one Listener per address): one Server
// serves two Listeners of the passive Runtime at once, each reached through
// its own datagram link and stream link (and Peers). With MaxFlows 1 and
// MaxConns 1, a flow and a connection through the first Listener take the
// Server's only units: a flow and a connection through the second are
// rejected CodeCapacity at once, without a hook call. Once the first
// Listener's flow and connection ended, the second Listener's are served,
// and the first Listener's newcomers are refused in turn. Status counts the
// sessions of both Listeners together, and every unit is released when
// both Serve calls returned.
func TestServerSeveralListeners_L48(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newSUWorld(t, suOpts{streams: true})
		ln2, err := w.p.Listen(rendr.ListenConfig{AcceptBacklog: 16})
		if err != nil {
			t.Fatalf("Listen (second): %v", err)
		}
		dl := rendrtest.NewDatagramLink(rendrtest.DatagramLinkConfig{Name: "d2", MTU: pfMTU, Accept: ln2.HandlePacket})
		dl.SetDelay(rendrtest.Up, pfOneWay, 0)
		dl.SetDelay(rendrtest.Down, pfOneWay, 0)
		sl := rendrtest.NewLink(rendrtest.LinkConfig{Name: "s2", Accept: ln2.Handle})
		sl.SetDelay(kitOneWay, 0)
		peer2, err := w.d.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{rendr.DatagramCarrier{Name: "d2", MTU: pfMTU, Dial: dl.Dial}}})
		if err != nil {
			t.Fatalf("NewPeer (second, datagram): %v", err)
		}
		speer2, err := w.d.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{rendr.StreamCarrier{Name: "s2", Dial: sl.Dial}}})
		if err != nil {
			t.Fatalf("NewPeer (second, stream): %v", err)
		}

		ts := newSUTargets(rendrtest.DatagramPipeConfig{})
		echo := rendrtest.NewTarget(rendrtest.TargetEcho(), 0)
		hl := newHookLog(suMixedHook(ts, echo.Dial))
		s := &Server{UDP: true, Dial: hl.dial, MaxConns: 1, MaxFlows: 1}
		sv1, sv2 := serveOn(s, w.ln), serveOn(s, ln2)
		ctx := context.Background()

		// The first Listener's flow and connection take both units.
		pc := suDial(t, w, pfTarget, nil)
		e1 := suEcho(ts.next(t, time.Second))
		suRoundTrip(t, pc, pfData(50, 1))
		c, err := Dial(ctx, w.speer, kitTarget, rendr.DialOptions{})
		if err != nil {
			t.Fatalf("Dial through the first Listener: %v", err)
		}
		ping(t, c, 100)
		calls, _, _, _ := hl.snapshot()

		// Through the second Listener both are refused at once.
		start := time.Now()
		if pc2, err := DialUDP(ctx, peer2, pfTarget, nil, rendr.DialOptions{}); pc2 != nil {
			t.Fatalf("DialUDP through the second Listener opened a flow beyond MaxFlows")
		} else {
			wantReject(t, err, CodeCapacity)
		}
		if c2, err := Dial(ctx, speer2, kitTarget, rendr.DialOptions{}); c2 != nil {
			t.Fatalf("Dial through the second Listener opened a connection beyond MaxConns")
		} else {
			wantReject(t, err, CodeCapacity)
		}
		if el := time.Since(start); el > 100*time.Millisecond {
			t.Fatalf("the two refusals took %v, want at once (one round trip each)", el)
		}
		if n, _, _, _ := hl.snapshot(); n != calls {
			t.Fatalf("hook calls %d → %d: the hook was called beyond the bounds", calls, n)
		}
		if d1, d2 := dl.Stats().Dials, sl.Stats().Dials; d1 == 0 || d2 == 0 {
			t.Fatalf("stimulus: the second Listener's links dialled %d datagram and %d stream carriers, want both", d1, d2)
		}

		// The first Listener's sessions end: their units serve the second's.
		pc.Close()
		<-e1
		c.Close()
		waitFor(t, time.Minute, "both units released", func() bool {
			return s.udp.units.Load() == 0 && s.tcp.units.Load() == 0
		})
		pc2, err := DialUDP(ctx, peer2, pfTarget, nil, rendr.DialOptions{})
		if err != nil {
			t.Fatalf("DialUDP through the second Listener after the unit freed: %v", err)
		}
		e2 := suEcho(ts.next(t, time.Second))
		suRoundTrip(t, pc2, pfData(60, 2))
		c2, err := Dial(ctx, speer2, kitTarget, rendr.DialOptions{})
		if err != nil {
			t.Fatalf("Dial through the second Listener after the unit freed: %v", err)
		}
		ping(t, c2, 100)
		r := suRecv(t, suDialAsync(ctx, w, pfTarget, nil, rendr.DialOptions{}), time.Minute)
		wantReject(t, r.err, CodeCapacity)
		_, err = Dial(ctx, w.speer, kitTarget, rendr.DialOptions{})
		wantReject(t, err, CodeCapacity)

		st := s.Status()
		if u := st.UDP; u.Confirmed != 2 || u.Rejected != 2 || u.ByCode[CodeCapacity] != 2 || u.Live != 1 {
			t.Fatalf("UDP status %+v: want both Listeners' flows (2 confirmed, 2 refused CodeCapacity, 1 live)", u)
		}
		if st.Confirmed != 2 || st.Rejected != 2 || st.ByCode[CodeCapacity] != 2 || st.Live != 1 {
			t.Fatalf("TCP status %+v: want both Listeners' connections (2 confirmed, 2 refused CodeCapacity, 1 live)", st)
		}

		pc2.Close()
		<-e2
		c2.Close()
		sv1.stop(t)
		sv2.stop(t)
		waitFor(t, time.Minute, "every unit released", func() bool {
			return s.udp.units.Load() == 0 && s.tcp.units.Load() == 0
		})
		peer2.Close()
		speer2.Close()
		w.shutdown()
		dl.Close()
		sl.Close()
	})
}
