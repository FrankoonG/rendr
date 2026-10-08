package lessons7

import (
	"context"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Flood bounds (M2-D59, R1-21): the hub's flood comes from four source IP
// addresses — host 0's (the victim's own: OPENs only) and three foreign
// ones (OPENs and JOINs) — so at most 4 × 32 OPEN flows and 3 × 32 JOIN
// flows admit at once; the victim's own JOINs (host 0) and the new
// session's OPEN (host 1) take at most two more each. Live flows add the
// victim's two carriers and the new session's one.
const (
	floodPerSource = 32
	floodAdmitMax  = 4*floodPerSource + 3*floodPerSource + 2 + 2
	floodFlowsMax  = floodAdmitMax + 3
)

// TestPacketFlood_L58 (M2 design §A8.3; M2-D59, R1-21, F26): a packet
// session (the victim, dialled from the hub's host 0) runs 200 datagrams/s
// up and 100 down over a DatagramHub while a 4,000-datagram/s flood hits
// the passive socket: random bytes, valid flow headers with bad CRCs, and
// valid OPEN and JOIN first datagrams with random IDs, a quarter of the
// flood from the victim's own source IP address (OPENs). Nobody accepts
// meanwhile, so the flood's OPENs keep that address's OPEN quota full.
//
//   - The victim keeps ≥ 90 % of its rate in both directions.
//   - Its carrier is closed under rendr: the failover JOIN from the
//     victim's own (flooded) address completes within 1 s.
//   - A new DialPacket from another host completes within 1 s (an acceptor
//     confirms it and rejects the flood's pending sessions).
//   - Status.Datagram.Flows and Admitting stay inside the quota bounds;
//     after the flood and Close nothing is left.
//
// Every victim datagram is verified; losses only at the kill.
func TestPacketFlood_L58(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const owd = 5 * time.Millisecond
		w := newWorld(t, worldOpts{hubUp: owd, hubDown: owd, noHubTap: true})
		start := time.Now()
		dc, pc := w.open(w.peer(w.hubCarrier("h0", 0)), rendr.DialOptions{})
		up := startFlow(dc, pc, 1, 5*time.Millisecond)
		down := startFlow(pc, dc, 2, 10*time.Millisecond)

		var mu sync.Mutex
		var maxFlows, maxAdmit, maxBacklog int
		sampleStop, sampled := make(chan struct{}), make(chan struct{})
		var stopOnce sync.Once
		stopSampler := func() {
			stopOnce.Do(func() { close(sampleStop) })
			<-sampled
		}
		t.Cleanup(stopSampler) // also when the test fails early
		go func() {
			defer close(sampled)
			for {
				st := w.p.Status()
				mu.Lock()
				maxFlows, maxAdmit = max(maxFlows, st.Datagram.Flows), max(maxAdmit, st.Datagram.Admitting)
				maxBacklog = max(maxBacklog, st.AcceptBacklog[1])
				mu.Unlock()
				select {
				case <-sampleStop:
					return
				case <-time.After(10 * time.Millisecond):
				}
			}
		}()

		time.Sleep(3 * time.Second)
		base := [2]time.Time{start.Add(time.Second), start.Add(3 * time.Second)}
		before := w.p.Status().Datagram
		floodAt := time.Now()
		stopFlood := w.hub.Flood(4000, rendrtest.FloodMix{Random: 1, BadCRC: 1, Preface: 4, Join: 2})
		time.Sleep(3 * time.Second)

		// The stimulus: the flood arrived and filled the OPEN quotas.
		st := w.p.Status()
		hs := w.hub.Stats()
		if hs.Spoofed < 11000 || st.Datagram.Dropped-before.Dropped < 4000 || st.Datagram.Admitting < floodPerSource || st.AcceptBacklog[1] == 0 {
			t.Fatalf("stimulus: %d flood datagrams delivered, %d dropped, %d admitting flows, packet backlog %d",
				hs.Spoofed, st.Datagram.Dropped-before.Dropped, st.Datagram.Admitting, st.AcceptBacklog[1])
		}
		// The victim's rate under the flood.
		flood := [2]time.Time{floodAt.Add(time.Second), floodAt.Add(3 * time.Second)}
		for _, f := range []*flow{up, down} {
			b, u := f.arrivedIn(base[0], base[1]), f.arrivedIn(flood[0], flood[1])
			if b < 190 || float64(u) < 0.9*float64(b) {
				t.Fatalf("seed %d: %d arrivals in 2 s under the flood against %d before it, want ≥ 90 %%", f.seed, u, b)
			}
		}

		// The failover JOIN from the victim's own (flooded) address.
		old := oneLive(t, "dialer", dc)
		killAt := time.Now()
		w.dconns.last().Close()
		joinTook := waitFor(t, time.Second, "the failover JOIN", func() bool {
			l := liveOf(dc.Status())
			if len(l) != 1 || l[0].ID == old.ID || dc.Status().Rejoins != 1 {
				return false
			}
			c, ok := carrierOf(pc.Status(), l[0].ID)
			return ok && c.State == rendr.CarrierActive
		})
		joinedAt := time.Now()

		// A new session from another host while the flood goes on.
		acc := make(chan *rendr.PacketConn, 1)
		ctx, cancel := context.WithCancel(context.Background())
		var rejected int
		accDone := make(chan struct{})
		go func() {
			defer close(accDone)
			for {
				pp, err := w.ln.AcceptPacket(ctx)
				if err != nil {
					return
				}
				if pp.PeerInstance() != w.d.InstanceID() {
					pp.Reject(1, "flood")
					rejected++
					continue
				}
				c, err := pp.Confirm()
				if err != nil {
					t.Errorf("Confirm: %v", err)
					return
				}
				acc <- c
			}
		}()
		dialAt := time.Now()
		r := <-dial(w.peer(w.hubCarrier("h1", 1)), rendr.DialOptions{})
		if r.err != nil {
			t.Fatalf("the new DialPacket: %v", r.err)
		}
		dialTook := r.at.Sub(dialAt)
		if dialTook > time.Second {
			t.Fatalf("the new DialPacket took %v under the flood, want ≤ 1 s", dialTook)
		}
		npc := <-acc
		burst(t, r.c, npc, 11, 100, "new session up")
		burst(t, npc, r.c, 12, 100, "new session down")
		after := [2]time.Time{time.Now(), time.Now().Add(2 * time.Second)}
		time.Sleep(2 * time.Second)
		for _, f := range []*flow{up, down} {
			b, u := f.arrivedIn(base[0], base[1]), f.arrivedIn(after[0], after[1])
			if float64(u) < 0.9*float64(b) {
				t.Fatalf("seed %d: %d arrivals in 2 s after the failover against %d before the flood", f.seed, u, b)
			}
		}
		stopFlood()
		floodEnd := time.Now()
		cancel()
		<-accDone
		time.Sleep(3 * time.Second) // the flood's flows leave (verdicts end within 2 s)

		stopSampler()
		mu.Lock()
		fl, ad, bl := maxFlows, maxAdmit, maxBacklog
		mu.Unlock()
		if fl > floodFlowsMax || ad > floodAdmitMax || bl > 4*floodPerSource {
			t.Fatalf("bounds: at most %d flows (bound %d), %d admitting (bound %d), packet backlog %d (bound %d)",
				fl, floodFlowsMax, ad, floodAdmitMax, bl, 4*floodPerSource)
		}
		if st := w.p.Status(); st.Datagram.Flows != 2 || st.Datagram.Admitting != 0 || st.AcceptBacklog[1] != 0 || st.Handshakes != 0 {
			t.Fatalf("after the flood: %+v, backlog %v, handshakes %d; want the two sessions' flows only", st.Datagram, st.AcceptBacklog, st.Handshakes)
		}

		// Load and integrity of the victim: losses only at the kill.
		up.halt(t, "up")
		down.halt(t, "down")
		time.Sleep(time.Second)
		endPair(t, dc, pc, up, down)
		kill := [2]time.Time{killAt.Add(-owd), joinedAt.Add(owd)}
		upIn, upOut := up.lostIn(kill)
		downIn, downOut := down.lostIn(kill)
		if len(upOut)+len(downOut) != 0 {
			t.Fatalf("losses away from the kill: up %v, down %v", upOut, downOut)
		}
		r.c.Close()
		npc.Close()
		waitDone(t, 10*time.Second, r.c, npc)
		w.noViolation()
		t.Logf("flood %v: %d datagrams; the victim kept its rate; failover JOIN %v; new DialPacket %v (%d flood sessions rejected); max flows %d, admitting %d, packet backlog %d; victim up %d (%d lost at the kill), down %d (%d lost)",
			floodEnd.Sub(floodAt), w.hub.Stats().Spoofed, joinTook, dialTook, rejected, fl, ad, bl,
			up.accepted.Load(), len(upIn), down.accepted.Load(), len(downIn))
		w.close()
	})
}
