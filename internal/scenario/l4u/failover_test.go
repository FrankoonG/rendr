package l4u

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/l4"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// recoveryBound is G4-pkt's bound (plan:757, F14): after a silent path
// death a selector session's datagrams arrive again within 5 s — DeadMax
// (4 s) for the death, then the failover dial and JOIN (two round trips of
// 20 ms) inside the second left.
const recoveryBound = 5 * time.Second

// manyFlow is one flow of TestL4UManyFlowsFailover_L27: its client, its
// target end, its two ledgers and its rate.
type manyFlow struct {
	i        int
	rate     float64
	size     int
	src      netip.AddrPort
	c        *rendrtest.DatagramConn
	e        *egress // the flow's target end, once its first datagram arrived
	up, down *ledger
	rd       *reader
}

// TestL4UManyFlowsFailover_L27 (gold/G4-l4u's shape at reduced scale,
// §B6.1; L27): 64 UDP flows through one ingress toward one target, over a
// Peer of two DatagramLinks u1 and u2 (selector; frame budget 1,463, so
// MaxPayload 1,438): flow 0 carries 1,000-byte test datagrams at 5,000 per
// second each way, the other 63 carry 200-byte ones at 50 per second each
// way (lane.failBig and lane.failSmall; 200 and 10 under the race
// detector); the target streams its own datagrams to each flow's egress
// source (learn-and-stream). The load starts once every flow is open at
// both ends and one second has passed (steady). After 10 s of steady
// traffic (lane.failWarm) every datagram of the link carrying the flows
// (the active carriers' link, u1) is dropped both ways without an error (a
// blackhole, plan:747) until the end, 10 s later (lane.failObserve).
//
// Stimulus: every flow's active carrier at the drop is on the dropped
// link, the link lost session datagrams, and the dropped carrier dies on
// both ends.
//
// PASS (G4-pkt's criteria on every flow and direction, plan:754–760):
// every flow's datagrams sent after the drop arrive again within
// recoveryBound of it (DeadMax + dial + JOIN); a datagram that was lost
// was sent in [drop − 200 ms, r_f + 200 ms], r_f that flow's first arrival
// in that direction of a datagram sent after the drop, and every other one
// arrived; every datagram arrived intact and once (0 duplicates, 0
// corrupt); the dropped carrier ends with ping_timeout or write_stall on
// both ends (or peer_down after the other end's verdict, PA-86); no flow
// was re-opened (Opened 64, Confirmed 64, 64 target dials: one egress
// source per flow, F79).
func TestL4UManyFlowsFailover_L27(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			flows = 64
			port  = 5000
			slack = 200 * time.Millisecond
		)
		w := newWorld(t, worldOpts{}, linkSpec{name: "u1"}, linkSpec{name: "u2"})
		pf := &l4.PortForward{Peer: w.peer("u1", "u2")}
		in := w.forward(pf, targetAddr(port), hubCfg(0))
		fs := make([]*manyFlow, flows)
		var seeds []uint64
		for i := range fs {
			f := &manyFlow{i: i, rate: lane.failSmall, size: 200, src: clientSrc(i)}
			if i == 0 {
				f.rate, f.size = lane.failBig, 1000
			}
			f.up = newLedger(flowName(i, "client → target"), uint64(2*i+1))
			f.down = newLedger(flowName(i, "target → client"), uint64(2*i+2))
			fs[i] = f
			seeds = append(seeds, f.up.seed)
		}
		var mu sync.Mutex
		w.target(port, func(e *egress) {
			buf := make([]byte, 64<<10)
			var f *manyFlow
			for {
				n, err := e.conn.Read(buf)
				if err != nil {
					return
				}
				if f == nil {
					i := seedOf(buf[:n], seeds)
					if i < 0 {
						t.Errorf("target: a first datagram of no flow (%d bytes) from %v", n, e.src)
						return
					}
					f = fs[i]
					mu.Lock()
					f.e = e
					mu.Unlock()
				}
				f.up.arrive(buf[:n], time.Now())
			}
		})

		for _, f := range fs {
			f.c = in.client(f.src)
			f.rd = startReader(f.c, f.down.arrive)
			if _, err := f.c.Write(f.up.next(nil, f.size, time.Now())); err != nil {
				t.Fatalf("flow %d: the first datagram: %v", f.i, err)
			}
		}
		waitFor(t, 15*time.Second, "every flow open", func() bool {
			mu.Lock()
			defer mu.Unlock()
			for _, f := range fs {
				if f.e == nil {
					return false
				}
			}
			return true
		})
		// Steady before the load (G4-l4u's "once steady"): every flow open
		// at both ends, then one second. A load that starts at the opens —
		// learn-and-stream targets writing as their flows confirm — loses
		// datagrams at the passive while 64 views wait for the trunk's REL
		// window (DropAge; the WP9 report's defect B): this row failed that
		// way in about two runs of three. That rule is guarded by
		// TestL4UFirstReplyAtConfirm_L40 (mux_test.go, merged with the core
		// fix), not here; once it passes, a load-at-open variant of this
		// row may follow.
		waitFor(t, 15*time.Second, "every flow open at both ends", func() bool {
			if w.srv.Status().UDP.Live != flows {
				return false
			}
			open := 0
			for _, fi := range pf.Flows() {
				if fi.State == l4.FlowOpen {
					open++
				}
			}
			return open == flows
		})
		time.Sleep(time.Second)
		start := time.Now()
		drop := start.Add(lane.failWarm)
		until := drop.Add(lane.failObserve)
		var gens []*gen
		for _, f := range fs {
			// The client's datagrams, and the target's toward the flow's
			// egress source (learn-and-stream).
			gens = append(gens, startGen(f.c, f.up, w.quit, f.rate, []int{f.size}, until),
				startGen(f.e.conn, f.down, w.quit, f.rate, []int{f.size}, until))
		}

		sleepUntil(drop.Add(-time.Second))
		victim := w.dlink("u1")
		var ids []rendr.CarrierID
		for _, f := range fs {
			fi, ok := flowOf(pf, f.src)
			a, aok := activeOf(fi.Session)
			if !ok || !aok || a.Name != "u1" {
				t.Fatalf("stimulus: flow %d's active carrier before the drop is %+v (flow found %v): not on the dropped link u1", f.i, a, ok)
			}
			ids = append(ids, a.ID)
		}
		sleepUntil(drop)
		lost0 := victim.Stats().Session.Lost
		for _, d := range bothDirs {
			victim.Blackhole(d, true)
		}
		sleepUntil(until)
		for _, g := range gens {
			g.wait(t, "a generator")
		}
		time.Sleep(time.Second) // the last datagrams arrive
		end := time.Now()
		if victim.Stats().Session.Lost == lost0 {
			t.Fatalf("stimulus: the drop of u1 lost no session datagram")
		}

		dead := map[rendr.CarrierID]bool{}
		for _, id := range ids {
			dead[id] = true
		}
		for id := range dead {
			droppedCause(t, w, pf, fs[0].src, id, drop)
		}
		var worst time.Duration
		for _, f := range fs {
			for _, l := range []*ledger{f.up, f.down} {
				l.integrity(t)
				rf := l.firstArrivalFrom(drop)
				if rf.IsZero() || rf.Sub(drop) > recoveryBound {
					t.Fatalf("%s: the first datagram sent after the drop arrived at %+v of it, want within %v", l.name, rf.Sub(drop), recoveryBound)
				}
				worst = max(worst, rf.Sub(drop))
				l.lossesOutside(t, end, []window{{drop.Add(-slack), rf.Add(slack)}}, start)
				if r := float64(l.arrived()) / float64(l.sentCount()); r < 0.5 {
					t.Fatalf("load: %s delivered %.3f of %d", l.name, r, l.sentCount())
				}
			}
		}
		t.Logf("64 flows: the slowest resumption +%v of the drop (bound %v); flow 0 sent %d each way",
			worst, recoveryBound, fs[0].up.sentCount())
		oneFlow(t, w, pf, port, flows)
		for _, f := range fs {
			fi, ok := flowOf(pf, f.src)
			if a, aok := activeOf(fi.Session); !ok || !aok || a.Name == "u1" {
				t.Fatalf("flow %d after the drop: %+v (found %v), want an active carrier off the dropped link", f.i, a, ok)
			}
		}
		for _, d := range bothDirs {
			victim.Blackhole(d, false)
		}
		w.noViolation()
		w.close()
	})
}

// flowName names one direction of flow i.
func flowName(i int, dir string) string { return "flow " + itoa(i) + " " + dir }

// itoa formats n.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	neg := n < 0
	if neg {
		n = -n
	}
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

// seedOf returns the index of the seed whose test datagram b is (the
// datagram rebuilt from its header for each seed), or −1.
func seedOf(b []byte, seeds []uint64) int {
	if len(b) < rendrtest.PacketHeaderLen {
		return -1
	}
	seq := binary.BigEndian.Uint64(b[0:])
	at := time.Unix(0, int64(binary.BigEndian.Uint64(b[8:])))
	tmp := make([]byte, len(b))
	for i, s := range seeds {
		if bytes.Equal(rendrtest.PacketPayload(tmp, s, seq, len(b), at), b) {
			return i
		}
	}
	return -1
}

// droppedCause requires that carrier id, whose path was dropped at drop,
// ended on both ends with ping_timeout or write_stall (E17) within the
// recovery bound — except that the end whose peer reached its verdict
// first may end it with peer_down after that verdict (PA-86: the first
// end's DOWN crosses on another trunk of the pair). The dialer's view is
// flow src's session; the passive's comes from its events.
func droppedCause(t *testing.T, w *world, pf *l4.PortForward, src netip.AddrPort, id rendr.CarrierID, drop time.Time) {
	t.Helper()
	silent := func(c rendr.Cause) bool { return c == rendr.CausePingTimeout || c == rendr.CauseWriteStall }
	var evs [2]rendr.Event
	for i, l := range []*eventLog{w.dev, w.pev} {
		downs := l.downOf(id)
		if len(downs) == 0 {
			t.Fatalf("%s: no CarrierDown of the dropped carrier %d", side(i), id)
		}
		ev := downs[0]
		for _, d := range downs {
			if d.Time.Before(ev.Time) {
				ev = d
			}
		}
		if ev.Time.Sub(drop) > recoveryBound || ev.Time.Before(drop) {
			t.Fatalf("%s: CarrierDown of %d at %+v of the drop, want within %v", side(i), id, ev.Time.Sub(drop), recoveryBound)
		}
		evs[i] = ev
	}
	for i, ev := range evs {
		o := evs[1-i]
		if !silent(ev.Cause) && !(ev.Cause == rendr.CausePeerDown && silent(o.Cause) && !ev.Time.Before(o.Time)) {
			t.Fatalf("%s: the dropped carrier %d ended with %v, want ping_timeout or write_stall (or peer_down after the other end's)", side(i), id, ev.Cause)
		}
		t.Logf("%s: dropped carrier %d down +%v: %v", side(i), id, ev.Time.Sub(drop), ev.Cause)
	}
	if fi, ok := flowOf(pf, src); ok {
		if cs, ok := carrierOf(fi.Session, id); ok && cs.State != rendr.CarrierDead {
			t.Fatalf("dialer: the dropped carrier %d is %v, want dead", id, cs.State)
		}
	}
}
