package mux

import (
	"fmt"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
)

// Packet-session bounds of this package: a datagram written in
// [event − pktBefore, event + pktLossWin) may be lost with a carrier that
// died at event (in flight on it, or written before the session had a
// carrier again); arrivals must resume within pktLossWin of the event.
const (
	pktBefore  = 50 * time.Millisecond
	pktLossWin = 500 * time.Millisecond
)

// pktFlows is a packet session's two flows.
type pktFlows struct {
	s        ppair
	up, down *flow
}

// judgeFlows checks one packet session's flows after its clean end:
// PacketIntegrity (0 application duplicates, nothing corrupt or resized),
// losses only inside the windows of events (pktBefore before each to
// pktLossWin after it), DeliveryRatio ≥ 0.95, and, for every event, a
// datagram written after it that arrived within pktLossWin.
func judgeFlows(t testing.TB, pf pktFlows, events []time.Time) {
	t.Helper()
	var wins [][2]time.Time
	for _, at := range events {
		wins = append(wins, [2]time.Time{at.Add(-pktBefore), at.Add(pktLossWin)})
	}
	for _, f := range []*flow{pf.up, pf.down} {
		res := f.integrity(t)
		outside, lost := f.lostOutside(wins)
		if outside != 0 {
			t.Fatalf("%s: %d datagrams lost outside the event windows (%d lost in all; events %v)", f.cfg.name, outside, lost, events)
		}
		acc := f.accepted.Load()
		if acc == 0 || float64(res.Unique) < 0.95*float64(acc) {
			t.Fatalf("load: %s: %d unique datagrams of %d accepted, want ≥ 95 %%", f.cfg.name, res.Unique, acc)
		}
		for _, at := range events {
			first := f.firstArrivalAfter(at)
			if first.IsZero() || first.Sub(at) > pktLossWin {
				t.Fatalf("%s: no datagram written after the event at %v arrived within %v (first at %v)", f.cfg.name, at, pktLossWin, first)
			}
		}
		t.Logf("%s: accepted %d, unique %d, lost %d", f.cfg.name, acc, res.Unique, lost)
	}
}

// TestMuxPacketSessions_L39_L40 (M3 design §A11.2, §A5.10; L39, L40,
// M3-D24): four selector packet sessions share the one datagram carrier
// of a Peer over a DatagramLink u (20 ms RTT), each sending 2,000
// datagrams/s A → B and 500/s B → A of 200 bytes; a fifth packet session
// runs on the stream carrier of another Peer over a Link s (DGRAM as
// DATA), at the same rates.
//
// Premise: the four sessions share one carrier (one factory call, one
// accepted carrier, Shared 4 on both ends).
// Stimulus: after the warm-up the dialer's conn of the shared datagram
// carrier is closed under rendr (F10's local close); later the stream
// carrier of s is killed (Link.Kill). Each must end the carrier: every
// session on it records it dead on the dialer. The four sessions recover
// with at most one factory call (the pool's coalesced redial, M3-D18) and
// all four end up on one new datagram carrier again; the REL-wrapped
// JOINs of the four views complete together (REL fairness, §A5.10): every
// session's datagrams arrive again within 500 ms of the close.
// PASS: per flow PacketIntegrity (0 application duplicates, 0 corrupt);
// losses only in [event − 50 ms, event + 500 ms) (L39: packet loses only
// what was in flight or written while no carrier existed); DeliveryRatio
// ≥ 0.95; every flow resumes within 500 ms of every event; every session
// ends cleanly and Runtime.Close leaves nothing.
func TestMuxPacketSessions_L39_L40(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		phase := 3 * time.Second
		if raceEnabled {
			phase = 1500 * time.Millisecond // R1-11: a shorter timeline, the same criteria
		}
		const oneWay = 10 * time.Millisecond
		w := newWorld(t, worldOpts{}, linkSpec{name: "u", oneWay: oneWay, dgram: true}, linkSpec{name: "s", oneWay: oneWay})
		pu, psr := w.peer("u"), w.peer("s")
		var all []pktFlows
		for i := range 4 {
			all = append(all, pktFlows{s: w.openPacket(pu, fmt.Sprintf("U%d", i), rendr.ModeSelector)})
		}
		all = append(all, pktFlows{s: w.openPacket(psr, "S0", rendr.ModeSelector)})
		if got, acc := w.dials("u"), w.accepted("u"); got != 1 || acc != 1 {
			t.Fatalf("premise: 4 packet sessions made %d factory calls and %d accepted carriers on u, want 1 each", got, acc)
		}
		var trunk rendr.CarrierID
		for _, pf := range all[:4] {
			for i, c := range []*rendr.PacketConn{pf.s.d, pf.s.p} {
				live := liveOf(c.Status())
				if len(live) != 1 || live[0].Shared != 4 || (trunk != 0 && live[0].ID != trunk) {
					t.Fatalf("premise: session %s (%s) lists %+v, want the shared datagram carrier with Shared 4", pf.s.key, side(i), live)
				}
				trunk = live[0].ID
			}
		}
		for i := range all {
			pf := &all[i]
			pf.up = w.startFlow(pf.s.d, pf.s.p, flowCfg{name: pf.s.key + " A → B", seed: uint64(100 + i), rate: 2000})
			pf.down = w.startFlow(pf.s.p, pf.s.d, flowCfg{name: pf.s.key + " B → A", seed: uint64(200 + i), rate: 500})
		}

		start := time.Now()
		sleepUntil(start.Add(phase))
		closed := time.Now()
		w.localClose(trunk)
		sleepUntil(closed.Add(phase))
		killed := time.Now()
		var streamTrunk rendr.CarrierID
		if a, ok := active(all[4].s.d.Status()); ok {
			streamTrunk = a.ID
		}
		if n := w.link("s").Kill(); n == 0 {
			t.Fatal("stimulus: the kill of s ended no carrier")
		}
		sleepUntil(killed.Add(phase))

		// Stimulus proofs.
		for _, pf := range all[:4] {
			if cs, ok := carrierOf(pf.s.d.Status(), trunk); !ok || cs.State != rendr.CarrierDead {
				t.Fatalf("stimulus: session %s does not list the closed carrier %d dead: %+v", pf.s.key, trunk, cs)
			}
		}
		if cs, ok := carrierOf(all[4].s.d.Status(), streamTrunk); streamTrunk == 0 || !ok || cs.State != rendr.CarrierDead {
			t.Fatalf("stimulus: session S0 does not list its killed stream carrier %d dead: %+v", streamTrunk, cs)
		}
		if got := w.dialsIn("u", closed, time.Now()); got != 1 {
			t.Fatalf("the four sessions made %d factory calls on u after the close, want 1 (coalesced)", got)
		}
		var rejoined rendr.CarrierID
		for _, pf := range all[:4] {
			live := liveOf(pf.s.d.Status())
			if len(live) != 1 || live[0].ID == trunk || live[0].Shared != 4 || (rejoined != 0 && live[0].ID != rejoined) {
				t.Fatalf("session %s after the close lists %+v, want one new carrier shared by the four", pf.s.key, live)
			}
			rejoined = live[0].ID
		}

		for _, pf := range all {
			endPackets(t, pf.s, pf.up, pf.down)
		}
		for i, pf := range all {
			ev := []time.Time{closed}
			if i == 4 {
				ev = []time.Time{killed}
			}
			judgeFlows(t, pf, ev)
		}
		w.noViolation()
		w.close()
	})
}

// TestMuxMixedKinds (M3 design §A11.2, §A5.10; M3-D24 and amendment
// KINDSPLIT): one Peer with a stream factory s (Link, 20 ms RTT) and a
// datagram factory u (DatagramLink, 20 ms RTT) carries two selector stream
// sessions and two bond packet sessions. Both kinds run on s (packet
// sessions as DGRAM inside a stream carrier), but a stream carrier carries
// sessions of one kind (KINDSPLIT): s has one carrier for the two stream
// sessions and another for the two packet sessions (Shared 2 each, two
// session factory calls on s, one per kind); a datagram carrier carries
// packet sessions only, so u's one carrier holds the two packet sessions
// (Shared 2, one call). Status.Mux counts exactly these three carriers on
// both ends.
//
// Load: each stream session sends 4 MiB each way paced over the run, each
// packet session 500 datagrams/s each way. Stimulus: midway s is killed
// (Link.Kill): all four sessions lose their s view at once (both of s's
// carriers end). The two kinds recover side by side on two new s carriers,
// again one per kind (at most one session factory call per kind on s from
// the kill on: at most two, Shared 2 each again), while the packet
// sessions keep their u member.
// PASS: every stream byte verified with io.EOF at the end and no
// zero-delivery gap above 2 s; packet flows: PacketIntegrity, losses only
// in the kill's window, DeliveryRatio ≥ 0.95; every session ends cleanly
// and Runtime.Close leaves nothing.
func TestMuxMixedKinds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		run := 8 * time.Second
		size := int64(4 << 20)
		if raceEnabled {
			run, size = 4*time.Second, 1<<20 // R1-11
		}
		const oneWay = 10 * time.Millisecond
		w := newWorld(t, worldOpts{}, linkSpec{name: "s", oneWay: oneWay}, linkSpec{name: "u", oneWay: oneWay, dgram: true})
		peer := w.peer("s", "u")
		ss := []pair{w.open(peer, "S0", rendr.ModeSelector), w.open(peer, "S1", rendr.ModeSelector)}
		pk := []pktFlows{{s: w.openPacket(peer, "P0", rendr.ModeBond)}, {s: w.openPacket(peer, "P1", rendr.ModeBond)}}
		waitFor(t, 10*time.Second, "both packet sessions bonded over s and u", func() bool {
			for _, pf := range pk {
				_, okS := liveNamed(pf.s.d.Status(), "s")
				_, okU := liveNamed(pf.s.d.Status(), "u")
				if !okS || !okU {
					return false
				}
			}
			return true
		})
		// shares checks the carriers of s per kind: the stream sessions on
		// one carrier, the packet sessions on another (Shared 2 each), none
		// of them among not; it returns the stream and the packet carrier.
		shares := func(when string, not ...rendr.CarrierID) (sID, pID rendr.CarrierID) {
			t.Helper()
			check := func(key string, st rendr.SessionStatus, name string, want int, id *rendr.CarrierID) {
				cs, ok := liveNamed(st, name)
				if !ok || cs.Shared != want || slices.Contains(not, cs.ID) || (id != nil && *id != 0 && cs.ID != *id) {
					t.Fatalf("%s: session %s's carrier of %s: %+v (found %v), want one shared with Shared %d (not %v)", when, key, name, cs, ok, want, not)
				}
				if id != nil {
					*id = cs.ID
				}
			}
			for _, s := range ss {
				check(s.key, s.d.Status(), "s", 2, &sID)
			}
			for _, pf := range pk {
				check(pf.s.key, pf.s.d.Status(), "s", 2, &pID)
				check(pf.s.key, pf.s.d.Status(), "u", 2, nil)
			}
			if sID == pID {
				t.Fatalf("%s: the stream and the packet sessions share carrier %v of s, want one carrier per session kind", when, sID)
			}
			return sID, pID
		}
		w.identities("after the opens", ss, pk[0].s, pk[1].s)
		for i, rt := range []*rendr.Runtime{w.d, w.p} {
			if m := rt.Status().Mux; m.Carriers != 3 || m.Views != 6 {
				t.Fatalf("premise: %s Status.Mux %+v, want 3 carriers (s per kind, u) with 6 views", side(i), m)
			}
		}
		sTrunk, pTrunk := shares("after the opens")
		if got, gotU := w.dials("s"), w.dials("u"); got != 2 || gotU != 1 {
			t.Fatalf("premise: %d session factory calls on s and %d on u, want 2 (one per session kind) and 1", got, gotU)
		}

		var rx []*receiver
		var tx []*sender
		for i, s := range ss {
			rx = append(rx, startReceiver(s.key+" A → B", s.p, uint64(10+2*i), size), startReceiver(s.key+" B → A", s.d, uint64(11+2*i), size))
			tx = append(tx, w.startSender(s.d, uint64(10+2*i), size, float64(size)/run.Seconds()), w.startSender(s.p, uint64(11+2*i), size, float64(size)/run.Seconds()))
		}
		for i := range pk {
			pf := &pk[i]
			pf.up = w.startFlow(pf.s.d, pf.s.p, flowCfg{name: pf.s.key + " A → B", seed: uint64(100 + i), rate: 500})
			pf.down = w.startFlow(pf.s.p, pf.s.d, flowCfg{name: pf.s.key + " B → A", seed: uint64(200 + i), rate: 500})
		}
		start := time.Now()
		sleepUntil(start.Add(run / 2))
		killed := time.Now()
		if n := w.link("s").Kill(); n == 0 {
			t.Fatal("stimulus: the kill of s ended no carrier")
		}
		for _, r := range rx {
			r.wait(t, 2*run)
		}
		for _, s := range tx {
			s.wait(t, time.Second)
		}
		for _, r := range rx {
			if g, at := r.maxGap(start, r.end()); g > 2*time.Second {
				t.Fatalf("%s: a zero-delivery gap of %v at +%v", r.name, g, at.Sub(start))
			}
		}
		for i, s := range []statuser{ss[0].d, ss[1].d, pk[0].s.d, pk[1].s.d} {
			id := sTrunk
			if i >= 2 {
				id = pTrunk
			}
			if cs, ok := carrierOf(s.Status(), id); !ok || cs.State != rendr.CarrierDead {
				t.Fatalf("stimulus: a session does not list the killed carrier %d dead: %+v", id, cs)
			}
		}
		waitFor(t, 10*time.Second, "the bond members to rejoin s", func() bool {
			for _, pf := range pk {
				if cs, ok := liveNamed(pf.s.d.Status(), "s"); !ok || cs.ID == pTrunk {
					return false
				}
			}
			return true
		})
		shares("after the kill", sTrunk, pTrunk)
		if got := w.dialsIn("s", killed, time.Now()); got > 2 {
			// With the two distinct new carriers shares found, ≤ 2 is
			// exactly one call per session kind.
			t.Fatalf("%d session factory calls on s after the kill, want ≤ 2 (coalesced: one per session kind)", got)
		}

		for _, pf := range pk {
			endPackets(t, pf.s, pf.up, pf.down)
			judgeFlows(t, pf, []time.Time{killed})
		}
		for _, s := range ss {
			closeBoth(t, s)
		}
		w.noViolation()
		w.close()
	})
}
