package lessons6

import (
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// mtuSize cycles test datagram k through 24 … 1375 bytes: every size up to
// the session limit of a 1400-byte frame budget.
func mtuSize(k int) int { return rendrtest.PacketHeaderLen + k*131%(1375-rendrtest.PacketHeaderLen+1) }

// TestPacketMTUShrink_L37: an embedder datagram conn that knows its limit
// (rendrtest.MTURefuse: WriteTo returns *wire.DatagramTooLargeError{Max})
// lowers one carrier's MTU from 1400 to 800 mid-session, in both
// directions. The carrier's frame budget shrinks to 800 on both ends
// (M2-D25); it is not a death, not even after 60 s of MTU probes padded to
// the new budget; the session's MaxPayload (1375) stays — fixed at OPEN
// (L37: "容量下降不算承载死亡"). Datagrams the shrunk carrier can no longer
// carry go to another live lane that can (bond, M2-D45) or are dropped and
// counted DropTooLarge (selector: none can); WriteTo still accepts every
// datagram up to MaxPayload and refuses MaxPayload + 1. Nothing is lost
// uncounted: accepted = Sent + DropTooLarge on each end and the peer
// receives exactly Sent. A refusal that leaves a budget below the control
// floor (300) kills the carrier (transport_error) and the session lives
// on.
func TestPacketMTUShrink_L37(t *testing.T) {
	t.Run("bond", func(t *testing.T) { synctest.Test(t, mtuShrinkBond) })
	t.Run("selector", func(t *testing.T) { synctest.Test(t, mtuShrinkSelector) })
	t.Run("below the floor", func(t *testing.T) { synctest.Test(t, mtuShrinkBelowFloor) })
}

// mtuWorld opens a packet session over links named names (5 ms one way,
// frame budget 1400) and starts traffic of every size both ways.
func mtuWorld(t *testing.T, mode rendr.Mode, names ...string) (w *world, dc, pc *rendr.PacketConn, up, down *flow) {
	w = newWorld(t, worldOpts{}, names...)
	var cs []rendr.Carrier
	for _, l := range w.links {
		for _, d := range bothDirs {
			l.SetDelay(d, 5*time.Millisecond, 0)
		}
		cs = append(cs, dgCarrier(l, 1400))
	}
	dc, pc = w.open(w.peer(cs...), rendr.DialOptions{Mode: mode})
	if mode == rendr.ModeBond {
		waitFor(t, 10*time.Second, "every member on both ends", func() bool {
			return len(liveOf(dc.Status())) == len(names) && len(liveOf(pc.Status())) == len(names)
		})
	}
	for _, c := range []*rendr.PacketConn{dc, pc} {
		if mp := c.MaxPayload(); mp != 1375 {
			t.Fatalf("%v MaxPayload %d, want 1375", c.Status().Role, mp)
		}
	}
	up = startFlow(dc, pc, flowCfg{seed: 31, pace: 2 * time.Millisecond, size: mtuSize})
	down = startFlow(pc, dc, flowCfg{seed: 32, pace: 10 * time.Millisecond, size: mtuSize})
	time.Sleep(5 * time.Second)
	return w, dc, pc, up, down
}

// budgets returns carrier id's frame budget on both ends.
func budgets(dc, pc *rendr.PacketConn, id rendr.CarrierID) [2]int {
	a, _ := carrierOf(dc.Status(), id)
	b, _ := carrierOf(pc.Status(), id)
	return [2]int{a.MTU, b.MTU}
}

// accountExact requires accepted = Sent + DropTooLarge on the sending end
// (no other drop) and Received = Sent = the datagrams that arrived on the
// receiving end, for one direction.
func accountExact(t *testing.T, what string, send, recv *rendr.PacketConn, f *flow) {
	t.Helper()
	s, r := send.Status().Packet, recv.Status().Packet
	if s.Sent+s.DropTooLarge != uint64(f.accepted.Load()) || s.DropQueue+s.DropAge+s.DropNoPath != 0 {
		t.Fatalf("%s: %d accepted, sender %+v", what, f.accepted.Load(), *s)
	}
	if r.Received != s.Sent || uint64(f.arrivedCount()) != s.Sent || r.Duplicates+r.DropLate+r.DropRecvQueue != 0 {
		t.Fatalf("%s: sender Sent %d, receiver %+v, %d arrived", what, s.Sent, *r, f.arrivedCount())
	}
	if uint64(len(f.losses())) != s.DropTooLarge {
		t.Fatalf("%s: %d datagrams missing, DropTooLarge %d", what, len(f.losses()), s.DropTooLarge)
	}
}

// noDeath requires that no carrier of either end went down and that the
// carriers are those of before.
func noDeath(t *testing.T, w *world, dc *rendr.PacketConn, ids []rendr.CarrierID) {
	t.Helper()
	for i, l := range []*eventLog{w.dev, w.pev} {
		if evs := l.of(rendr.EventCarrierDown); len(evs) != 0 {
			t.Fatalf("%s: a carrier went down: %+v", [2]string{"dialer", "passive"}[i], evs)
		}
	}
	var now []rendr.CarrierID
	for _, c := range liveOf(dc.Status()) {
		now = append(now, c.ID)
	}
	if len(now) != len(ids) {
		t.Fatalf("carriers %v, before the shrink %v", now, ids)
	}
	for i := range ids {
		if now[i] != ids[i] {
			t.Fatalf("carriers %v, before the shrink %v", now, ids)
		}
	}
}

func liveIDs(c *rendr.PacketConn) []rendr.CarrierID {
	var ids []rendr.CarrierID
	for _, s := range liveOf(c.Status()) {
		ids = append(ids, s.ID)
	}
	return ids
}

func mtuShrinkBond(t *testing.T) {
	w, dc, pc, up, down := mtuWorld(t, rendr.ModeBond, "A", "B")
	la := w.links[0]
	ca, _ := liveNamed(dc.Status(), "A")
	ids := liveIDs(dc)
	if b := budgets(dc, pc, ca.ID); b != [2]int{1400, 1400} {
		t.Fatalf("A's budgets before the shrink: %v", b)
	}
	before := la.Stats().Session.Oversize
	shrink := time.Now()
	la.SetMTU(800, rendrtest.MTURefuse)
	waitFor(t, 5*time.Second, "A's budget to shrink on both ends", func() bool { return budgets(dc, pc, ca.ID) == [2]int{800, 800} })
	if la.Stats().Session.Oversize == before {
		t.Fatalf("stimulus: A refused nothing")
	}
	txA, _ := carrierOf(dc.Status(), ca.ID)
	time.Sleep(60 * time.Second)
	noDeath(t, w, dc, ids)
	if b := budgets(dc, pc, ca.ID); b != [2]int{800, 800} {
		t.Fatalf("A's budgets 60 s after the shrink: %v (never raised)", b)
	}
	if c, _ := carrierOf(dc.Status(), ca.ID); c.TxBytes <= txA.TxBytes {
		t.Fatalf("A carried nothing after the shrink: %+v", c)
	}
	up.halt(t, "dialer → passive")
	down.halt(t, "passive → dialer")
	settle(t, dc, pc, up, down)
	for _, d := range []struct {
		name       string
		f          *flow
		send, recv *rendr.PacketConn
	}{{"dialer → passive", up, dc, pc}, {"passive → dialer", down, pc, dc}} {
		accountExact(t, d.name, d.send, d.recv, d.f)
		// Big datagrams written after the shrink ride B: none lost after
		// the shrink settled; the only losses are the datagrams of the
		// refused writes themselves.
		big := 0
		d.f.mu.Lock()
		for k, at := range d.f.wrote {
			if at.After(shrink.Add(time.Second)) && mtuSize(k) > 775 {
				if k >= len(d.f.arrived) || d.f.arrived[k].IsZero() {
					d.f.mu.Unlock()
					t.Fatalf("%s: seq %d of %d bytes, written +%v after the shrink, was lost", d.name, k, mtuSize(k), at.Sub(shrink))
				}
				big++
			}
		}
		d.f.mu.Unlock()
		if big == 0 {
			t.Fatalf("%s: load: no datagram above A's new limit after the shrink", d.name)
		}
		for _, l := range d.f.losses() {
			if l.wrote.Before(shrink.Add(-time.Second)) || l.wrote.After(shrink.Add(time.Second)) {
				t.Fatalf("%s: seq %d written +%v of the shrink was lost", d.name, l.seq, l.wrote.Sub(shrink))
			}
		}
		t.Logf("%s: %d accepted, %d above 775 B delivered after the shrink, %d lost (DropTooLarge)", d.name, d.f.accepted.Load(), big, len(d.f.losses()))
	}
	for _, c := range []*rendr.PacketConn{dc, pc} {
		if mp := c.MaxPayload(); mp != 1375 {
			t.Fatalf("%v MaxPayload %d after the shrink, want 1375", c.Status().Role, mp)
		}
	}
	endPair(t, dc, pc, up, down)
	w.noViolation()
	w.close()
}

func mtuShrinkSelector(t *testing.T) {
	w, dc, pc, up, down := mtuWorld(t, rendr.ModeSelector, "A")
	la := w.links[0]
	ca, _ := activeOf(dc.Status())
	ids := liveIDs(dc)
	shrink := time.Now()
	la.SetMTU(800, rendrtest.MTURefuse)
	waitFor(t, 5*time.Second, "A's budget to shrink on both ends", func() bool { return budgets(dc, pc, ca.ID) == [2]int{800, 800} })

	// WriteTo keeps the session's limit: MaxPayload is accepted (and
	// dropped, counted), MaxPayload + 1 is refused without a side effect.
	tl0 := dc.Status().Packet.DropTooLarge
	buf := make([]byte, 1376)
	if n, err := dc.WriteTo(buf[:1375], nil); n != 1375 || err != nil {
		t.Fatalf("WriteTo of MaxPayload after the shrink = %d, %v", n, err)
	}
	up.extra.Add(1)
	if n, err := dc.WriteTo(buf, nil); n != 0 || !errors.Is(err, rendr.ErrPacketTooLarge) {
		t.Fatalf("WriteTo of MaxPayload + 1 = %d, %v; want 0, ErrPacketTooLarge", n, err)
	}
	waitFor(t, time.Second, "the extra datagram's drop", func() bool { return dc.Status().Packet.DropTooLarge > tl0 })
	time.Sleep(60 * time.Second)
	noDeath(t, w, dc, ids)
	up.halt(t, "dialer → passive")
	down.halt(t, "passive → dialer")
	settle(t, dc, pc, up, down)
	for _, d := range []struct {
		name       string
		f          *flow
		send, recv *rendr.PacketConn
		extra      uint64
	}{{"dialer → passive", up, dc, pc, 1}, {"passive → dialer", down, pc, dc, 0}} {
		s := d.send.Status().Packet
		r := d.recv.Status().Packet
		// The extra MaxPayload datagram is not one of the flow's.
		if s.Sent+s.DropTooLarge != uint64(d.f.accepted.Load())+d.extra || s.DropQueue+s.DropAge+s.DropNoPath != 0 {
			t.Fatalf("%s: %d accepted (+%d), sender %+v", d.name, d.f.accepted.Load(), d.extra, *s)
		}
		if r.Received != s.Sent || uint64(d.f.arrivedCount()) != s.Sent {
			t.Fatalf("%s: sender Sent %d, receiver %+v, %d arrived", d.name, s.Sent, *r, d.f.arrivedCount())
		}
		// After the shrink settled: every datagram above 775 bytes is
		// dropped (no lane can carry it), every smaller one delivered.
		bigLost, small := 0, 0
		d.f.mu.Lock()
		for k, at := range d.f.wrote {
			if !at.After(shrink.Add(time.Second)) {
				continue
			}
			got := k < len(d.f.arrived) && !d.f.arrived[k].IsZero()
			switch {
			case mtuSize(k) > 775 && got:
				d.f.mu.Unlock()
				t.Fatalf("%s: seq %d of %d bytes crossed the 800-byte carrier", d.name, k, mtuSize(k))
			case mtuSize(k) > 775:
				bigLost++
			case !got:
				d.f.mu.Unlock()
				t.Fatalf("%s: seq %d of %d bytes, written +%v after the shrink, was lost", d.name, k, mtuSize(k), at.Sub(shrink))
			default:
				small++
			}
		}
		d.f.mu.Unlock()
		if bigLost == 0 || small == 0 {
			t.Fatalf("%s: load: %d big and %d small datagrams after the shrink", d.name, bigLost, small)
		}
		t.Logf("%s: after the shrink %d small delivered, %d big dropped; DropTooLarge %d", d.name, small, bigLost, s.DropTooLarge)
	}
	if mp := dc.MaxPayload(); mp != 1375 {
		t.Fatalf("MaxPayload %d after the shrink, want 1375", mp)
	}
	endPair(t, dc, pc, up, down)
	w.noViolation()
	w.close()
}

func mtuShrinkBelowFloor(t *testing.T) {
	w, dc, pc, up, down := mtuWorld(t, rendr.ModeSelector, "A")
	la := w.links[0]
	ca, _ := activeOf(dc.Status())
	shrink := time.Now()
	la.SetMTU(250, rendrtest.MTURefuse)
	waitFor(t, 5*time.Second, "the death below the floor", func() bool {
		c, _ := carrierOf(dc.Status(), ca.ID)
		return c.State == rendr.CarrierDead
	})
	c, _ := carrierOf(dc.Status(), ca.ID)
	if c.DeathCause != rendr.CauseTransportError || !strings.Contains(c.DeathDetail, "control floor") {
		t.Fatalf("the carrier died of %v (%q), want transport_error below the control floor", c.DeathCause, c.DeathDetail)
	}
	t.Logf("death %v after the refusal: %v %q", time.Since(shrink), c.DeathCause, c.DeathDetail)
	// The path recovers; the session lives on over a new carrier.
	la.SetMTU(1400, rendrtest.MTURefuse)
	waitFor(t, 10*time.Second, "a new carrier", func() bool {
		a, ok := activeOf(dc.Status())
		return ok && a.ID != ca.ID
	})
	resumed := time.Now()
	time.Sleep(5 * time.Second)
	up.halt(t, "dialer → passive")
	down.halt(t, "passive → dialer")
	settle(t, dc, pc, up, down)
	for _, d := range []struct {
		name string
		f    *flow
	}{{"dialer → passive", up}, {"passive → dialer", down}} {
		for _, l := range d.f.losses() {
			if l.wrote.Before(shrink.Add(-time.Second)) || l.wrote.After(resumed) {
				t.Fatalf("%s: seq %d written +%v of the shrink was lost (new carrier at +%v)", d.name, l.seq, l.wrote.Sub(shrink), resumed.Sub(shrink))
			}
		}
		if d.f.firstArrivalWrittenFrom(resumed).IsZero() {
			t.Fatalf("%s: nothing arrived over the new carrier", d.name)
		}
	}
	if mp := dc.MaxPayload(); mp != 1375 {
		t.Fatalf("MaxPayload %d, want 1375", mp)
	}
	endPair(t, dc, pc, up, down)
	w.noViolation()
	w.close()
}

// TestPacketMTUBlackhole_L37: a path MTU black hole (rendrtest.MTUDrop: a
// datagram above 1,000 bytes is silently lost, no error, no ICMP) under a
// selector session whose single carrier negotiated a 1400-byte budget.
// Every 10th PacketPing-cadence PING is an MTU probe padded to the budget
// (M2-D24); none of them is answered, and the carrier is killed with
// ping_timeout, detail "mtu probe", when the fourth probe finds its three
// predecessors unanswered: about 40 s after the carrier attached, never
// before the third probe could have failed (30 s) and within
// 4 × 10 × PacketPing + 2 s = 42 s (B1.9 part 4). Each redial attaches at
// once (no ErrNoPath, the session's MaxPayload unchanged) and lives another
// ≈ 40 s. 500-byte datagrams (which fit) keep flowing both ways: every one
// written outside [death − 1 s, death + 1 s] arrives, intact. A WriteTo of
// 1,300 bytes (≤ MaxPayload) is accepted and that datagram is lost on the
// path — never fragmented, never delivered.
func TestPacketMTUBlackhole_L37(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{}, "A")
		la := w.links[0]
		for _, d := range bothDirs {
			la.SetDelay(d, 10*time.Millisecond, 0)
		}
		la.SetMTU(1000, rendrtest.MTUDrop)
		start := time.Now()
		dc, pc := w.open(w.peer(dgCarrier(la, 1400)), rendr.DialOptions{})
		if mp := dc.MaxPayload(); mp != 1375 {
			t.Fatalf("MaxPayload %d, want 1375", mp)
		}
		fixed := func(int) int { return 500 }
		up := startFlow(dc, pc, flowCfg{seed: 41, pace: 5 * time.Millisecond, size: fixed})
		down := startFlow(pc, dc, flowCfg{seed: 42, pace: 20 * time.Millisecond, size: fixed})

		// One 1,300-byte datagram: accepted, lost on the path. Its seed is
		// not the flow's: should it arrive, the passive's verifier fails.
		time.Sleep(2 * time.Second)
		lost0, sent0 := la.Stats().Session.Lost, dc.Status().Packet.Sent
		big := rendrtest.PacketPayload(nil, 99, 0, 1300, time.Now())
		if n, err := dc.WriteTo(big, nil); n != 1300 || err != nil {
			t.Fatalf("WriteTo of 1300 bytes = %d, %v", n, err)
		}
		up.extra.Add(1)
		waitFor(t, time.Second, "the 1300-byte datagram's loss", func() bool {
			return la.Stats().Session.Lost > lost0 && dc.Status().Packet.Sent > sent0
		})

		time.Sleep(88 * time.Second)
		end := time.Now()
		up.halt(t, "dialer → passive")
		down.halt(t, "passive → dialer")
		settle(t, dc, pc, up, down)

		// The carriers' lives: attach (CarrierUp) → death (CarrierDown) on
		// the dialer.
		ups := map[rendr.CarrierID]time.Time{}
		for _, ev := range w.dev.of(rendr.EventCarrierUp) {
			ups[ev.Carrier] = ev.Time
		}
		var deaths []time.Time
		for _, ev := range w.dev.of(rendr.EventCarrierDown) {
			c, ok := carrierOf(dc.Status(), ev.Carrier)
			if !ok {
				t.Fatalf("no status for the dead carrier %d", ev.Carrier)
			}
			if _, sessionCarrier := ups[ev.Carrier]; !sessionCarrier {
				continue
			}
			if ev.Cause != rendr.CausePingTimeout || c.DeathDetail != "mtu probe" {
				t.Fatalf("carrier %d died of %v (%q), want ping_timeout \"mtu probe\"", ev.Carrier, ev.Cause, c.DeathDetail)
			}
			life := ev.Time.Sub(ups[ev.Carrier])
			if life < 30*time.Second || life > 42*time.Second {
				t.Fatalf("carrier %d lived %v, want the 4th probe's verdict in (30 s, 42 s]", ev.Carrier, life)
			}
			// The redial attaches within 1 s.
			next := time.Time{}
			for id, at := range ups {
				if id != ev.Carrier && !at.Before(ev.Time) && (next.IsZero() || at.Before(next)) {
					next = at
				}
			}
			if next.IsZero() && end.Sub(ev.Time) > time.Second {
				t.Fatalf("no carrier attached after carrier %d's death at +%v", ev.Carrier, ev.Time.Sub(start))
			}
			if !next.IsZero() && next.Sub(ev.Time) > time.Second {
				t.Fatalf("the redial after carrier %d's death attached %v later", ev.Carrier, next.Sub(ev.Time))
			}
			deaths = append(deaths, ev.Time)
			t.Logf("carrier %d: attached +%v, died +%v (lived %v): %v %q; next attached +%v",
				ev.Carrier, ups[ev.Carrier].Sub(start), ev.Time.Sub(start), life, ev.Cause, c.DeathDetail, next.Sub(start))
		}
		if len(deaths) != 2 {
			t.Fatalf("%d MTU-probe deaths in 90 s, want 2 (at ≈ 40 s and ≈ 80 s)", len(deaths))
		}
		if m := dc.Status().Migrations; m.Death != uint64(len(deaths)) {
			t.Fatalf("migrations %+v, want %d death migrations", m, len(deaths))
		}
		if mp := dc.MaxPayload(); mp != 1375 {
			t.Fatalf("MaxPayload %d after the redials, want 1375", mp)
		}
		if _, ok := activeOf(dc.Status()); !ok {
			t.Fatalf("no active carrier at the end: %+v", dc.Status().Carriers)
		}

		// The 500-byte datagrams written away from the deaths all arrived.
		for _, d := range []struct {
			name string
			f    *flow
		}{{"dialer → passive", up}, {"passive → dialer", down}} {
			ls := d.f.losses()
			for _, l := range ls {
				near := false
				for _, at := range deaths {
					near = near || (!l.wrote.Before(at.Add(-time.Second)) && !l.wrote.After(at.Add(time.Second)))
				}
				if !near {
					t.Fatalf("%s: seq %d written +%v was lost away from every death", d.name, l.seq, l.wrote.Sub(start))
				}
			}
			if n := d.f.accepted.Load(); n < 4000 {
				t.Fatalf("%s: load: %d datagrams", d.name, n)
			}
			t.Logf("%s: %d lost of %d", d.name, len(ls), d.f.accepted.Load())
		}
		if s, r := dc.Status().Packet, pc.Status().Packet; r.Received != uint64(up.arrivedCount()) || s.Sent != uint64(up.accepted.Load()+up.extra.Load()) {
			t.Fatalf("dialer %+v, passive %+v, %d arrived", *s, *r, up.arrivedCount())
		}
		endPair(t, dc, pc, up, down)
		w.noViolation()
		w.close()
	})
}
