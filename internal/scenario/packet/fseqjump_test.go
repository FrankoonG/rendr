package packet

import (
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestPacketFseqJumpRecovery_L43: a genuine fseq jump of a window or more
// inside a real packet session (m3 FSEQJUMP; m3 design §A9.1, R1-35). One
// DatagramLink of 20 ms RTT and the zero Config (DeadMin 3 s); 1000-byte
// datagrams at 2,000 per second B → A, and 200 (down) or 2,000 (both) per
// second A → B. After 2 s, the B → A direction (down) or both directions
// (both) are blackholed for 1 s, so the blackholed senders hand at least
// FseqWindowBits datagrams to the carrier, each a frame of its own whose
// fseq the receiver never sees, and the link heals. Every frame that
// arrives after the heal is then a window or more ahead of the receiver's
// fseq window: it is dropped until the datagram proves the jump with a PONG
// of the receiver's own PING (dgJumpProof), which takes about one round
// trip.
//
// Stimulus: the blackholed senders handed ≥ 1,024 datagrams to the session's
// one carrier while the blackhole lasted (Packet.Sent), so the receiver's
// window can deliver again only by the jump; the frames each receiving
// carrier dropped after the heal (CarrierStatus.Dropped) are logged (none
// when the first datagram after the heal carries the PONG of a PING the
// receiver sent during the blackhole). PASS: the session keeps its one
// carrier on both ends (same CarrierID, the only live one, no CarrierDown)
// and its traffic: a datagram written after the heal arrives within 2·RTT + a
// send slot, and no datagram written later than that is lost; the datagrams
// lost that were written after the heal are at most rate × (2·RTT + a send
// slot) + 1 per direction (the rule's cost; before it the window took the
// jump at once and lost nothing after the heal); integrity, NonBlockingWrite,
// the attribution of every loss to the link and a clean end with io.EOF.
// The post-heal loss is logged for the pool follow-up.
func TestPacketFseqJumpRecovery_L43(t *testing.T) {
	for _, mode := range []rendr.Mode{rendr.ModeSelector, rendr.ModeBond} {
		for _, both := range []bool{false, true} {
			name := mode.String() + "/down"
			if both {
				name = mode.String() + "/both"
			}
			t.Run(name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) { fseqJumpRecovery(t, mode, both) })
			})
		}
	}
}

func fseqJumpRecovery(t *testing.T, mode rendr.Mode, both bool) {
	const (
		rtt   = 2 * goldOneWay
		hole  = time.Second + sendSlot/2 // the heal falls between two send slots
		warm  = 2 * time.Second
		after = 3 * time.Second
		win   = 1024 // wire.FseqWindowBits
	)
	bound := 2*rtt + sendSlot
	rateUp := goldRateAB
	if both {
		rateUp = goldRateBA
	}
	w := newWorld(t, worldOpts{oneWay: goldOneWay}, "u1")
	l := w.link("u1")
	dc, pc := w.open(w.peer("u1"), rendr.DialOptions{Mode: mode})
	up := startFlow(dc, pc, flowCfg{name: "A → B", seed: 1, rate: rateUp})
	down := startFlow(pc, dc, flowCfg{name: "B → A", seed: 2, rate: goldRateBA})
	time.Sleep(warm)

	act, ok := activeOf(dc.Status())
	if mode == rendr.ModeBond {
		lv := liveOf(dc.Status())
		ok = len(lv) == 1
		if ok {
			act = lv[0]
		}
	}
	if !ok {
		t.Fatalf("stimulus: no single live carrier before the blackhole: %+v", dc.Status().Carriers)
	}
	dirs := []rendrtest.Dir{rendrtest.Down}
	if both {
		dirs = bothDirs
	}
	sent0 := [2]uint64{dc.Status().Packet.Sent, pc.Status().Packet.Sent}
	for _, d := range dirs {
		l.Blackhole(d, true)
	}
	time.Sleep(hole)
	sent1 := [2]uint64{dc.Status().Packet.Sent, pc.Status().Packet.Sent}
	var dropped0 [2]uint64
	for i, c := range []*rendr.PacketConn{dc, pc} {
		cs, ok := carrierOf(c.Status(), act.ID)
		if !ok {
			t.Fatalf("%s: carrier %d is gone at the heal: %+v", side(i), act.ID, c.Status().Carriers)
		}
		dropped0[i] = cs.Dropped
	}
	for _, d := range dirs {
		l.Blackhole(d, false)
	}
	heal := time.Now()
	time.Sleep(after)
	up.halt(t)
	down.halt(t)
	time.Sleep(time.Second) // every datagram written arrived or was lost

	// Stimulus: the blackholed senders handed a window of frames to the
	// session's one carrier, so its receivers saw the next frame a window
	// or more ahead; when the datagram that carries it holds a PONG of the
	// receiver's PING, nothing is dropped (logged).
	if n := sent1[1] - sent0[1]; n < win {
		t.Fatalf("stimulus: B handed %d datagrams to the carrier during the blackhole, want ≥ %d", n, win)
	}
	if n := sent1[0] - sent0[0]; both && n < win {
		t.Fatalf("stimulus: A handed %d datagrams to the carrier during the blackhole, want ≥ %d", n, win)
	}
	receivers := []int{0} // the dialer receives B → A
	if both {
		receivers = []int{0, 1}
	}
	for _, i := range receivers {
		c := []*rendr.PacketConn{dc, pc}[i]
		cs, _ := carrierOf(c.Status(), act.ID)
		t.Logf("%s's carrier dropped %d frames after the heal", side(i), cs.Dropped-dropped0[i])
	}

	// The carrier survived on both ends — its windows took the jump — and
	// the traffic recovered.
	for i, c := range []*rendr.PacketConn{dc, pc} {
		if lv := liveOf(c.Status()); len(lv) != 1 || lv[0].ID != act.ID {
			t.Fatalf("%s: live carriers %+v, want carrier %d alone", side(i), lv, act.ID)
		}
		if cs, ok := carrierOf(c.Status(), act.ID); !ok || (cs.State != rendr.CarrierActive && cs.State != rendr.CarrierMember) {
			t.Fatalf("%s: carrier %d is %+v (found %v) after the heal, want live", side(i), act.ID, cs, ok)
		}
		if evs := [2]*eventLog{w.dev, w.pev}[i].of(rendr.EventCarrierDown); len(evs) != 0 {
			t.Fatalf("%s: carriers went down: %+v", side(i), evs)
		}
	}
	flows := []*flow{down}
	if both {
		flows = []*flow{down, up}
	}
	rates := map[*flow]int{down: goldRateBA, up: rateUp}
	for _, f := range flows {
		first := f.firstArrivalWrittenFrom(heal)
		if first.IsZero() || first.Sub(heal) > bound+goldOneWay {
			t.Fatalf("%s: the first datagram written after the heal arrived at %+v, want within %v", f.cfg.name, first.Sub(heal), bound+goldOneWay)
		}
		var post []loss
		for _, ls := range f.losses() {
			if !ls.wrote.Before(heal) {
				post = append(post, ls)
			}
		}
		var last time.Duration
		if len(post) > 0 {
			last = post[len(post)-1].wrote.Sub(heal)
		}
		t.Logf("%s: %d datagrams written after the heal lost, the last written +%v; first arrival +%v",
			f.cfg.name, len(post), last, first.Sub(heal))
		if last > bound {
			t.Fatalf("%s: a datagram written +%v after the heal was lost, want none after %v", f.cfg.name, last, bound)
		}
		if max := int(float64(rates[f])*bound.Seconds()) + 1; len(post) > max {
			t.Fatalf("%s: %d datagrams written after the heal lost, want ≤ %d", f.cfg.name, len(post), max)
		}
	}
	for _, f := range []*flow{up, down} {
		f.integrity(t)
		f.nonBlocking(t)
	}
	var dropped uint64
	for _, c := range []*rendr.PacketConn{dc, pc} {
		cs, _ := carrierOf(c.Status(), act.ID)
		dropped += cs.Dropped
	}
	endClean(t, dc, pc, up, down)
	// Attribution (B1.0): every datagram sent and not received was lost on
	// the link or dropped by a receiving carrier as a window ahead.
	ds, ps := dc.Status().Packet, pc.Status().Packet
	for i, c := range []*rendr.PacketCounters{ds, ps} {
		if c.Duplicates+c.DropRecvQueue+c.DropLate != 0 {
			t.Fatalf("%s: receive-side drops %+v", side(i), *c)
		}
	}
	miss := (ds.Sent - ps.Received) + (ps.Sent - ds.Received)
	if lost := w.sessionLost(); miss > lost+dropped {
		t.Fatalf("%d datagrams were sent and not received, but the link lost %d and the carriers dropped %d frames", miss, lost, dropped)
	}
	w.noViolation()
	if n := w.pendings(); n != 1 {
		t.Fatalf("the passive was offered %d PendingPackets for one packet session", n)
	}
	w.close()
}
