package packet

import (
	"sync"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The datagram replay window at the M5 rate (m5 F-5, PA-85 amending
// plan:332; L39, L43). C-P found that M3's 1,024-frame window spans 10 ms
// at G3-100k's 100 kpps, less than the about 2,000 frames in flight over
// its 20-ms round trip, and that the PING proving a jump of a window or
// more was repeated only at the RTO: a burst loss of 1,024 frames made the
// receiving carrier discard everything it received intact for a round trip
// or more. These are C-P's failing-first rows, beside
// TestPacketFseqJumpRecovery_L43.

// m3Window is M3's datagram replay window (plan:332 before PA-85): a
// consecutive loss of more frames was a forward jump the receiver had to
// prove.
const m3Window = 1024

// jumpRateBA is the B → A rate, in datagrams per second, of the rows that
// need a window of frames lost in a blackhole of about 1 s: 10,000 per
// second hand the carrier more than wire.FseqWindowBits (8,192) frames in
// 1 s. The rows scale G3-100k down for synctest.
const jumpRateBA = 10000

// TestPacketFseqJumpShortBurst_L39_L43: a consecutive loss of more than
// M3's 1,024-frame window that is shorter than one round trip costs no
// datagram written after it: the carrier's replay window covers the frames
// legitimately in flight (L39). At G3-100k's 100 kpps over 20 ms about
// 2,000 frames are in flight, so a softnet backlog overflow of 10.24 ms or
// more was a jump to prove, and the receiver discarded what it received
// intact until the proof (C-P: 9.6 M datagrams in one run). Scaled for
// synctest: one DatagramLink of 200 ms RTT, B → A at 10,000 datagrams per
// second (2,000 in flight) and A → B at 1,000, then a 125-ms blackhole
// B → A (C-P's 120 ms and half a send slot, so that the heal falls between
// two send slots); with the 100 ms of datagrams in flight at its start the
// burst is about 2,250 frames: more than 1,024, fewer than the window's
// 8,192 (PA-85).
//
// Stimulus: B handed more than 1,024 datagrams to the carrier while the
// blackhole lasted, which lasted less than one round trip. PASS: at most
// one datagram written after the heal is lost (C-P's bound: rate × 0 + 1),
// the dialer's carrier dropped none of the frames it received (none was a
// window ahead), the session keeps its one carrier on both ends (same
// CarrierID, the only live one, no CarrierDown), integrity,
// NonBlockingWrite, the attribution of every loss to the link and a clean
// end with io.EOF.
func TestPacketFseqJumpShortBurst_L39_L43(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			oneWay = 100 * time.Millisecond
			rtt    = 2 * oneWay
			hole   = 120*time.Millisecond + sendSlot/2 // the heal falls between two send slots
			rate   = jumpRateBA
		)
		w := newWorld(t, worldOpts{oneWay: oneWay}, "u1")
		l := w.link("u1")
		dc, pc := w.open(w.peer("u1"), rendr.DialOptions{Mode: rendr.ModeSelector})
		up := startFlow(dc, pc, flowCfg{name: "A → B", seed: 1, rate: rate / 10})
		down := startFlow(pc, dc, flowCfg{name: "B → A", seed: 2, rate: rate})
		time.Sleep(2 * time.Second)
		act, ok := activeOf(dc.Status())
		if !ok {
			t.Fatalf("stimulus: no active carrier: %+v", dc.Status().Carriers)
		}
		cs0, _ := carrierOf(dc.Status(), act.ID)
		sent0 := pc.Status().Packet.Sent
		l.Blackhole(rendrtest.Down, true)
		time.Sleep(hole)
		sent1 := pc.Status().Packet.Sent
		l.Blackhole(rendrtest.Down, false)
		heal := time.Now()
		time.Sleep(3 * time.Second)
		up.halt(t)
		down.halt(t)
		time.Sleep(time.Second) // every datagram written arrived or was lost
		cs1, _ := carrierOf(dc.Status(), act.ID)

		if n := sent1 - sent0; n <= m3Window || hole >= rtt {
			t.Fatalf("stimulus: B handed %d datagrams to the carrier in a %v blackhole, want more than %d in less than the %v round trip", n, hole, m3Window, rtt)
		}
		post, last := lostAfter(down, heal)
		first := down.firstArrivalWrittenFrom(heal)
		t.Logf("B → A at %d/s over RTT %v, hole %v (%d datagrams handed to the carrier): %d datagrams written after the heal lost (the last written +%v), first arrival of one written after the heal +%v; A's carrier dropped %d frames",
			rate, rtt, hole, sent1-sent0, post, last, first.Sub(heal), cs1.Dropped-cs0.Dropped)
		if post > 1 {
			t.Errorf("%d datagrams written after the heal lost, want ≤ 1 (bound 0s)", post)
		}
		if d := cs1.Dropped - cs0.Dropped; d != 0 {
			t.Errorf("A's carrier dropped %d frames it received after the burst, want 0: the burst was inside the replay window", d)
		}
		fseqRowEnd(t, w, dc, pc, act.ID, up, down)
	})
}

// TestPacketFseqJumpProofLost_L43: after a blackhole that cost a window of
// frames, the receiver's first proof PING is lost (A → B blackholed for one
// round trip from the heal); the jump is still proved within 2·RTT + a
// send slot of the heal plus that round trip, not after RelRTOMin (200 ms):
// the proof PING is repeated at the carrier's round-trip time (PA-85) — the
// cost bound of TestPacketFseqJumpRecovery_L43 with one lost proof. One
// DatagramLink of 20 ms RTT and the zero Config; B → A at 10,000 datagrams
// per second (C-P's draft ran 2,000: at the M5 window a 1-s blackhole must
// cost more than 8,192 frames) and A → B at 1,000; a blackhole B → A of
// 1 s and half a send slot (the heal falls between two send slots, so the
// first frame B sends after it reaches A before A → B heals).
//
// Stimulus: B handed at least wire.FseqWindowBits datagrams to the
// carrier while the blackhole lasted (the jump is real), the dialer's
// carrier encoded a PING while A → B was blackholed after the first frame
// B sent after the heal could have arrived (the lost proof PING; recorded
// through Hooks.PingTS) and it dropped frames after the heal (they were a
// window ahead). PASS: at most rate × (2·RTT + a send slot + the lost
// round trip) + 1 = 701 datagrams written after the heal are lost, the
// session keeps its one carrier on both ends, integrity, NonBlockingWrite,
// the attribution of every loss to the link or to a receiving carrier's
// drops and a clean end with io.EOF. The PINGs after the heal are logged.
func TestPacketFseqJumpProofLost_L43(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			oneWay = goldOneWay
			rtt    = 2 * oneWay
			hole   = time.Second + sendSlot/2
			upLoss = rtt // A → B lost for one round trip after the heal
			rate   = jumpRateBA
		)
		pings := &pingLog{}
		dh := &testhooks.Hooks{PingTS: pings.note}
		w := newWorldHooked(t, worldOpts{oneWay: oneWay}, dh, nil, "u1")
		l := w.link("u1")
		dc, pc := w.open(w.peer("u1"), rendr.DialOptions{Mode: rendr.ModeSelector})
		up := startFlow(dc, pc, flowCfg{name: "A → B", seed: 1, rate: rate / 10})
		down := startFlow(pc, dc, flowCfg{name: "B → A", seed: 2, rate: rate})
		time.Sleep(2 * time.Second)
		act, ok := activeOf(dc.Status())
		if !ok {
			t.Fatalf("stimulus: no active carrier: %+v", dc.Status().Carriers)
		}
		sent0 := pc.Status().Packet.Sent
		l.Blackhole(rendrtest.Down, true)
		time.Sleep(hole)
		sent1 := pc.Status().Packet.Sent
		cs0, _ := carrierOf(dc.Status(), act.ID)
		l.Blackhole(rendrtest.Up, true)
		l.Blackhole(rendrtest.Down, false)
		heal := time.Now()
		time.Sleep(upLoss)
		l.Blackhole(rendrtest.Up, false)
		time.Sleep(3 * time.Second)
		up.halt(t)
		down.halt(t)
		time.Sleep(time.Second) // every datagram written arrived or was lost
		cs1, _ := carrierOf(dc.Status(), act.ID)

		if n := sent1 - sent0; n < wire.FseqWindowBits {
			t.Fatalf("stimulus: B handed %d datagrams to the carrier during the blackhole, want ≥ %d", n, wire.FseqWindowBits)
		}
		after := pings.since(uint32(act.ID), heal)
		lostProof := false
		for _, at := range after {
			lostProof = lostProof || (!at.Before(heal.Add(oneWay)) && at.Before(heal.Add(upLoss)))
		}
		if !lostProof {
			t.Fatalf("stimulus: A's carrier encoded no PING in [+%v, +%v) after the heal, while A → B was blackholed (PINGs at %v)", oneWay, upLoss, offsets(after, heal))
		}
		if cs1.Dropped == cs0.Dropped {
			t.Fatalf("stimulus: A's carrier dropped no frame after the heal: nothing arrived a window ahead")
		}
		post, last := lostAfter(down, heal)
		first := down.firstArrivalWrittenFrom(heal)
		bound := 2*rtt + sendSlot + upLoss
		t.Logf("B → A at %d/s over RTT %v, hole %v, A → B lost for %v after the heal: %d datagrams written after the heal lost (the last written +%v), first arrival of one written after the heal +%v; A's carrier dropped %d frames; A's PINGs after the heal at %v",
			rate, rtt, hole, upLoss, post, last, first.Sub(heal), cs1.Dropped-cs0.Dropped, offsets(after, heal))
		if max := int(float64(rate)*bound.Seconds()) + 1; post > max {
			t.Errorf("%d datagrams written after the heal lost, want ≤ %d (bound %v)", post, max, bound)
		}
		fseqRowEnd(t, w, dc, pc, act.ID, up, down)
	})
}

// lostAfter returns how many datagrams of f written at or after at were
// lost, and when the last of them was written (relative to at).
func lostAfter(f *flow, at time.Time) (n int, last time.Duration) {
	for _, ls := range f.losses() {
		if !ls.wrote.Before(at) {
			n++
			last = ls.wrote.Sub(at)
		}
	}
	return n, last
}

// fseqRowEnd is the common end of the replay-window rows: the session kept
// carrier id on both ends (the only live one, no CarrierDown), every flow
// is intact and never blocked, the session ends cleanly with io.EOF, every
// datagram sent and not received was lost on the link or dropped by a
// receiving carrier, no carrier ended with protocol_violation, and the
// passive was offered one PendingPacket.
func fseqRowEnd(t *testing.T, w *world, dc, pc *rendr.PacketConn, id rendr.CarrierID, up, down *flow) {
	t.Helper()
	var dropped uint64
	for i, c := range []*rendr.PacketConn{dc, pc} {
		if lv := liveOf(c.Status()); len(lv) != 1 || lv[0].ID != id {
			t.Fatalf("%s: live carriers %+v, want carrier %d alone", side(i), lv, id)
		}
		if evs := [2]*eventLog{w.dev, w.pev}[i].of(rendr.EventCarrierDown); len(evs) != 0 {
			t.Fatalf("%s: carriers went down: %+v", side(i), evs)
		}
		cs, _ := carrierOf(c.Status(), id)
		dropped += cs.Dropped
	}
	for _, f := range []*flow{up, down} {
		f.integrity(t)
		f.nonBlocking(t)
	}
	endClean(t, dc, pc, up, down)
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

// pingLog records when each carrier encoded a PING (Hooks.PingTS, which
// runs under the carrier's lock: it only appends).
type pingLog struct {
	mu sync.Mutex
	at map[uint32][]time.Time
}

func (p *pingLog) note(carrier uint32, ts uint64) uint64 {
	p.mu.Lock()
	if p.at == nil {
		p.at = map[uint32][]time.Time{}
	}
	p.at[carrier] = append(p.at[carrier], time.Now())
	p.mu.Unlock()
	return ts
}

// since returns the times carrier encoded a PING at or after from.
func (p *pingLog) since(carrier uint32, from time.Time) []time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []time.Time
	for _, at := range p.at[carrier] {
		if !at.Before(from) {
			out = append(out, at)
		}
	}
	return out
}

// offsets returns ts relative to from.
func offsets(ts []time.Time, from time.Time) []time.Duration {
	out := make([]time.Duration, len(ts))
	for i, at := range ts {
		out[i] = at.Sub(from)
	}
	return out
}
