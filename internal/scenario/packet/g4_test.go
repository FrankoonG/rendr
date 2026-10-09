package packet

import (
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestG4PktMiniature: gold/G4-pkt-sel and gold/G4-pkt-bond (M2 design
// B1.3) at reduced scale (§A8.3): the zero Config, two DatagramLinks of
// 20 ms RTT (u1, u2), one packet session with 1000-byte datagrams at 2,000
// per second B → A and 200 per second A → B (F3). After a 30-s warm-up the
// path of the carrier that carries data — selector: the dialer's active
// one; bond: B's member with the largest Tx growth over the last second
// (F13, which must be at least 25 % of B's offered bytes) — drops
// everything in both directions without an error, an RST or an ICMP
// (plan:747) until the end, starting just after a PONG of the dialer's
// PING on it (afterPong: the worst phase, so the outage is the designed
// PacketPing + D); the clean end comes 60 s later. The run is
// 90 s, not 60: the designed outage of the selector (≈ PacketPing + D +
// 2·RTT ≈ 4.05 s per direction, PA-13) must stay below 5 % of the run for
// DeliveryRatio, the rule by which the gold sizes its runs (B6).
//
// PASS (plan:748–749, B1.3): no application error and no io.EOF before
// the clean end; PktRecovery per direction (F14): every datagram lost was
// written in [T − 100 ms, T + 5 s] and a datagram written after T arrives
// within 5 s of T (the 5-s margin is logged); selector: an arrival gap of
// at least 1 s starts within W_s = one-way delay + 1 s of T, else the drop
// missed the data path (stimulus); PacketIntegrity; DeliveryRatio ≥ 0.95;
// NonBlockingWrite; the dropped carrier ends with ping_timeout or
// write_stall on both ends (E17); no order check (plan:749).
func TestG4PktMiniature(t *testing.T) {
	for _, mode := range []rendr.Mode{rendr.ModeSelector, rendr.ModeBond} {
		t.Run(mode.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { g4(t, mode) })
		})
	}
}

// recoveryBound is PktRecovery's bound (F14) and the G4-pkt expectation
// (PA-13: ≈ PacketPing + D + 2·RTT ≈ 4.05 s ≤ 5 s).
const recoveryBound = 5 * time.Second

func g4(t *testing.T, mode rendr.Mode) {
	const (
		warm    = 30 * time.Second
		observe = 60 * time.Second
	)
	w := newWorld(t, worldOpts{oneWay: goldOneWay}, "u1", "u2")
	dc, pc := w.open(w.peer("u1", "u2"), rendr.DialOptions{Mode: mode})
	if mode == rendr.ModeBond {
		waitFor(t, 10*time.Second, "both members on both ends", func() bool {
			return len(liveOf(dc.Status())) == 2 && len(liveOf(pc.Status())) == 2
		})
	}
	up := startFlow(dc, pc, flowCfg{name: "A → B", seed: 1, rate: goldRateAB})
	down := startFlow(pc, dc, flowCfg{name: "B → A", seed: 2, rate: goldRateBA})

	sleepUntil(up.start.Add(warm - time.Second))
	victim := pickDataCarrier(t, dc, pc, mode)
	vl := w.link(victim.Name)
	afterPong(t, vl)
	lost0 := vl.Stats().Session.Lost
	drop := time.Now()
	for _, d := range bothDirs {
		vl.Blackhole(d, true)
	}
	sleepUntil(drop.Add(observe))
	end := time.Now()
	endClean(t, dc, pc, up, down)
	if vl.Stats().Session.Lost == lost0 {
		t.Fatalf("stimulus: the drop of %s lost nothing", vl.Name())
	}

	droppedCause(t, w, dc, pc, victim.ID, drop)
	for _, f := range []*flow{up, down} {
		pktRecovery(t, f, drop, end, mode == rendr.ModeSelector, end)
		f.integrity(t)
		f.nonBlocking(t)
		if r := f.ratio(); r < minRatio {
			t.Fatalf("%s: delivery ratio %.4f, want ≥ %v", f.cfg.name, r, minRatio)
		}
		t.Logf("%s: %d written, %d lost (ratio %.4f)", f.cfg.name, f.accepted.Load(), len(f.losses()), f.ratio())
	}
	if mode == rendr.ModeSelector {
		if a, ok := activeOf(dc.Status()); ok && a.Name == victim.Name {
			t.Fatalf("the active carrier after the drop is on the dropped path: %+v", a)
		}
	}
	attribution(t, w, dc, pc)
	for _, d := range bothDirs {
		vl.Blackhole(d, false) // Drop.Remove()
	}
	w.noViolation()
	w.close()
}

// afterPong waits for the dialer's next PING on l and then one round trip
// and 10 ms more, so that a DROP right after it lands just after that
// PING's PONG arrived: the worst phase of the death rule (PA-13). The next
// PING is then committed about a PacketPing later and the death comes D
// after it, so the outage is PacketPing + D, not D (synctest fixes the
// phase: a drop at an arbitrary instant lands at the same phase in every
// run). The dialer's session carrier on l is the only one that PINGs at
// the PacketPing cadence; a probe carrier's PING would land the drop at an
// arbitrary phase, which the logged recovery would show.
func afterPong(t *testing.T, l *rendrtest.DatagramLink) {
	t.Helper()
	ch := l.CaptureNext(rendrtest.Up, rendrtest.FramePing)
	t0 := time.Now()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatalf("stimulus: no PING of the dialer on %s within 3 s", l.Name())
	}
	t.Logf("%s: the dialer's PING at +%v; the drop follows one round trip and 10 ms later", l.Name(), time.Since(t0))
	time.Sleep(2*goldOneWay + 10*time.Millisecond)
}

// pickDataCarrier picks the carrier that carries data (F13) over the
// coming second: selector the dialer's active carrier; bond B's member
// whose Tx grew most. Its B-side Tx growth must be at least 25 % of B's
// offered bytes (the gold's kernel cross-check), else the pick carried no
// data. The returned status is the dialer's (it has the factory name).
func pickDataCarrier(t *testing.T, dc, pc *rendr.PacketConn, mode rendr.Mode) rendr.CarrierStatus {
	t.Helper()
	tx0 := map[rendr.CarrierID]uint64{}
	for _, c := range liveOf(pc.Status()) {
		tx0[c.ID] = c.TxBytes
	}
	time.Sleep(time.Second)
	var id rendr.CarrierID
	var best uint64
	for _, c := range liveOf(pc.Status()) {
		if t0, ok := tx0[c.ID]; ok && c.TxBytes-t0 >= best {
			g := c.TxBytes - t0
			id, best = c.ID, g
		}
	}
	if mode == rendr.ModeSelector {
		a, ok := activeOf(dc.Status())
		if !ok {
			t.Fatalf("no active carrier: %+v", dc.Status())
		}
		id = a.ID
		c, _ := carrierOf(pc.Status(), id)
		best = c.TxBytes - tx0[id]
	}
	if offered := uint64(goldRateBA * 1000); best < offered/4 {
		t.Fatalf("stimulus: the picked carrier %d carried %d bytes of B's %d in the last second (< 25 %%)", id, best, offered)
	}
	c, ok := carrierOf(dc.Status(), id)
	if !ok || (c.State != rendr.CarrierActive && c.State != rendr.CarrierMember) {
		t.Fatalf("the picked carrier %d is not live on the dialer: %+v", id, c)
	}
	return c
}

// droppedCause requires that the carrier whose path was dropped at drop
// ended on both ends with ping_timeout or write_stall (E17), each by its
// own death rule within the recovery bound.
func droppedCause(t *testing.T, w *world, dc, pc *rendr.PacketConn, id rendr.CarrierID, drop time.Time) {
	t.Helper()
	for i, c := range []*rendr.PacketConn{dc, pc} {
		cs, ok := carrierOf(c.Status(), id)
		if !ok || cs.State != rendr.CarrierDead || (cs.DeathCause != rendr.CausePingTimeout && cs.DeathCause != rendr.CauseWriteStall) {
			t.Fatalf("%s: the dropped carrier %d is %+v (found %v), want dead of ping_timeout or write_stall", side(i), id, cs, ok)
		}
		ev, ok := [2]*eventLog{w.dev, w.pev}[i].downOf(id)
		if !ok || ev.Cause != cs.DeathCause || ev.Time.Sub(drop) > recoveryBound {
			t.Fatalf("%s: CarrierDown of %d: %+v (found %v), want %v within %v of the drop", side(i), id, ev, ok, cs.DeathCause, recoveryBound)
		}
		t.Logf("%s: dropped carrier %d dead +%v: %v %q", side(i), id, ev.Time.Sub(drop), cs.DeathCause, cs.DeathDetail)
	}
}

// pktRecovery applies F14 to one direction for a DROP at drop: every
// datagram written before until that was lost was written in [drop −
// 100 ms, drop + 5 s]; a datagram written after drop arrived within 5 s of
// it; selector: an arrival gap of at least 1 s starts within W_s of drop
// (the drop hit the data path), else the stimulus is not proven.
func pktRecovery(t *testing.T, f *flow, drop, until time.Time, selector bool, end time.Time) {
	t.Helper()
	for _, l := range f.losses() {
		if l.wrote.Before(until) && (l.wrote.Before(drop.Add(-100*time.Millisecond)) || l.wrote.After(drop.Add(recoveryBound))) {
			t.Fatalf("%s: seq %d, written at %+v of the drop, was lost outside [−100 ms, +5 s]", f.cfg.name, l.seq, l.wrote.Sub(drop))
		}
	}
	resume := f.firstArrivalWrittenFrom(drop)
	if resume.IsZero() || resume.Sub(drop) > recoveryBound {
		t.Fatalf("%s: the first datagram written after the drop arrived at %+v, want within %v", f.cfg.name, resume.Sub(drop), recoveryBound)
	}
	t.Logf("%s: recovery +%v (margin %v)", f.cfg.name, resume.Sub(drop), recoveryBound-resume.Sub(drop))
	if !selector {
		return
	}
	ws := goldOneWay + time.Second
	if g, at := f.gapFrom(drop, drop.Add(ws), end); g < time.Second {
		t.Fatalf("stimulus: %s: no arrival gap of 1 s within %v of the drop (longest %v at %+v): the drop missed the data path",
			f.cfg.name, ws, g, at.Sub(drop))
	}
}
