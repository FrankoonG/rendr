package race

import (
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestG4RaceMiniature: gold/G4-race (M3 design B1.6, plan:746–751) at
// reduced scale: the zero Config on both ends, two Links p1 and p2 of
// 20 ms RTT shaped to 8 MiB/s each, one race session (both members listed
// on both ends first), B → A 64 MiB of PRNG data (32 MiB under -race at
// the same 8 MiB/s per link, a 4-s timeline, R1-11: the rate stays so that
// the bytes left after the DROP still exceed the session Window well before
// the dropped member's death verdict — a lower rate would never fill the
// Window and could not catch a stalled ACK path).
//
// Stimulus: when A has received 30 % of the bytes, p1 is blackholed in
// both directions until the end (the gold's nft DROP: no RST, no ICMP;
// bytes vanish, new dials never answer, and in BlackholeCloses mode an
// end's close of its carrier does not cross either). Its member must have
// carried data (TxBytes on the passive) and the link must drop session
// bytes.
// Premise: the bytes A still lacks at the DROP exceed the session Window
// (8 MiB, the default), so a sender whose ACKs stop would exhaust it
// within Window / rate (≈ 1 s) of the DROP, long before the death verdict.
//
// PASS (§A11.2): the receiving application sees no error and no early EOF;
// delivery continues: the longest zero-delivery interval from the DROP to
// the last byte is at most one RTT of the other member + 50 ms — its RTT
// as the sending side B measured it at the DROP (SRTT; the bytes the
// dropped member carried ahead of it reach A through its queue, which the
// bulk transfer fills);
// every byte verified, then io.EOF (the data written before the DROP
// included); the dropped member recorded dead on both ends, each end's
// cause ping_timeout or write_stall (droppedCause; B1.6: the close of the
// end that decides first is swallowed, so the other end decides on its
// own: the dropped member's Link carrier shows its close held, closeHeld);
// a clean end with io.EOF on both ends and nothing left after
// Runtime.Close.
func TestG4RaceMiniature(t *testing.T) {
	size, rate := int64(64<<20), float64(8<<20)
	if raceEnabled {
		size = 32 << 20 // R1-11: the full rate on a shorter transfer
	}
	synctest.Test(t, func(t *testing.T) { g4(t, size, rate) })
}

func g4(t *testing.T, size int64, rate float64) {
	const oneWay = 10 * time.Millisecond
	w := newWorld(t, worldOpts{}, linkSpec{name: "p1", oneWay: oneWay, rate: rate}, linkSpec{name: "p2", oneWay: oneWay, rate: rate})
	dc, pc := w.open(w.peer("p1", "p2"), rendr.DialOptions{Mode: rendr.ModeRace})
	waitFor(t, 10*time.Second, "two race members on both ends", func() bool { return twoMembers(dc, pc) })

	down := startReceiver(dc, 1, size)
	up := startReceiver(pc, 2, 0)
	tx := w.startSender(pc, 1, size, 0)
	w.startSender(dc, 2, 0, 0)

	waitFor(t, time.Minute, "30 % of the bytes", func() bool { return down.got.Load() >= size*3/10 })
	victim, _ := liveNamed(dc.Status(), "p1")
	if pm, ok := carrierOf(pc.Status(), victim.ID); !ok || pm.TxBytes == 0 {
		t.Fatalf("stimulus: p1's member %d carried no data before the DROP: %+v", victim.ID, pm)
	}
	other, _ := liveNamed(dc.Status(), "p2")
	om, _ := carrierOf(pc.Status(), other.ID)
	if lack, win := size-down.got.Load(), int64(8<<20); lack <= win {
		t.Fatalf("premise: A lacks %d bytes at the DROP, want > the %d-byte Window (a stalled ACK path must be able to exhaust it)", lack, win)
	}
	l := w.link("p1")
	dropped0 := l.Stats().Session.Dropped
	target := dropTarget(t, l)
	drop := time.Now()
	l.SetBlackholeMode(rendrtest.BlackholeCloses) // an nft DROP: no close crosses either
	l.SetBlackhole(true)

	down.wait(t, 2*time.Minute)
	up.wait(t, time.Minute)
	tx.wait(t, time.Minute)
	if l.Stats().Session.Dropped == dropped0 {
		t.Fatal("stimulus: the DROP of p1 dropped no session byte")
	}
	gap, at := down.maxGap(drop, down.end())
	if limit := om.SRTT + 50*time.Millisecond; gap > limit {
		t.Errorf("delivery stalled after the DROP: a zero-delivery gap of %v at DROP +%v, want ≤ %v (p2's RTT %v at the DROP + 50 ms)",
			gap, at.Sub(drop), limit, om.SRTT)
	}
	t.Logf("DROP at +%v (p2's RTT on B %v); longest gap after it %v; transfer %v", drop.Sub(tx.start), om.SRTT, gap, down.end().Sub(tx.start))

	droppedCause(t, w, dc, pc, victim.ID, drop)
	closeHeld(t, l, target)
	finish(t, dc, pc)
	w.noViolation()
	w.close()
}
