package session

import (
	"io"
	"testing"
	"testing/synctest"
	"time"
)

// The second review wave's race rows on DGRAMs a dying carrier hands back
// (pkt_handback_test.go has the first wave's, which run the death step
// first). In production the writer of the round that ends a carrier hands
// its DGRAMs back right after the carrier's death record is set
// (dgWriteBatch: killCarrier, then dgReturnUnsent), usually before the
// actor's death step for that carrier, and reapDead runs one death per
// step in attach order: these rows hand back first (dpReturn before
// dpKill), so the dying member is still a live data lane when its
// datagrams come back.

// TestPacketRaceUnsentOutage_L39 (M5 review, second wave; L39, M2-D45,
// M3-D32): two race members die together. lB placed seq 0 and its writer
// hands it back before either death step; lA's cursor is behind it.
//   - behind-first: lA is reaped first, so lB — dying, its death step not
//     run yet — is the only live cursor, and it is past the datagram. The
//     100-byte datagram is too large for nobody: it waits (the first wave
//     counted it DropTooLarge: "every live lane skipped it"), and with no
//     data lane left it ages out DropNoPath after MaxAge.
//   - placer-first: lB is reaped first; lA's cursor keeps it queued until
//     lA's death step, then the no-path ageing counts it DropNoPath.
//   - redial: as behind-first, then a member attaches before MaxAge and
//     places seq 0 again (L39: it never left): Sent 1, no drop.
//
// The send-side identity holds throughout. Mutant: a fully returned head
// counted DropTooLarge again.
func TestPacketRaceUnsentOutage_L39(t *testing.T) {
	const maxAge = 100 * time.Millisecond
	for _, tc := range []struct {
		name                string
		behindFirst, redial bool
	}{{"behind-first", true, false}, {"placer-first", false, false}, {"redial", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, ls := hbRace(t, maxAge, 2)
				lA, lB := ls[0], ls[1]
				dpWrite(t, s, 1, 100)
				bB := dpFill(lB, time.Now())
				if seqs, _ := rcDgrams(bB); len(seqs) != 1 {
					t.Fatalf("premise: lB placed %v, want the datagram", seqs)
				}
				if _, n := rcTx(s); n != 1 {
					t.Fatalf("premise: %d queued, want 1 (lA is behind it)", n)
				}
				dpReturn(lB, bB) // lB's writer, right after its carrier's death record
				first, second := lA, lB
				if !tc.behindFirst {
					first, second = lB, lA
				}
				dpKill(s, first)
				waiting := dpLocked(s, func(_ *stream, pk *packet) int { return pk.tx.n + pk.redoN() })
				if c := dpCtr(s); c.Sent != 0 || hbDrops(c) != 0 || waiting != 1 {
					t.Fatalf("after the first death step: %+v, %d waiting: a 100-byte datagram no placement of which left must wait, not count", c, waiting)
				}
				dpKill(s, second)
				if tc.redial {
					l3 := hbRaceLane(s, 3)
					got := hbDgrams(dpFrames(dpFill(l3, time.Now())))
					if len(got) != 1 || got[0].seq != 0 || dpID(got[0].body) != 1 {
						t.Fatalf("the redialed member placed %v, want the returned seq 0", got)
					}
					if c := hbIdentity(t, s, 1, "placed by the redialed member"); c.Sent != 1 || hbDrops(c) != 0 {
						t.Fatalf("%+v: want Sent 1 and no drop", c)
					}
				} else {
					time.Sleep(maxAge + time.Millisecond)
					hbAge(s)
					if c := hbIdentity(t, s, 1, "aged without a data lane"); c.DropNoPath != 1 || c.Sent != 0 || hbDrops(c) != 1 {
						t.Fatalf("%+v: want the datagram DropNoPath", c)
					}
				}
				dpEnd(s, io.EOF)
			})
		})
	}
}

// TestPacketRaceUnsentWideKept_L37 (M5 review, second wave; W4-REL-5, L37,
// M3-D32): race, l1 (1400) placed a 1000-byte datagram — queued as wide,
// above l3's 600-byte budget — and l3 skipped it, so the head passed it.
// l2 (1400) joins after that and is write-blocked; l1 returns the datagram
// and dies, so it waits in the redo list for a member that can carry it.
// l3's Fill for a 100-byte datagram written 10 ms later places that
// datagram from its own cursor: the wide returned DGRAM is left to l2
// without holding l3's cursor (the first wave stopped l3's whole Fill
// there until the entry was placed or aged out), and it is not dropped as
// too large. Once l2's write returns, l2 places the returned seq 0 and its
// own copy of seq 1. Mutant: a race member's Fill stops where the redo
// head is left to another member.
func TestPacketRaceUnsentWideKept_L37(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := dpSession(dpOpt{mode: ModeRace, maxAge: 100 * time.Millisecond})
		l1 := hbRaceLane(s, 1)
		l3 := hbRaceLane(s, 3)
		l3.port.(*dpPort).set(func(f *dpPort) { f.budget = 600 })
		s.mu.Lock()
		s.pktRecomputeLocked()
		s.mu.Unlock()
		dpIdle(l1)
		dpIdle(l3)
		dpWrite(t, s, 1, 1000)
		if wide := dpLocked(s, func(_ *stream, pk *packet) bool { return pk.tx.n == 1 && pk.tx.front().wide }); !wide {
			t.Fatal("premise: the 1000-byte datagram is not queued as wide")
		}
		b1 := dpFill(l1, time.Now())
		if seqs, _ := rcDgrams(dpFill(l3, time.Now())); len(seqs) != 0 {
			t.Fatalf("premise: l3 placed %v, want none (too large for its budget)", seqs)
		}
		if _, n := rcTx(s); n != 0 {
			t.Fatalf("premise: %d queued, want 0 (the head passed it)", n)
		}
		l2 := hbRaceLane(s, 2) // its cursor starts behind nothing: it cannot reach seq 0
		p2 := l2.port.(*dpPort)
		p2.set(func(f *dpPort) { f.blocked = true })
		dpReturn(l1, b1)
		dpKill(s, l1)
		if n := dpLocked(s, func(_ *stream, pk *packet) int { return pk.redoN() }); n != 1 {
			t.Fatalf("premise: %d returned DGRAMs waiting, want 1", n)
		}
		time.Sleep(10 * time.Millisecond)
		dpWrite(t, s, 2, 100)
		got := hbDgrams(dpFrames(dpFill(l3, time.Now())))
		c := dpCtr(s)
		waiting := dpLocked(s, func(_ *stream, pk *packet) int { return pk.redoN() })
		if len(got) != 1 || got[0].seq != 1 || dpID(got[0].body) != 2 || c.DropTooLarge != 0 || waiting != 1 {
			t.Fatalf("l3 placed %v with %+v, %d waiting: want its own seq 1 and the wide returned DGRAM left to l2", got, c, waiting)
		}
		p2.set(func(f *dpPort) { f.blocked = false })
		got = hbDgrams(dpFrames(dpFill(l2, time.Now())))
		if len(got) != 2 || got[0].seq != 0 || len(got[0].body) != 1000 || dpID(got[0].body) != 1 || got[1].seq != 1 {
			t.Fatalf("once its write returned l2 placed %v, want the returned seq 0, then seq 1", got)
		}
		copies := dpLocked(s, func(_ *stream, pk *packet) uint64 { return pk.copies })
		if c := hbIdentity(t, s, 2, "placed by l2"); c.Sent != 2 || hbDrops(c) != 0 || copies != 1 {
			t.Fatalf("%+v with Race.Copies %d: want Sent 2, no drop and l2's copy of seq 1", c, copies)
		}
		dpEnd(s, io.EOF)
	})
}

// TestPacketRaceUnsentMovedWakes_L39 (M5 review, second wave; L39,
// M3-D30): a fully returned datagram that leaves the ring for the redo
// list at the end of a member's Fill wakes the member that can carry it.
// l1 (1400) placed a 1000-byte datagram; lG skipped it while its budget was
// 600 and then grew back to 1400 (its cursor is past it); lS (600) is
// behind it. l1 returns it and dies, so the ring keeps it for lS. lS's
// Fill skips it as too large, the head passes it, and it joins the redo
// list: lG, idle, is woken and places it. Mutant: no wake after the move
// (lG stays idle with the datagram waiting).
func TestPacketRaceUnsentMovedWakes_L39(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := dpSession(dpOpt{mode: ModeRace, maxAge: time.Second})
		l1 := hbRaceLane(s, 1)
		lG := hbRaceLane(s, 2)
		lS := hbRaceLane(s, 3)
		pG := lG.port.(*dpPort)
		pG.set(func(f *dpPort) { f.budget = 600 })
		lS.port.(*dpPort).set(func(f *dpPort) { f.budget = 600 })
		s.mu.Lock()
		s.pktRecomputeLocked()
		s.mu.Unlock()
		for _, l := range []*lane{l1, lG, lS} {
			dpIdle(l)
		}
		dpWrite(t, s, 1, 1000)
		b1 := dpFill(l1, time.Now())
		if seqs, _ := rcDgrams(dpFill(lG, time.Now())); len(seqs) != 0 {
			t.Fatalf("premise: lG placed %v at a 600-byte budget", seqs)
		}
		dpReturn(l1, b1)
		dpKill(s, l1)
		pG.set(func(f *dpPort) { f.budget = 1400 })
		s.mu.Lock()
		s.pktRecomputeLocked()
		s.mu.Unlock()
		dpIdle(lG) // its cursor is past the datagram, which the ring keeps for lS
		if _, n := rcTx(s); n != 1 {
			t.Fatalf("premise: %d queued, want 1 (lS is behind it)", n)
		}
		w0 := pG.wakeCount()
		if seqs, _ := rcDgrams(dpFill(lS, time.Now())); len(seqs) != 0 {
			t.Fatalf("premise: lS placed %v, want none (too large for its budget)", seqs)
		}
		if n := dpLocked(s, func(_ *stream, pk *packet) int { return pk.tx.n + pk.redoN() }); n != 1 || pG.wakeCount() == w0 {
			t.Fatalf("after lS's Fill: %d waiting, lG woken %v: want the datagram in the redo list and lG woken", n, pG.wakeCount() != w0)
		}
		got := hbDgrams(dpFrames(dpFill(lG, time.Now())))
		if len(got) != 1 || got[0].seq != 0 || dpID(got[0].body) != 1 {
			t.Fatalf("lG placed %v, want the returned seq 0", got)
		}
		if c := hbIdentity(t, s, 1, "placed by lG"); c.Sent != 1 || hbDrops(c) != 0 {
			t.Fatalf("%+v: want Sent 1 and no drop", c)
		}
		dpEnd(s, io.EOF)
	})
}
