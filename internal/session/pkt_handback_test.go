package session

import (
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The M5 review's rows on DGRAMs a dying carrier hands back (pktloss's
// path: carrier.DgramReturner, plane.Unsent, pktUnsentLocked): a race
// hand-back is decided by the datagram's placements, not by the members'
// liveness (A1, A2); a returned DGRAM keeps its age from WriteTo (D2-1)
// and its wide mark (A5); the FIN waits for the returned DGRAMs (A4); the
// redo list is bounded (A6). Fake ports and real batches (the dp harness);
// dpReturn hands a batch's DGRAMs back as the carrier's writer does.

// hbRaceLane adds a datagram lane to race session s that joins its data
// set now (its cursor at the tx head, as an attach), with a bare carrier
// identity (no death record).
func hbRaceLane(s *Session, id uint32) *lane {
	l, _ := dpAddLane(s, id, false, true)
	l.c = &carrier.Conn{}
	rcRaceLane(s, l)
	s.mu.Lock()
	s.pktRecomputeLocked()
	s.pktWakeLocked(time.Now())
	s.mu.Unlock()
	return l
}

// hbRace is a race session with n datagram members, each idle.
func hbRace(t *testing.T, maxAge time.Duration, n int) (*Session, []*lane) {
	t.Helper()
	s := dpSession(dpOpt{mode: ModeRace, maxAge: maxAge})
	var ls []*lane
	for i := range n {
		ls = append(ls, hbRaceLane(s, uint32(i+1)))
	}
	for _, l := range ls {
		dpIdle(l)
	}
	return s, ls
}

// hbDrops is the sum of the send-side drop counters.
func hbDrops(c PacketCounters) uint64 {
	return c.DropQueue + c.DropAge + c.DropTooLarge + c.DropNoPath
}

// hbIdentity checks the send-side identity of s once its tx queue is
// empty: Sent + every drop + the returned DGRAMs still waiting = the
// datagrams written.
func hbIdentity(t *testing.T, s *Session, writes uint64, when string) PacketCounters {
	t.Helper()
	q := dpLocked(s, func(_ *stream, pk *packet) [2]int { return [2]int{pk.tx.n, pk.redoN()} })
	if q[0] != 0 {
		t.Fatalf("%s: %d datagrams still queued (the identity is checked on an empty queue)", when, q[0])
	}
	c := dpCtr(s)
	if c.Sent+hbDrops(c)+uint64(q[1]) != writes {
		t.Fatalf("%s: %+v with %d returned DGRAMs waiting, want the %d written", when, c, q[1], writes)
	}
	return c
}

// hbAge runs the actor's no-path ageing at now.
func hbAge(s *Session) {
	s.mu.Lock()
	s.pktAgeLocked(time.Now())
	s.mu.Unlock()
}

// hbDgrams returns the DGRAM frames of fs.
func hbDgrams(fs []dpFrame) []dpFrame {
	var out []dpFrame
	for _, f := range fs {
		if f.typ == wire.TypeDgram {
			out = append(out, f)
		}
	}
	return out
}

// TestPacketRaceUnsentCoveredNeverLeft_L39 (M5 review A1; L39, M3-D32): a
// race DGRAM whose returned copy was the only placement of it that may
// have left is not "covered" by another live member. In each case the
// send-side identity holds and Sent counts only the datagrams with a
// placement that may have left:
//   - lags: l1 places seq 0 and returns it while l2 lives; l2 fills only
//     after MaxAge: DropAge 1, Sent 0 (the old rule kept it in Sent and the
//     head dropped it as sent);
//   - dies: l2 dies before its cursor reaches it; the actor's no-path
//     ageing after MaxAge: DropNoPath 1, Sent 0;
//   - redo, redo-late: l1 and l2 both placed seq 0 (the head passed it) and
//     both return it; l3, joining later, places it again from the redo list
//     and returns it while l4 lives: l4 places it (Sent 1), or, filling only
//     after MaxAge, counts DropAge 1 (no live cursor can reach a popped
//     descriptor);
//   - behind: l2's cursor has not reached the returned datagram: l2 places
//     it once, and Race.Copies stays 0 (the returned copy left the count).
//
// Mutants: coverage decided by liveness (the old raceCoveredLocked); pc
// not decremented at a hand-back.
func TestPacketRaceUnsentCoveredNeverLeft_L39(t *testing.T) {
	const maxAge = 100 * time.Millisecond
	t.Run("lags", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, ls := hbRace(t, maxAge, 2)
			dpWrite(t, s, 1, 100)
			b1 := dpFill(ls[0], time.Now())
			if n := dpCount(dpFrames(b1), wire.TypeDgram); n != 1 {
				t.Fatalf("premise: l1 placed %d DGRAMs, want 1", n)
			}
			dpKill(s, ls[0])
			dpReturn(ls[0], b1)
			time.Sleep(maxAge + time.Millisecond)
			if fs := dpFrames(dpFill(ls[1], time.Now())); dpCount(fs, wire.TypeDgram) != 0 {
				t.Fatalf("the lagging member placed a datagram older than MaxAge: %v", fs)
			}
			if c := hbIdentity(t, s, 1, "aged on the lagging member"); c.DropAge != 1 || c.Sent != 0 {
				t.Fatalf("a returned datagram no placement of which left: %+v, want DropAge 1 and Sent 0", c)
			}
			dpEnd(s, io.EOF)
		})
	})
	t.Run("dies", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, ls := hbRace(t, maxAge, 2)
			dpWrite(t, s, 1, 100)
			b1 := dpFill(ls[0], time.Now())
			dpKill(s, ls[0])
			dpReturn(ls[0], b1)
			dpKill(s, ls[1]) // before its cursor reached the datagram
			time.Sleep(maxAge + time.Millisecond)
			hbAge(s)
			if c := hbIdentity(t, s, 1, "aged without a data lane"); c.DropNoPath != 1 || c.Sent != 0 {
				t.Fatalf("a returned datagram whose covering member died: %+v, want DropNoPath 1 and Sent 0", c)
			}
			dpEnd(s, io.EOF)
		})
	})
	for _, late := range []bool{false, true} {
		name := "redo"
		if late {
			name = "redo-late"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, ls := hbRace(t, maxAge, 2)
				dpWrite(t, s, 1, 100)
				b1 := dpFill(ls[0], time.Now())
				b2 := dpFill(ls[1], time.Now())
				if _, n := rcTx(s); n != 0 {
					t.Fatalf("premise: %d queued after both members placed it, want 0 (the head passed it)", n)
				}
				dpKill(s, ls[0])
				dpKill(s, ls[1])
				dpReturn(ls[0], b1)
				dpReturn(ls[1], b2)
				l3 := hbRaceLane(s, 3)
				l4 := hbRaceLane(s, 4)
				b3 := dpFill(l3, time.Now())
				if got := hbDgrams(dpFrames(b3)); len(got) != 1 || got[0].seq != 0 || dpID(got[0].body) != 1 {
					t.Fatalf("premise: l3 placed %v, want the returned seq 0 again", got)
				}
				dpKill(s, l3)
				dpReturn(l3, b3)
				if late {
					time.Sleep(maxAge + time.Millisecond)
				}
				got := hbDgrams(dpFrames(dpFill(l4, time.Now())))
				c := hbIdentity(t, s, 1, "after l4's Fill")
				switch {
				case !late && (len(got) != 1 || got[0].seq != 0 || dpID(got[0].body) != 1 || c.Sent != 1 || hbDrops(c) != 0):
					t.Fatalf("l4 placed %v with %+v: want the returned seq 0 placed once more and Sent 1", got, c)
				case late && (len(got) != 0 || c.DropAge != 1 || c.Sent != 0):
					t.Fatalf("l4 placed %v with %+v after MaxAge: want nothing and DropAge 1", got, c)
				}
				dpEnd(s, io.EOF)
			})
		})
	}
	t.Run("behind", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, ls := hbRace(t, maxAge, 2)
			dpWrite(t, s, 1, 100)
			b1 := dpFill(ls[0], time.Now())
			dpKill(s, ls[0])
			dpReturn(ls[0], b1)
			got := hbDgrams(dpFrames(dpFill(ls[1], time.Now())))
			if len(got) != 1 || got[0].seq != 0 || dpID(got[0].body) != 1 {
				t.Fatalf("the member behind placed %v, want seq 0 once", got)
			}
			copies := dpLocked(s, func(_ *stream, pk *packet) uint64 { return pk.copies })
			if c := hbIdentity(t, s, 1, "placed by the member behind"); c.Sent != 1 || copies != 0 {
				t.Fatalf("%+v with Race.Copies %d: want Sent 1 and no copy (the returned one never left)", c, copies)
			}
			dpEnd(s, io.EOF)
		})
	})
}

// TestPacketRaceUnsentWrittenCopy_L39 (M5 review A2; L39, M3-D35): a race
// copy a dying member returns while the datagram's other placement was
// written — l1's batch reached the passive (Received 1) — leaves Race.Copies
// only, also after both members died: Sent 1, no drop counter, Copies 0,
// and the settled PeerReceived (the passive's Received) never exceeds Sent.
// Variants: the no-path ageing after MaxAge, and the session's end before
// the hand-back. The old rule saw no live member and took the copy out of
// Sent, then counted it DropNoPath or DropQueue while the peer had it.
func TestPacketRaceUnsentWrittenCopy_L39(t *testing.T) {
	for _, tc := range []struct {
		name        string
		noPath, end bool
	}{{"settled", false, false}, {"no-path", true, false}, {"after-end", false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const maxAge = 100 * time.Millisecond
				p := dpNewPair(dpOpt{mode: ModeRace, maxAge: maxAge}, dpOpt{mode: ModeRace}, true, true)
				rcPktRace(p.a.s)
				rcPktRace(p.b.s)
				a := p.a.s
				for _, l := range p.a.ls {
					l.c = &carrier.Conn{}
				}
				dpWrite(t, a, 1, 100)
				b1 := dpFill(p.a.ls[0], time.Now())
				if err := dpDeliver(b1, p.b.ls[0], 0, nil); err != nil {
					t.Fatal(err)
				}
				b1.ReleaseRefs()
				if r := dpCtr(p.b.s).Received; r != 1 {
					t.Fatalf("premise: the passive received %d, want l1's datagram", r)
				}
				b2 := dpFill(p.a.ls[1], time.Now())
				if seqs, _ := rcDgrams(b2); len(seqs) != 1 || seqs[0] != 0 {
					t.Fatalf("premise: l2 placed %v, want the copy of seq 0", seqs)
				}
				dpKill(a, p.a.ls[0])
				dpKill(a, p.a.ls[1])
				if tc.end {
					dpEnd(a, io.EOF)
				}
				dpReturn(p.a.ls[1], b2)
				if tc.noPath {
					time.Sleep(maxAge + time.Millisecond)
					hbAge(a)
				}
				c := dpCtr(a)
				copies := dpLocked(a, func(_ *stream, pk *packet) uint64 { return pk.copies })
				if c.Sent != 1 || hbDrops(c) != 0 || copies != 0 {
					t.Fatalf("a copy returned after the datagram was written: %+v, Race.Copies %d: want Sent 1, no drop, no copy", c, copies)
				}
				if r := dpCtr(p.b.s).Received; r > c.Sent {
					t.Fatalf("the passive received %d, the sender's Sent is %d: PeerReceived would exceed Sent", r, c.Sent)
				}
				dpEnd(a, io.EOF)
				dpEnd(p.b.s, io.EOF)
			})
		})
	}
}

// TestPacketUnsentAgesFromWriteTo_L40 (M5 review D2-1; plan:286, M2-D35,
// L40): a returned DGRAM keeps its age from WriteTo. A round that blocks
// for its stall window (2–4 s by default) is handed back long after its
// WriteTo; with MaxAge 100 ms it must count DropAge, never reach the next
// data lane stale. bond (the surviving member), selector (the failover
// lane) and race (a member that joins after the only one placed it, so the
// redo list holds it): the next Fill carries no DGRAM and DropAge is 1.
// aged-after-return: returned 60 ms after its WriteTo and filled 60 ms
// later, it is older than MaxAge since WriteTo though not since the
// hand-back: DropAge. young: returned 50 ms after its WriteTo it is placed
// again (pktloss's purpose). Mutant: predo.at = the hand-back time.
func TestPacketUnsentAgesFromWriteTo_L40(t *testing.T) {
	const maxAge = 100 * time.Millisecond
	for _, tc := range []struct {
		name          string
		mode          Mode
		before, after time.Duration // sleep between the Fill and the hand-back, and after it
		placed        bool
	}{
		{"bond", ModeBond, 2 * time.Second, 0, false},
		{"selector", ModeSelector, 2 * time.Second, 0, false},
		{"race", ModeRace, 2 * time.Second, 0, false},
		{"aged-after-return", ModeBond, 60 * time.Millisecond, 60 * time.Millisecond, false},
		{"young", ModeBond, 50 * time.Millisecond, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := dpSession(dpOpt{mode: tc.mode, maxAge: maxAge})
				var l1, l2 *lane
				switch tc.mode {
				case ModeRace:
					l1 = hbRaceLane(s, 1)
				case ModeSelector:
					l1, _ = dpAddLane(s, 1, true, true)
					l2, _ = dpAddLane(s, 2, false, true)
				default:
					l1, _ = dpAddLane(s, 1, true, true)
					l2, _ = dpAddLane(s, 2, true, true)
					dpIdle(l2)
				}
				dpIdle(l1)
				dpWrite(t, s, 1, 100)
				b := dpFill(l1, time.Now())
				if n := dpCount(dpFrames(b), wire.TypeDgram); n != 1 {
					t.Fatalf("premise: l1 placed %d DGRAMs, want 1", n)
				}
				time.Sleep(tc.before) // the round's write blocks
				switch tc.mode {
				case ModeRace:
					if _, n := rcTx(s); n != 0 {
						t.Fatalf("premise: %d queued, want 0 (the only member passed it)", n)
					}
					l2 = hbRaceLane(s, 2)
				case ModeSelector:
					dpRoute(s, l2, true)
				}
				dpKill(s, l1)
				dpReturn(l1, b)
				time.Sleep(tc.after)
				got := hbDgrams(dpFrames(dpFill(l2, time.Now())))
				c := hbIdentity(t, s, 1, "after the next Fill")
				if tc.placed {
					if len(got) != 1 || got[0].seq != 0 || dpID(got[0].body) != 1 || c.Sent != 1 || hbDrops(c) != 0 {
						t.Fatalf("a returned datagram younger than MaxAge: placed %v with %+v, want seq 0 again and Sent 1", got, c)
					}
				} else if len(got) != 0 || c.DropAge != 1 || c.Sent != 0 {
					t.Fatalf("a returned datagram older than MaxAge since its WriteTo: placed %v with %+v, want nothing and DropAge 1", got, c)
				}
				dpEnd(s, io.EOF)
			})
		})
	}
}

// TestPacketUnsentAgeOrder_L40 (M5 review D2-1; M2-D35): returned DGRAMs
// are aged by their own WriteTo, whatever order the dying carriers hand
// them back in. Bond: X1 placed on l1, X2 placed 60 ms later on l2; both
// die and l2 returns X2 before l1 returns X1. Without a data lane, 50 ms
// later the actor's ageing drops X1 (110 ms old: DropNoPath) though X2
// (50 ms old) came back first, keeps X2 and returns X2's age-out as the
// next deadline. Mutant: the redo list kept in hand-back order (its head
// is younger than an entry behind it).
func TestPacketUnsentAgeOrder_L40(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const maxAge = 100 * time.Millisecond
		s := dpSession(dpOpt{mode: ModeBond, maxAge: maxAge})
		l1, _ := dpAddLane(s, 1, true, true)
		l2, _ := dpAddLane(s, 2, true, true)
		dpIdle(l1)
		dpIdle(l2)
		dpWrite(t, s, 1, 100)
		b1 := dpFill(l1, time.Now())
		time.Sleep(60 * time.Millisecond)
		dpWrite(t, s, 2, 100)
		t2 := time.Now()
		b2 := dpFill(l2, time.Now())
		if dpCount(dpFrames(b1), wire.TypeDgram) != 1 || dpCount(dpFrames(b2), wire.TypeDgram) != 1 {
			t.Fatal("premise: each member placed one datagram")
		}
		dpKill(s, l1)
		dpKill(s, l2)
		dpReturn(l2, b2)
		dpReturn(l1, b1)
		time.Sleep(50 * time.Millisecond)
		s.mu.Lock()
		next := s.pktAgeLocked(time.Now())
		s.mu.Unlock()
		c := dpCtr(s)
		waiting := dpLocked(s, func(_ *stream, pk *packet) int { return pk.redoN() })
		if c.DropNoPath != 1 || waiting != 1 || c.Sent != 0 {
			t.Fatalf("after 50 ms without a data lane: %+v, %d waiting: want X1 (110 ms old) DropNoPath and X2 (50 ms old) kept", c, waiting)
		}
		if want := t2.Add(maxAge + 1); !next.Equal(want) {
			t.Fatalf("pktAgeLocked returned %v after X2's WriteTo, want X2's age-out %v", next.Sub(t2), want.Sub(t2))
		}
		dpEnd(s, io.EOF)
		if c := dpCtr(s); c.Sent+hbDrops(c) != 2 {
			t.Fatalf("at the end: %+v, want both datagrams counted", c)
		}
	})
}

// TestPacketFinAfterReturned_L40 (M5 review A4; L40, M2 design §A5.6:
// queued datagrams still leave while younger than MaxAge, then the FIN):
// the datagram member dies with seq 0 in its round, the stream member takes
// over at capacity 0, then Close. No FIN while the returned DGRAM waits;
// once capacity frees, the DGRAM and then the FIN are placed, and the peer
// reads the datagram before io.EOF with no DropLate (the old rule placed
// the FIN first: the peer delivered io.EOF at its straggler bound and
// counted the datagram late). selector, and race (the only datagram member
// placed it, so the redo list holds it). race-ring: the ring keeps the
// returned datagram for a member behind it (finAfterReturnedRing).
// race-too-large, race-too-large-dying: a returned datagram no live member
// can carry does not hold our FIN (finAfterTooLarge). after-peer-fin: a
// DGRAM handed back after a peer FIN that came before ours was requested
// is DropQueue at once (PA-6: nothing queued is worth sending) and does
// not hold our FIN; after-our-fin: one handed back after the peer's FIN
// that answered ours is placed again (finAfterOursReturned). Mutants: the
// FIN without the redo check (selector; race); the race FIN without the
// ring's returned-datagram check (race-ring); a fully returned head moved
// to the redo list though no live member can carry it (race-too-large); a
// hand-back after the peer's FIN kept (after-peer-fin); a hand-back after
// any peer FIN dropped (after-our-fin).
func TestPacketFinAfterReturned_L40(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(t *testing.T)
	}{
		{"selector", func(t *testing.T) { finAfterReturned(t, ModeSelector, false) }},
		{"race", func(t *testing.T) { finAfterReturned(t, ModeRace, false) }},
		{"after-peer-fin", func(t *testing.T) { finAfterReturned(t, ModeSelector, true) }},
		{"race-ring", finAfterReturnedRing},
		{"race-too-large", func(t *testing.T) { finAfterTooLarge(t, false) }},
		{"race-too-large-dying", func(t *testing.T) { finAfterTooLarge(t, true) }},
		{"after-our-fin", finAfterOursReturned},
	} {
		t.Run(tc.name, func(t *testing.T) { synctest.Test(t, tc.run) })
	}
}

func finAfterReturned(t *testing.T, mode Mode, peerFin bool) {
	p := dpNewPair(dpOpt{mode: mode, maxAge: time.Second}, dpOpt{mode: mode}, true, false)
	a, b := p.a.s, p.b.s
	for _, sd := range []*dpSide{&p.a, &p.b} {
		for _, l := range sd.ls {
			l.c = &carrier.Conn{}
		}
	}
	dl, sl := p.a.ls[0], p.a.ls[1] // the datagram member, the stream member
	if mode == ModeRace {
		rcRaceLane(a, dl)
		a.mu.Lock()
		a.pktRecomputeLocked()
		a.mu.Unlock()
	}
	dpIdle(dl)
	dpWrite(t, a, 1, 100)
	b0 := dpFill(dl, time.Now())
	if n := dpCount(dpFrames(b0), wire.TypeDgram); n != 1 {
		t.Fatalf("premise: the datagram member placed %d DGRAMs, want 1", n)
	}
	if _, n := rcTx(a); mode == ModeRace && n != 0 {
		t.Fatalf("premise: %d queued, want 0 (the only member passed it)", n)
	}
	dpKill(a, dl)
	dpKill(b, p.b.ls[0])
	p.a.ps[1].set(func(f *dpPort) { f.capacity = 0 })
	if mode == ModeRace {
		rcRaceLane(a, sl)
		a.mu.Lock()
		a.pktRecomputeLocked()
		a.mu.Unlock()
	} else {
		dpRoute(a, sl, true)
	}
	if peerFin {
		if err := dpSendFin(sl, 0); err != nil {
			t.Fatal(err)
		}
		dpReturn(dl, b0)
		fs := dpFrames(dpFill(sl, time.Now()))
		c := dpCtr(a)
		waiting := dpLocked(a, func(_ *stream, pk *packet) int { return pk.redoN() })
		if dpCount(fs, wire.TypeFin) != 1 || dpCount(fs, wire.TypeDgram) != 0 || c.DropQueue != 1 || c.Sent != 0 || waiting != 0 {
			t.Fatalf("returned after the peer's FIN: placed %v with %+v, %d waiting: want our FIN at once and the DGRAM DropQueue", fs, c, waiting)
		}
		dpEnd(a, io.EOF)
		dpEnd(b, io.EOF)
		return
	}
	dpReturn(dl, b0)
	dpClose(a)
	b1 := dpFill(sl, time.Now())
	if fs := dpFrames(b1); dpCount(fs, wire.TypeFin) != 0 || dpCount(fs, wire.TypeDgram) != 0 {
		t.Fatalf("at capacity 0 the stream member placed %v: the FIN must wait for the returned DGRAM", fs)
	}
	if err := dpDeliver(b1, p.b.ls[1], 1, nil); err != nil {
		t.Fatal(err)
	}
	b1.ReleaseRefs()
	time.Sleep(100 * time.Millisecond) // beyond the peer's EOF straggler bound (50 ms)
	b.mu.Lock()
	b.pktPeerFinCheckLocked(time.Now())
	b.mu.Unlock()
	p.a.ps[1].set(func(f *dpPort) { f.capacity = 1 << 40 })
	b2 := dpFill(sl, time.Now())
	var order []dpFrame
	for _, f := range dpFrames(b2) {
		if f.typ == wire.TypeDgram || f.typ == wire.TypeFin {
			order = append(order, f)
		}
	}
	if len(order) != 2 || order[0].typ != wire.TypeDgram || order[0].seq != 0 || order[1].typ != wire.TypeFin || order[1].fin != 1 {
		t.Fatalf("once capacity freed the stream member placed %v, want DGRAM(0) then FIN(1)", order)
	}
	if err := dpDeliver(b2, p.b.ls[1], 1, nil); err != nil {
		t.Fatal(err)
	}
	b2.ReleaseRefs()
	got := dpReadEOF(t, b)
	if len(got) != 1 || dpID(got[0]) != 1 {
		t.Fatalf("the peer read %d datagrams before io.EOF, want the returned one", len(got))
	}
	if c := dpCtr(b); c.DropLate != 0 || c.Received != 1 {
		t.Fatalf("the peer's counters %+v: the returned datagram arrived after its FIN", c)
	}
	dpEnd(a, io.EOF)
	dpEnd(b, io.EOF)
}

// hbDrain runs l's Fill until it appends nothing (as dpIdle) and returns
// every frame placed meanwhile.
func hbDrain(l *lane) []dpFrame {
	var out []dpFrame
	for range 64 {
		b := dpFill(l, time.Now())
		fs := dpFrames(b)
		b.ReleaseRefs()
		if len(fs) == 0 {
			return out
		}
		out = append(out, fs...)
	}
	panic("hbDrain: the lane never went idle")
}

// finAfterReturnedRing (race-ring; M5 review, second wave; L40): race with
// mixed budgets. l1 (1400) placed the datagram, l3 (600) skipped it as too
// large and is at the queue's end, and l2 (1400) is behind it and
// write-blocked, so when l1's writer hands it back — before l1's death
// step, as in production — the ring keeps it for l2 (pkt_unsent.go). After
// Close l3 places no FIN while it waits (the old rule placed it: l3 had
// passed every queued datagram and this one had its seq). Once l2's write
// returns, l2 places the datagram and then our FIN, and the peer reads it
// before io.EOF with no DropLate.
func finAfterReturnedRing(t *testing.T) {
	p := dpNewPair(dpOpt{mode: ModeRace, maxAge: time.Second}, dpOpt{mode: ModeRace}, true, true, true)
	rcPktRace(p.a.s)
	rcPktRace(p.b.s)
	a, b := p.a.s, p.b.s
	for _, sd := range []*dpSide{&p.a, &p.b} {
		for _, l := range sd.ls {
			l.c = &carrier.Conn{}
		}
	}
	l1, l2, l3 := p.a.ls[0], p.a.ls[1], p.a.ls[2]
	p.a.ps[2].set(func(f *dpPort) { f.budget = 600 })
	a.mu.Lock()
	a.pktRecomputeLocked()
	a.mu.Unlock()
	for _, l := range p.a.ls {
		dpIdle(l)
	}
	p.a.ps[1].set(func(f *dpPort) { f.blocked = true })
	dpWrite(t, a, 1, 1000)
	b1 := dpFill(l1, time.Now())
	if seqs, _ := rcDgrams(b1); len(seqs) != 1 {
		t.Fatalf("premise: l1 placed %v, want the datagram", seqs)
	}
	if seqs, _ := rcDgrams(dpFill(l3, time.Now())); len(seqs) != 0 {
		t.Fatalf("premise: l3 placed %v, want none (too large for its budget)", seqs)
	}
	if _, n := rcTx(a); n != 1 {
		t.Fatalf("premise: %d queued, want 1 (l2 is behind it)", n)
	}
	dpReturn(l1, b1)
	dpKill(a, l1)
	dpKill(b, p.b.ls[0])
	dpClose(a)
	b3 := dpFill(l3, time.Now())
	if fs := dpFrames(b3); dpCount(fs, wire.TypeFin) != 0 {
		t.Fatalf("l3 placed %v: our FIN must wait for the returned datagram the ring keeps for l2", fs)
	}
	if err := dpDeliver(b3, p.b.ls[2], 2, nil); err != nil {
		t.Fatal(err)
	}
	b3.ReleaseRefs()
	time.Sleep(100 * time.Millisecond) // beyond the peer's EOF straggler bound (50 ms)
	b.mu.Lock()
	b.pktPeerFinCheckLocked(time.Now())
	b.mu.Unlock()
	p.a.ps[1].set(func(f *dpPort) { f.blocked = false })
	b2 := dpFill(l2, time.Now())
	var order []dpFrame
	for _, f := range dpFrames(b2) {
		if f.typ == wire.TypeDgram || f.typ == wire.TypeFin {
			order = append(order, f)
		}
	}
	if len(order) != 2 || order[0].typ != wire.TypeDgram || order[0].seq != 0 || order[1].typ != wire.TypeFin || order[1].fin != 1 {
		t.Fatalf("once its write returned l2 placed %v, want DGRAM(0) then FIN(1)", order)
	}
	if err := dpDeliver(b2, p.b.ls[1], 1, nil); err != nil {
		t.Fatal(err)
	}
	b2.ReleaseRefs()
	got := dpReadEOF(t, b)
	if len(got) != 1 || dpID(got[0]) != 1 {
		t.Fatalf("the peer read %d datagrams before io.EOF, want the returned one", len(got))
	}
	if c := dpCtr(b); c.DropLate != 0 || c.Received != 1 {
		t.Fatalf("the peer's counters %+v: the returned datagram arrived after its FIN", c)
	}
	if c := dpCtr(a); c.Sent != 1 || hbDrops(c) != 0 {
		t.Fatalf("the sender's counters %+v, want Sent 1 and no drop", c)
	}
	dpEnd(a, io.EOF)
	dpEnd(b, io.EOF)
}

// finAfterTooLarge (race-too-large, race-too-large-dying; M5 review,
// second wave; M2-D45, L40): race, l1 (1400) placed a 1000-byte datagram
// and its writer hands it back; l3 (600), the only other member, is behind
// it and can never carry it. Once l1's death step ran no live member can
// carry it: l3's Fill after Close counts it DropTooLarge and places our FIN
// in the same batch (it neither waits in the redo list nor holds the FIN).
// dying: l3 drains before l1's death step — l1 may still count as a member
// that can carry it, so it may wait and our FIN with it — and then the
// death step wakes l3 for whatever is still due: our FIN goes out once and
// the datagram is counted DropTooLarge once.
func finAfterTooLarge(t *testing.T, dying bool) {
	s := dpSession(dpOpt{mode: ModeRace, maxAge: time.Second})
	l1 := hbRaceLane(s, 1)
	l3 := hbRaceLane(s, 3)
	p3 := l3.port.(*dpPort)
	p3.set(func(f *dpPort) { f.budget = 600 })
	s.mu.Lock()
	s.pktRecomputeLocked()
	s.mu.Unlock()
	dpIdle(l1)
	dpIdle(l3)
	dpWrite(t, s, 1, 1000)
	b1 := dpFill(l1, time.Now())
	if seqs, _ := rcDgrams(b1); len(seqs) != 1 {
		t.Fatalf("premise: l1 placed %v, want the datagram", seqs)
	}
	if _, n := rcTx(s); n != 1 {
		t.Fatalf("premise: %d queued, want 1 (l3 is behind it)", n)
	}
	dpReturn(l1, b1)
	if !dying {
		dpKill(s, l1)
		dpClose(s)
		fs := dpFrames(dpFill(l3, time.Now()))
		if dpCount(fs, wire.TypeFin) != 1 || dpCount(fs, wire.TypeDgram) != 0 {
			t.Fatalf("l3's Fill after Close placed %v: want our FIN at once, the datagram no live member can carry counted", fs)
		}
		if c := hbIdentity(t, s, 1, "after l3's Fill"); c.DropTooLarge != 1 || c.Sent != 0 || hbDrops(c) != 1 {
			t.Fatalf("%+v: want the datagram DropTooLarge", c)
		}
		dpEnd(s, io.EOF)
		return
	}
	dpClose(s)
	fs := hbDrain(l3)
	w0 := p3.wakeCount()
	dpKill(s, l1)
	if dpCount(fs, wire.TypeFin) == 0 && p3.wakeCount() == w0 {
		t.Fatalf("l3 placed %v before l1's death step, and the death step did not wake it for our FIN", fs)
	}
	fs = append(fs, hbDrain(l3)...)
	if dpCount(fs, wire.TypeFin) != 1 || dpCount(fs, wire.TypeDgram) != 0 {
		t.Fatalf("l3 placed %v by l1's death step: want our FIN once and no DGRAM", fs)
	}
	if c := hbIdentity(t, s, 1, "after l1's death step"); c.DropTooLarge != 1 || c.Sent != 0 || hbDrops(c) != 1 {
		t.Fatalf("%+v: want the datagram DropTooLarge", c)
	}
	dpEnd(s, io.EOF)
}

// finAfterOursReturned (after-our-fin; M5 review, second wave; PA-6, L39,
// L40): bond, and we close first. Our last datagram is in l1's round, in
// flight, when our FIN goes out on l2; the peer answers with its FIN at
// once (PA-6 at the peer) and still waits for seq 0, which is below our
// final seq. Then l1's round fails and hands seq 0 back. The peer's FIN
// came after ours was requested, so the send queue was not released and
// the returned DGRAM follows it: placed again on l2 and read by the peer
// before io.EOF, with no drop counted (the first wave counted it
// DropQueue: the peer never got it).
func finAfterOursReturned(t *testing.T) {
	p := dpNewPair(dpOpt{mode: ModeBond, maxAge: time.Second}, dpOpt{mode: ModeBond}, true, true)
	a, b := p.a.s, p.b.s
	for _, sd := range []*dpSide{&p.a, &p.b} {
		for _, l := range sd.ls {
			l.c = &carrier.Conn{}
			dpIdle(l)
		}
	}
	a1, a2, b2 := p.a.ls[0], p.a.ls[1], p.b.ls[1]
	dpWrite(t, a, 1, 100)
	r1 := dpFill(a1, time.Now()) // the round in flight on l1
	if seqs, _ := rcDgrams(r1); len(seqs) != 1 {
		t.Fatalf("premise: l1 placed %v, want the datagram", seqs)
	}
	p.a.ps[0].b = carrier.NewBatch(0) // keep r1: a later Fill of l1 gets a fresh batch
	dpClose(a)
	f2 := dpFill(a2, time.Now())
	if dpCount(dpFrames(f2), wire.TypeFin) != 1 {
		t.Fatalf("premise: our FIN on l2: %v", dpFrames(f2))
	}
	if err := dpDeliver(f2, b2, 1, nil); err != nil {
		t.Fatal(err)
	}
	f2.ReleaseRefs()
	g2 := dpFill(b2, time.Now())
	if dpCount(dpFrames(g2), wire.TypeFin) != 1 {
		t.Fatalf("premise: the peer's FIN follows ours at once: %v", dpFrames(g2))
	}
	if err := dpDeliver(g2, a2, 1, nil); err != nil {
		t.Fatal(err)
	}
	g2.ReleaseRefs()
	dpReturn(a1, r1) // l1's round fails now, before l1's death step
	dpKill(a, a1)
	dpKill(b, p.b.ls[0])
	if c := dpCtr(a); hbDrops(c) != 0 {
		t.Fatalf("returned after the peer's FIN that answered ours: %+v: the peer still waits for it, want no drop", c)
	}
	h2 := dpFill(a2, time.Now())
	if got := hbDgrams(dpFrames(h2)); len(got) != 1 || got[0].seq != 0 || dpID(got[0].body) != 1 {
		t.Fatalf("l2 placed %v, want the returned seq 0 again", got)
	}
	if err := dpDeliver(h2, b2, 1, nil); err != nil {
		t.Fatal(err)
	}
	h2.ReleaseRefs()
	got := dpReadEOF(t, b)
	if len(got) != 1 || dpID(got[0]) != 1 {
		t.Fatalf("the peer read %d datagrams before io.EOF, want the returned one", len(got))
	}
	if c := dpCtr(a); c.Sent != 1 || hbDrops(c) != 0 {
		t.Fatalf("the sender's counters %+v, want Sent 1 and no drop", c)
	}
	if c := dpCtr(b); c.Received != 1 || c.DropLate != 0 {
		t.Fatalf("the peer's counters %+v, want the datagram received in time", c)
	}
	dpEnd(a, io.EOF)
	dpEnd(b, io.EOF)
}

// TestPacketUnsentWideKept_L37 (M5 review A5; W4-REL-5, L37): a returned
// DGRAM keeps its wide mark. Bond with l1 at a 1400-byte budget (dies),
// l2 at 600 and l3 at 1400 but write-blocked; one 1000-byte datagram,
// queued above the smallest member's DgramMax, comes back from l1. l2's
// Fill (another reason to fill) leaves it for l3 instead of dropping it as
// too large, and l3 places it once its write returns. Mutant: the wide
// mark dropped at the hand-back.
func TestPacketUnsentWideKept_L37(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := dpSession(dpOpt{mode: ModeBond})
		l1, _ := dpAddLane(s, 1, true, true)
		l2, p2 := dpAddLane(s, 2, true, true)
		l3, p3 := dpAddLane(s, 3, true, true)
		p2.set(func(f *dpPort) { f.budget = 600 })
		s.mu.Lock()
		s.pktRecomputeLocked()
		s.mu.Unlock()
		for _, l := range []*lane{l1, l2, l3} {
			dpIdle(l)
		}
		p3.set(func(f *dpPort) { f.blocked = true })
		dpWrite(t, s, 1, 1000)
		if wide := dpLocked(s, func(_ *stream, pk *packet) bool { return pk.tx.n == 1 && pk.tx.front().wide }); !wide {
			t.Fatal("premise: the 1000-byte datagram is not queued as wide")
		}
		b := dpFill(l1, time.Now())
		if _, lens := rcDgrams(b); len(lens) != 1 || lens[0] != 1000 {
			t.Fatalf("premise: l1 placed %v, want the 1000-byte datagram", lens)
		}
		dpKill(s, l1)
		dpReturn(l1, b)
		fs := dpFrames(dpFill(l2, time.Now()))
		c := dpCtr(s)
		waiting := dpLocked(s, func(_ *stream, pk *packet) int { return pk.redoN() })
		if dpCount(fs, wire.TypeDgram) != 0 || c.DropTooLarge != 0 || waiting != 1 {
			t.Fatalf("the small member's Fill placed %v with %+v, %d waiting: want the wide DGRAM left for l3", fs, c, waiting)
		}
		p3.set(func(f *dpPort) { f.blocked = false })
		got := hbDgrams(dpFrames(dpFill(l3, time.Now())))
		if len(got) != 1 || got[0].seq != 0 || len(got[0].body) != 1000 || dpID(got[0].body) != 1 {
			t.Fatalf("l3 placed %v once its write returned, want the returned seq 0", got)
		}
		if c := hbIdentity(t, s, 1, "placed by l3"); c.Sent != 1 || hbDrops(c) != 0 {
			t.Fatalf("%+v, want Sent 1 and no drop", c)
		}
		dpEnd(s, io.EOF)
	})
}

// TestPacketRedoBounded (M5 review A6; invariant 4): hand-backs keep
// arriving while every Fill places only part of the redo list — 10,000
// rounds of one hand-back and one placement on a stream lane with room for
// one, two returned DGRAMs always waiting — and the redo list's storage
// stays bounded: len and cap of pk.redo ≤ 2·maxRedo throughout. Every
// chunk reference is back at the end. Mutant: the consumed slots never
// reused (the old append-only slice).
func TestPacketRedoBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		bud := carrier.NewBudget(1 << 30)
		s := dpSession(dpOpt{mode: ModeBond, budget: bud})
		l, p := dpAddLane(s, 1, true, false)
		p.set(func(f *dpPort) { f.capacity = 100 })
		dpIdle(l)
		buf := s.env.Carrier.Bufs.Get(carrier.ChunkSize, bud)
		back := func(seq uint64) {
			buf.Ref()
			(*plane)(l).Unsent(nil, seq, buf.B[:100], buf)
		}
		back(0)
		back(1)
		maxLen, maxCap := 0, 0
		for i := range 10000 {
			back(uint64(2 + i))
			b := dpFill(l, time.Now())
			n := 0
			for k := range b.Len() {
				if b.Frame(k).Header.Type == wire.TypeDgram {
					n++
				}
			}
			b.ReleaseRefs()
			st := dpLocked(s, func(_ *stream, pk *packet) [3]int { return [3]int{len(pk.redo), cap(pk.redo), pk.redoN()} })
			if n != 1 || st[2] != 2 {
				t.Fatalf("round %d: placed %d DGRAMs with %d waiting, want 1 and 2", i, n, st[2])
			}
			maxLen, maxCap = max(maxLen, st[0]), max(maxCap, st[1])
		}
		if maxLen > 2*maxRedo || maxCap > 2*maxRedo {
			t.Fatalf("the redo list grew to len %d cap %d over 10,000 hand-backs, want ≤ %d", maxLen, maxCap, 2*maxRedo)
		}
		dpEnd(s, io.EOF)
		buf.Release()
		if u := bud.Used(); u != 0 {
			t.Fatalf("budget %d after the end, want every chunk released", u)
		}
	})
}
