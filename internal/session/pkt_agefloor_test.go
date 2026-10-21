package session

import (
	"bytes"
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestPacketPassiveAgeFromPlaceable_L40 (L40; M2-D35, M3-D8; the m6-design
// decision on core defect B, 2026-10-21): a passive packet session's
// datagrams age (Packet.MaxAge) from the first call in which its lane can
// place one, not from their WriteTo, so a reply written at Confirm survives
// the wait for the view's first response and the dialer's go frame.
//
// The lane's first response (OK) is due when the target replies; 50 ms
// later a MUX writer's call places the OK under the response hold — a
// Confirm that came after the round's control pass — and nothing else of
// the handle; the go frame comes 150 ms after that (MaxAge 100 ms). A
// second reply is written during the hold, 120 ms after the first.
//
//   - selector: both replies are placed at the first call after the hold,
//     with nothing counted; from then the clock runs (a third reply that
//     waits 150 ms for a call is DropAge).
//   - race: a routing change during the hold (the race head step) drops
//     nothing either.
func TestPacketPassiveAgeFromPlaceable_L40(t *testing.T) {
	const maxAge = 100 * time.Millisecond
	for _, arm := range []struct {
		name string
		mode Mode
	}{{"selector", ModeSelector}, {"race", ModeRace}} {
		mode := arm.mode
		t.Run(arm.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := dpSession(dpOpt{role: RolePassive, mode: mode, maxAge: maxAge})
				l, fp := dpAddLane(s, 1, true, true)
				s.mu.Lock()
				l.firstSent = false
				l.first = firstFrame{t: wire.TypeOpenAck, openAck: wire.OpenAck{Status: wire.StatusOK, Window: 1 << 20}}
				s.mu.Unlock()
				t0 := time.Now()
				dpWrite(t, s, 1, 100) // the reply written at Confirm

				time.Sleep(50 * time.Millisecond)
				b := fp.b
				b.Reset(time.Now())
				b.SetDatagram(1400, wire.RelWindow)
				b.SetResponseHold(l.Handle())
				(*plane)(l).Fill(nil, b)
				fs := dpFrames(b)
				b.ReleaseRefs()
				if len(fs) != 1 || fs[0].typ != wire.TypeOpenAck {
					t.Fatalf("the held call placed %v, want its OK only", fs)
				}

				sleepUntilT(t0.Add(120 * time.Millisecond))
				dpWrite(t, s, 2, 100) // during the hold, more than MaxAge after the first
				if mode == ModeRace {
					sleepUntilT(t0.Add(190 * time.Millisecond))
					dpRoute(s, l, true) // a routing change runs the race head step
				}
				if c := dpCtr(s); c.DropAge != 0 || c.DropNoPath != 0 {
					t.Fatalf("during the hold: %+v, want nothing dropped", c)
				}

				sleepUntilT(t0.Add(200 * time.Millisecond)) // the go frame ended the hold
				fs = dpFrames(dpFill(l, time.Now()))
				var ids []uint64
				for _, f := range fs {
					if f.typ == wire.TypeDgram {
						ids = append(ids, dpID(f.body))
					}
				}
				if len(ids) != 2 || ids[0] != 1 || ids[1] != 2 {
					t.Fatalf("L40: the first call after the hold placed datagrams %v (%v), want 1 and 2; %+v", ids, fs, dpCtr(s))
				}
				if c := dpCtr(s); c.DropAge != 0 || c.Sent != 2 {
					t.Fatalf("after the hold: %+v, want Sent 2 and nothing dropped", c)
				}

				dpIdle(l)
				dpWrite(t, s, 3, 100)
				time.Sleep(150 * time.Millisecond)
				b = dpFill(l, time.Now())
				b.ReleaseRefs()
				if c := dpCtr(s); c.DropAge != 1 || c.Sent != 2 {
					t.Fatalf("once placeable: %+v, want the third datagram DropAge (the clock runs)", c)
				}
				dpEnd(s, nil)
			})
		})
	}
}

// sleepUntilT sleeps until at (no-op when it passed).
func sleepUntilT(at time.Time) {
	if d := time.Until(at); d > 0 {
		time.Sleep(d)
	}
}

// pktActorWants returns the deadline the actor's packet step (packetLocked)
// wants at now, run on a fresh actor (zero: none).
func pktActorWants(s *Session, now time.Time) time.Time {
	return wpLocked(s, func() time.Time {
		a := newActor(s)
		a.packetLocked(now)
		return a.wakeAt
	})
}

// pktBell consumes the actor's bell and reports whether it rang.
func pktBell(s *Session) bool {
	select {
	case <-s.mb.bell:
		return true
	default:
		return false
	}
}

// TestPacketBigHeldAgesFromPlaceable_L37_L40 (L37, L40; C4-F2, M2-D35,
// M3-D8; the m6-design decision on core defect B, 2026-10-21): a passive
// mixed bond's datagram that only its stream member can carry waits in
// txBig while that member awaits its SCHED (pk.bigHeld), aged by the actor
// (pktAgeBigLocked). Before the session's MaxAge clock starts (the
// datagram member's first response, OK, not yet placed, then held for the
// dialer's go frame) the datagram does not age, and the actor wants no
// deadline that already passed (it would re-arm every millisecond). Once
// the member can place, the clock starts: the datagram ages from that
// moment, and the actor is rung to arm its new deadline.
//
// MaxAge 50 ms; the big datagram is written at 0, the OK placed under the
// hold at 150 ms, the go frame ends the hold at 200 ms.
//
//   - routed: the SCHED routes the stream member at 230 ms, 230 ms after
//     the WriteTo; it places the datagram intact, nothing dropped.
//   - aged: no SCHED; the actor's ageing keeps it at 249 ms and drops it
//     DropAge at 251 ms, MaxAge after the placeable moment.
func TestPacketBigHeldAgesFromPlaceable_L37_L40(t *testing.T) {
	const maxAge = 50 * time.Millisecond
	for _, arm := range []string{"routed", "aged"} {
		t.Run(arm, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := dpSession(dpOpt{role: RolePassive, mode: ModeBond, maxPayload: wire.MaxPacketPayload, maxAge: maxAge})
				ld, pd := dpAddLane(s, 1, true, true)
				lst, _ := dpAddLane(s, 2, false, false)
				s.mu.Lock()
				ld.firstSent = false
				ld.first = firstFrame{t: wire.TypeOpenAck, openAck: wire.OpenAck{Status: wire.StatusOK, Window: 1 << 20}}
				s.pktMemberConfirmedLocked(lst) // the stream member awaits its SCHED
				s.mu.Unlock()
				queued := func() [2]int {
					return dpLocked(s, func(_ *stream, pk *packet) [2]int { return [2]int{pk.tx.n, pk.txBig.n} })
				}
				if !dpLocked(s, func(_ *stream, pk *packet) bool { return pk.bigHeld && !pk.ageOn }) {
					t.Fatal("premise: not a held mixed bond whose clock waits")
				}
				pktBell(s)
				t0 := time.Now()
				dpWrite(t, s, 1, 3000)
				if q := queued(); q != [2]int{0, 1} {
					t.Fatalf("premise: queued tx %d txBig %d, want the big datagram in txBig", q[0], q[1])
				}
				noPast := func(when string) {
					t.Helper()
					now := time.Now()
					if w := pktActorWants(s, now); !w.IsZero() && !w.After(now) {
						t.Fatalf("%s: the actor wants a deadline %v ago: it would re-arm at minArm until the clock starts", when, now.Sub(w))
					}
					if c := dpCtr(s); c.DropAge != 0 || c.DropNoPath != 0 {
						t.Fatalf("%s: %+v, want nothing dropped before the clock starts", when, c)
					}
				}
				for _, at := range []time.Duration{60 * time.Millisecond, 120 * time.Millisecond} {
					sleepUntilT(t0.Add(at))
					noPast(fmt.Sprintf("held, %v after the WriteTo", at))
				}

				sleepUntilT(t0.Add(150 * time.Millisecond)) // the OK, under the response hold
				b := pd.b
				b.Reset(time.Now())
				b.SetDatagram(1400, wire.RelWindow)
				b.SetResponseHold(ld.Handle())
				(*plane)(ld).Fill(nil, b)
				fs := dpFrames(b)
				b.ReleaseRefs()
				if len(fs) != 1 || fs[0].typ != wire.TypeOpenAck {
					t.Fatalf("the held call placed %v, want its OK only", fs)
				}
				noPast("after the held call")

				sleepUntilT(t0.Add(200 * time.Millisecond)) // the go frame ended the hold
				pktBell(s)
				placeable := time.Now()
				dpFill(ld, placeable).ReleaseRefs() // the clock starts
				if !pktBell(s) {
					t.Fatal("the clock started with a held txBig and did not ring the actor (its deadline unarmed)")
				}
				w := pktActorWants(s, time.Now())
				if lo, hi := placeable.Add(maxAge), placeable.Add(maxAge+time.Millisecond); w.Before(lo) || w.After(hi) {
					t.Fatalf("the actor wants %v after the placeable moment, want MaxAge (%v): the big datagram ages from it", w.Sub(placeable), maxAge)
				}

				switch arm {
				case "routed":
					sleepUntilT(t0.Add(230 * time.Millisecond))
					dpRoute(s, lst, true) // the SCHED lists it
					got := cfDgrams(dpFrames(dpFill(lst, time.Now())))
					if len(got) != 1 || dpID(got[0].body) != 1 || !bytes.Equal(got[0].body, dpPayload(1, 3000)) {
						t.Fatalf("L37: the routed stream member placed %v, want datagram 1 intact; %+v", got, dpCtr(s))
					}
					if c := dpCtr(s); c.DropAge != 0 || c.Sent != 1 {
						t.Fatalf("L40: %+v, want Sent 1 and nothing dropped (it waited 230 ms, 30 ms of them placeable)", c)
					}
				case "aged":
					sleepUntilT(t0.Add(249 * time.Millisecond))
					pktActorWants(s, time.Now())
					if c := dpCtr(s); c.DropAge != 0 || queued() != [2]int{0, 1} {
						t.Fatalf("49 ms after the placeable moment: %+v, queued %v; want it kept", c, queued())
					}
					sleepUntilT(t0.Add(251 * time.Millisecond))
					if w := pktActorWants(s, time.Now()); !w.IsZero() {
						t.Fatalf("a deadline %v wanted with nothing held", w)
					}
					if c := dpCtr(s); c.DropAge != 1 || c.DropNoPath != 0 || queued() != [2]int{0, 0} {
						t.Fatalf("51 ms after the placeable moment: %+v, queued %v; want it DropAge", c, queued())
					}
				}
				dpEnd(s, nil)
			})
		})
	}
}

// TestPacketPassiveNoPathAgesFromWrite_L40 (L40; M2-D35; the m6-design
// decision on core defect B, 2026-10-21): the floor applies only while a
// data lane exists. A passive's only lane dies before it could place (its
// OK not yet placed, the clock not started): the actor's no-path step ages
// the reply from its WriteTo as before. It is kept at 90 ms with its
// deadline at MaxAge (100 ms), and dropped DropNoPath at 101 ms.
func TestPacketPassiveNoPathAgesFromWrite_L40(t *testing.T) {
	const maxAge = 100 * time.Millisecond
	synctest.Test(t, func(t *testing.T) {
		s := dpSession(dpOpt{role: RolePassive, maxAge: maxAge})
		l, _ := dpAddLane(s, 1, true, true)
		s.mu.Lock()
		l.firstSent = false
		l.first = firstFrame{t: wire.TypeOpenAck, openAck: wire.OpenAck{Status: wire.StatusOK, Window: 1 << 20}}
		s.mu.Unlock()
		t0 := time.Now()
		dpWrite(t, s, 1, 100)
		time.Sleep(30 * time.Millisecond)
		dpKill(s, l) // the only lane dies before it could place
		if dpLocked(s, func(_ *stream, pk *packet) bool { return pk.ageOn }) {
			t.Fatal("premise: the clock started")
		}
		sleepUntilT(t0.Add(90 * time.Millisecond))
		w := pktActorWants(s, time.Now())
		if lo, hi := t0.Add(maxAge), t0.Add(maxAge+time.Millisecond); w.Before(lo) || w.After(hi) {
			t.Fatalf("no path, 90 ms after the WriteTo: the actor wants %v after it, want MaxAge (%v)", w.Sub(t0), maxAge)
		}
		if c := dpCtr(s); c.DropNoPath != 0 || c.DropAge != 0 {
			t.Fatalf("90 ms after the WriteTo: %+v, want it kept", c)
		}
		sleepUntilT(t0.Add(101 * time.Millisecond))
		pktActorWants(s, time.Now())
		if c := dpCtr(s); c.DropNoPath != 1 || c.DropAge != 0 {
			t.Fatalf("L40: 101 ms after the WriteTo with no data lane: %+v, want it DropNoPath (the no-path step ages from the WriteTo)", c)
		}
		dpEnd(s, nil)
	})
}
