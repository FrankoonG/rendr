package session

import (
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
