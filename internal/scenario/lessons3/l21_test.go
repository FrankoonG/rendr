package lessons3

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestStaleIncarnationEventsIgnored_L21: three late events of a dead carrier
// incarnation A never affect its successor A' (L21; design §7.3: a stale
// incarnation's death, PONG or write completion belongs to a Conn the actor
// no longer holds).
//
// One factory (no probe carrier) dials its first carrier, A, over link x and
// every later one over link y, so x's faults never touch A'. Small writes
// flow both ways all the time. A's PINGs are captured. Then x stalls and
// the dialer's writes on x block hard (an embedder Write that ignores its
// deadline and Close): A dies by write stall, the factory is redialled at
// once and A' attaches over y with one death migration on both ends. The
// passive's death deadline is set long, so its own A outlives A's
// replacement. Then:
//
//   - stale PONG: a PONG carrying A's PING id k, timestamp and nonce is
//     injected towards the dialer on A' right after A' committed its own
//     PING k, a full y round trip before that PING's genuine PONG: A' must
//     ignore it — no RTT sample (A's minimum RTT stays the round trip of
//     y), no violation (A' lives).
//   - late death: the passive's A dies of its own ping timeout seconds
//     after A' took over its traffic: routing and counts stay as they are.
//   - late write completion: A's write, abandoned in the embedder since A's
//     death, finally returns (and its writer reports a failure): the
//     abandoned goroutine leaves the pool, A' is unaffected and A's death
//     record keeps its first cause.
//
// After each event A' is the active carrier on both ends and the
// migrations are exactly the one death; the streams arrive intact.
func TestStaleIncarnationEventsIgnored_L21(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			dx = 10 * time.Millisecond
			dy = 100 * time.Millisecond // a PING's genuine PONG on A' takes 2·dy
		)
		w := newWorld(t, worldConfig{
			links: []linkSpec{{name: "x", delay: dx}, {name: "y", delay: dy}},
			// The dialer detects A's death by its blocked write (500 ms);
			// the passive's death deadline outlives A's replacement.
			dov: &testhooks.Overrides{WriteStall: 500 * time.Millisecond, DeadMin: 2 * time.Second, DeadMax: 2 * time.Second},
			pov: &testhooks.Overrides{DeadMin: 6 * time.Second, DeadMax: 6 * time.Second},
		})
		x, y := w.link("x"), w.link("y")
		var dials atomic.Int64
		p := w.peerOf(rendr.StreamCarrier{Name: "p", Dial: func(ctx context.Context) (net.Conn, error) {
			if dials.Add(1) == 1 {
				return x.Dial(ctx)
			}
			return y.Dial(ctx)
		}})
		dc, pc := w.open(p, rendr.ModeSelector)
		up := w.startFlow("up", dc, pc, 211, flowOpts{chunk: kib, gap: 10 * time.Millisecond})
		down := w.startFlow("down", pc, dc, 212, flowOpts{chunk: kib, gap: 10 * time.Millisecond})
		a := mustActive(t, dc, "dialer")

		// A's PINGs (dialer → passive) while it is busy: id → payload.
		pings := map[uint32]wire.Ping{}
		for until := time.Now().Add(1500 * time.Millisecond); time.Now().Before(until); {
			select {
			case raw := <-x.CaptureNextFrame(rendrtest.Up, rendrtest.FramePing):
				pg := parsePing(t, raw, wire.TypePing)
				pings[pg.ID] = pg
			case <-time.After(time.Until(until)):
			}
		}
		if len(pings) < 10 {
			t.Fatalf("captured %d PINGs of A in 1.5 s, want a busy cadence", len(pings))
		}

		// A dies: x holds every byte, then the dialer's next write on it
		// blocks for good. Nothing reaches the passive's A any more.
		x.SetStall(true)
		time.Sleep(20 * time.Millisecond)
		x.BlockWrites(rendrtest.Up, rendrtest.BlockHard)
		dmark, pmark := w.dev.mark(), w.pev.mark()
		ev := w.dev.wait(t, dmark, 3*time.Second, "dialer death migration", isKind(rendr.EventMigration, dc.ID()))
		if ev.From != a.ID || !isDeathCause(ev.Cause) {
			t.Fatalf("dialer migration %+v, want a death of A %d", ev, a.ID)
		}
		succ := ev.To
		w.pev.wait(t, pmark, 3*time.Second, "passive migration", isKind(rendr.EventMigration, pc.ID()))
		pup := w.pev.wait(t, pmark, time.Second, "passive CarrierUp of A'", func(e rendr.Event) bool {
			return e.Kind == rendr.EventCarrierUp && e.Session == pc.ID() && e.Carrier == succ
		})
		switched := time.Now() // both ends route over A'
		if cs := mustActive(t, dc, "dialer"); cs.ID != succ || cs.Name != "p" || cs.Gen != 2 {
			t.Fatalf("dialer active %+v, want A' %d (factory p, generation 2)", cs, succ)
		}
		ok := func(stage string) {
			t.Helper()
			for _, e := range []struct {
				side string
				c    *rendr.Conn
			}{{"dialer", dc}, {"passive", pc}} {
				if cs := mustActive(t, e.c, e.side); cs.ID != succ {
					t.Fatalf("%s: %s active carrier %d, want A' %d", stage, e.side, cs.ID, succ)
				}
				wantMigrations(t, e.side+" after "+stage, e.c, rendr.MigrationCounts{Death: 1})
			}
		}
		ok("A' attached")
		ad, _ := carrierByID(dc, a.ID)
		if ad.State != rendr.CarrierDead || !isDeathCause(ad.DeathCause) {
			t.Fatalf("dialer's A %+v, want dead by a death cause", ad)
		}

		// 1. A stale PONG of A on A'. y carries nothing but A': the
		// injection after the passive's next DATA frame reaches A' within dy
		// + one inter-frame gap of A' committing its PING k, a full y round
		// trip before that PING's genuine PONG.
		var k uint32
		for k == 0 {
			select {
			case raw := <-y.CaptureNextFrame(rendrtest.Up, rendrtest.FramePing):
				pg := parsePing(t, raw, wire.TypePing)
				if _, seen := pings[pg.ID]; seen && time.Since(switched) >= 2*dy {
					k = pg.ID
				} else if time.Since(switched) > 2*time.Second {
					t.Fatalf("A' sent no PING with an id of A's (last %d) within 2 s", pg.ID)
				}
			case <-time.After(time.Second):
				t.Fatal("A' sent no PING for 1 s")
			}
		}
		committed := time.Now()
		stale := pings[k] // A's PING k: its PONG echoes id, timestamp and nonce
		var payload [wire.PingFixedLen]byte
		wire.PutPing(payload[:], &stale)
		y.InjectAfterNextFrame(rendrtest.Down, rendrtest.FrameData, rendrtest.FramePong, 0, 0, payload[:])
		waitFor(t, dy, "the stale PONG injected while A''s PING was outstanding", func() bool {
			return y.Stats().Session.FramesInjected == 1
		})
		t.Logf("stale PONG (id %d) injected %v after A' committed its PING %d", k, time.Since(committed), k)
		time.Sleep(time.Second) // the genuine PONG and more samples
		cs, _ := carrierByID(dc, succ)
		if cs.State != rendr.CarrierActive || cs.MinRTT < 2*dy {
			t.Fatalf("A' after the stale PONG: %+v; want active with min RTT ≥ %v (no sample from the stale PONG)", cs, 2*dy)
		}
		ok("the stale PONG")

		// 2. The passive's A dies of its own ping timeout, long after A'
		// took over.
		pdown := w.pev.wait(t, pmark, 10*time.Second, "passive CarrierDown of A", func(e rendr.Event) bool {
			return e.Kind == rendr.EventCarrierDown && e.Session == pc.ID() && e.Carrier == a.ID
		})
		if pdown.Cause != rendr.CausePingTimeout || !pdown.Time.After(pup.Time.Add(time.Second)) {
			t.Fatalf("passive's A ended %+v, want ping_timeout well after A' came up at %v", pdown, pup.Time)
		}
		ok("the late death")

		// 3. A's abandoned write returns late.
		if n := w.d.Status().Abandoned; n != 1 {
			t.Fatalf("dialer Runtime: %d abandoned goroutines before the release, want A's stuck writer", n)
		}
		before, _ := carrierByID(dc, a.ID)
		x.Release()
		waitFor(t, time.Second, "A's late write completion", func() bool { return w.d.Status().Abandoned == 0 })
		synctest.Wait()
		ok("the late write completion")
		if after, _ := carrierByID(dc, a.ID); after.DeathCause != before.DeathCause || after.DeathDetail != before.DeathDetail {
			t.Fatalf("A's death record changed by its late write: %q (%v) → %q (%v)", before.DeathDetail, before.DeathCause, after.DeathDetail, after.DeathCause)
		}

		time.Sleep(time.Second)
		up.stop()
		down.stop()
		up.wait(t, 10*time.Second)
		down.wait(t, 10*time.Second)
		ok("the transfer")
		for _, f := range []*flow{up, down} {
			if f.recvd.Load() < 600*kib { // ≈ 1 KiB per 10 ms for ≈ 11 s
				t.Fatalf("flow %s carried %d bytes, want the chatter to keep going throughout", f.name, f.recvd.Load())
			}
		}
		if n := dc.Status().NoPathEpisodes; n != 1 {
			t.Fatalf("dialer no-path episodes %d, want 1 (A died before A' attached)", n)
		}
		if n := pc.Status().NoPathEpisodes; n != 0 {
			t.Fatalf("passive no-path episodes %d, want 0 (A' attached before its A died)", n)
		}
		// Stimulus proofs.
		xs, ys := x.Stats().Session, y.Stats().Session
		if xs.WritesBlocked < 1 || xs.Held < 1 || xs.FramesCaptured < 10 || ys.FramesInjected != 1 || ys.FramesCaptured < 1 {
			t.Fatalf("stimulus: x %+v, y %+v", xs, ys)
		}
		finishSession(t, dc, pc)
		w.finish()
	})
}

// parsePing decodes a captured PING or PONG frame.
func parsePing(t testing.TB, raw []byte, typ wire.Type) wire.Ping {
	t.Helper()
	f, _, err := wire.DecodeFrame(raw)
	if err != nil || f.Type != typ {
		t.Fatalf("captured frame %x: type %v, %v", raw, f.Type, err)
	}
	p, err := wire.ParsePing(f.Payload)
	if err != nil {
		t.Fatalf("captured %v payload: %v", typ, err)
	}
	return p
}

// isDeathCause reports a carrier death cause (plan §3.6): not a planned
// retirement, a local close or no cause at all.
func isDeathCause(c rendr.Cause) bool {
	switch c {
	case rendr.CausePingTimeout, rendr.CauseWriteStall, rendr.CauseTransportError, rendr.CauseProtocolViolation, rendr.CauseInstanceMismatch, rendr.CauseGoAway:
		return true
	}
	return false
}
