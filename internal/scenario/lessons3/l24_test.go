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
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// g4Budget is the G4 bound on recovering delivery after a path failure
// with default timings (plan §3.6: D ≤ DeadMax plus one dial and one RTT).
const g4Budget = 5 * time.Second

// TestThreeDeathCauses_L24: each death cause is detected on its own and
// bypasses dwell and cooldown (both 1 h here): the selector is on B within
// the G4 budget with the right cause (L24; P5: a control frame queued behind
// a stalled data write is that write's stall). Default death timings
// (DeadMin 3 s, DeadMax 4 s, WriteStall 2 s). The passive's own death
// deadline is pushed out so that its detection — whose carrier close a
// Link delivers to the dialer even through a blackhole, unlike a real
// DROP — cannot pre-empt the dialer's own:
//
//   - blackhole: every byte on a vanishes; A's committed PINGs stay
//     unanswered → ping_timeout.
//   - hard-block: the dialer's writes on a block and ignore their deadline
//     and Close → the write watchdog → write_stall.
//   - soft-block-behind-data: the dialer's writes on a block until their
//     deadline while bulk data is queued; the PINGs wait behind that data
//     → write_stall.
func TestThreeDeathCauses_L24(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fault func(a *rendrtest.Link)
		cause rendr.Cause
	}{
		{"blackhole", func(a *rendrtest.Link) { a.SetBlackhole(true) }, rendr.CausePingTimeout},
		{"hard-block", func(a *rendrtest.Link) { a.BlockWrites(rendrtest.Up, rendrtest.BlockHard) }, rendr.CauseWriteStall},
		{"soft-block-behind-data", func(a *rendrtest.Link) { a.BlockWrites(rendrtest.Up, rendrtest.BlockSoft) }, rendr.CauseWriteStall},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				dov := &testhooks.Overrides{SelectorDwell: time.Hour, SelectorCooldown: time.Hour}
				pov := &testhooks.Overrides{SelectorDwell: time.Hour, SelectorCooldown: time.Hour, DeadMin: 10 * time.Second, DeadMax: 10 * time.Second}
				w := newWorld(t, worldConfig{
					links: []linkSpec{{name: "a", delay: 5 * time.Millisecond, rate: 2 * mib}, {name: "b", delay: 10 * time.Millisecond, rate: 2 * mib}},
					dov:   dov, pov: pov,
				})
				a := w.link("a")
				dc, pc := w.open(w.peer(), rendr.ModeSelector)
				first := mustActive(t, dc, "dialer")
				if first.Name != "a" {
					t.Fatalf("initial active %+v, want a carrier of a", first)
				}
				up := w.startFlow("up", dc, pc, 241, flowOpts{})
				down := w.startFlow("down", pc, dc, 242, flowOpts{chunk: 8 * kib, gap: 10 * time.Millisecond})
				time.Sleep(2 * time.Second)

				mark := w.dev.mark()
				faultAt := time.Now()
				tc.fault(a)
				ev := w.dev.wait(t, mark, g4Budget, "death migration", isKind(rendr.EventMigration, dc.ID()))
				took := ev.Time.Sub(faultAt)
				dead, _ := carrierByID(dc, first.ID)
				now := mustActive(t, dc, "dialer")
				if ev.From != first.ID || ev.Cause != tc.cause || dead.DeathCause != tc.cause || now.Name != "b" || ev.To != now.ID {
					t.Fatalf("after %v: migration %+v, A %+v, active %+v; want A's %v and B active", took, ev, dead, now, tc.cause)
				}
				t.Logf("%s: on B %v after the fault (cause %v: %s)", tc.name, took, dead.DeathCause, dead.DeathDetail)

				time.Sleep(2 * time.Second) // the transfer goes on over B
				up.stop()
				down.stop()
				up.wait(t, 30*time.Second)
				down.wait(t, 30*time.Second)
				wantMigrations(t, "dialer", dc, rendr.MigrationCounts{Death: 1})
				waitFor(t, time.Second, "the passive counting the death", func() bool {
					return pc.Status().Migrations == rendr.MigrationCounts{Death: 1}
				})
				s := a.Stats().Session
				var stimulus bool
				switch tc.name {
				case "blackhole":
					stimulus = s.Dropped > 0
				default:
					stimulus = s.WritesBlocked > 0
				}
				if !stimulus || up.recvd.Load() < 4*mib {
					t.Fatalf("stimulus/load: a's session counters %+v, %d bytes carried", s, up.recvd.Load())
				}
				a.Release()
				finishSession(t, dc, pc)
				w.finish()
			})
		})
	}
}

// TestSlowProgressIsNotDeath_L24: every write of the active carrier takes
// 200 ms but completes, so the transfer progresses slowly and steadily —
// queueing, not a stall (L24: "每帧慢 200ms 但持续有进展时，不切换"). The
// write stall window (≥ WriteStall, 2 s) and the death deadline (≥ 3 s;
// RTT counts from the write's return, L23) never expire: no carrier dies
// and nothing switches, though a second path is available and the
// selector's timings are short.
func TestSlowProgressIsNotDeath_L24(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ov := selectorTimings(2 * time.Second)
		w := newWorld(t, worldConfig{
			links: []linkSpec{{name: "a", delay: 5 * time.Millisecond}, {name: "b", delay: 5 * time.Millisecond}},
			dov:   &ov,
		})
		a := w.link("a")
		var slow atomic.Int64
		p := w.peerOf(
			rendr.StreamCarrier{Name: "a", Dial: func(ctx context.Context) (net.Conn, error) {
				c, err := a.Dial(ctx)
				if err != nil {
					return nil, err
				}
				return slowConn{Conn: c, d: 200 * time.Millisecond, writes: &slow}, nil
			}},
			carrierOf(w.link("b")),
		)
		dc, pc := w.open(p, rendr.ModeSelector)
		first := mustActive(t, dc, "dialer")
		if first.Name != "a" {
			t.Fatalf("initial active %+v, want a carrier of a", first)
		}
		dur := 30 * time.Second
		if raceEnabled {
			dur = 15 * time.Second
		}
		up := w.startFlow("up", dc, pc, 251, flowOpts{})
		down := w.startFlow("down", pc, dc, 252, flowOpts{chunk: 4 * kib, gap: 50 * time.Millisecond})
		start, writes := time.Now(), slow.Load()
		time.Sleep(dur)
		up.stop()
		down.stop()
		up.wait(t, 30*time.Second)
		down.wait(t, 30*time.Second)
		elapsed, delayed := time.Since(start), slow.Load()-writes

		for _, e := range []struct {
			side string
			c    *rendr.Conn
		}{{"dialer", dc}, {"passive", pc}} {
			wantMigrations(t, e.side, e.c, rendr.MigrationCounts{})
			st := e.c.Status()
			if cs := mustActive(t, e.c, e.side); cs.ID != first.ID {
				t.Fatalf("%s active %+v, want A %d", e.side, cs, first.ID)
			}
			for _, cs := range st.Carriers {
				if cs.State == rendr.CarrierDead {
					t.Fatalf("%s: carrier %+v died", e.side, cs)
				}
			}
		}
		// Stimulus: the writes of a were slow for the whole run; load: the
		// transfer kept progressing at about one batch per slow write.
		if min := int64(elapsed / (250 * time.Millisecond)); delayed < min {
			t.Fatalf("stimulus: %d writes delayed by 200 ms in %v, want ≥ %d", delayed, elapsed, min)
		}
		if up.recvd.Load() < delayed*16*kib {
			t.Fatalf("load: %d bytes in %d slow writes, want steady progress", up.recvd.Load(), delayed)
		}
		t.Logf("%d slow writes in %v carried %d bytes", delayed, elapsed, up.recvd.Load())
		finishSession(t, dc, pc)
		w.finish()
	})
}

// TestReceiverDetectsSilentDrop_L24_L25: the passive sends bulk to the
// dialer, which only receives (ACKs, no DATA in flight), when the active
// path starts dropping everything silently. The dialer must detect it by
// its own PINGs: a carrier that received DATA since its previous PING
// keeps the busy PING cadence (F12/P12), so its oldest unanswered PING
// expires after D (≤ DeadMax) and the selector fails over within the G4
// budget, with cause ping_timeout. With an idle cadence the pure receiver
// would PING only every PingIdle (10 s) and detect the drop after up to
// PingIdle + D ≈ 14 s. The passive's own death deadline is pushed out so
// that its detection — whose close a Link delivers to the dialer even
// through a blackhole — cannot pre-empt the dialer's.
func TestReceiverDetectsSilentDrop_L24_L25(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pov := &testhooks.Overrides{DeadMin: 10 * time.Second, DeadMax: 10 * time.Second}
		w := newWorld(t, worldConfig{
			links: []linkSpec{{name: "a", delay: 5 * time.Millisecond, rate: 4 * mib}, {name: "b", delay: 10 * time.Millisecond, rate: 4 * mib}},
			pov:   pov,
		})
		a := w.link("a")
		dc, pc := w.open(w.peer(), rendr.ModeSelector)
		first := mustActive(t, dc, "dialer")
		if first.Name != "a" {
			t.Fatalf("initial active %+v, want a carrier of a", first)
		}
		total := int64(24 * mib)
		if raceEnabled {
			total = 12 * mib
		}
		down := w.startFlow("down", pc, dc, 261, flowOpts{n: total})
		waitFor(t, 10*time.Second, "a quarter of the bulk received", func() bool { return down.recvd.Load() >= total/4 })
		if st := dc.Status(); st.TxBytes != 0 {
			t.Fatalf("the dialer sent %d bytes: it must be a pure receiver", st.TxBytes)
		}
		mark := w.dev.mark()
		dropAt := time.Now()
		a.SetBlackhole(true)
		down2 := w.dev.wait(t, mark, g4Budget, "the dialer's failover", isKind(rendr.EventMigration, dc.ID()))
		took := down2.Time.Sub(dropAt)
		dead, _ := carrierByID(dc, first.ID)
		now := mustActive(t, dc, "dialer")
		if down2.From != first.ID || dead.DeathCause != rendr.CausePingTimeout || now.Name != "b" {
			t.Fatalf("after %v: migration %+v, A %+v, active %+v; want A's ping_timeout detected by the dialer and B active", took, down2, dead, now)
		}
		t.Logf("receiver failed over %v after the drop (%s)", took, dead.DeathDetail)
		down.wait(t, 60*time.Second)
		if s := a.Stats().Session; s.Dropped == 0 {
			t.Fatalf("stimulus: a dropped nothing: %+v", s)
		}
		wantMigrations(t, "dialer", dc, rendr.MigrationCounts{Death: 1})
		finishSession(t, dc, pc)
		w.finish()
	})
}

// slowConn delays every Write by d before it starts (L24's slow but steady
// progress); it counts the delayed writes.
type slowConn struct {
	net.Conn
	d      time.Duration
	writes *atomic.Int64
}

func (c slowConn) Write(p []byte) (int, error) {
	time.Sleep(c.d)
	c.writes.Add(1)
	return c.Conn.Write(p)
}
