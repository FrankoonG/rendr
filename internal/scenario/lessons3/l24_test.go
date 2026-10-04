package lessons3

import (
	"context"
	"net"
	"strings"
	"sync"
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
// the G4 budget with the right cause, reported by the detector that owns
// it (L24; P5: a control frame queued behind a stalled data write is that
// write's stall). Default death timings (DeadMin 3 s, DeadMax 4 s,
// WriteStall 2 s). The passive's own death deadline is pushed out so that
// its detection — whose carrier close a Link delivers to the dialer even
// through a blackhole, unlike a real DROP — cannot pre-empt the dialer's
// own:
//
//   - blackhole: every byte on a vanishes; A's committed PINGs stay
//     unanswered → ping_timeout, from the death deadline.
//   - hard-block: the dialer's writes on a block and ignore their deadline
//     and Close → write_stall, from the write watchdog's stage 2.
//   - soft-block-behind-data: the dialer's writes on a block until their
//     deadline while bulk data is queued; the PINGs wait behind that data
//     → write_stall, from the write's own deadline expiry. The writer arms
//     that deadline and stage 2 for the same instant, so a's conns here
//     move every write deadline 1 ms earlier (earlyDeadlineConn): the
//     deadline path, not stage 2, must classify the timeout.
func TestThreeDeathCauses_L24(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fault  func(a *rendrtest.Link)
		cause  rendr.Cause
		detail string // in A's DeathDetail: the detector that fired
		early  bool   // a's conns move their write deadlines 1 ms earlier
	}{
		{"blackhole", func(a *rendrtest.Link) { a.SetBlackhole(true) }, rendr.CausePingTimeout, "no PONG for", false},
		{"hard-block", func(a *rendrtest.Link) { a.BlockWrites(rendrtest.Up, rendrtest.BlockHard) }, rendr.CauseWriteStall, "batch write exceeded its stall window", false},
		{"soft-block-behind-data", func(a *rendrtest.Link) { a.BlockWrites(rendrtest.Up, rendrtest.BlockSoft) }, rendr.CauseWriteStall, "i/o timeout", true},
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
				ca := carrierOf(a)
				if tc.early {
					ca.Dial = func(ctx context.Context) (net.Conn, error) {
						c, err := a.Dial(ctx)
						if err != nil {
							return nil, err
						}
						return earlyDeadlineConn{c}, nil
					}
				}
				dc, pc := w.open(w.peerOf(ca, carrierOf(w.link("b"))), rendr.ModeSelector)
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
				if !strings.Contains(dead.DeathDetail, tc.detail) {
					t.Fatalf("A died of %v: %q, want the detector of %q", dead.DeathCause, dead.DeathDetail, tc.detail)
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
// selector's timings are short. The stimulus and load are proven on the
// session carrier's own conn (factory a also dials a's probe carrier,
// whose writes are slow too): it carried the stream, its writes stayed
// slow and steady, and the stream never outran one batch per slow write.
func TestSlowProgressIsNotDeath_L24(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const batchBudget = 256 * kib // DATA per batch write (the default, pinned)
		ov := selectorTimings(2 * time.Second)
		ov.BatchBudget = batchBudget
		w := newWorld(t, worldConfig{
			links: []linkSpec{{name: "a", delay: 5 * time.Millisecond}, {name: "b", delay: 5 * time.Millisecond}},
			dov:   &ov,
		})
		a := w.link("a")
		var smu sync.Mutex
		var slow []*slowConn // every conn factory a dialled, in order
		conns := func() []*slowConn {
			smu.Lock()
			defer smu.Unlock()
			return append([]*slowConn(nil), slow...)
		}
		p := w.peerOf(
			rendr.StreamCarrier{Name: "a", Dial: func(ctx context.Context) (net.Conn, error) {
				c, err := a.Dial(ctx)
				if err != nil {
					return nil, err
				}
				sc := &slowConn{Conn: c, d: 200 * time.Millisecond}
				smu.Lock()
				slow = append(slow, sc)
				smu.Unlock()
				return sc, nil
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
		start := time.Now()
		var writesAt []int64 // each conn's writes at start
		for _, c := range conns() {
			writesAt = append(writesAt, c.writes.Load())
		}
		time.Sleep(dur)
		up.stop()
		down.stop()
		up.wait(t, 30*time.Second)
		down.wait(t, 30*time.Second)
		elapsed := time.Since(start)

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
		// The session carrier's conn is the slow conn that carried the
		// stream: everything up delivered went over A.
		recvd, all := up.recvd.Load(), conns()
		var sess *slowConn
		k := 0
		for i, c := range all {
			if sess == nil || c.bytes.Load() > sess.bytes.Load() {
				sess, k = c, i
			}
		}
		if sess == nil || sess.bytes.Load() < recvd {
			t.Fatalf("stimulus: no slow conn of a carried the %d stream bytes (%d conns)", recvd, len(all))
		}
		total, delayed := sess.writes.Load(), sess.writes.Load()
		if k < len(writesAt) {
			delayed -= writesAt[k]
		}
		// Stimulus: A's writes were slow and steady for the whole run (at
		// most 50 ms between one slow write and the next on average).
		if min := int64(elapsed / (250 * time.Millisecond)); delayed < min {
			t.Fatalf("stimulus: A's conn made %d writes delayed by 200 ms in %v, want ≥ %d", delayed, elapsed, min)
		}
		// Load: the transfer kept progressing, and the slow writes paced it:
		// one write carries at most one batch of DATA.
		if recvd < delayed*16*kib || recvd > total*batchBudget {
			t.Fatalf("load: %d bytes in %d slow writes of A (%d in all), want steady progress of at most one batch per write", recvd, delayed, total)
		}
		t.Logf("A's conn: %d slow writes in %v (%d in all, %d bytes) carried %d stream bytes; %d conns of a",
			delayed, elapsed, total, sess.bytes.Load(), recvd, len(all))
		finishSession(t, dc, pc)
		w.finish()
	})
}

// TestReceiverDetectsSilentDrop_L24_L25: the passive sends bulk to the
// dialer, which only receives (ACKs, no DATA in flight), when the active
// path starts dropping everything silently. The dialer must detect it by
// its own PINGs: a carrier that received DATA since its previous PING
// keeps the busy PING cadence (F12/P12), so the first PING whose PONG the
// drop swallowed was committed at most PingBusy after the drop and expires
// after D (L25: the receiver has nothing in flight, so D = clamp(max(
// DeadMin, 3·srtt), DeadMin, DeadMax)); the race's first JOIN on b then
// takes one round trip of b. The selector fails over within that bound —
// PingBusy + D + b's round trip, ≈ 3.07 s here, inside the G4 budget —
// with cause ping_timeout. With an idle cadence the pure receiver would
// PING only every PingIdle (10 s) and detect the drop after up to
// PingIdle + D ≈ 13 s. The passive's own death deadline is pushed out so
// that its detection — whose close a Link delivers to the dialer even
// through a blackhole — cannot pre-empt the dialer's.
func TestReceiverDetectsSilentDrop_L24_L25(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			bDelay           = 10 * time.Millisecond            // b's one-way delay
			pingBusy         = 50 * time.Millisecond            // the default PingBusy
			deadMin, deadMax = 3 * time.Second, 4 * time.Second // the default DeadMin, DeadMax
		)
		pov := &testhooks.Overrides{DeadMin: 10 * time.Second, DeadMax: 10 * time.Second}
		w := newWorld(t, worldConfig{
			links: []linkSpec{{name: "a", delay: 5 * time.Millisecond, rate: 4 * mib}, {name: "b", delay: bDelay, rate: 4 * mib}},
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
		d := min(max(deadMin, 3*dead.SRTT), deadMax)
		if bound := pingBusy + d + 2*bDelay + time.Millisecond; took > bound {
			t.Fatalf("failover %v after the drop, want ≤ %v (PingBusy + D %v + b's round trip): the receiver's PING cadence was not PingBusy", took, bound, d)
		}
		t.Logf("receiver failed over %v after the drop (A's srtt %v, D %v; %s)", took, dead.SRTT, d, dead.DeathDetail)
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
// progress); it counts its writes and the bytes they wrote.
type slowConn struct {
	net.Conn
	d             time.Duration
	writes, bytes atomic.Int64
}

func (c *slowConn) Write(p []byte) (int, error) {
	time.Sleep(c.d)
	n, err := c.Conn.Write(p)
	c.writes.Add(1)
	c.bytes.Add(int64(max(n, 0)))
	return n, err
}

// earlyDeadlineConn moves every write deadline 1 ms earlier, so that a
// write blocked until its deadline ends by that deadline before the write
// watchdog's stage 2, which the writer arms for the same instant
// (TestThreeDeathCauses_L24).
type earlyDeadlineConn struct{ net.Conn }

func (c earlyDeadlineConn) SetWriteDeadline(t time.Time) error {
	if !t.IsZero() {
		t = t.Add(-time.Millisecond)
	}
	return c.Conn.SetWriteDeadline(t)
}
