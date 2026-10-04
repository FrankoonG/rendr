package lessons2

import (
	"io"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// openTwoPaths opens a session of mode m over a fast path a (1 ms one way)
// and a slower path b (5 ms): the selector makes a active, the bond orders
// a first, so the application's data first goes to a. For bond it waits
// until both members carry data with an RTT sample each.
func openTwoPaths(t *testing.T, e *env, m rendr.Mode) (a, b *path, dc, pc *rendr.Conn) {
	t.Helper()
	a = e.path("a", time.Millisecond)
	b = e.path("b", 5*time.Millisecond)
	dc, pc = e.open(e.peer(a, b), rendr.DialOptions{Mode: m})
	if m == rendr.ModeBond {
		waitFor(t, 5*time.Second, time.Millisecond, "two bond members", func() bool {
			ls := liveOf(dc.Status(), "")
			return len(ls) == 2 && ls[0].SRTT > 0 && ls[1].SRTT > 0
		})
		return a, b, dc, pc
	}
	if c, ok := activeOf(dc.Status()); !ok || c.Name != "a" {
		t.Fatalf("selector active carrier %+v, want the fast path a", c)
	}
	return a, b, dc, pc
}

// TestAppWriteDecoupledFromCarrierWrite_L17 (L17): the application's Write
// only copies into the send buffer. Path a's dialer-side writes are
// Hard-blocked (they ignore deadlines and Close, like a wedged embedder
// conn) right before the application writes 32 KiB: Write returns (32768,
// nil) at once — in the bubble, after no time at all (the lesson's bound
// is 1 s). The bytes reach the passive through b — selector: a dies with
// write_stall and the failover replays them on b; bond: b rescues the
// stuck head (L34) — intact. Releasing a afterwards lets the stuck carrier
// write complete late: it has no effect — no DATA frame below the first
// 32 KiB is dispatched again on any carrier, the stream arrives exactly
// once, and the blocked carrier was closed exactly once on each end.
func TestAppWriteDecoupledFromCarrierWrite_L17(t *testing.T) {
	for _, m := range []rendr.Mode{rendr.ModeSelector, rendr.ModeBond} {
		t.Run(m.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := newEnv(t, rendr.Config{}, rendr.Config{}, nil)
				a, b, dc, pc := openTwoPaths(t, e, m)
				const seed, first, second = 17, 32768, 64 << 10
				src := rendrtest.PRNG(seed)
				v := rendrtest.NewVerifier(seed, first+second)

				a.link.BlockWrites(rendrtest.Up, rendrtest.BlockHard)
				p1 := make([]byte, first)
				src.Read(p1)
				start := time.Now()
				n, err := dc.Write(p1)
				if el := time.Since(start); n != first || err != nil || el != 0 {
					t.Fatalf("Write over a Hard-blocked carrier = (%d, %v) after %v, want (%d, nil) at once", n, err, el, first)
				}

				// The bytes arrive through b, intact.
				pc.SetReadDeadline(time.Now().Add(10 * time.Second))
				got := make([]byte, first)
				if _, err := io.ReadFull(pc, got); err != nil {
					t.Fatalf("passive read: %v", err)
				}
				if _, err := v.Write(got); err != nil {
					t.Fatalf("passive stream: %v", err)
				}
				t.Logf("%s: 32 KiB delivered through b %v after the Write", m, time.Since(start))
				if dataBytes(b.received(wire.TypeData)) < first || len(a.received(wire.TypeData)) != 0 {
					t.Fatalf("DATA read by the passive: %d bytes on a, %d on b; want none on a",
						dataBytes(a.received(wire.TypeData)), dataBytes(b.received(wire.TypeData)))
				}
				if blocked := a.link.Stats().Session.WritesBlocked; blocked < 1 {
					t.Fatalf("stimulus: %d session writes blocked on a", blocked)
				}
				// a dies of its stalled write (the carrier write is never waited for).
				waitFor(t, 10*time.Second, 10*time.Millisecond, "a's death", func() bool {
					ds := deadOf(dc.Status(), "a")
					return len(ds) > 0 && ds[0].DeathCause == rendr.CauseWriteStall
				})
				if m == rendr.ModeSelector {
					if c, ok := activeOf(dc.Status()); !ok || c.Name != "b" {
						t.Fatalf("selector after a's death: active %+v", c)
					}
				}

				// Release a: the stuck carrier write completes late. Everything below
				// offset 32 KiB is acknowledged by then; nothing may resend it.
				waitFor(t, time.Second, time.Millisecond, "32 KiB acknowledged", func() bool { return dc.Status().AckedBytes == first })
				below := dataFramesBelow(first, a, b)
				a.link.BlockWrites(rendrtest.Up, rendrtest.BlockOff)
				synctest.Wait()
				p2 := make([]byte, second)
				src.Read(p2)
				if n, err := dc.Write(p2); n != second || err != nil {
					t.Fatalf("second Write = (%d, %v)", n, err)
				}
				if err := dc.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				if err := v.ReadAll(pc); err != nil { // exactly first+second bytes, then io.EOF: nothing twice
					t.Fatalf("passive stream after the release: %v", err)
				}
				endClean(t, dc, pc)
				if n := dataFramesBelow(first, a, b); n != below {
					t.Fatalf("%d DATA frames below offset %d dispatched after the release (%d before it)", n-below, first, below)
				}
				// a's first session carrier is the blocked one (a later one is a
				// bond member redialled after its death).
				ds, ps := a.sessionConns(true), a.sessionConns(false)
				if len(ds) == 0 || len(ps) == 0 {
					t.Fatal("no session carrier on a")
				}
				if dn, pn := ds[0].closes.Load(), ps[0].closes.Load(); dn != 1 || pn != 1 {
					t.Fatalf("a's blocked carrier closed %d times (dialer end) and %d times (passive end), want exactly once each", dn, pn)
				}
				e.close()
			})
		})
	}
}

// TestWriteBeforeSlowReturn_L17 (L17): a carrier write hands its bytes to
// the peer and then returns only hold = WriteStall/2 later (below the stall
// window, so the carrier stays alive). The application's Write under a
// 500 ms deadline succeeds at once. The peer application reads the bytes
// at once (the acknowledgement arrives while the carrier write is still
// blocked), or — so that a resend would be possible at all — only later:
// in bond mode after the watchdog reported the write blocked (PingBusy) but
// before a rescue could be due (RescueMin), in selector mode only after the
// slow write returned. In every case nothing is written twice (one DATA
// frame per byte on the wire, no retransmission), no carrier dies, nothing
// migrates, and the session goes on intact.
func TestWriteBeforeSlowReturn_L17(t *testing.T) {
	const (
		pingBusy   = 50 * time.Millisecond  // PingBusy: the watchdog reports a write blocked
		writeStall = 2 * time.Second        // WriteStall: the watchdog kills the carrier
		hold       = writeStall / 2         // the slow write returns this long after the hand-over
		rescueMin  = 300 * time.Millisecond // RescueMin: the bond rescue floor (RescueWait at these RTTs)
		ackDelay   = 20 * time.Millisecond  // AckDelay
		maxOneWay  = 5 * time.Millisecond   // path b (openTwoPaths)
	)
	for _, tc := range []struct {
		name string
		mode rendr.Mode
		read time.Duration // when the peer application reads, after the hand-over (≥ hold: once the write returned)
	}{
		{"selector, peer reads at once", rendr.ModeSelector, 0},
		{"bond, peer reads at once", rendr.ModeBond, 0},
		{"selector, peer reads after the write returned", rendr.ModeSelector, hold},
		{"bond, peer reads while the write is reported blocked", rendr.ModeBond, 2 * pingBusy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.read > 0 && tc.read < hold && (tc.read <= pingBusy || tc.read+ackDelay+2*maxOneWay >= rescueMin) {
				t.Fatal("test parameters: the read must follow the blocked report and acknowledge before a rescue is due")
			}
			synctest.Test(t, func(t *testing.T) {
				cfg := rendr.Config{PingBusy: pingBusy, WriteStall: writeStall}
				e := newEnv(t, cfg, cfg, &testhooks.Overrides{RescueMin: rescueMin, AckDelay: ackDelay})
				a, b, dc, pc := openTwoPaths(t, e, tc.mode)
				const seed, first, second = 171, 32768, 128 << 10
				src := rendrtest.PRNG(seed)
				v := rendrtest.NewVerifier(seed, first+second)
				sw := newSlowWrite(hold)
				a.slow.Store(sw)
				b.slow.Store(sw)

				p1 := make([]byte, first)
				src.Read(p1)
				dc.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
				start := time.Now()
				n, err := dc.Write(p1)
				if el := time.Since(start); n != first || err != nil || el != 0 {
					t.Fatalf("Write with a 500 ms deadline = (%d, %v) after %v, want (%d, nil) at once", n, err, el, first)
				}
				dc.SetWriteDeadline(time.Time{})
				select {
				case <-sw.started:
				case <-time.After(time.Second):
					t.Fatal("stimulus: no carrier write carried the DATA")
				}
				handed := time.Now()

				// The peer reads at tc.read; until then nothing is acknowledged.
				if tc.read >= hold {
					select {
					case <-sw.returned:
					case <-time.After(2 * hold):
						t.Fatal("the slow carrier write never returned")
					}
					synctest.Wait()
				} else {
					time.Sleep(time.Until(handed.Add(tc.read)))
				}
				if st := dc.Status(); st.AckedBytes != 0 {
					t.Fatalf("stimulus: %d bytes acknowledged %v after the hand-over, before the peer read", st.AckedBytes, time.Since(handed))
				}
				pc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				got := make([]byte, first)
				if _, err := io.ReadFull(pc, got); err != nil {
					t.Fatalf("passive read: %v", err)
				}
				if _, err := v.Write(got); err != nil {
					t.Fatalf("passive stream: %v", err)
				}
				waitFor(t, 500*time.Millisecond, time.Millisecond, "acknowledged", func() bool { return dc.Status().AckedBytes == first })
				if tc.read < hold {
					select {
					case <-sw.returned:
						t.Fatalf("the carrier write returned before the acknowledgement (after %v)", time.Since(handed))
					default:
					}
					select {
					case <-sw.returned:
					case <-time.After(2 * hold):
						t.Fatal("the slow carrier write never returned")
					}
				}
				synctest.Wait()

				// One physical write of these bytes; nothing replayed, nobody died.
				data := append(a.sent(wire.TypeData), b.sent(wire.TypeData)...)
				st := dc.Status()
				if dataBytes(data) != first || st.RetransmittedBytes != 0 || st.Migrations != (rendr.MigrationCounts{}) {
					t.Fatalf("after the slow write: %d DATA bytes written (want %d), status %+v", dataBytes(data), first, st)
				}
				for _, c := range st.Carriers {
					if c.State == rendr.CarrierDead {
						t.Fatalf("a carrier died during the slow write: %+v", c)
					}
				}

				// The session goes on.
				p2 := make([]byte, second)
				src.Read(p2)
				if n, err := dc.Write(p2); n != second || err != nil {
					t.Fatalf("second Write = (%d, %v)", n, err)
				}
				if err := dc.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				pc.SetReadDeadline(time.Now().Add(10 * time.Second))
				if err := v.ReadAll(pc); err != nil {
					t.Fatalf("passive stream: %v", err)
				}
				endClean(t, dc, pc)
				e.close()
			})
		})
	}
}
