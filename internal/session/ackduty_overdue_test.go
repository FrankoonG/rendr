package session

import (
	"bytes"
	"io"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestAckDutyOverdueTakenByFillingLane_L08 (§4.6, D5, L08; the
// TestMuxDeathDuringRequeue_L10_L27 race-lane gaps of 1.38 s and 1.32 s,
// run 20261018-050552-0937): a bond receiver whose two member lanes both
// carry bulk the other way, each over a saturated path on which every batch
// write takes W = 62.5 ms, must not starve its ACKs. W is BatchBudget
// (256 KiB) at the race lane's 4 MiB/s per Link (R1-11): longer than
// PingBusy, shorter than twice it. The band PingBusy < W < 2·PingBusy is,
// with the defaults (PingBusy 50 ms, BatchBudget 256 KiB), a saturated
// member rate between 2.5 and 5 MiB/s, which is why only the race lane
// showed it. Before the fix the duty fled to whichever lane
// was not flagged write-blocked at that instant — at a lane's WriteBlocked
// (PingBusy into its write) and at every cadence bump that found the duty
// lane flagged — and an unflagged lane of a saturated path is one that has
// just started a write: it fills only when that write returns, and by then
// the duty has moved on. With the two writers' phases φ apart, W − PingBusy
// < φ < PingBusy, every fill fell on the lane without the duty, the owed
// ACK was never placed and the sender's acknowledged front froze for as
// long as the bulk lasted (about 2.6 s, at most 2.85 s, in instrumented
// host runs of the scenario at -race -cpu 8), until its window ran out: a
// zero-delivery gap.
//
// Stimulus: the passive (receiver of A → B) of a bond session with lanes 1
// (srtt 5 ms) and 2 (10 ms), both data lanes; its application writes B → A
// without pause (the peer's window never limits it), so each lane's writer
// fills a full batch and "writes" it for W, flagged blocked and reported
// (WriteBlocked) after PingBusy; lane 2's writer starts φ = 31 ms after lane
// 1's. A → B: 64 KiB arrives in order on lane 1 every 20 ms and is read at
// once, each read an AckEvery bump. Load: both lanes place B → A DATA in at
// least 90 % of the W slots of the 2-s run and each is reported blocked as
// often. PASS: every A → B front read is carried by an ACK placed within
// PingBusy + W of the read (the derivation: the ACK is overdue PingBusy
// after its bump, and each saturated lane fills once per W; the lane that
// fills first takes the overdue ACK), the ACKs' Delivered values only grow
// per lane and never exceed what was read, and every A → B byte read is
// the pattern's.
func TestAckDutyOverdueTakenByFillingLane_L08(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			pingBusy = 50 * time.Millisecond // stSession's Timing.PingBusy
			slot     = 62500 * time.Microsecond
			phase    = 31 * time.Millisecond
			every    = 20 * time.Millisecond
			chunk    = 64 << 10
			run      = 2 * time.Second
		)
		s := stSession(stOpt{role: RolePassive, mode: ModeBond, window: 64 << 20})
		l1, p1 := stAddLane(s, 1, true)
		l2, p2 := stAddLane(s, 2, true)
		p1.set(func(f *stPort) { f.srtt = 5 * time.Millisecond })
		p2.set(func(f *stPort) { f.srtt = 10 * time.Millisecond })
		s.mu.Lock()
		s.peerWindowLocked(64 << 20)
		s.refreshOrderLocked(time.Now(), true)
		s.mu.Unlock()

		type ackRec struct {
			lane uint32
			at   time.Time
			del  uint64
		}
		var (
			mu      sync.Mutex
			acks    []ackRec
			slots   [3]int // per lane: batches that carried B → A DATA
			blocked [3]int // per lane: WriteBlocked reports
		)
		stop := make(chan struct{})
		var wg sync.WaitGroup
		writer := func(l *lane, fp *stPort, start time.Duration) {
			defer wg.Done()
			time.Sleep(start)
			b := carrier.NewBatch(0)
			for {
				select {
				case <-stop:
					return
				default:
				}
				b.Reset(time.Now())
				l.Fill(nil, b)
				fs := stFrames(b)
				b.ReleaseRefs()
				mu.Lock()
				for _, f := range fs {
					if f.typ == wire.TypeAck {
						acks = append(acks, ackRec{l.id, time.Now(), f.ack.Delivered})
					}
				}
				data := stCount(fs, wire.TypeData) > 0
				if data {
					slots[l.id]++
				}
				mu.Unlock()
				if !data {
					// Nothing to write (or control frames only): wait for a
					// wake, as an idle writer does.
					select {
					case <-fp.wake:
					case <-time.After(time.Millisecond):
					case <-stop:
						return
					}
					continue
				}
				// A saturated path: the batch write takes slot; its
				// watchdog reports it PingBusy in (§4.8).
				time.Sleep(pingBusy)
				fp.set(func(f *stPort) { f.blocked = true })
				l.WriteBlocked(nil)
				mu.Lock()
				blocked[l.id]++
				mu.Unlock()
				time.Sleep(slot - pingBusy)
				fp.set(func(f *stPort) { f.blocked = false })
			}
		}
		// B → A: the passive's application writes without pause.
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := stPattern(0, chunk)
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := s.Write(buf); err != nil {
					return
				}
			}
		}()
		wg.Add(2)
		go writer(l1, p1, 0)
		go writer(l2, p2, phase)

		// A → B: 64 KiB in order on lane 1 every 20 ms, read at once.
		type readRec struct {
			at    time.Time
			front uint64
		}
		var reads []readRec
		start := time.Now()
		var off uint64
		for time.Since(start) < run {
			time.Sleep(every)
			want := stPattern(off, chunk)
			if err := l1.Data(nil, off, want, nil); err != nil {
				t.Fatalf("A → B DATA at %d: %v", off, err)
			}
			if got := stReadN(t, s, chunk); !bytes.Equal(got, want) {
				t.Fatalf("integrity: the A → B bytes read at %d are not the pattern's", off)
			}
			off += chunk
			reads = append(reads, readRec{time.Now(), off})
		}
		end := time.Now()
		close(stop)
		stEnd(s, errClosed)
		wg.Wait()

		mu.Lock()
		defer mu.Unlock()
		want := int(run/slot) * 9 / 10
		for _, id := range []uint32{1, 2} {
			if slots[id] < want || blocked[id] < want {
				t.Fatalf("load: lane %d placed B → A DATA in %d write slots and was reported blocked %d times, want ≥ %d each", id, slots[id], blocked[id], want)
			}
		}
		last := map[uint32]uint64{}
		for _, a := range acks {
			if a.del < last[a.lane] || a.del > off {
				t.Fatalf("an ACK on lane %d carried Delivered %d after %d (read %d)", a.lane, a.del, last[a.lane], off)
			}
			last[a.lane] = a.del
		}
		bound := pingBusy + slot
		var worst time.Duration
		late := 0
		for _, r := range reads {
			if r.at.Add(bound).After(end) {
				break // its bound reaches past the run
			}
			lag := bound + time.Nanosecond // none found
			for _, a := range acks {
				if a.del >= r.front && !a.at.Before(r.at) {
					lag = a.at.Sub(r.at)
					break
				}
			}
			worst = max(worst, lag)
			if lag > bound {
				late++
			}
		}
		t.Logf("%d fronts read, %d ACKs placed (lane 1: %d B → A slots, lane 2: %d), worst ACK lag %v (bound %v)", len(reads), len(acks), slots[1], slots[2], worst, bound)
		if late > 0 {
			t.Fatalf("%d of %d fronts read were not carried by an ACK within PingBusy + W = %v (worst %v): the ACK duty starves between two saturated lanes", late, len(reads), bound, worst)
		}
	})
}

// TestAckOverdueRule_L08 pins ackOverdueLocked's edges on a passive bond
// receiver with lanes 1 (srtt 5 ms, the duty) and 2 (10 ms), Fill driven
// by hand: lane 1 never fills after the ACK became due.
//   - bump: an AckEvery bump at t0; lane 2 filling at t0 + PingBusy − 1 ns
//     places nothing and the duty stays; at t0 + PingBusy it places the
//     ACK of the current front and takes the duty, after which lane 1
//     places none (no duplicate for a gen already carried).
//   - dropped: as bump, with an applied SCHED that lists lane 1 only (the
//     dialer abandoned lane 2: one-way loss, A7 (c), L45): lane 2 takes
//     nothing at t0 + PingBusy, the duty stays and lane 1 places the ACK.
//   - delayed: a delivery below AckEvery arms the ACK delay at t1; lane 2
//     filling 1 ns before t1 + delay + PingBusy places nothing, at that
//     instant it places the ACK of the front and takes the duty.
//   - holcoupled (M3-D39, PA-30): a dialer whose lanes a and b form a
//     HoLCoupled fate group and c is independent (mgHolSession); a's write
//     blocked, so the duty is on c. b filling PingBusy after a bump places
//     nothing while a is blocked (its write would stall with a) and the
//     duty stays on c; once a's write returned, b's next fill places the
//     overdue ACK and takes the duty, after which c places none.
func TestAckOverdueRule_L08(t *testing.T) {
	const (
		pingBusy = 50 * time.Millisecond
		delay    = 20 * time.Millisecond
	)
	setup := func(t *testing.T) (*Session, *lane, *lane, uint64) {
		s := stSession(stOpt{role: RolePassive, mode: ModeBond, ackDelay: delay})
		l1, p1 := stAddLane(s, 1, true)
		l2, p2 := stAddLane(s, 2, true)
		p1.set(func(f *stPort) { f.srtt = 5 * time.Millisecond })
		p2.set(func(f *stPort) { f.srtt = 10 * time.Millisecond })
		s.mu.Lock()
		s.peerWindowLocked(1 << 20)
		s.refreshOrderLocked(time.Now(), true)
		s.st.ackLane = nil
		s.ensureAckLaneLocked()
		s.mu.Unlock()
		// The first DATA after the attaches is acknowledged at once (L19);
		// the duty lane places it: nothing is owed on lane 1 afterwards.
		if err := l1.Data(nil, 0, stPattern(0, 100), nil); err != nil {
			t.Fatal(err)
		}
		stReadN(t, s, 100)
		if _, ok := wpsessAckOf(l1); !ok {
			t.Fatal("setup: the duty lane 1 placed no ACK for the first DATA")
		}
		return s, l1, l2, 100
	}
	duty := func(s *Session) *lane { return stLocked(s, func(st *stream) *lane { return st.ackLane }) }
	deliver := func(t *testing.T, s *Session, l *lane, off uint64, n int) uint64 {
		t.Helper()
		if err := l.Data(nil, off, stPattern(off, n), nil); err != nil {
			t.Fatal(err)
		}
		stReadN(t, s, n)
		return off + uint64(n)
	}

	t.Run("bump", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, l1, l2, off := setup(t)
			defer stEnd(s, errClosed)
			front := deliver(t, s, l1, off, 64<<10)
			time.Sleep(pingBusy - time.Nanosecond)
			if a, ok := wpsessAckOf(l2); ok || duty(s) != l1 {
				t.Fatalf("lane 2 placed %v (%v) and holds the duty %v before PingBusy passed: want nothing, the duty on lane 1", a, ok, duty(s) == l2)
			}
			time.Sleep(time.Nanosecond)
			if a, ok := wpsessAckOf(l2); !ok || a.Delivered != front || duty(s) != l2 {
				t.Fatalf("lane 2 at PingBusy: ACK %v (%v), duty on lane 2 %v; want the ACK of %d and the duty", a, ok, duty(s) == l2, front)
			}
			if a, ok := wpsessAckOf(l1); ok {
				t.Fatalf("lane 1 placed %v after lane 2 carried the same gen: want none", a)
			}
		})
	})
	t.Run("dropped", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, l1, l2, off := setup(t)
			defer stEnd(s, errClosed)
			wpsessApplySched(s, 2, 1) // the dialer sends on lane 1 only
			if _, ok := wpsessAckOf(l1); !ok {
				t.Fatal("setup: lane 1 placed no ACK for the SCHED's echo")
			}
			front := deliver(t, s, l1, off, 64<<10)
			time.Sleep(pingBusy)
			if a, ok := wpsessAckOf(l2); ok || duty(s) != l1 {
				t.Fatalf("the dropped lane 2 placed %v (%v), duty there %v: want nothing, the duty on lane 1", a, ok, duty(s) == l2)
			}
			if a, ok := wpsessAckOf(l1); !ok || a.Delivered != front {
				t.Fatalf("lane 1 placed %v (%v), want the ACK of %d", a, ok, front)
			}
		})
	})
	t.Run("delayed", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, l1, l2, off := setup(t)
			defer stEnd(s, errClosed)
			front := deliver(t, s, l1, off, 1000) // below AckEvery: the delay is armed
			time.Sleep(delay + pingBusy - time.Nanosecond)
			if a, ok := wpsessAckOf(l2); ok || duty(s) != l1 {
				t.Fatalf("lane 2 placed %v (%v) and holds the duty %v before the delay + PingBusy passed: want nothing", a, ok, duty(s) == l2)
			}
			time.Sleep(time.Nanosecond)
			if a, ok := wpsessAckOf(l2); !ok || a.Delivered != front || duty(s) != l2 {
				t.Fatalf("lane 2 at the delay + PingBusy: ACK %v (%v), duty on lane 2 %v; want the ACK of %d and the duty", a, ok, duty(s) == l2, front)
			}
		})
	})
	t.Run("holcoupled", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, _, lanes, ports := mgHolSession(t, true)
			defer stEnd(s, errClosed)
			a, b, c := lanes[0], lanes[1], lanes[2]
			ports[0].set(func(f *stPort) { f.blocked = true })
			a.WriteBlocked(nil)
			if duty(s) != c {
				t.Fatalf("setup: a blocked, the duty on a %v, on b %v; want it on c", duty(s) == a, duty(s) == b)
			}
			s.mu.Lock()
			s.bumpNowLocked()
			gen := s.st.ackGen
			s.mu.Unlock()
			time.Sleep(pingBusy)
			if ack, ok := wpsessAckOf(b); ok || duty(s) != c {
				t.Fatalf("b, whose sibling a is blocked, placed %v (%v) and holds the duty %v: want nothing, the duty on c", ack, ok, duty(s) == b)
			}
			ports[0].set(func(f *stPort) { f.blocked = false })
			if _, ok := wpsessAckOf(b); !ok || duty(s) != b {
				t.Fatalf("b once a's write returned: ACK %v, duty on b %v; want the overdue ACK and the duty", ok, duty(s) == b)
			}
			if ack, ok := wpsessAckOf(c); ok {
				t.Fatalf("c placed %v after b carried gen %d: want none", ack, gen)
			}
		})
	})
}

// TestAckOverdueStreamOnly_L08: the overdue rule is a stream session's
// (ackOverdueLocked). PingBusy is 50 ms; Fill is driven by hand and the
// duty lane does not fill after the ACK or PACK became due.
//   - packet_bump: a passive packet bond with stream lanes 1 (srtt 5 ms,
//     the PACK duty) and 2 (10 ms): a bump starts no overdue clock (PACK
//     placement would never clear it); lane 2 filling PingBusy later
//     places no PACK and the duty stays on lane 1, which then places the
//     owed PACK.
//   - packet_delayed: as packet_bump, the PACK delay (PacketPing 1 s)
//     armed by a datagram instead: lane 2 filling at the delay + PingBusy
//     places no PACK, the duty stays and lane 1 places the PACK reporting
//     the datagram.
//   - race: a passive race session, data lanes 1 (5 ms, the duty) and 2
//     (80 ms) and lane 3 (200 ms) that carries no data and so no ACK copy
//     (M3-D33, PA-33). 64 KiB read bumps the ACK; lane 3 filling PingBusy
//     later places nothing and the duty stays on the fastest lane 1; lane
//     2's copy and lane 1 carry the front.
func TestAckOverdueStreamOnly_L08(t *testing.T) {
	const (
		pingBusy = 50 * time.Millisecond
		pp       = time.Second
	)
	pkSetup := func() (*Session, *lane, *lane) {
		s := dpSession(dpOpt{role: RolePassive, mode: ModeBond, packetPing: pp})
		l1, f1 := dpAddLane(s, 1, true, false)
		l2, f2 := dpAddLane(s, 2, true, false)
		f1.set(func(f *dpPort) { f.srtt = 5 * time.Millisecond })
		f2.set(func(f *dpPort) { f.srtt = 10 * time.Millisecond })
		s.mu.Lock()
		s.refreshOrderLocked(time.Now(), true)
		s.st.ackLane = nil
		s.ensureAckLaneLocked()
		s.mu.Unlock()
		dpIdle(l1)
		dpIdle(l2)
		return s, l1, l2
	}
	duty := func(s *Session) *lane { return stLocked(s, func(st *stream) *lane { return st.ackLane }) }
	packs := func(l *lane) []dpFrame {
		var out []dpFrame
		for _, f := range dpFrames(dpFill(l, time.Now())) {
			if f.typ == wire.TypePack {
				out = append(out, f)
			}
		}
		return out
	}

	t.Run("packet_bump", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, l1, l2 := pkSetup()
			defer dpEnd(s, io.EOF)
			if duty(s) != l1 {
				t.Fatalf("setup: the PACK duty is on lane %v, want 1", duty(s))
			}
			s.mu.Lock()
			s.bumpNowLocked()
			clock := s.st.ackOwedSince
			s.mu.Unlock()
			if !clock.IsZero() {
				t.Fatalf("a packet session's bump started the overdue clock at %v: want none", clock)
			}
			time.Sleep(pingBusy)
			if ps := packs(l2); len(ps) != 0 || duty(s) != l1 {
				t.Fatalf("lane 2 PingBusy after the bump placed %v, duty on lane 2 %v: want no PACK, the duty on lane 1", ps, duty(s) == l2)
			}
			if ps := packs(l1); len(ps) != 1 {
				t.Fatalf("the duty lane 1 placed %v: want the owed PACK", ps)
			}
		})
	})
	t.Run("packet_delayed", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, l1, l2 := pkSetup()
			defer dpEnd(s, io.EOF)
			if err := dpDatagram(l1, 0, []byte("a")); err != nil {
				t.Fatal(err)
			}
			if at := stLocked(s, func(st *stream) time.Time { return st.ackDelayAt }); at.IsZero() {
				t.Fatal("setup: the datagram armed no PACK delay")
			}
			time.Sleep(pp + pingBusy)
			if ps := packs(l2); len(ps) != 0 || duty(s) != l1 {
				t.Fatalf("lane 2 at the delay + PingBusy placed %v, duty on lane 2 %v: want no PACK, the duty on lane 1", ps, duty(s) == l2)
			}
			if ps := packs(l1); len(ps) != 1 || ps[0].pack.Received != 1 {
				t.Fatalf("the duty lane 1 placed %v: want one PACK reporting the datagram", ps)
			}
			if got, err := dpReadAll(t, s); err != nil || len(got) != 1 || string(got[0]) != "a" {
				t.Fatalf("integrity: read %q, %v; want the one datagram \"a\"", got, err)
			}
		})
	})
	t.Run("race", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := stSession(stOpt{role: RolePassive, mode: ModeRace, window: 1 << 20})
			defer stEnd(s, errClosed)
			fast, fp := stAddLane(s, 1, true)
			slow, sp := stAddLane(s, 2, true)
			ctl, cp := stAddLane(s, 3, false)
			rcRaceLanes(s)
			s.mu.Lock()
			ctl.data = false // carries no data: no ACK copy
			s.mu.Unlock()
			fp.set(func(f *stPort) { f.srtt = 5 * time.Millisecond })
			sp.set(func(f *stPort) { f.srtt = 80 * time.Millisecond })
			cp.set(func(f *stPort) { f.srtt = 200 * time.Millisecond })
			// The first DATA after an attach bumps at once: deliver it, and
			// let every lane place what it owes.
			if err := stDeliverData(fast, 0, stPattern(0, 1000)); err != nil {
				t.Fatal(err)
			}
			stReadN(t, s, 1000)
			for _, l := range []*lane{fast, slow, ctl} {
				for {
					fs, b := stFill(l, time.Now())
					b.ReleaseRefs()
					if len(fs) == 0 {
						break
					}
				}
			}
			front := uint64(1000 + 64<<10)
			if err := stDeliverData(fast, 1000, stPattern(1000, 64<<10)); err != nil {
				t.Fatal(err)
			}
			if got := stReadN(t, s, 64<<10); !bytes.Equal(got, stPattern(1000, 64<<10)) {
				t.Fatal("integrity: the bytes read are not the pattern's")
			}
			time.Sleep(pingBusy)
			if ack, ok := wpsessAckOf(ctl); ok || duty(s) != fast {
				t.Fatalf("lane 3 (no data) PingBusy after the bump placed %v (%v), duty on lane 3 %v: want nothing, the duty on lane 1", ack, ok, duty(s) == ctl)
			}
			for _, l := range []*lane{slow, fast} {
				if ack, ok := wpsessAckOf(l); !ok || ack.Delivered != front {
					t.Fatalf("lane %d placed %v (%v): want the ACK of %d", l.id, ack, ok, front)
				}
			}
		})
	})
}
