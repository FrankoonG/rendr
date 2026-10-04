package lessons1

import (
	"io"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestBlockedCarrierDoesNotBlockControl_L08: a bond over members a, b, c
// whose lowest-srtt member a carries the dialer's ACK duty. a's writes
// then block for good (a Hard block ignores deadlines and Close). The
// dialer's ACKs for data it receives appear on another member within
// 300 ms, and the SCHED published when member c dies appears on b within
// 300 ms; Close returns at once and the session still finishes cleanly.
// The writer stuck on a is counted as abandoned (bounded teardown) and
// returns once the block is released.
func TestBlockedCarrierDoesNotBlockControl_L08(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			warm = 1 << 20
			m    = 256 << 10 // passive → dialer after the block
			d    = 256 << 10 // dialer → passive after the block
		)
		f := newFixture(t, opts{}, "a", "b", "c")
		la, lb, lc := f.link("a"), f.link("b"), f.link("c")
		la.SetDelay(time.Millisecond, 0)
		lb.SetDelay(3*time.Millisecond, 0)
		lc.SetDelay(5*time.Millisecond, 0)
		dc, pc := f.open(f.peer("a", "b", "c"), rendr.DialOptions{Mode: rendr.ModeBond})
		eventually(t, 10*time.Second, "three bond members", func() bool {
			n := 0
			for _, c := range dc.Status().Carriers {
				if c.State == rendr.CarrierMember {
					n++
				}
			}
			return n == 3
		})
		// Warm up both ways so that every member has an srtt.
		errs := make(chan error, 4)
		go func() { _, err := writeStream(dc, warm, 1, 64<<10); errs <- err }()
		go func() { _, err := writeStream(pc, warm, 2, 64<<10); errs <- err }()
		go func() { errs <- readN(pc, warm, 1) }()
		go func() { errs <- readN(dc, warm, 2) }()
		for range 4 {
			if err := <-errs; err != nil {
				t.Fatalf("warm-up: %v", err)
			}
		}
		time.Sleep(200 * time.Millisecond) // PINGs settle the srtts
		synctest.Wait()

		ta := f.wire.sessionTaps(dialerSide, "a")
		if len(ta) != 1 {
			t.Fatalf("%d dialer session carriers on a", len(ta))
		}
		a := ta[0]
		st := dc.Status()
		var srttA time.Duration
		for _, c := range st.Carriers {
			if uint32(c.ID) == a.cid.Load() {
				srttA = c.SRTT
			}
		}
		for _, c := range st.Carriers {
			if c.State == rendr.CarrierMember && uint32(c.ID) != a.cid.Load() && (srttA == 0 || c.SRTT <= srttA) {
				t.Fatalf("a (srtt %v) is not the lowest-srtt member: %+v", srttA, st.Carriers)
			}
		}
		acks := f.wire.pick(func(fr frame) bool {
			return fr.out && fr.tap.side == dialerSide && fr.typ == wire.TypeAck && fr.fate == fateWritten
		})
		if len(acks) == 0 || acks[len(acks)-1].tap != a {
			t.Fatalf("the dialer's ACK duty is not on a before the block")
		}
		ackedBefore := acks[len(acks)-1].ack.Delivered

		// Block a for good; the passive sends data the dialer must ACK.
		la.BlockWrites(rendrtest.Up, rendrtest.BlockHard)
		t0 := time.Now()
		go func() { _, err := writeStream(pc, m, 3, 64<<10); errs <- err }()
		go func() { errs <- readN(dc, m, 3) }()
		ack, ok := f.wire.wait(time.Second, func(fr frame) bool {
			return fr.out && fr.tap.side == dialerSide && fr.tap != a && fr.typ == wire.TypeAck &&
				fr.fate == fateWritten && fr.ack.Delivered > ackedBefore
		})
		if !ok {
			t.Fatal("no ACK left on another member after a blocked")
		}
		if el := ack.at.Sub(t0); el > 300*time.Millisecond {
			t.Fatalf("the ACK appeared on %q %v after a blocked, want ≤ 300 ms", ack.tap.link, el)
		}
		for range 2 {
			if err := <-errs; err != nil {
				t.Fatalf("passive → dialer after the block: %v", err)
			}
		}

		// Member c dies: the shrunk SCHED must appear on b.
		epoch := dc.Status().SchedEpoch
		t1 := time.Now()
		if k := lc.Kill(); k < 1 {
			t.Fatal("killing c hit no carrier")
		}
		sched, ok := f.wire.wait(time.Second, func(fr frame) bool {
			return fr.out && fr.tap.link == "b" && fr.typ == wire.TypeSched && fr.fate == fateWritten && fr.sched.Epoch > epoch
		})
		if !ok {
			t.Fatal("no SCHED appeared on b after c died")
		}
		if el := sched.at.Sub(t1); el > 300*time.Millisecond {
			t.Fatalf("the SCHED appeared on b %v after c died, want ≤ 300 ms", el)
		}

		// Close returns at once; the session finishes without a.
		go func() {
			_, err := writeStream(dc, d, 4, 64<<10)
			if err == nil {
				err = dc.CloseWrite()
			}
			errs <- err
		}()
		go func() {
			err := readStream(pc, d, 4, nil)
			if err == nil {
				err = pc.CloseWrite()
			}
			errs <- err
		}()
		for range 2 {
			if err := <-errs; err != nil {
				t.Fatalf("dialer → passive after the block: %v", err)
			}
		}
		if k, err := dc.Read(make([]byte, 1)); k != 0 || err != io.EOF {
			t.Fatalf("dialer Read: (%d, %v)", k, err)
		}
		closedAt := time.Now()
		for _, c := range []*rendr.Conn{dc, pc} {
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
		}
		if el := time.Since(closedAt); el != 0 {
			t.Fatalf("Close took %v", el)
		}
		for _, c := range []*rendr.Conn{dc, pc} {
			if st := waitEnded(t, c, 10*time.Second); st.Err != io.EOF {
				t.Fatalf("%v ended with %v", st.Role, st.Err)
			}
		}
		if s := la.Stats(); s.Session.WritesBlocked < 1 {
			t.Fatalf("a's session writes blocked: %d", s.Session.WritesBlocked)
		}

		// Bounded teardown: the writer stuck in a's Write is counted as
		// abandoned, and returns once released.
		eventually(t, 10*time.Second, "the stuck writer counted as abandoned", func() bool { return f.d.Status().Abandoned >= 1 })
		la.Release()
		eventually(t, 100*time.Millisecond, "the abandoned writers returned", func() bool { return f.d.Status().Abandoned == 0 })
		f.close()
	})
}

// readN reads exactly n bytes of PRNG(seed) from c (no EOF expected).
func readN(c *rendr.Conn, n int64, seed uint64) error {
	_, err := io.CopyN(rendrtest.NewVerifier(seed, n), c, n)
	return err
}

// TestBidirectionalBulkNoDeadlock_L08: two engines joined by a carrier
// whose Link holds only 64 KiB per direction move 64 MiB each way at once
// while both keep PINGing: no deadlock (the reader never writes, so PONGs
// and ACKs never wait for the other side's reader), no carrier death, and
// both streams arrive intact.
func TestBidirectionalBulkNoDeadlock_L08(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := int64(64 << 20)
		if lessonsRace {
			n = 16 << 20
		}
		f := newFixture(t, opts{buffer: 64 << 10}, "a")
		f.link("a").SetDelay(time.Millisecond, 0)
		dc, pc := f.open(f.peer("a"), rendr.DialOptions{})
		start := time.Now()
		done := make(chan error, 1)
		go func() { done <- exchange(dc, pc, n, 7, 64<<10) }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("exchange: %v", err)
			}
		case <-time.After(10 * time.Minute):
			t.Fatalf("no progress: deadlock after %v", time.Since(start))
		}
		el := time.Since(start)
		synctest.Wait()

		// Stimulus: PINGs and PONGs kept flowing both ways during the transfer.
		for _, s := range []side{dialerSide, passiveSide} {
			pings := f.wire.count(func(fr frame) bool {
				return fr.out && fr.tap.side == s && fr.typ == wire.TypePing && fr.at.Before(start.Add(el))
			})
			pongs := f.wire.count(func(fr frame) bool {
				return fr.out && fr.tap.side == s && fr.typ == wire.TypePong && fr.at.Before(start.Add(el))
			})
			if min(pings, pongs) < int(el/(4*50*time.Millisecond)) || pings < 5 {
				t.Fatalf("%v sent %d PINGs and %d PONGs during %v", s, pings, pongs, el)
			}
		}
		// Load: n bytes each way across a 64 KiB link buffer; no death.
		for _, c := range []*rendr.Conn{dc, pc} {
			st := c.Status()
			if st.DeliveredBytes != uint64(n) || st.TxBytes != uint64(n) || st.Migrations != noMigrations || len(deadCarriers(st)) != 0 {
				t.Fatalf("%v: %+v", st.Role, st)
			}
		}
		if s := f.link("a").Stats(); s.Session.Killed != 0 || s.All.Bytes < 2*n {
			t.Fatalf("link stats %+v", s)
		}
		finish(t, dc, pc)
		f.close()
	})
}
