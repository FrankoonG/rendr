package lessons4

import (
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestBondAsymmetricReorderBounded_L34: a bond over a 5 ms and a 200 ms
// path (one-way; same rate R) moves 64 MiB (16 MiB under -race). The fast
// member never runs so far ahead that the receiver's reorder exceeds the
// window: no carrier dies (no window violation), the passive's buffered
// bytes stay within 2·Window plus its reader stages; the slow member
// carries a real share, so the session beats a single fast carrier (> R);
// every byte arrives intact.
func TestBondAsymmetricReorderBounded_L34(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const rate = 4 << 20 // bytes/s per path
		n := int64(64 << 20)
		if raceEnabled {
			n = 16 << 20
		}
		w := newWorld(t, worldOpts{}, "fast", "slow")
		lf, ls := w.link("fast"), w.link("slow")
		lf.SetDelay(5*time.Millisecond, 0)
		ls.SetDelay(200*time.Millisecond, 0)
		lf.SetRate(rate)
		ls.SetRate(rate)
		dc, pc := w.open(w.peer(nil, lf, ls), rendr.DialOptions{Mode: rendr.ModeBond})
		waitFor(t, 5*time.Second, "both members", func() bool { return len(dataCarriers(dc.Status())) == 2 })

		start := time.Now()
		f := startFlow(dc, pc, n, 34, flowOpts{closeWrite: true, eof: true})
		var maxBuf int64
		for done := false; !done; {
			select {
			case <-f.rdone:
				done = true
			case <-time.After(10 * time.Millisecond):
				maxBuf = max(maxBuf, w.p.Status().BufferedBytes)
			}
		}
		elapsed := time.Since(start)
		f.wait(t, time.Second, "bond transfer")

		window := int64(8 << 20) // the default Window
		if limit := 2*window + 1<<20; maxBuf > limit {
			t.Fatalf("the passive buffered up to %s, want ≤ 2·Window + 1 MiB (%s)", mib(maxBuf), mib(limit))
		}
		got := float64(n) / elapsed.Seconds()
		if got <= 1.2*rate {
			t.Fatalf("goodput %.2f MiB/s over %v, want more than a single fast path (%.2f MiB/s) by 20%%", got/(1<<20), elapsed, float64(rate)/(1<<20))
		}
		ds, ps := dc.Status(), pc.Status()
		for _, s := range []rendr.SessionStatus{ds, ps} {
			if d := deadOf(s); len(d) != 0 || s.Migrations != (rendr.MigrationCounts{}) {
				t.Fatalf("%v: dead carriers %+v, migrations %+v; want none", s.Role, d, s.Migrations)
			}
		}
		slow, ok := memberOn(ds, "slow")
		fast, ok2 := memberOn(ds, "fast")
		if !ok || !ok2 || int64(slow.TxBytes) < n/10 || int64(fast.TxBytes) < n/10 {
			t.Fatalf("member shares: fast %d, slow %d of %d bytes; want ≥ 10%% each", fast.TxBytes, slow.TxBytes, n)
		}
		if lf.Stats().Session.MaxDelay != 5*time.Millisecond || ls.Stats().Session.MaxDelay != 200*time.Millisecond ||
			lf.Stats().Throttled == 0 || ls.Stats().Throttled == 0 {
			t.Fatal("the asymmetric delays or the rate limits were not applied (stimulus)")
		}
		t.Logf("goodput %.2f MiB/s (single path %.2f), passive buffered ≤ %s, shares fast %s / slow %s, retransmitted %d",
			got/(1<<20), float64(rate)/(1<<20), mib(maxBuf), mib(int64(fast.TxBytes)), mib(int64(slow.TxBytes)), ds.RetransmittedBytes)
		endClean(t, dc, pc)
		w.close()
	})
}

// TestBondStalledMemberRecovers_L34 (Z4; design §4.11, §11.4): the
// lowest-srtt member stalls while the receiver holds part of one of its
// frames, and the head of the send window is held by it. The other member
// rescues that head (the holder never duplicates it itself while another
// data lane exists) within max(300 ms, 3·srtt), so the receiver's in-order
// delivery moves on long before any death deadline; a stall shorter than
// the death deadline kills nothing, and the session then finishes intact.
// Two stalls: "write" — the member's carrier Write stops in the middle of
// a frame (the embedder conn blocks after half a batch; its path stays
// healthy) —, and "path" — the member's path stops delivering in both
// directions while its conns keep accepting writes (L34's "a stalled
// member that still accepts writes").
func TestBondStalledMemberRecovers_L34(t *testing.T) {
	for _, mode := range []string{"write", "path"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { bondStall(t, mode == "path") })
		})
	}
}

// stallConn is a dialer carrier conn of the fast factory: once armed, its
// next Write of a big batch (a session carrier moving bulk) transmits about
// half the batch — ending inside a DATA frame — and then blocks, ignoring
// deadlines like a stuck kernel, until released.
type stallConn struct {
	net.Conn
	s *stallCtl
}

// stallCtl arms and releases the stallConns of one test.
type stallCtl struct {
	armed   atomic.Bool
	stalled chan struct{} // closed when a Write stalled
	release chan struct{} // closed by the test
}

func (c *stallConn) Write(p []byte) (int, error) {
	if len(p) < 128<<10 || !c.s.armed.CompareAndSwap(true, false) {
		return c.Conn.Write(p)
	}
	cut := len(p)/2 - 1000 // inside a DATA frame of a batch of 64 KiB frames
	n, err := c.Conn.Write(p[:cut])
	close(c.s.stalled)
	<-c.s.release
	if err != nil {
		return n, err
	}
	m, err := c.Conn.Write(p[cut:])
	return n + m, err
}

func bondStall(t *testing.T, path bool) {
	n := int64(32 << 20)
	if raceEnabled {
		n = 12 << 20
	}
	ctl := &stallCtl{stalled: make(chan struct{}), release: make(chan struct{})}
	defer func() {
		select {
		case <-ctl.release:
		default:
			close(ctl.release) // a failed test still ends its bubble
		}
	}()
	w := newWorld(t, worldOpts{tap: true}, "fast", "slow")
	lf, ls := w.link("fast"), w.link("slow")
	lf.SetDelay(5*time.Millisecond, 0)
	ls.SetDelay(20*time.Millisecond, 0)
	lf.SetRate(24 << 20)
	ls.SetRate(24 << 20)
	wrap := func(link string, c net.Conn) net.Conn {
		if link == "fast" {
			return &stallConn{Conn: c, s: ctl}
		}
		return c
	}
	dc, pc := w.open(w.peer(wrap, lf, ls), rendr.DialOptions{Mode: rendr.ModeBond})
	waitFor(t, 5*time.Second, "both members", func() bool { return len(dataCarriers(dc.Status())) == 2 })
	f := startFlow(dc, pc, n, 341, flowOpts{closeWrite: true, eof: true})
	waitFor(t, 30*time.Second, "30% delivered", func() bool { return f.got.Load() >= n*3/10 })

	var tap *tapConn // the passive end of the fast member
	for _, c := range w.taps.all("fast") {
		if fr := c.snapshot(); fr.count[0x01]+fr.count[0x03] > 0 { // first frame OPEN or JOIN: a session carrier
			tap = c
		}
	}
	if tap == nil {
		t.Fatal("no session carrier on the fast path")
	}
	st := dc.Status()
	fast, ok := memberOn(st, "fast")
	slow, ok2 := memberOn(st, "slow")
	if !ok || !ok2 || fast.SRTT == 0 || fast.SRTT >= slow.SRTT {
		t.Fatalf("the fast member is not the lowest-srtt one: %+v", st.Carriers)
	}
	srtt := fast.SRTT
	var stallAt time.Time
	if path {
		waitFor(t, 5*time.Second, "a partial frame of the fast member at the receiver", func() bool { return tap.snapshot().midFrame() })
		lf.SetStall(true)
		stallAt = time.Now()
	} else {
		ctl.armed.Store(true)
		select {
		case <-ctl.stalled:
		case <-time.After(5 * time.Second):
			t.Fatal("the fast member never wrote a big batch")
		}
		stallAt = time.Now()
		waitFor(t, time.Second, "the half-written frame at the receiver", func() bool { return tap.snapshot().midFrame() })
	}
	stuckAt := f.got.Load()
	bound := max(300*time.Millisecond, 3*srtt)

	var rescuedAt time.Time
	waitFor(t, 3*time.Second, "a rescue by the other member", func() bool {
		if c, ok := carrierOf(dc.Status(), slow.ID); ok && c.RetxBytes > 0 {
			rescuedAt = time.Now()
			return true
		}
		return false
	})
	time.Sleep(time.Second - time.Since(stallAt)) // a stall shorter than the death deadline (≥ 2 s here)
	stuck := f.got.Load()
	releasedAt := time.Now()
	if path {
		lf.SetStall(false)
	} else {
		close(ctl.release)
	}
	moved, ok := f.firstReadAfter(rescuedAt)
	// The head is stuck since the receiver's last in-order delivery before
	// the rescue; its ACK reaches the dialer within the ACK delay (20 ms)
	// and one srtt, and the rescue clock (lastAdvance) starts there.
	last, _ := f.lastReadBefore(rescuedAt)
	ds, ps := dc.Status(), pc.Status()
	t.Logf("fast srtt %v, slow srtt %v: receiver at %s when stalled, stuck from +%v, rescue at +%v (bound %v), first delivery after it at +%v (%s), %s at the release; dialer acked %s",
		srtt, slow.SRTT, mib(stuckAt), last.at.Sub(stallAt), rescuedAt.Sub(stallAt), bound, moved.at.Sub(stallAt), mib(moved.got), mib(stuck), mib(int64(ds.AckedBytes)))
	if d := rescuedAt.Sub(last.at); d > bound+20*time.Millisecond+srtt {
		t.Fatalf("the rescue left %v after the head got stuck, want within max(300 ms, 3·srtt) = %v (+ the ACK delay and one srtt for the ACK)", d, bound)
	}
	if fs, _ := carrierOf(ds, fast.ID); fs.RetxBytes != 0 {
		t.Fatalf("the stalled holder sent its own duplicate while another data lane existed: %+v", fs)
	}
	if !ok || !moved.at.Before(releasedAt) || moved.at.Sub(rescuedAt) > 2*slow.SRTT+50*time.Millisecond {
		t.Fatalf("the receiver's in-order delivery did not move within 2·srtt of the rescuing member after the rescue: stuck at %s from the stall until the release %v later (dialer acked %s, passive delivered %s)",
			mib(stuckAt), releasedAt.Sub(stallAt), mib(int64(ds.AckedBytes)), mib(int64(ps.DeliveredBytes)))
	}
	f.wait(t, time.Minute, "transfer across the stall")

	ds, ps = dc.Status(), pc.Status()
	for _, s := range []rendr.SessionStatus{ds, ps} {
		if d := deadOf(s); len(d) != 0 || s.Migrations != (rendr.MigrationCounts{}) {
			t.Fatalf("%v: a stall below the death deadline killed %+v (migrations %+v)", s.Role, d, s.Migrations)
		}
	}
	if path && lf.Stats().Session.Held == 0 {
		t.Fatal("the path stall held no chunk of the fast member (stimulus)")
	}
	endClean(t, dc, pc)
	w.close()
}

// TestBondDoubleDeathSingleTeardown_L34: both members of a bond die at the
// same instant while both carry unacknowledged data in both directions.
// On each end every carrier is torn down exactly once (one CarrierDown
// event per carrier), the session enters exactly one no-path episode
// instead of ending, no dead CarrierID is ever live again, both factories
// are redialled as new incarnations, and both transfers complete intact.
func TestBondDoubleDeathSingleTeardown_L34(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := int64(24 << 20)
		if raceEnabled {
			n = 8 << 20
		}
		w := newWorld(t, worldOpts{}, "a", "b")
		la, lb := w.link("a"), w.link("b")
		for _, l := range []*rendrtest.Link{la, lb} {
			l.SetDelay(5*time.Millisecond, 0)
			l.SetRate(16 << 20)
		}
		dc, pc := w.open(w.peer(nil, la, lb), rendr.DialOptions{Mode: rendr.ModeBond})
		waitFor(t, 5*time.Second, "both members", func() bool { return len(dataCarriers(dc.Status())) == 2 })
		f := startFlow(dc, pc, n, 342, flowOpts{closeWrite: true, eof: true})
		g := startFlow(pc, dc, n/4, 343, flowOpts{closeWrite: true, eof: true})
		waitFor(t, 30*time.Second, "40% delivered", func() bool { return f.got.Load() >= n*4/10 })

		before := dc.Status()
		old := map[rendr.CarrierID]bool{}
		for _, c := range dataCarriers(before) {
			if c.TxBytes == 0 {
				t.Fatalf("member %d carried no data before the double death: %+v", c.ID, before.Carriers)
			}
			old[c.ID] = true
		}
		if len(old) != 2 {
			t.Fatalf("members before the double death: %+v", before.Carriers)
		}
		la.Kill()
		lb.Kill()
		f.wait(t, time.Minute, "transfer across the double death")
		g.wait(t, time.Minute, "reverse transfer across the double death")

		for i, s := range []rendr.SessionStatus{dc.Status(), pc.Status()} {
			evs := []*eventLog{w.dev, w.pev}[i]
			downs := map[rendr.CarrierID]int{}
			for _, ev := range evs.of(rendr.EventCarrierDown) {
				downs[ev.Carrier]++
			}
			for id := range old {
				if downs[id] != 1 {
					t.Fatalf("%v: carrier %d torn down %d times, want exactly once (CarrierDown events %v)", s.Role, id, downs[id], downs)
				}
			}
			if s.NoPathEpisodes != 1 || len(evs.of(rendr.EventNoPathStart)) != 1 || s.State != rendr.StateOpen {
				t.Fatalf("%v: %d no-path episodes (%d events), state %v; want exactly one and an open session",
					s.Role, s.NoPathEpisodes, len(evs.of(rendr.EventNoPathStart)), s.State)
			}
			for _, c := range dataCarriers(s) {
				if old[c.ID] {
					t.Fatalf("%v: dead carrier %d is live again: %+v", s.Role, c.ID, s.Carriers)
				}
			}
			if len(dataCarriers(s)) != 2 {
				t.Fatalf("%v: data carriers after the redial %+v, want both factories back", s.Role, s.Carriers)
			}
		}
		ds := dc.Status()
		if ds.Rejoins != 2 {
			t.Fatalf("dialer rejoins %d, want 2 (both factories redialled)", ds.Rejoins)
		}
		for _, c := range dataCarriers(ds) {
			if c.Gen != 2 {
				t.Fatalf("carrier %+v: want the second incarnation of its factory", c)
			}
		}
		if ds.Migrations.Death < 1 || ds.Migrations.Death > 2 || ds.Migrations.Quality+ds.Migrations.Explicit != 0 {
			t.Fatalf("dialer migrations %+v, want one death per member that held unacknowledged data", ds.Migrations)
		}
		for _, l := range []*rendrtest.Link{la, lb} {
			if s := l.Stats().Session; s.Killed != 1 || s.BufferLost == 0 {
				t.Fatalf("link %s killed %d session carriers losing %d bytes, want 1 with loss (stimulus)", l.Name(), s.Killed, s.BufferLost)
			}
		}
		endClean(t, dc, pc)
		w.close()
	})
}

// TestBondSplitFollowsDrainRate_L32: a saturated bond over a 2 MiB/s and a
// 16 MiB/s path (both 10 ms one-way) splits its bytes by the members'
// drain rates — 1:8 within 15% over the steady part of the transfer —
// because each member pulls DATA only up to its PONG-proven capacity
// (L32, P4; no configured weights). The capacity evidence exists only
// under backlog: once the transfer turns into a demand-limited trickle,
// the member carrying it is no longer backlogged, so its PONGs bring no
// rate sample, its rate decays and its cap falls back to the 128 KiB floor
// (the cold-start prior).
func TestBondSplitFollowsDrainRate_L32(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const slowRate, fastRate = 2 << 20, 16 << 20
		const floor = 128 << 10 // the per-carrier capacity floor
		n := int64(48 << 20)
		if raceEnabled {
			n = 32 << 20
		}
		w := newWorld(t, worldOpts{}, "slow", "fast")
		ls, lf := w.link("slow"), w.link("fast")
		for _, l := range []*rendrtest.Link{ls, lf} {
			l.SetDelay(10*time.Millisecond, 0)
		}
		ls.SetRate(slowRate)
		lf.SetRate(fastRate)
		dc, pc := w.open(w.peer(nil, ls, lf), rendr.DialOptions{Mode: rendr.ModeBond})
		waitFor(t, 5*time.Second, "both members", func() bool { return len(dataCarriers(dc.Status())) == 2 })
		f := startFlow(dc, pc, n, 32, flowOpts{})

		// The steady part, from 25% to 90% of the transfer (the ramp from the
		// floor and the tail are excluded), measured where the bytes drain:
		// the passive's per-carrier receive counters. (A member's send
		// counter moves in bursts of its cap.)
		split := func() (slow, fast rendr.CarrierStatus, rxSlow, rxFast uint64) {
			st, ps := dc.Status(), pc.Status()
			slow, ok := memberOn(st, "slow")
			fast, ok2 := memberOn(st, "fast")
			if !ok || !ok2 {
				t.Fatalf("members: %+v", st.Carriers)
			}
			rs, ok := carrierOf(ps, slow.ID)
			rf, ok2 := carrierOf(ps, fast.ID)
			if !ok || !ok2 {
				t.Fatalf("passive carriers: %+v", ps.Carriers)
			}
			return slow, fast, rs.RxBytes, rf.RxBytes
		}
		waitFor(t, time.Minute, "25% delivered", func() bool { return f.got.Load() >= n/4 })
		_, _, s0, f0 := split()
		t0 := time.Now()
		waitFor(t, time.Minute, "90% delivered", func() bool { return f.got.Load() >= n*9/10 })
		sc, fc, s1, f1 := split()
		dt := time.Since(t0).Seconds()
		ds, df := float64(s1-s0), float64(f1-f0)
		ratio := df / ds
		t.Logf("steady split fast:slow = %.2f (want 8 ± 15%%): slow %.2f MiB/s (rate est %.2f, cap %s), fast %.2f MiB/s (rate est %.2f, cap %s), retransmitted %d",
			ratio, ds/dt/(1<<20), sc.Rate/(1<<20), mib(int64(sc.Cap)), df/dt/(1<<20), fc.Rate/(1<<20), mib(int64(fc.Cap)), dc.Status().RetransmittedBytes)
		if ratio < 8*0.85 || ratio > 8*1.15 {
			t.Fatalf("steady split fast:slow = %.2f, want 1:8 within 15%%", ratio)
		}
		if total := (ds + df) / dt; total < 0.9*(slowRate+fastRate) {
			t.Fatalf("steady goodput %.2f MiB/s, want ≥ 90%% of the paths' %.2f MiB/s (load not reached)", total/(1<<20), float64(slowRate+fastRate)/(1<<20))
		}
		if sc.Cap <= floor || fc.Cap <= sc.Cap {
			t.Fatalf("caps under backlog: slow %d, fast %d; want both raised by evidence, fast above slow", sc.Cap, fc.Cap)
		}
		if ls.Stats().Throttled == 0 || lf.Stats().Throttled == 0 {
			t.Fatal("the paths' rate limits were not applied (stimulus)")
		}
		f.wait(t, time.Minute, "bulk transfer")

		// A demand-limited trickle: 2 KiB every 20 ms for 5 s. It rides the
		// lowest-srtt member, the fast one.
		g := startFlow(dc, pc, 250*2<<10, 33, flowOpts{chunk: 2 << 10, pace: 20 * time.Millisecond})
		g.wait(t, time.Minute, "trickle")
		st := dc.Status()
		carrying, ok := memberOn(st, "fast")
		if !ok || carrying.TxBytes <= fc.TxBytes {
			t.Fatalf("the fast member carried none of the trickle: %+v", st.Carriers)
		}
		t.Logf("after the trickle: fast rate %.0f cap %d; slow (idle) rate %.0f cap %d", carrying.Rate, carrying.Cap, sc.Rate, sc.Cap)
		if carrying.Cap != floor || carrying.Rate >= fc.Rate/8 {
			t.Fatalf("after 5 s of demand-limited traffic the fast member's cap is %d (rate %.0f, was %.0f), want the %d floor", carrying.Cap, carrying.Rate, fc.Rate, floor)
		}
		endClean(t, dc, pc)
		w.close()
	})
}

// TestBondUnknownMemberGetsFloor_L33 (should): a member that joins a busy
// bond has Unknown evidence (no srtt, no rate) and still gets data at once
// — its 128 KiB capacity floor, never starved behind a member whose proven
// capacity covers the backlog — but no more than the floor plus one
// segment before its first PONG proves anything (bounded exploration).
// Under backlog its own PONGs then raise its capacity, and it carries a
// real share; every byte arrives intact.
func TestBondUnknownMemberGetsFloor_L33(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const floor, segment = 128 << 10, 64 << 10
		n := int64(48 << 20)
		if raceEnabled {
			n = 40 << 20
		}
		w := newWorld(t, worldOpts{ov: testhooks.Overrides{RejoinBackoffMax: 500 * time.Millisecond}}, "a", "b")
		la, lb := w.link("a"), w.link("b")
		la.SetDelay(10*time.Millisecond, 0)
		lb.SetDelay(100*time.Millisecond, 0) // b's first PONG is ≥ 200 ms away
		la.SetRate(16 << 20)
		lb.SetRate(16 << 20)
		lb.SetRefuse(true)
		dc, pc := w.open(w.peer(nil, la, lb), rendr.DialOptions{Mode: rendr.ModeBond})
		f := startFlow(dc, pc, n, 331, flowOpts{closeWrite: true, eof: true})
		waitFor(t, time.Minute, "a's capacity proven under backlog", func() bool {
			a, ok := memberOn(dc.Status(), "a")
			return ok && a.Cap >= 4*floor && f.got.Load() >= n/10
		})
		if len(dataCarriers(dc.Status())) != 1 || lb.Stats().DialFailures == 0 {
			t.Fatalf("b joined early or was never tried: %+v", dc.Status().Carriers)
		}
		lb.SetRefuse(false)
		var joined rendr.CarrierStatus
		waitFor(t, 5*time.Second, "b attached", func() bool {
			var ok bool
			joined, ok = memberOn(dc.Status(), "b")
			return ok
		})
		if joined.SRTT != 0 || joined.Rate != 0 || joined.Cap != floor {
			t.Fatalf("the new member is not Unknown at the floor: %+v", joined)
		}
		// Until its first PONG: data at once, never beyond the floor plus one segment.
		var maxTx uint64
		for {
			b, ok := carrierOf(dc.Status(), joined.ID)
			if !ok || b.State == rendr.CarrierDead {
				t.Fatalf("the new member is gone: %+v", dc.Status().Carriers)
			}
			if b.SRTT != 0 {
				break
			}
			maxTx = max(maxTx, b.TxBytes)
			if maxTx > floor+segment {
				t.Fatalf("the Unknown member has %d bytes in flight before any PONG, want ≤ floor + one segment (%d)", maxTx, floor+segment)
			}
			time.Sleep(time.Millisecond)
		}
		if maxTx < floor/2 {
			t.Fatalf("the Unknown member got only %d bytes before its first PONG: starved behind the proven member", maxTx)
		}
		waitFor(t, 10*time.Second, "the new member's capacity raised by its own evidence", func() bool {
			b, ok := carrierOf(dc.Status(), joined.ID)
			return ok && b.Cap > floor
		})
		// From then on it carries a real share: over the next 300 ms (the
		// transfer still running), at least 15% of the bytes sent.
		shares := func() (a, b uint64) {
			st := dc.Status()
			ca, _ := memberOn(st, "a")
			cb, _ := carrierOf(st, joined.ID)
			return ca.TxBytes, cb.TxBytes
		}
		a0, b0 := shares()
		time.Sleep(300 * time.Millisecond)
		a1, b1 := shares()
		if f.got.Load() >= n {
			t.Fatal("the transfer ended within the share window (load not reached)")
		}
		share := float64(b1-b0) / float64(a1-a0+b1-b0)
		t.Logf("before its first PONG the new member carried %s; afterwards %.0f%% of the bytes sent in 300 ms", mib(int64(maxTx)), share*100)
		if share < 0.15 {
			t.Fatalf("the joined member carried %.1f%% of the bytes sent in 300 ms after its capacity grew, want a real share (≥ 15%%)", share*100)
		}
		f.wait(t, time.Minute, "transfer")
		endClean(t, dc, pc)
		w.close()
	})
}
