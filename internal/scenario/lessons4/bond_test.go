package lessons4

import (
	"fmt"
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
// path (one-way; the same rate R = 4 MiB/s each) moves 64 MiB (16 MiB under
// -race). "window": the receiver's window W = 1.5 MiB is below what the two
// paths could keep busy (≈ R·400 ms on the slow path plus the fast data
// queued for 200 ms behind its head), so the sender is window-limited —
// the case the lesson is about: the fast member must never run so far
// ahead of the head on the slow member that the receiver has to hold more
// than W; its receive charge reaches W/2 (the window binds). "aggregate":
// the default 8 MiB window does not bind, and the bond adds the slow path's
// rate to the fast one's. In both the receiver's charge stays within W
// plus its two reader stages, no carrier dies (no window violation),
// nothing is retransmitted (nothing was dropped at the receiver's 2·W cap
// or rescued), the steady goodput (25%–90% of the transfer) beats a single
// fast carrier (> 1.2·R), the slow member carries a real share, and every
// byte arrives intact.
func TestBondAsymmetricReorderBounded_L34(t *testing.T) {
	for _, c := range []struct {
		name   string
		window int // the passive's Window (0: the default 8 MiB)
	}{
		{"window", 3 << 19},
		{"aggregate", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { bondAsym(t, c.window) })
		})
	}
}

func bondAsym(t *testing.T, window int) {
	const rate = 4 << 20 // bytes/s per path
	n := int64(64 << 20)
	if raceEnabled {
		n = 16 << 20
	}
	w := newWorld(t, worldOpts{pcfg: rendr.Config{Window: window}}, "fast", "slow")
	lf, ls := w.link("fast"), w.link("slow")
	lf.SetDelay(5*time.Millisecond, 0)
	ls.SetDelay(200*time.Millisecond, 0)
	lf.SetRate(rate)
	ls.SetRate(rate)
	dc, pc := w.open(w.peer(nil, lf, ls), rendr.DialOptions{Mode: rendr.ModeBond})
	waitFor(t, 5*time.Second, "both members", func() bool { return len(dataCarriers(dc.Status())) == 2 })
	win := pc.Status().Window
	if window != 0 && win != int64(window) {
		t.Fatalf("the passive advertises a %s window, want %s", mib(win), mib(int64(window)))
	}

	start := time.Now()
	f := startFlow(dc, pc, n, 34, flowOpts{closeWrite: true, eof: true})
	// The passive only receives: its Budget charge is its receive buffers
	// (in order and out of order) plus its carriers' reader stages.
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

	// The goodput of the steady part, from 25% to 90% of the transfer (the
	// slow member's ramp from the capacity floor takes a few of its 400 ms
	// RTTs).
	from, ok := f.reached(n / 4)
	to, ok2 := f.reached(n * 9 / 10)
	if !ok || !ok2 || !to.at.After(from.at) {
		t.Fatalf("no steady part in the reads (%v, %v)", from, to)
	}
	got := float64(to.got-from.got) / to.at.Sub(from.at).Seconds()
	ds, ps := dc.Status(), pc.Status()
	slow, ok := memberOn(ds, "slow")
	fast, ok2 := memberOn(ds, "fast")
	t.Logf("window %s: steady goodput %.2f MiB/s (single path %.2f; %.2f MiB/s with the ramp), passive buffered ≤ %s, shares fast %s / slow %s, retransmitted %d",
		mib(win), got/(1<<20), float64(rate)/(1<<20), float64(n)/elapsed.Seconds()/(1<<20), mib(maxBuf),
		mib(int64(fast.TxBytes)), mib(int64(slow.TxBytes)), ds.RetransmittedBytes)
	// A reader stage: one 16 KiB-class stage buffer plus one 64 KiB-class
	// DATA buffer being filled (design D29, §4.9).
	stages := 2 * int64(16<<10+64+64<<10+64)
	if window != 0 {
		if maxBuf < win/2 {
			t.Fatalf("the passive buffered at most %s: the %s window never bound (load not reached)", mib(maxBuf), mib(win))
		}
	}
	if limit := win + stages; maxBuf > limit {
		t.Fatalf("the passive buffered up to %s, want ≤ its window plus two reader stages (%s): the fast member ran ahead of the window", mib(maxBuf), mib(limit))
	}
	if got <= 1.2*rate {
		t.Fatalf("steady goodput %.2f MiB/s, want more than a single fast path (%.2f MiB/s) by 20%%", got/(1<<20), float64(rate)/(1<<20))
	}
	for _, s := range []rendr.SessionStatus{ds, ps} {
		if d := deadOf(s); len(d) != 0 || s.Migrations != (rendr.MigrationCounts{}) {
			t.Fatalf("%v: dead carriers %+v, migrations %+v; want none", s.Role, d, s.Migrations)
		}
	}
	if ds.RetransmittedBytes != 0 {
		t.Fatalf("the dialer retransmitted %d bytes: DATA beyond the window was dropped or a head was rescued", ds.RetransmittedBytes)
	}
	if !ok || !ok2 || int64(slow.TxBytes) < n/10 || int64(fast.TxBytes) < n/10 {
		t.Fatalf("member shares: fast %d, slow %d of %d bytes; want ≥ 10%% each", fast.TxBytes, slow.TxBytes, n)
	}
	if lf.Stats().Session.MaxDelay != 5*time.Millisecond || ls.Stats().Session.MaxDelay != 200*time.Millisecond ||
		lf.Stats().Throttled == 0 || ls.Stats().Throttled == 0 {
		t.Fatal("the asymmetric delays or the rate limits were not applied (stimulus)")
	}
	endClean(t, dc, pc)
	w.close()
}

// TestBondStalledMemberRecovers_L34 (Z4; design §4.11, §11.4): the
// lowest-srtt member stalls while the receiver holds part of one of its
// frames, and the head of the send window is held by it. The other member
// rescues that head (the holder never duplicates it itself while another
// data lane exists) within max(300 ms, 3·srtt), so the receiver's in-order
// delivery moves on long before any death deadline; a stall shorter than
// the death deadline kills nothing, and the session then finishes intact.
// A rescue is a duplicate of the head the receiver lacks: the stalled
// member's death and requeue is none, nor is a resend of bytes the
// receiver already has in order (the test names either case). Two stalls:
// "write" — the member's carrier Write stops in the middle of a frame (the
// embedder conn blocks after half a batch; its path stays healthy) —, and
// "path" — the member's path stops delivering in both directions while its
// conns keep accepting writes until the link buffer is full (L34's "a
// stalled member that still accepts writes"). There the receiver's ACK duty
// stays on the stalled member, whose small writes never block; its ACKs
// reach the dialer over the other member, which delivers DATA beyond the
// gap (design §0.13 A4).
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
	defer lf.SetStall(false) // a failed test still ends its bubble
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

	// Wait for the slow member's duplicate of the stuck head — or for the
	// stalled member's death: its requeue would resend bytes on the slow
	// member too, but it is no rescue.
	var rescuedAt time.Time
	var atD, atP rendr.SessionStatus // both ends at that moment
	waitFor(t, 3*time.Second, "a rescue by the other member", func() bool {
		st := dc.Status()
		sc, _ := carrierOf(st, slow.ID)
		fc, _ := carrierOf(st, fast.ID)
		if sc.RetxBytes == 0 && fc.State != rendr.CarrierDead {
			return false
		}
		rescuedAt, atD, atP = time.Now(), st, pc.Status()
		return true
	})
	if path && lf.Stats().Session.Held == 0 {
		t.Fatal("the path stall held no chunk of the fast member (stimulus)")
	}
	fc, _ := carrierOf(atD, fast.ID)
	sc, _ := carrierOf(atD, slow.ID)
	// ACK = delivered: once the head has been stuck long enough to be
	// rescued, the dialer's acknowledged front is the receiver's in-order
	// front — unless the receiver's ACKs cannot reach the dialer.
	ackLag := int64(atP.RxBytes) - int64(atD.AckedBytes)
	diag := fmt.Sprintf("at +%v the dialer had %s acknowledged and the receiver %s in order (ACK lag %s); the fast member was %v (retransmitted %d, in flight %d, death %v %q), the slow member had retransmitted %d (in flight %d)",
		rescuedAt.Sub(stallAt), mib(int64(atD.AckedBytes)), mib(int64(atP.RxBytes)), mib(ackLag),
		fc.State, fc.RetxBytes, fc.Inflight, fc.DeathCause, fc.DeathDetail, sc.RetxBytes, sc.Inflight)
	if fc.State == rendr.CarrierDead {
		t.Fatalf("no rescue sender: no member duplicated the stuck head before the stalled member died (its requeue is no rescue); %s", diag)
	}
	if ackLag >= 64<<10 {
		t.Fatalf("the rescue resent bytes the receiver already had in order: its ACKs are held on the stalled member, so the dialer cannot see the real head; %s", diag)
	}
	time.Sleep(time.Second - time.Since(stallAt)) // a stall shorter than the death deadline (≥ 2 s here)
	stuck := f.got.Load()
	releasedAt := time.Now()
	if path {
		lf.SetStall(false)
	} else {
		close(ctl.release)
	}
	moved, ok := f.firstReadAfter(rescuedAt)
	movedAt := "none before the release"
	if ok {
		movedAt = fmt.Sprintf("+%v (%s)", moved.at.Sub(stallAt), mib(moved.got))
	}
	// The head is stuck since the receiver's last in-order delivery before
	// the rescue, and the rescue clock (lastAdvance) starts when the ACK of
	// that delivery reaches the dialer. With a stalled write the ACK duty
	// moves off the blocked lane and the ACK arrives within the ACK delay
	// (20 ms) and one srtt. With a stalled path the duty lane's writes never
	// block: the ACK rides the other member, which carries it as soon as it
	// delivers DATA beyond the gap — within one of its round trips — and
	// then crosses that member's path (design §0.13 A4): 2·srtt of the
	// rescuing member.
	ackBy := 20*time.Millisecond + srtt
	if path {
		ackBy = 2 * slow.SRTT
	}
	last, _ := f.lastReadBefore(rescuedAt)
	ds, ps := dc.Status(), pc.Status()
	t.Logf("fast srtt %v, slow srtt %v: receiver at %s when stalled, stuck from +%v, rescue at +%v (bound %v), first delivery after it %s, %s at the release; dialer acked %s",
		srtt, slow.SRTT, mib(stuckAt), last.at.Sub(stallAt), rescuedAt.Sub(stallAt), bound, movedAt, mib(stuck), mib(int64(ds.AckedBytes)))
	if d := rescuedAt.Sub(last.at); d > bound+ackBy {
		t.Fatalf("the rescue left %v after the head got stuck, want within max(300 ms, 3·srtt) = %v plus %v for its ACK", d, bound, ackBy)
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
// under backlog: once the transfer turns into a demand-limited trickle
// (≈ 100 KB/s for 10 s), the member carrying it is no longer backlogged, so
// its PONGs bring no rate sample: its rate estimate decays far below even
// the trickle's own rate, which samples taken without backlog would track,
// and its cap falls back to the 128 KiB floor (the cold-start prior).
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

		// A demand-limited trickle: 2 KiB every 20 ms for 10 s. It rides the
		// lowest-srtt member, the fast one. Its rate decays by 0.95 per
		// 50 ms (design §4.10) from ≈ 16 MiB/s to ≈ 0.6 KB/s in 10 s, while
		// samples taken without backlog would keep it near the trickle's own
		// rate.
		const chunk, gap, writes = 2 << 10, 20 * time.Millisecond, 500
		trickle := float64(chunk) / gap.Seconds()
		g := startFlow(dc, pc, writes*chunk, 33, flowOpts{chunk: chunk, pace: gap})
		g.wait(t, time.Minute, "trickle")
		st := dc.Status()
		carrying, ok := memberOn(st, "fast")
		if !ok || carrying.TxBytes <= fc.TxBytes {
			t.Fatalf("the fast member carried none of the trickle: %+v", st.Carriers)
		}
		t.Logf("after the trickle (%.0f B/s): fast rate %.0f cap %d; slow (idle) rate %.0f cap %d", trickle, carrying.Rate, carrying.Cap, sc.Rate, sc.Cap)
		if carrying.Rate >= trickle/4 || carrying.Cap != floor {
			t.Fatalf("after 10 s of demand-limited traffic the fast member's rate is %.0f B/s (was %.0f; the trickle's own rate %.0f) and its cap %d: want the rate far below the trickle's (no rate sample without backlog) and the %d floor",
				carrying.Rate, fc.Rate, trickle, carrying.Cap, floor)
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
