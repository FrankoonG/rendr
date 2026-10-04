package lessons2

import (
	"context"
	"errors"
	"net"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestRedialAfterFailures_L20 (L20): the factory's 2nd and 3rd calls fail.
// The carrier dies in the middle of a transfer in both directions; the
// immediate redial (call 2) and the first backoff retry (call 3) fail, the
// next one attaches within 2 s of the death. Killed again later, the
// session recovers at once (call 5). The transfers complete intact and both
// ends count exactly two death migrations.
func TestRedialAfterFailures_L20(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, rendr.Config{}, rendr.Config{}, nil)
		a := e.path("a", time.Millisecond)
		a.gate = func(_ context.Context, n int64, _ []byte) error {
			if n == 2 || n == 3 {
				return errRefused
			}
			return nil
		}
		dc, pc := e.open(e.peer(a), rendr.DialOptions{}) // factory call 1
		vol := int64(8 << 20)
		if raceEnabled {
			vol = 2 << 20
		}
		a.link.SetRate(float64(vol / 4)) // each direction takes about 4 s
		up := startXfer(dc, pc, vol, 201, vol/8)
		down := startXfer(pc, dc, vol, 202, vol/8)
		up.waitMark(t, 0, 20*time.Second)
		down.waitMark(t, 0, 20*time.Second)

		if n := a.link.Kill(); n != 1 {
			t.Fatalf("Kill killed %d carriers", n)
		}
		took := waitFor(t, 2*time.Second, time.Millisecond, "reattach", func() bool {
			st := dc.Status()
			return st.NoPathEpisodes == 1 && !st.InNoPath
		})
		if n := a.calls.Load(); n != 4 {
			t.Fatalf("%d factory calls, want 4 (calls 2 and 3 failed)", n)
		}
		t.Logf("reattached %v after the death, at the 4th factory call", took)

		// The second death once the session runs on the new carrier: the
		// passive follows its SCHED and both directions moved data over it.
		waitFor(t, time.Second, time.Millisecond, "passive follows", func() bool {
			return pc.Status().SchedEpoch == dc.Status().SchedEpoch
		})
		u0, d0 := up.got.Load(), down.got.Load()
		waitFor(t, 20*time.Second, time.Millisecond, "progress after the recovery", func() bool {
			return up.got.Load() >= u0+256<<10 && down.got.Load() >= d0+256<<10
		})
		if up.got.Load() >= vol || down.got.Load() >= vol {
			t.Fatalf("stimulus: the transfers finished before the second death (up %d, down %d of %d)", up.got.Load(), down.got.Load(), vol)
		}
		if n := a.link.Kill(); n != 1 {
			t.Fatalf("second Kill killed %d carriers", n)
		}
		up.wait(t, 30*time.Second)
		down.wait(t, 30*time.Second)
		if n := a.calls.Load(); n != 5 {
			t.Fatalf("%d factory calls, want 5", n)
		}
		for _, c := range []*rendr.Conn{dc, pc} {
			if st := c.Status(); st.State != rendr.StateOpen || st.Migrations.Death != 2 || st.NoPathEpisodes != 2 {
				t.Fatalf("%v after two deaths: %+v", st.Role, st)
			}
		}
		if st := dc.Status(); st.Rejoins != 2 || a.link.Stats().Session.Killed != 2 {
			t.Fatalf("stimulus: rejoins %d, killed %d", st.Rejoins, a.link.Stats().Session.Killed)
		}
		endClean(t, dc, pc)
		e.close()
	})
}

// TestManySlotsDieTogether_L20 (L20): 64 sessions, one factory slot each,
// lose their carriers at once while the factory hangs and ignores its
// context. Exactly 64 factory calls run concurrently — one recovery per
// slot, no second wave while they hang — and Runtime.Close returns within
// 100 ms, every stuck call counted in Status.Abandoned until the factory
// returns.
func TestManySlotsDieTogether_L20(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const slots = 64
		e := newEnv(t, rendr.Config{}, rendr.Config{}, nil)
		a := e.path("a", time.Millisecond)
		peer := e.peer(a)
		dcs, pcs := make([]*rendr.Conn, slots), make([]*rendr.Conn, slots)
		for i := range slots {
			dcs[i], pcs[i] = e.open(peer, rendr.DialOptions{})
		}
		for i := range slots {
			exchange(t, dcs[i], pcs[i], 16<<10, uint64(2000+2*i))
		}

		a.link.SetDial(rendrtest.DialHangForever)
		before := a.calls.Load()
		if n := a.link.Kill(); n != slots {
			t.Fatalf("Kill killed %d carriers, want %d", n, slots)
		}
		synctest.Wait()
		check := func(when string) {
			t.Helper()
			if calls, in, pk := a.calls.Load()-before, a.inflight.Load(), a.peak.Load(); calls != slots || in != slots || pk != slots {
				t.Fatalf("%s: %d factory calls, %d running, peak %d; want exactly %d", when, calls, in, pk, slots)
			}
		}
		check("right after the deaths")
		time.Sleep(time.Second)
		check("1 s later")

		start := time.Now()
		if err := e.d.Close(); err != nil {
			t.Fatal(err)
		}
		if el := time.Since(start); el > 100*time.Millisecond {
			t.Fatalf("Runtime.Close took %v with %d hung factory calls", el, slots)
		}
		if n := e.d.Status().Abandoned; n != slots {
			t.Fatalf("abandoned %d when Runtime.Close returned, want the %d stuck factory calls", n, slots)
		}
		for i, c := range dcs {
			if _, err := c.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("session %d: Read after Runtime.Close = %v", i, err)
			}
		}
		a.link.Release() // the factory calls return
		waitFor(t, 5*time.Second, 10*time.Millisecond, "stuck calls returned", func() bool { return e.d.Status().Abandoned == 0 })
		e.close()
	})
}

// TestBondMemberImmediateRedial_L20_L22 (L20, L22; plan §3.6): a healthy
// bond member is killed in the middle of a transfer. Its death marks the
// factory failed in the health layer — and the member's slot redials it at
// once anyway (the mark only ranks): the JOIN starts at the death and the
// factory is a member again one dial plus one RTT later, as a new
// incarnation (Gen 2, one rejoin) that PINGs at once. The transfers
// complete intact.
func TestBondMemberImmediateRedial_L20_L22(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const oneWay = 25 * time.Millisecond // RTT 50 ms: the mark is observable while the JOIN is in flight
		e := newEnv(t, rendr.Config{}, rendr.Config{}, nil)
		a := e.path("a", oneWay)
		a.early = true
		b := e.path("b", oneWay)
		peer := e.peer(a, b)
		dc, pc := e.open(peer, rendr.DialOptions{Mode: rendr.ModeBond})
		waitFor(t, 5*time.Second, time.Millisecond, "members a and b", func() bool {
			st := dc.Status()
			return len(liveOf(st, "a")) == 1 && len(liveOf(st, "b")) == 1
		})
		vol := int64(4 << 20)
		if raceEnabled {
			vol = 1 << 20
		}
		for _, p := range []*path{a, b} {
			p.link.SetRate(float64(vol / 4)) // about 2 s per direction over both members
		}
		up := startXfer(dc, pc, vol, 203, vol/4)
		down := startXfer(pc, dc, vol, 204, vol/4)
		up.waitMark(t, 0, 20*time.Second)
		down.waitMark(t, 0, 20*time.Second)

		old := liveOf(dc.Status(), "a")[0]
		t1 := time.Now()
		if n := a.link.Kill(); n < 1 {
			t.Fatalf("Kill killed %d carriers", n)
		}
		synctest.Wait()
		if fs := peer.Status().Factories[0]; !fs.Failed {
			t.Fatalf("stimulus: factory a not marked failed after its member died: %+v", fs)
		}
		joins := a.callsSince(t1, wire.TypeJoin)
		if len(joins) != 1 || !joins[0].at.Equal(t1) {
			t.Fatalf("JOIN dials of a after the death: %+v, want one started at the death", joins)
		}
		took := waitFor(t, time.Second, time.Millisecond, "member a back", func() bool {
			ls := liveOf(dc.Status(), "a")
			return len(ls) == 1 && ls[0].ID != old.ID
		})
		if took > 2*oneWay+time.Millisecond {
			t.Fatalf("member a back %v after its death, want one dial plus one RTT (%v)", took, 2*oneWay)
		}
		st := dc.Status()
		if nw := liveOf(st, "a")[0]; nw.Gen != old.Gen+1 || st.Rejoins != 1 {
			t.Fatalf("rejoined member %+v (old gen %d), rejoins %d", nw, old.Gen, st.Rejoins)
		}
		sc := a.sessionConns(true)
		nc := sc[len(sc)-1]
		ack, ok := nc.in.first()
		pings := nc.out.list(wire.TypePing)
		if !ok || ack.typ != wire.TypeJoinAck || len(pings) == 0 || !pings[0].at.Equal(ack.at) {
			t.Fatalf("the rejoined carrier's first PING at %v, JOIN_ACK at %v: want the PING at once", pings, ack)
		}
		if up.got.Load() >= vol || down.got.Load() >= vol {
			t.Fatal("stimulus: the transfers finished before the member came back")
		}
		up.wait(t, 30*time.Second)
		down.wait(t, 30*time.Second)
		endClean(t, dc, pc)
		e.close()
	})
}

// TestOptionalCarrierAttachesAfterFix_L20 (L20): a bond's second factory b
// first reaches a non-rendr endpoint (a misconfigured forwarding). Dial
// succeeds on a — the first admitted carrier is the Dial's success; b's
// failed handshakes are never reported to the application — data flows on
// a, and b's member slot keeps retrying with backoff. Once the forwarding
// is fixed, b attaches within two backoff periods (with its first attempt
// after the fix) and then carries data; everything arrives intact.
func TestOptionalCarrierAttachesAfterFix_L20(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, rendr.Config{}, rendr.Config{}, nil)
		a := e.path("a", 5*time.Millisecond)
		b := e.path("b", time.Millisecond) // the faster path once it works
		b.early = true
		b.setFar(nonRendr)
		peer := e.peer(a, b)
		start := time.Now()
		dc, pc := e.open(peer, rendr.DialOptions{Mode: rendr.ModeBond})
		exchange(t, dc, pc, 512<<10, 205)

		time.Sleep(time.Until(start.Add(12 * time.Second)))
		joins := b.callsSince(start, wire.TypeJoin)
		if len(joins) < 4 {
			t.Fatalf("stimulus: %d JOIN attempts on b in 12 s", len(joins))
		}
		for i := 2; i < len(joins); i++ { // the spacing grows with the backoff
			if joins[i].at.Sub(joins[i-1].at) < joins[i-1].at.Sub(joins[i-2].at)/2 {
				t.Fatalf("JOIN attempts on b not backing off: %+v", joins)
			}
		}
		if st := dc.Status(); len(liveOf(st, "b")) != 0 || st.State != rendr.StateOpen || len(b.received(wire.TypeJoin)) != 0 {
			t.Fatalf("before the fix: %+v", st)
		}

		fixed := time.Now()
		b.setFar(e.ln.Handle)
		took := waitFor(t, 20*time.Second, time.Millisecond, "b attached", func() bool { return len(liveOf(dc.Status(), "b")) == 1 })
		const backoffMax = 4 * time.Second // RejoinBackoffMax
		if took > 2*backoffMax*6/5 {
			t.Fatalf("b attached %v after the fix, want within two backoff periods", took)
		}
		if n := len(b.callsSince(fixed, wire.TypeJoin)); n != 1 {
			t.Fatalf("%d JOIN attempts on b after the fix, want the first one to attach", n)
		}
		t.Logf("b attached %v after the fix (%d failed JOIN attempts before)", took, len(joins))
		if st := dc.Status(); st.Rejoins != 0 || st.State != rendr.StateOpen {
			t.Fatalf("after b attached: %+v", st)
		}
		// Once b has an RTT sample and the passive follows the grown member
		// set, the faster b takes demand-limited data (srtt order, §4.11).
		waitFor(t, time.Second, time.Millisecond, "b measured and followed", func() bool {
			st := dc.Status()
			ls := liveOf(st, "b")
			return len(ls) == 1 && ls[0].SRTT > 0 && st.SchedEchoed == st.SchedEpoch
		})
		time.Sleep(100 * time.Millisecond)
		exchange(t, dc, pc, 1<<20, 207)
		if len(b.received(wire.TypeData)) == 0 || len(b.sentBack(wire.TypeData)) == 0 {
			t.Fatalf("b carries no DATA after it attached: dialer→passive a %d b %d, passive→dialer a %d b %d; status %+v",
				dataBytes(a.received(wire.TypeData)), dataBytes(b.received(wire.TypeData)),
				dataBytes(a.sentBack(wire.TypeData)), dataBytes(b.sentBack(wire.TypeData)), dc.Status())
		}
		endClean(t, dc, pc)
		e.close()
	})
}
