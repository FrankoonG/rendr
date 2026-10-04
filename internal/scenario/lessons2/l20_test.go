package lessons2

import (
	"context"
	"errors"
	"net"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestRedialAfterFailures_L20 (L20): the factory's 2nd and 3rd calls fail.
// The carrier dies in the middle of a transfer in both directions; the
// immediate redial (call 2) and the first backoff retry (call 3) fail and
// the next one (call 4) attaches within 2 s of the death — the calls start
// on the plan §3.6 cadence: at the death, then 0.5 s and 1 s apart (the
// jitter fixed at its mean). Then the replacement dies too, either once the
// passive followed its SCHED and both directions moved data over it, or
// right after it attached, before that SCHED could reach the passive (L20:
// "替换后立刻又死就再拨"). The session redials at once (call 5) and
// recovers, the transfers complete intact, and both ends count exactly two
// death migrations (L20: "两端都计数迁移"; design §7.6: "both ends count the
// same selector migrations").
func TestRedialAfterFailures_L20(t *testing.T) {
	for _, tc := range []struct {
		name     string
		followed bool // the second death waits until the passive applied the replacement's SCHED
	}{
		{"replacement dies after the passive followed", true},
		{"replacement dies before the passive followed", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const (
					oneWay = 20 * time.Millisecond // a SCHED needs 20 ms to reach the passive
					jitter = 0.5                   // U[0,1) fixed: the backoff factor 0.8 + 0.4·U is 1
				)
				// backoff is the plan §3.6 interval after the n-th consecutive failure
				// (n from 0), below the RejoinBackoffMax cap here.
				backoff := func(n int) time.Duration {
					return time.Duration(float64(500*time.Millisecond<<n) * (0.8 + 0.4*jitter))
				}
				e := newEnv(t, rendr.Config{}, rendr.Config{}, &testhooks.Overrides{Rand: func() float64 { return jitter }})
				a := e.path("a", oneWay)
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

				t0 := time.Now()
				if n := a.link.Kill(); n != 1 {
					t.Fatalf("Kill killed %d carriers", n)
				}
				took := waitFor(t, 2*time.Second, time.Millisecond, "reattach", func() bool {
					st := dc.Status()
					return st.NoPathEpisodes == 1 && !st.InNoPath
				})
				cs := a.callsSince(t0, 0)
				want := []time.Time{t0, t0.Add(backoff(0)), t0.Add(backoff(0) + backoff(1))}
				if n := a.calls.Load(); n != 4 || len(cs) != len(want) {
					t.Fatalf("%d factory calls (%d since the death), want 4 (calls 2 and 3 failed)", n, len(cs))
				}
				for i, c := range cs {
					if !c.at.Equal(want[i]) {
						t.Fatalf("factory call %d started %v after the death, want %v (plan §3.6 cadence)", c.n, c.at.Sub(t0), want[i].Sub(t0))
					}
				}
				t.Logf("reattached %v after the death, at the 4th factory call", took)

				if tc.followed {
					// The session runs on the replacement: the passive follows its SCHED
					// and both directions moved data over it.
					waitFor(t, time.Second, time.Millisecond, "passive follows", func() bool {
						return pc.Status().SchedEpoch == dc.Status().SchedEpoch
					})
					u0, d0 := up.got.Load(), down.got.Load()
					waitFor(t, 20*time.Second, time.Millisecond, "progress after the recovery", func() bool {
						return up.got.Load() >= u0+256<<10 && down.got.Load() >= d0+256<<10
					})
				} else if ds, ps := dc.Status(), pc.Status(); ps.SchedEpoch == ds.SchedEpoch {
					t.Fatalf("stimulus: the passive already applied the replacement's SCHED (epoch %d)", ds.SchedEpoch)
				}
				if up.got.Load() >= vol || down.got.Load() >= vol {
					t.Fatalf("stimulus: the transfers finished before the second death (up %d, down %d of %d)", up.got.Load(), down.got.Load(), vol)
				}
				t1 := time.Now()
				if n := a.link.Kill(); n != 1 {
					t.Fatalf("second Kill killed %d carriers", n)
				}
				up.wait(t, 30*time.Second)
				down.wait(t, 30*time.Second)
				if cs := a.callsSince(t1, 0); a.calls.Load() != 5 || len(cs) != 1 || !cs[0].at.Equal(t1) {
					t.Fatalf("%d factory calls, after the second death %+v; want call 5, started at the death", a.calls.Load(), cs)
				}
				ds, ps := dc.Status(), pc.Status()
				for _, st := range []rendr.SessionStatus{ds, ps} {
					if st.State != rendr.StateOpen || st.NoPathEpisodes != 2 {
						t.Fatalf("%v after two deaths: %+v", st.Role, st)
					}
				}
				if ds.Rejoins != 2 || a.link.Stats().Session.Killed != 2 || ds.Migrations.Death != 2 {
					t.Fatalf("dialer after two deaths: rejoins %d, killed %d, death migrations %d; want 2 each",
						ds.Rejoins, a.link.Stats().Session.Killed, ds.Migrations.Death)
				}
				if ps.Migrations.Death != ds.Migrations.Death {
					why := ""
					if !tc.followed {
						why = "; the passive counts a migration when an applied SCHED changes its named lane, and the" +
							" SCHED naming the replacement died with it, superseded before the passive could apply it"
					}
					// Non-fatal: the session itself must still end cleanly.
					t.Errorf("death migrations: dialer %d, passive %d; want 2 on both ends (L20, design §7.6)%s",
						ds.Migrations.Death, ps.Migrations.Death, why)
				}
				endClean(t, dc, pc)
				e.close()
			})
		})
	}
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
// first reaches a non-rendr endpoint (a misconfigured forwarding) that
// answers every handshake with an HTTP error. Dial succeeds on a — the
// first admitted carrier is the Dial's success; b's failed handshakes are
// never reported to the application — data flows on a, and b's member slot
// keeps retrying with backoff (jitter fixed at its mean, so the attempt
// times are reproducible). Once the forwarding is fixed, b attaches within
// two backoff periods (2 × RejoinBackoffMax × 1.2, the longest jittered
// interval) with its first attempt after the fix, and then carries data in
// both directions; everything arrives intact.
func TestOptionalCarrierAttachesAfterFix_L20(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			backoffMax = 4 * time.Second       // RejoinBackoffMax (the default, set explicitly)
			pingBusy   = 50 * time.Millisecond // PingBusy (the default, set explicitly)
		)
		cfg := rendr.Config{RejoinBackoffMax: backoffMax, PingBusy: pingBusy}
		e := newEnv(t, cfg, cfg, &testhooks.Overrides{Rand: func() float64 { return 0.5 }})
		a := e.path("a", 5*time.Millisecond)
		b := e.path("b", time.Millisecond) // the faster path once it works
		b.early = true
		junk := new(junkEnd)
		b.setFar(junk.accept)
		peer := e.peer(a, b)
		start := time.Now()
		dc, pc := e.open(peer, rendr.DialOptions{Mode: rendr.ModeBond})
		exchange(t, dc, pc, 512<<10, 205)

		time.Sleep(time.Until(start.Add(3 * backoffMax)))
		joins := b.callsSince(start, wire.TypeJoin)
		if len(joins) < 4 || junk.join.Load() != int64(len(joins)) {
			t.Fatalf("stimulus: %d JOIN attempts on b in %v, %d of them answered by the non-rendr endpoint", len(joins), 3*backoffMax, junk.join.Load())
		}
		for i := 2; i < len(joins); i++ { // the spacing grows with the backoff
			if joins[i].at.Sub(joins[i-1].at) < joins[i-1].at.Sub(joins[i-2].at)/2 {
				t.Fatalf("JOIN attempts on b not backing off: %+v", joins)
			}
		}
		// Only a's carrier reached the passive: none of b's attempts got there.
		st, ps := dc.Status(), pc.Status()
		if la := liveOf(st, "a"); len(liveOf(st, "b")) != 0 || st.State != rendr.StateOpen || len(la) != 1 ||
			len(ps.Carriers) != 1 || ps.Carriers[0].ID != la[0].ID {
			t.Fatalf("before the fix: dialer %+v, passive carriers %+v", st, ps.Carriers)
		}

		fixed := time.Now()
		b.setFar(e.ln.Handle)
		took := waitFor(t, 20*time.Second, time.Millisecond, "b attached", func() bool { return len(liveOf(dc.Status(), "b")) == 1 })
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
		// Once b has an RTT sample on both ends and the passive follows the
		// grown member set, the faster b takes demand-limited data in both
		// directions: each end wakes its data lanes in srtt order, an order
		// it re-sorts at most once per PingBusy (design §4.11), so b leads it
		// on both ends PingBusy after its first sample.
		waitFor(t, time.Second, time.Millisecond, "b measured on both ends and followed", func() bool {
			st, ps := dc.Status(), pc.Status()
			ls := liveOf(st, "b")
			if len(ls) != 1 || ls[0].SRTT == 0 || st.SchedEchoed != st.SchedEpoch || ps.SchedEpoch != st.SchedEpoch {
				return false
			}
			for _, c := range ps.Carriers {
				if c.ID == ls[0].ID {
					return c.State == rendr.CarrierMember && c.SRTT > 0
				}
			}
			return false
		})
		time.Sleep(pingBusy)
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
