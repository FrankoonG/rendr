package lessons2

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestNoPathGraceExpiry_L18 (L18): NoPathGrace 200 ms, the only factory
// fails from the moment the carrier dies. A Write blocked on the full
// window and a Read blocked for data both return ErrNoPath — errors.Is,
// not io.EOF, not a timeout — between 200 and 700 ms after the death, and
// the factory was called at least once in between (the episode redialled;
// the expiry is not a false pass of a session that never tried). Later
// calls return the same error. What the passive received before the
// outage is intact.
func TestNoPathGraceExpiry_L18(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const grace, win = 200 * time.Millisecond, 256 << 10
		cfg := rendr.Config{Window: win}
		e := newEnv(t, cfg, cfg, &testhooks.Overrides{NoPathGrace: grace, Rand: func() float64 { return 0.5 }})
		a := e.path("a", time.Millisecond)
		dc, pc := e.open(e.peer(a), rendr.DialOptions{})

		const seed = 18
		payload := prngBytes(seed, win+64<<10)
		wres := goOp(func() (int, error) { return dc.Write(payload) })
		waitFor(t, 5*time.Second, time.Millisecond, "window full", func() bool {
			return dc.Status().TxBytes == win && pc.Status().RxBytes == win
		})
		rres := goOp(func() (int, error) { return dc.Read(make([]byte, 1)) })
		if !running(wres) || !running(rres) {
			t.Fatal("Read or Write did not block")
		}

		a.link.SetRefuse(true)
		before := a.calls.Load()
		t0 := time.Now()
		if n := a.link.Kill(); n != 1 {
			t.Fatalf("Kill killed %d carriers", n)
		}
		w := await(t, wres, 2*time.Second, "blocked Write")
		r := await(t, rres, 2*time.Second, "blocked Read")
		for _, x := range []struct {
			name string
			r    opResult
		}{{"Write", w}, {"Read", r}} {
			if el := x.r.at.Sub(t0); !isTerminal(x.r.err, rendr.ErrNoPath) || el < grace || el > 700*time.Millisecond {
				t.Fatalf("blocked %s returned %v after %v, want ErrNoPath within [%v, 700ms]", x.name, x.r.err, el, grace)
			}
		}
		if w.n != win || r.n != 0 {
			t.Fatalf("Write accepted %d bytes (want %d), Read returned %d", w.n, win, r.n)
		}
		if calls := a.calls.Load() - before; calls < 1 || a.link.Stats().DialFailures < calls {
			t.Fatalf("stimulus: %d factory calls during the episode (%d failed)", calls, a.link.Stats().DialFailures)
		}
		st := dc.Status()
		if st.State != rendr.StateEnded || !isTerminal(st.Err, rendr.ErrNoPath) || st.NoPathEpisodes != 1 {
			t.Fatalf("dialer status %+v", st)
		}
		if _, err := dc.Write([]byte{1}); !isTerminal(err, rendr.ErrNoPath) {
			t.Fatalf("Write after the expiry: %v", err)
		}
		if _, err := dc.Read(make([]byte, 1)); !isTerminal(err, rendr.ErrNoPath) {
			t.Fatalf("Read after the expiry: %v", err)
		}
		pc.SetReadDeadline(time.Now().Add(time.Second))
		got := make([]byte, win)
		if _, err := io.ReadFull(pc, got); err != nil || !bytes.Equal(got, payload[:win]) {
			t.Fatalf("passive data received before the outage: err %v, intact %v", err, bytes.Equal(got, payload[:win]))
		}
		e.close()
	})
}

// TestNoPathRecoveryBeforeGrace_L18 (L18): NoPathGrace 200 ms; the carrier
// dies in the middle of a transfer in both directions and the factory
// succeeds 150 ms later — either the first redial's factory call itself
// takes 150 ms, or the factory fails until then and the redial cadence
// (backoff capped at grace/2, jitter fixed at its low end) retries. The
// session recovers inside the grace, both transfers complete intact, and
// the episode is counted once on both ends.
func TestNoPathRecoveryBeforeGrace_L18(t *testing.T) {
	for _, tc := range []struct {
		name      string
		slow      bool  // the redial's factory call takes until the heal; else it fails until then
		wantCalls int64 // factory calls during the episode
	}{
		{"slow factory call", true, 1},
		{"factory fails until the heal", false, 3}, // at 0, 80 and 160 ms
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const grace, heal = 200 * time.Millisecond, 150 * time.Millisecond
				ov := &testhooks.Overrides{NoPathGrace: grace, Rand: func() float64 { return 0 }}
				e := newEnv(t, rendr.Config{}, rendr.Config{}, ov)
				a := e.path("a", time.Millisecond)
				var cut atomic.Pointer[time.Time]
				a.gate = func(ctx context.Context, _ int64, _ []byte) error {
					at := cut.Load()
					if at == nil {
						return nil
					}
					healAt := at.Add(heal)
					if tc.slow {
						select {
						case <-time.After(time.Until(healAt)):
							return nil
						case <-ctx.Done():
							return ctx.Err()
						}
					}
					if time.Now().Before(healAt) {
						return errRefused
					}
					return nil
				}
				dc, pc := e.open(e.peer(a), rendr.DialOptions{})
				vol := int64(4 << 20)
				if raceEnabled {
					vol = 1 << 20
				}
				a.link.SetRate(float64(4 * vol)) // each transfer takes about 250 ms
				up := startXfer(dc, pc, vol, 181, vol/3)
				down := startXfer(pc, dc, vol, 182, vol/3)
				up.waitMark(t, 0, 10*time.Second)
				down.waitMark(t, 0, 10*time.Second)

				before := a.calls.Load()
				t0 := time.Now()
				cut.Store(&t0)
				if n := a.link.Kill(); n != 1 {
					t.Fatalf("Kill killed %d carriers", n)
				}
				if up.got.Load() >= vol || down.got.Load() >= vol {
					t.Fatal("stimulus: the carrier died after the transfers")
				}
				up.wait(t, 30*time.Second)
				down.wait(t, 30*time.Second)

				ns, ne := e.dev.of(rendr.EventNoPathStart), e.dev.of(rendr.EventNoPathEnd)
				if len(ns) != 1 || len(ne) != 1 || !ns[0].Time.Equal(t0) {
					t.Fatalf("no-path events: start %+v, end %+v (death at %v)", ns, ne, t0)
				}
				if d := ne[0].Time.Sub(t0); d < heal || d >= grace {
					t.Fatalf("recovered %v after the death, want within [%v, %v)", d, heal, grace)
				}
				if calls := a.calls.Load() - before; calls != tc.wantCalls {
					t.Fatalf("%d factory calls during the episode, want %d", calls, tc.wantCalls)
				}
				for _, c := range []*rendr.Conn{dc, pc} {
					st := c.Status()
					if st.State != rendr.StateOpen || st.InNoPath || st.NoPathEpisodes != 1 || st.Migrations.Death != 1 {
						t.Fatalf("%v status after the recovery: %+v", st.Role, st)
					}
				}
				endClean(t, dc, pc)
				e.close()
			})
		})
	}
}

// TestNoPathEpisodesFreshBudget_L18 (L18): every no-path episode gets the
// full grace, counted from the death of the last carrier. With NoPathGrace
// 15 s (the default) and t the death time of the first outage: outage at
// t = 0, recovery at t = 10 s, a second outage at t = 11 s; at t = 24 s the
// session is still open (a budget shared with the first episode would have
// run out at 15 s or 16 s), and at t = 26 s — the grace after the second
// death — it ends with ErrNoPath. The first redial of each episode starts
// at its death and waits in the factory (DialTimeout raised to a minute so
// that it outlasts both episodes); data crosses the recovery intact.
func TestNoPathEpisodesFreshBudget_L18(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			grace   = 15 * time.Second // NoPathGrace (the default, set explicitly)
			healAt  = 10 * time.Second // the first outage ends
			again   = 11 * time.Second // the second outage starts
			checkAt = again + grace - 2*time.Second
		)
		if checkAt <= grace+again-healAt {
			t.Fatal("test parameters: the check must come after any budget shared with the first episode ran out")
		}
		cfg := rendr.Config{NoPathGrace: grace}
		e := newEnv(t, cfg, cfg, &testhooks.Overrides{DialTimeout: time.Minute})
		a := e.path("a", time.Millisecond)
		var gate atomic.Pointer[chan struct{}]
		a.gate = func(ctx context.Context, _ int64, _ []byte) error {
			if g := gate.Load(); g != nil {
				select {
				case <-*g:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		}
		dc, pc := e.open(e.peer(a), rendr.DialOptions{})
		exchange(t, dc, pc, 256<<10, 1)
		down := func() time.Time {
			t.Helper()
			g := make(chan struct{})
			gate.Store(&g)
			at := time.Now()
			if n := a.link.Kill(); n != 1 {
				t.Fatalf("Kill killed %d carriers", n)
			}
			return at
		}
		up := func() {
			if g := gate.Swap(nil); g != nil {
				close(*g)
			}
		}
		defer up()

		t0 := down() // t = 0
		time.Sleep(time.Until(t0.Add(healAt)))
		if st := dc.Status(); st.State != rendr.StateOpen || !st.InNoPath || st.NoPathEpisodes != 1 {
			t.Fatalf("t = %v, first outage: %+v", healAt, st)
		}
		if cs := a.callsSince(t0, 0); len(cs) != 1 || !cs[0].at.Equal(t0) {
			t.Fatalf("redials in the first episode: %+v, want one, started at the death", cs)
		}
		up() // t = 10 s: the redial in flight succeeds
		waitFor(t, 100*time.Millisecond, time.Millisecond, "recovery", func() bool { return !dc.Status().InNoPath })
		exchange(t, dc, pc, 256<<10, 3)

		time.Sleep(time.Until(t0.Add(again)))
		t1 := down() // t = 11 s
		rres := goOp(func() (int, error) { return dc.Read(make([]byte, 1)) })
		time.Sleep(time.Until(t0.Add(checkAt)))
		if st := dc.Status(); st.State != rendr.StateOpen || !st.InNoPath || st.NoPathEpisodes != 2 || !running(rres) {
			t.Fatalf("t = %v, second outage: %+v", checkAt, st)
		}
		if cs := a.callsSince(t1, 0); len(cs) != 1 || !cs[0].at.Equal(t1) {
			t.Fatalf("redials in the second episode: %+v, want one, started at the death (t = %v)", cs, again)
		}
		r := await(t, rres, 3*time.Second, "Read at the second episode's expiry")
		if !isTerminal(r.err, rendr.ErrNoPath) || !r.at.Equal(t1.Add(grace)) {
			t.Fatalf("Read returned %v at t = %v, want ErrNoPath at t = %v", r.err, r.at.Sub(t0), again+grace)
		}
		ns, ne := e.dev.of(rendr.EventNoPathStart), e.dev.of(rendr.EventNoPathEnd)
		if len(ns) != 2 || !ns[0].Time.Equal(t0) || !ns[1].Time.Equal(t1) || len(ne) != 1 || ne[0].Time.Sub(t0) > healAt+10*time.Millisecond {
			t.Fatalf("episodes: starts %+v, ends %+v", ns, ne)
		}
		if st := dc.Status(); st.State != rendr.StateEnded || !isTerminal(st.Err, rendr.ErrNoPath) || st.NoPathEpisodes != 2 {
			t.Fatalf("t = %v: %+v", again+grace, st)
		}
		if k := a.link.Stats().Session.Killed; k != 2 {
			t.Fatalf("stimulus: %d session carriers killed", k)
		}
		e.close()
	})
}

// TestIdleOutageWorstPhaseSurvives_L18 (L18): an idle single-path session
// meets a 5 s outage (a blackhole) at the PING phase that is worst for a
// grace counted from the last frame: the outage swallows the dialer's next
// idle PING right before it ends, so the death is judged DeadMin after
// that PING — about PingIdle + DeadMin after the last frame received and
// after the path came back. With the default grace (15 s) and with the
// minimum grace (3 s) the session survives: the first reconnect starts at
// the death judgment (the grace counts from there) and attaches one RTT
// later; data then crosses intact. PingIdle and DeadMin are set explicitly
// to their defaults; every bound derives from them.
func TestIdleOutageWorstPhaseSurvives_L18(t *testing.T) {
	for _, g := range []struct {
		name  string
		grace time.Duration
	}{
		{"default grace", 15 * time.Second},
		{"minimum grace", 3 * time.Second},
	} {
		t.Run(g.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var mu sync.Mutex
				var starts []time.Time
				dov := &testhooks.Overrides{Hooks: &testhooks.Hooks{DialStart: func(int) {
					mu.Lock()
					starts = append(starts, time.Now())
					mu.Unlock()
				}}}
				const oneWay, pingIdle, deadMin = time.Millisecond, 10 * time.Second, 3 * time.Second
				cfg := rendr.Config{PingIdle: pingIdle, DeadMin: deadMin}
				e := newEnvSplit(t, cfg, cfg, dov, nil)
				a := e.path("a", oneWay)
				dc, pc := e.open(e.peer(a), rendr.DialOptions{NoPathGrace: g.grace})
				dconn := a.sessionConns(true)[0]

				// Idle: each end PINGs every PingIdle from its carrier's start.
				time.Sleep(2*pingIdle + pingIdle/2)
				pings := dconn.out.list(wire.TypePing)
				if len(pings) < 3 {
					t.Fatalf("%d dialer PINGs in %v idle", len(pings), 2*pingIdle+pingIdle/2)
				}
				last, prev := pings[len(pings)-1].at, pings[len(pings)-2].at
				if last.Sub(prev) != pingIdle {
					t.Fatalf("idle PINGs %v apart, want %v", last.Sub(prev), pingIdle)
				}
				next := last.Add(pingIdle)
				outStart, outEnd := next.Add(-5*time.Second+10*time.Millisecond), next.Add(10*time.Millisecond)
				time.Sleep(time.Until(outStart))
				a.link.SetBlackhole(true)
				time.Sleep(time.Until(outEnd))
				a.link.SetBlackhole(false)
				lastRx, _ := dconn.in.lastBefore(outStart)

				waitFor(t, 2*pingIdle, time.Millisecond, "recovery", func() bool {
					st := dc.Status()
					return st.NoPathEpisodes == 1 && !st.InNoPath
				})
				// The PING at the worst phase was sent into the outage and lost.
				lost := false
				for _, p := range dconn.out.list(wire.TypePing) {
					lost = lost || (!p.at.Before(outStart) && p.at.Before(outEnd))
				}
				if !lost || a.link.Stats().Session.Dropped == 0 {
					t.Fatalf("stimulus: no dialer PING inside the outage [%v, %v) was dropped", outStart, outEnd)
				}
				ns, ne := e.dev.of(rendr.EventNoPathStart), e.dev.of(rendr.EventNoPathEnd)
				if len(ns) != 1 || len(ne) != 1 {
					t.Fatalf("no-path events: %+v / %+v", ns, ne)
				}
				death := ns[0].Time
				if death.Before(outEnd) || death.Sub(next) > deadMin || death.Sub(lastRx.at) < pingIdle+deadMin-10*time.Millisecond {
					t.Fatalf("death judged at outage+%v (outage %v long, last frame %v before), want after the outage, ≈ DeadMin after the lost PING",
						death.Sub(outStart), outEnd.Sub(outStart), death.Sub(lastRx.at))
				}
				mu.Lock()
				var first time.Time
				for _, s := range starts {
					if !s.Before(outStart) {
						first = s
						break
					}
				}
				mu.Unlock()
				if !first.Equal(death) {
					t.Fatalf("first reconnect at outage+%v, death judged at outage+%v: want the same instant", first.Sub(outStart), death.Sub(outStart))
				}
				if d := ne[0].Time.Sub(death); d > 2*oneWay+time.Millisecond {
					t.Fatalf("reattached %v after the death, want one RTT", d)
				}
				t.Logf("death judged %v after the last frame received; reattached %v later", death.Sub(lastRx.at), ne[0].Time.Sub(death))
				exchange(t, dc, pc, 1<<20, 19)
				endClean(t, dc, pc)
				e.close()
			})
		})
	}
}

// TestConcurrentDeathsNeverEOF_L18 (L18): 100 runs in which both carriers
// of a bond session die in the middle of a transfer in both directions —
// at the same instant (two concurrent Kills), or with the survivor dying
// while the actor handles the first death (Hooks.DeathObserved holds the
// first death step and kills the second carrier). The application never
// sees EOF or an error: both readers accept EOF only after exactly the
// expected bytes; the session goes through one no-path episode and both
// members rejoin.
func TestConcurrentDeathsNeverEOF_L18(t *testing.T) {
	vol := int64(256 << 10)
	if raceEnabled {
		vol = 128 << 10
	}
	for i := range 100 {
		t.Run(fmt.Sprintf("run%03d", i), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				held := i%2 == 1
				var second atomic.Pointer[func()]
				dov := &testhooks.Overrides{Hooks: &testhooks.Hooks{DeathObserved: func(uint32) {
					if f := second.Swap(nil); f != nil {
						(*f)()
					}
				}}}
				e := newEnvSplit(t, rendr.Config{}, rendr.Config{}, dov, nil)
				a := e.path("a", time.Millisecond)
				b := e.path("b", 2*time.Millisecond)
				for _, p := range []*path{a, b} {
					p.link.SetRate(8 << 20)
				}
				dc, pc := e.open(e.peer(a, b), rendr.DialOptions{Mode: rendr.ModeBond})
				waitFor(t, 5*time.Second, time.Millisecond, "two members", func() bool { return len(liveOf(dc.Status(), "")) == 2 })
				seed := uint64(1000 + 2*i)
				up := startXfer(dc, pc, vol, seed, vol/4)
				down := startXfer(pc, dc, vol, seed+1, vol/4)
				up.waitMark(t, 0, 10*time.Second)
				down.waitMark(t, 0, 10*time.Second)
				if up.got.Load() >= vol || down.got.Load() >= vol {
					t.Fatal("stimulus: the carriers died after the transfers")
				}
				if held {
					kill := func() { b.link.Kill() }
					second.Store(&kill)
					a.link.Kill()
				} else {
					var wg sync.WaitGroup
					wg.Go(func() { a.link.Kill() })
					wg.Go(func() { b.link.Kill() })
					wg.Wait()
				}
				up.wait(t, 30*time.Second)
				down.wait(t, 30*time.Second)
				if second.Load() != nil {
					t.Fatal("stimulus: the held death step never ran")
				}
				for _, p := range []*path{a, b} {
					if k := p.link.Stats().Session.Killed; k != 1 {
						t.Fatalf("stimulus: %d session carriers killed on %s", k, p.name)
					}
				}
				if st := dc.Status(); st.NoPathEpisodes != 1 || st.Rejoins != 2 || st.State != rendr.StateOpen {
					t.Fatalf("dialer after both deaths: %+v", st)
				}
				endClean(t, dc, pc)
				e.close()
			})
		})
	}
}

// TestDialAllFactoriesFail_L18 (L18): Dial over four factories that all
// fail — one refuses, one hangs until its context ends, one reaches a
// blackholed path, one reaches a non-rendr endpoint — returns ErrNoPath
// (errors.Is, wrapping the last carrier error, not a timeout) exactly
// NoPathGrace after the opening race started, and not earlier. The race
// starts once the cold start's probe wait ends: the hanging and the
// blackholed factory give neither a probe sample nor a failure, so Dial
// waits the whole Probe.DialWait first (design §6.6, §7.8). Every factory
// got at least one OPEN attempt, each failing its own way (stimulus);
// neither Runtime keeps any state of the session.
func TestDialAllFactoriesFail_L18(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const grace, dialWait = 3 * time.Second, 800 * time.Millisecond // NoPathGrace; Probe.DialWait (the default, set explicitly)
		dcfg := rendr.Config{JoinStagger: 100 * time.Millisecond, Probe: rendr.ProbePolicy{DialWait: dialWait}}
		e := newEnv(t, dcfg, rendr.Config{}, &testhooks.Overrides{Rand: func() float64 { return 0.5 }})
		refused := e.path("refused", time.Millisecond)
		refused.link.SetRefuse(true)
		hangs := e.path("hangs", time.Millisecond)
		hangs.link.SetDial(rendrtest.DialHang)
		hole := e.path("blackholed", time.Millisecond)
		hole.link.SetBlackhole(true)
		notRendr := e.path("not-rendr", time.Millisecond)
		junk := new(junkEnd)
		notRendr.setFar(junk.accept)
		ps := []*path{refused, hangs, hole, notRendr}
		for _, p := range ps {
			p.early = true
		}
		peer := e.peer(ps...)

		start := time.Now()
		c, err := peer.Dial(context.Background(), rendr.DialOptions{NoPathGrace: grace})
		failed := time.Now()
		if c != nil || !isTerminal(err, rendr.ErrNoPath) || !strings.Contains(err.Error(), "last carrier error") {
			t.Fatalf("Dial = %v, %v; want ErrNoPath wrapping the last carrier error", c, err)
		}
		var race time.Time // the first OPEN attempt: the opening race's start
		for _, p := range ps {
			cs := p.callsSince(start, wire.TypeOpen)
			if len(cs) < 1 {
				t.Fatalf("stimulus: no OPEN attempt on %s (calls %d)", p.name, p.calls.Load())
			}
			if race.IsZero() || cs[0].at.Before(race) {
				race = cs[0].at
			}
		}
		if d := race.Sub(start); d != dialWait {
			t.Fatalf("the opening race started %v after Dial, want after the cold start's probe wait (%v)", d, dialWait)
		}
		if d := failed.Sub(race); d != grace {
			t.Fatalf("Dial failed %v after the opening race started (%v after the call), want exactly NoPathGrace (%v)", d, failed.Sub(start), grace)
		}
		if st := refused.link.Stats(); st.DialFailures < 1 {
			t.Fatalf("stimulus: refused path: %+v", st)
		}
		if st := hole.link.Stats(); st.Session.Dropped == 0 {
			t.Fatalf("stimulus: no OPEN bytes swallowed by the blackhole: %+v", st)
		}
		if n := junk.open.Load(); n < 1 {
			t.Fatalf("stimulus: %d OPENs answered by the non-rendr endpoint", n)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		if pc, err := e.ln.Accept(ctx); err == nil {
			t.Fatalf("the passive admitted a session: %v", pc.ID())
		}
		synctest.Wait()
		for _, rt := range []*rendr.Runtime{e.d, e.p} {
			if s := rt.Status().Sessions; s != (rendr.SessionCounts{}) {
				t.Fatalf("sessions left after the failed Dial: %+v", s)
			}
		}
		e.close()
	})
}
