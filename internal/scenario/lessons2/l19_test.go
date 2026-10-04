package lessons2

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestUploadOnlySurvivesDeaths_L19 (L19: no zombie protection). A session
// that only uploads — the dialer never receives an application byte —
// loses its active carrier twice in a row: in the middle of the upload,
// and again right after the replacement attached, either once the passive
// followed the replacement's SCHED or before that SCHED could reach it. It
// survives both: the upload completes intact, the dialer received nothing
// but control frames, it rejoined twice and counted two death migrations
// (and so did the passive once it followed). Whether the passive also
// counts two when the second death beats the replacement's SCHED is L20's
// rule ("两端都计数迁移"), asserted by TestRedialAfterFailures_L20.
func TestUploadOnlySurvivesDeaths_L19(t *testing.T) {
	for _, tc := range []struct {
		name     string
		followed bool // the second death waits until the passive applied the replacement's SCHED
	}{
		{"second death after the passive followed", true},
		{"second death before the passive followed", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := newEnv(t, rendr.Config{}, rendr.Config{}, nil)
				const oneWay = 20 * time.Millisecond // the replacement's SCHED needs 20 ms to reach the passive
				a := e.path("a", oneWay)
				vol := int64(8 << 20)
				if raceEnabled {
					vol = 2 << 20
				}
				a.link.SetRate(float64(vol)) // the upload takes about 1 s
				dc, pc := e.open(e.peer(a), rendr.DialOptions{})
				up := startXfer(dc, pc, vol, 191, vol/3)
				up.waitMark(t, 0, 10*time.Second)

				first, _ := activeOf(dc.Status())
				if n := a.link.Kill(); n != 1 {
					t.Fatalf("Kill killed %d carriers", n)
				}
				waitFor(t, time.Second, time.Millisecond, "replacement", func() bool {
					c, ok := activeOf(dc.Status())
					return ok && c.ID != first.ID
				})
				if tc.followed {
					waitFor(t, time.Second, time.Millisecond, "passive follows", func() bool {
						return pc.Status().SchedEpoch == dc.Status().SchedEpoch
					})
				} else if pc.Status().SchedEpoch == dc.Status().SchedEpoch {
					t.Fatal("stimulus: the passive already applied the replacement's SCHED")
				}
				if up.got.Load() >= vol {
					t.Fatal("stimulus: the upload finished before the second death")
				}
				if n := a.link.Kill(); n != 1 { // the replacement dies right away
					t.Fatalf("second Kill killed %d carriers", n)
				}
				up.wait(t, 30*time.Second)

				ds, ps := dc.Status(), pc.Status()
				if ds.RxBytes != 0 || ps.TxBytes != 0 {
					t.Fatalf("not upload-only: dialer received %d bytes, passive sent %d", ds.RxBytes, ps.TxBytes)
				}
				if ds.State != rendr.StateOpen || ps.State != rendr.StateOpen || ds.Rejoins != 2 || a.link.Stats().Session.Killed != 2 {
					t.Fatalf("after two deaths: dialer %+v, passive %+v, killed %d", ds, ps, a.link.Stats().Session.Killed)
				}
				if ds.Migrations.Death != 2 || (tc.followed && ps.Migrations.Death != 2) {
					t.Fatalf("death migrations: dialer %d, passive %d; want 2 on the dialer (and on the passive, which"+
						" applied both SCHEDs)", ds.Migrations.Death, ps.Migrations.Death)
				}
				t.Logf("death migrations: dialer %d, passive %d", ds.Migrations.Death, ps.Migrations.Death)
				endClean(t, dc, pc)
				e.close()
			})
		})
	}
}

// TestIdleSurvivesRepeatedDeaths_L19 (L19): an idle session — no
// application byte in either direction — loses its carrier three times
// within 30 s (at 5, 15 and 25 s). Every death is followed by an immediate
// redial that reattaches; at 30 s the session is open on both ends with
// three death migrations and three no-path episodes each, and data then
// crosses intact.
func TestIdleSurvivesRepeatedDeaths_L19(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, rendr.Config{}, rendr.Config{}, nil)
		a := e.path("a", time.Millisecond)
		dc, pc := e.open(e.peer(a), rendr.DialOptions{})
		t0 := time.Now()
		for i, at := range []time.Duration{5 * time.Second, 15 * time.Second, 25 * time.Second} {
			time.Sleep(time.Until(t0.Add(at)))
			if n := a.link.Kill(); n != 1 {
				t.Fatalf("death %d: Kill killed %d carriers", i+1, n)
			}
			waitFor(t, time.Second, time.Millisecond, "reattach", func() bool {
				st := dc.Status()
				return !st.InNoPath && st.NoPathEpisodes == uint64(i+1)
			})
		}
		time.Sleep(time.Until(t0.Add(30 * time.Second)))
		for _, c := range []*rendr.Conn{dc, pc} {
			st := c.Status()
			if st.State != rendr.StateOpen || st.Migrations.Death != 3 || st.NoPathEpisodes != 3 || st.TxBytes != 0 || st.RxBytes != 0 {
				t.Fatalf("%v at 30 s: %+v", st.Role, st)
			}
		}
		if st := dc.Status(); st.Rejoins != 3 || a.link.Stats().Session.Killed != 3 {
			t.Fatalf("stimulus: rejoins %d, killed %d", st.Rejoins, a.link.Stats().Session.Killed)
		}
		exchange(t, dc, pc, 1<<20, 192)
		endClean(t, dc, pc)
		e.close()
	})
}

// TestUnknownSessionIsSessionLost_L19 (L19): the bound instance forgets the
// session while the dialer is cut off — the passive's IdleTimeout ends it,
// its tombstone remains — and the dialer, still inside its 60 s grace,
// redials (jitter fixed at its mean, so the redial times are reproducible).
// The JOIN is answered UNKNOWN_SESSION and the session ends with
// ErrSessionLost within one RTT of that redial's start, without waiting for
// the grace.
func TestUnknownSessionIsSessionLost_L19(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var mu sync.Mutex
		var starts []time.Time
		dov := &testhooks.Overrides{Rand: func() float64 { return 0.5 }, Hooks: &testhooks.Hooks{DialStart: func(int) {
			mu.Lock()
			starts = append(starts, time.Now())
			mu.Unlock()
		}}}
		e := newEnvSplit(t, rendr.Config{}, rendr.Config{IdleTimeout: 10 * time.Second}, dov, nil)
		const oneWay = 5 * time.Millisecond
		a := e.path("a", oneWay)
		dc, pc := e.open(e.peer(a), rendr.DialOptions{NoPathGrace: time.Minute})
		exchange(t, dc, pc, 256<<10, 193) // the passive's idle clock starts at its last read

		a.link.SetRefuse(true)
		cut := time.Now()
		if n := a.link.Kill(); n != 1 {
			t.Fatalf("Kill killed %d carriers", n)
		}
		waitEnded(t, pc, 15*time.Second)
		if st := pc.Status(); !errors.Is(st.Err, rendr.ErrIdleTimeout) {
			t.Fatalf("passive ended with %v, want ErrIdleTimeout", st.Err)
		}
		if n := e.p.Status().Sessions.Tombstones; n != 1 {
			t.Fatalf("passive tombstones: %d", n)
		}
		if st := dc.Status(); st.State != rendr.StateOpen || !st.InNoPath {
			t.Fatalf("dialer while cut off: %+v", st)
		}
		if a.link.Stats().DialFailures < 2 {
			t.Fatalf("stimulus: %d refused redials while cut off", a.link.Stats().DialFailures)
		}

		rres := goOp(func() (int, error) { return dc.Read(make([]byte, 1)) })
		fixed := time.Now()
		a.link.SetRefuse(false)
		r := await(t, rres, 10*time.Second, "Read after the redial")
		if !isTerminal(r.err, rendr.ErrSessionLost) {
			t.Fatalf("Read = %v, want ErrSessionLost", r.err)
		}
		mu.Lock()
		var att time.Time
		for _, s := range starts {
			if !s.Before(fixed) {
				att = s
				break
			}
		}
		mu.Unlock()
		if att.IsZero() || r.at.Sub(att) > 2*oneWay+time.Millisecond {
			t.Fatalf("ErrSessionLost %v after the redial started, want within one RTT", r.at.Sub(att))
		}
		if r.at.Sub(cut) >= time.Minute {
			t.Fatal("the session ended only at its grace")
		}
		var answered bool
		for _, c := range a.sessionConns(false) {
			for _, f := range c.out.list(wire.TypeJoinAck) {
				answered = answered || f.b0 == byte(wire.StatusUnknownSession)
			}
		}
		if !answered {
			t.Fatal("stimulus: no JOIN_ACK(UNKNOWN_SESSION) crossed the wire")
		}
		if st := dc.Status(); st.State != rendr.StateEnded || !isTerminal(st.Err, rendr.ErrSessionLost) {
			t.Fatalf("dialer status %+v", st)
		}
		e.close()
	})
}

// TestPeerRestartFastFail_L19 (L19, plan §3.4). The passive instance
// vanishes without a GOAWAY and a new instance (another InstanceID) takes
// its place behind the same path. When the session has no live carrier
// left, its redial reaches the new instance and the session ends with
// ErrSessionLost at once (one RTT after the death), not at the grace. When
// it still has a live carrier to the original instance (bond), each of the
// member slot's redials that reaches the new instance is closed (exactly
// once) and the session carries on intact. The new instance never admits a
// session. Redial jitter is fixed at its mean.
func TestPeerRestartFastFail_L19(t *testing.T) {
	ov := &testhooks.Overrides{Rand: func() float64 { return 0.5 }}
	t.Run("no live carrier", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := newEnv(t, rendr.Config{}, rendr.Config{}, ov)
			const oneWay = 5 * time.Millisecond
			a := e.path("a", oneWay)
			dc, pc := e.open(e.peer(a), rendr.DialOptions{})
			exchange(t, dc, pc, 256<<10, 194)

			p2, reached := restarted(t, e, a)
			t0 := time.Now()
			if n := a.link.Kill(); n != 1 { // the old instance is gone: no GOAWAY, no RST
				t.Fatalf("Kill killed %d carriers", n)
			}
			rres := goOp(func() (int, error) { return dc.Read(make([]byte, 1)) })
			r := await(t, rres, 5*time.Second, "Read after the restart")
			if !isTerminal(r.err, rendr.ErrSessionLost) || r.at.Sub(t0) > 2*oneWay+time.Millisecond {
				t.Fatalf("Read = %v after %v, want ErrSessionLost within one RTT (grace 15 s)", r.err, r.at.Sub(t0))
			}
			if reached.Load() < 1 || len(a.sessionConns(true)) != 2 {
				t.Fatalf("stimulus: %d carriers reached the new instance, %d session carriers on a", reached.Load(), len(a.sessionConns(true)))
			}
			if st := dc.Status(); st.State != rendr.StateEnded || st.NoPathEpisodes != 1 {
				t.Fatalf("dialer status %+v", st)
			}
			synctest.Wait()
			if st := p2.Status(); st.Sessions != (rendr.SessionCounts{}) {
				t.Fatalf("the new instance admitted a session: %+v", st.Sessions)
			}
			p2.Close()
			synctest.Wait()
			noState(t, "restarted passive", p2)
			e.close()
			if dn, pn := a.sessionConns(true)[1].closes.Load(), a.sessionConns(false)[1].closes.Load(); dn != 1 || pn != 1 {
				t.Fatalf("the redial into the new instance closed %d times (dialer end) and %d times (its end), want once each", dn, pn)
			}
		})
	})
	t.Run("old instance still reachable", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := newEnv(t, rendr.Config{}, rendr.Config{}, ov)
			a := e.path("a", time.Millisecond)
			b := e.path("b", time.Millisecond)
			dc, pc := e.open(e.peer(a, b), rendr.DialOptions{Mode: rendr.ModeBond})
			waitFor(t, 5*time.Second, time.Millisecond, "two members", func() bool { return len(liveOf(dc.Status(), "")) == 2 })

			old := len(b.sessionConns(true)) // b's member to the original instance
			if old != 1 {
				t.Fatalf("%d session carriers on b before the restart, want its member", old)
			}
			p2, _ := restarted(t, e, b)
			if n := b.link.Kill(); n < 1 {
				t.Fatalf("Kill killed %d carriers", n)
			}
			vol := int64(4 << 20)
			if raceEnabled {
				vol = 1 << 20
			}
			a.link.SetRate(float64(vol / 6)) // each direction takes about 6 s
			up := startXfer(dc, pc, vol, 195)
			down := startXfer(pc, dc, vol, 196)
			time.Sleep(3 * time.Second) // b's member slot redials several times into the new instance
			mismatched := b.sessionConns(true)[old:]
			if len(mismatched) < 2 {
				t.Fatalf("stimulus: %d session redials of b reached the new instance", len(mismatched))
			}
			st := dc.Status()
			if st.State != rendr.StateOpen || len(liveOf(st, "a")) != 1 || len(liveOf(st, "b")) != 0 || up.got.Load() >= vol {
				t.Fatalf("dialer with a live carrier to the old instance: %+v (read %d of %d)", st, up.got.Load(), vol)
			}
			up.wait(t, 30*time.Second)
			down.wait(t, 30*time.Second)
			endClean(t, dc, pc)
			synctest.Wait()
			if st := p2.Status(); st.Sessions != (rendr.SessionCounts{}) {
				t.Fatalf("the new instance admitted a session: %+v", st.Sessions)
			}
			p2.Close()
			synctest.Wait()
			noState(t, "restarted passive", p2)
			e.close()
			ds, ps := b.sessionConns(true)[old:], b.sessionConns(false)[old:]
			if len(ds) != len(ps) {
				t.Fatalf("b's redials: %d dialer ends, %d ends at the new instance", len(ds), len(ps))
			}
			for i := range ds {
				if dn, pn := ds[i].closes.Load(), ps[i].closes.Load(); dn != 1 || pn != 1 {
					t.Fatalf("b's redial %d into the new instance closed %d times (dialer end) and %d times (its end), want once each", i+1, dn, pn)
				}
			}
			t.Logf("%d of b's redials reached the new instance", len(ds))
		})
	})
}

// restarted builds the new incarnation of the passive (a Runtime with
// another InstanceID and a Listener) and routes p's new carriers to it. It
// returns the Runtime and the count of carriers routed there.
func restarted(t *testing.T, e *env, p *path) (*rendr.Runtime, *atomic.Int64) {
	t.Helper()
	p2 := buildRuntime(t, rendr.Config{}, nil)
	t.Cleanup(func() { p2.Close() })
	ln2, err := p2.Listen(rendr.ListenConfig{})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if p2.InstanceID() == e.p.InstanceID() {
		t.Fatal("the restarted passive has the old InstanceID")
	}
	reached := new(atomic.Int64)
	p.setFar(func(c net.Conn) error {
		reached.Add(1)
		return ln2.Handle(c)
	})
	return p2, reached
}
