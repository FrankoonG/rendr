package rendr

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestNewRuntimeIdentityAndStatus: every Runtime draws its own non-zero
// InstanceID; a fresh Runtime reports it and all-zero counters; clamped
// Config fields and every Listen call's clamped fields are listed in
// ConfigAdjustments (Config first, then "Listen[i]."), and Status returns
// a copy of that list. After Close, Listen and NewPeer return
// net.ErrClosed and Close stays idempotent.
func TestNewRuntimeIdentityAndStatus(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, err := NewRuntime(Config{})
		if err != nil {
			t.Fatal(err)
		}
		b, err := NewRuntime(Config{Window: 1})
		if err != nil {
			t.Fatal(err)
		}
		if a.InstanceID().IsZero() || b.InstanceID().IsZero() || a.InstanceID() == b.InstanceID() {
			t.Fatalf("instance IDs %v and %v", a.InstanceID(), b.InstanceID())
		}
		st := a.Status()
		if st.Instance != a.InstanceID() || st.Sessions != (SessionCounts{}) || st.Handshakes != 0 || st.HandshakeEvictions != 0 ||
			st.AcceptBacklog != [2]int{} || st.Sessionless != 0 || st.BufferedBytes != 0 || st.Abandoned != 0 ||
			st.EventsDropped != 0 || st.CallbackPanics != 0 || len(st.ConfigAdjustments) != 0 {
			t.Fatalf("fresh status %+v", st)
		}
		if _, err := b.Listen(ListenConfig{}); err != nil {
			t.Fatal(err)
		}
		if _, err := b.Listen(ListenConfig{AcceptBacklog: -5, AcceptTimeout: time.Millisecond}); err != nil {
			t.Fatal(err)
		}
		adj := b.Status().ConfigAdjustments
		want := []string{"Window: 1 → ", "Listen[1].AcceptBacklog: -5 → 1 ", "Listen[1].AcceptTimeout: 1ms → 100ms "}
		if len(adj) != len(want) {
			t.Fatalf("adjustments %q", adj)
		}
		for i, w := range want {
			if !strings.HasPrefix(adj[i], w) {
				t.Fatalf("adjustment %d %q, want prefix %q", i, adj[i], w)
			}
		}
		adj[0] = "changed"
		if b.Status().ConfigAdjustments[0] == "changed" {
			t.Fatal("Status shares its adjustment list")
		}
		for _, rt := range []*Runtime{a, b} {
			for range 2 {
				if err := rt.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := rt.Listen(ListenConfig{}); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Listen after Close: %v", err)
			}
		}
	})
}

// TestListenRejectsBadSources: a Listen source must be FromListener of a
// non-nil net.Listener, and one net.Listener may not appear twice (it would
// get two accept loops and two Closes, L50/L51); a rejected Listen takes no
// ownership (the listener is not closed) and records no adjustment.
func TestListenRejectsBadSources(t *testing.T) {
	rt := wpTestRuntime(t, Config{}, nil)
	defer rt.Close()
	l := newFakeListener()
	for _, srcs := range [][]Source{{nil}, {FromListener(nil)}, {FromListener(l), nil}, {FromListener(l), FromListener(newFakeListener()), FromListener(l)}} {
		if ln, err := rt.Listen(ListenConfig{Sources: srcs, AcceptBacklog: -1}); ln != nil || err == nil {
			t.Fatalf("Listen(%v) = %v, %v", srcs, ln, err)
		}
	}
	if l.closes.Load() != 0 || len(rt.Status().ConfigAdjustments) != 0 {
		t.Fatalf("a rejected Listen closed its source (%d) or recorded %q", l.closes.Load(), rt.Status().ConfigAdjustments)
	}
	// A listener type that cannot be compared is never mistaken for a
	// repetition (no panic).
	ln, err := rt.Listen(ListenConfig{Sources: []Source{
		FromListener(uncomparableListener{fakeListener: newFakeListener()}),
		FromListener(uncomparableListener{fakeListener: newFakeListener()}),
	}})
	if err != nil {
		t.Fatalf("Listen of two uncomparable listeners: %v", err)
	}
	ln.Close()
}

// uncomparableListener is a net.Listener whose dynamic type has a slice
// field: comparing two of them with == panics.
type uncomparableListener struct {
	*fakeListener
	pad []int
}

// TestTesthooksNewRuntime: testhooks.NewRuntime builds a *Runtime with the
// overrides applied after normalization — unclamped, unrecorded, copied
// (a later change of the caller's value has no effect) — including the
// Listen-time AcceptTimeout and the carrier and table parameters; a nil
// Config pointer or nil cfg means the zero Config; any other cfg type is an
// error.
func TestTesthooksNewRuntime(t *testing.T) {
	ov := &testhooks.Overrides{
		HandshakeTimeout: 10 * time.Millisecond, // below the 1 s clamp
		AcceptTimeout:    5 * time.Millisecond,
		AbandonWait:      50 * time.Millisecond,
		MaxSessions:      3,
		FirstCarrierID:   0xfffffff0,
	}
	v, err := testhooks.NewRuntime(Config{Window: 1 << 20}, ov)
	if err != nil {
		t.Fatal(err)
	}
	rt, ok := v.(*Runtime)
	if !ok {
		t.Fatalf("testhooks.NewRuntime returned %T", v)
	}
	defer rt.Close()
	ov.HandshakeTimeout = time.Hour
	if rt.eff.cfg.Handshake.Timeout != 10*time.Millisecond || rt.cenv.Timing.HandshakeTimeout != 10*time.Millisecond ||
		rt.cenv.Timing.AbandonWait != 50*time.Millisecond || rt.table.maxUnits != 3 || rt.eff.cfg.Window != 1<<20 {
		t.Fatalf("overrides not applied: %+v", rt.eff.cfg)
	}
	if id := rt.cenv.IDs.Next(); id != 0xfffffff0 {
		t.Fatalf("first CarrierID %#x", id)
	}
	ln, err := rt.Listen(ListenConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if ln.cfg.AcceptTimeout != 5*time.Millisecond || len(rt.Status().ConfigAdjustments) != 0 {
		t.Fatalf("AcceptTimeout %v, adjustments %q", ln.cfg.AcceptTimeout, rt.Status().ConfigAdjustments)
	}
	for _, cfg := range []any{nil, (*Config)(nil), &Config{}} {
		v, err := testhooks.NewRuntime(cfg, nil)
		if err != nil {
			t.Fatalf("NewRuntime(%T): %v", cfg, err)
		}
		v.(*Runtime).Close()
	}
	if v, err := testhooks.NewRuntime(42, nil); v != nil || err == nil {
		t.Fatalf("NewRuntime(int) = %v, %v", v, err)
	}
}

// TestRuntimeEnvWiring: the carrier Env, the session Envs of Peers and
// Listeners and the admission tables all use the Runtime's own services
// (instance, timing, budget, abandoned-call pool, buffer pool, ID
// allocator, hooks, jitter source), built once (design §10.4 step 3).
func TestRuntimeEnvWiring(t *testing.T) {
	hooks := &testhooks.Hooks{}
	rnd := func() float64 { return 0.5 }
	rt := wpTestRuntime(t, Config{MaxBufferedBytes: 128 << 20}, &testhooks.Overrides{Hooks: hooks, Rand: rnd, AbandonLimit: 7})
	defer rt.Close()
	ce := &rt.cenv
	if ce.Local != rt.InstanceID() || ce.Budget != rt.budget || ce.Abandon != rt.abandon || ce.Hooks != hooks ||
		ce.Bufs == nil || ce.IDs == nil || ce.Timing != rt.eff.timing || rt.budget.Max() != 128<<20 {
		t.Fatalf("carrier env %+v", ce)
	}
	for range 6 {
		rt.abandon.Adopt()
	}
	if rt.abandon.Full() {
		t.Fatal("abandon limit not applied")
	}
	rt.abandon.Adopt()
	if !rt.abandon.Full() {
		t.Fatal("abandon limit not applied")
	}
	for range 7 {
		rt.abandon.Leave()
	}
	p, err := rt.NewPeer(PeerConfig{Carriers: []Carrier{(&countingFactory{name: "f"}).carrier()}})
	if err != nil {
		t.Fatal(err)
	}
	ln := wpListen(t, rt, ListenConfig{})
	for _, env := range []struct {
		name string
		e    *carrier.Env
		h    *testhooks.Hooks
		r    func() float64
		sink any
	}{
		{"peer", p.env.Carrier, p.env.Hooks, p.env.Rand, p.env.Events},
		{"listener", ln.env.Carrier, ln.env.Hooks, ln.env.Rand, ln.env.Events},
	} {
		if env.e != ce || env.h != hooks || env.r() != 0.5 || env.sink == nil {
			t.Fatalf("%s session env not wired", env.name)
		}
	}
	if p.env.Registry != nil {
		t.Fatalf("the Peer's Env template has Registry %T; every Dial sets its own", p.env.Registry)
	}
	if r, ok := ln.env.Registry.(lnRegistry); !ok || r.ln != ln {
		t.Fatalf("listener registry %T", ln.env.Registry)
	}
	if !slices.Equal(p.names, []string{"f"}) {
		t.Fatalf("names %q", p.names)
	}
}

// TestGroupJoinBounded_L52: the bounded join of rendr's goroutine groups
// (design §3.1): wait returns as soon as every member exited; at its
// deadline it counts each member still running once in the abandoned-call
// pool (a second wait does not count it again), and a counted member
// leaves the pool when it exits; members joined with a nil pool are never
// counted.
func TestGroupJoinBounded_L52(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := carrier.NewAbandonPool(256)
		g := newGroup()
		if !g.wait(time.Now(), pool) {
			t.Fatal("an empty group did not join")
		}
		release := make(chan struct{})
		for range 3 {
			g.add()
			go func() {
				defer g.done(pool)
				<-release
			}()
		}
		quick := make(chan struct{})
		g.add()
		go func() {
			defer g.done(pool)
			<-quick
		}()
		go func() {
			time.Sleep(100 * time.Millisecond)
			close(quick)
		}()
		start := time.Now()
		if g.wait(start.Add(time.Second), pool) || time.Since(start) != time.Second {
			t.Fatalf("wait returned early: %v", time.Since(start))
		}
		if pool.Len() != 3 || g.running() != 3 {
			t.Fatalf("abandoned %d, running %d; want 3 and 3", pool.Len(), g.running())
		}
		if g.wait(time.Now(), pool) || pool.Len() != 3 {
			t.Fatalf("a second wait counted again: %d", pool.Len())
		}
		close(release)
		synctest.Wait()
		if pool.Len() != 0 || g.running() != 0 {
			t.Fatalf("after the members exited: abandoned %d, running %d", pool.Len(), g.running())
		}
		if !g.wait(time.Now(), pool) {
			t.Fatal("a drained group did not join")
		}

		g2 := newGroup()
		block := make(chan struct{})
		g2.add()
		go func() {
			defer g2.done(nil)
			<-block
		}()
		if g2.wait(time.Now().Add(time.Millisecond), nil) || pool.Len() != 0 {
			t.Fatal("a nil pool counted a member")
		}
		close(block)
		start = time.Now()
		if !g2.wait(start.Add(time.Hour), nil) || time.Since(start) != 0 {
			t.Fatal("wait did not return when the last member exited")
		}
	})
}

// TestRuntimeActorsGauge (M3-D42, M3-D44, M3-D50; WP5): the Runtime hands
// every session its running-actor gauge and the testhooks ActorLinger.
// Status.Actors counts both ends' actors while the session opens; with
// ActorLinger 50 ms both park within it: Status.Actors is 0 on both
// Runtimes and testhooks.ParkedSessions counts the two; data still flows;
// once the sessions ended (Close restarts each parked actor for its end
// phase), nothing is counted, no session is live and none is parked.
func TestRuntimeActorsGauge(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const linger = 50 * time.Millisecond
		live0, parked0 := testhooks.LiveSessions.Load(), testhooks.ParkedSessions.Load()
		e := e2eNew(t, Config{}, Config{}, &testhooks.Overrides{ActorLinger: linger}, ListenConfig{}, "a")
		dc, pc := e2eOpen(t, e.peer(), e.ln, DialOptions{})
		synctest.Wait()
		if d, p := e.d.Status().Actors, e.p.Status().Actors; d != 1 || p != 1 {
			t.Fatalf("stimulus: Status.Actors %d and %d right after the open, want 1 and 1", d, p)
		}
		if n := testhooks.LiveSessions.Load() - live0; n != 2 {
			t.Fatalf("LiveSessions grew by %d, want 2", n)
		}
		time.Sleep(linger + 10*time.Millisecond)
		synctest.Wait()
		if d, p := e.d.Status().Actors, e.p.Status().Actors; d != 0 || p != 0 {
			t.Fatalf("Status.Actors %d and %d after the linger %v, want 0 and 0 (the override reached the sessions)", d, p, linger)
		}
		if n := testhooks.ParkedSessions.Load() - parked0; n != 2 {
			t.Fatalf("ParkedSessions grew by %d after the linger, want 2", n)
		}
		if _, err := dc.Write([]byte("wake")); err != nil {
			t.Fatalf("Write: %v", err)
		}
		var b [4]byte
		if _, err := pc.Read(b[:]); err != nil || string(b[:]) != "wake" {
			t.Fatalf("Read: %q, %v", b, err)
		}
		dc.Close()
		pc.Close()
		e2eDone(t, dc, 10*time.Second)
		e2eDone(t, pc, 10*time.Second)
		if d, p := e.d.Status().Actors, e.p.Status().Actors; d != 0 || p != 0 {
			t.Fatalf("Status.Actors %d and %d after the sessions ended, want 0 and 0", d, p)
		}
		if n := testhooks.LiveSessions.Load() - live0; n != 0 {
			t.Fatalf("%d sessions still live after both ended", n)
		}
		if n := testhooks.ParkedSessions.Load() - parked0; n != 0 {
			t.Fatalf("ParkedSessions %+d after both sessions ended, want 0 (a restart gives its count back)", n)
		}
		e.close()
	})
}

// manySessions opens n sessions between e's Runtimes concurrently over its
// single Link. The passive application rejects every session whose
// metadata is "reject" (Reject(9, "rejected")) and runs behave on the
// passive end of every other one; the dialer's Conns of the confirmed
// sessions are returned in Dial order (nil for rejected ones).
func manySessions(t testing.TB, e *e2ePair, n int, reject func(i int) bool, behave func(c *Conn)) []*Conn {
	t.Helper()
	peer := e.peer()
	var wg sync.WaitGroup
	acc := newAcceptLog(e.ln, func(pc *PendingConn) (*Conn, error) {
		if string(pc.Metadata()) == "reject" {
			return nil, pc.Reject(9, "rejected")
		}
		c, err := pc.Confirm()
		if err == nil {
			wg.Go(func() { behave(c) })
		}
		return c, err
	})
	out := make([]*Conn, n)
	var dials sync.WaitGroup
	for i := range n {
		dials.Go(func() {
			meta := []byte("accept")
			if reject(i) {
				meta = []byte("reject")
			}
			c, err := peer.Dial(context.Background(), DialOptions{Metadata: meta})
			switch {
			case reject(i):
				var re *RejectError
				if !errors.As(err, &re) || re.Code != 9 {
					t.Errorf("Dial %d: %v, want the rejection", i, err)
				}
			case err != nil:
				t.Errorf("Dial %d: %v", i, err)
			default:
				out[i] = c
			}
		})
	}
	dials.Wait()
	if t.Failed() {
		t.FailNow()
	}
	t.Cleanup(func() {
		acc.stop()
		e.d.Close() // a failed test's behaviours still blocked in a Read return
		e.p.Close()
		wg.Wait()
	})
	return out
}

// TestThousandSessionsPoolsReturnToZero_L48: 1000 concurrent sessions —
// every tenth rejected by the passive application, the other 900 each
// echoing 4 KiB — all complete their round trip and end cleanly, and then
// every admission pool and budget of both Runtimes is back to zero while
// they still run (L48, R7): no open, pending, lingering or orphaned session,
// no MaxSessions unit, backlog slot, handshake slot or sessionless carrier,
// BufferedBytes 0, nothing abandoned, no handshake evicted; the passive's
// tombstones disappear after TombstoneTTL. Load proof: 1000 sessions
// existed at once on each side.
func TestThousandSessionsPoolsReturnToZero_L48(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const n = 1000
		big := ListenConfig{AcceptBacklog: 2 * n}
		cfg := Config{Handshake: HandshakeLimits{MaxConcurrent: 2 * n}}
		e := e2eNew(t, cfg, cfg, nil, big, "a")
		rejected := func(i int) bool { return i%10 == 9 }
		conns := manySessions(t, e, n, rejected, func(c *Conn) {
			if err := rendrtest.Echo()(c); err != nil {
				t.Errorf("echo: %v", err)
			}
		})
		synctest.Wait()
		if ds, ps := e.d.Status(), e.p.Status(); ds.Sessions.Open != 900 || ps.Sessions.Open != 900 || ps.Sessions.Tombstones != 100 {
			t.Fatalf("load: dialer %+v, passive %+v", ds.Sessions, ps.Sessions)
		}
		var wg sync.WaitGroup
		for i, c := range conns {
			if c == nil {
				continue
			}
			wg.Go(func() {
				msg := bytes.Repeat([]byte{byte(i)}, 4<<10)
				if _, err := c.Write(msg); err != nil {
					t.Errorf("session %d: Write: %v", i, err)
				}
				if err := c.CloseWrite(); err != nil {
					t.Errorf("session %d: CloseWrite: %v", i, err)
				}
				got, err := io.ReadAll(c)
				if err != nil || !bytes.Equal(got, msg) {
					t.Errorf("session %d: echo of %d bytes: %d bytes, %v", i, len(msg), len(got), err)
				}
				c.Close()
				e2eDone(t, c, time.Minute)
			})
		}
		wg.Wait()
		synctest.Wait()
		for _, rt := range []*Runtime{e.d, e.p} {
			st := rt.Status()
			sc := st.Sessions
			if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || rt.table.inUse() != 0 || st.AcceptBacklog[0] != 0 ||
				st.Handshakes != 0 || st.Sessionless != 0 || st.BufferedBytes != 0 || st.Abandoned != 0 || st.HandshakeEvictions != 0 {
				t.Fatalf("pools of %v after every session ended: %+v (units %d)", rt.InstanceID(), st, rt.table.inUse())
			}
		}
		if n := e.p.Status().Sessions.Tombstones; n != 1000 {
			t.Fatalf("%d tombstones, want one per session", n)
		}
		time.Sleep(e.p.eff.passiveParams(ModeSelector, uint32(e.d.eff.passiveRetain(e.d.eff.cfg.NoPathGrace)/time.Millisecond), 0).TombstoneTTL)
		if n := e.p.Status().Sessions.Tombstones; n != 0 {
			t.Fatalf("%d tombstones after TombstoneTTL", n)
		}
		e.close()
	})
}

// TestGoroutineBound_L52: with 1000 idle sessions (each used once) the
// goroutines rendr runs stay within the design's bound (§3.1: an idle
// selector session is its actor plus one reader and one writer per
// carrier, on each side; no per-session goroutine anywhere else): at most
// 6 per session plus a constant, exactly one actor per session end, and
// none of them outlives the sessions (L52). The count is taken within
// ActorLinger, before the actors park (M3-D42); parked actors hold no
// goroutine at all, which the timers scenarios check.
func TestGoroutineBound_L52(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const n = 1000
		big := ListenConfig{AcceptBacklog: 2 * n}
		cfg := Config{Handshake: HandshakeLimits{MaxConcurrent: 2 * n}}
		e := e2eNew(t, cfg, cfg, nil, big, "a")
		passive := make(chan *Conn, n)
		conns := manySessions(t, e, n, func(int) bool { return false }, func(c *Conn) { passive <- c })
		var wg sync.WaitGroup
		for i, c := range conns {
			wg.Go(func() {
				if _, err := c.Write([]byte{byte(i)}); err != nil {
					t.Errorf("session %d: %v", i, err)
				}
			})
		}
		wg.Wait()
		var ends []*Conn
		for range n {
			sc := <-passive
			var b [1]byte
			if _, err := io.ReadFull(sc, b[:]); err != nil {
				t.Fatal(err)
			}
			ends = append(ends, sc)
		}
		synctest.Wait()
		ours, byEntry := rendrGoroutines()
		actors := byEntry["github.com/FrankoonG/rendr/v2/internal/session.(*actor).run"]
		t.Logf("%d sessions: %d rendr goroutines (%d actors)", n, ours, actors)
		if actors != 2*n || ours > 6*n+16 {
			t.Fatalf("%d rendr goroutines (%d actors) for %d idle sessions per side; want ≤ %d and %d actors: %v",
				ours, actors, n, 6*n+16, 2*n, byEntry)
		}
		for _, c := range append(conns, ends...) {
			c.Close()
		}
		for _, c := range append(conns, ends...) {
			e2eDone(t, c, time.Minute)
		}
		synctest.Wait()
		if n, left := rendrGoroutines(); n != 0 {
			t.Fatalf("%d rendr goroutines after every session ended: %v", n, left)
		}
		e.close()
	})
}

// TestAcceptTimeoutIsCapacity_L48: with the default timings a passive
// application that never decides makes the dialer's Dial fail with
// ErrCapacity before NoPathGrace (design §6.2 timing check, plan §6, G6):
// the first attempt times out at DialTimeout (10 s), its immediate retry
// parks on the pending session (which survived the first carrier), and the
// AcceptTimeout (10 s after the admission) answers CAPACITY to it. A
// PendingConn the application accepted but never decided then returns
// ErrCapacity from Confirm, and the passive keeps a tombstone that repeats
// CAPACITY(accept timeout).
func TestAcceptTimeoutIsCapacity_L48(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
		e.links[0].SetDelay(5*time.Millisecond, 0) // the admission is later than the Dial start
		res := e2eDialAsync(context.Background(), e.peer(), DialOptions{})
		pc, err := e.ln.Accept(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		r := <-res
		if r.c != nil || !errors.Is(r.err, ErrCapacity) || r.at < 10*time.Second || r.at >= 15*time.Second {
			t.Fatalf("Dial = %v, %v after %v; want ErrCapacity after the 10 s AcceptTimeout, before the 15 s grace", r.c, r.err, r.at)
		}
		if n := e.links[0].Stats().Dials; n != 2 {
			t.Fatalf("%d carrier dials, want the timed-out first and its parked retry", n)
		}
		if c, err := pc.Confirm(); c != nil || !errors.Is(err, ErrCapacity) {
			t.Fatalf("Confirm after the AcceptTimeout: %v, %v", c, err)
		}
		synctest.Wait()
		if st := e.p.Status(); st.Sessions != (SessionCounts{Tombstones: 1}) || st.AcceptBacklog[0] != 0 {
			t.Fatalf("passive %+v", st)
		}
		d := wpConnect(t, e.ln, e.d.InstanceID(), 50)
		d.hello(e.p)
		d.send(wire.TypeOpen, 0, wpOpen(pc.ID(), wire.KindStream, 1, nil))
		d.expectOpenAck(wire.StatusCapacity, wire.CodeAcceptTimeout)
		d.expectEOF()
		d.close()
		e.close()
	})
}

// TestJoinPriorityUnderOpenFlood_L48: a JOIN of an existing session is
// admitted while the passive application is stalled and an OPEN flood
// keeps MaxSessions and the accept backlog full (plan §3.5 mandatory, L48:
// no OPEN capacity applies to a JOIN). The active carrier of a session in
// the middle of a bulk transfer is killed during the flood: the session
// fails over (one death migration on both ends) and every byte arrives;
// the flood's OPENs meanwhile get CAPACITY(MaxSessions), and the 4 parked
// ones CAPACITY(backlog) at Listener.Close. Load proof: MaxSessions and the
// backlog are full and the flood was refused.
func TestJoinPriorityUnderOpenFlood_L48(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pcfg := Config{MaxSessions: 5}
		e := e2eNew(t, Config{}, pcfg, nil, ListenConfig{AcceptBacklog: 4}, "a")
		link := e.links[0]
		link.SetRate(16 << 20)
		dc, sc := e2eOpen(t, e.peer(), e.ln, DialOptions{})

		// The flood: scripted OPENs (one dialer instance per OPEN) every 5 ms
		// until stop, never accepted: 4 fill the backlog and MaxSessions and
		// wait for the application, every other one is refused.
		stop := make(chan struct{})
		var stopOnce sync.Once
		var flood sync.WaitGroup
		var fmu sync.Mutex
		answers := map[[2]uint32]int{} // {status, code}
		// A failing test still ends the flood and its parked OPENs before
		// the bubble ends (the Runtimes' Close answers or closes them).
		t.Cleanup(func() {
			stopOnce.Do(func() { close(stop) })
			e.d.Close()
			e.p.Close()
			flood.Wait()
		})
		flood.Go(func() {
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				case <-time.After(5 * time.Millisecond):
				}
				d := wpConnect(t, e.ln, wpInst(byte(0x80+i%64)), uint32(i+1))
				flood.Go(func() {
					defer d.close()
					if ack, ok, _ := d.sendPreface(wpPreface(d.inst, d.id)); !ok || ack.Status != wire.PrefaceOK {
						t.Errorf("flood OPEN %d: PREFACE_ACK %+v", i, ack)
						return
					}
					d.send(wire.TypeOpen, 0, wpOpen(wpSID(1000+i), wire.KindStream, 1, nil))
					f, err := d.recv()
					if err != nil || f.Type != wire.TypeOpenAck {
						t.Errorf("flood OPEN %d: %v %v", i, f.Type, err)
						return
					}
					a, err := wire.ParseOpenAck(f.Payload)
					if err != nil {
						t.Errorf("flood OPEN %d: %v", i, err)
						return
					}
					fmu.Lock()
					answers[[2]uint32{uint32(a.Status), a.Code}]++
					fmu.Unlock()
				})
			}
		})
		time.Sleep(200 * time.Millisecond)
		if st := e.p.Status(); st.Sessions.Pending != 4 || st.AcceptBacklog[0] != 4 || e.p.table.inUse() != 5 {
			t.Fatalf("flood load not reached: %+v (units %d)", st, e.p.table.inUse())
		}

		done := make(chan error, 1)
		go func() { done <- e2eExchangeErr(dc, sc, 8<<20, 11) }()
		time.Sleep(200 * time.Millisecond) // mid-transfer
		if n := link.Kill(); n != 1 {
			t.Fatalf("killed %d carriers", n)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("the transfer across the failover: %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("the transfer did not complete after the failover")
		}
		stopOnce.Do(func() { close(stop) })
		if err := e.ln.Close(); err != nil { // the 4 parked OPENs get CAPACITY(backlog); the session is not affected
			t.Fatal(err)
		}
		flood.Wait()
		for _, c := range []*Conn{dc, sc} {
			if st := c.Status(); st.Migrations.Death != 1 || len(liveCarriers(st)) != 1 {
				t.Fatalf("%v after the failover: %+v", st.Role, st)
			}
		}
		fmu.Lock()
		capacity := uint32(wire.StatusCapacity)
		refused, parked, kinds := answers[[2]uint32{capacity, wire.CodeMaxSessions}], answers[[2]uint32{capacity, wire.CodeBacklog}], len(answers)
		fmu.Unlock()
		if refused < 20 || parked != 4 || kinds != 2 {
			t.Fatalf("flood answers %v ({status, code}), want CAPACITY(MaxSessions) ≥ 20 and 4 CAPACITY(backlog) at Listener.Close", answers)
		}
		t.Logf("flood: %d OPENs refused CAPACITY during the failover", refused)
		e2eFinish(t, dc, sc)
		e.close()
	})
}
