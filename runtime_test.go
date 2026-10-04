package rendr

import (
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
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
// non-nil net.Listener; a rejected Listen takes no ownership (the listener
// is not closed) and records no adjustment.
func TestListenRejectsBadSources(t *testing.T) {
	rt := wpTestRuntime(t, Config{}, nil)
	defer rt.Close()
	l := newFakeListener()
	for _, srcs := range [][]Source{{nil}, {FromListener(nil)}, {FromListener(l), nil}} {
		if ln, err := rt.Listen(ListenConfig{Sources: srcs, AcceptBacklog: -1}); ln != nil || err == nil {
			t.Fatalf("Listen(%v) = %v, %v", srcs, ln, err)
		}
	}
	if l.closes.Load() != 0 || len(rt.Status().ConfigAdjustments) != 0 {
		t.Fatalf("a rejected Listen closed its source (%d) or recorded %q", l.closes.Load(), rt.Status().ConfigAdjustments)
	}
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
