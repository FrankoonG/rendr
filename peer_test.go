package rendr

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
)

// countingFactory is a StreamCarrier whose Dial counts calls and fails.
type countingFactory struct {
	name  string
	calls atomic.Int32
	err   error
}

func (f *countingFactory) carrier() StreamCarrier {
	return StreamCarrier{Name: f.name, Dial: func(context.Context) (net.Conn, error) {
		f.calls.Add(1)
		return nil, f.err
	}}
}

// TestNewPeerValidation: NewPeer accepts 1–16 carriers whose names are
// non-empty and unique and whose Dial is set, as a StreamCarrier value or
// pointer; anything else is an error that leaves nothing behind. After
// Runtime.Close it returns net.ErrClosed.
func TestNewPeerValidation(t *testing.T) {
	rt := wpTestRuntime(t, Config{}, nil)
	dial := func(context.Context) (net.Conn, error) { return nil, errors.New("unused") }
	sc := func(name string) StreamCarrier { return StreamCarrier{Name: name, Dial: dial} }
	many := func(n int) []Carrier {
		cs := make([]Carrier, n)
		for i := range cs {
			cs[i] = sc(string(rune('a' + i)))
		}
		return cs
	}
	bad := []struct {
		name string
		cs   []Carrier
		msg  string
	}{
		{"none", nil, "0 carriers"},
		{"seventeen", many(17), "17 carriers"},
		{"empty name", []Carrier{sc("")}, "no Name"},
		{"duplicate name", []Carrier{sc("x"), sc("y"), sc("x")}, `"x" is used twice`},
		{"nil Dial", []Carrier{StreamCarrier{Name: "x"}}, "no Dial"},
		{"nil Carrier", []Carrier{sc("x"), nil}, "carrier 1"},
		{"nil *StreamCarrier", []Carrier{(*StreamCarrier)(nil)}, "nil *StreamCarrier"},
	}
	for _, tc := range bad {
		p, err := rt.NewPeer(PeerConfig{Carriers: tc.cs})
		if p != nil || err == nil || !strings.Contains(err.Error(), tc.msg) {
			t.Errorf("%s: NewPeer = %v, %v; want an error mentioning %q", tc.name, p, err, tc.msg)
		}
	}
	ptr := sc("by pointer")
	for _, cs := range [][]Carrier{{sc("value")}, {&ptr}} {
		p, err := rt.NewPeer(PeerConfig{Carriers: cs})
		if err != nil {
			t.Fatalf("NewPeer(%v): %v", cs, err)
		}
		if len(p.factories) != 1 || p.health != nil {
			t.Fatalf("single-factory Peer: %d factories, health %v", len(p.factories), p.health)
		}
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
	}
	rt.mu.Lock()
	n := len(rt.peers)
	rt.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d Peers registered after Close", n)
	}
	rt.Close()
	if p, err := rt.NewPeer(PeerConfig{Carriers: []Carrier{sc("late")}}); p != nil || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("NewPeer after Close = %v, %v", p, err)
	}
}

// TestFactorySnapshotFrozen_L20: a session dials only with the snapshot
// taken at Dial (L20). NewPeer deep-copies the carrier list, so changing
// the caller's PeerConfig afterwards changes neither the Peer nor the
// factory snapshot every Dial hands to its session; the snapshot carries
// the configuration order as indexes and the per-Dial Params (NoPathGrace
// override clamped to 3 s, backoff cap, retain). End to end: after Dial
// the caller replaces the factory of the same name in its PeerConfig; when
// the session's carrier is killed, its redial still calls the original
// factory (both ends count one death migration, every byte arrives), never
// the replacement, which only a new Peer built from the changed config
// uses.
func TestFactorySnapshotFrozen_L20(t *testing.T) {
	rt := wpTestRuntime(t, Config{}, nil)
	defer rt.Close()
	f := &countingFactory{name: "orig", err: errors.New("dialled")}
	cfg := PeerConfig{Carriers: []Carrier{f.carrier()}}
	p, err := rt.NewPeer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	other := &countingFactory{name: "other"}
	cfg.Carriers[0] = other.carrier()
	cfg.Carriers = append(cfg.Carriers, other.carrier())

	spec := p.spec(SessionID(wpSID(1)), DialOptions{Mode: ModeBond, Metadata: []byte("m"), NoPathGrace: time.Second}, false)
	if len(spec.Factories) != 1 || spec.Factories[0].Name != "orig" || spec.Factories[0].Index != 0 {
		t.Fatalf("snapshot %+v", spec.Factories)
	}
	if _, err := spec.Factories[0].Dial(context.Background()); err == nil || f.calls.Load() != 1 || other.calls.Load() != 0 {
		t.Fatalf("the snapshot dials the changed factory: orig %d, other %d calls", f.calls.Load(), other.calls.Load())
	}
	ps := spec.Params
	if ps.Role != session.RoleDialer || ps.Mode != session.ModeBond || ps.Grace != 3*time.Second ||
		ps.BackoffMax != 1500*time.Millisecond || ps.Retain != 3*time.Second+rt.eff.cfg.PingIdle+rt.eff.cfg.DeadMax+defRetainSlack {
		t.Fatalf("per-Dial params %+v", ps)
	}
	if spec.SID != wpSID(1) || string(spec.Metadata) != "m" || spec.Health != nil {
		t.Fatalf("spec %+v", spec)
	}
	if ps := p.spec(SessionID(wpSID(2)), DialOptions{}, false).Params; ps.Mode != session.ModeSelector || ps.Grace != rt.eff.cfg.NoPathGrace {
		t.Fatalf("default Dial params %+v", ps)
	}

	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "orig", "repl")
		orig, repl := e.links[0], e.links[1]
		cfg := PeerConfig{Carriers: []Carrier{StreamCarrier{Name: "a", Dial: orig.Dial}}}
		peer, err := e.d.NewPeer(cfg)
		if err != nil {
			t.Fatal(err)
		}
		dc, sc := e2eOpen(t, peer, e.ln, DialOptions{})
		cfg.Carriers[0] = StreamCarrier{Name: "a", Dial: repl.Dial}
		if n := orig.Kill(); n != 1 {
			t.Fatalf("killed %d carriers", n)
		}
		e2eExchange(t, dc, sc, 1<<20, 20)
		if o, r := orig.Stats().Dials, repl.Stats().Dials; o != 2 || r != 0 {
			t.Fatalf("factory calls: original %d, replacement %d; want 2 and 0", o, r)
		}
		for _, c := range []*Conn{dc, sc} {
			if st := c.Status(); st.Migrations.Death != 1 {
				t.Fatalf("%v: %+v", st.Role, st.Migrations)
			}
		}
		p2, err := e.d.NewPeer(cfg)
		if err != nil {
			t.Fatal(err)
		}
		dc2, sc2 := e2eOpen(t, p2, e.ln, DialOptions{})
		if n := repl.Stats().Dials; n != 1 {
			t.Fatalf("the new Peer called the replacement %d times", n)
		}
		e2eFinish(t, dc, sc)
		e2eFinish(t, dc2, sc2)
		e.close()
	})
}

// TestDialPrechecks: Peer.Dial refuses before any factory call, any
// session and any held MaxSessions unit (design §6.6): an unknown Mode is
// ErrProtocol, metadata over Handshake.MaxMetadata is ErrMetadataTooLarge,
// a full abandoned-call pool is ErrCapacity wrapping carrier.ErrAbandonFull,
// local MaxSessions is ErrCapacity, and a closed Peer or Runtime is
// net.ErrClosed. Each error is a net.Error with Timeout false.
func TestDialPrechecks(t *testing.T) {
	rt := wpTestRuntime(t, Config{MaxSessions: 1, Handshake: HandshakeLimits{MaxMetadata: 16}}, &testhooks.Overrides{AbandonLimit: 1})
	f := &countingFactory{name: "f", err: errors.New("unused")}
	p, err := rt.NewPeer(PeerConfig{Carriers: []Carrier{f.carrier()}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	check := func(name string, err error, want error) {
		t.Helper()
		var ne net.Error
		if !errors.Is(err, want) || (want != net.ErrClosed && (!errors.As(err, &ne) || ne.Timeout())) {
			t.Fatalf("%s: Dial error %v, want %v as a net.Error", name, err, want)
		}
		if f.calls.Load() != 0 || rt.table.inUse() != 0 || rt.dial.running() != 0 {
			t.Fatalf("%s: %d factory calls, %d units, %d dials in flight", name, f.calls.Load(), rt.table.inUse(), rt.dial.running())
		}
	}
	_, err = p.Dial(ctx, DialOptions{Mode: 3})
	check("mode 3", err, ErrProtocol)
	_, err = p.Dial(ctx, DialOptions{Metadata: make([]byte, 17)})
	check("metadata", err, ErrMetadataTooLarge)
	rt.abandon.Adopt()
	_, err = p.Dial(ctx, DialOptions{})
	check("abandoned-call pool full", err, ErrCapacity)
	if !errors.Is(err, carrier.ErrAbandonFull) {
		t.Fatalf("abandon-full error %v does not wrap carrier.ErrAbandonFull", err)
	}
	rt.abandon.Leave()
	if !rt.table.placeDialer(SessionID(wpSID(9))) { // the one unit: another Dial in progress
		t.Fatal("placeDialer")
	}
	_, err = p.Dial(ctx, DialOptions{})
	if !errors.Is(err, ErrCapacity) || rt.table.inUse() != 1 {
		t.Fatalf("MaxSessions: %v (%d units)", err, rt.table.inUse())
	}
	rt.table.ended(dialerKey(SessionID(wpSID(9))), nil, session.Verdict{}, time.Now())
	p.Close()
	_, err = p.Dial(ctx, DialOptions{})
	check("closed Peer", err, net.ErrClosed)
	p2, err := rt.NewPeer(PeerConfig{Carriers: []Carrier{f.carrier()}})
	if err != nil {
		t.Fatal(err)
	}
	rt.Close()
	_, err = p2.Dial(ctx, DialOptions{})
	check("closed Runtime", err, net.ErrClosed)
}

// TestPeerGoneAwaySet: the gone-away set (D21) remembers the 64 most
// recently noted instances; noting one again makes it the most recent.
func TestPeerGoneAwaySet(t *testing.T) {
	rt := wpTestRuntime(t, Config{}, nil)
	defer rt.Close()
	f := &countingFactory{name: "f"}
	p, err := rt.NewPeer(PeerConfig{Carriers: []Carrier{f.carrier()}})
	if err != nil {
		t.Fatal(err)
	}
	inst := func(i int) [16]byte { return [16]byte{0xaa, byte(i >> 8), byte(i)} }
	for i := range goneAwayLimit {
		p.noteGoAway(inst(i))
	}
	p.noteGoAway(inst(0)) // the oldest becomes the newest
	for i := goneAwayLimit; i < goneAwayLimit+5; i++ {
		p.noteGoAway(inst(i))
	}
	for i := range goneAwayLimit + 5 {
		want := i == 0 || i >= 6
		if got := p.goneAway(inst(i)); got != want {
			t.Fatalf("instance %d gone away: %v, want %v", i, got, want)
		}
	}
	if len(p.gone) != goneAwayLimit {
		t.Fatalf("%d instances remembered", len(p.gone))
	}
	spec := p.spec(SessionID(wpSID(1)), DialOptions{}, false)
	spec.NoteGoAway(inst(1000))
	if !spec.GoneAway(inst(1000)) || !p.goneAway(inst(1000)) {
		t.Fatal("the session's GoneAway/NoteGoAway are not the Peer's set")
	}
}

// TestPeerStatusSingleFactory: a single-factory Peer never probes; its
// status names the factory with unknown evidence.
func TestPeerStatusSingleFactory(t *testing.T) {
	rt := wpTestRuntime(t, Config{}, nil)
	defer rt.Close()
	f := &countingFactory{name: "only"}
	p, err := rt.NewPeer(PeerConfig{Carriers: []Carrier{f.carrier()}})
	if err != nil {
		t.Fatal(err)
	}
	st := p.Status()
	if st.Probing || len(st.Factories) != 1 || st.Factories[0] != (FactoryStatus{Name: "only"}) {
		t.Fatalf("status %+v", st)
	}
}
