package rendr

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
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
// session and any held MaxSessions unit (design §6.6): an unknown Mode
// (above ModeRace since M3) is ErrProtocol, metadata over Handshake.MaxMetadata is ErrMetadataTooLarge,
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
	_, err = p.Dial(ctx, DialOptions{Mode: ModeRace + 1})
	check("mode 4", err, ErrProtocol)
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

// countingDgram is a datagram factory that counts its calls and refuses
// them.
type countingDgram struct {
	name  string
	mtu   int
	calls atomic.Int32
}

func (f *countingDgram) carrier() DatagramCarrier {
	return DatagramCarrier{Name: f.name, MTU: f.mtu, Dial: func(context.Context) (net.PacketConn, net.Addr, error) {
		f.calls.Add(1)
		return nil, nil, errors.New("refused")
	}}
}

// TestNewPeerDatagramValidation: NewPeer accepts DatagramCarrier factories
// beside StreamCarrier ones (M2 design §A2.1): as a value or a non-nil
// pointer, with a unique non-empty Name across both kinds, a Dial, and an
// MTU of 537–65,507 bytes (M2-D51: the frame budget of a 512-byte
// MaxPayload; carrier/udp reports an invalid MaxDatagram as MTU 0, which
// fails here); at most 16 factories of both kinds. Every factory carries
// its kind (R1-32), and a datagram factory its MTU and its Dial as
// DialPacket.
func TestNewPeerDatagramValidation(t *testing.T) {
	rt := wpTestRuntime(t, Config{}, nil)
	pdial := func(context.Context) (net.PacketConn, net.Addr, error) { return nil, nil, errors.New("unused") }
	sdial := func(context.Context) (net.Conn, error) { return nil, errors.New("unused") }
	dc := func(name string, mtu int) DatagramCarrier { return DatagramCarrier{Name: name, Dial: pdial, MTU: mtu} }
	sc := func(name string) StreamCarrier { return StreamCarrier{Name: name, Dial: sdial} }
	var nilDC *DatagramCarrier
	bad := []struct {
		name string
		cs   []Carrier
		want string
	}{
		{"MTU 0", []Carrier{dc("d", 0)}, "MTU 0"},
		{"MTU 536", []Carrier{dc("d", 536)}, "MTU 536"},
		{"MTU 65,508", []Carrier{dc("d", 65508)}, "MTU 65508"},
		{"no name", []Carrier{dc("", 1152)}, "no Name"},
		{"no Dial", []Carrier{DatagramCarrier{Name: "d", MTU: 1152}}, "no Dial"},
		{"nil pointer", []Carrier{nilDC}, "nil *DatagramCarrier"},
		{"name used by a stream factory", []Carrier{sc("x"), dc("x", 1152)}, "used twice"},
		{"17 factories", func() []Carrier {
			cs := []Carrier{}
			for i := range 17 {
				if i%2 == 0 {
					cs = append(cs, dc(string(rune('a'+i)), 1152))
				} else {
					cs = append(cs, sc(string(rune('a'+i))))
				}
			}
			return cs
		}(), "17 carriers"},
	}
	for _, tc := range bad {
		if p, err := rt.NewPeer(PeerConfig{Carriers: tc.cs}); p != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: NewPeer = %v, %v; want an error mentioning %q", tc.name, p, err, tc.want)
		}
	}
	d := dc("d", wire.MinFrameBudget)
	p, err := rt.NewPeer(PeerConfig{Carriers: []Carrier{sc("s"), d, &DatagramCarrier{Name: "q", Dial: pdial, MTU: wire.MaxDatagram}}})
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	fs := p.factories
	if fs[0].Kind != wire.KindStream || fs[0].Dial == nil || fs[0].MTU != 0 ||
		fs[1].Kind != wire.KindDatagram || fs[1].DialPacket == nil || fs[1].Dial != nil || fs[1].MTU != wire.MinFrameBudget || fs[1].Index != 1 ||
		fs[2].Kind != wire.KindDatagram || fs[2].MTU != wire.MaxDatagram || fs[2].Name != "q" {
		t.Fatalf("factories %+v", fs)
	}
	if p.streams != 1 || p.health == nil || len(p.Status().Factories) != 3 {
		t.Fatalf("stream mask %b, health %v", p.streams, p.health)
	}
	p.Close()
}

// TestStreamDialNeedsStreamFactory: a stream session dials stream
// factories only (M2-D46): Peer.Dial on a Peer without a stream factory
// fails at once with an error matching ErrNoPath, without a factory call
// or a probe wait; on a mixed Peer its DialSpec makes only the stream
// factories eligible, while a packet session's makes every factory
// eligible; an all-stream Peer keeps M1's DialSpec (Eligible 0).
func TestStreamDialNeedsStreamFactory(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		d1, d2 := &countingDgram{name: "d1", mtu: 1152}, &countingDgram{name: "d2", mtu: 1232}
		p, err := rt.NewPeer(PeerConfig{Carriers: []Carrier{d1.carrier(), d2.carrier()}})
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		c, err := p.Dial(context.Background(), DialOptions{})
		if c != nil || !errors.Is(err, ErrNoPath) || !strings.Contains(err.Error(), "no stream carrier factory") {
			t.Fatalf("Dial on a datagram-only Peer = %v, %v", c, err)
		}
		if el := time.Since(start); el != 0 {
			t.Fatalf("Dial took %v, want an immediate failure", el)
		}
		synctest.Wait()
		if n := d1.calls.Load() + d2.calls.Load(); n != 0 || rt.table.inUse() != 0 {
			t.Fatalf("%d factory calls, %d MaxSessions units", n, rt.table.inUse())
		}
		if spec := p.spec(SessionID(wpSID(1)), DialOptions{}, true); spec.Eligible != 0 || spec.Params.Kind != wire.KindDatagram {
			t.Fatalf("packet DialSpec: eligible %b, kind %v", spec.Eligible, spec.Params.Kind)
		}
		p.Close()

		s1, s2 := &countingFactory{name: "s1"}, &countingFactory{name: "s2"}
		mixed, err := rt.NewPeer(PeerConfig{Carriers: []Carrier{d1.carrier(), s1.carrier(), d2.carrier(), s2.carrier()}})
		if err != nil {
			t.Fatal(err)
		}
		if spec := mixed.spec(SessionID(wpSID(2)), DialOptions{}, false); spec.Eligible != 0b1010 || spec.Params.Kind != 0 {
			t.Fatalf("stream DialSpec on a mixed Peer: eligible %b, kind %v; want 1010 and stream", spec.Eligible, spec.Params.Kind)
		}
		if spec := mixed.spec(SessionID(wpSID(3)), DialOptions{}, true); spec.Eligible != 0 {
			t.Fatalf("packet DialSpec on a mixed Peer: eligible %b, want all", spec.Eligible)
		}
		mixed.Close()
		streams, err := rt.NewPeer(PeerConfig{Carriers: []Carrier{s1.carrier(), s2.carrier()}})
		if err != nil {
			t.Fatal(err)
		}
		if spec := streams.spec(SessionID(wpSID(4)), DialOptions{}, false); spec.Eligible != 0 {
			t.Fatalf("stream DialSpec on an all-stream Peer: eligible %b, want 0 (M1)", spec.Eligible)
		}
		if !anyEligible(2, 0) || !anyEligible(4, 0b1000) || anyEligible(2, 0b100) || anyEligible(0, 0) {
			t.Fatal("anyEligible")
		}
		streams.Close()
		rt.Close()
	})
}

// TestDialPacketMaxPayload_L37 (the dialer's offer; M2-D49, §A5.4): a
// selector session with a datagram factory offers the smallest datagram
// payload budget (MTU − 25) of the Peer's datagram factories, also when
// the Peer has a stream factory (PA-4); a bond session offers
// Packet.MaxPayload when a stream factory can carry what the datagram
// members cannot, else that minimum; a stream-only Peer offers
// Packet.MaxPayload; no offer exceeds Packet.MaxPayload. The DialSpec of a
// DialPacket carries the offer and the packet configuration. (The end-to-
// end table — the session's MaxPayload once OPEN_ACK fixed it — is
// TestDialPacketMaxPayloadE2E_L37.)
func TestDialPacketMaxPayload_L37(t *testing.T) {
	ds := func(mtus ...int) []carrier.Factory {
		fs := make([]carrier.Factory, len(mtus))
		for i, m := range mtus {
			if m == 0 {
				fs[i] = carrier.Factory{Kind: wire.KindStream}
			} else {
				fs[i] = carrier.Factory{Kind: wire.KindDatagram, MTU: m}
			}
		}
		return fs
	}
	for _, tc := range []struct {
		name       string
		fs         []carrier.Factory
		bond       bool
		maxPayload int
		want       int
	}{
		{"selector, QUIC", ds(1152), false, 65507, 1127},
		{"selector, raw UDP default", ds(1223), false, 65507, 1198},
		{"selector, two MTUs: the smaller", ds(1425, 1125), false, 65507, 1100},
		{"selector with a stream factory: still the datagram budget (PA-4)", ds(0, 1425, 1125), false, 65507, 1100},
		{"selector, stream only", ds(0, 0), false, 65507, 65507},
		{"selector, own limit", ds(1425), false, 1000, 1000},
		{"bond with a stream factory", ds(1425, 0, 1125), true, 65507, 65507},
		{"bond with a stream factory, own limit", ds(1425, 0), true, 1250, 1250},
		{"bond without a stream factory", ds(1425, 1125), true, 65507, 1100},
		{"bond, stream only", ds(0), true, 2000, 2000},
	} {
		if got := packetOffer(tc.fs, tc.bond, tc.maxPayload); got != tc.want {
			t.Errorf("%s: offer %d, want %d", tc.name, got, tc.want)
		}
	}

	rt := wpTestRuntime(t, Config{Packet: PacketPolicy{Queue: 2 << 20, MaxAge: 50 * time.Millisecond, MaxPayload: 1250}, PacketPing: 500 * time.Millisecond},
		&testhooks.Overrides{PackEvery: 64, FinWaitMax: 300 * time.Millisecond, DedupBits: 1024, FirstSeq: 1 << 40})
	d1, d2, s1 := &countingDgram{name: "d1", mtu: 1425}, &countingDgram{name: "d2", mtu: 1125}, &countingFactory{name: "s"}
	p, err := rt.NewPeer(PeerConfig{Carriers: []Carrier{d1.carrier(), s1.carrier(), d2.carrier()}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	want := session.PacketParams{MaxPayload: 1100, Queue: 2 << 20, MaxAge: 50 * time.Millisecond, PacketPing: 500 * time.Millisecond,
		PackEvery: 64, FinWaitMax: 300 * time.Millisecond, DedupBits: 1024, FirstSeq: 1 << 40}
	if sp := p.spec(SessionID(wpSID(1)), DialOptions{}, true).Params; sp.Kind != wire.KindDatagram || sp.Packet != want || sp.Role != session.RoleDialer {
		t.Fatalf("selector packet params %+v, want %+v", sp, want)
	}
	want.MaxPayload = 1250 // bond with a stream factory: Packet.MaxPayload
	if sp := p.spec(SessionID(wpSID(2)), DialOptions{Mode: ModeBond}, true).Params; sp.Packet != want || sp.Mode != session.ModeBond {
		t.Fatalf("bond packet params %+v, want %+v", sp, want)
	}
}

// TestPacketMetadataTooLarge_L37: a datagram factory carries a packet
// session's OPEN only when the whole first datagram — 99 bytes plus the
// metadata — fits its frame budget (M2-D52, plan:358). DialPacket refuses
// at once with ErrMetadataTooLarge, before any factory call or MaxSessions
// unit, when no factory of the Peer can carry the OPEN; a stream factory
// carries any metadata within Handshake.MaxMetadata, and so does a
// datagram factory at exactly its limit.
func TestPacketMetadataTooLarge_L37(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, &testhooks.Overrides{NoPathGrace: 200 * time.Millisecond})
		d := &countingDgram{name: "d", mtu: 1152}
		p, err := rt.NewPeer(PeerConfig{Carriers: []Carrier{d.carrier()}})
		if err != nil {
			t.Fatal(err)
		}
		over := make([]byte, 1152-99+1)
		c, err := p.DialPacket(context.Background(), DialOptions{Metadata: over})
		if c != nil || !errors.Is(err, ErrMetadataTooLarge) {
			t.Fatalf("DialPacket with %d bytes of metadata on MTU 1152 = %v, %v", len(over), c, err)
		}
		synctest.Wait()
		if d.calls.Load() != 0 || rt.table.inUse() != 0 {
			t.Fatalf("a refused DialPacket called the factory %d times, %d units", d.calls.Load(), rt.table.inUse())
		}
		// At the limit the OPEN fits: the Dial proceeds (and fails later,
		// the factory refusing every call).
		if _, err := p.DialPacket(context.Background(), DialOptions{Metadata: over[1:]}); errors.Is(err, ErrMetadataTooLarge) || d.calls.Load() == 0 {
			t.Fatalf("DialPacket at the limit: %v after %d factory calls", err, d.calls.Load())
		}
		p.Close()
		if !openCapable([]carrier.Factory{{Kind: wire.KindDatagram, MTU: 537}, {Kind: wire.KindStream}}, 4096) ||
			openCapable([]carrier.Factory{{Kind: wire.KindDatagram, MTU: 537}}, 439) || !openCapable([]carrier.Factory{{Kind: wire.KindDatagram, MTU: 537}}, 438) {
			t.Fatal("openCapable")
		}
		if openOverhead != 99 {
			t.Fatalf("openOverhead %d, want 99 (plan:358)", openOverhead)
		}
		rt.Close()
		wpNoState(t, rt)
	})
}

// TestCarrierDialInfo: every factory call's context carries the carrier it
// is for (M2-D55; regress R-1): a stream session's call names its session
// and the carrier ID the session reports, kind stream; a packet session's
// datagram call kind datagram and its session; a probe call of a Peer's
// health layer Probe true and no session. Any other context reports false.
func TestCarrierDialInfo(t *testing.T) {
	if _, ok := CarrierDialInfo(context.Background()); ok {
		t.Fatal("CarrierDialInfo on a plain context")
	}
	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
		var (
			mu    sync.Mutex
			infos []DialInfo
		)
		record := func(ctx context.Context) {
			d, ok := CarrierDialInfo(ctx)
			if !ok {
				t.Error("a factory call without DialInfo")
			}
			mu.Lock()
			infos = append(infos, d)
			mu.Unlock()
		}
		taken := func() []DialInfo {
			mu.Lock()
			defer mu.Unlock()
			out := infos
			infos = nil
			return out
		}
		link := e.links[0]
		p, err := e.d.NewPeer(PeerConfig{Carriers: []Carrier{StreamCarrier{Name: "a", Dial: func(ctx context.Context) (net.Conn, error) {
			record(ctx)
			return link.Dial(ctx)
		}}}})
		if err != nil {
			t.Fatal(err)
		}
		dc, pc := e2eOpen(t, p, e.ln, DialOptions{})
		got := taken()
		if len(got) != 1 || got[0].Kind != KindStream || got[0].Probe || got[0].Session != dc.ID() ||
			got[0].Carrier == 0 || got[0].Carrier != dc.Status().Carriers[0].ID {
			t.Fatalf("stream DialInfo %+v (session %v, carrier %+v)", got, dc.ID(), dc.Status().Carriers)
		}
		dc.Close()
		pc.Close()
		p.Close()

		// Datagram factories: a packet session's call, and probes.
		dl := rendrtest.NewDatagramLink(rendrtest.DatagramLinkConfig{Name: "dg", Accept: e.ln.HandlePacket})
		defer dl.Close()
		dg := func(name string) DatagramCarrier {
			return DatagramCarrier{Name: name, MTU: 1152, Dial: func(ctx context.Context) (net.PacketConn, net.Addr, error) {
				record(ctx)
				return nil, nil, errors.New("refused")
			}}
		}
		pp, err := e.d.NewPeer(PeerConfig{Carriers: []Carrier{dg("x"), dg("y")}})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err = pp.DialPacket(ctx, DialOptions{})
		cancel()
		if err == nil {
			t.Fatal("DialPacket over refusing factories succeeded")
		}
		var sess, probes int
		var sid SessionID
		for _, d := range taken() {
			switch {
			case d.Kind != KindDatagram || d.Carrier == 0:
				t.Fatalf("datagram DialInfo %+v", d)
			case d.Probe:
				if d.Session != (SessionID{}) {
					t.Fatalf("probe DialInfo with a session %+v", d)
				}
				probes++
			default:
				if sid != (SessionID{}) && d.Session != sid || d.Session == (SessionID{}) {
					t.Fatalf("session DialInfo %+v (session %v)", d, sid)
				}
				sid = d.Session
				sess++
			}
		}
		if sess == 0 || probes == 0 {
			t.Fatalf("%d session and %d probe calls, want both", sess, probes)
		}
		pp.Close()
		e.close()
	})
}

// WP6 of milestone M3: the root surface of carrier properties (M3 design
// §A7.1).

// wp6Dial is a factory Dial that is never called (NewPeer only validates).
func wp6Dial(context.Context) (net.Conn, error) { return nil, errors.New("not dialled") }

// wp6DialPC is a datagram factory Dial that is never called.
func wp6DialPC(context.Context) (net.PacketConn, net.Addr, error) {
	return nil, nil, errors.New("not dialled")
}

func wp6Stream(name string, pr Props) StreamCarrier {
	return StreamCarrier{Name: name, Dial: wp6Dial, Props: pr}
}

func wp6Dgram(name string, pr Props) DatagramCarrier {
	return DatagramCarrier{Name: name, Dial: wp6DialPC, MTU: 1400, Props: pr}
}

// TestPropsValidation (M3-D36, §A7.1): NewPeer accepts a FateGroup of up
// to 64 bytes, HoLCoupled only with a FateGroup, and the factories of one
// FateGroup only when they agree on HoLCoupled; every refusal names the
// offending factory. Props are read from both factory kinds, as values and
// as pointers; a group may mix stream and datagram factories, and equal
// HoLCoupled settings in different groups never conflict.
func TestPropsValidation(t *testing.T) {
	g64, g65 := strings.Repeat("g", 64), strings.Repeat("g", 65)
	cases := []struct {
		name string
		cs   []Carrier
		bad  string // "" accepted; else a substring of the error (the factory's name)
	}{
		{"zero Props", []Carrier{wp6Stream("a", Props{}), wp6Dgram("b", Props{})}, ""},
		{"64-byte group", []Carrier{wp6Stream("a", Props{FateGroup: g64})}, ""},
		{"65-byte group", []Carrier{wp6Stream("a", Props{}), wp6Stream("long", Props{FateGroup: g65})}, `"long"`},
		{"65-byte group on a datagram pointer", []Carrier{&DatagramCarrier{Name: "dp", Dial: wp6DialPC, MTU: 1400, Props: Props{FateGroup: g65}}}, `"dp"`},
		{"coupled without a group", []Carrier{wp6Stream("a", Props{}), wp6Stream("lone", Props{HoLCoupled: true})}, `"lone"`},
		{"coupled without a group, stream pointer", []Carrier{&StreamCarrier{Name: "sp", Dial: wp6Dial, Props: Props{HoLCoupled: true}}}, `"sp"`},
		{"coupled group", []Carrier{
			wp6Stream("a", Props{FateGroup: "tls", HoLCoupled: true}),
			wp6Dgram("b", Props{FateGroup: "tls", HoLCoupled: true}),
			wp6Stream("c", Props{FateGroup: "relay"}),
		}, ""},
		{"group disagrees", []Carrier{
			wp6Stream("a", Props{FateGroup: "tls", HoLCoupled: true}),
			wp6Stream("b", Props{FateGroup: "relay"}),
			wp6Stream("c", Props{FateGroup: "tls"}),
		}, `"c"`},
		{"group disagrees the other way", []Carrier{
			wp6Dgram("a", Props{FateGroup: "tls"}),
			wp6Dgram("b", Props{FateGroup: "tls", HoLCoupled: true}),
		}, `"b"`},
		{"cheap subflows mixed", []Carrier{
			wp6Stream("a", Props{FateGroup: "x", CheapSubflow: true}),
			wp6Stream("b", Props{FateGroup: "x"}),
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := wpTestRuntime(t, Config{}, nil)
			p, err := rt.NewPeer(PeerConfig{Carriers: tc.cs})
			switch {
			case tc.bad == "" && err != nil:
				t.Fatalf("NewPeer: %v, want it accepted", err)
			case tc.bad != "" && err == nil:
				p.Close()
				t.Fatalf("NewPeer accepted invalid Props, want an error naming %s", tc.bad)
			case tc.bad != "" && !strings.Contains(err.Error(), tc.bad):
				t.Fatalf("NewPeer: %v, want it to name %s", err, tc.bad)
			}
			if p != nil {
				p.Close()
			}
			rt.Close()
		})
	}
}

// TestPropsGroupsInterned (§A7.1; M3-D37, M3-D39): equal non-empty
// FateGroups share one index, numbered from 1 in configuration order; every
// factory with an empty FateGroup gets index 0 (a group of its own); a
// coupled group sets the bit of each of its factories. Every dialer
// session's spec carries the Peer's groups, and the dialer reports each
// factory's FateGroup name. CheapSubflow factories stay off rendr mux
// (carrier.Factory.Mux is the complement).
func TestPropsGroupsInterned(t *testing.T) {
	cs := []Carrier{
		wp6Stream("a", Props{FateGroup: "edge"}),
		wp6Stream("b", Props{}),
		&StreamCarrier{Name: "c", Dial: wp6Dial, Props: Props{FateGroup: "edge"}},
		wp6Dgram("d", Props{FateGroup: "tls", HoLCoupled: true, CheapSubflow: true}),
		&DatagramCarrier{Name: "e", Dial: wp6DialPC, MTU: 1400, Props: Props{FateGroup: "tls", HoLCoupled: true}},
		wp6Stream("f", Props{CheapSubflow: true}),
		wp6Stream("g", Props{FateGroup: "relay"}),
	}
	rt := wpTestRuntime(t, Config{}, nil)
	defer rt.Close()
	p, err := rt.NewPeer(PeerConfig{Carriers: cs})
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	defer p.Close()
	want := [maxFactories]uint8{1, 0, 1, 2, 2, 0, 3}
	const wantCoupled = 1<<3 | 1<<4
	for _, packet := range []bool{false, true} {
		spec := p.spec(SessionID{1}, DialOptions{Mode: ModeRace}, packet)
		if spec.Groups != want || spec.Coupled != wantCoupled {
			t.Fatalf("packet %v: DialSpec.Groups %v Coupled %#x, want %v and %#x", packet, spec.Groups, spec.Coupled, want, wantCoupled)
		}
		if spec.Params.Mode != session.ModeRace {
			t.Fatalf("packet %v: DialSpec.Params.Mode %v, want race", packet, spec.Params.Mode)
		}
	}
	for i, name := range []string{"edge", "", "edge", "tls", "tls", "", "relay"} {
		if got := p.props.fateGroup(i); got != name {
			t.Fatalf("fateGroup(%d) = %q, want %q", i, got, name)
		}
	}
	if got := p.props.fateGroup(len(cs)); got != "" {
		t.Fatalf("fateGroup beyond the factories = %q", got)
	}
	fs := make([]carrier.Factory, len(cs))
	p.props.muxFactories(fs)
	for i, f := range fs {
		if cheap := i == 3 || i == 5; f.Mux == cheap {
			t.Fatalf("factory %d: Mux %v, CheapSubflow %v", i, f.Mux, cheap)
		}
	}
	// A zero-Props Peer keeps every factory independent (M2's behaviour).
	q, err := rt.NewPeer(PeerConfig{Carriers: []Carrier{wp6Stream("x", Props{}), wp6Stream("y", Props{})}})
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	defer q.Close()
	if spec := q.spec(SessionID{2}, DialOptions{}, false); spec.Groups != ([maxFactories]uint8{}) || spec.Coupled != 0 {
		t.Fatalf("zero Props: Groups %v Coupled %#x, want zero", spec.Groups, spec.Coupled)
	}
}
