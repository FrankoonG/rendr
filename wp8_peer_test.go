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

// TestPacketLogicalAddr_L38 (destination check): WriteTo accepts only nil
// or the session's remote Addr (also as a non-nil *Addr); any other
// address — another session's Addr, a typed nil *Addr, a *net.UDPAddr, a
// foreign net.Addr whose String panics — returns (0,
// ErrPacketDestinationMismatch) without calling any method of it and
// without reaching the session. (The end-to-end half — the address stable
// across migrations, the token reaching the factory — is
// TestPacketLogicalAddrE2E_L38.)
func TestPacketLogicalAddr_L38(t *testing.T) {
	remote := Addr{Instance: InstanceID(wpInst(1)), Session: SessionID(wpSID(1))}
	c := &PacketConn{remote: remote} // no session: a mismatch never reaches it
	other := remote
	other.Session[15] ^= 1
	var typedNil *Addr
	for _, tc := range []struct {
		name string
		addr net.Addr
	}{
		{"another session", other},
		{"another session by pointer", &other},
		{"typed nil *Addr", typedNil},
		{"UDP address", &net.UDPAddr{Port: 1}},
		{"foreign address whose String panics", panicAddr{}},
	} {
		if n, err := c.WriteTo([]byte("x"), tc.addr); n != 0 || !errors.Is(err, ErrPacketDestinationMismatch) {
			t.Errorf("%s: WriteTo = %d, %v", tc.name, n, err)
		}
	}
	for _, a := range []net.Addr{nil, remote, &remote} {
		if !c.isRemote(a) {
			t.Errorf("isRemote(%v) = false", a)
		}
	}
	if c.RemoteAddr() != net.Addr(remote) {
		t.Fatal("RemoteAddr")
	}
}

// TestPacketStatusFields: Status of a packet session (M2-D61, §A7.2): Kind
// KindPacket, MaxPayload and every PacketCounters field copied; a datagram
// carrier is reported with KindDatagram, its frame budget and its
// Dropped, Retransmits and Rebinds; a stream session keeps Kind stream and
// a nil Packet.
func TestPacketStatusFields(t *testing.T) {
	pk := session.PacketCounters{Sent: 1, Received: 2, Duplicates: 3, DropQueue: 4, DropAge: 5, DropTooLarge: 6, DropNoPath: 7,
		DropRecvQueue: 8, DropLate: 9, PeerReceived: 10}
	st := session.Status{Kind: wire.KindDatagram, MaxPayload: 1127, Packet: &pk, Carriers: []session.CarrierStatus{
		{ID: 1, Stats: carrier.Stats{Kind: wire.KindDatagram, MTU: 1152, Dropped: 11, Retransmits: 12, Rebinds: 13, TxBytes: 14}},
		{ID: 2, Stats: carrier.Stats{Kind: wire.KindStream, TxBytes: 15}},
		{ID: 3, Stats: carrier.Stats{Kind: wire.KindDatagram}}, // the kind is the carrier's, not inferred from MTU
	}}
	out := sessionStatusFrom(st)
	want := PacketCounters{Sent: 1, Received: 2, Duplicates: 3, DropQueue: 4, DropAge: 5, DropTooLarge: 6, DropNoPath: 7,
		DropRecvQueue: 8, DropLate: 9, PeerReceived: 10}
	if out.Kind != KindPacket || out.MaxPayload != 1127 || out.Packet == nil || *out.Packet != want {
		t.Fatalf("packet session status %+v", out)
	}
	c0, c1 := out.Carriers[0], out.Carriers[1]
	if c2 := out.Carriers[2]; c2.Kind != KindDatagram {
		t.Fatalf("datagram carrier without MTU %+v", c2)
	}
	if c0.Kind != KindDatagram || c0.MTU != 1152 || c0.Dropped != 11 || c0.Retransmits != 12 || c0.Rebinds != 13 || c0.TxBytes != 14 {
		t.Fatalf("datagram carrier %+v", c0)
	}
	if c1.Kind != KindStream || c1.MTU != 0 || c1.TxBytes != 15 {
		t.Fatalf("stream carrier %+v", c1)
	}
	if s := sessionStatusFrom(session.Status{}); s.Kind != KindStream || s.Packet != nil || s.MaxPayload != 0 {
		t.Fatalf("stream session status %+v", s)
	}
}
