package rendr

import (
	"io"
	"math"
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestEventFromAllFields converts an event with every field set.
func TestEventFromAllFields(t *testing.T) {
	at := time.Date(2026, 10, 4, 1, 2, 3, 4, time.UTC)
	in := session.Event{
		Kind: session.EventCarrierDown, Session: [16]byte{1, 2, 3}, Carrier: 7, From: 8, To: 9,
		Cause: carrier.CauseWriteStall, Err: io.ErrUnexpectedEOF, Time: at,
	}
	want := Event{
		Kind: EventCarrierDown, Session: SessionID{1, 2, 3}, Carrier: 7, From: 8, To: 9,
		Cause: CauseWriteStall, Err: io.ErrUnexpectedEOF, Time: at,
	}
	if got := eventFrom(in); got != want {
		t.Fatalf("eventFrom\n got %+v\nwant %+v", got, want)
	}
	if got := eventFrom(in); got.Seq != 0 || got.Cause.String() != "write_stall" || got.Kind.String() != "carrier_down" {
		t.Fatalf("eventFrom %+v", got)
	}
}

// TestSessionStatusFrom converts a full session snapshot, including the
// lane list, field for field.
func TestSessionStatusFrom(t *testing.T) {
	in := session.Status{
		ID: [16]byte{9}, Mode: session.ModeBond, Role: session.RolePassive, PeerInstance: [16]byte{4, 2},
		State: session.StateEnded, Err: ErrIdleTimeout, SchedEpoch: 5, SchedEchoed: 4,
		MigDeath: 1, MigQuality: 2, MigExplicit: 3, Rejoins: 4, NoPathEpisodes: 5, InNoPath: true,
		TxBytes: 10, AckedBytes: 11, RxBytes: 12, DeliveredBytes: 13, RetransmittedBytes: 14,
		Window: 1 << 20, PeerWindow: 1 << 19,
		Carriers: []session.CarrierStatus{
			{ID: 3, Name: "a", Gen: 2, State: session.LaneActive, Stats: carrier.Stats{
				SRTT: time.Millisecond, MinRTT: time.Microsecond, Rate: 1.5, RxRate: 2.5, Inflight: 100, Cap: 200,
				Backlogged: true, PeerBusy: true, TxBytes: 1, RxBytes: 2, RetxBytes: 3, Frames: 4, LastRx: time.Unix(1, 0),
				Handle: 7, Shared: 3,
			}},
			{ID: 4, Gen: 1, State: session.LaneDead, DeathCause: carrier.CausePingTimeout, DeathDetail: "pong late",
				DeathAt: time.Unix(2, 0)},
		},
	}
	want := SessionStatus{
		ID: SessionID{9}, Kind: KindStream, Mode: ModeBond, Role: RolePassive, PeerInstance: InstanceID{4, 2},
		State: StateEnded, Err: ErrIdleTimeout, SchedEpoch: 5, SchedEchoed: 4,
		Migrations: MigrationCounts{Death: 1, Quality: 2, Explicit: 3}, Rejoins: 4, NoPathEpisodes: 5, InNoPath: true,
		TxBytes: 10, AckedBytes: 11, RxBytes: 12, DeliveredBytes: 13, RetransmittedBytes: 14,
		Window: 1 << 20, PeerWindow: 1 << 19,
		Carriers: []CarrierStatus{
			{ID: 3, Name: "a", Kind: KindStream, Gen: 2, State: CarrierActive, SRTT: time.Millisecond, MinRTT: time.Microsecond,
				Rate: 1.5, Inflight: 100, Cap: 200, TxBytes: 1, RxBytes: 2, RetxBytes: 3, Frames: 4, Handle: 7, Shared: 3},
			{ID: 4, Kind: KindStream, Gen: 1, State: CarrierDead, DeathCause: CausePingTimeout, DeathDetail: "pong late"},
		},
	}
	got := sessionStatusFrom(in)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sessionStatusFrom\n got %+v\nwant %+v", got, want)
	}
	// The result shares no memory with the snapshot's lane list.
	in.Carriers[0].Name = "changed"
	if got.Carriers[0].Name != "a" {
		t.Fatal("converted lanes alias the snapshot")
	}
	if st := sessionStatusFrom(session.Status{}); st.Carriers != nil || st.Kind != KindStream {
		t.Fatalf("empty snapshot: %+v", st)
	}
}

// TestFactoryStatusFrom checks the evidence and RTT mapping of PeerStatus
// (design §8.2: a Held path reports its held value, or 0 without one;
// Unknown and Stale report no RTT).
func TestFactoryStatusFrom(t *testing.T) {
	info := carrier.FactoryInfo{Samples: 1, LoadedSamples: 2, Attempts: 3, FailReason: "capacity", ProbeCarrier: 9}
	for _, tc := range []struct {
		ev      sched.Evidence
		wantEv  Evidence
		wantRTT time.Duration
	}{
		{sched.Evidence{State: sched.EvFresh, RTT: 30 * time.Millisecond}, EvidenceFresh, 30 * time.Millisecond},
		{sched.Evidence{State: sched.EvHeld, RTT: 20 * time.Millisecond}, EvidenceHeld, 20 * time.Millisecond},
		{sched.Evidence{State: sched.EvHeld}, EvidenceHeld, 0},
		{sched.Evidence{State: sched.EvStale, RTT: time.Second}, EvidenceStale, 0},
		{sched.Evidence{State: sched.EvUnknown, RTT: time.Second}, EvidenceUnknown, 0},
	} {
		fs := factoryStatusFrom("p1", tc.ev, true, info)
		want := FactoryStatus{Name: "p1", Evidence: tc.wantEv, RTT: tc.wantRTT, Samples: 1, LoadedSamples: 2,
			Failed: true, FailReason: "capacity", ProbeCarrier: 9, Attempts: 3}
		if fs != want {
			t.Errorf("%v: got %+v, want %+v", tc.ev, fs, want)
		}
	}
}

// TestPeerStatusFrom checks the conversions that need no classification:
// a nil snapshot (single-factory Peer) reports every factory Unknown and
// not probing; per-factory failed marks and counters are copied in
// configuration order, tolerating a snapshot shorter than the name list.
func TestPeerStatusFrom(t *testing.T) {
	names := []string{"a", "b", "c"}
	ps := peerStatusFrom(nil, names, time.Now())
	if ps.Probing || len(ps.Factories) != 3 {
		t.Fatalf("nil snapshot: %+v", ps)
	}
	for i, f := range ps.Factories {
		if f != (FactoryStatus{Name: names[i]}) {
			t.Fatalf("nil snapshot factory %d: %+v", i, f)
		}
	}
	snap := &carrier.Snapshot{
		Probing: true,
		Failed:  []bool{false, true},
		Info:    []carrier.FactoryInfo{{Samples: 5}, {Attempts: 7, FailReason: "transport_error"}},
	}
	ps = peerStatusFrom(snap, names, time.Now())
	want := []FactoryStatus{
		{Name: "a", Samples: 5},
		{Name: "b", Failed: true, Attempts: 7, FailReason: "transport_error"},
		{Name: "c"},
	}
	if !ps.Probing || !reflect.DeepEqual(ps.Factories, want) {
		t.Fatalf("snapshot: %+v, want %+v", ps, want)
	}
}

// TestClampInt checks the int64 → int conversion of carrier counters.
func TestClampInt(t *testing.T) {
	for _, tc := range []struct {
		in   int64
		want int
	}{{0, 0}, {-5, -5}, {1 << 30, 1 << 30}, {math.MaxInt64, math.MaxInt}, {math.MinInt64, math.MinInt}} {
		if got := clampInt(tc.in); got != tc.want {
			t.Errorf("clampInt(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestCausePeerDown_PA86: the cause of a carrier the peer reported dead
// with DOWN (PA-86) is public as CausePeerDown, named "peer_down" in
// CarrierStatus.DeathCause and EventCarrierDown, numerically equal to the
// carrier package's (a plain conversion maps it), a death like a transport
// error, and one after which the carrier sends no DOWN of its own; every
// Runtime builds the trunk index the DOWN path uses.
func TestCausePeerDown_PA86(t *testing.T) {
	if CausePeerDown != 10 || CausePeerDown.String() != "peer_down" || Cause(carrier.CausePeerDown) != CausePeerDown || carrier.CausePeerDown.String() != "peer_down" {
		t.Fatalf("CausePeerDown %d %q, carrier's %d %q", CausePeerDown, CausePeerDown.String(), carrier.CausePeerDown, carrier.CausePeerDown.String())
	}
	if !carrier.CausePeerDown.Death() {
		t.Fatal("peer_down is not a death")
	}
	rt, err := NewRuntime(Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	if rt.cenv.Trunks == nil {
		t.Fatal("the Runtime has no trunk index: no DOWN would be sent or understood")
	}
}

// TestStatusConvertM3 (§A10.2, M3-D35, M3-D49): the conversion copies the
// receiver's DupBytes, the race sender's copies and each carrier's Handle
// and Shared; a dialer's CarrierStatus.FateGroup comes from its Peer's
// Props by factory name, the passive's stays empty. End to end, for a
// stream (Dial) and a packet (DialPacket) session, a live unshared carrier
// reports Handle 1 and Shared 1 on both sides and its factory's FateGroup
// on the dialer only.
func TestStatusConvertM3(t *testing.T) {
	in := session.Status{
		Mode: session.ModeRace, DupBytes: 4096, Race: session.RaceCounters{CopyBytes: 8192, Copies: 3},
		Carriers: []session.CarrierStatus{
			{ID: 1, Name: "edge-a", State: session.LaneMember, Stats: carrier.Stats{Handle: 1, Shared: 1}},
			{ID: 2, Name: "solo", State: session.LaneMember, Stats: carrier.Stats{Handle: 9, Shared: 4}},
			{ID: 3, Name: "edge-b", State: session.LaneDead},
		},
	}
	base := sessionStatusFrom(in)
	if base.Mode != ModeRace || base.DupBytes != 4096 || base.Race != (RaceCounters{CopyBytes: 8192, Copies: 3}) {
		t.Fatalf("session fields: mode %v DupBytes %d Race %+v", base.Mode, base.DupBytes, base.Race)
	}
	type row struct {
		Handle    uint32
		Shared    int
		FateGroup string
	}
	rows := func(st SessionStatus) []row {
		var out []row
		for _, c := range st.Carriers {
			out = append(out, row{c.Handle, c.Shared, c.FateGroup})
		}
		return out
	}
	if got, want := rows(base), []row{{1, 1, ""}, {9, 4, ""}, {0, 0, ""}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("carrier rows %+v, want %+v", got, want)
	}
	var passive *peerProps
	if got := passive.status(in); !reflect.DeepEqual(got, base) {
		t.Fatalf("a nil peerProps changed the conversion:\n got %+v\nwant %+v", got, base)
	}
	pp, err := newPeerProps([]Carrier{
		wp6Stream("edge-a", Props{FateGroup: "edge"}), wp6Stream("solo", Props{}), wp6Stream("edge-b", Props{FateGroup: "edge"}),
	}, []string{"edge-a", "solo", "edge-b"})
	if err != nil {
		t.Fatalf("newPeerProps: %v", err)
	}
	if got, want := rows(pp.status(in)), []row{{1, 1, "edge"}, {9, 4, ""}, {0, 0, "edge"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("dialer carrier rows %+v, want %+v", got, want)
	}

	synctest.Test(t, func(t *testing.T) {
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "edge")
		c := e2eCarrier(e.links[0])
		c.Props = Props{FateGroup: "first-hop"}
		p, err := e.d.NewPeer(PeerConfig{Carriers: []Carrier{c}})
		if err != nil {
			t.Fatalf("NewPeer: %v", err)
		}
		dc, pc := e2eOpen(t, p, e.ln, DialOptions{})
		e2eExchange(t, dc, pc, 64<<10, 61)
		for _, x := range []struct {
			c     *Conn
			group string
		}{{dc, "first-hop"}, {pc, ""}} {
			cs := x.c.Status().Carriers
			if len(cs) != 1 || cs[0].State != CarrierActive {
				t.Fatalf("stimulus: carriers %+v, want one active", cs)
			}
			if cs[0].Handle != 1 || cs[0].Shared != 1 || cs[0].FateGroup != x.group {
				t.Fatalf("live carrier: Handle %d Shared %d FateGroup %q, want 1, 1 and %q", cs[0].Handle, cs[0].Shared, cs[0].FateGroup, x.group)
			}
		}
		e2eFinish(t, dc, pc)
		if cs := dc.Status().Carriers; len(cs) != 1 || cs[0].FateGroup != "first-hop" {
			t.Fatalf("ended session's carrier rows %+v, want its fate group kept", cs)
		}
		p.Close()

		// A packet session (DialPacket) on a Peer of its own over the same
		// factory: its dialer *PacketConn reports the factory's fate group
		// as well, its passive none.
		pp, err := e.d.NewPeer(PeerConfig{Carriers: []Carrier{c}})
		if err != nil {
			t.Fatalf("NewPeer: %v", err)
		}
		dpc, ppc := peOpen(t, pp, e.ln, DialOptions{})
		peSend(t, dpc, 67, 0, 16, 200)
		if r := peRecv(t, ppc, 67, 16, 10*time.Second).Result(); r.Unique != 16 || r.Duplicates != 0 || r.Corrupt != 0 {
			t.Fatalf("packet integrity: %+v, want 16 unique datagrams", r)
		}
		for _, x := range []struct {
			c     *PacketConn
			group string
		}{{dpc, "first-hop"}, {ppc, ""}} {
			cs := peLive(x.c)
			if len(cs) != 1 || cs[0].State != CarrierActive {
				t.Fatalf("packet stimulus: carriers %+v, want one active", x.c.Status().Carriers)
			}
			if cs[0].Handle != 1 || cs[0].Shared != 1 || cs[0].FateGroup != x.group {
				t.Fatalf("packet live carrier: Handle %d Shared %d FateGroup %q, want 1, 1 and %q", cs[0].Handle, cs[0].Shared, cs[0].FateGroup, x.group)
			}
		}
		peEnd(t, dpc, ppc)
		pp.Close()
		e.close()
	})
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
