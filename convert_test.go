package rendr

import (
	"io"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/session"
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
				Rate: 1.5, Inflight: 100, Cap: 200, TxBytes: 1, RxBytes: 2, RetxBytes: 3, Frames: 4},
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
