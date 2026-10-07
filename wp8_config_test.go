package rendr

import (
	"slices"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/udpflow"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestPacketConfigNormalize: Config.PacketPing and Config.Packet (M2-D64,
// §A7.4): defaults 1 s, 1 MiB, 100 ms and 65,507; clamps 0.2–10 s, 64 KiB–
// 64 MiB, 10 ms–2 s and 512–65,507, each recorded; then constraint 2
// (PacketPing ≤ DeadMin/2, R1-29's wording) and constraint 8 (Queue ≥
// MaxPayload + 64). The normalized values reach the carrier Timing, the
// packet session template and the udpflow bounds — MaxFlows = min(65,536,
// MaxSessions × MaxCarriersPerSession + Sessionless.Total +
// Handshake.MaxConcurrent), tombstones for max(Handshake.Timeout,
// DialTimeout) + 2 s (M2-D59, R1-11, R1-21) — and the testhooks overrides
// reach all of them unclamped.
func TestPacketConfigNormalize(t *testing.T) {
	e, adj := normalize(Config{}, nil)
	if len(adj) != 0 {
		t.Fatalf("defaults recorded %q", adj)
	}
	if c := e.cfg; c.PacketPing != time.Second || c.Packet != (PacketPolicy{Queue: 1 << 20, MaxAge: 100 * time.Millisecond, MaxPayload: 65507}) {
		t.Fatalf("defaults %v %+v", c.PacketPing, c.Packet)
	}
	wantPk := session.PacketParams{MaxPayload: 65507, Queue: 1 << 20, MaxAge: 100 * time.Millisecond, PacketPing: time.Second,
		PackEvery: 256, FinWaitMax: time.Second, DedupBits: wire.DefaultSeqWindowBits}
	if e.packet != wantPk {
		t.Fatalf("packet template %+v, want %+v", e.packet, wantPk)
	}
	wantFlow := udpflow.Limits{MaxFlows: 10000*6 + 1024 + 256, PerSource: 32, PerSourceJoin: 32, Inbox: 512, TombstoneTTL: 12 * time.Second, Tombstones: 4096}
	if e.flow != wantFlow {
		t.Fatalf("flow limits %+v, want %+v", e.flow, wantFlow)
	}
	tm := e.timing
	if tm.PacketPing != time.Second || tm.PacketActive != 10*time.Second || tm.RelRTOInit != 300*time.Millisecond ||
		tm.RelRTOMin != 200*time.Millisecond || tm.RelRTOMax != 2*time.Second || tm.MTUProbeEvery != 10 || tm.MTUProbeFails != 3 {
		t.Fatalf("timing %+v", tm)
	}

	for _, tc := range []struct {
		name string
		in   Config
		want []string
		ok   func(Config) bool
	}{
		{"PacketPing below", Config{PacketPing: 199 * time.Millisecond}, []string{"PacketPing: 199ms → 200ms (range 200ms..10s)"},
			func(c Config) bool { return c.PacketPing == 200*time.Millisecond }},
		{"PacketPing above, then constraint 2", Config{PacketPing: time.Minute, DeadMin: 10 * time.Second, DeadMax: 10 * time.Second},
			[]string{"PacketPing: 1m0s → 10s (range 200ms..10s)", "PacketPing: 10s → 5s (constraint 2: PacketPing ≤ DeadMin/2)"},
			func(c Config) bool { return c.PacketPing == 5*time.Second }},
		{"PacketPing at DeadMin/2", Config{PacketPing: 1500 * time.Millisecond, DeadMin: 3 * time.Second}, nil,
			func(c Config) bool { return c.PacketPing == 1500*time.Millisecond }},
		{"MaxAge", Config{Packet: PacketPolicy{MaxAge: time.Hour}}, []string{"Packet.MaxAge: 1h0m0s → 2s (range 10ms..2s)"},
			func(c Config) bool { return c.Packet.MaxAge == 2*time.Second }},
		{"MaxPayload", Config{Packet: PacketPolicy{MaxPayload: 100}}, []string{"Packet.MaxPayload: 100 → 512 (range 512..65507)"},
			func(c Config) bool { return c.Packet.MaxPayload == 512 }},
		{"Queue at its floor with the largest MaxPayload", Config{Packet: PacketPolicy{Queue: 64 << 10}},
			[]string{"Packet.Queue: 65536 → 65571 (constraint 8: Packet.Queue ≥ Packet.MaxPayload + 64)"},
			func(c Config) bool { return c.Packet.Queue == 65571 }},
		{"Queue above", Config{Packet: PacketPolicy{Queue: 1 << 30}}, []string{"Packet.Queue: 1073741824 → 67108864 (range 65536..67108864)"},
			func(c Config) bool { return c.Packet.Queue == 64<<20 }},
	} {
		e, adj := normalize(tc.in, nil)
		if !slices.Equal(adj, tc.want) || !tc.ok(e.cfg) {
			t.Errorf("%s: adjustments %q, config %v %+v; want %q", tc.name, adj, e.cfg.PacketPing, e.cfg.Packet, tc.want)
		}
		if e.timing.PacketPing != e.cfg.PacketPing || e.packet.PacketPing != e.cfg.PacketPing || e.packet.Queue != e.cfg.Packet.Queue ||
			e.packet.MaxAge != e.cfg.Packet.MaxAge || e.packet.MaxPayload != e.cfg.Packet.MaxPayload {
			t.Errorf("%s: derived values differ from the config: timing %v, template %+v", tc.name, e.timing.PacketPing, e.packet)
		}
	}

	// The flow bounds follow the Runtime's limits.
	e, _ = normalize(Config{MaxSessions: 10, MaxCarriersPerSession: 4, Sessionless: SessionlessLimits{Total: 7}, Handshake: HandshakeLimits{MaxConcurrent: 3, Timeout: 20 * time.Second}}, nil)
	if e.flow.MaxFlows != 50 || e.flow.TombstoneTTL != 22*time.Second {
		t.Fatalf("flow limits %+v, want MaxFlows 50 and a 22 s tombstone", e.flow)
	}
	if n := flowCap(Config{MaxSessions: 1000000, MaxCarriersPerSession: 16, Sessionless: SessionlessLimits{Total: 1}, Handshake: HandshakeLimits{MaxConcurrent: 1}}); n != udpflow.MaxFlowsCap {
		t.Fatalf("flowCap %d, want the cap %d", n, udpflow.MaxFlowsCap)
	}

	// Overrides reach every derived structure, unclamped and unrecorded.
	ov := &testhooks.Overrides{
		PacketPing: 10 * time.Millisecond, PacketActive: 3 * time.Second, PacketMaxAge: time.Millisecond,
		RelRTOInit: 30 * time.Millisecond, RelRTOMin: 20 * time.Millisecond, RelRTOMax: 90 * time.Millisecond, FinWaitMax: 7 * time.Millisecond,
		PacketQueue: 4096, PacketMaxPayload: 100, PackEvery: 4, DedupBits: 128, MTUProbeEvery: 2, MTUProbeFails: 5,
		FlowMaxFlows: 9, FlowPerSource: 2, FlowPerSourceJoin: 3, FlowInbox: 6, FlowTombstoneTTL: 40 * time.Millisecond,
		FirstSeq: 1<<62 - 10, FirstCseq: 0xFFFFFFF0, PingIdle: 2 * time.Second,
	}
	e, adj = normalize(Config{}, ov)
	if len(adj) != 0 {
		t.Fatalf("overrides recorded %q", adj)
	}
	wantTm := carrier.Timing{PacketPing: 10 * time.Millisecond, PacketActive: 3 * time.Second, RelRTOInit: 30 * time.Millisecond,
		RelRTOMin: 20 * time.Millisecond, RelRTOMax: 90 * time.Millisecond, MTUProbeEvery: 2, MTUProbeFails: 5}
	got := e.timing
	got.PingBusy, got.PingIdle, got.DeadMin, got.DeadMax, got.WriteStall, got.DialTimeout, got.HandshakeTimeout = 0, 0, 0, 0, 0, 0, 0
	got.ProbeInterval, got.SessionlessIdle, got.AbandonWait, got.Window, got.CapFloor, got.BatchBudget, got.Segment = 0, 0, 0, 0, 0, 0, 0
	if got != wantTm {
		t.Fatalf("timing overrides %+v, want %+v", got, wantTm)
	}
	wantPk = session.PacketParams{MaxPayload: 100, Queue: 4096, MaxAge: time.Millisecond, PacketPing: 10 * time.Millisecond,
		PackEvery: 4, FinWaitMax: 7 * time.Millisecond, DedupBits: 128, FirstSeq: 1<<62 - 10}
	if e.packet != wantPk {
		t.Fatalf("packet overrides %+v, want %+v", e.packet, wantPk)
	}
	wantFlow = udpflow.Limits{MaxFlows: 9, PerSource: 2, PerSourceJoin: 3, Inbox: 6, TombstoneTTL: 40 * time.Millisecond, Tombstones: 4096}
	if e.flow != wantFlow || e.presets.FirstCseq != 0xFFFFFFF0 {
		t.Fatalf("flow overrides %+v (FirstCseq %#x), want %+v", e.flow, e.presets.FirstCseq, wantFlow)
	}
	// PacketActive follows an overridden PingIdle unless it is set itself.
	if e2, _ := normalize(Config{}, &testhooks.Overrides{PingIdle: 2 * time.Second}); e2.timing.PacketActive != 2*time.Second {
		t.Fatalf("PacketActive %v, want the overridden PingIdle", e2.timing.PacketActive)
	}

	// The per-session packet Params.
	p := e.packetParams(e.passiveParams(ModeBond, 30000, time.Second), 600)
	if p.Kind != wire.KindDatagram || p.Packet.MaxPayload != 600 || p.Packet.Queue != 4096 || p.Role != session.RolePassive || p.Mode != session.ModeBond {
		t.Fatalf("passive packet params %+v", p)
	}
}
