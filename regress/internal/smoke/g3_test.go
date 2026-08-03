package smoke

import (
	"strings"
	"testing"
	"time"
)

func TestG3OptsStrictLossAndMigrationDisable(t *testing.T) {
	defaults := G3Opts{}
	defaults.withDefaults()
	if defaults.LossPct != 0 {
		t.Fatalf("default loss budget=%v want strict zero", defaults.LossPct)
	}
	if defaults.Migrations != 3 {
		t.Fatalf("default migrations=%d want 3", defaults.Migrations)
	}

	disabled := G3Opts{Migrations: -1}
	disabled.withDefaults()
	if disabled.Migrations != 0 {
		t.Fatalf("disabled migrations=%d want 0", disabled.Migrations)
	}
}

func TestValidateG3MeasurementsRejectsFalseGreenEvidence(t *testing.T) {
	opts := G3Opts{
		PPS:          1000,
		Migrations:   3,
		Paths:        4,
		P95CeilingMs: 50,
		LossPct:      0,
		Duration:     time.Second,
		PayloadLen:   1024,
	}
	valid := g3Measurements{
		sent:               1000,
		received:           1000,
		sendElapsed:        time.Second,
		latencySamples:     20,
		p95:                10 * time.Millisecond,
		migrationAttempts:  3,
		migrationsObserved: 3,
		pathWriters:        4,
		wireWrites:         1000,
	}

	tests := []struct {
		name        string
		mutate      func(*g3Measurements)
		wantInvalid string
		wantFailure string
	}{
		{name: "no packets", mutate: func(m *g3Measurements) { m.sent = 0 }, wantInvalid: "no packets"},
		{name: "under offered load", mutate: func(m *g3Measurements) { m.sent = 900; m.received = 900 }, wantInvalid: "offered load"},
		{name: "no samples", mutate: func(m *g3Measurements) { m.latencySamples = 0 }, wantInvalid: "latency samples"},
		{name: "missing stimulus", mutate: func(m *g3Measurements) { m.migrationAttempts = 2 }, wantInvalid: "attempts=2"},
		{name: "single path traffic", mutate: func(m *g3Measurements) { m.pathWriters = 1 }, wantInvalid: "paths carrying frames"},
		{name: "missing wire evidence", mutate: func(m *g3Measurements) { m.wireWrites = 999 }, wantInvalid: "wire write delta"},
		{name: "migration rejected", mutate: func(m *g3Measurements) { m.migrationErrors = 1 }, wantFailure: "rejected=1"},
		{name: "migration not observed", mutate: func(m *g3Measurements) { m.migrationsObserved = 2 }, wantFailure: "MigrationCount=2"},
		{name: "corrupt packet", mutate: func(m *g3Measurements) { m.corruptPackets = 1 }, wantFailure: "integrity failures"},
		{name: "duplicate packet", mutate: func(m *g3Measurements) { m.duplicatePackets = 1 }, wantFailure: "duplicate application"},
		{name: "strict packet loss", mutate: func(m *g3Measurements) { m.received = 999 }, wantFailure: "exceeds budget"},
		{name: "latency ceiling", mutate: func(m *g3Measurements) { m.p95 = 51 * time.Millisecond }, wantFailure: "exceeds ceiling"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := valid
			tt.mutate(&got)
			invalid, failure := validateG3Measurements(opts, got)
			if !strings.Contains(invalid, tt.wantInvalid) {
				t.Fatalf("invalid=%q want substring %q", invalid, tt.wantInvalid)
			}
			if !strings.Contains(failure, tt.wantFailure) {
				t.Fatalf("failure=%q want substring %q", failure, tt.wantFailure)
			}
			if tt.wantInvalid != "" && failure != "" {
				t.Fatalf("invalid evidence also classified as product failure: %q", failure)
			}
			if tt.wantFailure != "" && invalid != "" {
				t.Fatalf("product failure also classified as invalid: %q", invalid)
			}
		})
	}

	if invalid, failure := validateG3Measurements(opts, valid); invalid != "" || failure != "" {
		t.Fatalf("valid evidence rejected: invalid=%q failure=%q", invalid, failure)
	}
}

func TestValidateG3MeasurementsHonorsExplicitSmokeLossBudget(t *testing.T) {
	opts := G3Opts{PPS: 1000, Migrations: 1, Paths: 2, P95CeilingMs: 50, LossPct: 0.5}
	m := g3Measurements{
		sent:               1000,
		received:           999,
		sendElapsed:        time.Second,
		latencySamples:     20,
		p95:                time.Millisecond,
		migrationAttempts:  1,
		migrationsObserved: 1,
		pathWriters:        2,
		wireWrites:         1000,
	}
	if invalid, failure := validateG3Measurements(opts, m); invalid != "" || failure != "" {
		t.Fatalf("explicit 0.5%% smoke budget rejected: invalid=%q failure=%q", invalid, failure)
	}
}

func TestSummarizeG3MissingReportsRangesAndMigrationDistance(t *testing.T) {
	bitmap := []uint8{1, 1, 0, 0, 1, 0, 1, 1, 0, 0}
	got := summarizeG3Missing(bitmap, 12, []int64{4, 9}, 100)
	if got.Count != 7 || got.RangeCount != 3 || got.RangeSample != "2-3,5,8-11" {
		t.Fatalf("summary = %+v", got)
	}
	if got.SampleTruncated || got.NearestMigrationDistancePackets != 0 ||
		got.NearMigrationPackets != 5 || got.NearMigrationWindowPackets != 1 {
		t.Fatalf("migration correlation = %+v", got)
	}
}

func TestSummarizeG3MissingBoundsRangeEvidence(t *testing.T) {
	bitmap := make([]uint8, g3MissingRangeSampleLimit*2+1)
	for i := 1; i < len(bitmap); i += 2 {
		bitmap[i] = 1
	}
	got := summarizeG3Missing(bitmap, int64(len(bitmap)), nil, 100_000)
	if !got.SampleTruncated || got.RangeCount <= g3MissingRangeSampleLimit {
		t.Fatalf("summary = %+v", got)
	}
	if strings.Count(got.RangeSample, ",") != g3MissingRangeSampleLimit-1 {
		t.Fatalf("range sample = %q", got.RangeSample)
	}
	if got.NearestMigrationDistancePackets != -1 || got.NearMigrationPackets != 0 {
		t.Fatalf("unexpected migration evidence = %+v", got)
	}
}

func TestParseAndDeltaG3HostUDPStats(t *testing.T) {
	const fixture = `Ip: Forwarding DefaultTTL
Ip: 1 64
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors
Udp: 100 2 7 110 5 1 0 3 2
UdpLite: InDatagrams NoPorts
UdpLite: 0 0
`
	before, err := parseG3HostUDPStats(strings.NewReader(fixture))
	if err != nil {
		t.Fatal(err)
	}
	after := before
	after.InDatagrams += 10
	after.OutDatagrams += 12
	after.InErrors += 3
	after.RcvbufErrors += 2
	after.SndbufErrors++
	delta, err := deltaG3HostUDPStats(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if delta.InDatagrams != 10 || delta.OutDatagrams != 12 || delta.InErrors != 3 ||
		delta.RcvbufErrors != 2 || delta.SndbufErrors != 1 {
		t.Fatalf("delta = %+v", delta)
	}
}

func TestParseG3HostUDPStatsRejectsMalformedEvidence(t *testing.T) {
	tests := []string{
		"Tcp: A B\nTcp: 1 2\n",
		"Udp: InDatagrams OutDatagrams\nUdp: 1\n",
		"Udp: InDatagrams\nUdp: nope\n",
	}
	for _, fixture := range tests {
		if _, err := parseG3HostUDPStats(strings.NewReader(fixture)); err == nil {
			t.Fatalf("fixture %q unexpectedly parsed", fixture)
		}
	}
	before := g3HostUDPStats{InDatagrams: 2}
	if _, err := deltaG3HostUDPStats(before, g3HostUDPStats{InDatagrams: 1}); err == nil {
		t.Fatal("decreasing counters unexpectedly accepted")
	}
}
