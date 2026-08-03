package tunfull

import (
	"strings"
	"testing"
	"time"
)

func testValidateTUNG3MeasurementsFailsClosed(t *testing.T) {
	opts := g3Options{
		pps: 1000, duration: time.Second, payloadLen: 1024,
		paths: 4, migrations: 3, lossPct: 0, p95Ceiling: 50 * time.Millisecond,
	}
	valid := tunG3Measurements{
		sent: 1000, received: 1000, sendElapsed: time.Second,
		latencySamples: 20, p95: 10 * time.Millisecond,
		migrationAttempts: 3, migrationsObserved: 3,
		perPathWrites: map[uint32]uint64{1: 250, 2: 250, 3: 250, 4: 250},
		wireWrites:    1000,
	}
	tests := []struct {
		name        string
		mutate      func(*tunG3Measurements)
		wantInvalid string
		wantFailure string
	}{
		{name: "no packets", mutate: func(m *tunG3Measurements) { m.sent = 0 }, wantInvalid: "no packets"},
		{name: "under offered load", mutate: func(m *tunG3Measurements) { m.sendElapsed = 2 * time.Second }, wantInvalid: "offered load"},
		{name: "no samples", mutate: func(m *tunG3Measurements) { m.latencySamples = 0 }, wantInvalid: "latency samples"},
		{name: "missing migration stimulus", mutate: func(m *tunG3Measurements) { m.migrationAttempts = 2 }, wantInvalid: "attempts=2"},
		{name: "missing path evidence", mutate: func(m *tunG3Measurements) { delete(m.perPathWrites, 4) }, wantInvalid: "covers 3 paths"},
		{name: "idle path", mutate: func(m *tunG3Measurements) { m.perPathWrites[4] = 0 }, wantInvalid: "below minimum measured wire writes"},
		{name: "insufficient wire writes", mutate: func(m *tunG3Measurements) { m.wireWrites = 999 }, wantInvalid: "wire write delta"},
		{name: "migration rejected", mutate: func(m *tunG3Measurements) { m.migrationErrors = 1 }, wantFailure: "rejected=1"},
		{name: "migration not observed exactly", mutate: func(m *tunG3Measurements) { m.migrationsObserved = 2 }, wantFailure: "want exactly 3"},
		{name: "corrupt packet", mutate: func(m *tunG3Measurements) { m.corruptPackets = 1 }, wantFailure: "integrity failures"},
		{name: "duplicate packet", mutate: func(m *tunG3Measurements) { m.duplicatePackets = 1 }, wantFailure: "duplicate application"},
		{name: "explicit zero loss", mutate: func(m *tunG3Measurements) { m.received = 999 }, wantFailure: "exceeds budget 0.000%"},
		{name: "latency ceiling", mutate: func(m *tunG3Measurements) { m.p95 = 51 * time.Millisecond }, wantFailure: "exceeds ceiling"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := valid
			got.perPathWrites = clonePathWrites(valid.perPathWrites)
			tt.mutate(&got)
			invalid, failure := validateTUNG3Measurements(opts, got)
			if !strings.Contains(invalid, tt.wantInvalid) {
				t.Fatalf("invalid=%q want substring %q", invalid, tt.wantInvalid)
			}
			if !strings.Contains(failure, tt.wantFailure) {
				t.Fatalf("failure=%q want substring %q", failure, tt.wantFailure)
			}
			if tt.wantInvalid != "" && failure != "" {
				t.Fatalf("invalid evidence also classified as failure: %q", failure)
			}
			if tt.wantFailure != "" && invalid != "" {
				t.Fatalf("product failure also classified as invalid: %q", invalid)
			}
		})
	}
	if invalid, failure := validateTUNG3Measurements(opts, valid); invalid != "" || failure != "" {
		t.Fatalf("valid evidence rejected: invalid=%q failure=%q", invalid, failure)
	}
}

func testValidateTUNG3MeasurementsHonorsOnlyExplicitLossBudget(t *testing.T) {
	opts := g3Options{pps: 1000, paths: 2, migrations: 1, lossPct: 0.5, p95Ceiling: 50 * time.Millisecond}
	m := tunG3Measurements{
		sent: 1000, received: 999, sendElapsed: time.Second,
		latencySamples: 20, p95: time.Millisecond,
		migrationAttempts: 1, migrationsObserved: 1,
		perPathWrites: map[uint32]uint64{1: 500, 2: 500}, wireWrites: 1000,
	}
	if invalid, failure := validateTUNG3Measurements(opts, m); invalid != "" || failure != "" {
		t.Fatalf("explicit 0.5%% budget rejected: invalid=%q failure=%q", invalid, failure)
	}
}

func testFormatTUNG3PathWritesIsDeterministic(t *testing.T) {
	if got := formatTUNG3PathWrites(map[uint32]uint64{9: 3, 2: 7, 5: 1}); got != "2:7,5:1,9:3" {
		t.Fatalf("format=%q", got)
	}
}

func clonePathWrites(source map[uint32]uint64) map[uint32]uint64 {
	result := make(map[uint32]uint64, len(source))
	for id, writes := range source {
		result[id] = writes
	}
	return result
}
