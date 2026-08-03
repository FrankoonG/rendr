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
