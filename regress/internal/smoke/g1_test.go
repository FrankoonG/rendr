package smoke

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"
)

func TestValidateRequestedMigrations(t *testing.T) {
	tests := []struct {
		name      string
		requested int
		fired     int
		before    uint64
		after     uint64
		want      uint64
		wantErr   string
	}{
		{name: "all requested observed", requested: 3, fired: 3, before: 7, after: 10, want: 3},
		{name: "independent extra migration", requested: 3, fired: 3, before: 7, after: 11, want: 4},
		{name: "zero explicitly allowed", requested: 0, fired: 0, before: 7, after: 7},
		{name: "old one-of-many false green", requested: 3, fired: 1, before: 7, after: 8, wantErr: "fired=1, want 3"},
		{name: "calls not reflected by counter", requested: 3, fired: 3, before: 7, after: 8, want: 1, wantErr: "advanced=1, want at least 3"},
		{name: "counter regression", requested: 1, fired: 1, before: 7, after: 6, wantErr: "counter regressed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateRequestedMigrations(tt.requested, tt.fired, tt.before, tt.after)
			if got != tt.want {
				t.Fatalf("observed migrations = %d, want %d", got, tt.want)
			}
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestG1OptsMigrationDefaultAndDisable(t *testing.T) {
	defaults := G1Opts{}
	defaults.withDefaults()
	if defaults.Migrations != 3 {
		t.Fatalf("default migrations=%d want 3", defaults.Migrations)
	}
	disabled := G1Opts{Migrations: -1}
	disabled.withDefaults()
	if disabled.Migrations != 0 {
		t.Fatalf("disabled migrations=%d want 0", disabled.Migrations)
	}
}

func TestFillG1PatternIsPositionStableAndNotChunkPeriodic(t *testing.T) {
	whole := make([]byte, 8192)
	fillG1Pattern(whole, 0)
	segmented := make([]byte, len(whole))
	fillG1Pattern(segmented[:137], 0)
	fillG1Pattern(segmented[137:4099], 137)
	fillG1Pattern(segmented[4099:], 4099)
	if !bytes.Equal(whole, segmented) {
		t.Fatal("pattern depends on caller chunk boundaries")
	}
	other := make([]byte, len(whole))
	fillG1Pattern(other, 256<<10)
	if bytes.Equal(whole, other) {
		t.Fatal("pattern repeats at the former 256-byte/chunk-aligned period")
	}
}

func TestVerifyNoTrailingPayload(t *testing.T) {
	reader, writer := net.Pipe()
	defer reader.Close()
	defer writer.Close()
	if err := verifyNoTrailingPayload(reader, 5*time.Millisecond); err != nil {
		t.Fatalf("quiet connection: %v", err)
	}

	reader, writer = net.Pipe()
	defer reader.Close()
	defer writer.Close()
	go func() { _, _ = writer.Write([]byte{1}) }()
	if err := verifyNoTrailingPayload(reader, time.Second); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("extra payload error=%v", err)
	}
}
