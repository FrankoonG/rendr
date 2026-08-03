package smoke

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/FrankoonG/rendr"
)

func TestValidateG4EvidenceNegativeControls(t *testing.T) {
	killAt := time.Unix(100, 0)
	postKill := killAt.Add(25 * time.Millisecond)
	tests := []struct {
		name     string
		killErr  error
		killAt   time.Time
		postKill time.Time
		samples  int
		budget   time.Duration
		wantErr  string
	}{
		{name: "kill error", killErr: errors.New("injected"), killAt: killAt, postKill: postKill, samples: 1, budget: time.Second, wantErr: "kill stimulus failed"},
		{name: "missing kill timestamp", postKill: postKill, samples: 1, budget: time.Second, wantErr: "kill stimulus timestamp"},
		{name: "missing post-kill timestamp", killAt: killAt, samples: 1, budget: time.Second, wantErr: "post-kill delivery timestamp"},
		{name: "missing post-kill samples", killAt: killAt, postKill: postKill, budget: time.Second, wantErr: "samples=0"},
		{name: "uninitialized zero", budget: time.Second, wantErr: "kill stimulus timestamp"},
		{name: "timestamp order", killAt: postKill, postKill: killAt, samples: 1, budget: time.Second, wantErr: "precedes kill"},
		{name: "budget exceeded", killAt: killAt, postKill: postKill, samples: 1, budget: time.Millisecond, wantErr: "exceeds"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateG4Evidence(tt.killErr, tt.killAt, tt.postKill, tt.samples, tt.budget)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateG4EvidenceAllowsMeasuredSubMillisecondFailover(t *testing.T) {
	stamp := time.Unix(100, 0)
	got, err := validateG4Evidence(nil, stamp, stamp, 1, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got != 0 {
		t.Fatalf("failover = %s, want 0", got)
	}
}

func TestValidateG5PayloadRejectsMismatch(t *testing.T) {
	err := validateG5Payload(100, []byte{1, 2, 3}, []byte{1, 9, 3})
	if err == nil || !strings.Contains(err.Error(), "offset 101") {
		t.Fatalf("error = %v, want byte mismatch at offset 101", err)
	}
	if err := validateG5Payload(100, []byte{1, 2, 3}, []byte{1, 2, 3}); err != nil {
		t.Fatalf("matching payload rejected: %v", err)
	}
}

func TestValidateRecoveredPathProgressNegativeControl(t *testing.T) {
	now := time.Unix(100, 0)
	before := rendr.PathInfo{ID: 7, Writes: 10, LastSendAt: now}
	after := rendr.PathInfo{ID: 7, Writes: 10, LastSendAt: now}
	if err := validateRecoveredPathProgress(7, 7, before, after); err == nil || !strings.Contains(err.Error(), "writes did not advance") {
		t.Fatalf("unchanged path progress error = %v", err)
	}

	after.Writes = 11
	after.LastSendAt = now.Add(time.Millisecond)
	if err := validateRecoveredPathProgress(7, 6, before, after); err == nil || !strings.Contains(err.Error(), "active path") {
		t.Fatalf("wrong active path error = %v", err)
	}
	if err := validateRecoveredPathProgress(7, 7, before, after); err != nil {
		t.Fatalf("valid recovered path progress rejected: %v", err)
	}
}
