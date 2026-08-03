package smoke

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/FrankoonG/rendr"
)

type g2TimeoutError struct{}

func (g2TimeoutError) Error() string   { return "deadline exceeded" }
func (g2TimeoutError) Timeout() bool   { return true }
func (g2TimeoutError) Temporary() bool { return true }

func validG2RunEvidence() g2RunEvidence {
	return g2RunEvidence{
		requestedDuration: 10 * time.Second,
		observedDuration:  9500 * time.Millisecond,
		interval:          100 * time.Millisecond,
		sent:              95,
		received:          95,
	}
}

func checkValidateG2RunEvidence(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(*g2RunEvidence)
		wantInvalid string
		wantFailure string
	}{
		{name: "minimum valid evidence"},
		{
			name: "context cancellation",
			mutate: func(e *g2RunEvidence) {
				e.contextErr = context.Canceled
			},
			wantInvalid: "context canceled",
		},
		{
			name: "duration truncated",
			mutate: func(e *g2RunEvidence) {
				e.observedDuration = 9499 * time.Millisecond
			},
			wantInvalid: "run duration",
		},
		{
			name: "sender and receiver truncated equally",
			mutate: func(e *g2RunEvidence) {
				e.sent = 10
				e.received = 10
			},
			wantInvalid: "offered echo samples=10",
		},
		{
			name: "receiver below expected schedule",
			mutate: func(e *g2RunEvidence) {
				e.received = 94
			},
			wantFailure: "received echo samples=94",
		},
		{
			name: "sender operation error",
			mutate: func(e *g2RunEvidence) {
				e.operationErr = errors.New("write failed")
			},
			wantFailure: "write failed",
		},
		{
			name: "receiver error",
			mutate: func(e *g2RunEvidence) {
				e.receiverErr = errors.New("read failed")
			},
			wantFailure: "receiver exited before clean teardown: read failed",
		},
		{
			name: "server error",
			mutate: func(e *g2RunEvidence) {
				e.serverErr = errors.New("echo failed")
			},
			wantFailure: "server echo exited before clean teardown: echo failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evidence := validG2RunEvidence()
			if tt.mutate != nil {
				tt.mutate(&evidence)
			}
			invalidReason, failure := validateG2RunEvidence(evidence)
			if !strings.Contains(invalidReason, tt.wantInvalid) {
				t.Fatalf("invalid reason = %q, want substring %q", invalidReason, tt.wantInvalid)
			}
			if !strings.Contains(failure, tt.wantFailure) {
				t.Fatalf("failure = %q, want substring %q", failure, tt.wantFailure)
			}
		})
	}
}

func checkMinimumG2EvidenceRoundsUp(t *testing.T) {
	for input, want := range map[int]int{0: 0, 1: 1, 10: 10, 20: 19, 100: 95} {
		if got := minimumG2Evidence(input); got != want {
			t.Errorf("minimumG2Evidence(%d)=%d, want %d", input, got, want)
		}
	}
}

func checkG2IntentionalTeardownErrors(t *testing.T) {
	for _, err := range []error{
		io.EOF,
		io.ErrUnexpectedEOF,
		net.ErrClosed,
		fmt.Errorf("wrapped: %w", g2TimeoutError{}),
	} {
		if !isG2IntentionalTeardownError(err) {
			t.Errorf("error %v should be accepted during intentional teardown", err)
		}
	}
	for _, err := range []error{nil, context.Canceled, errors.New("transport reset")} {
		if isG2IntentionalTeardownError(err) {
			t.Errorf("error %v should not be accepted during intentional teardown", err)
		}
	}
}

func TestValidateG2EvidenceRejectsPartialMigrationStimulus(t *testing.T) {
	t.Run("run duration, samples, and errors", checkValidateG2RunEvidence)
	t.Run("minimum evidence rounding", checkMinimumG2EvidenceRoundsUp)
	t.Run("intentional teardown errors", checkG2IntentionalTeardownErrors)
	t.Run("partial migration schedule", func(t *testing.T) {
		_, _, err := validateG2Evidence(g2Evidence{
			mode:                 rendr.ModePrime,
			migrationsRequested:  5,
			migrationCallsFired:  1,
			migrationCountBefore: 20,
			migrationCountAfter:  21,
		})
		if err == nil || !strings.Contains(err.Error(), "fired=1, want 5") {
			t.Fatalf("error = %v, want partial-stimulus failure", err)
		}
	})
}

func TestValidateG2EvidenceRaceDuplicateSemantics(t *testing.T) {
	base := g2Evidence{
		mode:                 rendr.ModeRace,
		migrationsRequested:  0,
		migrationCallsFired:  0,
		migrationCountBefore: 20,
		migrationCountAfter:  20,
		recvDupsBefore:       4,
		recvDupsAfter:        5,
	}
	if migrations, duplicates, err := validateG2Evidence(base); err != nil || migrations != 0 || duplicates != 1 {
		t.Fatalf("valid race evidence = migrations %d duplicates %d err %v", migrations, duplicates, err)
	}

	missingStimulus := base
	missingStimulus.recvDupsAfter = missingStimulus.recvDupsBefore
	if _, _, err := validateG2Evidence(missingStimulus); err == nil || !strings.Contains(err.Error(), "duplicate stimulus was not observed") {
		t.Fatalf("missing duplicate stimulus error = %v", err)
	}

	visibleDuplicate := base
	visibleDuplicate.applicationDuplicates = 1
	if _, _, err := validateG2Evidence(visibleDuplicate); err == nil || !strings.Contains(err.Error(), "application-visible duplicate") {
		t.Fatalf("application duplicate error = %v", err)
	}
}

func TestG2OptsMigrationDefaultAndDisable(t *testing.T) {
	defaults := G2Opts{}
	defaults.withDefaults()
	if defaults.Migrations != 5 {
		t.Fatalf("default migrations=%d want 5", defaults.Migrations)
	}
	disabled := G2Opts{Migrations: -1}
	disabled.withDefaults()
	if disabled.Migrations != 0 {
		t.Fatalf("disabled migrations=%d want 0", disabled.Migrations)
	}
}
