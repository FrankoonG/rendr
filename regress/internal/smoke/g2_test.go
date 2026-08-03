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
		observedDuration:  10 * time.Second,
		interval:          100 * time.Millisecond,
		planned:           100,
		scheduled:         100,
		writeCompleted:    100,
		received:          100,
	}
}

func checkValidateG2RunEvidence(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(*g2RunEvidence)
		wantInvalid string
		wantFailure string
	}{
		{name: "exact valid evidence"},
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
				e.observedDuration = e.requestedDuration - time.Nanosecond
			},
			wantInvalid: "run duration",
		},
		{
			name: "planned schedule mismatch",
			mutate: func(e *g2RunEvidence) {
				e.planned = 99
				e.scheduled = 99
				e.writeCompleted = 99
				e.received = 99
			},
			wantInvalid: "planned echo slots=99",
		},
		{
			name: "write completion deficit",
			mutate: func(e *g2RunEvidence) {
				e.writeCompleted = 99
				e.received = 99
			},
			wantFailure: "write-completed echoes=99",
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

func TestG2PlanUsesExactHalfOpenSlots(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	tests := []struct {
		name     string
		duration time.Duration
		interval time.Duration
		want     []time.Duration
	}{
		{name: "exact multiple", duration: 300 * time.Millisecond, interval: 100 * time.Millisecond, want: []time.Duration{0, 100 * time.Millisecond, 200 * time.Millisecond}},
		{name: "partial final interval", duration: 250 * time.Millisecond, interval: 100 * time.Millisecond, want: []time.Duration{0, 100 * time.Millisecond, 200 * time.Millisecond}},
		{name: "shorter than cadence", duration: 50 * time.Millisecond, interval: 100 * time.Millisecond, want: []time.Duration{0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheduler := newG2SlotScheduler(start, tt.duration, tt.interval)
			requests := make(chan g2WriteRequest, len(tt.want))
			scheduler.offerDue(start.Add(tt.duration), requests)
			close(requests)

			var got []time.Duration
			for request := range requests {
				got = append(got, request.plannedAt.Sub(start))
			}
			if len(got) != len(tt.want) {
				t.Fatalf("planned slots = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("planned slots = %v, want %v", got, tt.want)
				}
			}
			if !scheduler.start.Equal(start) || got[0] != 0 {
				t.Fatalf("first slot = %s after start, want 0", got[0])
			}
			if last := got[len(got)-1]; last >= tt.duration {
				t.Fatalf("last slot = %s, want before endpoint %s", last, tt.duration)
			}
		})
	}
}

func TestValidateG2RunEvidenceRejectsUnofferedSlots(t *testing.T) {
	evidence := validG2RunEvidence()
	evidence.scheduled--
	evidence.unoffered = 1
	evidence.writeCompleted--
	evidence.received--

	invalidReason, failure := validateG2RunEvidence(evidence)
	if !strings.Contains(invalidReason, "unoffered echo slots=1") || failure != "" {
		t.Fatalf("invalid=%q failure=%q, want explicit unoffered-slot invalidity", invalidReason, failure)
	}
}

func TestValidateG2RunEvidenceRejectsTransportLoss(t *testing.T) {
	evidence := validG2RunEvidence()
	evidence.received--
	evidence.transportLost = 1

	invalidReason, failure := validateG2RunEvidence(evidence)
	if invalidReason != "" || !strings.Contains(failure, "transport-lost echoes=1") {
		t.Fatalf("invalid=%q failure=%q, want explicit transport loss", invalidReason, failure)
	}
}

func TestValidateG2LatencyUsesStrictDurationBoundary(t *testing.T) {
	ceiling := 200 * time.Millisecond
	p99Qualified, _, failure := validateG2Latency(g2P99MinimumSamples, ceiling-time.Nanosecond, 0, ceiling)
	if !p99Qualified || failure != "" {
		t.Fatalf("ceiling - 1ns qualified=%v failure=%q, want qualified pass", p99Qualified, failure)
	}

	p99Qualified, _, failure = validateG2Latency(g2P99MinimumSamples, ceiling, 0, ceiling)
	if !p99Qualified || !strings.Contains(failure, "strict ceiling") {
		t.Fatalf("exact ceiling qualified=%v failure=%q, want strict failure", p99Qualified, failure)
	}
}

func TestG2ShortRunKeepsP99DiagnosticOnly(t *testing.T) {
	p99Qualified, p999Qualified, failure := validateG2Latency(
		g2P99MinimumSamples-1,
		10*time.Second,
		10*time.Second,
		200*time.Millisecond,
	)
	if p99Qualified || p999Qualified || failure != "" {
		t.Fatalf("short-run qualification=(%v,%v) failure=%q, want diagnostic-only evidence", p99Qualified, p999Qualified, failure)
	}
}

func TestG2SenderStallDoesNotBlockEndpointEvaluator(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	scheduler := newG2SlotScheduler(start, 350*time.Millisecond, 100*time.Millisecond)
	requests := make(chan g2WriteRequest, 1)

	// The first request remains queued, deterministically modelling a sender
	// that cannot accept more work. Endpoint evaluation must still account for
	// every later slot without blocking behind it.
	scheduler.offerDue(start, requests)
	scheduler.offerDue(start.Add(350*time.Millisecond), requests)

	if scheduler.next != 4 || scheduler.scheduled != 1 || scheduler.unoffered() != 3 {
		t.Fatalf("endpoint evidence planned=%d evaluated=%d scheduled=%d unoffered=%d, want 4/4/1/3",
			scheduler.planned, scheduler.next, scheduler.scheduled, scheduler.unoffered())
	}
	_, _, _, maxLateness := g2DurationStats(scheduler.latenesses)
	if maxLateness != 250*time.Millisecond {
		t.Fatalf("max schedule lateness=%s, want 250ms", maxLateness)
	}

	invalidReason, failure := validateG2RunEvidence(g2RunEvidence{
		requestedDuration: 350 * time.Millisecond,
		observedDuration:  350 * time.Millisecond,
		interval:          100 * time.Millisecond,
		planned:           scheduler.planned,
		scheduled:         scheduler.scheduled,
		unoffered:         scheduler.unoffered(),
	})
	if !strings.Contains(invalidReason, "unoffered echo slots=3") || failure != "" {
		t.Fatalf("invalid=%q failure=%q, want stalled sender to invalidate exact load", invalidReason, failure)
	}
}

func TestRunG2ShortRunReportsExactSchedule(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := RunG2(ctx, G2Opts{
		Duration:   500 * time.Millisecond,
		Interval:   100 * time.Millisecond,
		Migrations: 1,
		Paths:      2,
		Transport:  "tcp",
		Mode:       rendr.ModePrime,
	})
	if result.InvalidReason != "" || result.Failure != "" {
		t.Fatalf("short G2 invalid=%q failure=%q detail=%v", result.InvalidReason, result.Failure, result.Detail)
	}
	for key, want := range map[string]any{
		"planned_echoes":         5,
		"scheduled_echoes":       5,
		"write_completed_echoes": 5,
		"received_echoes":        5,
		"unoffered_echoes":       0,
		"transport_lost_echoes":  0,
		"p99_qualified":          false,
		"latency_evidence":       "diagnostic",
	} {
		if got := result.Detail[key]; got != want {
			t.Errorf("detail[%q]=%v (%T), want %v (%T)", key, got, got, want, want)
		}
	}
	for _, key := range []string{"blackout_ms", "schedule_lateness_max_ms", "write_start_lateness_max_ms"} {
		if _, ok := result.Detail[key]; !ok {
			t.Errorf("detail missing %q: %v", key, result.Detail)
		}
	}
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
