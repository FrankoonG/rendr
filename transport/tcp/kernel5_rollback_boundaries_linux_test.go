//go:build linux && amd64 && rendr_experimental_tcprepair

package tcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/FrankoonG/rendr/internal/tcpquarantine"
	"github.com/FrankoonG/rendr/internal/tcprepair"
)

const (
	kernel5TCPRepairRollbackBoundaryEvidenceEnvironment = "RENDR_KERNEL5_TCP_REPAIR_ROLLBACK_BOUNDARY_EVIDENCE"
	kernel5TCPRepairRollbackBoundaryEvidenceSchema      = "kernel5-tcprepair-rollback-boundaries-v1"
)

type kernel5TCPRollbackBoundaryRecord struct {
	Boundary                string   `json:"boundary"`
	Fault                   string   `json:"fault"`
	Driver                  string   `json:"driver"`
	DependencyMode          string   `json:"dependency_mode"`
	TransactionID           string   `json:"transaction_id"`
	TransactionObservations int      `json:"transaction_observations"`
	TransactionMismatches   int      `json:"transaction_mismatches"`
	FaultObserved           bool     `json:"fault_observed"`
	QuarantineInstalls      int      `json:"quarantine_installs"`
	QuarantineReleases      int      `json:"quarantine_releases"`
	QuarantineActive        bool     `json:"quarantine_active"`
	InitialGeneration       uint64   `json:"initial_generation"`
	FinalGeneration         uint64   `json:"final_generation"`
	FinalStage              string   `json:"final_stage"`
	EndpointChanged         bool     `json:"endpoint_changed"`
	EndpointAvailable       bool     `json:"endpoint_available"`
	EndpointTerminal        bool     `json:"endpoint_terminal"`
	BidirectionalSocketIO   bool     `json:"bidirectional_socket_io"`
	ExpectedTerminalOutcome bool     `json:"expected_terminal_outcome"`
	OutcomeVerified         bool     `json:"outcome_verified"`
	Trace                   []string `json:"trace"`
	TraceSHA256             string   `json:"trace_sha256"`
}

type kernel5TCPRollbackBoundaryEvidence struct {
	Schema           string                             `json:"schema"`
	InvocationNonce  string                             `json:"invocation_nonce"`
	NetworkNamespace string                             `json:"network_namespace"`
	TestName         string                             `json:"test_name"`
	Records          []kernel5TCPRollbackBoundaryRecord `json:"records"`
}

func TestKernel5TCPRepairRollbackFaultBoundaryEvidence(t *testing.T) {
	binding, enabled, err := loadKernel5TCPEvidenceBinding(kernel5TCPRepairRollbackBoundaryEvidenceEnvironment)
	if err != nil {
		t.Fatal(err)
	}

	scenarios := []struct {
		name string
		run  func(*testing.T) kernel5TCPRollbackBoundaryRecord
	}{
		{name: "prepare", run: runKernel5RollbackPrepareBoundary},
		{name: "stage", run: runKernel5RollbackStageBoundary},
		{name: "restore", run: runKernel5RollbackRestoreBoundary},
		{name: "publish", run: runKernel5RollbackPublishBoundary},
		{name: "rollback", run: runKernel5RollbackRetryBoundary},
		{name: "activate", run: runKernel5RollbackActivateBoundary},
		{name: "fail_closed", run: runKernel5RollbackFailClosedBoundary},
	}
	records := make([]kernel5TCPRollbackBoundaryRecord, 0, len(scenarios))
	for _, scenario := range scenarios {
		var record kernel5TCPRollbackBoundaryRecord
		if t.Run(scenario.name, func(t *testing.T) {
			record = scenario.run(t)
		}) {
			records = append(records, record)
		}
	}
	if len(records) != len(scenarios) || !enabled {
		return
	}
	evidence := kernel5TCPRollbackBoundaryEvidence{
		Schema: kernel5TCPRepairRollbackBoundaryEvidenceSchema, InvocationNonce: binding.nonce,
		NetworkNamespace: binding.netns, TestName: "TestKernel5TCPRepairRollbackFaultBoundaryEvidence",
		Records: records,
	}
	if err := validateKernel5TCPRollbackBoundaryEvidence(evidence); err != nil {
		t.Fatalf("rollback boundary evidence is invalid: %v", err)
	}
	if err := writeKernel5TCPStrictJSON(binding.path, evidence, func(decoded *kernel5TCPRollbackBoundaryEvidence) error {
		return validateKernel5TCPRollbackBoundaryEvidence(*decoded)
	}); err != nil {
		t.Fatalf("write rollback boundary evidence: %v", err)
	}
}

func runKernel5RollbackPrepareBoundary(t *testing.T) kernel5TCPRollbackBoundaryRecord {
	fault := errors.New("injected quarantine install failure")
	fixture := newRepairDriverFixture(t)
	record := newKernel5TCPRollbackBoundaryRecord("prepare", "quarantine_install_partial_lease", fixture)
	bindKernel5RollbackTransaction(&record, fixture, func(
		context.Context, tcpquarantine.TransactionID, tcpquarantine.Tuple,
	) (quarantineLease, error) {
		return fixture.lease, fault
	})
	if err := fixture.attempt.Prepare(context.Background(), fixture.request); !errors.Is(err, fault) {
		t.Fatalf("Prepare=%v, want injected install failure", err)
	}
	record.FaultObserved = true
	if err := fixture.attempt.Rollback(context.Background(), fixture.request); err != nil {
		t.Fatalf("Rollback after failed Prepare: %v", err)
	}
	assertRepairPathRoundTrip(t, fixture.path, fixture.peer)
	record.BidirectionalSocketIO = true
	return finishKernel5TCPRollbackBoundary(t, record, fixture, false)
}

func runKernel5RollbackStageBoundary(t *testing.T) kernel5TCPRollbackBoundaryRecord {
	fault := errors.New("injected capture failure")
	fixture := newRepairDriverFixture(t)
	record := newKernel5TCPRollbackBoundaryRecord("stage", "capture_failure", fixture)
	bindKernel5RollbackTransaction(&record, fixture, fixture.manager.installFn)
	fixture.kernel.captureFn = func(conn *net.TCPConn) (repairSource, error) {
		return &fakeRepairSource{trace: fixture.trace, conn: conn, state: tcprepair.SourceStateNormal}, fault
	}
	if err := fixture.attempt.Prepare(context.Background(), fixture.request); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if _, err := fixture.attempt.Stage(context.Background(), fixture.request); !errors.Is(err, fault) {
		t.Fatalf("Stage=%v, want injected capture failure", err)
	}
	record.FaultObserved = true
	if err := fixture.attempt.Rollback(context.Background(), fixture.request); err != nil {
		t.Fatalf("Rollback after failed Stage: %v", err)
	}
	assertRepairPathRoundTrip(t, fixture.path, fixture.peer)
	record.BidirectionalSocketIO = true
	return finishKernel5TCPRollbackBoundary(t, record, fixture, false)
}

func runKernel5RollbackRestoreBoundary(t *testing.T) kernel5TCPRollbackBoundaryRecord {
	fault := errors.New("injected first restore failure")
	fixture := newRepairDriverFixture(t)
	record := newKernel5TCPRollbackBoundaryRecord("restore", "first_restore_failure", fixture)
	bindKernel5RollbackTransaction(&record, fixture, fixture.manager.installFn)
	replacement, replacementPeer := newRepairDriverTCPPair(t)
	restoreCalls := 0
	fixture.kernel.restoreFn = func(context.Context, *tcprepair.Snapshot) (*net.TCPConn, error) {
		restoreCalls++
		if restoreCalls == 1 {
			return nil, fault
		}
		return replacement, nil
	}
	if err := fixture.attempt.Prepare(context.Background(), fixture.request); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if _, err := fixture.attempt.Stage(context.Background(), fixture.request); !errors.Is(err, fault) {
		t.Fatalf("Stage=%v, want injected restore failure", err)
	}
	record.FaultObserved = true
	if err := fixture.attempt.Rollback(context.Background(), fixture.request); err != nil {
		t.Fatalf("Rollback from snapshot: %v", err)
	}
	if restoreCalls != 2 {
		t.Fatalf("restore calls=%d, want 2", restoreCalls)
	}
	assertRepairPathRoundTrip(t, fixture.path, replacementPeer)
	record.BidirectionalSocketIO = true
	return finishKernel5TCPRollbackBoundary(t, record, fixture, false)
}

func runKernel5RollbackPublishBoundary(t *testing.T) kernel5TCPRollbackBoundaryRecord {
	fixture := newRepairDriverFixture(t)
	record := newKernel5TCPRollbackBoundaryRecord("publish", "stale_endpoint_maintenance_lease", fixture)
	bindKernel5RollbackTransaction(&record, fixture, fixture.manager.installFn)
	_, replacementPeer := configurePrivateRepairReplacement(t, fixture)
	prepareAndStageRepairAttempt(t, fixture)
	fixture.path.endpoint.mu.Lock()
	fixture.path.endpoint.readActive = true
	fixture.path.endpoint.mu.Unlock()
	publishErr := fixture.attempt.Publish(context.Background(), fixture.request)
	fixture.path.endpoint.mu.Lock()
	fixture.path.endpoint.readActive = false
	fixture.path.endpoint.mu.Unlock()
	if !errors.Is(publishErr, errEndpointStaleLease) {
		t.Fatalf("Publish=%v, want stale maintenance lease", publishErr)
	}
	record.FaultObserved = true
	if err := fixture.attempt.Rollback(context.Background(), fixture.request); err != nil {
		t.Fatalf("Rollback after rejected Publish: %v", err)
	}
	assertRepairPathRoundTrip(t, fixture.path, replacementPeer)
	record.BidirectionalSocketIO = true
	return finishKernel5TCPRollbackBoundary(t, record, fixture, false)
}

func runKernel5RollbackRetryBoundary(t *testing.T) kernel5TCPRollbackBoundaryRecord {
	fault := errors.New("injected first quarantine release failure")
	fixture := newRepairDriverFixture(t)
	record := newKernel5TCPRollbackBoundaryRecord("rollback", "quarantine_release_retry", fixture)
	bindKernel5RollbackTransaction(&record, fixture, fixture.manager.installFn)
	_, replacementPeer := configurePrivateRepairReplacement(t, fixture)
	fixture.lease.releaseFn = func(_ context.Context, call int) error {
		if call == 1 {
			return fault
		}
		return nil
	}
	prepareAndStageRepairAttempt(t, fixture)
	if err := fixture.attempt.Rollback(context.Background(), fixture.request); !errors.Is(err, fault) {
		t.Fatalf("first Rollback=%v, want injected release failure", err)
	}
	record.FaultObserved = true
	if err := fixture.attempt.Rollback(context.Background(), fixture.request); err != nil {
		t.Fatalf("retry Rollback: %v", err)
	}
	assertRepairPathRoundTrip(t, fixture.path, replacementPeer)
	record.BidirectionalSocketIO = true
	return finishKernel5TCPRollbackBoundary(t, record, fixture, false)
}

func runKernel5RollbackActivateBoundary(t *testing.T) kernel5TCPRollbackBoundaryRecord {
	fault := errors.New("injected first activate release failure")
	fixture := newRepairDriverFixture(t)
	record := newKernel5TCPRollbackBoundaryRecord("activate", "activate_quarantine_release_retry", fixture)
	bindKernel5RollbackTransaction(&record, fixture, fixture.manager.installFn)
	_, replacementPeer := configurePrivateRepairReplacement(t, fixture)
	fixture.lease.releaseFn = func(_ context.Context, call int) error {
		if call == 1 {
			return fault
		}
		return nil
	}
	prepareAndStageRepairAttempt(t, fixture)
	if err := fixture.attempt.Publish(context.Background(), fixture.request); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if err := fixture.attempt.Activate(context.Background(), fixture.request); !errors.Is(err, fault) {
		t.Fatalf("first Activate=%v, want injected release failure", err)
	}
	record.FaultObserved = true
	if err := fixture.attempt.Activate(context.Background(), fixture.request); err != nil {
		t.Fatalf("retry Activate: %v", err)
	}
	assertRepairPathRoundTrip(t, fixture.path, replacementPeer)
	record.BidirectionalSocketIO = true
	return finishKernel5TCPRollbackBoundary(t, record, fixture, false)
}

func runKernel5RollbackFailClosedBoundary(t *testing.T) kernel5TCPRollbackBoundaryRecord {
	fault := errors.New("injected rollback release failure")
	fixture := newRepairDriverFixture(t)
	record := newKernel5TCPRollbackBoundaryRecord("fail_closed", "partial_rollback_release_failure", fixture)
	bindKernel5RollbackTransaction(&record, fixture, fixture.manager.installFn)
	configurePrivateRepairReplacement(t, fixture)
	fixture.lease.releaseFn = func(_ context.Context, call int) error {
		if call == 1 {
			return fault
		}
		return nil
	}
	prepareAndStageRepairAttempt(t, fixture)
	if err := fixture.attempt.Rollback(context.Background(), fixture.request); !errors.Is(err, fault) {
		t.Fatalf("Rollback=%v, want injected release failure", err)
	}
	record.FaultObserved = true
	if err := fixture.attempt.FailClosed(context.Background(), fixture.request); err != nil {
		t.Fatalf("FailClosed after partial rollback: %v", err)
	}
	record.ExpectedTerminalOutcome = true
	return finishKernel5TCPRollbackBoundary(t, record, fixture, true)
}

func newKernel5TCPRollbackBoundaryRecord(
	boundary, fault string,
	fixture *repairDriverFixture,
) kernel5TCPRollbackBoundaryRecord {
	_, generation, _, _ := repairEndpointState(fixture.path.endpoint)
	return kernel5TCPRollbackBoundaryRecord{
		Boundary: boundary, Fault: fault, Driver: "tcp_repair_attempt",
		DependencyMode:    "production_state_machine_with_injected_kernel_and_quarantine",
		TransactionID:     hex.EncodeToString(fixture.request.Plan.TransactionID[:]),
		InitialGeneration: generation,
	}
}

func bindKernel5RollbackTransaction(
	record *kernel5TCPRollbackBoundaryRecord,
	fixture *repairDriverFixture,
	delegate func(context.Context, tcpquarantine.TransactionID, tcpquarantine.Tuple) (quarantineLease, error),
) {
	expected := tcpquarantine.TransactionID(fixture.request.Plan.TransactionID)
	fixture.manager.installFn = func(
		ctx context.Context,
		transaction tcpquarantine.TransactionID,
		tuple tcpquarantine.Tuple,
	) (quarantineLease, error) {
		record.TransactionObservations++
		if transaction != expected {
			record.TransactionMismatches++
		}
		return delegate(ctx, transaction, tuple)
	}
}

func finishKernel5TCPRollbackBoundary(
	t *testing.T,
	record kernel5TCPRollbackBoundaryRecord,
	fixture *repairDriverFixture,
	wantTerminal bool,
) kernel5TCPRollbackBoundaryRecord {
	t.Helper()
	_, generation, _, terminal := repairEndpointState(fixture.path.endpoint)
	_, _, available := fixture.path.endpoint.current()
	record.FinalGeneration = generation
	record.FinalStage = kernel5TCPRepairAttemptStageName(fixture.attempt.stage)
	record.EndpointChanged = fixture.attempt.EndpointGenerationChanged()
	record.EndpointAvailable = available
	record.EndpointTerminal = terminal
	record.QuarantineActive = fixture.attempt.quarantine != nil || fixture.attempt.quarantineUnverified
	record.QuarantineReleases = fixture.lease.releaseCalls()
	record.Trace = fixture.trace.snapshot()
	record.QuarantineInstalls = countKernel5TCPRollbackEvents(record.Trace, "install")
	record.TraceSHA256 = kernel5TCPRollbackTraceDigest(record.Trace)
	record.OutcomeVerified = record.FaultObserved && record.TransactionObservations > 0 &&
		record.TransactionMismatches == 0 && record.QuarantineInstalls > 0 &&
		record.QuarantineReleases > 0 && !record.QuarantineActive &&
		terminal == wantTerminal && available != wantTerminal &&
		((wantTerminal && !record.BidirectionalSocketIO) || (!wantTerminal && record.BidirectionalSocketIO))
	if !record.OutcomeVerified {
		t.Fatalf("rollback boundary outcome is not verified: %+v", record)
	}
	return record
}

func kernel5TCPRepairAttemptStageName(stage repairAttemptStage) string {
	switch stage {
	case repairAttemptPreflight:
		return "preflight"
	case repairAttemptPrepared:
		return "prepared"
	case repairAttemptStaged:
		return "staged"
	case repairAttemptPublished:
		return "published"
	case repairAttemptActivated:
		return "activated"
	case repairAttemptRolledBack:
		return "rolled_back"
	case repairAttemptFailedClosed:
		return "failed_closed"
	default:
		return fmt.Sprintf("unknown_%d", stage)
	}
}

func countKernel5TCPRollbackEvents(events []string, target string) int {
	count := 0
	for _, event := range events {
		if event == target {
			count++
		}
	}
	return count
}

func kernel5TCPRollbackTraceDigest(events []string) string {
	hash := sha256.New()
	for _, event := range events {
		_, _ = hash.Write([]byte(event))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func validateKernel5TCPRollbackBoundaryEvidence(evidence kernel5TCPRollbackBoundaryEvidence) error {
	if evidence.Schema != kernel5TCPRepairRollbackBoundaryEvidenceSchema ||
		evidence.TestName != "TestKernel5TCPRepairRollbackFaultBoundaryEvidence" {
		return fmt.Errorf("schema/test=%q/%q", evidence.Schema, evidence.TestName)
	}
	if err := validateKernel5EvidenceIdentity(evidence.InvocationNonce, evidence.NetworkNamespace); err != nil {
		return err
	}
	expected := map[string]struct {
		stage      string
		terminal   bool
		trace      []string
		generation bool
	}{
		"prepare":     {stage: "rolled_back", trace: []string{"inspect", "install", "release"}},
		"stage":       {stage: "rolled_back", trace: []string{"inspect", "install", "capture", "release"}},
		"restore":     {stage: "rolled_back", trace: []string{"inspect", "install", "capture", "restore", "restore", "release"}, generation: true},
		"publish":     {stage: "rolled_back", trace: []string{"inspect", "install", "capture", "restore", "release"}, generation: true},
		"rollback":    {stage: "rolled_back", trace: []string{"inspect", "install", "capture", "restore", "release", "release"}, generation: true},
		"activate":    {stage: "activated", trace: []string{"inspect", "install", "capture", "restore", "release", "release"}, generation: true},
		"fail_closed": {stage: "failed_closed", terminal: true, trace: []string{"inspect", "install", "capture", "restore", "release", "enter", "release"}, generation: true},
	}
	if len(evidence.Records) != len(expected) {
		return fmt.Errorf("rollback boundary records=%d, want %d", len(evidence.Records), len(expected))
	}
	seen := make(map[string]struct{}, len(expected))
	for _, record := range evidence.Records {
		want, ok := expected[record.Boundary]
		if !ok {
			return fmt.Errorf("unknown rollback boundary %q", record.Boundary)
		}
		if _, duplicate := seen[record.Boundary]; duplicate {
			return fmt.Errorf("duplicate rollback boundary %q", record.Boundary)
		}
		seen[record.Boundary] = struct{}{}
		if record.Fault == "" || record.Driver != "tcp_repair_attempt" ||
			record.DependencyMode != "production_state_machine_with_injected_kernel_and_quarantine" ||
			!record.FaultObserved || !record.OutcomeVerified || record.TransactionObservations != 1 ||
			record.TransactionMismatches != 0 || record.QuarantineInstalls != 1 ||
			record.QuarantineReleases < 1 || record.QuarantineActive ||
			record.FinalStage != want.stage || record.EndpointTerminal != want.terminal ||
			record.ExpectedTerminalOutcome != want.terminal || record.EndpointAvailable == want.terminal ||
			record.BidirectionalSocketIO == want.terminal || record.EndpointChanged != want.generation {
			return fmt.Errorf("rollback boundary %q has contradictory outcome: %+v", record.Boundary, record)
		}
		if want.generation {
			if record.FinalGeneration <= record.InitialGeneration {
				return fmt.Errorf("rollback boundary %q did not advance endpoint generation", record.Boundary)
			}
		} else if record.FinalGeneration != record.InitialGeneration {
			return fmt.Errorf("rollback boundary %q unexpectedly changed endpoint generation", record.Boundary)
		}
		if err := validateKernel5TCPFixedLowerHex("transaction_id", record.TransactionID, 16); err != nil {
			return err
		}
		if err := validateKernel5TCPFixedLowerHex("trace_sha256", record.TraceSHA256, sha256.Size); err != nil {
			return err
		}
		if strings.Join(record.Trace, "\x00") != strings.Join(want.trace, "\x00") ||
			record.TraceSHA256 != kernel5TCPRollbackTraceDigest(record.Trace) {
			return fmt.Errorf("rollback boundary %q trace is not exact: %v", record.Boundary, record.Trace)
		}
	}
	return nil
}

func TestKernel5TCPRepairRollbackBoundaryEvidenceRejectsMutations(t *testing.T) {
	evidence := validKernel5TCPRollbackBoundaryEvidenceForTest()
	if err := validateKernel5TCPRollbackBoundaryEvidence(evidence); err != nil {
		t.Fatalf("valid rollback boundary evidence: %v", err)
	}
	mutations := []struct {
		name   string
		mutate func(*kernel5TCPRollbackBoundaryEvidence)
	}{
		{name: "missing boundary", mutate: func(value *kernel5TCPRollbackBoundaryEvidence) { value.Records = value.Records[:5] }},
		{name: "transaction mismatch", mutate: func(value *kernel5TCPRollbackBoundaryEvidence) { value.Records[0].TransactionMismatches = 1 }},
		{name: "quarantine retained", mutate: func(value *kernel5TCPRollbackBoundaryEvidence) { value.Records[1].QuarantineActive = true }},
		{name: "fault unobserved", mutate: func(value *kernel5TCPRollbackBoundaryEvidence) { value.Records[2].FaultObserved = false }},
		{name: "false bidirectional", mutate: func(value *kernel5TCPRollbackBoundaryEvidence) { value.Records[3].BidirectionalSocketIO = false }},
		{name: "false terminal", mutate: func(value *kernel5TCPRollbackBoundaryEvidence) { value.Records[6].EndpointTerminal = false }},
		{name: "trace drift", mutate: func(value *kernel5TCPRollbackBoundaryEvidence) { value.Records[4].Trace[0] = "release" }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			candidate := validKernel5TCPRollbackBoundaryEvidenceForTest()
			mutation.mutate(&candidate)
			if err := validateKernel5TCPRollbackBoundaryEvidence(candidate); err == nil {
				t.Fatal("mutated rollback boundary evidence was accepted")
			}
		})
	}
}

func validKernel5TCPRollbackBoundaryEvidenceForTest() kernel5TCPRollbackBoundaryEvidence {
	expected := []struct {
		boundary string
		fault    string
		stage    string
		terminal bool
		changed  bool
		initial  uint64
		final    uint64
		trace    []string
		releases int
	}{
		{boundary: "prepare", fault: "quarantine_install_partial_lease", stage: "rolled_back", initial: 1, final: 1, trace: []string{"inspect", "install", "release"}, releases: 1},
		{boundary: "stage", fault: "capture_failure", stage: "rolled_back", initial: 1, final: 1, trace: []string{"inspect", "install", "capture", "release"}, releases: 1},
		{boundary: "restore", fault: "first_restore_failure", stage: "rolled_back", changed: true, initial: 1, final: 2, trace: []string{"inspect", "install", "capture", "restore", "restore", "release"}, releases: 1},
		{boundary: "publish", fault: "stale_endpoint_maintenance_lease", stage: "rolled_back", changed: true, initial: 1, final: 2, trace: []string{"inspect", "install", "capture", "restore", "release"}, releases: 1},
		{boundary: "rollback", fault: "quarantine_release_retry", stage: "rolled_back", changed: true, initial: 1, final: 2, trace: []string{"inspect", "install", "capture", "restore", "release", "release"}, releases: 2},
		{boundary: "activate", fault: "activate_quarantine_release_retry", stage: "activated", changed: true, initial: 1, final: 2, trace: []string{"inspect", "install", "capture", "restore", "release", "release"}, releases: 2},
		{boundary: "fail_closed", fault: "partial_rollback_release_failure", stage: "failed_closed", terminal: true, changed: true, initial: 1, final: 2, trace: []string{"inspect", "install", "capture", "restore", "release", "enter", "release"}, releases: 2},
	}
	records := make([]kernel5TCPRollbackBoundaryRecord, 0, len(expected))
	for _, item := range expected {
		records = append(records, kernel5TCPRollbackBoundaryRecord{
			Boundary: item.boundary, Fault: item.fault, Driver: "tcp_repair_attempt",
			DependencyMode: "production_state_machine_with_injected_kernel_and_quarantine",
			TransactionID:  strings.Repeat("a", 32), TransactionObservations: 1, FaultObserved: true,
			QuarantineInstalls: 1, QuarantineReleases: item.releases,
			InitialGeneration: item.initial, FinalGeneration: item.final, FinalStage: item.stage,
			EndpointChanged: item.changed, EndpointAvailable: !item.terminal, EndpointTerminal: item.terminal,
			BidirectionalSocketIO: !item.terminal, ExpectedTerminalOutcome: item.terminal, OutcomeVerified: true,
			Trace: append([]string(nil), item.trace...), TraceSHA256: kernel5TCPRollbackTraceDigest(item.trace),
		})
	}
	return kernel5TCPRollbackBoundaryEvidence{
		Schema:          kernel5TCPRepairRollbackBoundaryEvidenceSchema,
		InvocationNonce: strings.Repeat("b", 64), NetworkNamespace: "4:5",
		TestName: "TestKernel5TCPRepairRollbackFaultBoundaryEvidence", Records: records,
	}
}
