//go:build linux && amd64

package tcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/internal/tcpquarantine"
	"github.com/FrankoonG/rendr/internal/tcprepair"
)

const (
	kernel5TCPRepairRollbackKernelEvidenceEnvironment = "RENDR_KERNEL5_TCP_REPAIR_ROLLBACK_KERNEL_EVIDENCE"
	kernel5TCPRepairRollbackKernelEvidenceSchema      = "kernel5-tcprepair-rollback-kernel-v2"
)

type kernel5TCPRollbackKernelCycleEvidence struct {
	Index                          int                       `json:"index"`
	RecordClass                    string                    `json:"record_class"`
	FaultBoundary                  string                    `json:"fault_boundary"`
	PlanTransactionID              string                    `json:"plan_transaction_id"`
	QuarantineInstallTransactionID string                    `json:"quarantine_install_transaction_id"`
	RollbackRequestTransactionID   string                    `json:"rollback_request_transaction_id"`
	TupleLocalBefore               string                    `json:"tuple_local_before"`
	TupleRemoteBefore              string                    `json:"tuple_remote_before"`
	TupleLocalAfter                string                    `json:"tuple_local_after"`
	TupleRemoteAfter               string                    `json:"tuple_remote_after"`
	SourceSocketCookie             uint64                    `json:"source_socket_cookie"`
	RollbackSocketCookie           uint64                    `json:"rollback_socket_cookie"`
	GenerationBefore               uint64                    `json:"generation_before"`
	GenerationAfter                uint64                    `json:"generation_after"`
	SnapshotStageSHA256            string                    `json:"snapshot_stage_sha256"`
	SnapshotRollbackSHA256         string                    `json:"snapshot_rollback_sha256"`
	QuarantineRulesDuring          int                       `json:"quarantine_rules_during"`
	QuarantineRuleSetSHA256        string                    `json:"quarantine_rule_set_sha256"`
	QuarantineRulesAfter           int                       `json:"quarantine_rules_after"`
	FinalStage                     string                    `json:"final_stage"`
	EndpointAvailable              bool                      `json:"endpoint_available"`
	EndpointTerminal               bool                      `json:"endpoint_terminal"`
	MaintenanceRetained            bool                      `json:"maintenance_retained"`
	QuarantineRetained             bool                      `json:"quarantine_retained"`
	ExecutorRetained               bool                      `json:"executor_retained"`
	ForwardPayload                 kernel5TCPPayloadEvidence `json:"forward_payload"`
	ReversePayload                 kernel5TCPPayloadEvidence `json:"reverse_payload"`
	ApplicationErrors              int                       `json:"application_errors"`
	ApplicationEOFs                int                       `json:"application_eofs"`
	ApplicationResets              int                       `json:"application_resets"`
}

type kernel5TCPRepairRollbackKernelEvidence struct {
	Schema           string                                  `json:"schema"`
	RecordClass      string                                  `json:"record_class"`
	InvocationNonce  string                                  `json:"invocation_nonce"`
	NetworkNamespace string                                  `json:"network_namespace"`
	TestName         string                                  `json:"test_name"`
	Cycles           kernel5TCPRollbackCycleEvidence         `json:"cycles"`
	Stages           kernel5TCPRollbackStageEvidence         `json:"stages"`
	Records          []kernel5TCPRollbackKernelCycleEvidence `json:"records"`
	Before           kernel5TCPResourceEvidence              `json:"before"`
	Warm             kernel5TCPResourceEvidence              `json:"warm"`
	After            kernel5TCPResourceEvidence              `json:"after"`
}

type kernel5TCPRollbackRecordingQuarantineManager struct {
	delegate quarantineManager

	mu       sync.Mutex
	installs []tcpquarantine.TransactionID
}

func (manager *kernel5TCPRollbackRecordingQuarantineManager) Preflight(
	ctx context.Context,
	transaction tcpquarantine.TransactionID,
	tuple tcpquarantine.Tuple,
) error {
	if manager == nil || manager.delegate == nil {
		return errors.New("rollback evidence quarantine manager has no delegate")
	}
	return manager.delegate.Preflight(ctx, transaction, tuple)
}

func (manager *kernel5TCPRollbackRecordingQuarantineManager) Install(
	ctx context.Context,
	transaction tcpquarantine.TransactionID,
	tuple tcpquarantine.Tuple,
) (quarantineLease, error) {
	if manager == nil || manager.delegate == nil {
		return nil, errors.New("rollback evidence quarantine manager has no delegate")
	}
	manager.mu.Lock()
	manager.installs = append(manager.installs, transaction)
	manager.mu.Unlock()
	return manager.delegate.Install(ctx, transaction, tuple)
}

func (manager *kernel5TCPRollbackRecordingQuarantineManager) singleInstall() (tcpquarantine.TransactionID, error) {
	if manager == nil {
		return tcpquarantine.TransactionID{}, errors.New("rollback evidence quarantine manager is nil")
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.installs) != 1 {
		return tcpquarantine.TransactionID{}, fmt.Errorf("quarantine install transactions=%d, want 1", len(manager.installs))
	}
	return manager.installs[0], nil
}

func newKernel5TCPRollbackTransaction(t testing.TB) leafmobility.TransactionID {
	t.Helper()
	for {
		var transaction leafmobility.TransactionID
		if _, err := rand.Read(transaction[:]); err != nil {
			t.Fatalf("generate rollback transaction: %v", err)
		}
		if transaction != (leafmobility.TransactionID{}) {
			return transaction
		}
	}
}

func finishKernel5TCPRollbackKernelCycle(
	t testing.TB,
	cycle int,
	fixture *repairDriverFixture,
	manager *kernel5TCPRollbackRecordingQuarantineManager,
	before tcprepair.Inspection,
	sourceCookie uint64,
	snapshotDigest string,
	quarantineRules int,
	quarantineDigest string,
	forward kernel5TCPPayloadEvidence,
	reverse kernel5TCPPayloadEvidence,
) kernel5TCPRollbackKernelCycleEvidence {
	t.Helper()
	installedTransaction, err := manager.singleInstall()
	if err != nil {
		t.Fatal(err)
	}
	conn, generation, available := fixture.path.endpoint.current()
	if !available {
		t.Fatal("rollback endpoint is not available")
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("rollback endpoint type=%T, want *net.TCPConn", conn)
	}
	after, err := tcprepair.Inspect(tcpConn)
	if err != nil {
		t.Fatalf("inspect rollback endpoint: %v", err)
	}
	rollbackCookie, err := measureKernel5TCPSocketCookie(tcpConn)
	if err != nil {
		t.Fatalf("measure rollback endpoint SO_COOKIE: %v", err)
	}
	_, _, maintenance, terminal := repairEndpointState(fixture.path.endpoint)
	rulesAfter := kernel5TCPRepairQuarantineRuleCount(t)
	index := cycle
	if index <= 0 {
		index = 1
	}
	record := kernel5TCPRollbackKernelCycleEvidence{
		Index: index, RecordClass: "real_kernel", FaultBoundary: "post_stage_pre_publish",
		PlanTransactionID:              hex.EncodeToString(fixture.request.Plan.TransactionID[:]),
		QuarantineInstallTransactionID: hex.EncodeToString(installedTransaction[:]),
		RollbackRequestTransactionID:   hex.EncodeToString(fixture.request.Plan.TransactionID[:]),
		TupleLocalBefore:               before.Tuple.Local.String(), TupleRemoteBefore: before.Tuple.Remote.String(),
		TupleLocalAfter: after.Tuple.Local.String(), TupleRemoteAfter: after.Tuple.Remote.String(),
		SourceSocketCookie: sourceCookie, RollbackSocketCookie: rollbackCookie,
		GenerationBefore: fixture.attempt.ownerGeneration, GenerationAfter: generation,
		SnapshotStageSHA256: snapshotDigest, SnapshotRollbackSHA256: fmt.Sprintf("%x", fixture.attempt.snapshot.Digest()),
		QuarantineRulesDuring: quarantineRules, QuarantineRuleSetSHA256: quarantineDigest,
		QuarantineRulesAfter: rulesAfter, FinalStage: kernel5TCPRepairAttemptStageName(fixture.attempt.stage),
		EndpointAvailable: available, EndpointTerminal: terminal, MaintenanceRetained: maintenance,
		QuarantineRetained: fixture.attempt.quarantine != nil, ExecutorRetained: fixture.attempt.executor != nil,
		ForwardPayload: forward, ReversePayload: reverse,
	}
	if err := validateKernel5TCPRollbackKernelCycle(record); err != nil {
		t.Fatalf("real-kernel rollback cycle evidence is invalid: %v", err)
	}
	return record
}

func assertKernel5TCPRollbackPayloadRoundTrip(
	t testing.TB,
	path *PathConn,
	peer net.Conn,
	cycle int,
	transaction leafmobility.TransactionID,
) (kernel5TCPPayloadEvidence, kernel5TCPPayloadEvidence) {
	t.Helper()
	if err := peer.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set rollback peer deadline: %v", err)
	}
	forwardOffered := kernel5TCPRollbackCyclePayload("forward", cycle, transaction)
	forwardReceived := make([]byte, len(forwardOffered))
	writeDone := make(chan error, 1)
	go func() {
		n, writeErr := path.Write(forwardOffered)
		if writeErr == nil && n != len(forwardOffered) {
			writeErr = fmt.Errorf("rollback path write=%d want=%d", n, len(forwardOffered))
		}
		writeDone <- writeErr
	}()
	wire := make([]byte, LengthPrefixSize+len(forwardOffered))
	if _, err := io.ReadFull(peer, wire); err != nil {
		t.Fatalf("read rollback forward frame: %v", err)
	}
	if int(binary.BigEndian.Uint16(wire[:LengthPrefixSize])) != len(forwardOffered) {
		t.Fatalf("rollback forward frame length=%d want=%d", binary.BigEndian.Uint16(wire[:LengthPrefixSize]), len(forwardOffered))
	}
	copy(forwardReceived, wire[LengthPrefixSize:])
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(forwardReceived, forwardOffered) {
		t.Fatal("rollback forward payload mismatch")
	}

	reverseOffered := kernel5TCPRollbackCyclePayload("reverse", cycle, transaction)
	reverseReceived := make([]byte, len(reverseOffered))
	reverseDone := make(chan error, 1)
	go func() {
		_, readErr := io.ReadFull(path, reverseReceived)
		reverseDone <- readErr
	}()
	reverseWire := make([]byte, LengthPrefixSize+len(reverseOffered))
	binary.BigEndian.PutUint16(reverseWire[:LengthPrefixSize], uint16(len(reverseOffered)))
	copy(reverseWire[LengthPrefixSize:], reverseOffered)
	if _, err := peer.Write(reverseWire); err != nil {
		t.Fatalf("write rollback reverse frame: %v", err)
	}
	if err := <-reverseDone; err != nil {
		t.Fatalf("read rollback reverse payload: %v", err)
	}
	if !bytes.Equal(reverseReceived, reverseOffered) {
		t.Fatal("rollback reverse payload mismatch")
	}
	return kernel5TCPRollbackPayloadEvidence(forwardOffered, forwardReceived),
		kernel5TCPRollbackPayloadEvidence(reverseOffered, reverseReceived)
}

func kernel5TCPRollbackCyclePayload(
	direction string,
	cycle int,
	transaction leafmobility.TransactionID,
) []byte {
	payload := make([]byte, 1024)
	seed := make([]byte, 0, len(direction)+len(transaction)+8)
	seed = append(seed, direction...)
	seed = append(seed, transaction[:]...)
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], uint64(cycle))
	seed = append(seed, scalar[:]...)
	for offset, counter := 0, uint64(0); offset < len(payload); counter++ {
		binary.BigEndian.PutUint64(scalar[:], counter)
		digest := sha256.Sum256(append(seed, scalar[:]...))
		offset += copy(payload[offset:], digest[:])
	}
	return payload
}

func kernel5TCPRollbackPayloadEvidence(offered, received []byte) kernel5TCPPayloadEvidence {
	offeredDigest := sha256.Sum256(offered)
	receivedDigest := sha256.Sum256(received)
	return kernel5TCPPayloadEvidence{
		OfferedBytes: len(offered), ReceivedBytes: len(received),
		OfferedSHA256: hex.EncodeToString(offeredDigest[:]), ReceivedSHA256: hex.EncodeToString(receivedDigest[:]),
	}
}

func kernel5TCPRollbackQuarantineEvidence(t testing.TB) (int, string) {
	t.Helper()
	output, err := exec.Command("/usr/sbin/nft", "-j", "list", "ruleset").Output()
	if err != nil {
		t.Fatalf("list rollback quarantine rules: %v", err)
	}
	var document struct {
		NFTables []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(output, &document); err != nil {
		t.Fatalf("decode rollback quarantine rules: %v", err)
	}
	selected := make([]string, 0)
	rules := 0
	for _, raw := range document.NFTables {
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatalf("decode rollback quarantine entry: %v", err)
		}
		if !kernel5TCPRollbackContainsOwnedTable(value) {
			continue
		}
		canonical, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("canonicalize rollback quarantine entry: %v", err)
		}
		selected = append(selected, string(canonical))
		if object, ok := value.(map[string]any); ok && object["rule"] != nil {
			rules++
		}
	}
	if rules == 0 || len(selected) == 0 {
		return rules, ""
	}
	sort.Strings(selected)
	hash := sha256.New()
	for _, entry := range selected {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(entry)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write([]byte(entry))
	}
	return rules, hex.EncodeToString(hash.Sum(nil))
}

func kernel5TCPRollbackContainsOwnedTable(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for _, child := range typed {
			if kernel5TCPRollbackContainsOwnedTable(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if kernel5TCPRollbackContainsOwnedTable(child) {
				return true
			}
		}
	case string:
		return strings.HasPrefix(typed, "rendr_q2_")
	}
	return false
}

func emitKernel5TCPRepairRollbackKernelEvidence(
	t testing.TB,
	requested, completed, warmup int,
	stages kernel5TCPRollbackStageEvidence,
	records []kernel5TCPRollbackKernelCycleEvidence,
	before, warm, after refreshResourceSample,
) {
	t.Helper()
	binding, enabled, err := loadKernel5TCPEvidenceBinding(kernel5TCPRepairRollbackKernelEvidenceEnvironment)
	if err != nil {
		t.Fatal(err)
	}
	if !enabled {
		return
	}
	evidence := kernel5TCPRepairRollbackKernelEvidence{
		Schema: kernel5TCPRepairRollbackKernelEvidenceSchema, RecordClass: "real_kernel",
		InvocationNonce: binding.nonce, NetworkNamespace: binding.netns,
		TestName: "TestPrivilegedTCPRepairRollbackResourceSlope",
		Cycles:   kernel5TCPRollbackCycleEvidence{Requested: requested, Completed: completed, Warmup: warmup},
		Stages:   stages, Records: append([]kernel5TCPRollbackKernelCycleEvidence(nil), records...),
		Before: kernel5TCPResourceFromSample(before), Warm: kernel5TCPResourceFromSample(warm),
		After: kernel5TCPResourceFromSample(after),
	}
	if err := validateKernel5TCPRepairRollbackKernelEvidence(evidence); err != nil {
		t.Fatalf("real-kernel rollback evidence is invalid: %v", err)
	}
	if err := writeKernel5TCPStrictJSON(binding.path, evidence, func(decoded *kernel5TCPRepairRollbackKernelEvidence) error {
		return validateKernel5TCPRepairRollbackKernelEvidence(*decoded)
	}); err != nil {
		t.Fatalf("write real-kernel rollback evidence: %v", err)
	}
}

func validateKernel5TCPRepairRollbackKernelEvidence(evidence kernel5TCPRepairRollbackKernelEvidence) error {
	if evidence.Schema != kernel5TCPRepairRollbackKernelEvidenceSchema || evidence.RecordClass != "real_kernel" ||
		evidence.TestName != "TestPrivilegedTCPRepairRollbackResourceSlope" {
		return fmt.Errorf("schema/class/test=%q/%q/%q", evidence.Schema, evidence.RecordClass, evidence.TestName)
	}
	if err := validateKernel5EvidenceIdentity(evidence.InvocationNonce, evidence.NetworkNamespace); err != nil {
		return err
	}
	if evidence.Cycles.Requested != 200 || evidence.Cycles.Completed != 200 || evidence.Cycles.Warmup != 20 ||
		len(evidence.Records) != evidence.Cycles.Completed {
		return fmt.Errorf("real-kernel rollback cycles are incomplete: %+v records=%d", evidence.Cycles, len(evidence.Records))
	}
	if evidence.Stages.Prepare != 200 || evidence.Stages.Stage != 200 || evidence.Stages.Rollback != 200 ||
		evidence.Stages.Total != 600 {
		return fmt.Errorf("real-kernel rollback stages are incomplete: %+v", evidence.Stages)
	}
	transactions := make(map[string]struct{}, len(evidence.Records))
	for index, record := range evidence.Records {
		if record.Index != index+1 {
			return fmt.Errorf("real-kernel rollback record index=%d, want %d", record.Index, index+1)
		}
		if err := validateKernel5TCPRollbackKernelCycle(record); err != nil {
			return fmt.Errorf("real-kernel rollback record %d: %w", index+1, err)
		}
		if _, duplicate := transactions[record.PlanTransactionID]; duplicate {
			return fmt.Errorf("real-kernel rollback transaction %q is reused", record.PlanTransactionID)
		}
		transactions[record.PlanTransactionID] = struct{}{}
	}
	for name, sample := range map[string]kernel5TCPResourceEvidence{
		"before": evidence.Before, "warm": evidence.Warm, "after": evidence.After,
	} {
		if sample.OpenFDs <= 0 || sample.Goroutines <= 0 || sample.HeapInuseBytes == 0 || sample.RSSBytes == 0 ||
			sample.QuarantineRules != 0 {
			return fmt.Errorf("%s real-kernel rollback resource sample is invalid: %+v", name, sample)
		}
	}
	if evidence.After.OpenFDs > evidence.Before.OpenFDs+4 || evidence.After.Goroutines > evidence.Before.Goroutines+8 ||
		evidence.After.HeapInuseBytes > evidence.Warm.HeapInuseBytes+(16<<20) ||
		evidence.After.RSSBytes > evidence.Warm.RSSBytes+(32<<20) {
		return fmt.Errorf("real-kernel rollback resource slope exceeded: before=%+v warm=%+v after=%+v",
			evidence.Before, evidence.Warm, evidence.After)
	}
	return nil
}

func validateKernel5TCPRollbackKernelCycle(record kernel5TCPRollbackKernelCycleEvidence) error {
	if record.Index <= 0 || record.RecordClass != "real_kernel" || record.FaultBoundary != "post_stage_pre_publish" {
		return fmt.Errorf("record identity is invalid: %+v", record)
	}
	for label, transaction := range map[string]string{
		"plan": record.PlanTransactionID, "quarantine": record.QuarantineInstallTransactionID,
		"rollback": record.RollbackRequestTransactionID,
	} {
		if err := validateKernel5TCPFixedLowerHex(label+"_transaction_id", transaction, 16); err != nil {
			return err
		}
	}
	if record.PlanTransactionID != record.QuarantineInstallTransactionID ||
		record.PlanTransactionID != record.RollbackRequestTransactionID {
		return errors.New("plan/quarantine/rollback transactions differ")
	}
	if record.TupleLocalBefore == "" || record.TupleRemoteBefore == "" ||
		record.TupleLocalAfter != record.TupleLocalBefore || record.TupleRemoteAfter != record.TupleRemoteBefore {
		return fmt.Errorf("rollback tuple changed: %+v", record)
	}
	if record.SourceSocketCookie == 0 || record.RollbackSocketCookie == 0 ||
		record.SourceSocketCookie == record.RollbackSocketCookie {
		return fmt.Errorf("rollback physical socket incarnation is not distinct: %d/%d",
			record.SourceSocketCookie, record.RollbackSocketCookie)
	}
	if record.GenerationBefore == 0 || record.GenerationAfter <= record.GenerationBefore {
		return fmt.Errorf("rollback endpoint generation did not advance: %d/%d", record.GenerationBefore, record.GenerationAfter)
	}
	if err := validateKernel5TCPFixedLowerHex("snapshot_stage_sha256", record.SnapshotStageSHA256, sha256.Size); err != nil {
		return err
	}
	if record.SnapshotRollbackSHA256 != record.SnapshotStageSHA256 {
		return errors.New("rollback snapshot digest changed")
	}
	if record.QuarantineRulesDuring < 2 || record.QuarantineRulesAfter != 0 {
		return fmt.Errorf("rollback quarantine rules during/after=%d/%d", record.QuarantineRulesDuring, record.QuarantineRulesAfter)
	}
	if err := validateKernel5TCPFixedLowerHex("quarantine_rule_set_sha256", record.QuarantineRuleSetSHA256, sha256.Size); err != nil {
		return err
	}
	if record.FinalStage != "rolled_back" || !record.EndpointAvailable || record.EndpointTerminal ||
		record.MaintenanceRetained || record.QuarantineRetained || record.ExecutorRetained {
		return fmt.Errorf("rollback final ownership is incomplete: %+v", record)
	}
	if err := validateKernel5TCPPayload(record.ForwardPayload); err != nil {
		return fmt.Errorf("rollback forward payload: %w", err)
	}
	if err := validateKernel5TCPPayload(record.ReversePayload); err != nil {
		return fmt.Errorf("rollback reverse payload: %w", err)
	}
	if record.ForwardPayload.OfferedBytes != 1024 || record.ReversePayload.OfferedBytes != 1024 ||
		record.ForwardPayload.OfferedSHA256 == record.ReversePayload.OfferedSHA256 {
		return errors.New("rollback bidirectional payload evidence is not cycle-bound")
	}
	if record.ApplicationErrors != 0 || record.ApplicationEOFs != 0 || record.ApplicationResets != 0 {
		return fmt.Errorf("rollback application outcomes report errors: %+v", record)
	}
	return nil
}

func TestKernel5TCPRepairRollbackKernelEvidenceRejectsMutations(t *testing.T) {
	evidence := validKernel5TCPRepairRollbackKernelEvidenceForTest()
	if err := validateKernel5TCPRepairRollbackKernelEvidence(evidence); err != nil {
		t.Fatalf("valid real-kernel rollback evidence: %v", err)
	}
	mutations := []struct {
		name   string
		mutate func(*kernel5TCPRepairRollbackKernelEvidence)
	}{
		{name: "missing cycle", mutate: func(value *kernel5TCPRepairRollbackKernelEvidence) { value.Records = value.Records[:199] }},
		{name: "duplicate transaction", mutate: func(value *kernel5TCPRepairRollbackKernelEvidence) {
			value.Records[1].PlanTransactionID = value.Records[0].PlanTransactionID
			value.Records[1].QuarantineInstallTransactionID = value.Records[0].PlanTransactionID
			value.Records[1].RollbackRequestTransactionID = value.Records[0].PlanTransactionID
		}},
		{name: "same socket", mutate: func(value *kernel5TCPRepairRollbackKernelEvidence) {
			value.Records[0].RollbackSocketCookie = value.Records[0].SourceSocketCookie
		}},
		{name: "snapshot drift", mutate: func(value *kernel5TCPRepairRollbackKernelEvidence) {
			value.Records[0].SnapshotRollbackSHA256 = strings.Repeat("f", 64)
		}},
		{name: "quarantine leak", mutate: func(value *kernel5TCPRepairRollbackKernelEvidence) { value.Records[0].QuarantineRulesAfter = 1 }},
		{name: "payload corruption", mutate: func(value *kernel5TCPRepairRollbackKernelEvidence) {
			value.Records[0].ForwardPayload.ReceivedSHA256 = strings.Repeat("e", 64)
		}},
		{name: "application EOF", mutate: func(value *kernel5TCPRepairRollbackKernelEvidence) { value.Records[0].ApplicationEOFs = 1 }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			candidate := validKernel5TCPRepairRollbackKernelEvidenceForTest()
			mutation.mutate(&candidate)
			if err := validateKernel5TCPRepairRollbackKernelEvidence(candidate); err == nil {
				t.Fatal("mutated real-kernel rollback evidence was accepted")
			}
		})
	}
}

func validKernel5TCPRepairRollbackKernelEvidenceForTest() kernel5TCPRepairRollbackKernelEvidence {
	resources := kernel5TCPResourceEvidence{OpenFDs: 10, Goroutines: 2, HeapInuseBytes: 1 << 20, RSSBytes: 2 << 20}
	records := make([]kernel5TCPRollbackKernelCycleEvidence, 200)
	for index := range records {
		transactionDigest := sha256.Sum256([]byte(fmt.Sprintf("transaction-%d", index+1)))
		transaction := hex.EncodeToString(transactionDigest[:16])
		forward := sha256.Sum256([]byte(fmt.Sprintf("forward-%d", index+1)))
		reverse := sha256.Sum256([]byte(fmt.Sprintf("reverse-%d", index+1)))
		records[index] = kernel5TCPRollbackKernelCycleEvidence{
			Index: index + 1, RecordClass: "real_kernel", FaultBoundary: "post_stage_pre_publish",
			PlanTransactionID: transaction, QuarantineInstallTransactionID: transaction, RollbackRequestTransactionID: transaction,
			TupleLocalBefore: "127.0.0.1:1000", TupleRemoteBefore: "127.0.0.1:2000",
			TupleLocalAfter: "127.0.0.1:1000", TupleRemoteAfter: "127.0.0.1:2000",
			SourceSocketCookie: uint64(index*2 + 1), RollbackSocketCookie: uint64(index*2 + 2),
			GenerationBefore: 1, GenerationAfter: 2,
			SnapshotStageSHA256: strings.Repeat("a", 64), SnapshotRollbackSHA256: strings.Repeat("a", 64),
			QuarantineRulesDuring: 2, QuarantineRuleSetSHA256: strings.Repeat("b", 64),
			FinalStage: "rolled_back", EndpointAvailable: true,
			ForwardPayload: kernel5TCPPayloadEvidence{OfferedBytes: 1024, ReceivedBytes: 1024, OfferedSHA256: hex.EncodeToString(forward[:]), ReceivedSHA256: hex.EncodeToString(forward[:])},
			ReversePayload: kernel5TCPPayloadEvidence{OfferedBytes: 1024, ReceivedBytes: 1024, OfferedSHA256: hex.EncodeToString(reverse[:]), ReceivedSHA256: hex.EncodeToString(reverse[:])},
		}
	}
	return kernel5TCPRepairRollbackKernelEvidence{
		Schema: kernel5TCPRepairRollbackKernelEvidenceSchema, RecordClass: "real_kernel",
		InvocationNonce: strings.Repeat("c", 64), NetworkNamespace: "4:5",
		TestName: "TestPrivilegedTCPRepairRollbackResourceSlope",
		Cycles:   kernel5TCPRollbackCycleEvidence{Requested: 200, Completed: 200, Warmup: 20},
		Stages:   kernel5TCPRollbackStageEvidence{Prepare: 200, Stage: 200, Rollback: 200, Total: 600},
		Records:  records, Before: resources, Warm: resources, After: resources,
	}
}
