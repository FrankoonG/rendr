package rendr

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	tier6EvidenceMarker = "RENDR_T6_EVIDENCE_JSON="
	tier6EvidenceSchema = "tier6-selector-semantics-v1"
)

func emitTier6Evidence(t *testing.T, caseID string, facts map[string]string) {
	t.Helper()
	evidence := make(map[string]string, len(facts)+8)
	evidence["schema"] = tier6EvidenceSchema
	evidence["case_id"] = caseID
	evidence["test_name"] = t.Name()
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	resourceDir := t.TempDir()
	resourceFile, err := os.CreateTemp(resourceDir, "tier6-resource-*")
	if err != nil {
		t.Fatalf("create tier6 resource probe: %v", err)
	}
	written, writeErr := resourceFile.Write([]byte{0x6})
	closeErr := resourceFile.Close()
	removeErr := os.Remove(resourceFile.Name())
	if writeErr != nil || written != 1 || closeErr != nil || removeErr != nil {
		t.Fatalf("tier6 resource probe write/close/remove=%d/%v/%v/%v", written, writeErr, closeErr, removeErr)
	}
	evidence["resource_visible_vcpus"] = strconv.Itoa(runtime.GOMAXPROCS(0))
	evidence["resource_process_sys_bytes"] = strconv.FormatUint(memory.Sys, 10)
	evidence["resource_disk_write_bytes"] = strconv.Itoa(written)
	evidence["resource_cleanup_confirmed"] = "true"
	evidence["resource_roles_observed"] = "1"
	for key, value := range facts {
		if _, reserved := evidence[key]; reserved {
			t.Fatalf("tier6 evidence fact %q collides with marker identity", key)
		}
		if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			t.Fatalf("tier6 evidence contains an empty key or value: %q=%q", key, value)
		}
		evidence[key] = value
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("encode tier6 evidence: %v", err)
	}
	t.Logf("%s%s", tier6EvidenceMarker, encoded)
}

func tier6Bool(value bool) string { return strconv.FormatBool(value) }

func tier6Uint(value uint64) string { return strconv.FormatUint(value, 10) }

func tier6Duration(value time.Duration) string { return strconv.FormatInt(value.Nanoseconds(), 10) }

func tier6DeterministicPayload(label string, size int) []byte {
	seed := sha256.Sum256([]byte("rendr-tier6-payload-v1:" + label))
	payload := make([]byte, size)
	state := uint64(0x9e3779b97f4a7c15)
	for i := 0; i < 8; i++ {
		state ^= uint64(seed[i]) << (8 * i)
	}
	for i := range payload {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		payload[i] = byte(state >> 24)
	}
	return payload
}

type tier6IntegrityResult struct {
	bytes  uint64
	sha256 string
	err    error
}

type tier6IntegrityCollector struct {
	expected      hash.Hash
	expectedBytes uint64
	done          chan tier6IntegrityResult
}

func newTier6IntegrityCollector(reader io.Reader) *tier6IntegrityCollector {
	collector := &tier6IntegrityCollector{
		expected: sha256.New(),
		done:     make(chan tier6IntegrityResult, 1),
	}
	go func() {
		actual := sha256.New()
		bytes, err := io.Copy(actual, reader)
		collector.done <- tier6IntegrityResult{
			bytes:  uint64(bytes),
			sha256: hex.EncodeToString(actual.Sum(nil)),
			err:    err,
		}
	}()
	return collector
}

func (c *tier6IntegrityCollector) write(t *testing.T, writer io.Writer, payload []byte) {
	t.Helper()
	written, err := writer.Write(payload)
	if written > 0 {
		_, _ = c.expected.Write(payload[:written])
		c.expectedBytes += uint64(written)
	}
	if err != nil {
		t.Fatalf("write deterministic tier6 payload: %v", err)
	}
	if written != len(payload) {
		t.Fatalf("short deterministic tier6 payload write: got %d, want %d", written, len(payload))
	}
}

func (c *tier6IntegrityCollector) finish(t *testing.T, prefix string) map[string]string {
	t.Helper()
	var actual tier6IntegrityResult
	select {
	case actual = <-c.done:
	case <-time.After(5 * time.Second):
		t.Fatal("tier6 integrity collector did not observe EOF")
	}
	if actual.err != nil {
		t.Fatalf("read deterministic tier6 payload: %v", actual.err)
	}
	expectedSHA := hex.EncodeToString(c.expected.Sum(nil))
	if actual.bytes != c.expectedBytes || actual.sha256 != expectedSHA {
		t.Fatalf(
			"tier6 payload integrity mismatch: bytes=%d/%d sha256=%s/%s",
			actual.bytes, c.expectedBytes, actual.sha256, expectedSHA,
		)
	}
	return map[string]string{
		prefix + "_bytes":        tier6Uint(actual.bytes),
		prefix + "_sha256":       actual.sha256,
		prefix + "_sha256_match": "true",
	}
}

func tier6CloseWrite(t *testing.T, connection Conn) {
	t.Helper()
	halfCloser, ok := connection.(StreamHalfCloser)
	if !ok {
		t.Fatalf("connection %T does not implement StreamHalfCloser", connection)
	}
	if err := halfCloser.CloseWrite(); err != nil {
		t.Fatalf("close tier6 stream write direction: %v", err)
	}
}

func mergeTier6Facts(t *testing.T, destination map[string]string, source map[string]string) {
	t.Helper()
	for key, value := range source {
		if _, exists := destination[key]; exists {
			t.Fatalf("duplicate tier6 evidence fact %q", key)
		}
		destination[key] = value
	}
}

type tier6MigrationEvent struct {
	oldName string
	newName string
	cause   string
}

type tier6MigrationRecorder struct {
	mu       sync.Mutex
	base     uint64
	byID     map[uint32]string
	events   []tier6MigrationEvent
	cancel   func()
	observer ConnectionObserver
}

func newTier6MigrationRecorder(t *testing.T, connection Conn) *tier6MigrationRecorder {
	t.Helper()
	observer, ok := connection.(ConnectionObserver)
	if !ok {
		t.Fatalf("connection %T does not implement ConnectionObserver", connection)
	}
	byID := make(map[uint32]string)
	for _, path := range connection.Paths() {
		byID[path.ID] = path.Spec.Opts["name"]
	}
	recorder := &tier6MigrationRecorder{
		base:     observer.MigrationCount(),
		byID:     byID,
		observer: observer,
	}
	recorder.cancel = observer.OnMigrate(func(oldID, newID uint32, cause string) {
		recorder.mu.Lock()
		recorder.events = append(recorder.events, tier6MigrationEvent{
			oldName: recorder.byID[oldID],
			newName: recorder.byID[newID],
			cause:   cause,
		})
		recorder.mu.Unlock()
	})
	return recorder
}

func (r *tier6MigrationRecorder) finish(t *testing.T) []tier6MigrationEvent {
	t.Helper()
	want := r.observer.MigrationCount() - r.base
	deadline := time.Now().Add(time.Second)
	for {
		r.mu.Lock()
		got := uint64(len(r.events))
		r.mu.Unlock()
		if got >= want || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	r.cancel()
	r.mu.Lock()
	defer r.mu.Unlock()
	if got := uint64(len(r.events)); got != want {
		t.Fatalf("tier6 migration callbacks=%d, committed migrations=%d", got, want)
	}
	return append([]tier6MigrationEvent(nil), r.events...)
}

func tier6MigrationTargets(events []tier6MigrationEvent) string {
	targets := make([]string, 0, len(events))
	for _, event := range events {
		name := event.newName
		if name == "" {
			name = fmt.Sprintf("path-%d", len(targets)+1)
		}
		targets = append(targets, name)
	}
	if len(targets) == 0 {
		return "none"
	}
	return strings.Join(targets, ">")
}

func tier6MigrationContains(events []tier6MigrationEvent, name string) bool {
	for _, event := range events {
		if event.newName == name {
			return true
		}
	}
	return false
}
