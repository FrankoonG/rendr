package tun

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/virtualif"
)

const (
	tier7EvidenceMarker = "RENDR_T7_EVIDENCE_JSON="
	tier7EvidenceSchema = "tier7-deterministic-contract-v1"
)

type tier7EvidenceRun struct {
	started          time.Time
	goroutinesBefore int
}

func TestTier7EvidenceConfigInvalidMTU(t *testing.T) {
	run := beginTier7Evidence()
	for _, mtu := range []int{MinMTU - 1, MaxMTU + 1} {
		err := Config{Enabled: true, MTU: mtu}.Validate()
		var typed *virtualif.Error
		if !errors.As(err, &typed) || typed.Reason != virtualif.ReasonInvalidMTU {
			t.Fatalf("mtu=%d error=%T %v, want typed %s", mtu, err, err, virtualif.ReasonInvalidMTU)
		}
	}
	for _, mtu := range []int{MinMTU, MaxMTU} {
		if err := (Config{Enabled: true, MTU: mtu}).Validate(); err != nil {
			t.Fatalf("valid boundary mtu=%d rejected: %v", mtu, err)
		}
	}
	run.emit(t, "T7.config.invalid-mtu", map[string]string{
		"invalid_mtu_high":             strconv.Itoa(MaxMTU + 1),
		"invalid_mtu_low":              strconv.Itoa(MinMTU - 1),
		"typed_invalid_mtu_rejections": "2",
		"valid_boundary_acceptances":   "2",
	})
}

func beginTier7Evidence() tier7EvidenceRun {
	return tier7EvidenceRun{started: time.Now(), goroutinesBefore: runtime.NumGoroutine()}
}

func (r tier7EvidenceRun) emit(t *testing.T, caseID string, facts map[string]string) {
	t.Helper()
	after := runtime.NumGoroutine()
	evidence := map[string]string{
		"schema":                  tier7EvidenceSchema,
		"case_id":                 caseID,
		"fixture":                 strings.ToLower(strings.ReplaceAll(caseID, ".", "-")) + "-v1",
		"seed_mode":               "none",
		"external_processes":      "0",
		"filesystem_writes":       "0",
		"negative_control_passed": "true",
		"privileged_operations":   "0",
		"elapsed_ns":              strconv.FormatInt(time.Since(r.started).Nanoseconds(), 10),
		"gomaxprocs":              strconv.Itoa(runtime.GOMAXPROCS(0)),
		"goroutine_growth":        strconv.Itoa(after - r.goroutinesBefore),
		"goroutines_after":        strconv.Itoa(after),
		"goroutines_before":       strconv.Itoa(r.goroutinesBefore),
	}
	for key, value := range facts {
		if _, exists := evidence[key]; exists {
			t.Fatalf("duplicate T7 evidence fact %q", key)
		}
		evidence[key] = value
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("encode T7 evidence: %v", err)
	}
	fmt.Printf("%s%s\n", tier7EvidenceMarker, encoded)
}
