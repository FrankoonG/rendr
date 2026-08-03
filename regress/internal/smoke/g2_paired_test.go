package smoke

import (
	"strings"
	"testing"
	"time"
)

func TestEvaluateG2PairUsesQualifiedMatchedBaselineWithFloor(t *testing.T) {
	baseline := syntheticG2PairedArm(0.4, true, 1_000_000_000)
	treatment := syntheticG2PairedArm(1.9, true, 1_000_100_000)
	result := evaluateG2Pair("paired", time.Second, baseline, treatment, time.Millisecond)
	if result.Failure != "" || result.InvalidReason != "" {
		t.Fatalf("evaluateG2Pair = %+v", result)
	}
	if result.Detail["paired_floor_applied"] != true || result.Detail["paired_p99_ceiling_ms"] != float64(2) {
		t.Fatalf("floor evidence = %+v", result.Detail)
	}

	treatment.Detail["p99_ms"] = float64(2)
	result = evaluateG2Pair("paired", time.Second, baseline, treatment, time.Millisecond)
	if !strings.Contains(result.Failure, "strict matched ceiling") {
		t.Fatalf("boundary result = %+v", result)
	}
}

func TestEvaluateG2PairRejectsUnqualifiedOrMismatchedEvidence(t *testing.T) {
	baseline := syntheticG2PairedArm(1, true, 1_000_000_000)
	treatment := syntheticG2PairedArm(1, false, 1_000_100_000)
	result := evaluateG2Pair("paired", time.Second, baseline, treatment, time.Millisecond)
	if !strings.Contains(result.InvalidReason, "not both qualified") {
		t.Fatalf("unqualified result = %+v", result)
	}

	treatment = syntheticG2PairedArm(1, true, 1_000_100_000)
	treatment.Detail["planned_echoes"] = 999
	result = evaluateG2Pair("paired", time.Second, baseline, treatment, time.Millisecond)
	if !strings.Contains(result.InvalidReason, "metadata mismatch") {
		t.Fatalf("mismatch result = %+v", result)
	}

	treatment = syntheticG2PairedArm(1, true, 1_000_000_000+int64(g2PairedMaxStartSkew)+1)
	result = evaluateG2Pair("paired", time.Second, baseline, treatment, time.Millisecond)
	if !strings.Contains(result.InvalidReason, "start skew") {
		t.Fatalf("skew result = %+v", result)
	}
}

func TestEvaluateG2PairPreservesArmFailureClassification(t *testing.T) {
	baseline := syntheticG2PairedArm(1, true, 1_000_000_000)
	treatment := syntheticG2PairedArm(1, true, 1_000_100_000)
	baseline.InvalidReason = "missing offered load"
	result := evaluateG2Pair("paired", time.Second, baseline, treatment, time.Millisecond)
	if !strings.Contains(result.InvalidReason, "baseline arm invalid") || result.Failure != "" {
		t.Fatalf("invalid baseline result = %+v", result)
	}

	baseline.InvalidReason = ""
	treatment.Failure = "echo loss"
	result = evaluateG2Pair("paired", time.Second, baseline, treatment, time.Millisecond)
	if !strings.Contains(result.Failure, "treatment arm failed") || result.InvalidReason != "" {
		t.Fatalf("failed treatment result = %+v", result)
	}
}

func syntheticG2PairedArm(p99MS float64, qualified bool, startedNS int64) Result {
	return Result{Duration: time.Second, Detail: map[string]any{
		"requested_duration_ms":       int64(30_000),
		"interval_ns":                 int64(100_000_000),
		"expected_echoes":             1_000,
		"planned_echoes":              1_000,
		"latency_samples":             1_000,
		"mode":                        "selector",
		"transport":                   "tcp",
		"paths":                       2,
		"measurement_started_unix_ns": startedNS,
		"p99_qualified":               qualified,
		"p99_ms":                      p99MS,
	}}
}
