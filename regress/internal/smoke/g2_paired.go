package smoke

import (
	"context"
	"fmt"
	"math"
	"time"
)

const (
	g2PairedBaselineFloor = time.Millisecond
	g2PairedMaxStartSkew  = 5 * time.Second
)

type g2PairedArmResult struct {
	arm    string
	result Result
}

// RunG2Paired runs a no-migration baseline and a migration treatment at the
// same time under the same host/qdisc conditions. It is intended for qualified
// long runs; short populations are INVALID rather than being promoted from
// diagnostic percentiles.
func RunG2Paired(ctx context.Context, opts G2Opts) Result {
	opts.withDefaults()
	started := time.Now()
	name := fmt.Sprintf("G2-paired (%s/%s, %s, %d paths, %d treatment migrations)",
		opts.Transport, modeName(opts.Mode), opts.Duration, opts.Paths, opts.Migrations)

	baselineOpts := opts
	baselineOpts.Migrations = -1
	pairCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	start := make(chan struct{})
	results := make(chan g2PairedArmResult, 2)
	runArm := func(arm string, armOpts G2Opts) {
		<-start
		results <- g2PairedArmResult{arm: arm, result: RunG2(pairCtx, armOpts)}
	}
	go runArm("baseline", baselineOpts)
	go runArm("treatment", opts)
	close(start)

	var baseline, treatment Result
	for completed := 0; completed < 2; completed++ {
		arm := <-results
		if arm.arm == "baseline" {
			baseline = arm.result
		} else {
			treatment = arm.result
		}
		if arm.result.Failure != "" || arm.result.InvalidReason != "" {
			cancel()
		}
	}

	result := evaluateG2Pair(name, time.Since(started), baseline, treatment, g2PairedBaselineFloor)
	result.Detail["fd_identity_observed"] = false
	result.Detail["independent_path_observer"] = false
	return result
}

func evaluateG2Pair(name string, elapsed time.Duration, baseline, treatment Result, floor time.Duration) Result {
	result := Result{Name: name, Duration: elapsed, Detail: make(map[string]any)}
	copyG2ArmDetail(result.Detail, "baseline", baseline)
	copyG2ArmDetail(result.Detail, "treatment", treatment)
	result.Detail["paired_baseline_floor_ms"] = durationMilliseconds(floor)

	if baseline.InvalidReason != "" {
		result.InvalidReason = "baseline arm invalid: " + baseline.InvalidReason
		return result
	}
	if treatment.InvalidReason != "" {
		result.InvalidReason = "treatment arm invalid: " + treatment.InvalidReason
		return result
	}
	if baseline.Failure != "" {
		result.Failure = "baseline arm failed: " + baseline.Failure
		return result
	}
	if treatment.Failure != "" {
		result.Failure = "treatment arm failed: " + treatment.Failure
		return result
	}

	for _, key := range []string{"requested_duration_ms", "interval_ns", "expected_echoes", "planned_echoes", "latency_samples", "mode", "transport", "paths"} {
		baselineValue, baselineOK := baseline.Detail[key]
		treatmentValue, treatmentOK := treatment.Detail[key]
		if !baselineOK || !treatmentOK || fmt.Sprint(baselineValue) != fmt.Sprint(treatmentValue) {
			result.InvalidReason = fmt.Sprintf("paired arm metadata mismatch for %s: baseline=%v treatment=%v", key, baselineValue, treatmentValue)
			return result
		}
	}

	baselineStart, baselineStartOK := detailInt64(baseline.Detail, "measurement_started_unix_ns")
	treatmentStart, treatmentStartOK := detailInt64(treatment.Detail, "measurement_started_unix_ns")
	if !baselineStartOK || !treatmentStartOK {
		result.InvalidReason = "paired arms are missing measurement start timestamps"
		return result
	}
	startSkew := time.Duration(absInt64(treatmentStart - baselineStart))
	result.Detail["paired_start_skew_ms"] = durationMilliseconds(startSkew)
	if startSkew > g2PairedMaxStartSkew {
		result.InvalidReason = fmt.Sprintf("paired arm measurement start skew %s exceeds %s", startSkew, g2PairedMaxStartSkew)
		return result
	}

	baselineQualified, baselineQualifiedOK := detailBool(baseline.Detail, "p99_qualified")
	treatmentQualified, treatmentQualifiedOK := detailBool(treatment.Detail, "p99_qualified")
	if !baselineQualifiedOK || !treatmentQualifiedOK || !baselineQualified || !treatmentQualified {
		result.InvalidReason = "paired P99 populations are not both qualified"
		return result
	}
	baselineP99, baselineP99OK := detailFloat64(baseline.Detail, "p99_ms")
	treatmentP99, treatmentP99OK := detailFloat64(treatment.Detail, "p99_ms")
	if !baselineP99OK || !treatmentP99OK || baselineP99 <= 0 || treatmentP99 <= 0 {
		result.InvalidReason = fmt.Sprintf("paired P99 evidence is missing or non-positive: baseline=%v treatment=%v", baseline.Detail["p99_ms"], treatment.Detail["p99_ms"])
		return result
	}

	floorMS := durationMilliseconds(floor)
	referenceP99 := math.Max(baselineP99, floorMS)
	ceilingP99 := referenceP99 * 2
	result.Detail["baseline_p99_ms"] = baselineP99
	result.Detail["treatment_p99_ms"] = treatmentP99
	result.Detail["paired_reference_p99_ms"] = referenceP99
	result.Detail["paired_p99_ceiling_ms"] = ceilingP99
	result.Detail["paired_p99_ratio"] = treatmentP99 / referenceP99
	result.Detail["paired_p99_qualified"] = true
	result.Detail["paired_floor_applied"] = baselineP99 < floorMS
	if treatmentP99 >= ceilingP99 {
		result.Failure = fmt.Sprintf("treatment P99 %.6fms does not satisfy strict matched ceiling < %.6fms (baseline %.6fms, floor %.6fms)",
			treatmentP99, ceilingP99, baselineP99, floorMS)
	}
	return result
}

func copyG2ArmDetail(destination map[string]any, prefix string, result Result) {
	destination[prefix+"_duration_ms"] = result.Duration.Milliseconds()
	destination[prefix+"_failure"] = result.Failure
	destination[prefix+"_invalid_reason"] = result.InvalidReason
	for key, value := range result.Detail {
		destination[prefix+"_"+key] = value
	}
}

func detailInt64(detail map[string]any, key string) (int64, bool) {
	switch value := detail[key].(type) {
	case int:
		return int64(value), true
	case int64:
		return value, true
	case uint64:
		if value <= math.MaxInt64 {
			return int64(value), true
		}
	}
	return 0, false
}

func detailFloat64(detail map[string]any, key string) (float64, bool) {
	switch value := detail[key].(type) {
	case float64:
		return value, true
	case float32:
		return float64(value), true
	case int:
		return float64(value), true
	case int64:
		return float64(value), true
	}
	return 0, false
}

func detailBool(detail map[string]any, key string) (bool, bool) {
	value, ok := detail[key].(bool)
	return value, ok
}

func durationMilliseconds(value time.Duration) float64 {
	return float64(value) / float64(time.Millisecond)
}

func absInt64(value int64) int64 {
	if value < 0 {
		return -value
	}
	return value
}
