// Package smoke implements rendr's own G1-G5 acceptance contracts at
// "smoke" scale: small enough to fit phase 1 (T2) in <8min, large
// enough to catch real engine-layer regressions before phase 2
// burns CI time on a longer matrix.
//
// Each G has a Run* function that returns a Result. The Result is
// suitable for direct conversion to report.Case (caller decides the
// Tier/Name presentation). The smoke harness keeps allocations and
// goroutines bounded; nothing here is meant for nightly long-runs
// (those live in regress/internal/longrun for T4).
package smoke

import "time"

// Result is the common outcome shape for a single smoke run.
type Result struct {
	Name     string
	Duration time.Duration
	// Empty Failure means the run passed all internal asserts.
	Failure string
	// InvalidReason means the harness did not establish its stimulus,
	// target load, or minimum evidence. Invalid is distinct from a
	// product failure, but both must fail a mandatory release gate.
	InvalidReason string
	// Detail is free-form context for the report (throughput, RTT
	// percentiles, migration count, etc.). Each Run* function
	// documents its keys.
	Detail map[string]any
}

// FromError builds a failed Result from an error.
func FromError(name string, dur time.Duration, err error) Result {
	r := Result{Name: name, Duration: dur, Detail: map[string]any{}}
	if err != nil {
		r.Failure = err.Error()
	}
	return r
}
