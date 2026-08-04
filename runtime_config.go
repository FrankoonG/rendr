package rendr

import (
	"fmt"
	"math"
	"time"
)

const (
	defaultLatencyBandRatio = 0.25
	maxLatencyBandRatio     = 1.0

	defaultLatencyBandFloor = time.Millisecond
	defaultQualityDwell     = 5 * time.Second
	defaultQualityCooldown  = 30 * time.Second
	defaultPeakPromoteAfter = 600 * time.Millisecond
	defaultPeakReturnAfter  = 800 * time.Millisecond
	maxMigrationBudget      = 90 * time.Second
)

// RuntimeConfig contains the process-wide tuning shared by rendr sessions.
// It intentionally contains only value fields so a Runtime can retain an
// immutable defensive copy. A zero-valued field selects its documented
// default.
type RuntimeConfig struct {
	Selector SelectorTuning
	Recovery RecoveryTuning
}

// SelectorTuning controls quality and peak-transfer decisions made by
// selector targets. Negative durations are rejected, and these delays never
// postpone failover from a dead target.
type SelectorTuning struct {
	// LatencyBandRatio is the maximum relative latency spread considered
	// equivalent. Zero selects 0.25; nonzero values must be finite and in
	// the range (0, 1].
	LatencyBandRatio float64
	// LatencyBandFloor is the absolute floor for near-zero latency samples.
	// Zero selects 1ms.
	LatencyBandFloor time.Duration
	// QualityDwell is how long a quality candidate must remain preferable.
	// Zero selects 5s.
	QualityDwell time.Duration
	// QualityCooldown is the minimum interval between quality migrations.
	// Zero selects 30s and never delays failover from a dead target.
	QualityCooldown time.Duration
	// PeakPromoteAfter is the sustained peak-load window before promotion.
	// Zero selects 600ms.
	PeakPromoteAfter time.Duration
	// PeakReturnAfter is the sustained non-peak window before return.
	// Zero selects 800ms.
	PeakReturnAfter time.Duration
}

// RecoveryTuning controls how long sessions may remain suspended while all
// targets are unavailable. Negative durations are rejected.
type RecoveryTuning struct {
	// MigrationBudget is the maximum suspension time with no available
	// target. Zero selects 90s; values above the 90s hard cap are rejected.
	MigrationBudget time.Duration
}

// DefaultRuntimeConfig returns the runtime defaults. The returned value owns
// all of its state and may be changed by the caller without affecting later
// calls or a config already copied by a Runtime.
func DefaultRuntimeConfig() RuntimeConfig {
	return RuntimeConfig{
		Selector: SelectorTuning{
			LatencyBandRatio: defaultLatencyBandRatio,
			LatencyBandFloor: defaultLatencyBandFloor,
			QualityDwell:     defaultQualityDwell,
			QualityCooldown:  defaultQualityCooldown,
			PeakPromoteAfter: defaultPeakPromoteAfter,
			PeakReturnAfter:  defaultPeakReturnAfter,
		},
		Recovery: RecoveryTuning{
			MigrationBudget: maxMigrationBudget,
		},
	}
}

// normalizeRuntimeConfig validates cfg and fills zero-valued fields. cfg is
// accepted by value so normalization cannot mutate caller-owned state.
func normalizeRuntimeConfig(cfg RuntimeConfig) (RuntimeConfig, error) {
	ratio := cfg.Selector.LatencyBandRatio
	if math.IsNaN(ratio) || math.IsInf(ratio, 0) {
		return RuntimeConfig{}, invalidRuntimeConfig("Selector.LatencyBandRatio", "must be finite")
	}
	if ratio < 0 {
		return RuntimeConfig{}, invalidRuntimeConfig("Selector.LatencyBandRatio", "must not be negative")
	}
	if ratio > maxLatencyBandRatio {
		return RuntimeConfig{}, invalidRuntimeConfig("Selector.LatencyBandRatio", "must not exceed 1")
	}

	durations := []struct {
		name  string
		value time.Duration
	}{
		{"Selector.LatencyBandFloor", cfg.Selector.LatencyBandFloor},
		{"Selector.QualityDwell", cfg.Selector.QualityDwell},
		{"Selector.QualityCooldown", cfg.Selector.QualityCooldown},
		{"Selector.PeakPromoteAfter", cfg.Selector.PeakPromoteAfter},
		{"Selector.PeakReturnAfter", cfg.Selector.PeakReturnAfter},
		{"Recovery.MigrationBudget", cfg.Recovery.MigrationBudget},
	}
	for _, field := range durations {
		if field.value < 0 {
			return RuntimeConfig{}, invalidRuntimeConfig(field.name, "must not be negative")
		}
	}
	if cfg.Recovery.MigrationBudget > maxMigrationBudget {
		return RuntimeConfig{}, invalidRuntimeConfig("Recovery.MigrationBudget", "must not exceed 90s")
	}

	defaults := DefaultRuntimeConfig()
	if cfg.Selector.LatencyBandRatio == 0 {
		cfg.Selector.LatencyBandRatio = defaults.Selector.LatencyBandRatio
	}
	if cfg.Selector.LatencyBandFloor == 0 {
		cfg.Selector.LatencyBandFloor = defaults.Selector.LatencyBandFloor
	}
	if cfg.Selector.QualityDwell == 0 {
		cfg.Selector.QualityDwell = defaults.Selector.QualityDwell
	}
	if cfg.Selector.QualityCooldown == 0 {
		cfg.Selector.QualityCooldown = defaults.Selector.QualityCooldown
	}
	if cfg.Selector.PeakPromoteAfter == 0 {
		cfg.Selector.PeakPromoteAfter = defaults.Selector.PeakPromoteAfter
	}
	if cfg.Selector.PeakReturnAfter == 0 {
		cfg.Selector.PeakReturnAfter = defaults.Selector.PeakReturnAfter
	}
	if cfg.Recovery.MigrationBudget == 0 {
		cfg.Recovery.MigrationBudget = defaults.Recovery.MigrationBudget
	}
	return cfg, nil
}

func invalidRuntimeConfig(field, reason string) error {
	return fmt.Errorf("rendr: invalid RuntimeConfig.%s: %s", field, reason)
}
