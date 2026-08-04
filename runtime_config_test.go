package rendr

import (
	"math"
	"strings"
	"testing"
	"time"
)

func TestDefaultRuntimeConfig(t *testing.T) {
	want := RuntimeConfig{
		Selector: SelectorTuning{
			LatencyBandRatio: 0.25,
			LatencyBandFloor: time.Millisecond,
			QualityDwell:     5 * time.Second,
			QualityCooldown:  30 * time.Second,
			PeakPromoteAfter: 600 * time.Millisecond,
			PeakReturnAfter:  800 * time.Millisecond,
		},
		Recovery: RecoveryTuning{
			MigrationBudget: 90 * time.Second,
		},
	}
	if got := DefaultRuntimeConfig(); got != want {
		t.Fatalf("DefaultRuntimeConfig() = %+v, want %+v", got, want)
	}
}

func TestNormalizeRuntimeConfigZeroMatchesDefaults(t *testing.T) {
	got, err := normalizeRuntimeConfig(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if want := DefaultRuntimeConfig(); got != want {
		t.Fatalf("normalizeRuntimeConfig(zero) = %+v, want %+v", got, want)
	}

	got, err = normalizeRuntimeConfig(DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	if want := DefaultRuntimeConfig(); got != want {
		t.Fatalf("normalizeRuntimeConfig(defaults) = %+v, want %+v", got, want)
	}
}

func TestNormalizeRuntimeConfigPreservesValidValues(t *testing.T) {
	want := RuntimeConfig{
		Selector: SelectorTuning{
			LatencyBandRatio: 0.5,
			LatencyBandFloor: 2 * time.Millisecond,
			QualityDwell:     time.Second,
			QualityCooldown:  2 * time.Second,
			PeakPromoteAfter: 300 * time.Millisecond,
			PeakReturnAfter:  400 * time.Millisecond,
		},
		Recovery: RecoveryTuning{
			MigrationBudget: 45 * time.Second,
		},
	}
	got, err := normalizeRuntimeConfig(want)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("normalizeRuntimeConfig(custom) = %+v, want %+v", got, want)
	}
}

func TestNormalizeRuntimeConfigDefaultsEachZeroField(t *testing.T) {
	custom := RuntimeConfig{
		Selector: SelectorTuning{
			LatencyBandRatio: 0.5,
			LatencyBandFloor: 2 * time.Millisecond,
			QualityDwell:     time.Second,
			QualityCooldown:  2 * time.Second,
			PeakPromoteAfter: 300 * time.Millisecond,
			PeakReturnAfter:  400 * time.Millisecond,
		},
		Recovery: RecoveryTuning{MigrationBudget: 45 * time.Second},
	}
	defaults := DefaultRuntimeConfig()
	tests := []struct {
		name string
		zero func(*RuntimeConfig)
		want func(RuntimeConfig) RuntimeConfig
	}{
		{
			name: "latency band ratio",
			zero: func(c *RuntimeConfig) { c.Selector.LatencyBandRatio = 0 },
			want: func(c RuntimeConfig) RuntimeConfig {
				c.Selector.LatencyBandRatio = defaults.Selector.LatencyBandRatio
				return c
			},
		},
		{
			name: "latency band floor",
			zero: func(c *RuntimeConfig) { c.Selector.LatencyBandFloor = 0 },
			want: func(c RuntimeConfig) RuntimeConfig {
				c.Selector.LatencyBandFloor = defaults.Selector.LatencyBandFloor
				return c
			},
		},
		{
			name: "quality dwell",
			zero: func(c *RuntimeConfig) { c.Selector.QualityDwell = 0 },
			want: func(c RuntimeConfig) RuntimeConfig {
				c.Selector.QualityDwell = defaults.Selector.QualityDwell
				return c
			},
		},
		{
			name: "quality cooldown",
			zero: func(c *RuntimeConfig) { c.Selector.QualityCooldown = 0 },
			want: func(c RuntimeConfig) RuntimeConfig {
				c.Selector.QualityCooldown = defaults.Selector.QualityCooldown
				return c
			},
		},
		{
			name: "peak promote after",
			zero: func(c *RuntimeConfig) { c.Selector.PeakPromoteAfter = 0 },
			want: func(c RuntimeConfig) RuntimeConfig {
				c.Selector.PeakPromoteAfter = defaults.Selector.PeakPromoteAfter
				return c
			},
		},
		{
			name: "peak return after",
			zero: func(c *RuntimeConfig) { c.Selector.PeakReturnAfter = 0 },
			want: func(c RuntimeConfig) RuntimeConfig {
				c.Selector.PeakReturnAfter = defaults.Selector.PeakReturnAfter
				return c
			},
		},
		{
			name: "migration budget",
			zero: func(c *RuntimeConfig) { c.Recovery.MigrationBudget = 0 },
			want: func(c RuntimeConfig) RuntimeConfig {
				c.Recovery.MigrationBudget = defaults.Recovery.MigrationBudget
				return c
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := custom
			tt.zero(&input)
			got, err := normalizeRuntimeConfig(input)
			if err != nil {
				t.Fatal(err)
			}
			if want := tt.want(custom); got != want {
				t.Fatalf("normalized config = %+v, want %+v", got, want)
			}
		})
	}
}

func TestNormalizeRuntimeConfigRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name  string
		cfg   RuntimeConfig
		field string
	}{
		{
			name:  "negative ratio",
			cfg:   RuntimeConfig{Selector: SelectorTuning{LatencyBandRatio: -0.01}},
			field: "Selector.LatencyBandRatio",
		},
		{
			name:  "NaN ratio",
			cfg:   RuntimeConfig{Selector: SelectorTuning{LatencyBandRatio: math.NaN()}},
			field: "Selector.LatencyBandRatio",
		},
		{
			name:  "positive infinite ratio",
			cfg:   RuntimeConfig{Selector: SelectorTuning{LatencyBandRatio: math.Inf(1)}},
			field: "Selector.LatencyBandRatio",
		},
		{
			name:  "negative infinite ratio",
			cfg:   RuntimeConfig{Selector: SelectorTuning{LatencyBandRatio: math.Inf(-1)}},
			field: "Selector.LatencyBandRatio",
		},
		{
			name:  "unreasonable ratio",
			cfg:   RuntimeConfig{Selector: SelectorTuning{LatencyBandRatio: math.Nextafter(1, 2)}},
			field: "Selector.LatencyBandRatio",
		},
		{
			name:  "negative latency floor",
			cfg:   RuntimeConfig{Selector: SelectorTuning{LatencyBandFloor: -time.Nanosecond}},
			field: "Selector.LatencyBandFloor",
		},
		{
			name:  "negative quality dwell",
			cfg:   RuntimeConfig{Selector: SelectorTuning{QualityDwell: -time.Nanosecond}},
			field: "Selector.QualityDwell",
		},
		{
			name:  "negative quality cooldown",
			cfg:   RuntimeConfig{Selector: SelectorTuning{QualityCooldown: -time.Nanosecond}},
			field: "Selector.QualityCooldown",
		},
		{
			name:  "negative peak promote delay",
			cfg:   RuntimeConfig{Selector: SelectorTuning{PeakPromoteAfter: -time.Nanosecond}},
			field: "Selector.PeakPromoteAfter",
		},
		{
			name:  "negative peak return delay",
			cfg:   RuntimeConfig{Selector: SelectorTuning{PeakReturnAfter: -time.Nanosecond}},
			field: "Selector.PeakReturnAfter",
		},
		{
			name:  "negative migration budget",
			cfg:   RuntimeConfig{Recovery: RecoveryTuning{MigrationBudget: -time.Nanosecond}},
			field: "Recovery.MigrationBudget",
		},
		{
			name:  "migration budget above hard maximum",
			cfg:   RuntimeConfig{Recovery: RecoveryTuning{MigrationBudget: 90*time.Second + time.Nanosecond}},
			field: "Recovery.MigrationBudget",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeRuntimeConfig(tt.cfg)
			if err == nil {
				t.Fatalf("normalizeRuntimeConfig(%+v) = %+v, want error", tt.cfg, got)
			}
			if !strings.Contains(err.Error(), tt.field) {
				t.Fatalf("error %q does not identify %s", err, tt.field)
			}
		})
	}
}

func TestNormalizeRuntimeConfigAcceptsBoundaries(t *testing.T) {
	want := RuntimeConfig{
		Selector: SelectorTuning{
			LatencyBandRatio: 1,
			LatencyBandFloor: time.Nanosecond,
			QualityDwell:     time.Nanosecond,
			QualityCooldown:  time.Nanosecond,
			PeakPromoteAfter: time.Nanosecond,
			PeakReturnAfter:  time.Nanosecond,
		},
		Recovery: RecoveryTuning{MigrationBudget: 90 * time.Second},
	}
	got, err := normalizeRuntimeConfig(want)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("normalizeRuntimeConfig(boundaries) = %+v, want %+v", got, want)
	}
}

func TestRuntimeConfigUsesDefensiveValueSemantics(t *testing.T) {
	want := DefaultRuntimeConfig()
	mutated := DefaultRuntimeConfig()
	mutated.Selector.LatencyBandRatio = 1
	mutated.Recovery.MigrationBudget = time.Second
	if got := DefaultRuntimeConfig(); got != want {
		t.Fatalf("mutating a returned default changed later defaults: got %+v want %+v", got, want)
	}

	input := RuntimeConfig{Selector: SelectorTuning{QualityDwell: time.Second}}
	before := input
	normalized, err := normalizeRuntimeConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	if input != before {
		t.Fatalf("normalization mutated input: got %+v want %+v", input, before)
	}
	normalized.Selector.QualityDwell = 2 * time.Second
	again, err := normalizeRuntimeConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	if again.Selector.QualityDwell != time.Second {
		t.Fatalf("mutating normalized result changed input: got dwell %v want 1s", again.Selector.QualityDwell)
	}
}
