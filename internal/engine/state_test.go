package engine

import (
	"testing"
	"time"
)

func TestDefaultLimits(t *testing.T) {
	d := DefaultLimits()
	if d.MigrationBudget != 90*time.Second {
		t.Errorf("MigrationBudget drift: got %v want 90s (CLAUDE.md hard rule #4)", d.MigrationBudget)
	}
	if d.ZombieMaxMigrations != 2 {
		t.Errorf("ZombieMaxMigrations drift: got %d want 2 (CLAUDE.md hard rule #5)", d.ZombieMaxMigrations)
	}
	if d.ZombieCooldown != 30*time.Second {
		t.Errorf("ZombieCooldown drift: got %v want 30s (CLAUDE.md hard rule #5)", d.ZombieCooldown)
	}
}

func TestLimitsClampUpper(t *testing.T) {
	got := Limits{MigrationBudget: 5 * time.Minute}.Clamp()
	if got.MigrationBudget != 90*time.Second {
		t.Errorf("over-budget not clamped: got %v want 90s", got.MigrationBudget)
	}
}

func TestLimitsClampLowerAllowed(t *testing.T) {
	got := Limits{MigrationBudget: 30 * time.Second}.Clamp()
	if got.MigrationBudget != 30*time.Second {
		t.Errorf("under-budget should be allowed: got %v want 30s", got.MigrationBudget)
	}
}

func TestLimitsClampZeroFillsDefaults(t *testing.T) {
	got := Limits{}.Clamp()
	if got != DefaultLimits() {
		t.Errorf("zero Limits should clamp to defaults: got %+v want %+v", got, DefaultLimits())
	}
}
