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
	if d.ProbeInterval != time.Second {
		t.Errorf("ProbeInterval drift: got %v want 1s", d.ProbeInterval)
	}
	if d.BondPinSize != 8 {
		t.Errorf("BondPinSize drift: got %d want 8", d.BondPinSize)
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

func TestLimitsClampImmutableSchedulerBounds(t *testing.T) {
	for _, test := range []struct {
		name string
		in   Limits
		want Limits
	}{
		{
			name: "minimum accepted",
			in:   Limits{ProbeInterval: 10 * time.Millisecond, BondPinSize: 1},
			want: Limits{ProbeInterval: 10 * time.Millisecond, BondPinSize: 1},
		},
		{
			name: "probe below floor defaults",
			in:   Limits{ProbeInterval: time.Millisecond},
			want: Limits{ProbeInterval: time.Second, BondPinSize: defaultBondPinSize},
		},
		{
			name: "probe above ceiling defaults",
			in:   Limits{ProbeInterval: time.Minute},
			want: Limits{ProbeInterval: time.Second, BondPinSize: defaultBondPinSize},
		},
		{
			name: "bond pin capped by replay window",
			in:   Limits{BondPinSize: sendHistoryWindow + 1},
			want: Limits{ProbeInterval: time.Second, BondPinSize: sendHistoryWindow},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := test.in.Clamp()
			if got.ProbeInterval != test.want.ProbeInterval || got.BondPinSize != test.want.BondPinSize {
				t.Fatalf("scheduler limits = (%v,%d), want (%v,%d)", got.ProbeInterval, got.BondPinSize, test.want.ProbeInterval, test.want.BondPinSize)
			}
		})
	}

	configured := Limits{ProbeInterval: 10 * time.Millisecond, BondPinSize: 1}
	e := New(SideClient, NewClientFlowID(), configured)
	t.Cleanup(func() { _ = e.Close() })
	configured.ProbeInterval = 30 * time.Second
	configured.BondPinSize = sendHistoryWindow
	if e.limits.ProbeInterval != 10*time.Millisecond || e.limits.BondPinSize != 1 {
		t.Fatalf("engine scheduler limits mutated with caller copy: (%v,%d)", e.limits.ProbeInterval, e.limits.BondPinSize)
	}
}
