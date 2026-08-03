package main

import "testing"

func TestDecidePhasesFullRunsEverything(t *testing.T) {
	p1, p2 := decidePhases(runFlags{full: true, tier: "4"})
	if !p1 || !p2 {
		t.Fatalf("full should run both phases, got p1=%v p2=%v", p1, p2)
	}
}

func TestSelectedTiers(t *testing.T) {
	tests := []struct {
		name   string
		cfg    runFlags
		wantT3 bool
		wantT4 bool
		wantT5 bool
		wantT6 bool
		wantT7 bool
		wantT8 bool
	}{
		{name: "default", cfg: runFlags{}, wantT3: true},
		{name: "tier4", cfg: runFlags{tier: "4"}, wantT4: true},
		{name: "tier5", cfg: runFlags{tier: "5"}, wantT5: true},
		{name: "tier6", cfg: runFlags{tier: "6"}, wantT6: true},
		{name: "tier7", cfg: runFlags{tier: "7"}, wantT7: true},
		{name: "tier8", cfg: runFlags{tier: "8"}, wantT8: true},
		{name: "tun-full-handled-before-tier-selection", cfg: runFlags{tunFull: true}},
		{name: "full", cfg: runFlags{full: true}, wantT3: true, wantT4: true, wantT5: true, wantT6: true, wantT7: true, wantT8: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotT3, gotT4, gotT5, gotT6, gotT7, gotT8 := selectedTiers(tt.cfg)
			if gotT3 != tt.wantT3 || gotT4 != tt.wantT4 || gotT5 != tt.wantT5 || gotT6 != tt.wantT6 || gotT7 != tt.wantT7 || gotT8 != tt.wantT8 {
				t.Fatalf("selectedTiers=%v/%v/%v/%v/%v/%v want %v/%v/%v/%v/%v/%v",
					gotT3, gotT4, gotT5, gotT6, gotT7, gotT8,
					tt.wantT3, tt.wantT4, tt.wantT5, tt.wantT6, tt.wantT7, tt.wantT8)
			}
		})
	}
}

func TestTunFullUnimplementedCaseFails(t *testing.T) {
	c := tunFullUnimplementedCase()
	if c.Name != "TUN-full-not-implemented" || c.Tier != "T7" || c.Failure == "" {
		t.Fatalf("bad tun-full guard case: %+v", c)
	}
}
