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
	}{
		{name: "default", cfg: runFlags{}, wantT3: true},
		{name: "tier4", cfg: runFlags{tier: "4"}, wantT4: true},
		{name: "tier5", cfg: runFlags{tier: "5"}, wantT5: true},
		{name: "full", cfg: runFlags{full: true}, wantT3: true, wantT4: true, wantT5: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotT3, gotT4, gotT5 := selectedTiers(tt.cfg)
			if gotT3 != tt.wantT3 || gotT4 != tt.wantT4 || gotT5 != tt.wantT5 {
				t.Fatalf("selectedTiers=%v/%v/%v want %v/%v/%v", gotT3, gotT4, gotT5, tt.wantT3, tt.wantT4, tt.wantT5)
			}
		})
	}
}
