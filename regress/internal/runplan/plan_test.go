package runplan

import (
	"reflect"
	"strings"
	"testing"
)

func TestBuildScopes(t *testing.T) {
	tests := []struct {
		name       string
		req        Request
		wantTiers  []string
		completeP1 bool
	}{
		{name: "default", req: Request{}, wantTiers: []string{"T1", "T2", "T3"}, completeP1: true},
		{name: "phase one", req: Request{Phase: "1"}, wantTiers: []string{"T1", "T2"}, completeP1: true},
		{name: "phase two default", req: Request{Phase: "2"}, wantTiers: []string{"T3"}},
		{name: "one tier", req: Request{Tier: "6"}, wantTiers: []string{"T6"}},
		{name: "full", req: Request{Full: true}, wantTiers: []string{"T1", "T2", "T3", "T4", "T5", "T6", "T7", "T8"}, completeP1: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan, err := Build(tt.req)
			if err != nil {
				t.Fatal(err)
			}
			if got := tiers(plan.Runs); !reflect.DeepEqual(got, tt.wantTiers) {
				t.Fatalf("tiers=%v want %v", got, tt.wantTiers)
			}
			if plan.CompletePhase1 != tt.completeP1 {
				t.Fatalf("CompletePhase1=%v want %v", plan.CompletePhase1, tt.completeP1)
			}
		})
	}
}

func TestBuildExactCaseFindsOwningTier(t *testing.T) {
	plan, err := Build(Request{Phase: "2", Case: "T5.4-gvisor-unprivileged"})
	if err != nil {
		t.Fatal(err)
	}
	want := []TierRun{{Tier: "T5", Case: "T5.4-gvisor-unprivileged"}}
	if !reflect.DeepEqual(plan.Runs, want) || plan.CompletePhase1 || !plan.HasPhase2() {
		t.Fatalf("plan=%+v want runs=%+v", plan, want)
	}
}

func TestBuildResumeCrossesTierBoundaries(t *testing.T) {
	plan, err := Build(Request{Full: true, FromCase: "T5.4-gvisor-unprivileged"})
	if err != nil {
		t.Fatal(err)
	}
	want := []TierRun{
		{Tier: "T5", FromCase: "T5.4-gvisor-unprivileged"},
		{Tier: "T6"},
		{Tier: "T7"},
		{Tier: "T8"},
	}
	if !reflect.DeepEqual(plan.Runs, want) {
		t.Fatalf("runs=%+v want %+v", plan.Runs, want)
	}
	if plan.CompletePhase1 {
		t.Fatal("resuming in phase two must not claim a complete phase one")
	}
}

func TestBuildResumeWithinTier(t *testing.T) {
	plan, err := Build(Request{Tier: "8", FromCase: "T8.primary.explicit-path"})
	if err != nil {
		t.Fatal(err)
	}
	want := []TierRun{{Tier: "T8", FromCase: "T8.primary.explicit-path"}}
	if !reflect.DeepEqual(plan.Runs, want) {
		t.Fatalf("runs=%+v want %+v", plan.Runs, want)
	}
}

func TestBuildPhaseOnePartialDoesNotMintGate(t *testing.T) {
	plan, err := Build(Request{Phase: "1", FromCase: "go-test"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.CompletePhase1 {
		t.Fatal("partial phase one must not be marked complete")
	}
	if plan.HasPhase2() {
		t.Fatal("phase-one-only request unexpectedly enters phase two")
	}
}

func TestBuildFromFirstCaseKeepsCompletePhaseOne(t *testing.T) {
	plan, err := Build(Request{Full: true, FromCase: "go-vet"})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.CompletePhase1 {
		t.Fatal("resume from the first full case still covers all of phase one")
	}
}

func TestBuildRejectsInvalidOrOutOfScopeRequests(t *testing.T) {
	tests := []struct {
		name string
		req  Request
		want string
	}{
		{name: "both filters", req: Request{Case: "go-vet", FromCase: "go-test"}, want: "mutually exclusive"},
		{name: "bad phase", req: Request{Phase: "3"}, want: "invalid --phase"},
		{name: "bad tier", req: Request{Tier: "9"}, want: "invalid --tier"},
		{name: "full and tier", req: Request{Full: true, Tier: "4"}, want: "cannot be combined"},
		{name: "phase one and tier", req: Request{Phase: "1", Tier: "4"}, want: "cannot be combined"},
		{name: "case outside phase", req: Request{Phase: "1", Case: "T8.status.local-default"}, want: "no case matched"},
		{name: "case outside tier", req: Request{Tier: "6", Case: "G5"}, want: "no case matched"},
		{name: "unknown case", req: Request{Case: "missing"}, want: "no case matched"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Build(tt.req)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err=%v want substring %q", err, tt.want)
			}
		})
	}
}

func tiers(runs []TierRun) []string {
	out := make([]string, len(runs))
	for i, run := range runs {
		out[i] = run.Tier
	}
	return out
}
