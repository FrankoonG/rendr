package packet

import (
	"fmt"
	"runtime/debug"
	"slices"
	"testing"

	rendr "github.com/FrankoonG/rendr/v2"
)

// TestRaceLaneSubtests (racebudget; m5-design, the C-P round 2 decision):
// under -race a heavy row runs fewer subtests, and the non-race unit and
// sweep lanes run all of them. The row lists the subtests each such row of
// the package runs in this binary's lane and checks them against the lane,
// which it reads from the binary's build information (-race), not from
// raceEnabled: an inverted race switch (race_on_test.go and
// race_off_test.go) or an inverted selection fails it in both lanes.
func TestRaceLaneSubtests(t *testing.T) {
	race := raceBuild(t)
	if raceEnabled != race {
		t.Fatalf("raceEnabled is %v in a binary built with -race=%v: the race switch is inverted", raceEnabled, race)
	}
	lane := "non-race lane"
	if race {
		lane = "race lane"
	}
	check := func(row string, got, all, raceSet []string) {
		t.Helper()
		want := all
		if race {
			want = raceSet
		}
		t.Logf("%s: %s runs %v", lane, row, got)
		if !slices.Equal(got, want) {
			t.Errorf("%s: %s runs %v, want %v", lane, row, got, want)
		}
	}

	cases := fseqJumpCases()
	var names []string
	modes, dirs := map[rendr.Mode]int{}, map[bool]int{}
	for _, c := range cases {
		names = append(names, c.name())
		modes[c.mode]++
		dirs[c.both]++
	}
	check("TestPacketFseqJumpRecovery_L43", names,
		[]string{"selector/down", "selector/both", "bond/down", "bond/both"},
		[]string{"selector/both", "bond/down"})
	// The race lane's subset covers each of the row's rules once: each mode
	// and each direction exactly once (fseqJumpCases).
	if race && (len(cases) != 2 || modes[rendr.ModeSelector] != 1 || modes[rendr.ModeBond] != 1 || dirs[false] != 1 || dirs[true] != 1) {
		t.Errorf("race lane: TestPacketFseqJumpRecovery_L43's subtests %v do not cover selector, bond, down and both once each", names)
	}

	var sessions []string
	for _, n := range trunkLearnSessions() {
		sessions = append(sessions, fmt.Sprintf("sessions=%d", n))
	}
	check("TestPacketTrunkCloseEverySessionLearns_L45_L39", sessions,
		[]string{"sessions=8", "sessions=32", "sessions=256"},
		[]string{"sessions=8", "sessions=32"})
}

// raceBuild reports whether this test binary was built with -race. It reads
// the build information's -race setting, so it does not depend on the
// build-tag files that set raceEnabled.
func raceBuild(t *testing.T) bool {
	t.Helper()
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("the test binary has no build information: its lane is unknown")
	}
	for _, s := range bi.Settings {
		if s.Key == "-race" {
			return s.Value == "true"
		}
	}
	return false
}
