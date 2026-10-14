package mux

import (
	"runtime/debug"
	"slices"
	"testing"
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
	want := []string{"deep", "shallow", "shallow-late6ms"}
	if race {
		lane = "race lane"
		want = []string{"deep", "shallow"}
	}
	var got []string
	for _, l := range bulkLinks() {
		got = append(got, l.name)
	}
	t.Logf("%s: TestMuxBulkBothWaysKeepsTheLink runs %v", lane, got)
	if !slices.Equal(got, want) {
		t.Errorf("%s: TestMuxBulkBothWaysKeepsTheLink runs %v, want %v", lane, got, want)
	}
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
