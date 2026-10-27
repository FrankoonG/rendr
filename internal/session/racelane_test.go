package session

import (
	"errors"
	"runtime/debug"
	"slices"
	"testing"
)

// TestRaceLaneSubtests (M6 I3; M5's racebudget rule): under -race
// TestPacketWakePolicy_L08 runs four of its six minimum-share subtests
// (dpShareCases says which covers which rule), and the non-race unit and
// sweep lanes run all of them, every bound unchanged. The row checks the
// list against the binary's lane, which it reads from the binary's build
// information (-race), not from dpRaceEnabled: an inverted race switch
// (pkt_race_test.go and pkt_norace_test.go) or an inverted selection fails
// it in both lanes. It checks the selection, not the subtests the row
// starts: a row whose loop stopped ranging over its selection would pass
// here, so that link is kept by review.
func TestRaceLaneSubtests(t *testing.T) {
	bi, ok := debug.ReadBuildInfo()
	race, err := buildLane(bi, ok)
	if err != nil {
		t.Fatal(err)
	}
	if dpRaceEnabled != race {
		t.Fatalf("dpRaceEnabled is %v in a binary built with -race=%v: the race switch is inverted", dpRaceEnabled, race)
	}
	lane := "non-race lane"
	want := []string{"share/2@1ms", "share/4@1ms", "share/2@100µs", "share/4@100µs", "share/8@1ms", "share/16@1ms"}
	if race {
		lane = "race lane"
		want = []string{"share/2@1ms", "share/4@100µs", "share/8@1ms", "share/16@1ms"}
	}
	var got []string
	for _, c := range dpShareCases() {
		got = append(got, c.name())
	}
	t.Logf("%s: TestPacketWakePolicy_L08 runs %v", lane, got)
	if !slices.Equal(got, want) {
		t.Errorf("%s: TestPacketWakePolicy_L08 runs %v, want %v", lane, got, want)
	}
}

// buildLane reads a binary's lane from its build information. The go
// command records -compiler in every build and -race only when it is set.
// A missing -race setting therefore means the non-race lane only when
// -compiler shows that the go command wrote the settings; without
// -compiler the lane is unknown.
func buildLane(bi *debug.BuildInfo, ok bool) (race bool, err error) {
	if !ok || bi == nil {
		return false, errors.New("the test binary has no build information: its lane is unknown")
	}
	var compiler bool
	for _, s := range bi.Settings {
		switch s.Key {
		case "-compiler":
			compiler = true
		case "-race":
			race = s.Value == "true"
		}
	}
	if !compiler {
		return false, errors.New("the test binary's build information has no -compiler setting, so the go command did not write it and its lane is unknown")
	}
	return race, nil
}
