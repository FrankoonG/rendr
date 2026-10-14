package packet

import (
	"errors"
	"fmt"
	"runtime/debug"
	"slices"
	"testing"

	rendr "github.com/FrankoonG/rendr/v2"
)

// TestRaceLaneSubtests (racebudget; m5-design, the C-P round 2 decision):
// under -race a heavy row runs fewer subtests, and the non-race unit and
// sweep lanes run all of them. The row checks the list each such row of
// the package ranges over (fseqJumpCases, trunkLearnSessions) against the
// binary's lane, which it reads from the binary's build information
// (-race), not from raceEnabled: an inverted race switch (race_on_test.go
// and race_off_test.go) or an inverted selection fails it in both lanes.
// It checks the selection, not the subtests the row starts: a row whose
// loop stopped ranging over its selection would pass here, so that link is
// kept by review.
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
// the build information's -race setting (buildLane), so it does not depend
// on the build-tag files that set raceEnabled.
func raceBuild(t *testing.T) bool {
	t.Helper()
	race, err := buildLane(debug.ReadBuildInfo())
	if err != nil {
		t.Fatal(err)
	}
	return race
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

// TestRaceLaneBuildInfo: buildLane reads the lane only from the go
// command's build settings and reports any other build information as an
// unknown lane instead of the non-race lane.
func TestRaceLaneBuildInfo(t *testing.T) {
	gc := debug.BuildSetting{Key: "-compiler", Value: "gc"}
	on := debug.BuildSetting{Key: "-race", Value: "true"}
	goos := debug.BuildSetting{Key: "GOOS", Value: "linux"}
	for _, c := range []struct {
		name    string
		bi      *debug.BuildInfo
		ok      bool
		race    bool
		unknown bool
	}{
		{"no information", nil, false, false, true},
		{"no go command settings", &debug.BuildInfo{Settings: []debug.BuildSetting{goos}}, true, false, true},
		{"race without -compiler", &debug.BuildInfo{Settings: []debug.BuildSetting{on}}, true, false, true},
		{"non-race", &debug.BuildInfo{Settings: []debug.BuildSetting{gc, goos}}, true, false, false},
		{"race", &debug.BuildInfo{Settings: []debug.BuildSetting{gc, on, goos}}, true, true, false},
	} {
		race, err := buildLane(c.bi, c.ok)
		if (err != nil) != c.unknown || race != c.race {
			t.Errorf("%s: buildLane = %v, %v; want race %v, unknown lane %v", c.name, race, err, c.race, c.unknown)
		}
	}
}
