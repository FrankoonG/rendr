package mux

import (
	"errors"
	"runtime/debug"
	"slices"
	"testing"
)

// TestRaceLaneSubtests (racebudget; m5-design, the C-P round 2 decision):
// under -race a heavy row runs fewer subtests, and the non-race unit and
// sweep lanes run all of them. The row checks the list each such row of
// the package ranges over (bulkLinks) against the binary's lane, which it
// reads from the binary's build information (-race), not from raceEnabled:
// an inverted race switch (race_on_test.go and race_off_test.go) or an
// inverted selection fails it in both lanes. It checks the selection, not
// the subtests the row starts: a row whose loop stopped ranging over its
// selection would pass here, so that link is kept by review.
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

	// TestMuxPacketBesideBulk (M6 I3): each bulk shape and each rate once.
	want = []string{"twoway=false/rate=1.048576e+06", "twoway=false/rate=4.194304e+06", "twoway=true/rate=1.048576e+06", "twoway=true/rate=4.194304e+06"}
	if race {
		want = []string{"twoway=false/rate=1.048576e+06", "twoway=true/rate=4.194304e+06"}
	}
	got = nil
	for _, c := range besideBulkCases() {
		got = append(got, c.name())
	}
	t.Logf("%s: TestMuxPacketBesideBulk runs %v", lane, got)
	if !slices.Equal(got, want) {
		t.Errorf("%s: TestMuxPacketBesideBulk runs %v, want %v", lane, got, want)
	}
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
