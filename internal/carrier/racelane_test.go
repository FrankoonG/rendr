package carrier

import (
	"errors"
	"runtime/debug"
	"slices"
	"testing"
)

// TestRaceLaneSubtests (prerc; m5-design, the RI part 4 decision): under
// -race the carrier package's heaviest estimator rows run a fixed subset
// of their subtests that covers each of their rules once, and the non-race
// unit and sweep lanes run all of them, every bound unchanged (R1-23 lever
// 1; the race-unit target of 270 s per pass). The row checks the lists
// those rows range over (duplexBothWaysCases, longRTTCases, whose comments
// say which subtest covers which rule) against the binary's lane, which it
// reads from the binary's build information (-race), not from carrierRace:
// an inverted race switch (carrier_race_on_test.go and
// carrier_race_off_test.go) or an inverted selection fails it in both
// lanes. It checks the selections, not the subtests the rows start: a row
// whose loop stopped ranging over its selection would pass here, so that
// link is kept by review.
func TestRaceLaneSubtests(t *testing.T) {
	race := raceBuild(t)
	if carrierRace != race {
		t.Fatalf("carrierRace is %v in a binary built with -race=%v: the race switch is inverted", carrierRace, race)
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

	var duplex []string
	for _, tc := range duplexBothWaysCases() {
		duplex = append(duplex, tc.name())
	}
	check("TestDuplexKeepsBothDirections_L15", duplex,
		[]string{
			"rtt20ms/4MiBps/buf2048KiB/6s",
			"rtt20ms/2MiBps/buf128KiB/6s",
			"rtt20ms/2MiBps/buf128KiB/6s/late100ms",
			"rtt20ms/2MiBps/buf128KiB/6s/dlate292ms",
			"rtt20ms/2MiBps/buf128KiB/6s/stalls",
			"rtt100ms/16MiBps/buf65536KiB/6s",
			"rtt20ms/4MiBps/buf2048KiB/1m0s",
			"rtt20ms/2MiBps/buf2048KiB/1m0s",
			"rtt20ms/1MiBps/buf1024KiB/1m0s",
			"rtt20ms/8MiBps/buf8192KiB/1m0s",
		},
		[]string{
			"rtt20ms/4MiBps/buf2048KiB/6s",
			"rtt20ms/2MiBps/buf128KiB/6s",
			"rtt20ms/2MiBps/buf128KiB/6s/late100ms",
			"rtt20ms/2MiBps/buf128KiB/6s/dlate292ms",
			"rtt20ms/2MiBps/buf128KiB/6s/stalls",
			"rtt20ms/1MiBps/buf1024KiB/1m0s",
		})

	var long []string
	for _, tc := range longRTTCases() {
		long = append(long, tc.name())
	}
	check("TestCapLimitedFlowLongRTT_L15_L32", long,
		[]string{
			"rtt50ms/unlimited", "rtt100ms/unlimited", "rtt102ms/unlimited", "rtt105ms/unlimited",
			"rtt200ms/unlimited", "rtt400ms/unlimited",
			"rtt100ms/16MiBps", "rtt105ms/16MiBps", "rtt400ms/8MiBps",
			"rtt100ms/16MiBps/duplex", "rtt400ms/8MiBps/duplex",
		},
		[]string{"rtt100ms/unlimited", "rtt102ms/unlimited", "rtt105ms/unlimited", "rtt100ms/16MiBps", "rtt400ms/8MiBps/duplex"})
}

// raceBuild reports whether this test binary was built with -race. It reads
// the build information's -race setting (buildLane), so it does not depend
// on the build-tag files that set carrierRace.
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
