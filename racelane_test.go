package rendr_test

import (
	"errors"
	"fmt"
	"runtime/debug"
	"slices"
	"testing"

	"github.com/FrankoonG/rendr/v2"
)

// TestRaceLaneSubtests (prerc; m5-design, the RI part 4 decision): under
// -race the root package's heaviest rows run a fixed subset of their
// subtests that covers each of their rules once, and the non-race unit and
// sweep lanes run all of them, every bound unchanged (R1-23 lever 1; the
// race-unit target of 270 s per pass). The row checks the lists those
// rows range over against the binary's lane, which it reads from the
// binary's build information (-race), not from loopbackRace: an inverted
// race switch (loopback_race_on_test.go and loopback_race_off_test.go) or
// an inverted selection fails it in both lanes. It checks the selections,
// not the subtests the rows start: a row whose loop stopped ranging over
// its selection would pass here, so that link is kept by review.
//
// Which subtest covers which rule in the race lane:
//   - TestPacketSmoke_CA: DatagramLink/selector and DatagramHub/bond, each
//     transport and each mode once; the rules are runSmoke's for every
//     pair (stimulus, load, integrity, counters, nothing left).
//   - TestPacketRaceSmoke_CR: DatagramHub; its race rules (delivery,
//     Duplicates, Race.Copies) are the mode's on either transport.
//   - TestUDPEndToEnd and TestPacketSmokeUDP60_CA: their race timelines
//     repeat TestPacketSmokeUDP_CA's (2,000 datagrams per second over
//     carrier/udp with carrier kills), which keeps both modes; they keep
//     one mode each: selector (the active carrier's migration) and bond
//     (each member killed once).
//   - TestLoopbackCloseWithUnreadNoReset_L05: both variants (dedicated,
//     mux), 50 of the 200 rounds; each round repeats the rule.
func TestRaceLaneSubtests(t *testing.T) {
	race := raceBuild(t)
	if loopbackRace != race {
		t.Fatalf("loopbackRace is %v in a binary built with -race=%v: the race switch is inverted", loopbackRace, race)
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
	modes := func(ms []rendr.Mode) []string {
		var out []string
		for _, m := range ms {
			out = append(out, m.String())
		}
		return out
	}

	var ca []string
	for _, c := range smokeCACases() {
		ca = append(ca, c.name())
	}
	check("TestPacketSmoke_CA", ca,
		[]string{"DatagramLink/selector", "DatagramLink/bond", "DatagramHub/selector", "DatagramHub/bond"},
		[]string{"DatagramLink/selector", "DatagramHub/bond"})

	var rs []string
	for _, tr := range raceSmokeNets() {
		rs = append(rs, tr.name)
	}
	check("TestPacketRaceSmoke_CR", rs, []string{"DatagramLink", "DatagramHub"}, []string{"DatagramHub"})

	check("TestUDPEndToEnd", modes(udpEndToEndModes()), []string{"selector", "bond"}, []string{"selector"})
	rounds := []string{fmt.Sprintf("%d rounds", loopCloseRounds())}
	check("TestLoopbackCloseWithUnreadNoReset_L05 (each variant)", rounds, []string{"200 rounds"}, []string{"50 rounds"})
	check("TestPacketSmokeUDP60_CA", modes(smokeUDP60Modes()), []string{"selector", "bond"}, []string{"bond"})
}

// raceBuild reports whether this test binary was built with -race. It reads
// the build information's -race setting (buildLane), so it does not depend
// on the build-tag files that set loopbackRace.
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
