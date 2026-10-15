package adversarial

import (
	"errors"
	"runtime/debug"
	"slices"
	"strings"
	"testing"

	rendr "github.com/FrankoonG/rendr/v2"
)

// TestRaceLaneSubtests (prerc; m5-design, the RI part 4 decision): under
// -race the package's heaviest rows run a fixed subset of their setups
// that covers each of their rules once, and the non-race unit and sweep
// lanes run all of them, every bound unchanged (R1-23 lever 1; the
// race-unit target of 270 s per pass). The row checks the lists those rows
// range over (bitFlipRows, replayedFrameSetups, flipsAreLossSetups,
// writerMutationSetups, datagramReplaySetups, droppedFrameRows,
// duplicatedFrameRows, spliceRows, whose comments say
// which subtest covers which rule) against the binary's lane, which it
// reads from the binary's build information (-race), not from raceEnabled:
// an inverted race switch (race_on_test.go and race_off_test.go) or an
// inverted selection fails it in both lanes. It checks the selections, not
// the subtests the rows start: a row whose loop stopped ranging over its
// selection would pass here, so that link is kept by review (the frame and
// cut rows look their subtests' setups up by name, rowSetups, which fails
// the row on a name it does not list).
func TestRaceLaneSubtests(t *testing.T) {
	race := raceBuild(t)
	if raceEnabled != race {
		t.Fatalf("raceEnabled is %v in a binary built with -race=%v: the race switch is inverted", raceEnabled, race)
	}
	lane := "non-race lane"
	if race {
		lane = "race lane"
	}
	all := names(setups())
	check := func(row string, got, raceSet []string) {
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

	check("TestAdvReplayedFrame_L43", names(replayedFrameSetups()), []string{"selector", "bond", "race", "mux-bond"})
	check("TestAdvDatagramFlipsAreLoss_L43", names(flipsAreLossSetups()), []string{"selector", "bond", "race", "mux-selector"})
	check("TestAdvWriterBufferMutation_L43", names(writerMutationSetups()), []string{"selector", "bond", "race", "mux-race"})
	check("TestAdvDatagramReplay_L43_L39", names(datagramReplaySetups()), []string{"selector", "bond", "race", "mux-bond"})
	// The rows' subtests find their setups by name (rowSetups), so the
	// lists are checked by name too: each subtest's own, and rowSetups's
	// answer for it.
	for _, f := range []struct {
		row     string
		rows    []setupRow
		raceSet map[string][]string
	}{
		{"TestAdvDroppedFrame_L43", droppedFrameRows(),
			map[string][]string{"DATA": {"selector", "mux-bond"}, "ACK": {"bond", "mux-race"}, "SCHED": {"race", "mux-selector"}}},
		{"TestAdvDuplicatedFrame_L43", duplicatedFrameRows(),
			map[string][]string{"DATA": {"selector", "mux-bond"}, "ACK": {"race", "mux-selector"}}},
		{"TestAdvSpliceTwoSessions_L41_L43", spliceRows(),
			map[string][]string{"boundary": {"selector", "mux-bond"}, "midframe": {"race", "mux-selector"}}},
	} {
		modes := map[rendr.Mode]bool{}
		if len(f.rows) != len(f.raceSet) {
			t.Errorf("%s has %d subtests, want %d", f.row, len(f.rows), len(f.raceSet))
		}
		for _, r := range f.rows {
			raceSet, ok := f.raceSet[r.name]
			if !ok {
				t.Errorf("%s has an unknown subtest %q", f.row, r.name)
				continue
			}
			check(f.row+"/"+r.name, names(r.setups), raceSet)
			check(f.row+"/"+r.name+" (rowSetups)", names(rowSetups(t, f.rows, r.name)), raceSet)
			var mux int
			for _, s := range r.setups {
				modes[s.mode] = true
				if s.mux {
					mux++
				}
			}
			// The race subset of each subtest: one dedicated carrier and one
			// MUX trunk.
			if race && (len(r.setups) != 2 || mux != 1) {
				t.Errorf("race lane: %s/%s runs %v, want one dedicated and one MUX setup", f.row, r.name, names(r.setups))
			}
		}
		if len(modes) != 3 {
			t.Errorf("%s: %s's subtests run the modes %v, want all three", lane, f.row, modes)
		}
	}

	// TestAdvBitFlipRegions_L41_L43: every (frame kind, region) once; under
	// -race one setup per subtest, each kind's setups all run, and the
	// handle regions, whose expectation differs on a MUX trunk, run on a
	// dedicated carrier and on a MUX trunk among the stream kinds.
	kinds := map[string][]string{}
	seen := map[string]bool{}
	handle := map[string][2]bool{} // region → {dedicated, MUX} among the stream kinds
	for _, r := range bitFlipRows() {
		if seen[r.name] {
			t.Errorf("TestAdvBitFlipRegions_L41_L43/%s twice", r.name)
		}
		seen[r.name] = true
		full := all
		if strings.HasSuffix(r.kind, "/DETACH") {
			full = names(muxSetups())
		}
		got := names(r.setups)
		t.Logf("%s: TestAdvBitFlipRegions_L41_L43/%s runs %v", lane, r.name, got)
		switch {
		case !race && !slices.Equal(got, full):
			t.Errorf("non-race lane: TestAdvBitFlipRegions_L41_L43/%s runs %v, want %v", r.name, got, full)
		case race && len(got) != 1:
			t.Errorf("race lane: TestAdvBitFlipRegions_L41_L43/%s runs %v, want one setup", r.name, got)
		}
		for _, n := range got {
			if !slices.Contains(kinds[r.kind], n) {
				kinds[r.kind] = append(kinds[r.kind], n)
			}
		}
		if r.region.mux != nil && strings.HasPrefix(r.kind, "stream/") {
			h := handle[r.region.name]
			for _, s := range r.setups {
				h[btoi(s.mux)] = true
			}
			handle[r.region.name] = h
		}
	}
	if len(seen) != 8*len(regions) {
		t.Errorf("TestAdvBitFlipRegions_L41_L43 has %d subtests, want %d (eight frame kinds × %d regions)", len(seen), 8*len(regions), len(regions))
	}
	for kind, got := range kinds {
		full := all
		if strings.HasSuffix(kind, "/DETACH") {
			full = names(muxSetups())
		}
		if slices.Sort(got); !slices.Equal(got, sorted(full)) {
			t.Errorf("%s: TestAdvBitFlipRegions_L41_L43's %s subtests run %v, want each of %v", lane, kind, got, full)
		}
	}
	for _, r := range regions {
		if r.mux == nil {
			continue
		}
		if h := handle[r.name]; !h[0] || !h[1] {
			t.Errorf("%s: TestAdvBitFlipRegions_L41_L43's %s region runs on a dedicated carrier %v and on a MUX trunk %v among the stream kinds, want both", lane, r.name, h[0], h[1])
		}
	}
}

// names returns the setups' names, in order.
func names(ss []setup) []string {
	var out []string
	for _, s := range ss {
		out = append(out, s.name)
	}
	return out
}

// sorted returns a sorted copy of ss.
func sorted(ss []string) []string {
	out := slices.Clone(ss)
	slices.Sort(out)
	return out
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
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
