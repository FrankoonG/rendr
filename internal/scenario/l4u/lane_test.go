package l4u

import (
	"errors"
	"runtime/debug"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
)

// laneSize is what the heavy rows run in a lane (M5's racebudget rule,
// m6-design R1-37: the package has 15 s of the race lane; the non-race
// unit and sweep lanes run the design's full sizes). Under the race
// detector the rows keep every criterion, bound and window and run a
// smaller volume (race_on_test.go); the non-race values are the design's
// (race_off_test.go).
type laneSize struct {
	// TestL4UStreamMiniature_L39_L40_L70: the modes, Q, the kills (count
	// and spacing), the blackhole's length and T's tail after its removal.
	mlModes                         []rendr.Mode
	mlQuiet                         time.Duration
	mlKills                         int
	mlFirst, mlKill, mlDrop, mlTail time.Duration // the first kill after T's start, the kills' spacing, ...
	failBig, failSmall              float64       // TestL4UManyFlowsFailover_L27's big flow and its 63 others, datagrams per second each way
	failWarm, failObserve           time.Duration
	dnsQueries                      [3]int // TestL4UDNSChurnMiniature_L48_L72: recipe, full-table, reuse
	dnsPorts                        int    // the reuse arm's port space
	churnSessions                   int    // TestL4UChurnNoResurrection_L47: MaxSessions of both Runtimes
	churnRate                       int    // new flows per second
	churnSpan                       time.Duration
	fallbackSpan                    time.Duration // TestL4UStreamCarrierFallback_L37 (a kill every 6 s)
	bondSpan                        time.Duration // TestL4UMixedBondOversize_L37
}

// fullLane is the design's size: what the non-race lanes run.
var fullLane = laneSize{
	mlModes: []rendr.Mode{rendr.ModeSelector, rendr.ModeBond, rendr.ModeRace},
	mlQuiet: 10 * time.Second, mlKills: 4, mlFirst: 5 * time.Second, mlKill: 7 * time.Second, mlDrop: 20 * time.Second, mlTail: 10 * time.Second,
	failBig: 5000, failSmall: 50, failWarm: 10 * time.Second, failObserve: 10 * time.Second,
	dnsQueries: [3]int{20000, 4000, 4000}, dnsPorts: 4096,
	churnSessions: 1000, churnRate: 40, churnSpan: 5 * time.Minute,
	fallbackSpan: 30 * time.Second, bondSpan: 20 * time.Second,
}

// raceLane is the race lane's size: the default mode of the stream
// miniature with one kill and a shorter blackhole (the same windows and
// bounds), the 64 flows at 200 and 20 datagrams per second, a fortieth and
// a tenth of the DNS arms' queries (the reuse arm's port space scaled with
// them), and the churn's regime at a quarter of the sessions and the rate
// (10 × 64 s = 640 tombstones wanted against 500).
var raceLane = laneSize{
	mlModes: []rendr.Mode{rendr.ModeSelector},
	mlQuiet: 3 * time.Second, mlKills: 1, mlFirst: 2 * time.Second, mlKill: 5 * time.Second, mlDrop: 6 * time.Second, mlTail: 2 * time.Second,
	failBig: 200, failSmall: 20, failWarm: 4 * time.Second, failObserve: 6 * time.Second,
	dnsQueries: [3]int{500, 400, 400}, dnsPorts: 409,
	churnSessions: 250, churnRate: 10, churnSpan: 80 * time.Second,
	fallbackSpan: 14 * time.Second, bondSpan: 8 * time.Second,
}

// TestL4URaceLane (racebudget): the lane's sizes follow the binary's
// build — the race lane's under -race, the design's otherwise — read from
// the build information, not from raceEnabled, so an inverted switch
// (race_on_test.go, race_off_test.go) fails in both lanes; and the churn
// row's tombstone-eviction regime holds in both lanes.
func TestL4URaceLane(t *testing.T) {
	bi, ok := debug.ReadBuildInfo()
	race, err := buildLane(bi, ok)
	if err != nil {
		t.Fatal(err)
	}
	if raceEnabled != race {
		t.Fatalf("raceEnabled is %v in a binary built with -race=%v: the race switch is inverted", raceEnabled, race)
	}
	want := fullLane
	if race {
		want = raceLane
	}
	if lane.mlKills != want.mlKills || len(lane.mlModes) != len(want.mlModes) || lane.dnsQueries != want.dnsQueries ||
		lane.churnSpan != want.churnSpan || lane.failBig != want.failBig {
		t.Fatalf("the lane runs %+v, want %+v", lane, want)
	}
	// More tombstones wanted (rate × 64 s of TombstoneTTL) than the cap (2 ×
	// MaxSessions), and at least 30 s of churn past the cap's first fill.
	for _, l := range []laneSize{fullLane, raceLane} {
		if l.churnRate*64 <= 2*l.churnSessions || l.churnSpan < time.Duration(2*l.churnSessions/l.churnRate)*time.Second+30*time.Second {
			t.Fatalf("lane %+v: not the tombstone-eviction regime", l)
		}
	}
	t.Logf("race lane %v: %+v", race, lane)
}

// buildLane reads a binary's lane from its build information: -race is
// recorded only when set, and -compiler in every go command build, so a
// missing -race means the non-race lane only when -compiler is there.
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
		return false, errors.New("the test binary's build information has no -compiler setting: its lane is unknown")
	}
	return race, nil
}
