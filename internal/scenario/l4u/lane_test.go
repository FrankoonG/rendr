package l4u

import (
	"errors"
	"reflect"
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
	silentWarm, silentDrop          time.Duration // TestL4UBondSilentMemberKeepsStream_L39: the streaming before the blackhole, the blackhole (at least recoveryBound)
	silentTail                      time.Duration // the judged span after the blackhole's removal (at least a second past the rejoin)
	replySpan, replyFlip            time.Duration // TestL4UFirstReplyUnderChurn_L12_L72: the load's span and the event's time
	massRate                        int           // TestMuxDgramMassRejoinAfterBlackhole_L27_L72: new flows per second
	massBefore, massAfter           time.Duration // its load before the DROP and after it
	massSessions                    int           // its sessions on the dropped path at the DROP (at least)
}

// fullLane is the design's size: what the non-race lanes run.
var fullLane = laneSize{
	mlModes: []rendr.Mode{rendr.ModeSelector, rendr.ModeBond, rendr.ModeRace},
	mlQuiet: 10 * time.Second, mlKills: 4, mlFirst: 5 * time.Second, mlKill: 7 * time.Second, mlDrop: 20 * time.Second, mlTail: 10 * time.Second,
	failBig: 5000, failSmall: 50, failWarm: 10 * time.Second, failObserve: 10 * time.Second,
	dnsQueries: [3]int{20000, 4000, 4000}, dnsPorts: 4096,
	churnSessions: 1000, churnRate: 40, churnSpan: 5 * time.Minute,
	fallbackSpan: 30 * time.Second, bondSpan: 20 * time.Second,
	silentWarm: 3 * time.Second, silentDrop: 6 * time.Second, silentTail: mlSpanAfter,
	replySpan: 30 * time.Second, replyFlip: 15 * time.Second,
	massRate: 300, massBefore: 7700 * time.Millisecond, massAfter: 8 * time.Second, massSessions: 2200,
}

// raceLane is the race lane's size (every rule covered once, every window
// and bound unchanged): the default mode of the stream miniature, Q 2 s,
// one kill at T + 1 s, the blackhole 3 s later for 5 s (the
// death-detection bound) and T's end 1 s after its removal; the 64 flows
// at 200 and 10 datagrams per second; an eightieth and three fortieths of
// the DNS arms' queries, the reuse arm's 300 over 250 ports (dnsArms:
// about a fifth of them land on a live flow); the churn's regime at a
// sixteenth of the sessions and 3/40 of the rate (3 × 64 s = 192
// tombstones wanted against 128, 75 s of churn); one kill of the stream
// fallback (8 s) and 4 s of the mixed bond; the bond's silent member after
// 1 s of streaming, blackholed for 5 s (the death-detection bound) and
// judged until 1 s after the blackhole's removal or the member's rejoin,
// whichever is later; the first-reply row's 300 flows per second for 2 s
// with its event at 0.3 s (all of it inside the build-up spans: its
// run-wide median and build-up p99 are judged, its steady windows only in
// the full lane); the mass rejoin's 50 flows per second, 3.2 s before its
// DROP (≈ 160 sessions on 3 trunks of the dropped path) and 5.5 s after it
// (its late flows from tDead + 1 s on).
var raceLane = laneSize{
	mlModes: []rendr.Mode{rendr.ModeSelector},
	mlQuiet: 2 * time.Second, mlKills: 1, mlFirst: time.Second, mlKill: 3 * time.Second, mlDrop: recoveryBound, mlTail: time.Second,
	failBig: 200, failSmall: 10, failWarm: 4 * time.Second, failObserve: 6 * time.Second,
	dnsQueries: [3]int{250, 300, 300}, dnsPorts: 250,
	churnSessions: 64, churnRate: 3, churnSpan: 75 * time.Second,
	fallbackSpan: 8 * time.Second, bondSpan: 4 * time.Second,
	silentWarm: time.Second, silentDrop: recoveryBound, silentTail: time.Second,
	replySpan: 2 * time.Second, replyFlip: 300 * time.Millisecond,
	massRate: 50, massBefore: 3200 * time.Millisecond, massAfter: 5500 * time.Millisecond, massSessions: 150,
}

// TestL4URaceLane (racebudget): the lane's sizes follow the binary's
// build — the race lane's under -race, the design's otherwise — read from
// the build information, not from raceEnabled, so an inverted switch
// (race_on_test.go, race_off_test.go) fails in both lanes; and in both
// lanes the churn row's tombstone-eviction regime holds and the rows'
// spans hold their windows (a blackhole lasts at least the death-detection
// bound, the silent member is chosen from a full second of streaming, a
// kill's judged span starts inside T, the first-reply row has flows opened
// after its ranking moved, the mass rejoin has its sessions at the DROP and
// late flows after its verdicts).
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
	if !reflect.DeepEqual(lane, want) {
		t.Fatalf("the lane runs %+v, want %+v", lane, want)
	}
	// More tombstones wanted (rate × 64 s of TombstoneTTL) than the cap (2 ×
	// MaxSessions), and at least 30 s of churn past the cap's first fill.
	for _, l := range []laneSize{fullLane, raceLane} {
		if l.churnRate*64 <= 2*l.churnSessions || l.churnSpan < time.Duration(2*l.churnSessions/l.churnRate)*time.Second+30*time.Second {
			t.Fatalf("lane %+v: not the tombstone-eviction regime", l)
		}
		if l.mlDrop < recoveryBound || l.silentDrop < recoveryBound || l.silentWarm < time.Second || l.mlFirst < mlSpanBefore {
			t.Fatalf("lane %+v: a blackhole shorter than %v, less than a second of streaming before the silent member's, or a kill within %v of T's start", l, recoveryBound, mlSpanBefore)
		}
		if l.replyFlip < 0 || l.replyFlip+replyMoved+time.Second/2 > l.replySpan {
			t.Fatalf("lane %+v: the first-reply row's event leaves no flows opened %v after it", l, replyMoved)
		}
		// The mass rejoin: its sessions at the DROP, and late flows after
		// the last death verdict (≤ DeadMax) + 1 s.
		if time.Duration(l.massRate)*l.massBefore < time.Duration(l.massSessions)*time.Second || l.massAfter < kitDeadMax+time.Second+time.Second/2 {
			t.Fatalf("lane %+v: the mass rejoin opens fewer than %d sessions before its DROP, or no flow after its verdicts + 1 s", l, l.massSessions)
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
