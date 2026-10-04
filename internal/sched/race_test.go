package sched

import (
	"testing"
	"time"
)

// slots models the dialer's per-factory slots for race tests.
type slots []Cadence

func (s slots) ready(now time.Time) func(int) (bool, time.Time) {
	return func(i int) (bool, time.Time) { return s[i].Ready(now) }
}

// TestRaceStaggerAndCycle: the first candidate starts at once; while
// attempts are outstanding the next starts only after JoinStagger; ranking
// order is followed and cycled; slots that are busy or backing off are
// skipped; with nothing outstanding the next ready candidate starts without
// waiting; the wake is the earliest readiness.
func TestRaceStaggerAndCycle(t *testing.T) {
	const stagger = time.Second
	t0 := simEpoch
	at := func(d time.Duration) time.Time { return t0.Add(d) }
	sl := make(slots, 3)
	r := NewRace([]int{2, 0, 1}, stagger, t0)
	ids := make([]uint64, 3)
	next := func(now time.Time, outstanding int) (int, bool, time.Time) {
		idx, start, wake := r.Next(now, outstanding, sl.ready(now))
		if start {
			ids[idx] = sl[idx].Start(now)
		}
		return idx, start, wake
	}
	check := func(gotIdx int, gotStart bool, gotWake time.Time, wantIdx int, wantStart bool, wantWake time.Time) {
		t.Helper()
		if gotIdx != wantIdx || gotStart != wantStart || !gotWake.Equal(wantWake) {
			t.Fatalf("Next = (%d, %v, %v), want (%d, %v, %v)", gotIdx, gotStart, gotWake, wantIdx, wantStart, wantWake)
		}
	}
	i, s, w := next(at(0), 0)
	check(i, s, w, 2, true, at(stagger)) // the best candidate at once
	i, s, w = next(at(500*ms), 1)
	check(i, s, w, -1, false, at(stagger)) // within the stagger
	i, s, w = next(at(stagger), 1)
	check(i, s, w, 0, true, at(2*stagger)) // the next in rank order
	i, s, w = next(at(2*stagger), 2)
	check(i, s, w, 1, true, at(3*stagger))
	i, s, w = next(at(3*stagger), 3)
	check(i, s, w, -1, false, time.Time{}) // every slot busy: nothing to wake for

	// All three fail at different times and back off; with nothing
	// outstanding the race waits for the earliest readiness.
	sl[2].Finish(at(3100*ms), ids[2], OutcomeFailed, 4*time.Second, 0.5) // ready at 0 + 0.5 s → at once (ended later)
	sl[0].Finish(at(3200*ms), ids[0], OutcomeFailed, 4*time.Second, 0.5) // ready at 1.5 s → at once
	sl[1].Finish(at(3300*ms), ids[1], OutcomeFailed, 4*time.Second, 0.5) // ready at 2.5 s → at once
	// Every slot is ready again; the cursor continues after the last start
	// (factory 1 at position 2) and cycles to position 0 (factory 2).
	i, s, w = next(at(3300*ms), 0)
	check(i, s, w, 2, true, at(4300*ms))
	sl[2].Finish(at(3400*ms), ids[2], OutcomeFailed, 4*time.Second, 0.5) // 2nd failure: +1 s from 3.3 s → 4.3 s
	i, s, w = next(at(3400*ms), 0)
	check(i, s, w, 0, true, at(4400*ms))                                 // nothing outstanding: no stagger
	sl[0].Finish(at(3500*ms), ids[0], OutcomeFailed, 4*time.Second, 0.5) // → 4.4 s
	i, s, w = next(at(3500*ms), 0)
	check(i, s, w, 1, true, at(4500*ms))
	sl[1].Finish(at(3600*ms), ids[1], OutcomeFailed, 4*time.Second, 0.5) // → 4.5 s
	i, s, w = next(at(3600*ms), 0)
	check(i, s, w, -1, false, at(4300*ms)) // earliest readiness: factory 2
	i, s, w = next(at(4300*ms), 0)
	check(i, s, w, 2, true, at(5300*ms))

	// A kicked slot (death of that factory's carrier) is ready at once.
	sl[0].Kick()
	i, s, w = next(at(5300*ms), 1)
	check(i, s, w, 0, true, at(6300*ms))
}

// TestRaceCopiesOrder (C27): the race keeps its own copy of the ranking,
// so the caller may reuse its Rank buffer at once; NewRace and Next do not
// allocate; more than 16 candidates are truncated to the Peer limit; an
// empty race never starts anything.
func TestRaceCopiesOrder(t *testing.T) {
	buf := make([]int, 0, 16)
	buf = Rank([]Candidate{{Index: 0}, {Index: 1, Ev: Evidence{EvFresh, ms}}}, buf)
	r := NewRace(buf, time.Second, simEpoch)
	buf = Rank([]Candidate{{Index: 1}, {Index: 0, Ev: Evidence{EvFresh, ms}}}, buf) // reuse
	buf[0], buf[1] = 7, 8
	all := func(int) (bool, time.Time) { return true, time.Time{} }
	if idx, start, _ := r.Next(simEpoch, 0, all); !start || idx != 1 {
		t.Fatalf("first candidate %d (start %v), want 1 from the ranking at NewRace", idx, start)
	}
	if idx, start, _ := r.Next(simEpoch.Add(time.Second), 1, all); !start || idx != 0 {
		t.Fatalf("second candidate %d (start %v), want 0", idx, start)
	}

	long := make([]int, 20)
	for i := range long {
		long[i] = i
	}
	lr := NewRace(long, 0, simEpoch)
	seen := map[int]bool{}
	for k := 0; k < 40; k++ {
		idx, start, _ := lr.Next(simEpoch, 0, all)
		if !start {
			t.Fatal("no start")
		}
		seen[idx] = true
	}
	if len(seen) != maxRaceOrder || seen[16] {
		t.Fatalf("candidates started: %v, want exactly the first %d", seen, maxRaceOrder)
	}

	empty := NewRace(nil, time.Second, simEpoch)
	if idx, start, wake := empty.Next(simEpoch, 0, all); idx != -1 || start || !wake.IsZero() {
		t.Fatalf("empty race: (%d, %v, %v)", idx, start, wake)
	}

	// A readiness that is not in the future is not a wake time.
	r2 := NewRace([]int{0}, time.Second, simEpoch)
	past := func(int) (bool, time.Time) { return false, simEpoch.Add(-time.Second) }
	if _, start, wake := r2.Next(simEpoch, 0, past); start || !wake.IsZero() {
		t.Fatalf("past readiness: start %v wake %v", start, wake)
	}

	order := []int{3, 1, 2}
	if n := testing.AllocsPerRun(100, func() {
		rr := NewRace(order, time.Second, simEpoch)
		rr.Next(simEpoch, 0, all)
	}); n != 0 {
		t.Fatalf("NewRace+Next allocate %v times", n)
	}
}
