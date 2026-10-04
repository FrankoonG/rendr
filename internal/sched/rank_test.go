package sched

import (
	"math/rand"
	"reflect"
	"slices"
	"testing"
	"testing/quick"
	"time"
)

// TestComparatorUnknownStaleNeverWin_L28: against a Fresh 10 ms incumbent,
// a challenger with unknown latency, a stale 1 ns value, zero samples, a
// held state without a value or a zero RTT never ranks first — even with
// the better configuration position — and a failed one ranks last; a Fresh
// challenger outranks a Stale incumbent; all-Unknown ranks by configuration
// order.
func TestComparatorUnknownStaleNeverWin_L28(t *testing.T) {
	now := simEpoch.Add(time.Hour)
	ev := func(s Summary) Evidence { return Classify(s, now, defFresh) }
	inc := Candidate{Index: 1, Ev: ev(Summary{Seen: true, N: 32, Mean: 10 * ms, At: now.Add(-time.Second)})}
	if inc.Ev != (Evidence{EvFresh, 10 * ms}) {
		t.Fatalf("incumbent evidence %+v", inc.Ev)
	}
	for _, tc := range []struct {
		name string
		ch   Candidate
	}{
		{"unknown latency", Candidate{Index: 0, Ev: ev(Summary{})}},
		{"stale 1ns (classified)", Candidate{Index: 0, Ev: ev(Summary{Seen: true, N: 5, Mean: 1, At: now.Add(-time.Minute)})}},
		{"stale 1ns (raw value kept)", Candidate{Index: 0, Ev: Evidence{State: EvStale, RTT: 1}}},
		{"zero samples", Candidate{Index: 0, Ev: ev(Summary{Seen: true, N: 0, At: now.Add(-time.Second)})}},
		{"held without value", Candidate{Index: 0, Ev: ev(Summary{Seen: true, LoadedAt: now})}},
		{"fresh reading 0", Candidate{Index: 0, Ev: Evidence{State: EvFresh}}},
		{"fresh negative", Candidate{Index: 0, Ev: Evidence{State: EvFresh, RTT: -ms}}},
		{"failed fresh 1ns", Candidate{Index: 0, Ev: Evidence{EvFresh, 1}, Failed: true}},
		{"unknown state value", Candidate{Index: 0, Ev: Evidence{State: EvState(9), RTT: 1}}},
	} {
		if !Less(inc, tc.ch) || Less(tc.ch, inc) {
			t.Errorf("%s: Less(inc, ch)=%v Less(ch, inc)=%v, want the incumbent first", tc.name, Less(inc, tc.ch), Less(tc.ch, inc))
		}
		if got := Rank([]Candidate{tc.ch, inc}, nil); !slices.Equal(got, []int{1, 0}) {
			t.Errorf("%s: Rank = %v, want [1 0]", tc.name, got)
		}
	}

	// A Fresh challenger outranks a Stale incumbent, whatever its RTT.
	staleInc := Candidate{Index: 0, Ev: ev(Summary{Seen: true, N: 32, Mean: 5 * ms, At: now.Add(-time.Minute)})}
	freshCh := Candidate{Index: 1, Ev: ev(Summary{Seen: true, N: 3, Mean: 80 * ms, At: now})}
	if !Less(freshCh, staleInc) {
		t.Fatal("fresh challenger does not outrank a stale incumbent")
	}
	// Held with a value ranks with Fresh by its value (§8: a loaded path is
	// still a healthy failover candidate).
	held := Candidate{Index: 2, Ev: ev(Summary{Seen: true, N: 32, Mean: 15 * ms, At: now.Add(-time.Minute), LoadedAt: now})}
	if held.Ev != (Evidence{EvHeld, 15 * ms}) || !Less(held, Candidate{Index: 0, Ev: Evidence{EvFresh, 20 * ms}}) {
		t.Fatalf("held 15 ms (%+v) does not outrank fresh 20 ms", held.Ev)
	}
	// All Unknown: configuration order, whatever the input order.
	unk := []Candidate{{Index: 3}, {Index: 0}, {Index: 4}, {Index: 2}, {Index: 1}}
	if got := Rank(unk, nil); !slices.Equal(got, []int{0, 1, 2, 3, 4}) {
		t.Fatalf("all unknown: %v", got)
	}
	// The full ladder: measured by RTT, then unmeasured by index, then failed.
	mixed := []Candidate{
		{Index: 0, Ev: Evidence{State: EvStale}},
		{Index: 1, Ev: Evidence{EvFresh, 30 * ms}, Failed: true},
		{Index: 2, Ev: Evidence{EvFresh, 30 * ms}},
		{Index: 3, Ev: Evidence{}},
		{Index: 4, Ev: Evidence{EvHeld, 12 * ms}},
		{Index: 5, Ev: Evidence{EvFresh, 12 * ms}},
		{Index: 6, Ev: Evidence{State: EvUnknown}, Failed: true},
	}
	if got := Rank(mixed, nil); !slices.Equal(got, []int{4, 5, 2, 0, 3, 1, 6}) {
		t.Fatalf("mixed ranking %v", got)
	}
}

// candSet is a testing/quick input: 1–16 candidates with unique indexes
// and a small value space, so classes, RTT ties and failed marks collide
// often.
type candSet []Candidate

var quickRTTs = []time.Duration{-ms, 0, 1, 5 * ms, 5 * ms, 10 * ms, 30 * ms, 30 * ms, time.Second}

func (candSet) Generate(r *rand.Rand, _ int) reflect.Value {
	n := 1 + r.Intn(16)
	idx := r.Perm(64)[:n] // unique, not dense
	cs := make(candSet, n)
	for i := range cs {
		cs[i] = Candidate{
			Index:  idx[i],
			Ev:     Evidence{State: EvState(r.Intn(5)), RTT: quickRTTs[r.Intn(len(quickRTTs))]},
			Failed: r.Intn(4) == 0,
		}
	}
	return reflect.ValueOf(cs)
}

// TestComparatorProperties_L29: Less is a strict total order (irreflexive,
// antisymmetric, total on distinct indexes, transitive) and Rank's result
// is independent of the input order, sorted by Less, and leaves its input
// untouched (testing/quick, 2000 generated sets).
func TestComparatorProperties_L29(t *testing.T) {
	checked := 0
	prop := func(cs candSet) bool {
		checked++
		for _, x := range cs {
			if Less(x, x) {
				t.Logf("irreflexivity: %+v", x)
				return false
			}
			for _, y := range cs {
				if x.Index == y.Index {
					continue
				}
				if Less(x, y) == Less(y, x) {
					t.Logf("totality/antisymmetry: %+v vs %+v", x, y)
					return false
				}
				for _, z := range cs {
					if Less(x, y) && Less(y, z) && !Less(x, z) {
						t.Logf("transitivity: %+v < %+v < %+v", x, y, z)
						return false
					}
				}
			}
		}
		orig := slices.Clone(cs)
		want := Rank(cs, nil)
		if !slices.Equal(cs, orig) {
			t.Log("Rank modified its input")
			return false
		}
		for i := 1; i < len(want); i++ {
			if !Less(byIndex(cs, want[i-1]), byIndex(cs, want[i])) {
				t.Logf("Rank %v not sorted by Less", want)
				return false
			}
		}
		r := rand.New(rand.NewSource(int64(len(cs)*7919 + checked)))
		buf := make([]int, 0, 16)
		for k := 0; k < 4; k++ {
			sh := slices.Clone(cs)
			r.Shuffle(len(sh), func(i, j int) { sh[i], sh[j] = sh[j], sh[i] })
			if got := Rank(sh, buf); !slices.Equal(got, want) {
				t.Logf("input order changed the ranking: %v vs %v", got, want)
				return false
			}
		}
		return true
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 2000, Rand: rand.New(rand.NewSource(29))}); err != nil {
		t.Fatal(err)
	}
	if checked < 1000 {
		t.Fatalf("only %d generated cases", checked)
	}
	// Fixed examples (RTT-only evidence, P11): better RTT wins; equal RTT
	// falls back to configuration order; Held with a value is measured.
	a := Candidate{Index: 1, Ev: Evidence{EvFresh, 7 * ms}}
	b := Candidate{Index: 0, Ev: Evidence{EvFresh, 8 * ms}}
	c := Candidate{Index: 2, Ev: Evidence{EvHeld, 8 * ms}}
	if !Less(a, b) || !Less(b, c) || !Less(a, c) {
		t.Fatal("fixed examples out of order")
	}
}

func byIndex(cs []Candidate, idx int) Candidate {
	for _, c := range cs {
		if c.Index == idx {
			return c
		}
	}
	panic("index not found")
}

// TestRankReusesBuffer: Rank writes into out and allocates nothing when
// out is large enough.
func TestRankReusesBuffer(t *testing.T) {
	cs := []Candidate{{Index: 2}, {Index: 0, Ev: Evidence{EvFresh, ms}}, {Index: 1, Failed: true}}
	buf := make([]int, 0, 16)
	got := Rank(cs, buf)
	if &got[0] != &buf[:1][0] || !slices.Equal(got, []int{0, 2, 1}) {
		t.Fatalf("Rank = %v (buffer reused: %v)", got, &got[0] == &buf[:1][0])
	}
	if got := Rank(nil, buf); len(got) != 0 {
		t.Fatalf("Rank(nil) = %v", got)
	}
}
