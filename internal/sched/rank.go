package sched

// Candidate is one factory as seen by the ranking.
type Candidate struct {
	Index  int      // configuration order; unique, used as the final tie-break
	Ev     Evidence // evidence at the ranking instant
	Failed bool     // ranking demotion mark (plan §3.9); never blocks a dial
}

// rankClass is the comparator class of c: 0 measured (EvFresh, or EvHeld
// with a value), 1 unmeasured (EvUnknown, EvStale, EvHeld without a value,
// or any evidence without a positive RTT), 2 failed.
func rankClass(c Candidate) int {
	switch {
	case c.Failed:
		return 2
	case (c.Ev.State == EvFresh || c.Ev.State == EvHeld) && c.Ev.RTT > 0:
		return 0
	}
	return 1
}

// Less is the ranking comparator (plan §3.9; L28, L29). Classes, best
// first: (0) not failed and (EvFresh, or EvHeld with RTT > 0), ordered by RTT
// then Index; (1) not failed and (EvUnknown, EvStale, or EvHeld without a
// value), ordered by Index; (2) failed, ordered by Index. Less is a pure
// strict total order (Index is unique): antisymmetric, transitive and
// independent of input order.
//
// A non-failed candidate whose evidence has no positive RTT is unmeasured
// (class 1) whatever its state: a zero RTT never reads as "infinitely fast"
// (L28).
func Less(x, y Candidate) bool {
	cx, cy := rankClass(x), rankClass(y)
	if cx != cy {
		return cx < cy
	}
	if cx == 0 && x.Ev.RTT != y.Ev.RTT {
		return x.Ev.RTT < y.Ev.RTT
	}
	return x.Index < y.Index
}

// Rank orders cs by Less and writes their Index values into out (reused,
// returned with length len(cs)); it does not modify cs and does not allocate
// when cap(out) ≥ len(cs).
func Rank(cs []Candidate, out []int) []int {
	n := len(cs)
	if cap(out) < n {
		out = make([]int, n)
	}
	out = out[:n]
	for i := range out {
		out[i] = i
	}
	// Insertion sort of positions: n is the Peer factory count (≤ 16), and
	// unlike sort.Slice it allocates nothing.
	for i := 1; i < n; i++ {
		p := out[i]
		j := i
		for j > 0 && Less(cs[p], cs[out[j-1]]) {
			out[j] = out[j-1]
			j--
		}
		out[j] = p
	}
	for i, p := range out {
		out[i] = cs[p].Index
	}
	return out
}
