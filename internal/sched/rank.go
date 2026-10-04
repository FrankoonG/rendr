package sched

// Candidate is one factory as seen by the ranking.
type Candidate struct {
	Index  int      // configuration order; unique, used as the final tie-break
	Ev     Evidence // evidence at the ranking instant
	Failed bool     // ranking demotion mark (plan §3.9); never blocks a dial
}

// Less is the ranking comparator (plan §3.9; L28, L29). Classes, best
// first: (0) not failed and (EvFresh, or EvHeld with RTT > 0), ordered by RTT
// then Index; (1) not failed and (EvUnknown, EvStale, or EvHeld without a
// value), ordered by Index; (2) failed, ordered by Index. Less is a pure
// strict total order (Index is unique): antisymmetric, transitive and
// independent of input order.
func Less(x, y Candidate) bool {
	panic("unimplemented: M1b")
}

// Rank orders cs by Less and writes their Index values into out (reused,
// returned with length len(cs)); it does not modify cs and does not allocate
// when cap(out) ≥ len(cs).
func Rank(cs []Candidate, out []int) []int {
	panic("unimplemented: M1b")
}
