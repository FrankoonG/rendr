package sched

// Candidate is one factory as seen by the ranking.
type Candidate struct {
	Index  int      // configuration order; unique, used as the final tie-break
	Ev     Evidence // evidence at the ranking instant
	Failed bool     // ranking demotion mark (plan §3.9); never blocks a dial
	// Class is the kind class of the factory for the ranked session (M2-D47):
	// 0 the session's preferred carrier kind (a packet session's datagram
	// factories), 1 the fallback kind (its stream factories). Stream
	// sessions use class 0 only. Less orders by it after the failed mark
	// and before the evidence, so a higher class does not rank a factory
	// after the failed ones: a factory the session may not dial (M2-D46)
	// is left out of the ranked set instead.
	Class uint8
}

// measured reports whether c's evidence carries a value the ranking orders
// by: EvFresh, or EvHeld with a value, and a positive RTT. Any other
// evidence (EvUnknown, EvStale, EvHeld without a value, or no positive RTT
// whatever the state) is unmeasured: a zero RTT never reads as "infinitely
// fast" (L28).
func measured(c Candidate) bool {
	return (c.Ev.State == EvFresh || c.Ev.State == EvHeld) && c.Ev.RTT > 0
}

// Less is the ranking comparator (plan §3.9; L28, L29; M2-D47). It compares
// a key, most significant part first:
//
//  1. the failed mark: failed candidates rank last;
//  2. Class, lowest first: a packet session's datagram factories (0)
//     before its stream factories (1), whatever their evidence;
//  3. for candidates not failed, the evidence: measured (EvFresh, or EvHeld
//     with RTT > 0) by RTT, before unmeasured (EvUnknown, EvStale, or EvHeld
//     without a value); failed candidates are not ordered by evidence;
//  4. Index.
//
// With every Class equal (stream sessions) this is M1's order: (0) not failed
// and measured, by RTT then Index; (1) not failed and unmeasured, by Index;
// (2) failed, by Index. Less is a pure strict total order (Index is unique):
// antisymmetric, transitive and independent of input order.
func Less(x, y Candidate) bool {
	if x.Failed != y.Failed {
		return y.Failed
	}
	if x.Class != y.Class {
		return x.Class < y.Class
	}
	if !x.Failed {
		mx, my := measured(x), measured(y)
		if mx != my {
			return mx
		}
		if mx && x.Ev.RTT != y.Ev.RTT {
			return x.Ev.RTT < y.Ev.RTT
		}
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
