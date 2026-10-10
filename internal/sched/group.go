package sched

// Fate groups (M3 design §A7.2; M3-D37, M3-D38). Factories whose carriers
// fail together (Props.FateGroup) share a group index; group selects the
// index of a factory. Index 0 is a group of its own (an empty FateGroup:
// session.DialSpec.Groups), so a zero group function keeps every factory
// independent and both functions then return order (capped by max). Both
// are pure, allocate nothing when cap(out) ≥ len(order) and keep the
// caller's ranking order within each part. out may be order[:0] (in place)
// when order holds at most 16 entries, the Peer factory limit.

// GroupFirst returns order stably partitioned into the candidates whose
// group is not failed, then those whose group is failed: the failover race
// order of a selector whose carrier of group failed died (M3-D38). Within
// each part the order of order is kept. failed 0 (the dead carrier was a
// group of its own) shares its fate with no other factory and returns order
// unchanged. It appends to out[:0] and returns the result.
func GroupFirst(order []int, group func(int) uint8, failed uint8, out []int) []int {
	out = out[:0]
	if failed == 0 {
		return append(out, order...) // copy semantics: safe when out aliases order
	}
	// A stack copy, so that writing out cannot clobber an aliased order
	// before the second pass reads it.
	src := order
	var buf [maxFactories]int
	if len(order) <= maxFactories {
		src = buf[:copy(buf[:], order)]
	}
	for _, f := range src {
		if group(f) != failed {
			out = append(out, f)
		}
	}
	for _, f := range src {
		if group(f) == failed {
			out = append(out, f)
		}
	}
	return out
}

// OnePerGroup returns the first candidate of each group in the order of
// order, at most max of them: the bond and race members (M3-D37). A later
// candidate of a group already taken is skipped, so no two results share a
// group; every group-0 candidate is a group of its own and is never
// skipped. It appends to out[:0] and returns the result.
func OnePerGroup(order []int, group func(int) uint8, max int, out []int) []int {
	out = out[:0]
	var taken [4]uint64 // bit g: group g already has a member
	for _, f := range order {
		if len(out) >= max {
			break
		}
		// Reading f before the append keeps an aliased order intact: the
		// write position never passes the read position.
		if g := group(f); g != 0 {
			if taken[g>>6]&(1<<(g&63)) != 0 {
				continue
			}
			taken[g>>6] |= 1 << (g & 63)
		}
		out = append(out, f)
	}
	return out
}
