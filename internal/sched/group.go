package sched

// Fate groups (M3 design §A7.2; M3-D37, M3-D38). Factories whose carriers
// fail together (Props.FateGroup) share a group index; group selects the
// index of a factory. Both functions are pure, allocate nothing (they
// append to out, which the caller sizes) and keep the caller's ranking
// order within each part.

// GroupFirst returns order stably partitioned into the candidates whose
// group is not failed, then those whose group is failed: the failover race
// order of a selector whose carrier of group failed died (M3-D38). Within
// each part the order of order is kept. It appends to out[:0] and returns
// the result.
func GroupFirst(order []int, group func(int) uint8, failed uint8, out []int) []int {
	panic("unimplemented: M3")
}

// OnePerGroup returns the first candidate of each group in the order of
// order, at most max of them: the bond and race members (M3-D37). A later
// candidate of a group already taken is skipped, so no two results share a
// group. It appends to out[:0] and returns the result.
func OnePerGroup(order []int, group func(int) uint8, max int, out []int) []int {
	panic("unimplemented: M3")
}
