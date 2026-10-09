package sched

import (
	"math/rand/v2"
	"slices"
	"testing"
)

// groupOf returns the group function of a table of per-factory indexes.
func groupOf(g []uint8) func(int) uint8 { return func(i int) uint8 { return g[i] } }

// modelGroupFirst is the reference stable partition: the candidates whose
// group is not failed in their order, then the others in their order; a
// failed group 0 (a group of its own: nothing shares it) keeps order.
func modelGroupFirst(order []int, g []uint8, failed uint8) []int {
	if failed == 0 {
		return slices.Clone(order)
	}
	var head, tail []int
	for _, f := range order {
		if g[f] == failed {
			tail = append(tail, f)
		} else {
			head = append(head, f)
		}
	}
	return append(head, tail...)
}

// modelOnePerGroup is the reference membership: the first candidate of each
// group in order, every group-0 candidate (a group of its own), at most max.
func modelOnePerGroup(order []int, g []uint8, max int) []int {
	var out []int
	seen := map[uint8]bool{}
	for _, f := range order {
		if len(out) >= max {
			break
		}
		if g[f] != 0 {
			if seen[g[f]] {
				continue
			}
			seen[g[f]] = true
		}
		out = append(out, f)
	}
	return out
}

// randomCase returns a random ranking of n ≤ 16 factories and their groups
// (0 with probability ½, else one of a few named groups, so that groups
// repeat).
func randomCase(r *rand.Rand) (order []int, g []uint8) {
	n := 1 + r.IntN(maxFactories)
	g = make([]uint8, n)
	for i := range g {
		if r.IntN(2) == 1 {
			g[i] = uint8(1 + r.IntN(4))
		}
	}
	order = r.Perm(n)
	return order, g
}

// TestGroupFirstStable (M3-D38, §A7.2): the selector's failover order puts
// the candidates outside the dead carrier's group first; both halves keep
// the ranking order (a stable partition, not a re-rank); applying it twice
// changes nothing; a dead carrier of group 0 (an empty FateGroup: a group
// of its own) leaves the ranking unchanged, so a Peer without FateGroups
// fails over exactly as M1/M2 did. out may be order itself (in place), and
// a reused out is overwritten from index 0.
func TestGroupFirstStable(t *testing.T) {
	// The design example (§A7.2): a, b in group 1, c alone, ranked a > b > c;
	// a dies → c, then the group-1 candidates in rank order.
	g := []uint8{1, 1, 0} // a=0, b=1, c=2
	if got := GroupFirst([]int{0, 1, 2}, groupOf(g), 1, nil); !slices.Equal(got, []int{2, 0, 1}) {
		t.Fatalf("a dies: failover order %v, want [2 0 1]", got)
	}
	// c (group 0) dies: nothing else shares its fate, plain rank.
	if got := GroupFirst([]int{0, 1, 2}, groupOf(g), 0, nil); !slices.Equal(got, []int{0, 1, 2}) {
		t.Fatalf("c dies: failover order %v, want [0 1 2]", got)
	}
	// Stability inside both halves with interleaved groups.
	g = []uint8{2, 0, 2, 3, 2, 0, 3}
	order := []int{6, 4, 1, 0, 3, 5, 2}
	if got, want := GroupFirst(order, groupOf(g), 2, nil), []int{6, 1, 3, 5, 4, 0, 2}; !slices.Equal(got, want) {
		t.Fatalf("group 2 dies: %v, want %v", got, want)
	}
	// A reused out with stale contents and spare capacity.
	out := []int{9, 9, 9, 9, 9, 9, 9, 9, 9}
	if got := GroupFirst(order, groupOf(g), 3, out); !slices.Equal(got, []int{4, 1, 0, 5, 2, 6, 3}) || &got[0] != &out[0] {
		t.Fatalf("group 3 dies into a reused buffer: %v", got)
	}
	// Property: against the model, idempotent, in place, order untouched.
	r := rand.New(rand.NewPCG(38, 38))
	for i := 0; i < 20000; i++ {
		order, g := randomCase(r)
		failed := uint8(r.IntN(5))
		keep := slices.Clone(order)
		want := modelGroupFirst(order, g, failed)
		got := GroupFirst(order, groupOf(g), failed, make([]int, 0, len(order)))
		if !slices.Equal(got, want) {
			t.Fatalf("order %v groups %v failed %d: %v, want %v", order, g, failed, got, want)
		}
		if !slices.Equal(order, keep) {
			t.Fatalf("GroupFirst modified order: %v, was %v", order, keep)
		}
		if again := GroupFirst(got, groupOf(g), failed, nil); !slices.Equal(again, got) {
			t.Fatalf("not idempotent: %v then %v", got, again)
		}
		inPlace := GroupFirst(order, groupOf(g), failed, order[:0])
		if !slices.Equal(inPlace, want) {
			t.Fatalf("in place: order %v groups %v failed %d: %v, want %v", keep, g, failed, inPlace, want)
		}
	}
	if got := GroupFirst(nil, groupOf(nil), 1, nil); len(got) != 0 {
		t.Fatalf("empty order: %v", got)
	}
}

// TestOnePerGroup_L32 (M3-D37, L32: a fate group is not independent
// capacity): bond and race members are the first candidate of each group in
// rank order — a later candidate of a group already taken is skipped, so no
// two members share a group — while every group-0 candidate (an empty
// FateGroup) is a group of its own; at most max are taken, the best first.
// out may be order itself (in place).
func TestOnePerGroup_L32(t *testing.T) {
	// a, b in group 1, c alone, ranked a > b > c: members a and c.
	g := []uint8{1, 1, 0}
	if got := OnePerGroup([]int{0, 1, 2}, groupOf(g), 16, nil); !slices.Equal(got, []int{0, 2}) {
		t.Fatalf("members %v, want [0 2]", got)
	}
	// The ranking decides which factory of a group is the member.
	if got := OnePerGroup([]int{1, 2, 0}, groupOf(g), 16, nil); !slices.Equal(got, []int{1, 2}) {
		t.Fatalf("members %v, want [1 2]", got)
	}
	// Zero Props everywhere: every factory is a member (M1/M2 bond), capped.
	zero := make([]uint8, 5)
	if got := OnePerGroup([]int{4, 3, 2, 1, 0}, groupOf(zero), 16, nil); !slices.Equal(got, []int{4, 3, 2, 1, 0}) {
		t.Fatalf("independent factories: %v", got)
	}
	if got := OnePerGroup([]int{4, 3, 2, 1, 0}, groupOf(zero), 3, nil); !slices.Equal(got, []int{4, 3, 2}) {
		t.Fatalf("cap 3: %v", got)
	}
	// The cap counts members, not candidates: skipped group mates do not
	// consume it.
	g = []uint8{1, 1, 1, 2, 2, 0}
	if got := OnePerGroup([]int{0, 1, 2, 3, 4, 5}, groupOf(g), 3, nil); !slices.Equal(got, []int{0, 3, 5}) {
		t.Fatalf("cap 3 over groups: %v, want [0 3 5]", got)
	}
	for _, max := range []int{0, -1} {
		if got := OnePerGroup([]int{0, 1}, groupOf(g), max, nil); len(got) != 0 {
			t.Fatalf("max %d: %v", max, got)
		}
	}
	// All 255 named groups are distinct groups.
	g = make([]uint8, 16)
	order := make([]int, 16)
	for i := range g {
		g[i], order[i] = uint8(255-i), i
	}
	if got := OnePerGroup(order, groupOf(g), 16, nil); !slices.Equal(got, order) {
		t.Fatalf("16 distinct named groups: %v", got)
	}
	// Property: against the model; no two members share a non-zero group;
	// in place; order untouched.
	r := rand.New(rand.NewPCG(32, 32))
	for i := 0; i < 20000; i++ {
		order, g := randomCase(r)
		max := r.IntN(maxFactories + 2)
		keep := slices.Clone(order)
		want := modelOnePerGroup(order, g, max)
		got := OnePerGroup(order, groupOf(g), max, make([]int, 0, len(order)))
		if !slices.Equal(got, want) {
			t.Fatalf("order %v groups %v max %d: %v, want %v", order, g, max, got, want)
		}
		if !slices.Equal(order, keep) {
			t.Fatalf("OnePerGroup modified order: %v, was %v", order, keep)
		}
		taken := map[uint8]bool{}
		for _, f := range got {
			if g[f] != 0 && taken[g[f]] {
				t.Fatalf("two members of group %d: %v (groups %v)", g[f], got, g)
			}
			taken[g[f]] = true
		}
		if inPlace := OnePerGroup(order, groupOf(g), max, order[:0]); !slices.Equal(inPlace, want) {
			t.Fatalf("in place: order %v groups %v max %d: %v, want %v", keep, g, max, inPlace, want)
		}
	}
}
