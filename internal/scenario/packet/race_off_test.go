//go:build !race

package packet

// raceEnabled reports the race detector: the allocation gate asserts only
// without it (M2 design §A8.5, the non-race lane).
const raceEnabled = false
