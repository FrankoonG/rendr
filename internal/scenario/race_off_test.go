//go:build !race

package scenario

// raceEnabled: the race detector slows the data path several times, so
// throughput ratios are asserted only in the non-race lane.
const raceEnabled = false
