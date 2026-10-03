//go:build race

package msess_test

// raceEnabled: the race detector slows the data path several times, so
// throughput ratios are asserted only in the non-race lane.
const raceEnabled = true
