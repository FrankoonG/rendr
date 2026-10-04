//go:build !race

package lessons3

// raceEnabled: CPU-heavy scenarios shrink their volume under -race.
const raceEnabled = false
