//go:build !race

package race

// raceEnabled: under the race detector the bulk miniatures run their race
// size (M3 design R1-11: the same criteria on a smaller volume).
const raceEnabled = false
