//go:build race

package mux

// raceEnabled: under the race detector the bulk scenarios run their race
// size (M3 design R1-11: the same criteria on a smaller volume).
const raceEnabled = true
