//go:build !race

package l4

// raceEnabled: under the race detector the bulk scenarios run their race
// size (M3 design R1-11: the same criteria on a smaller volume).
const raceEnabled = false

// churnScale divides every class of TestL4ChurnNoLeak_L52's mix: 1
// (2,000 connections; 1,000 under the race detector).
const churnScale = 1
