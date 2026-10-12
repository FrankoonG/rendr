//go:build race

package l4

// raceEnabled: under the race detector the bulk scenarios run their race
// size (M3 design R1-11: the same criteria on a smaller volume).
const raceEnabled = true

// churnScale divides every class of TestL4ChurnNoLeak_L52's mix: 2
// under the race detector (m3 R1-23's first lever, I3 of M4: 1,000
// connections over the same 60 s with the same kills and criteria).
const churnScale = 2
