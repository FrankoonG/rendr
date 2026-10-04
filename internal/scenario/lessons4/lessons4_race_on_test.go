//go:build race

package lessons4

// raceEnabled shrinks the volume of CPU-heavy scenarios under -race
// (design §11.1).
const raceEnabled = true
