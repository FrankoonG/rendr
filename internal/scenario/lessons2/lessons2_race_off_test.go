//go:build !race

package lessons2

// raceEnabled shrinks the volume of CPU-heavy tests under the race detector
// (design §11.1).
const raceEnabled = false
