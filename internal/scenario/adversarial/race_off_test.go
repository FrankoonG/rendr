//go:build !race

package adversarial

// raceEnabled reports the race detector: under it the rows move less data
// on the same timeline with the same criteria (R2-37).
const raceEnabled = false
