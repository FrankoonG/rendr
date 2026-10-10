//go:build race

package timers

// raceEnabled: under the race detector the many-session scenarios run
// fewer sessions (R2-37: the same criteria on a smaller population).
const raceEnabled = true
