//go:build race

package main

// raceEnabled: the race lane (race-unit, R1-37's budget) leaves the rows
// that only wait out real timers to the non-race unit lane.
const raceEnabled = true
