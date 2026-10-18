//go:build race

package l4u

// raceEnabled: see race_off_test.go.
const raceEnabled = true

// lane under the race detector: the race lane's size (lane_test.go).
var lane = raceLane
