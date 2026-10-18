//go:build !race

package l4u

// raceEnabled reports the race detector (TestL4URaceLane checks it against
// the binary's build).
const raceEnabled = false

// lane is what the heavy rows run: the design's full size in the non-race
// unit and sweep lanes (lane_test.go).
var lane = fullLane
