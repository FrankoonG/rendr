//go:build !race

package packet

// raceEnabled reports the race detector: the allocation gate asserts only
// without it (M2 design §A8.5, the non-race lane), and under it the fseq
// jump and trunk-close rows run fewer subtests (fseqJumpCases,
// trunkLearnSessions). TestRaceLaneSubtests checks this switch against the
// binary's build.
const raceEnabled = false

// goldRateBA is the G3, G4 and G5 miniatures' B → A rate in datagrams
// per second: the full 2 kpps. The race lane halves it (race_on_test.go).
const goldRateBA = fullRateBA
