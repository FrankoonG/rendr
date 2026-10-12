//go:build race

package l4

// raceEnabled: allocation gates (testing.AllocsPerRun) are asserted only in
// the non-race lane (M4 design §A12.6); the functional checks run in both.
const raceEnabled = true
