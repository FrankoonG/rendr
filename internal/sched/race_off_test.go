//go:build !race

package sched

// raceEnabled: allocation gates (testing.AllocsPerRun) are asserted only in
// the non-race lane (design §11.1); the functional checks run in both.
const raceEnabled = false
