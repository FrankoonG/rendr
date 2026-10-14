//go:build race

package quic

// raceEnabled: the race detector allocates on its own paths, so the
// allocation gates are asserted only in the non-race lane (§A10.3); the
// race lane runs the same loops without the assertion.
const raceEnabled = true
