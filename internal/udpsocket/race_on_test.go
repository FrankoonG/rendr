//go:build race

package udpsocket

// raceEnabled: the race detector allocates on its own paths, so the
// allocation gates are asserted only in the non-race lane (§A10.3).
const raceEnabled = true
